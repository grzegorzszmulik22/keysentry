import { describe, expect, it } from 'vitest';
import { buildInventory, buildPlan, createLogger, createRedactor, fingerprint } from '../../src/core/index.js';
import { executePlan, resumeRotation, type EngineDeps, type RotateOptions } from '../../src/rotate/index.js';
import type { CrashPoint, JournalEntry, ProviderAdapter } from '../../src/types.js';
import { FakeHttp } from '../helpers/fake-http.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

async function fixture(readable = false) {
  const clock = { ms: Date.parse('2026-10-27T12:00:00.000Z') };
  const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-') as FakeProvider & Pick<ProviderAdapter, 'rotateByRef'>;
  provider.now = () => new Date(clock.ms - 86_400_000);
  const old = provider.issue();
  old.value = `sk-or-v1-${'a1'.repeat(32)}`;
  provider.keys.get(old.ref)!.value = old.value;
  provider.now = () => new Date(clock.ms);
  const host = new FakeHost(readable ? 'railway' : 'fly', { readValues: readable });
  host.pendingPolls = 0;
  const service = host.addService('consumer', { OPENROUTER_API_KEY: old.value });
  const fingerprintKey = Buffer.alloc(32, 0x73);
  const inventory = buildInventory([{ host: host.id, services: [{ service, vars: await host.readVariables(service) }] }], fingerprintKey, new Date(clock.ms));
  const plan = buildPlan(inventory);
  const clusterId = plan.steps[0]!.clusterId;
  const entries: JournalEntry[] = [];
  const redactor = createRedactor();
  const log = createLogger({ redactor, sink: () => {} });
  const inflight = createFakeInFlight();
  const byRefs: string[] = [];
  let valueRotations = 0;
  let prompts = 0;
  const rotate = provider.rotate.bind(provider);
  provider.rotate = async (value, ctx) => { valueRotations++; return rotate(value, ctx); };
  provider.rotateByRef = async (oldKeyRef, ctx) => {
    byRefs.push(oldKeyRef);
    const key = provider.keys.get(oldKeyRef);
    if (!key) throw Object.assign(new Error('Guided rotation required.'), { code: 'GUIDED_ROTATION_REQUIRED' });
    return rotate(key.value, ctx);
  };
  const deps: EngineDeps = {
    hosts: { [host.id]: host }, providers: () => provider,
    providerCtx: { http: new FakeHttp(), credentials: {}, log },
    journal: { async append(entry) { entries.push(structuredClone(entry)); }, async read() { return structuredClone(entries); } },
    prompt: async () => { prompts++; return null; }, fingerprintKey, redactor, log, inflight,
    now: () => new Date(clock.ms), sleep: async ms => { clock.ms += ms; },
  };
  const opts: RotateOptions & { adoptedKeyRefs: Record<string, string> } = {
    dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 1,
    revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 0,
    adoptedKeyRefs: { [clusterId]: old.ref },
  };
  return { clock, provider, old, host, service, inventory, plan, clusterId, entries, deps, opts, inflight, byRefs,
    valueRotations: () => valueRotations, prompts: () => prompts,
    input: () => ({ plan, inventory, entries: structuredClone(entries) }) };
}

describe('rotation of adopted write-only provider keys', () => {
  it('creates by reference, verifies, deploys and revokes the old reference without saving its value', async () => {
    const h = await fixture();
    const report = await executePlan(h.plan, h.inventory, h.deps, h.opts);
    expect(report.status).toBe('complete');
    expect(h.byRefs).toEqual([h.old.ref]);
    expect(h.valueRotations()).toBe(0);
    expect(h.prompts()).toBe(0);
    expect(h.provider.revoked).toEqual([h.old.ref]);
    expect(h.host.redeploys).toEqual([h.service.serviceId]);
    expect(h.host.peek(h.service.serviceId, 'OPENROUTER_API_KEY')).not.toBe(h.old.value);
    expect(report.steps[0]).toMatchObject({ status: 'revoked', oldKeyRef: h.old.ref, newKeyRef: 'key_2' });
    expect(h.inflight.calls).not.toContain(`put:old:${h.clusterId}`);
    const serialized = JSON.stringify({ report, entries: h.entries });
    for (const key of h.provider.keys.values()) expect(serialized).not.toContain(key.value);
  });

  it('accepts a stored adoption fingerprint for a still-sealed consumer', async () => {
    const h = await fixture();
    const known = fingerprint(h.old.value, h.deps.fingerprintKey);
    h.inventory.clusters[0]!.fingerprint = known;
    h.inventory.clusters[0]!.consumers[0]!.fingerprint = known;
    h.plan.steps[0]!.consumers[0]!.fingerprint = known;
    const report = await executePlan(h.plan, h.inventory, h.deps, h.opts);
    expect(report.status).toBe('complete');
    expect(h.byRefs).toEqual([h.old.ref]);
  });

  it.each(['missing-ref', 'missing-capability'])('%s retains the guided fallback', async mode => {
    const h = await fixture();
    if (mode === 'missing-ref') h.opts.adoptedKeyRefs = {};
    else delete h.provider.rotateByRef;
    const report = await executePlan(h.plan, h.inventory, h.deps, h.opts);
    expect(h.prompts()).toBe(1);
    expect(h.byRefs).toEqual([]);
    expect(h.valueRotations()).toBe(0);
    expect(h.host.writes).toEqual([]);
    expect(h.provider.revoked).toEqual([]);
    expect(report.steps[0]!.status).toBe('skipped');
  });

  it('a provider refusal before mutation retains the guided fallback', async () => {
    const h = await fixture();
    h.provider.rotateByRef = async () => { throw Object.assign(new Error('Guided rotation required.'), { code: 'GUIDED_ROTATION_REQUIRED' }); };
    const report = await executePlan(h.plan, h.inventory, h.deps, h.opts);
    expect(h.prompts()).toBe(1);
    expect(h.provider.keys.size).toBe(1);
    expect(h.host.writes).toEqual([]);
    expect(h.provider.revoked).toEqual([]);
    expect(report.steps[0]!.status).toBe('skipped');
  });

  it('a readable old value keeps using value-based rotation even when an adopted reference is supplied', async () => {
    const h = await fixture(true);
    const report = await executePlan(h.plan, h.inventory, h.deps, h.opts);
    expect(report.status).toBe('complete');
    expect(h.valueRotations()).toBe(1);
    expect(h.byRefs).toEqual([]);
  });

  it('a readable value changed since scan is still refused before any provider mutation', async () => {
    const h = await fixture(true);
    await h.host.writeVariables(h.service, { OPENROUTER_API_KEY: 'sk-or-v1-manually-changed-credential-value' }, { skipDeploy: true });
    h.host.writes.length = 0;
    const report = await executePlan(h.plan, h.inventory, h.deps, h.opts);
    expect(report.steps[0]!.status).toBe('skipped');
    expect(h.valueRotations()).toBe(0);
    expect(h.byRefs).toEqual([]);
    expect(h.host.writes).toEqual([]);
  });

  it.each(['after-create', 'after-store'] as const)('crash at %s preserves recovery behavior without knowing the old value', async point => {
    const h = await fixture();
    const interruption = new Error('simulated process interruption');
    h.deps.crashHook = (at: CrashPoint) => { if (at === point) throw interruption; };
    await expect(executePlan(h.plan, h.inventory, h.deps, h.opts)).rejects.toBe(interruption);
    expect(h.byRefs).toEqual([h.old.ref]);
    expect(h.provider.revoked).toEqual([]);
    expect(h.host.writes).toEqual([]);
    expect(await h.inflight.get(h.plan.id, `old:${h.clusterId}`)).toBeNull();
    delete h.deps.crashHook;
    const report = await resumeRotation(h.input(), h.deps, h.opts);
    expect(h.byRefs).toEqual([h.old.ref]);
    expect(h.valueRotations()).toBe(0);
    if (point === 'after-create') {
      expect(report.status).toBe('partial');
      expect(report.orphanSuspects?.map(key => key.keyRef)).toEqual(['key_2']);
      expect(h.provider.revoked).toEqual([]);
      expect(h.host.writes).toEqual([]);
      expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
    } else {
      expect(report.status).toBe('complete');
      expect(report.steps[0]).toMatchObject({ oldKeyRef: h.old.ref, newKeyRef: 'key_2', status: 'revoked' });
      expect(h.provider.revoked).toEqual([h.old.ref]);
      expect(h.host.writes).toHaveLength(1);
    }
  });

  it('orphan discovery excludes the adopted old reference even when its creation time is recent', async () => {
    const h = await fixture();
    h.provider.keys.get(h.old.ref)!.createdAt = new Date(h.clock.ms).toISOString();
    const interruption = new Error('simulated process interruption');
    h.deps.crashHook = point => { if (point === 'after-create') throw interruption; };
    await expect(executePlan(h.plan, h.inventory, h.deps, h.opts)).rejects.toBe(interruption);
    delete h.deps.crashHook;
    const report = await resumeRotation(h.input(), h.deps, h.opts);
    expect(report.orphanSuspects?.map(key => key.keyRef)).toEqual(['key_2']);
    expect(h.provider.revoked).toEqual([]);
  });

  it('resume after a recorded write uses stored references and does not create or write again', async () => {
    const h = await fixture();
    const interruption = new Error('simulated process interruption');
    h.deps.crashHook = point => { if (point === 'after-redeploy') throw interruption; };
    await expect(executePlan(h.plan, h.inventory, h.deps, h.opts)).rejects.toBe(interruption);
    delete h.deps.crashHook;
    const report = await resumeRotation(h.input(), h.deps, h.opts);
    expect(report.status).toBe('complete');
    expect(h.byRefs).toEqual([h.old.ref]);
    expect(h.host.writes).toHaveLength(1);
    expect(h.provider.revoked).toEqual([h.old.ref]);
  });

  it('failed durable storage cleans up the created reference and leaves the old key live', async () => {
    const h = await fixture();
    h.inflight.put = async () => { throw new Error('storage failed'); };
    const report = await executePlan(h.plan, h.inventory, h.deps, h.opts);
    expect(h.byRefs).toEqual([h.old.ref]);
    expect(report.steps[0]!.status).toBe('failed');
    expect(h.provider.revoked).toEqual(['key_2']);
    expect(h.provider.keys.get(h.old.ref)?.active).toBe(true);
    expect(h.host.writes).toEqual([]);
  });

  it('verification failure revokes only the unused replacement and changes no consumers', async () => {
    const h = await fixture();
    h.provider.failVerifyOfNew = true;
    const report = await executePlan(h.plan, h.inventory, h.deps, h.opts);
    expect(h.byRefs).toEqual([h.old.ref]);
    expect(h.host.writes).toEqual([]);
    expect(h.provider.revoked).toEqual(['key_2']);
    expect(h.provider.keys.get(h.old.ref)?.active).toBe(true);
    expect(report.steps[0]!.status).toBe('failed');
  });

  it('dry-run makes no by-reference mutation or prompt', async () => {
    const h = await fixture();
    const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, dryRun: true });
    expect(report.status).toBe('dry-run');
    expect(h.byRefs).toEqual([]);
    expect(h.prompts()).toBe(0);
    expect(h.host.writes).toEqual([]);
    expect(h.provider.revoked).toEqual([]);
  });
});
