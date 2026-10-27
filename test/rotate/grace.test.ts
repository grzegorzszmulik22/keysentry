import { describe, expect, it, vi } from 'vitest';
import { buildInventory, buildPlan, createLogger, createRedactor, serviceKey } from '../../src/core/index.js';
import { executePlan } from '../../src/rotate/engine.js';
import type { EngineDeps, RotateOptions } from '../../src/rotate/engine.js';
import { finishRotation } from '../../src/rotate/grace.js';
import { undoRotation } from '../../src/rotate/undo.js';
import { appSecretProvider } from '../../src/providers/app-secret.js';
import type { JournalEntry, RotationResult } from '../../src/types.js';
import { FakeHttp } from '../helpers/fake-http.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

async function fixture(withGuided = false, locallyGenerated = false) {
  let millis = Date.parse('2026-10-27T12:00:00.000Z');
  const now = () => new Date(millis);
  const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
  provider.now = now;
  const existing = provider.issue();
  const old = locallyGenerated ? { ref: existing.ref, value: 'LocalSigningSecret0123456789abcdef' } : existing;
  const guided = new FakeProvider('anthropic', 'guided', 'sk-ant-api03-');
  const guidedOld = guided.issue();
  const host = new FakeHost('railway');
  host.pendingPolls = 0;
  const secretName = locallyGenerated ? 'SESSION_SECRET' : 'OPENAI_API_KEY';
  const vars = { [secretName]: old.value, ...(withGuided ? { ANTHROPIC_API_KEY: guidedOld.value } : {}) };
  const services = [host.addService('api', vars), host.addService('worker', vars)];
  const fingerprintKey = Buffer.alloc(32, 0x46);
  const inventory = buildInventory([{ host: host.id, services: await Promise.all(services.map(async service => ({ service, vars: await host.readVariables(service) }))) }], fingerprintKey, now());
  const plan = buildPlan(inventory);
  const clusterId = plan.steps.find(step => step.provider === (locallyGenerated ? 'app-secret' : 'openai'))!.clusterId;
  const entries: JournalEntry[] = [];
  const inflight = createFakeInFlight();
  const redactor = createRedactor();
  const lines: string[] = [];
  const log = createLogger({ redactor, json: true, level: 'debug', sink: line => lines.push(line) });
  const sleep = vi.fn(async (ms: number) => { millis += ms; });
  const deps: EngineDeps = {
    hosts: { railway: host }, providers: id => id === 'app-secret' ? appSecretProvider : id === 'anthropic' ? guided : provider,
    providerCtx: { http: new FakeHttp(), credentials: {}, log },
    journal: { async append(e) { entries.push(structuredClone(e)); }, async read() { return [...entries]; } },
    prompt: async () => null, fingerprintKey, redactor, log, inflight, now, sleep,
  };
  const opts: RotateOptions = { dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 10, revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 0, graceMs: 1_000 };
  function event(event: JournalEntry['event'], extra: Partial<JournalEntry> = {}) {
    entries.push({ at: now().toISOString(), planId: plan.id, event, ...extra });
  }
  async function stage() {
    event('plan-start');
    const replacement: RotationResult = await (locallyGenerated ? appSecretProvider : provider).rotate!(old.value, deps.providerCtx);
    await inflight.put(plan.id, `old:${clusterId}`, old.value);
    await inflight.put(plan.id, `new:${clusterId}`, replacement.newValue);
    const data = { newKeyRef: replacement.newKeyRef, oldKeyRef: replacement.oldKeyRef, oldRevoked: false };
    event('value-stored', { clusterId, data });
    event('created', { clusterId, data });
    event('verified', { clusterId, data });
    for (const service of services) {
      await host.writeVariables(service, { [secretName]: replacement.newValue }, { skipDeploy: true });
      event('written', { clusterId, serviceKey: serviceKey(service) });
      const deploymentId = await host.redeploy(service);
      event('redeploy', { serviceKey: serviceKey(service), data: { deploymentId } });
      await host.deploymentStatus(service, deploymentId!);
      event('deploy-result', { serviceKey: serviceKey(service), data: { deploymentId, state: 'success' } });
    }
    event('grace-start', { clusterId, data: { deadline: new Date(millis + opts.graceMs!).toISOString() } });
    event('plan-end', { data: { status: 'grace-pending', pending: true } });
    return replacement;
  }
  return { provider, old, guided, guidedOld, host, services, inventory, plan, clusterId, entries, inflight, deps, opts, sleep, lines, stage, event,
    input: () => ({ plan, inventory, entries: [...entries] }), advance: (ms: number) => { millis += ms; } };
}

describe('rotation grace period', () => {
  it('grace defer leaves old keys valid and reports pendingRevocations', async () => {
    const h = await fixture();
    h.deps.grace = async info => {
      expect(info.clusters).toEqual([{ clusterId: h.clusterId, hint: h.plan.steps[0]!.hint, undoAvailable: true }]);
      expect(h.host.redeploys).toHaveLength(2);
      expect(h.provider.revoked).toHaveLength(0);
      return 'defer';
    };
    const report = await executePlan(h.plan, h.inventory, h.deps, h.opts);
    expect(report.status).toBe('grace-pending');
    expect(report.pendingRevocations).toEqual([{ clusterId: h.clusterId, deadline: '2026-10-27T12:00:01.000Z', undoAvailable: true }]);
    expect(h.provider.keys.get(h.old.ref)?.active).toBe(true);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
    expect(h.entries.some(e => e.event === 'grace-start')).toBe(true);
  });

  it('graceMs without a callback sleeps and re-verifies before revoking', async () => {
    const h = await fixture();
    const verify = vi.spyOn(h.provider, 'verify');
    const report = await executePlan(h.plan, h.inventory, h.deps, h.opts);
    expect(h.sleep).toHaveBeenCalledWith(1_000);
    const replacement = h.host.peek('api', 'OPENAI_API_KEY')!;
    expect(verify.mock.calls.filter(([value]) => value === replacement)).toHaveLength(2);
    expect(report.status).toBe('complete');
    expect(h.provider.revoked).toEqual([h.old.ref]);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(true);
    expect(h.entries.at(-1)?.event).toBe('plan-end');
  });

  it('failed verification after sleeping keeps the old key and in-flight values', async () => {
    const h = await fixture();
    h.deps.sleep = async ms => { h.advance(ms); h.provider.failVerifyOfNew = true; };
    const report = await executePlan(h.plan, h.inventory, h.deps, h.opts);
    expect(report.status).toBe('partial');
    expect(report.steps[0]?.status).toBe('failed');
    expect(h.provider.revoked).toEqual([]);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
  });
});

describe('finishRotation', () => {
  it('finish settles the remaining cluster after a subset undo on shared services', async () => {
    const h = await fixture(true);
    const guidedReplacement = h.guided.issue('guided replacement');
    h.deps.prompt = async () => guidedReplacement.value;
    h.deps.grace = async () => 'defer';
    const deferred = await executePlan(h.plan, h.inventory, h.deps, h.opts);
    expect(deferred.status).toBe('grace-pending');
    expect(deferred.pendingRevocations).toHaveLength(2);
    const restored = await undoRotation({ ...h.input(), clusterIds: [h.clusterId] }, h.deps, h.opts);
    expect(restored.restored).toHaveLength(1);
    expect(restored.unavailable).toEqual([]);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
    h.advance(1_001);
    // Older undo records carried service metadata without clusterIds; their
    // preceding per-cluster intent still identifies the direction's owner.
    const entries = h.entries.map(entry => {
      if (entry.data?.undo !== true || entry.clusterId !== undefined || entry.serviceKey === undefined) return entry;
      const { clusterIds: _clusterIds, ...data } = entry.data;
      return { ...entry, data };
    });
    const finished = await finishRotation({ ...h.input(), entries }, h.deps, h.opts);
    expect(finished.status).toBe('complete');
    expect(h.provider.keys.get(h.old.ref)?.active).toBe(true);
    expect(h.guided.keys.get(h.guidedOld.ref)?.active).toBe(false);
    for (const service of h.services) {
      expect(h.host.peek(service.serviceId, 'OPENAI_API_KEY')).toBe(h.old.value);
      expect(h.host.peek(service.serviceId, 'ANTHROPIC_API_KEY')).toBe(guidedReplacement.value);
    }
    expect(h.inflight.shredded.has(h.plan.id)).toBe(true);
    expect(h.entries.at(-1)?.event).toBe('plan-end');
  });

  it('finish retains the old key for legacy unscoped undo activity when no per-cluster intent was recorded', async () => {
    const h = await fixture();
    await h.stage();
    h.event('written', { serviceKey: serviceKey(h.services[0]!), data: { undo: true } });
    h.event('deploy-result', { serviceKey: serviceKey(h.services[0]!), data: { undo: true, state: 'success' } });
    h.advance(1_001);
    const providers = vi.spyOn(h.deps, 'providers');
    const report = await finishRotation(h.input(), h.deps, h.opts);
    expect(report.status).toBe('partial');
    expect(report.steps[0]?.warnings.join(' ')).toMatch(/resume.*undo/i);
    expect(h.provider.revoked).toEqual([]);
    expect(providers).not.toHaveBeenCalled();
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
  });

  it('finish reports failed and shreds when no step got past creation', async () => {
    const h = await fixture();
    const providers = vi.spyOn(h.deps, 'providers');
    const report = await finishRotation(h.input(), h.deps, h.opts);
    expect(report.status).toBe('failed');
    expect(providers).not.toHaveBeenCalled();
    expect(h.inflight.shredded.has(h.plan.id)).toBe(true);
    expect(h.entries.at(-1)?.data?.pending).toBe(false);
    const slots = vi.spyOn(h.inflight, 'slots');
    const replay = await finishRotation(h.input(), h.deps, h.opts);
    expect(replay.status).toBe('failed');
    expect(slots).not.toHaveBeenCalled();
  });

  it('finish clears the saved error after old-key revocation succeeds', async () => {
    const h = await fixture();
    const replacement = await h.stage();
    h.event('plan-end', { data: { status: 'partial', pending: true, steps: [{ clusterId: h.clusterId, status: 'failed',
      oldKeyRef: h.old.ref, newKeyRef: replacement.newKeyRef, error: 'Old credential revocation failed; check the provider before retrying.', warnings: [] }] } });
    h.advance(1_001);
    const report = await finishRotation(h.input(), h.deps, h.opts);
    expect(report.status).toBe('complete');
    expect(report.steps[0]?.status).toBe('revoked');
    expect(report.steps[0]).not.toHaveProperty('error');
  });

  it('finish retires a local generated signing secret after every consumer deployed and the new value verifies', async () => {
    const h = await fixture(false, true);
    const replacement = await h.stage();
    h.advance(1_001);
    const local = { ...appSecretProvider, verify: vi.fn(appSecretProvider.verify) };
    h.deps.providers = () => local;
    const remoteRevoke = vi.spyOn(h.provider, 'revoke');
    const report = await finishRotation(h.input(), h.deps, h.opts);
    expect(report.status).toBe('complete');
    expect(report.steps[0]?.status).toBe('revoked');
    expect(local.verify).toHaveBeenCalledExactlyOnceWith(replacement.newValue, expect.anything());
    expect(remoteRevoke).not.toHaveBeenCalled();
    expect(h.entries).toContainEqual(expect.objectContaining({ event: 'revoked', clusterId: h.clusterId,
      data: expect.objectContaining({ local: true, oldRevoked: true }) }));
    expect(h.inflight.shredded.has(h.plan.id)).toBe(true);
    for (const service of h.services) expect(h.host.peek(service.serviceId, 'SESSION_SECRET')).toBe(replacement.newValue);
    for (const value of [h.old.value, replacement.newValue]) expect(JSON.stringify({ journal: h.entries, report })).not.toContain(value);
  });

  it('finish completes and shreds when a guided step was skipped before preparing a value', async () => {
    const h = await fixture(true);
    h.deps.grace = async () => 'defer';
    const deferred = await executePlan(h.plan, h.inventory, h.deps, h.opts);
    const skipped = deferred.steps.find(step => step.clusterId !== h.clusterId)!;
    expect(skipped.status).toBe('skipped');
    expect(await h.inflight.get(h.plan.id, `new:${skipped.clusterId}`)).toBeNull();
    h.advance(1_001);
    const guidedVerify = vi.spyOn(h.guided, 'verify');
    const finished = await finishRotation(h.input(), h.deps, h.opts);
    expect(finished.status).toBe('complete');
    expect(finished.steps.find(step => step.clusterId === skipped.clusterId)).toEqual(skipped);
    expect(h.provider.revoked).toEqual([h.old.ref]);
    expect(h.guided.keys.get(h.guidedOld.ref)?.active).toBe(true);
    expect(guidedVerify).not.toHaveBeenCalled();
    expect(h.inflight.shredded.has(h.plan.id)).toBe(true);
  });

  it('finish preserves saved skip warnings and treats a guided fallback intent as unprepared', async () => {
    const h = await fixture(true);
    await h.stage();
    const guidedStep = h.plan.steps.find(step => step.provider === 'anthropic')!;
    const skipped = { clusterId: guidedStep.clusterId, status: 'skipped', warnings: ['The operator skipped the guided replacement.'] };
    h.event('created', { clusterId: guidedStep.clusterId, data: { phase: 'guided-fallback', code: 'GUIDED_ROTATION_REQUIRED' } });
    h.event('plan-end', { data: { status: 'grace-pending', pending: true, steps: [{ clusterId: h.clusterId, status: 'deployed', warnings: [] }, skipped] } });
    h.advance(1_001);
    const report = await finishRotation(h.input(), h.deps, h.opts);
    expect(report.status).toBe('complete');
    expect(report.steps.find(step => step.clusterId === guidedStep.clusterId)).toEqual(skipped);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(true);
  });

  it.each(['stored', 'created'] as const)('finish does not ignore a skipped step with an actual %s replacement', async evidence => {
    const h = await fixture(true);
    await h.stage();
    const guidedStep = h.plan.steps.find(step => step.provider === 'anthropic')!;
    if (evidence === 'stored') await h.inflight.put(h.plan.id, `new:${guidedStep.clusterId}`, 'prepared-guided-replacement-value');
    else h.event('created', { clusterId: guidedStep.clusterId, data: { newKeyRef: 'prepared-guided-key' } });
    h.event('plan-end', { data: { status: 'grace-pending', pending: true, steps: [{ clusterId: h.clusterId, status: 'deployed', warnings: [] }, { clusterId: guidedStep.clusterId, status: 'skipped', warnings: [] }] } });
    h.advance(1_001);
    const report = await finishRotation(h.input(), h.deps, h.opts);
    expect(report.status).toBe('partial');
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
  });

  it('finish revokes after the deadline only when the new key still verifies', async () => {
    const h = await fixture();
    const replacement = await h.stage();
    h.advance(1_001);
    const report = await finishRotation(h.input(), h.deps, h.opts);
    expect(report.status).toBe('complete');
    expect(h.provider.revoked).toEqual([h.old.ref]);
    expect(h.provider.keys.get(replacement.newKeyRef!)?.active).toBe(true);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(true);
    expect(h.entries.some(e => e.event === 'grace-end')).toBe(true);
    expect(h.entries.at(-1)?.event).toBe('plan-end');
    for (const value of [h.old.value, replacement.newValue]) {
      expect(JSON.stringify(h.entries)).not.toContain(value);
      expect(JSON.stringify(report)).not.toContain(value);
      expect(JSON.stringify(h.lines)).not.toContain(value);
    }
  });

  it('finish before the deadline keeps the old key unless early is requested', async () => {
    const h = await fixture();
    await h.stage();
    const report = await finishRotation(h.input(), h.deps, h.opts);
    expect(report.status).toBe('grace-pending');
    expect(report.steps[0]?.warnings.join(' ')).toMatch(/deadline|grace period/i);
    expect(h.provider.revoked).toEqual([]);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
    const finished = await finishRotation(h.input(), h.deps, { ...h.opts, early: true });
    expect(finished.status).toBe('complete');
    expect(h.provider.revoked).toEqual([h.old.ref]);
  });

  it('finish keeps the old key if the new key no longer verifies', async () => {
    const h = await fixture();
    await h.stage();
    h.advance(1_001);
    h.provider.failVerifyOfNew = true;
    const report = await finishRotation(h.input(), h.deps, h.opts);
    expect(report.status).toBe('partial');
    expect(report.steps[0]?.warnings.join(' ')).toMatch(/verif/i);
    expect(h.provider.revoked).toEqual([]);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
  });

  it('finish keeps the old key if any consumer deployment did not succeed', async () => {
    const h = await fixture();
    await h.stage();
    h.advance(1_001);
    h.event('deploy-result', { serviceKey: serviceKey(h.services[1]!), data: { state: 'failed' } });
    const report = await finishRotation(h.input(), h.deps, h.opts);
    expect(report.steps[0]?.warnings.join(' ')).toMatch(/deploy/i);
    expect(h.provider.revoked).toEqual([]);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
  });

  it.each(['intent', 'restored', 'new-revoked'] as const)('finish retains the old key without remote calls while undo is unfinished at %s', async phase => {
    const h = await fixture();
    const replacement = await h.stage();
    h.advance(1_001);
    h.event('resume', { clusterId: h.clusterId, data: { undo: true } });
    if (phase !== 'intent') {
      for (const service of h.services) {
        await h.host.writeVariables(service, { OPENAI_API_KEY: h.old.value }, { skipDeploy: true });
        h.event('written', { clusterId: h.clusterId, serviceKey: serviceKey(service), data: { undo: true } });
        h.event('deploy-result', { serviceKey: serviceKey(service), data: { state: 'success', undo: true } });
      }
    }
    if (phase === 'new-revoked') {
      await h.provider.revoke(replacement.newKeyRef!, h.deps.providerCtx);
      h.event('revoked', { clusterId: h.clusterId, data: { keyRef: replacement.newKeyRef, undo: true } });
    }
    const originalRevocations = [...h.provider.revoked];
    const providers = vi.spyOn(h.deps, 'providers');
    const verify = vi.spyOn(h.provider, 'verify');
    const write = vi.spyOn(h.host, 'writeVariables');
    const read = vi.spyOn(h.host, 'readVariables');
    const redeploy = vi.spyOn(h.host, 'redeploy');
    const report = await finishRotation(h.input(), h.deps, { ...h.opts, early: true });
    expect(report.status).toBe('partial');
    expect(report.steps[0]?.warnings.join(' ')).toMatch(/resume.*undo|undo.*resume/i);
    expect(report.pendingRevocations).toEqual([{ clusterId: h.clusterId, deadline: '2026-10-27T12:00:01.000Z', undoAvailable: true }]);
    expect(h.provider.revoked).toEqual(originalRevocations);
    expect(h.provider.keys.get(h.old.ref)?.active).toBe(true);
    expect(providers).not.toHaveBeenCalled();
    expect(verify).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
    expect(read).not.toHaveBeenCalled();
    expect(redeploy).not.toHaveBeenCalled();
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
  });

  it('finish returns a legacy completed plan without provider, host or in-flight calls', async () => {
    const h = await fixture();
    await h.stage();
    h.event('revoked', { clusterId: h.clusterId, data: { oldKeyRef: h.old.ref, oldRevoked: true } });
    h.event('plan-end', { data: { dryRun: false, steps: [{ clusterId: h.clusterId, status: 'revoked', warnings: [] }] } });
    const providers = vi.spyOn(h.deps, 'providers');
    const slots = vi.spyOn(h.inflight, 'slots');
    const read = vi.spyOn(h.host, 'readVariables');
    const append = vi.spyOn(h.deps.journal, 'append');
    const report = await finishRotation(h.input(), h.deps, h.opts);
    expect(report.status).toBe('complete');
    expect(providers).not.toHaveBeenCalled();
    expect(slots).not.toHaveBeenCalled();
    expect(read).not.toHaveBeenCalled();
    expect(append).not.toHaveBeenCalled();
  });

  it('finish skips a second revoke after a crash after-revoke', async () => {
    const h = await fixture();
    await h.stage();
    h.advance(1_001);
    const sentinel = new Error('simulated crash');
    h.deps.crashHook = point => { if (point === 'after-revoke') throw sentinel; };
    let thrown: unknown;
    const before = h.entries.length;
    try { await finishRotation(h.input(), h.deps, h.opts); } catch (error) { thrown = error; }
    expect(thrown).toBe(sentinel);
    expect(h.entries.slice(before).some(e => e.event === 'revoked')).toBe(false);
    expect(h.provider.revoked).toEqual([h.old.ref]);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
    delete h.deps.crashHook;
    const report = await finishRotation(h.input(), h.deps, h.opts);
    expect(report.status).toBe('complete');
    expect(h.provider.revoked).toEqual([h.old.ref]);
    expect(h.entries.some(e => e.event === 'revoked' && e.data?.alreadyRevoked === true)).toBe(true);
  });

  it.each(['after-verify', 'before-revoke', 'after-revoke'] as const)('finish preserves hook error identity at %s and records nothing after it', async point => {
    const h = await fixture();
    await h.stage();
    h.advance(1_001);
    const thrown = { simulated: point };
    let entriesAtCrash = -1;
    h.deps.crashHook = current => { if (current === point) { entriesAtCrash = h.entries.length; throw thrown; } };
    let actual: unknown;
    try { await finishRotation(h.input(), h.deps, h.opts); } catch (error) { actual = error; }
    expect(actual).toBe(thrown);
    expect(h.entries).toHaveLength(entriesAtCrash);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
  });

  it('finish is a dry run unless dryRun is explicitly false', async () => {
    const h = await fixture();
    await h.stage();
    h.advance(1_001);
    const verify = vi.spyOn(h.provider, 'verify');
    const report = await finishRotation(h.input(), h.deps, { ...h.opts, dryRun: true });
    expect(report.status).toBe('dry-run');
    expect(verify).not.toHaveBeenCalled();
    expect(h.provider.revoked).toEqual([]);
  });
});
