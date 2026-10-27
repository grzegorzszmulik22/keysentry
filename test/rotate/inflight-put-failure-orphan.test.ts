import { expect, test } from 'vitest';
import { buildInventory, buildPlan, createLogger, createRedactor } from '../../src/core/index.js';
import { executePlan, type EngineDeps, type RotateOptions } from '../../src/rotate/engine.js';
import { resumeRotation } from '../../src/rotate/resume.js';
import type { JournalEntry, ProviderAdapter } from '../../src/types.js';
import { FakeHttp } from '../helpers/fake-http.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

async function fixture() {
  const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
  const old = provider.issue();
  const host = new FakeHost('railway');
  host.pendingPolls = 0;
  const service = host.addService('api', { OPENAI_API_KEY: old.value });
  const fingerprintKey = Buffer.alloc(32, 5);
  const inventory = buildInventory([{ host: host.id, services: [{ service, vars: await host.readVariables(service) }] }], fingerprintKey, new Date());
  const plan = buildPlan(inventory);
  const inner = createFakeInFlight();
  const inflight = { ...inner, async put(planId: string, slot: string, value: string) {
    if (slot.startsWith('new:')) throw new Error('Unable to store temporary rotation values.');
    return inner.put(planId, slot, value);
  } };
  const entries: JournalEntry[] = [];
  const lines: string[] = [];
  const redactor = createRedactor();
  const log = createLogger({ redactor, sink: line => { lines.push(line); } });
  const deps: EngineDeps = {
    hosts: { railway: host }, providers: () => provider, providerCtx: { http: new FakeHttp(), credentials: {}, log },
    journal: { async append(entry) { entries.push(structuredClone(entry)); }, async read() { return [...entries]; } },
    prompt: async () => null, fingerprintKey, redactor, log, inflight, sleep: async () => {},
  };
  const opts: RotateOptions = { dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 10,
    revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 0 };
  return { provider, old, host, inventory, plan, inner, inflight, entries, lines, deps, opts };
}

// Retains the review probe's create-then-put-failure scenario, with stronger cleanup assertions.
test('a replacement created before the in-flight store fails is cleaned up or reported, never silently orphaned', async () => {
  const h = await fixture();
  const report = await executePlan(h.plan, h.inventory, h.deps, h.opts);
  const live = [...h.provider.keys.values()].filter(key => key.active).map(key => key.ref);
  const created = [...h.provider.keys.values()].find(key => key.name.startsWith('rotated'))!;
  const recorded = JSON.stringify({ report, entries: h.entries }).includes(created.ref);
  expect(report.steps[0]!.error).toMatch(/no consumer was changed/);
  expect(h.host.peek('api', 'OPENAI_API_KEY')).toBe(h.old.value);
  expect(live.length === 1 || recorded).toBe(true);
  expect(h.provider.revoked).toEqual([created.ref]);
  expect(h.entries).toContainEqual(expect.objectContaining({ event: 'revoked', data: { keyRef: created.ref, cleanup: true } }));
  expect(report.status).toBe('failed');
  expect(h.inflight.shredded.has(h.plan.id)).toBe(true);
});

test.each([
  { cleanup: 'rejects', stopOnFirstFailure: false },
  { cleanup: 'rejects', stopOnFirstFailure: true },
  { cleanup: 'is unavailable', stopOnFirstFailure: false },
  { cleanup: 'is unavailable', stopOnFirstFailure: true },
])('storage failure retains recovery data and reports the new key when cleanup $cleanup (stop=$stopOnFirstFailure)', async ({ cleanup, stopOnFirstFailure }) => {
  const h = await fixture();
  if (cleanup === 'rejects') h.provider.revoke = async () => { throw new Error('provider diagnostic must remain private'); };
  else h.deps.providers = () => new Proxy(h.provider, { get(target, name) {
    const value: unknown = Reflect.get(target, name);
    return name === 'revoke' ? undefined : typeof value === 'function' ? value.bind(target) : value;
  } }) as ProviderAdapter;
  // A failed put must not destroy any recovery data already present for this plan.
  await h.inner.put(h.plan.id, `old:${h.plan.steps[0]!.clusterId}`, h.old.value);
  const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, stopOnFirstFailure });
  const created = [...h.provider.keys.values()].find(key => key.name.startsWith('rotated'))!;
  expect(report.status).toBe('partial');
  expect(report.orphanSuspects).toEqual([{ clusterId: h.plan.steps[0]!.clusterId, provider: 'openai', keyRef: created.ref }]);
  expect(h.entries).toContainEqual(expect.objectContaining({ event: 'orphan-suspected', clusterId: h.plan.steps[0]!.clusterId,
    data: expect.objectContaining({ keyRef: created.ref }) }));
  expect(created.active).toBe(true);
  expect(h.provider.keys.get(h.old.ref)!.active).toBe(true);
  expect(h.host.writes).toEqual([]);
  expect(h.host.redeploys).toEqual([]);
  expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
  expect(await h.inflight.get(h.plan.id, `old:${h.plan.steps[0]!.clusterId}`)).toBe(h.old.value);
  expect(h.entries.at(-1)?.data?.status).toBe('partial');
  const output = JSON.stringify({ report, entries: h.entries, lines: h.lines });
  expect(output).not.toContain(created.value);
  expect(output).not.toContain(h.old.value);
  expect(output).not.toContain('provider diagnostic must remain private');
});

test('a failed companion put retains the stored replacement when unused-key cleanup fails', async () => {
  const h = await fixture();
  const rotate = h.provider.rotate.bind(h.provider);
  h.provider.rotate = async (...args) => ({ ...await rotate(...args), companions: { EXTRA_TOKEN: 'one-time-private-companion-value' } });
  h.inflight.put = async (planId, slot, value) => {
    if (slot.startsWith('companion:')) throw new Error('companion storage unavailable');
    return h.inner.put(planId, slot, value);
  };
  h.provider.revoke = async () => { throw new Error('cleanup unavailable'); };
  const report = await executePlan(h.plan, h.inventory, h.deps, h.opts);
  const created = [...h.provider.keys.values()].find(key => key.name.startsWith('rotated'))!;
  expect(report.status).toBe('partial');
  expect(report.orphanSuspects?.[0]?.keyRef).toBe(created.ref);
  expect(await h.inflight.get(h.plan.id, `new:${h.plan.steps[0]!.clusterId}`)).toBe(created.value);
  expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
  expect(h.host.writes).toEqual([]);
  expect(JSON.stringify({ report, entries: h.entries, lines: h.lines })).not.toContain('one-time-private-companion-value');
  const resumed = await resumeRotation({ plan: h.plan, inventory: h.inventory, entries: [...h.entries] }, h.deps, h.opts);
  expect(resumed.status).toBe('partial');
  expect(resumed.orphanSuspects?.[0]?.keyRef).toBe(created.ref);
  expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
  expect(h.host.writes).toEqual([]);
  expect(h.provider.keys.size).toBe(2);
});

test('an in-flight failure with a guided-fallback code still cleans the already created key', async () => {
  const h = await fixture();
  h.inflight.put = async () => { throw Object.assign(new Error('temporary storage unavailable'), { code: 'GUIDED_ROTATION_REQUIRED' }); };
  const report = await executePlan(h.plan, h.inventory, h.deps, h.opts);
  const created = [...h.provider.keys.values()].find(key => key.name.startsWith('rotated'))!;
  expect(created.active).toBe(false);
  expect(h.provider.revoked).toEqual([created.ref]);
  expect(report.steps[0]!.newKeyRef).toBe(created.ref);
  expect(h.entries.some(entry => entry.data?.phase === 'guided-fallback')).toBe(false);
  expect(h.host.writes).toEqual([]);
});

test('a failed preparation journal cannot prevent cleanup after the in-flight put fails', async () => {
  const h = await fixture();
  const append = h.deps.journal.append.bind(h.deps.journal);
  h.deps.journal.append = async entry => {
    if (entry.event === 'created') throw new Error('private journal storage diagnostic');
    return append(entry);
  };
  await expect(executePlan(h.plan, h.inventory, h.deps, h.opts)).rejects.toThrow('Unable to record rotation journal; execution stopped.');
  const created = [...h.provider.keys.values()].find(key => key.name.startsWith('rotated'))!;
  expect(created.active).toBe(false);
  expect(h.provider.revoked).toEqual([created.ref]);
  expect(h.provider.keys.get(h.old.ref)!.active).toBe(true);
  expect(h.host.writes).toEqual([]);
  expect(h.host.redeploys).toEqual([]);
  expect(h.entries).toContainEqual(expect.objectContaining({ event: 'revoked', data: { keyRef: created.ref, cleanup: true } }));
  expect(h.entries.some(entry => entry.event === 'plan-end')).toBe(false);
});

test('failed preparation journalling and cleanup retain recovery data and record the known orphan', async () => {
  const h = await fixture();
  // A rejected durability acknowledgement can leave a value in the store.
  h.inflight.put = async (planId, slot, value) => {
    await h.inner.put(planId, slot, value);
    throw new Error('private temporary storage diagnostic');
  };
  h.provider.revoke = async () => { throw new Error('private cleanup diagnostic'); };
  const append = h.deps.journal.append.bind(h.deps.journal);
  h.deps.journal.append = async entry => {
    if (entry.event === 'created') throw new Error('private journal storage diagnostic');
    return append(entry);
  };
  await expect(executePlan(h.plan, h.inventory, h.deps, h.opts)).rejects.toThrow('Unable to record rotation journal; execution stopped.');
  const created = [...h.provider.keys.values()].find(key => key.name.startsWith('rotated'))!;
  expect(created.active).toBe(true);
  expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
  expect(await h.inner.get(h.plan.id, `new:${h.plan.steps[0]!.clusterId}`)).toBe(created.value);
  expect(h.entries).toContainEqual(expect.objectContaining({ event: 'orphan-suspected', data: expect.objectContaining({ keyRef: created.ref }) }));
  expect(h.host.writes).toEqual([]);
  expect(h.host.redeploys).toEqual([]);
  expect(h.entries.some(entry => entry.event === 'plan-end')).toBe(false);
  const output = JSON.stringify({ entries: h.entries, lines: h.lines });
  expect(output).not.toContain(created.value);
  expect(output).not.toContain('private cleanup diagnostic');
  expect(output).not.toContain('private journal storage diagnostic');
});

test.each([false, true])('resume retains a recorded live orphan after storage and cleanup fail (stop=%s)', async stopOnFirstFailure => {
  const h = await fixture();
  h.provider.revoke = async () => { throw new Error('cleanup unavailable'); };
  await h.inner.put(h.plan.id, `old:${h.plan.steps[0]!.clusterId}`, h.old.value);
  const opts = { ...h.opts, stopOnFirstFailure };
  const first = await executePlan(h.plan, h.inventory, h.deps, opts);
  const created = [...h.provider.keys.values()].find(key => key.name.startsWith('rotated'))!;
  expect(first.status).toBe('partial');
  for (let attempt = 0; attempt < 2; attempt++) {
    const resumed = await resumeRotation({ plan: h.plan, inventory: h.inventory, entries: [...h.entries] }, h.deps, opts);
    expect(resumed.status).toBe('partial');
    expect(resumed.orphanSuspects).toEqual([{ clusterId: h.plan.steps[0]!.clusterId, provider: 'openai', keyRef: created.ref }]);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
    expect(await h.inner.get(h.plan.id, `old:${h.plan.steps[0]!.clusterId}`)).toBe(h.old.value);
    expect(h.provider.keys.size).toBe(2);
    expect(created.active).toBe(true);
    expect(h.host.writes).toEqual([]);
  }
});

test.each([false, true])('resume does not treat a journalled successful orphan cleanup as a live orphan (stop=%s)', async stopOnFirstFailure => {
  const h = await fixture();
  const revoke = h.provider.revoke.bind(h.provider);
  h.provider.revoke = async () => { throw new Error('cleanup unavailable'); };
  const opts = { ...h.opts, stopOnFirstFailure };
  await executePlan(h.plan, h.inventory, h.deps, opts);
  const created = [...h.provider.keys.values()].find(key => key.name.startsWith('rotated'))!;
  await revoke(created.ref, h.deps.providerCtx);
  await h.deps.journal.append({ at: new Date().toISOString(), planId: h.plan.id, clusterId: h.plan.steps[0]!.clusterId,
    event: 'revoked', data: { cleanup: true, keyRef: created.ref } });
  const resumed = await resumeRotation({ plan: h.plan, inventory: h.inventory, entries: [...h.entries] }, h.deps, opts);
  expect(resumed.orphanSuspects ?? []).toEqual([]);
  expect(resumed.status).toBe('failed');
  expect(h.inflight.shredded.has(h.plan.id)).toBe(true);
  expect(h.provider.keys.size).toBe(2);
  expect(h.host.writes).toEqual([]);
});
