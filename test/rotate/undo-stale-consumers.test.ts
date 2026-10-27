import { expect, test } from 'vitest';
import { buildInventory, buildPlan, createLogger, createRedactor, fingerprint, serviceKey } from '../../src/core/index.js';
import type { EngineDeps, RotateOptions } from '../../src/rotate/engine.js';
import { undoRotation } from '../../src/rotate/undo.js';
import type { JournalEntry } from '../../src/types.js';
import { FakeHttp } from '../helpers/fake-http.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

async function deferredRotation() {
  let millis = Date.parse('2026-10-27T12:00:00.000Z');
  const now = () => new Date(millis);
  const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
  provider.now = now;
  const old = provider.issue();
  const host = new FakeHost('railway');
  host.pendingPolls = 0;
  const services = [host.addService('api', { OPENAI_API_KEY: old.value }), host.addService('worker', { OPENAI_API_KEY: old.value })];
  const fingerprintKey = Buffer.alloc(32, 0x46);
  const scan = async () => buildInventory([{ host: host.id, services: await Promise.all(services.map(async service => ({ service, vars: await host.readVariables(service) }))) }], fingerprintKey, now());
  const inventory = await scan();
  const plan = buildPlan(inventory);
  const clusterId = plan.steps[0]!.clusterId;
  const entries: JournalEntry[] = [];
  const inflight = createFakeInFlight();
  const redactor = createRedactor();
  const log = createLogger({ redactor, sink: () => {} });
  const deps: EngineDeps = {
    hosts: { railway: host }, providers: () => provider, providerCtx: { http: new FakeHttp(), credentials: {}, log },
    journal: { async append(e) { entries.push(structuredClone(e)); }, async read() { return [...entries]; } },
    prompt: async () => null, fingerprintKey, redactor, log, inflight, now, sleep: async (ms: number) => { millis += ms; },
  };
  const opts: RotateOptions = { dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 10,
    revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 0, graceMs: 1_000 };
  const event = (name: JournalEntry['event'], extra: Partial<JournalEntry> = {}) => entries.push({ at: now().toISOString(), planId: plan.id, event: name, ...extra });
  // Same journal shape the engine writes for a rotation whose grace decision was "defer".
  event('plan-start');
  const replacement = await provider.rotate(old.value, deps.providerCtx);
  await inflight.put(plan.id, `old:${clusterId}`, old.value);
  await inflight.put(plan.id, `new:${clusterId}`, replacement.newValue);
  const data = { newKeyRef: replacement.newKeyRef, oldKeyRef: replacement.oldKeyRef, oldRevoked: false, newFingerprint: fingerprint(replacement.newValue, fingerprintKey) };
  event('value-stored', { clusterId, data }); event('created', { clusterId, data }); event('verified', { clusterId, data });
  for (const service of services) {
    await host.writeVariables(service, { OPENAI_API_KEY: replacement.newValue }, { skipDeploy: true });
    event('written', { clusterId, serviceKey: serviceKey(service) });
    const deploymentId = await host.redeploy(service);
    event('redeploy', { serviceKey: serviceKey(service), data: { deploymentId } });
    event('deploy-result', { serviceKey: serviceKey(service), data: { deploymentId, state: 'success' } });
  }
  event('grace-start', { clusterId, data: { deadline: new Date(millis + 1_000).toISOString() } });
  event('plan-end', { data: { status: 'grace-pending', pending: true } });
  return { provider, old, replacement, host, services, plan, entries, deps, opts, scan, advance: (ms: number) => { millis += ms; } };
}

test('undo does not overwrite a consumer that moved on to a newer key', async () => {
  const h = await deferredRotation();
  // Later, the operator rotated again by hand: both consumers now hold a third key.
  const newer = h.provider.issue('manual-newer');
  for (const service of h.services) await h.host.writeVariables(service, { OPENAI_API_KEY: newer.value }, { skipDeploy: true });

  const report = await undoRotation({ plan: h.plan, inventory: await h.scan(), entries: [...h.entries] }, h.deps, h.opts);
  // Correct behaviour: the newer value stays; the old (rotated-away) key is not written back.
  expect(h.host.peek('api', 'OPENAI_API_KEY')).toBe(newer.value);
  expect(report.unavailable[0]?.reason).toBe(`A newer value is in place at ${serviceKey(h.services[0]!)}; keysentry won't overwrite it.`);
  expect(h.provider.revoked).toEqual([]);
});

async function sealedWorker() {
  const h = await deferredRotation();
  h.host.addService('worker', { OPENAI_API_KEY: h.replacement.newValue }, ['OPENAI_API_KEY']);
  h.plan.steps[0]!.consumers.find(consumer => consumer.service.serviceId === 'worker')!.sealed = true;
  return h;
}

test('undo preserves a sealed consumer touched by a later plan in the full journal', async () => {
  const h = await sealedWorker();
  const newer = h.provider.issue('later-plan');
  await h.host.writeVariables(h.services[1]!, { OPENAI_API_KEY: newer.value }, { skipDeploy: true });
  h.entries.push({ at: '2026-10-27T12:01:00.000Z', planId: 'plan-later', event: 'written',
    clusterId: 'later-cluster', serviceKey: serviceKey(h.services[1]!), data: { variableNames: ['OPENAI_API_KEY'] } });
  h.host.writes.length = 0;
  const report = await undoRotation({ plan: h.plan, inventory: await h.scan(),
    entries: h.entries.filter(entry => entry.planId === h.plan.id) }, h.deps, h.opts);
  expect(report.restored).toEqual([]);
  expect(report.unavailable[0]?.reason).toContain(serviceKey(h.services[1]!));
  expect(h.host.writes).toEqual([]);
  expect(h.host.peek('worker', 'OPENAI_API_KEY')).toBe(newer.value);
  expect(h.provider.revoked).toEqual([]);
});

test('a later plan writing another variable does not prevent restoring a sealed consumer', async () => {
  const h = await sealedWorker();
  h.entries.push({ at: '2026-10-27T12:00:59.000Z', planId: 'plan-later', event: 'plan-start', data: { dryRun: false } });
  h.entries.push({ at: '2026-10-27T12:01:00.000Z', planId: 'plan-later', event: 'written',
    serviceKey: serviceKey(h.services[1]!), data: { variableNames: ['OTHER_TOKEN'] } });
  h.entries.push({ at: '2026-10-27T12:01:01.000Z', planId: 'plan-later', event: 'plan-end' });
  const report = await undoRotation({ plan: h.plan, inventory: await h.scan(), entries: [...h.entries] }, h.deps, h.opts);
  expect(report.unavailable).toEqual([]);
  expect(h.host.peek('worker', 'OPENAI_API_KEY')).toBe(h.old.value);
});

test('a later interrupted dry run does not prevent restoring a sealed consumer', async () => {
  const h = await sealedWorker();
  h.entries.push({ at: '2026-10-27T12:01:00.000Z', planId: 'plan-later', event: 'plan-start', data: { dryRun: true } });
  const report = await undoRotation({ plan: h.plan, inventory: await h.scan(), entries: [...h.entries] }, h.deps, h.opts);
  expect(report.unavailable).toEqual([]);
  expect(h.host.peek('worker', 'OPENAI_API_KEY')).toBe(h.old.value);
});

test('undo refuses a sealed consumer when a later write omitted variable names', async () => {
  const h = await sealedWorker();
  h.entries.push({ at: '2026-10-27T12:01:00.000Z', planId: 'plan-later', event: 'written',
    serviceKey: serviceKey(h.services[1]!) });
  h.host.writes.length = 0;
  const report = await undoRotation({ plan: h.plan, inventory: await h.scan(), entries: [...h.entries] }, h.deps, h.opts);
  expect(report.restored).toEqual([]);
  expect(h.host.writes).toEqual([]);
  expect(h.provider.revoked).toEqual([]);
});

test('undo refuses a sealed consumer without its own recorded forward write', async () => {
  const h = await sealedWorker();
  const key = serviceKey(h.services[1]!);
  h.entries.splice(h.entries.findIndex(entry => entry.event === 'written' && entry.serviceKey === key), 1);
  h.host.writes.length = 0;
  const report = await undoRotation({ plan: h.plan, inventory: await h.scan(), entries: [...h.entries] }, h.deps, h.opts);
  expect(report.restored).toEqual([]);
  expect(h.host.writes).toEqual([]);
});

test('undo retains a sealed consumer after a later plan has an uncertain write failure', async () => {
  const h = await sealedWorker();
  h.entries.push({ at: '2026-10-27T12:01:00.000Z', planId: 'plan-later', event: 'failed',
    serviceKey: serviceKey(h.services[1]!), data: { phase: 'write', partialWritePossible: true } });
  h.host.writes.length = 0;
  const report = await undoRotation({ plan: h.plan, inventory: await h.scan(), entries: [...h.entries] }, h.deps, h.opts);
  expect(report.restored).toEqual([]);
  expect(h.host.writes).toEqual([]);
  expect(h.provider.revoked).toEqual([]);
});

test('undo retains a sealed consumer when a later unfinished plan may have an unjournalled write', async () => {
  const h = await sealedWorker();
  const newer = h.provider.issue('later-plan');
  h.entries.push({ at: '2026-10-27T12:01:00.000Z', planId: 'plan-later', event: 'plan-start', data: { dryRun: false } });
  h.entries.push({ at: '2026-10-27T12:01:01.000Z', planId: 'plan-later', event: 'created', clusterId: 'new-cluster' });
  // The later process stopped after the host applied its write, before its written record.
  await h.host.writeVariables(h.services[1]!, { OPENAI_API_KEY: newer.value }, { skipDeploy: true });
  h.host.writes.length = 0;
  const report = await undoRotation({ plan: h.plan, inventory: await h.scan(),
    entries: h.entries.filter(entry => entry.planId === h.plan.id) }, h.deps, h.opts);
  expect(report.restored).toEqual([]);
  expect(h.host.writes).toEqual([]);
  expect(h.host.peek('worker', 'OPENAI_API_KEY')).toBe(newer.value);
  expect(h.provider.revoked).toEqual([]);
});

test('undo refuses sealed restoration when the full journal cannot be read', async () => {
  const h = await sealedWorker();
  h.deps.journal.read = async () => { throw new Error('journal unavailable'); };
  h.host.writes.length = 0;
  const report = await undoRotation({ plan: h.plan, inventory: await h.scan(), entries: [...h.entries] }, h.deps, h.opts);
  expect(report.restored).toEqual([]);
  expect(h.host.writes).toEqual([]);
  expect(h.provider.revoked).toEqual([]);
});

test('undo uses the journalled fingerprint even when the replacement value is unavailable', async () => {
  const h = await deferredRotation();
  const get = h.deps.inflight!.get.bind(h.deps.inflight);
  h.deps.inflight!.get = async (planId, slot) => slot.startsWith('new:') ? null : get(planId, slot);
  const report = await undoRotation({ plan: h.plan, inventory: await h.scan(), entries: [...h.entries] }, h.deps, h.opts);
  expect(report.unavailable).toEqual([]);
  expect(h.host.peek('api', 'OPENAI_API_KEY')).toBe(h.old.value);
});

test('undo compares a current value to the journalled replacement fingerprint', async () => {
  const h = await deferredRotation();
  const newer = h.provider.issue('manual-newer');
  const clusterId = h.plan.steps[0]!.clusterId;
  // A substituted stored value cannot become authorization to overwrite a later consumer value.
  await h.deps.inflight!.put(h.plan.id, `new:${clusterId}`, newer.value);
  for (const service of h.services) await h.host.writeVariables(service, { OPENAI_API_KEY: newer.value }, { skipDeploy: true });
  h.host.writes.length = 0;
  const report = await undoRotation({ plan: h.plan, inventory: await h.scan(), entries: [...h.entries] }, h.deps, h.opts);
  expect(report.restored).toEqual([]);
  expect(h.host.writes).toEqual([]);
  expect(h.host.peek('api', 'OPENAI_API_KEY')).toBe(newer.value);
});

test('retrying an interrupted undo does not rewrite an already restored consumer', async () => {
  const h = await deferredRotation();
  const stopped = new Error('simulated exit');
  h.deps.crashHook = point => { if (point === 'after-write') throw stopped; };
  await expect(undoRotation({ plan: h.plan, inventory: await h.scan(), entries: [...h.entries] }, h.deps, h.opts)).rejects.toBe(stopped);
  expect(h.host.peek('api', 'OPENAI_API_KEY')).toBe(h.old.value);
  delete h.deps.crashHook;
  h.host.writes.length = 0;
  const report = await undoRotation({ plan: h.plan, inventory: await h.scan(), entries: [...h.entries] }, h.deps, h.opts);
  expect(report.unavailable).toEqual([]);
  expect(h.host.writes.map(write => write.serviceId)).toEqual(['worker']);
  expect(h.host.peek('worker', 'OPENAI_API_KEY')).toBe(h.old.value);
  expect(h.provider.revoked).toEqual([h.replacement.newKeyRef]);
});
