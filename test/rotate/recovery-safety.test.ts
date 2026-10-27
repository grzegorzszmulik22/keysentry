import { expect, test } from 'vitest';
import { executePlan, resumeRotation, undoRotation } from '../../src/rotate/index.js';
import { recoveryFixture } from './recovery-fixture.js';
import { appSecretProvider } from '../../src/providers/app-secret.js';

test('resume repairs a reverted consumer and starts a new deployment for its rewritten batch', async () => {
  const f = await recoveryFixture();
  const stop = {};
  f.deps.crashHook = point => { if (point === 'after-deploy-result') throw stop; };
  await expect(executePlan(f.plan, f.inv, f.deps, f.opts)).rejects.toBe(stop);
  const replacement = f.host.peek('api', 'OPENAI_API_KEY');
  await f.host.writeVariables(f.services[0]!, { OPENAI_API_KEY: f.old.value }, { skipDeploy: true });
  delete f.deps.crashHook;
  const writes = f.host.writes.length;
  const report = await resumeRotation({ plan: f.plan, inventory: f.inv, entries: [...f.journal.entries] }, f.deps, f.opts);
  expect(f.host.peek('api', 'OPENAI_API_KEY')).toBe(replacement);
  expect(f.host.writes).toHaveLength(writes + 1);
  expect(f.host.redeploys.filter(id => id === 'api')).toHaveLength(2);
  expect(report.status).toBe('complete');
});

test('resume of a fully undone plan returns its final status without calls', async () => {
  const f = await recoveryFixture();
  f.deps.grace = async () => 'defer';
  await executePlan(f.plan, f.inv, f.deps, { ...f.opts, graceMs: 100 });
  await undoRotation({ plan: f.plan, inventory: f.inv, entries: [...f.journal.entries] }, f.deps, f.opts);
  expect(f.inflight.shredded.has(f.plan.id)).toBe(true);
  const before = [...f.trace];
  const report = await resumeRotation({ plan: f.plan, inventory: f.inv, entries: [...f.journal.entries] }, f.deps, f.opts);
  expect(report.status).toBe('complete');
  expect(f.trace).toEqual(before);
});

test('resume keeps old keys when an undo was interrupted after restoring a consumer', async () => {
  const f = await recoveryFixture();
  f.deps.grace = async () => 'defer';
  await executePlan(f.plan, f.inv, f.deps, { ...f.opts, graceMs: 100 });
  const stop = {};
  f.deps.crashHook = point => { if (point === 'after-write') throw stop; };
  await expect(undoRotation({ plan: f.plan, inventory: f.inv, entries: [...f.journal.entries] }, f.deps, f.opts)).rejects.toBe(stop);
  delete f.deps.crashHook;
  const before = f.trace.length;
  const report = await resumeRotation({ plan: f.plan, inventory: f.inv, entries: [...f.journal.entries] }, f.deps, f.opts);
  expect(report.status).toBe('partial');
  expect(report.steps.some(step => step.warnings.some(warning => /undo.*interrupt|interrupt.*undo/i.test(warning)))).toBe(true);
  expect(f.trace.slice(before).some(event => /^(rotate|write|redeploy|revoke):/.test(event))).toBe(false);
  expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
  expect(f.inflight.shredded.has(f.plan.id)).toBe(false);
});

test('grace-end follows the revocations it settles', async () => {
  const f = await recoveryFixture();
  f.deps.grace = async () => 'revoke';
  await executePlan(f.plan, f.inv, f.deps, { ...f.opts, graceMs: 100 });
  for (const step of f.plan.steps) {
    const events = f.journal.entries.filter(entry => entry.clusterId === step.clusterId).map(entry => entry.event);
    expect(events.lastIndexOf('grace-end')).toBeGreaterThan(events.lastIndexOf('revoked'));
  }
});

test('grace can undo within one run without a persistent in-flight store', async () => {
  const f = await recoveryFixture();
  delete f.deps.inflight;
  f.deps.grace = async info => { expect(info.clusters.every(cluster => cluster.undoAvailable)).toBe(true); return 'undo'; };
  const report = await executePlan(f.plan, f.inv, f.deps, { ...f.opts, graceMs: 100 });
  expect(report.status).toBe('complete');
  for (const service of f.services) {
    expect(f.host.peek(service.serviceId, 'OPENAI_API_KEY')).toBe(f.old.value);
    expect(f.host.peek(service.serviceId, 'SESSION_SECRET')).toBe(f.oldGenerated.value);
  }
});

test('a consumer write that applies values then throws retains the recovery store', async () => {
  const f = await recoveryFixture();
  const write = f.host.writeVariables.bind(f.host);
  f.host.writeVariables = async (service, values, opts) => { await write(service, values, opts); throw new Error('connection closed after write'); };
  const report = await executePlan(f.plan, f.inv, f.deps, f.opts);
  expect(report.status).toBe('partial');
  expect(f.host.peek('api', 'OPENAI_API_KEY')).not.toBe(f.old.value);
  expect(f.inflight.shredded.has(f.plan.id)).toBe(false);
  expect(f.provider.revoked).toEqual([]);
  expect(await f.inflight.get(f.plan.id, `new:${f.clusterId}`)).not.toBeNull();
});

test('crash during emergency atomic delivery exits before recovery journals or other host effects', async () => {
  const f = await recoveryFixture();
  f.plan.steps = [f.plan.steps[0]!];
  f.plan.steps[0]!.method = 'atomic-roll';
  const append = f.journal.append.bind(f.journal);
  f.journal.append = async entry => { if (entry.event === 'created') throw new Error('journal stopped'); await append(entry); };
  const stop = {};
  let trace: string[] = [];
  f.deps.crashHook = point => { if (point === 'after-write') { trace = [...f.trace]; throw stop; } };
  await expect(executePlan(f.plan, f.inv, f.deps, f.opts)).rejects.toBe(stop);
  expect(f.trace).toEqual(trace);
  expect(f.host.writes).toHaveLength(1);
  expect(f.host.redeploys).toHaveLength(0);
  expect(f.provider.revoked).toHaveLength(0);
});

test('orphan detection reports a plain failure when a provider lookup error contains the old value', async () => {
  const f = await recoveryFixture();
  const stop = {};
  f.deps.crashHook = point => { if (point === 'after-create') throw stop; };
  await expect(executePlan(f.plan, f.inv, f.deps, f.opts)).rejects.toBe(stop);
  delete f.deps.crashHook;
  f.provider.resolveKeyRef = async () => { throw new Error(`lookup failed for ${f.old.value}`); };
  const report = await resumeRotation({ plan: f.plan, inventory: f.inv, entries: [...f.journal.entries] }, f.deps, f.opts);
  expect(report.status).toBe('partial');
  expect(JSON.stringify({ report, journal: f.journal.entries, lines: f.lines })).not.toContain(f.old.value);
  expect(f.provider.revoked).toEqual([]);
});

test('a verified replacement with failed consumer writes reports partial and remains resumable', async () => {
  const f = await recoveryFixture();
  f.host.failWritesFor.add('api');
  f.host.failWritesFor.add('worker');
  const report = await executePlan(f.plan, f.inv, f.deps, f.opts);
  expect(report.status).toBe('partial');
  expect(f.host.writes).toEqual([]);
  expect(f.inflight.shredded.has(f.plan.id)).toBe(false);
  expect(f.provider.revoked).toEqual([]);
});

test.each(['after-deploy', 'immediately'] as const)('locally generated secrets finish after activation with revoke %s', async revoke => {
  const f = await recoveryFixture();
  const providers = f.deps.providers;
  f.deps.providers = id => id === 'app-secret' ? appSecretProvider : providers(id);
  const report = await executePlan(f.plan, f.inv, f.deps, { ...f.opts, revoke });
  expect(report.status).toBe('complete');
  expect(report.steps.find(step => step.clusterId === f.generatedClusterId)?.status).toBe('revoked');
  expect(f.generate.revoked).toEqual([]);
  expect(f.host.peek('api', 'SESSION_SECRET')).not.toBe(f.oldGenerated.value);
  expect(f.inflight.shredded.has(f.plan.id)).toBe(true);
  expect(f.journal.entries.some(entry => entry.event === 'revoked' && entry.clusterId === f.generatedClusterId && entry.data?.local === true)).toBe(true);
});

test('an atomic roll still delivers its replacement when the in-flight store becomes unavailable', async () => {
  const f = await recoveryFixture();
  f.plan.steps = [f.plan.steps[0]!];
  f.plan.steps[0]!.method = 'atomic-roll';
  const rotate = f.provider.rotate.bind(f.provider);
  f.provider.rotate = async (...args) => { const result = await rotate(...args); f.provider.revokeUpstream(f.old.ref); return { ...result, oldRevoked: true }; };
  f.inflight.put = async () => { throw new Error('store unavailable'); };
  await executePlan(f.plan, f.inv, f.deps, f.opts);
  const replacement = [...f.provider.keys.values()].find(key => key.ref !== f.old.ref)!;
  for (const service of f.services) expect(f.host.peek(service.serviceId, 'OPENAI_API_KEY')).toBe(replacement.value);
  expect(f.host.redeploys).toHaveLength(2);
});

test('resume recognizes a completed legacy journal without accessing its shredded store', async () => {
  const f = await recoveryFixture();
  await executePlan(f.plan, f.inv, f.deps, f.opts);
  const last = f.journal.entries.at(-1)!;
  last.data = { dryRun: false, steps: last.data?.steps };
  const before = [...f.trace];
  const report = await resumeRotation({ plan: f.plan, inventory: f.inv, entries: [...f.journal.entries] }, f.deps, f.opts);
  expect(report.status).toBe('complete');
  expect(f.trace).toEqual(before);
});
