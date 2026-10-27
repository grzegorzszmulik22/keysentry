import { describe, expect, it } from 'vitest';
import { buildInventory, buildPlan, createLogger, createRedactor, fingerprint } from '../../src/core/index.js';
import { executePlan, finishRotation, resumeRotation, undoRotation } from '../../src/rotate/index.js';
import type { EngineDeps, RotateOptions } from '../../src/rotate/engine.js';
import type { JournalEntry, ProviderContext } from '../../src/types.js';
import { FakeHttp } from '../helpers/fake-http.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

async function awsFixture(customPair = false) {
  const provider = new FakeProvider('aws', 'auto', 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv');
  const old = provider.issue();
  const oldId = 'AKIAABCDEFGHIJKLMNOP';
  const newId = 'AKIAQRSTUVWXYZABCDEF';
  const idName = customPair ? 'BACKUP_ACCESS_KEY_ID' : 'AWS_ACCESS_KEY_ID';
  const secretName = customPair ? 'BACKUP_SECRET_ACCESS_KEY' : 'AWS_SECRET_ACCESS_KEY';
  const unrelatedId = 'AKIAZYXWVUTSRQPONMLK';
  const unrelatedValue = 'Unrelated9Secret8For7Standard6Aws5Pair4';
  const unrelated = customPair ? { AWS_ACCESS_KEY_ID: unrelatedId, AWS_SECRET_ACCESS_KEY: unrelatedValue } : {};
  const host = new FakeHost('railway');
  host.pendingPolls = 0;
  const services = ['api', 'worker'].map(id => host.addService(id, {
    ...unrelated, [idName]: oldId, [secretName]: old.value, AWS_REGION: 'eu-west-1', NODE_ENV: 'production',
  }));
  const fingerprintKey = Buffer.alloc(32, 0x7a);
  const inventory = buildInventory([{ host: host.id, services: await Promise.all(services.map(async service => ({
    service, vars: await host.readVariables(service),
  }))) }], fingerprintKey);
  const clusterId = fingerprint(old.value, fingerprintKey);
  if (customPair) {
    const cluster = inventory.clusters.find(cluster => cluster.id === clusterId)!;
    cluster.provider = 'aws';
    cluster.tier = 'cloud';
    cluster.method = 'auto';
  }
  const plan = buildPlan(inventory, { clusterIds: [clusterId] });
  const entries: JournalEntry[] = [];
  const storedValues: string[] = [];
  const inflight = createFakeInFlight();
  const put = inflight.put.bind(inflight);
  inflight.put = async (planId, slot, value) => { storedValues.push(value); await put(planId, slot, value); };
  const redactor = createRedactor();
  const lines: string[] = [];
  const log = createLogger({ redactor, level: 'debug', json: true, sink: line => lines.push(line) });
  const contexts: { kind: string; value: string; id: string | undefined; secret: string | undefined; valid: boolean }[] = [];
  let newValue = '';
  let newFakeRef = '';
  const observe = (kind: string, value: string, ctx: ProviderContext) => {
    const id = ctx.siblingVars?.[idName];
    const secret = ctx.siblingVars?.[secretName];
    const isolated = !customPair || (ctx.siblingVars?.AWS_ACCESS_KEY_ID === undefined && ctx.siblingVars?.AWS_SECRET_ACCESS_KEY === undefined);
    const valid = isolated && id === (value === old.value ? oldId : newId) && secret === value;
    contexts.push({ kind, value, id, secret, valid });
    return valid;
  };
  const rotate = provider.rotate.bind(provider);
  provider.rotate = async (value, ctx) => {
    if (!observe('rotate', value, ctx)) throw new Error('AWS rotation needs a complete matching pair.');
    const result = await rotate(value, ctx);
    newValue = result.newValue;
    newFakeRef = result.newKeyRef!;
    return { ...result, oldKeyRef: oldId, newKeyRef: newId, companions: { [idName]: newId } };
  };
  const verify = provider.verify.bind(provider);
  provider.verify = async (value, ctx) => {
    if (!observe('verify', value, ctx)) return { ok: false, status: 401 };
    return verify(value, ctx);
  };
  provider.resolveKeyRef = async (value, ctx) => {
    if (!observe('resolve', value, ctx)) return null;
    return value === old.value ? oldId : value === newValue ? newId : null;
  };
  const revoke = provider.revoke.bind(provider);
  const revokedIds: string[] = [];
  provider.revoke = async (id, ctx) => {
    // Old-key revocation is signed using the replacement pair. Unused-key cleanup
    // uses the old pair because the replacement may not yet be usable.
    const value = id === oldId ? newValue : old.value;
    if (!observe('revoke', value, ctx)) throw new Error('AWS revocation needs a complete matching pair.');
    revokedIds.push(id);
    await revoke(id === oldId ? old.ref : newFakeRef, ctx);
  };
  const deps: EngineDeps = {
    hosts: { railway: host }, providers: () => provider,
    providerCtx: { http: new FakeHttp(), credentials: {}, log, ...(customPair ? { siblingVars: unrelated } : {}) },
    journal: { async append(entry) { entries.push(structuredClone(entry)); }, async read() { return entries; } },
    inflight, prompt: async () => null, fingerprintKey, redactor, log, sleep: async () => {},
  };
  const opts: RotateOptions = {
    dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 1,
    revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 0, graceMs: 0,
  };
  return { provider, host, services, inventory, plan, clusterId, old, oldId, newId, idName, secretName, unrelatedId, unrelatedValue,
    deps, opts, entries, inflight, storedValues, lines, contexts, revokedIds,
    newValue: () => newValue };
}

/** Public IAM IDs remain usable only in their explicit provider-reference fields. */
function withoutPublicReferences(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(withoutPublicReferences);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value)
    .filter(([key]) => !['oldKeyRef', 'newKeyRef', 'keyRef'].includes(key))
    .map(([key, entry]) => [key, withoutPublicReferences(entry)]));
  return value;
}

describe('AWS rotation recovery', () => {
  it('finish retains old keys when a consumer companion changed after staging', async () => {
    const f = await awsFixture();
    f.deps.grace = async () => 'defer';
    const options = { ...f.opts, graceMs: 1_000, holdRevocationOnAnyFailure: true };
    await executePlan(f.plan, f.inventory, f.deps, options);
    const manualId = 'AKIAMANUALPAIRABCDEFG';
    await f.host.writeVariables(f.services[1]!, { [f.idName]: manualId }, { skipDeploy: true });
    const report = await finishRotation({ plan: f.plan, inventory: f.inventory, entries: [...f.entries] }, f.deps, { ...options, early: true });
    expect(report.status).toBe('partial');
    expect(report.steps[0]!.status).toBe('failed');
    expect(f.revokedIds).toEqual([]);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(JSON.stringify(report)).not.toContain(manualId);
  });

  it('undo never overwrites a consumer companion that moved to a third value', async () => {
    const f = await awsFixture();
    f.deps.grace = async () => 'defer';
    await executePlan(f.plan, f.inventory, f.deps, { ...f.opts, graceMs: 1_000 });
    const manualId = 'AKIAMANUALPAIRABCDEFG';
    await f.host.writeVariables(f.services[1]!, { [f.idName]: manualId }, { skipDeploy: true });
    f.host.writes.length = 0;
    const report = await undoRotation({ plan: f.plan, inventory: f.inventory, entries: [...f.entries] }, f.deps, f.opts);
    expect(report.restored).toEqual([]);
    // M4 now identifies the service whose newer value must be preserved.
    expect(report.unavailable[0]!.reason).toMatch(/newer value.*keysentry won't overwrite/i);
    expect(f.host.peek(f.services[1]!.serviceId, f.idName)).toBe(manualId);
    expect(f.host.writes).toEqual([]);
    expect(f.revokedIds).toEqual([]);
    expect(JSON.stringify(report)).not.toContain(manualId);
  });

  it('keeps public key references usable when replacement storage and cleanup both fail', async () => {
    const f = await awsFixture();
    f.inflight.put = async () => { throw new Error('temporary storage unavailable'); };
    f.provider.revoke = async () => { throw new Error('cleanup unavailable'); };
    const report = await executePlan(f.plan, f.inventory, f.deps, f.opts);
    expect(report.steps[0]!.newKeyRef).toBe(f.newId);
    expect(report.steps[0]!.oldKeyRef).toBe(f.oldId);
    expect(f.entries.some(entry => entry.event === 'created' && entry.data?.newKeyRef === f.newId)).toBe(true);
    expect(JSON.stringify({ report, entries: f.entries })).not.toContain(f.newValue());
    expect(f.host.writes).toEqual([]);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
  });

  it('resumes a mixed pair after the first consumer write, verifies the stored old pair and revokes using the new pair', async () => {
    const f = await awsFixture();
    expect(f.plan.steps).toHaveLength(1);
    const stopped = { stopped: true };
    f.deps.crashHook = point => { if (point === 'after-write') throw stopped; };
    await expect(executePlan(f.plan, f.inventory, f.deps, f.opts)).rejects.toBe(stopped);
    expect(f.host.writes).toHaveLength(1);
    expect(f.host.peek('api', 'AWS_ACCESS_KEY_ID')).toBe(f.newId);
    expect(f.host.peek('worker', 'AWS_ACCESS_KEY_ID')).toBe(f.oldId);
    expect(await f.deps.inflight!.get(f.plan.id, `old-companion:${f.clusterId}:AWS_ACCESS_KEY_ID`)).toBe(f.oldId);
    delete f.deps.crashHook;
    const before = f.contexts.length;
    const report = await resumeRotation({ plan: f.plan, inventory: f.inventory, entries: [...f.entries] }, f.deps, f.opts);
    expect(report.status).toBe('complete');
    expect(report.steps[0]?.oldKeyRef).toBe(f.oldId);
    expect(report.steps[0]?.newKeyRef).toBe(f.newId);
    expect(f.host.writes).toHaveLength(2);
    for (const service of f.services) {
      expect(f.host.peek(service.serviceId, 'AWS_ACCESS_KEY_ID')).toBe(f.newId);
      expect(f.host.peek(service.serviceId, 'AWS_SECRET_ACCESS_KEY')).toBe(f.newValue());
      expect(f.host.peek(service.serviceId, 'AWS_REGION')).toBe('eu-west-1');
      expect(f.host.redeploys.filter(id => id === service.serviceId)).toHaveLength(1);
    }
    expect(f.contexts.slice(before)).toContainEqual(expect.objectContaining({ kind: 'verify', value: f.old.value, id: f.oldId, secret: f.old.value, valid: true }));
    expect(f.contexts).toContainEqual(expect.objectContaining({ kind: 'revoke', value: f.newValue(), id: f.newId, secret: f.newValue(), valid: true }));
    expect(f.contexts.filter(context => !context.valid)).toEqual([]);
    expect(f.revokedIds).toEqual([f.oldId]);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(false);
    expect([...f.provider.keys.values()].filter(key => key.active)).toHaveLength(1);
    await expect(f.deps.inflight!.slots(f.plan.id)).resolves.toEqual([]);
    const serialized = JSON.stringify(withoutPublicReferences({ journal: f.entries, report, logs: f.lines }));
    for (const value of f.storedValues) expect(serialized).not.toContain(value);
  });

  it('keeps the old pair and avoids malformed calls when a crash after-store loses the new companion', async () => {
    const f = await awsFixture();
    const stopped = { stopped: true };
    f.deps.crashHook = point => { if (point === 'after-store') throw stopped; };
    await expect(executePlan(f.plan, f.inventory, f.deps, f.opts)).rejects.toBe(stopped);
    expect(await f.deps.inflight!.get(f.plan.id, `new:${f.clusterId}`)).toBe(f.newValue());
    expect(await f.deps.inflight!.get(f.plan.id, `companion:${f.clusterId}:AWS_ACCESS_KEY_ID`)).toBeNull();
    delete f.deps.crashHook;
    const report = await resumeRotation({ plan: f.plan, inventory: f.inventory, entries: [...f.entries] }, f.deps, f.opts);
    expect(['failed', 'partial']).toContain(report.status);
    expect(report.steps[0]?.status).toBe('failed');
    expect(f.host.writes).toEqual([]);
    expect(f.host.redeploys).toEqual([]);
    for (const service of f.services) {
      expect(f.host.peek(service.serviceId, 'AWS_ACCESS_KEY_ID')).toBe(f.oldId);
      expect(f.host.peek(service.serviceId, 'AWS_SECRET_ACCESS_KEY')).toBe(f.old.value);
    }
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.revokedIds).not.toContain(f.oldId);
    expect(f.contexts.filter(context => !context.valid)).toEqual([]);
  });

  it('finishes after a crash before revocation with intact IAM references and matching old and new pairs', async () => {
    const f = await awsFixture();
    f.deps.grace = async () => 'defer';
    const opts = { ...f.opts, graceMs: 60_000 };
    const deferred = await executePlan(f.plan, f.inventory, f.deps, opts);
    expect(deferred.status).toBe('grace-pending');
    const stopped = { stopped: true };
    f.deps.crashHook = point => { if (point === 'before-revoke') throw stopped; };
    await expect(finishRotation({ plan: f.plan, inventory: f.inventory, entries: [...f.entries] }, f.deps,
      { ...opts, early: true })).rejects.toBe(stopped);
    expect(f.revokedIds).toEqual([]);
    expect(f.entries.at(-1)?.event).toBe('verified');
    delete f.deps.crashHook;
    const contextStart = f.contexts.length;
    const report = await finishRotation({ plan: f.plan, inventory: f.inventory, entries: [...f.entries] }, f.deps,
      { ...opts, early: true });
    expect(report.status).toBe('complete');
    expect(report.steps[0]?.oldKeyRef).toBe(f.oldId);
    expect(report.steps[0]?.newKeyRef).toBe(f.newId);
    expect(f.contexts.slice(contextStart)).toContainEqual(expect.objectContaining({ kind: 'verify', value: f.old.value, id: f.oldId, secret: f.old.value, valid: true }));
    expect(f.contexts.slice(contextStart)).toContainEqual(expect.objectContaining({ kind: 'verify', value: f.newValue(), id: f.newId, secret: f.newValue(), valid: true }));
    expect(f.contexts.filter(context => !context.valid)).toEqual([]);
    expect(f.revokedIds).toEqual([f.oldId]);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(false);
    expect(f.inflight.shredded.has(f.plan.id)).toBe(true);
    expect(f.entries.at(-1)?.event).toBe('plan-end');
    const serialized = JSON.stringify(withoutPublicReferences({ journal: f.entries, report, logs: f.lines }));
    for (const value of f.storedValues) expect(serialized).not.toContain(value);
  });

  it('finish isolates a custom AWS pair from unrelated standard credentials', async () => {
    const f = await awsFixture(true);
    f.deps.grace = async () => 'defer';
    const opts = { ...f.opts, graceMs: 60_000 };
    const deferred = await executePlan(f.plan, f.inventory, f.deps, opts);
    expect(deferred.status).toBe('grace-pending');
    expect(f.contexts.filter(context => !context.valid)).toEqual([]);
    const report = await finishRotation({ plan: f.plan, inventory: f.inventory, entries: [...f.entries] }, f.deps,
      { ...opts, early: true });
    expect(report.status).toBe('complete');
    expect(f.contexts.filter(context => !context.valid)).toEqual([]);
    expect(f.revokedIds).toEqual([f.oldId]);
    for (const service of f.services) {
      expect(f.host.peek(service.serviceId, f.idName)).toBe(f.newId);
      expect(f.host.peek(service.serviceId, f.secretName)).toBe(f.newValue());
      expect(f.host.peek(service.serviceId, 'AWS_ACCESS_KEY_ID')).toBe(f.unrelatedId);
      expect(f.host.peek(service.serviceId, 'AWS_SECRET_ACCESS_KEY')).toBe(f.unrelatedValue);
    }
  });
});
