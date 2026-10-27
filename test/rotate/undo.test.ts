import { describe, expect, it, vi } from 'vitest';
import { buildInventory, buildPlan, createRedactor, fingerprint, serviceKey } from '../../src/core/index.js';
import { undoRotation } from '../../src/rotate/undo.js';
import type { EngineDeps, RotateOptions } from '../../src/rotate/engine.js';
import type { CrashPoint, JournalEntry } from '../../src/types.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

const key = Buffer.alloc(32, 31);
const at = '2026-10-27T12:00:00.000Z';
const options: RotateOptions = {
  dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100,
  pollIntervalMs: 1, revokeUnconfirmed: false, acceptUnplannedSealed: false,
  allowGenerate: true, verifyRetries: 0,
};

async function prepared(twoClusters = false) {
  const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
  const old = provider.issue('old');
  const other = provider.issue('other');
  const host = new FakeHost('railway');
  host.pendingPolls = 0;
  const vars = { OPENAI_API_KEY: old.value, ...(twoClusters ? { OPENAI_BACKUP_KEY: other.value } : {}) };
  const services = [host.addService('api', vars), host.addService('worker', vars)];
  const inventory = buildInventory([{ host: host.id, services: await Promise.all(services.map(async service => ({
    service, vars: await host.readVariables(service),
  }))) }], key, new Date(at));
  const plan = buildPlan(inventory);
  const entries: JournalEntry[] = [{ at, planId: plan.id, event: 'plan-start' }];
  const inflight = createFakeInFlight();
  const deps: EngineDeps = {
    hosts: { railway: host }, providers: () => provider,
    providerCtx: { http: new FakeHttp(), credentials: {}, log: silentLogger },
    journal: { async append(entry) { entries.push(structuredClone(entry)); }, async read() { return entries; } },
    prompt: async () => null, fingerprintKey: key, redactor: createRedactor(), log: silentLogger,
    inflight, now: () => new Date(at), sleep: async () => {},
  };
  const pairs = [];
  for (const step of plan.steps) {
    const before = step.clusterId === fingerprint(old.value, key) ? old : other;
    const next = await provider.rotate(before.value, deps.providerCtx);
    await inflight.put(plan.id, `old:${step.clusterId}`, before.value);
    await inflight.put(plan.id, `new:${step.clusterId}`, next.newValue);
    entries.push({ at, planId: plan.id, clusterId: step.clusterId, event: 'created', data: {
      oldKeyRef: before.ref, newKeyRef: next.newKeyRef, newFingerprint: fingerprint(next.newValue, key), oldRevoked: false,
    } });
    for (const service of services) await host.writeVariables(service,
      Object.fromEntries(step.consumers.filter(c => serviceKey(c.service) === serviceKey(service)).map(c => [c.varName, next.newValue])),
      { skipDeploy: true });
    pairs.push({ step, before, next });
  }
  host.writes.length = 0;
  return { plan, inventory, deps, entries, inflight, host, provider, pairs, services };
}

describe('undoRotation', () => {
  it('restores old values in one batch per service, redeploys once, verifies old keys, and revokes replacements last', async () => {
    const h = await prepared(true);
    const complete = new Set<string>();
    const status = h.host.deploymentStatus.bind(h.host);
    vi.spyOn(h.host, 'deploymentStatus').mockImplementation(async (service, id) => {
      const result = await status(service, id);
      if (result === 'success') complete.add(service.serviceId);
      return result;
    });
    const revoke = h.provider.revoke.bind(h.provider);
    vi.spyOn(h.provider, 'revoke').mockImplementation(async (ref, ctx) => {
      expect(complete).toEqual(new Set(['api', 'worker']));
      for (const { step, before } of h.pairs) for (const consumer of step.consumers) {
        expect(h.host.peek(consumer.service.serviceId, consumer.varName)).toBe(before.value);
      }
      await revoke(ref, ctx);
    });
    const result = await undoRotation(h, h.deps, options);
    expect(result.unavailable).toEqual([]);
    expect(result.restored).toHaveLength(2);
    expect(h.host.writes).toHaveLength(2);
    expect(h.host.writes.every(write => Object.keys(write.vars).length === 2)).toBe(true);
    expect(h.host.redeploys).toEqual(['api', 'worker']);
    expect(new Set(result.newKeysRevoked)).toEqual(new Set(h.pairs.map(pair => pair.next.newKeyRef)));
    expect(h.provider.keys.get(h.pairs[0]!.before.ref)?.active).toBe(true);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(true);
    expect(h.entries.filter(entry => entry.event === 'undo')).toHaveLength(2);
    const deploymentEntries = h.entries.filter(entry => ['redeploy', 'deploy-result'].includes(entry.event) && entry.data?.undo === true);
    expect(deploymentEntries).toHaveLength(4);
    for (const entry of deploymentEntries) expect(new Set(entry.data?.clusterIds as string[]))
      .toEqual(new Set(h.plan.steps.map(step => step.clusterId)));
    expect(h.entries.at(-1)?.event).toBe('plan-end');
    const serialized = JSON.stringify({ result, entries: h.entries });
    for (const pair of h.pairs) for (const value of [pair.before.value, pair.next.newValue]) expect(serialized).not.toContain(value);
  });

  it('marks clusters whose old value was sealed or not stored unavailable', async () => {
    const h = await prepared();
    h.deps.inflight = createFakeInFlight();
    const result = await undoRotation(h, h.deps, options);
    expect(result.unavailable[0]?.reason).toMatch(/sealed|not stored/i);
    expect(h.host.writes).toEqual([]);
    expect(h.provider.revoked).toEqual([]);
  });

  it.each(['atomic-roll', 'revoked'] as const)('does not restore when the old key was already %s', async kind => {
    const h = await prepared();
    const clusterId = h.pairs[0]!.step.clusterId;
    if (kind === 'atomic-roll') h.entries.find(entry => entry.event === 'created')!.data!.oldRevoked = true;
    else h.entries.push({ at, planId: h.plan.id, clusterId, event: 'revoked', data: { oldKeyRef: h.pairs[0]!.before.ref } });
    const result = await undoRotation(h, h.deps, options);
    expect(result.unavailable[0]?.reason).toMatch(/already revoked|atomic/i);
    expect(h.host.writes).toEqual([]);
    expect(h.provider.revoked).toEqual([]);
  });

  it.each(['write', 'deployment'] as const)('keeps the replacement when a consumer %s fails', async failure => {
    const h = await prepared();
    if (failure === 'write') h.host.failWritesFor.add('worker');
    else h.host.failDeploysFor.add('worker');
    const result = await undoRotation(h, h.deps, options);
    expect(result.restored).toEqual([]);
    expect(result.unavailable[0]?.reason).toMatch(/write|deploy/i);
    expect(h.provider.revoked).toEqual([]);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
    expect(h.provider.keys.get(h.pairs[0]!.next.newKeyRef!)?.active).toBe(true);
    expect(h.entries.find(entry => entry.event === 'failed' && entry.data?.undo === true)?.data?.clusterIds)
      .toEqual([h.pairs[0]!.step.clusterId]);
  });

  it('keeps the replacement if the old key cannot be verified', async () => {
    const h = await prepared();
    h.provider.revokeUpstream(h.pairs[0]!.before.ref);
    const result = await undoRotation(h, h.deps, options);
    expect(result.unavailable[0]?.reason).toMatch(/verif|revoked/i);
    expect(h.provider.revoked).toEqual([]);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
  });

  it('does not shred while another cluster is pending', async () => {
    const h = await prepared(true);
    const clusterId = h.pairs[0]!.step.clusterId;
    const result = await undoRotation({ ...h, clusterIds: [clusterId] }, h.deps, options);
    expect(result.restored).toHaveLength(1);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
    expect(h.host.writes).toHaveLength(2);
    expect(h.host.writes.every(write => Object.keys(write.vars).length === 1)).toBe(true);
  });

  it('redeploys again when a later undo restores another cluster on the same services', async () => {
    const h = await prepared(true);
    await undoRotation({ ...h, clusterIds: [h.pairs[0]!.step.clusterId] }, h.deps, options);
    const result = await undoRotation({ ...h, clusterIds: [h.pairs[1]!.step.clusterId] }, h.deps, options);
    expect(result.unavailable).toEqual([]);
    expect(h.host.redeploys).toEqual(['api', 'worker', 'api', 'worker']);
    expect(h.provider.revoked).toHaveLength(2);
  });

  it('keeps the replacement when a saved reference is now a literal value', async () => {
    const h = await prepared();
    h.pairs[0]!.step.consumers.find(consumer => consumer.service.serviceId === 'worker')!.reference = true;
    const result = await undoRotation(h, h.deps, options);
    expect(result.unavailable[0]?.reason).toMatch(/reference/i);
    expect(h.host.writes).toEqual([]);
    expect(h.provider.revoked).toEqual([]);
  });

  it('redeploys a current reference without overwriting its expression', async () => {
    const h = await prepared();
    const consumer = h.pairs[0]!.step.consumers.find(consumer => consumer.service.serviceId === 'worker')!;
    consumer.reference = true;
    const expression = '${{api.OPENAI_API_KEY}}';
    await h.host.writeVariables(consumer.service, { OPENAI_API_KEY: expression }, { skipDeploy: true });
    h.host.writes.length = 0;
    const result = await undoRotation(h, h.deps, options);
    expect(result.unavailable).toEqual([]);
    expect(h.host.peek('worker', 'OPENAI_API_KEY')).toBe(expression);
    expect(h.host.writes).toHaveLength(1);
    expect(h.host.redeploys).toEqual(['api', 'worker']);
  });

  it('keeps the replacement for a shared variable with no reference service to confirm activation', async () => {
    const h = await prepared();
    const pair = h.pairs[0]!;
    const shared = h.host.addService('', { OPENAI_API_KEY: pair.next.newValue });
    pair.step.consumers = [{ ...pair.step.consumers[0]!, service: shared }];
    const result = await undoRotation(h, h.deps, options);
    expect(result.unavailable[0]?.reason).toMatch(/activat|reference/i);
    expect(h.provider.revoked).toEqual([]);
  });

  it('can retry undo after revocation without revoking the replacement twice', async () => {
    const h = await prepared();
    const error = new Error('simulated process exit');
    h.deps.crashHook = point => { if (point === 'after-revoke') throw error; };
    await expect(undoRotation(h, h.deps, options)).rejects.toBe(error);
    expect(h.provider.revoked).toEqual([h.pairs[0]!.next.newKeyRef]);
    delete h.deps.crashHook;
    const result = await undoRotation(h, h.deps, options);
    expect(result.unavailable).toEqual([]);
    expect(h.provider.revoked).toEqual([h.pairs[0]!.next.newKeyRef]);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(true);
  });

  it('restores old companion values and verifies the replacement with its new companion before revoking it', async () => {
    const h = await prepared();
    const pair = h.pairs[0]!;
    const oldId = 'AKIAABCDEFGHIJKLMNOP';
    const newId = 'AKIAQRSTUVWXYZABCDEF';
    await h.inflight.put(h.plan.id, `old-companion:${pair.step.clusterId}:AWS_ACCESS_KEY_ID`, oldId);
    await h.inflight.put(h.plan.id, `companion:${pair.step.clusterId}:AWS_ACCESS_KEY_ID`, newId);
    const verify = h.provider.verify.bind(h.provider);
    vi.spyOn(h.provider, 'verify').mockImplementation(async (value, ctx) => {
      expect(ctx.siblingVars?.AWS_ACCESS_KEY_ID).toBe(value === pair.before.value ? oldId : newId);
      return verify(value, ctx);
    });
    const result = await undoRotation(h, h.deps, options);
    expect(result.unavailable).toEqual([]);
    expect(h.host.peek('api', 'AWS_ACCESS_KEY_ID')).toBe(oldId);
    expect(h.host.peek('worker', 'AWS_ACCESS_KEY_ID')).toBe(oldId);
    expect(h.provider.revoked).toEqual([pair.next.newKeyRef]);
    for (const value of [oldId, newId]) expect(JSON.stringify({ result, entries: h.entries })).not.toContain(value);
  });

  it('uses the matching custom AWS pair instead of an unrelated standard pair', async () => {
    const h = await prepared();
    const pair = h.pairs[0]!;
    pair.step.provider = 'aws';
    for (const consumer of pair.step.consumers) consumer.varName = 'APP_AWS_SECRET_ACCESS_KEY';
    const oldId = 'AKIAABCDEFGHIJKLMNOP';
    const newId = 'AKIAQRSTUVWXYZABCDEF';
    await h.inflight.put(h.plan.id, `old-companion:${pair.step.clusterId}:APP_AWS_ACCESS_KEY_ID`, oldId);
    await h.inflight.put(h.plan.id, `companion:${pair.step.clusterId}:APP_AWS_ACCESS_KEY_ID`, newId);
    h.deps.providerCtx.siblingVars = { AWS_ACCESS_KEY_ID: 'AKIAUNRELATEDABCDEFG', AWS_SECRET_ACCESS_KEY: 'unrelated-secret' };
    const verify = h.provider.verify.bind(h.provider);
    vi.spyOn(h.provider, 'verify').mockImplementation(async (value, ctx) => {
      if (ctx.siblingVars?.AWS_ACCESS_KEY_ID !== undefined) return { ok: false, status: 401 };
      if (ctx.siblingVars?.APP_AWS_ACCESS_KEY_ID !== (value === pair.before.value ? oldId : newId)) return { ok: false, status: 401 };
      return verify(value, ctx);
    });
    const result = await undoRotation(h, h.deps, options);
    expect(result.unavailable).toEqual([]);
    expect(h.host.peek('api', 'APP_AWS_ACCESS_KEY_ID')).toBe(oldId);
    expect(h.provider.revoked).toEqual([pair.next.newKeyRef]);
  });

  it('returns public IAM references unchanged while redacting their freeform log appearances', async () => {
    const h = await prepared();
    const pair = h.pairs[0]!;
    const newId = 'AKIAQRSTUVWXYZABCDEF';
    const next = h.provider.keys.get(pair.next.newKeyRef!)!;
    h.provider.keys.delete(pair.next.newKeyRef!);
    next.ref = newId;
    h.provider.keys.set(newId, next);
    h.entries.find(entry => entry.event === 'created')!.data!.newKeyRef = newId;
    await h.inflight.put(h.plan.id, `companion:${pair.step.clusterId}:AWS_ACCESS_KEY_ID`, newId);
    const log = vi.fn();
    h.deps.providerCtx.log = { ...silentLogger, info: log };
    const verify = h.provider.verify.bind(h.provider);
    vi.spyOn(h.provider, 'verify').mockImplementation(async (value, ctx) => {
      ctx.log.info(`Provider identifier: ${newId}`);
      return verify(value, ctx);
    });
    const result = await undoRotation(h, h.deps, options);
    expect(result.unavailable).toEqual([]);
    expect(result.newKeysRevoked).toEqual([newId]);
    expect(h.entries.find(entry => entry.event === 'revoked' && entry.data?.undo === true)?.data)
      .toMatchObject({ keyRef: newId, newKeyRef: newId });
    expect(h.entries.find(entry => entry.event === 'undo')?.data?.newKeyRef).toBe(newId);
    expect(JSON.stringify(log.mock.calls)).not.toContain(newId);
  });

  it('redacts a primary secret even when its value has the same shape as a public IAM reference', async () => {
    const h = await prepared();
    const pair = h.pairs[0]!;
    const secret = 'AKIAQRSTUVWXYZABCDEF';
    const next = h.provider.keys.get(pair.next.newKeyRef!)!;
    h.provider.keys.delete(pair.next.newKeyRef!);
    next.ref = secret;
    next.value = secret;
    h.provider.keys.set(secret, next);
    h.entries.find(entry => entry.event === 'created')!.data!.newKeyRef = secret;
    await h.inflight.put(h.plan.id, `new:${pair.step.clusterId}`, secret);
    await h.inflight.put(h.plan.id, `companion:${pair.step.clusterId}:AWS_ACCESS_KEY_ID`, secret);
    const before = h.entries.length;
    const result = await undoRotation(h, h.deps, options);
    expect(result.unavailable).toEqual([]);
    expect(h.provider.revoked).toEqual([secret]);
    expect(JSON.stringify({ result, entries: h.entries.slice(before) })).not.toContain(secret);
  });

  it.each(['after-write', 'after-redeploy', 'after-deploy-result', 'after-verify', 'before-revoke', 'after-revoke'] as CrashPoint[])(
    'propagates %s hook errors unchanged and stops without a trailing journal entry', async point => {
      const h = await prepared();
      const error = new Error('simulated process exit');
      let entriesAtCrash = 0;
      let writesAtCrash = 0;
      let deploysAtCrash = 0;
      let revokesAtCrash = 0;
      h.deps.crashHook = current => {
        if (current !== point) return;
        entriesAtCrash = h.entries.length;
        writesAtCrash = h.host.writes.length;
        deploysAtCrash = h.host.redeploys.length;
        revokesAtCrash = h.provider.revoked.length;
        throw error;
      };
      await expect(undoRotation(h, h.deps, options)).rejects.toBe(error);
      expect(h.entries).toHaveLength(entriesAtCrash);
      expect(h.host.writes).toHaveLength(writesAtCrash);
      expect(h.host.redeploys).toHaveLength(deploysAtCrash);
      expect(h.provider.revoked).toHaveLength(revokesAtCrash);
      expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
    },
  );

  it('records per-cluster undo intent before the first restore effect and adds nothing after an after-write crash', async () => {
    const h = await prepared(true);
    const error = new Error('simulated process exit');
    let recordedAtCrash: JournalEntry[] = [];
    h.deps.crashHook = point => {
      if (point !== 'after-write') return;
      recordedAtCrash = structuredClone(h.entries);
      throw error;
    };
    await expect(undoRotation(h, h.deps, options)).rejects.toBe(error);
    expect(h.entries).toEqual(recordedAtCrash);
    const intents = h.entries.filter(entry => entry.event === 'resume' && entry.data?.undo === true && entry.data?.phase === 'start');
    expect(new Set(intents.map(entry => entry.clusterId))).toEqual(new Set(h.plan.steps.map(step => step.clusterId)));
    expect(h.entries.some(entry => entry.event === 'written' && entry.data?.undo === true)).toBe(false);
    expect(h.host.writes).toHaveLength(1);
    expect(h.host.redeploys).toEqual([]);
    expect(h.provider.revoked).toEqual([]);
  });

  it('dry run makes no host or provider mutations', async () => {
    const h = await prepared();
    const result = await undoRotation(h, h.deps, { ...options, dryRun: true });
    expect(result.restored).toEqual([]);
    expect(h.host.writes).toEqual([]);
    expect(h.host.redeploys).toEqual([]);
    expect(h.provider.revoked).toEqual([]);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
  });
});
