import { describe, expect, test } from 'vitest';
import { actionDigest } from '../../src/approvals/index.js';
import { buildInventory, buildPlan, fingerprint } from '../../src/core/index.js';
import {
  buildArmedPlan, signArmedPlan, executeApprovedAction, planHashFor, resumeWaves, settleWaves,
  type AutopilotState, type PendingAutopilotAction, type WaveRecoveryDeps,
} from '../../src/autopilot/index.js';
import { generateDeviceKey } from '../../src/security/index.js';
import type { ApprovalGrant, ArmedCluster, AuditEvent, AuditLog, Cluster, Inventory, NotifyMessage } from '../../src/types.js';
import { FakeHttp, text } from '../helpers/fake-http.js';
import { recoveryFixture } from '../rotate/recovery-fixture.js';

async function fixture() {
  const f = await recoveryFixture();
  const key = generateDeviceKey();
  const state: AutopilotState = { armedPlanId: null, disarmed: false, waves: [] };
  const messages: NotifyMessage[] = [];
  const audits: AuditEvent[] = [];
  const saved: AutopilotState[] = [];
  const requests: { ids: string[]; reasons: string[]; id?: string }[] = [];
  const audit: AuditLog = { async append(event) { audits.push(structuredClone(event)); },
    async checkpoint() {}, async verify() { return { ok: true, entries: audits.length, checkpoints: 0 }; } };
  const deps: WaveRecoveryDeps = { engine: f.deps, options: f.opts, audit,
    trustedKeyIds: [key.keyId], env: {}, selfCheck: { ok: true, reasons: [] },
    async notify(message) { messages.push(structuredClone(message)); },
    async requestApproval(ids, reasons, id) { requests.push({ ids: [...ids], reasons: [...reasons], id }); return id; },
    async saveState(value) { saved.push(structuredClone(value)); },
  };
  function approval(ids = [f.clusterId], inventory = f.inv, id = 'approved-incident-1') {
    const action: PendingAutopilotAction = { id, kind: 'autopilot', clusterIds: [...ids],
      planHash: planHashFor(buildPlan(inventory, { clusterIds: ids })) };
    const grant: ApprovalGrant = { actionId: action.id, digest: actionDigest(action),
      at: f.deps.now!().toISOString(), by: { kind: 'device', keyId: key.keyId } };
    return { action, grant, inventory, state, now: f.deps.now!() };
  }
  async function freshInventory(): Promise<Inventory> {
    return buildInventory([{ host: f.host.id, services: await Promise.all(f.services.map(async service => ({
      service, vars: await f.host.readVariables(service),
    }))) }], f.deps.fingerprintKey, f.deps.now!());
  }
  function arm(options: Parameters<typeof buildArmedPlan>[0]['options'] = {}) {
    const armed = signArmedPlan(buildArmedPlan({ projectId: 'project', inventory: f.inv,
      clusterIds: [f.clusterId], hosts: ['railway'], options, now: f.deps.now!() }).plan, key);
    state.armedPlanId = armed.id;
    return armed;
  }
  return { ...f, key, state, deps, messages, audits, saved, requests, approval, freshInventory, arm };
}

describe('approved autopilot execution', () => {
  test('plan hash is stable across generated plan ids and dates and binds actual consumers', async () => {
    const f = await fixture();
    const plan = buildPlan(f.inv, { clusterIds: [f.clusterId] });
    const identical = { ...structuredClone(plan), id: 'another-plan', createdAt: '2026-10-28T00:00:00Z' };
    expect(planHashFor(identical)).toBe(planHashFor(plan));
    identical.steps[0]!.consumers[0]!.fingerprint = 'changed';
    expect(planHashFor(identical)).not.toBe(planHashFor(plan));
  });

  test('approved readable automatic keys execute without an armed plan and retain old keys for grace', async () => {
    const f = await fixture();
    const result = await executeApprovedAction(f.approval(), f.deps);
    expect(result.executed).toEqual([f.clusterId]);
    expect(result.guided).toEqual([]);
    expect(result.report?.status).toBe('grace-pending');
    expect(f.host.writes).toHaveLength(2);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.state.waves).toHaveLength(1);
    expect(f.state.waves[0]?.status).toBe('grace');
    expect(f.messages.some(message => message.kind === 'autopilot:start')).toBe(true);
    expect(f.audits.some(event => event.kind === 'autopilot:created')).toBe(true);
  });

  test('approved allow-listed generated secrets execute without an armed plan', async () => {
    const f = await fixture();
    const result = await executeApprovedAction(f.approval([f.generatedClusterId]), f.deps);
    expect(result.executed).toEqual([f.generatedClusterId]);
    expect(result.report?.status).toBe('grace-pending');
    expect(f.host.writes).toHaveLength(2);
    expect(f.generate.keys.get(f.oldGenerated.ref)?.active).toBe(true);
  });

  test.each(['action-id', 'digest'] as const)('a mismatched grant %s cannot mutate a provider or consumer', async mismatch => {
    const f = await fixture();
    const input = f.approval();
    if (mismatch === 'action-id') input.grant.actionId = 'some-other-action';
    else input.grant.digest = '0'.repeat(64);
    const result = await executeApprovedAction(input, f.deps);
    expect(result.executed).toEqual([]);
    expect(f.host.writes).toEqual([]);
    expect(f.provider.keys.size).toBe(1);
  });

  test.each(['new-consumer', 'removed-consumer', 'missing-cluster', 'fingerprint', 'method'] as const)(
    'inventory %s drift requests fresh approval without using the old grant', async drift => {
      const f = await fixture();
      const input = f.approval();
      input.inventory = structuredClone(f.inv);
      const cluster = input.inventory.clusters.find(item => item.id === f.clusterId)!;
      if (drift === 'new-consumer') cluster.consumers.push({ ...structuredClone(cluster.consumers[0]!), varName: 'SECOND_OPENAI_KEY' });
      if (drift === 'removed-consumer') cluster.consumers.pop();
      if (drift === 'missing-cluster') input.inventory.clusters = input.inventory.clusters.filter(item => item.id !== f.clusterId);
      if (drift === 'fingerprint') cluster.consumers[0]!.fingerprint = 'changed-fingerprint';
      if (drift === 'method') cluster.method = 'guided';
      const result = await executeApprovedAction(input, f.deps);
      expect(result.executed).toEqual([]);
      expect(result.asked).toContain(f.clusterId);
      expect(f.requests.some(request => request.ids.includes(f.clusterId))).toBe(true);
      expect(f.host.writes).toEqual([]);
      expect(f.provider.keys.size).toBe(1);
    });

  test('guided clusters are reported for the user while an approved automatic cluster proceeds', async () => {
    const f = await fixture();
    const inventory = structuredClone(f.inv);
    const guided = inventory.clusters.find(cluster => cluster.id === f.generatedClusterId)!;
    guided.provider = 'anthropic'; guided.method = 'guided'; guided.tier = 'ai';
    const result = await executeApprovedAction(f.approval([f.clusterId, f.generatedClusterId], inventory), f.deps);
    expect(result.executed).toEqual([f.clusterId]);
    expect(result.guided).toEqual([f.generatedClusterId]);
    expect(f.host.writes.every(write => !Object.hasOwn(write.vars, 'SESSION_SECRET'))).toBe(true);
    expect(f.messages.some(message => /need.*(user|you|guided)|guided.*rotation/i.test(JSON.stringify(message)))).toBe(true);
  });

  test('unapproved application-secret names remain guided even when the inventory says generate', async () => {
    const f = await fixture();
    const inventory = structuredClone(f.inv);
    inventory.clusters.find(cluster => cluster.id === f.generatedClusterId)!.consumers[0]!.varName = 'MY_SESSION_SECRET';
    const result = await executeApprovedAction(f.approval([f.generatedClusterId], inventory), f.deps);
    expect(result.executed).toEqual([]);
    expect(result.guided).toContain(f.generatedClusterId);
    expect(f.host.writes).toEqual([]);
  });

  test.each(['disarmed', 'alert-only', 'self-check'] as const)('%s keeps an approved action from executing', async gate => {
    const f = await fixture();
    if (gate === 'disarmed') f.state.disarmed = true;
    if (gate === 'alert-only') f.deps.env = { KEYSENTRY_ALERT_ONLY: '1' };
    if (gate === 'self-check') f.deps.selfCheck = { ok: false, reasons: ['Notification check unavailable.'] };
    const result = await executeApprovedAction(f.approval(), f.deps);
    expect(result.executed).toEqual([]);
    expect(f.host.writes).toEqual([]);
    expect(f.provider.keys.size).toBe(1);
  });

  test('an incomplete latest inventory cannot execute even a matching approved plan', async () => {
    const f = await fixture();
    const input = f.approval();
    input.inventory = { ...f.inv, errors: [{ host: 'render', message: 'private diagnostic' }] };
    const result = await executeApprovedAction(input, f.deps);
    expect(result.executed).toEqual([]);
    expect(f.host.writes).toEqual([]);
    expect(f.provider.keys.size).toBe(1);
    expect(JSON.stringify(f.messages)).not.toContain('private diagnostic');
  });

  test('approved execution forces serial deployment and stops after the first failure', async () => {
    const f = await fixture();
    f.deps.options = { ...f.opts, deployConcurrency: 20, stopOnFirstFailure: false,
      holdRevocationOnAnyFailure: false, revoke: 'immediately', revokeUnconfirmed: true };
    f.host.failDeploysFor.add(f.services[0]!.serviceId);
    const result = await executeApprovedAction(f.approval(), f.deps);
    expect(result.report?.status).toBe('partial');
    expect(f.host.redeploys).toHaveLength(1);
    expect(f.provider.revoked).toEqual([]);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.state.waves[0]?.status).toBe('stopped');
    expect(f.messages.some(message => message.severity === 'urgent')).toBe(true);
  });

  test('a remote stop observed before approved creation keeps every old key active', async () => {
    const f = await fixture();
    f.deps.shouldStop = async () => true;
    await executeApprovedAction(f.approval(), f.deps);
    expect(f.provider.keys.size).toBe(1);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.host.writes).toEqual([]);
    expect(f.state.disarmed).toBe(true);
    expect(f.messages.some(message => message.severity === 'urgent')).toBe(true);
  });

  test('a remote stop after approved staging prevents deployment and revocation', async () => {
    const f = await fixture();
    f.deps.shouldStop = async () => f.host.writes.length === 2;
    await executeApprovedAction(f.approval(), f.deps);
    expect(f.host.writes).toHaveLength(2);
    expect(f.host.redeploys).toEqual([]);
    expect(f.provider.revoked).toEqual([]);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.state.disarmed).toBe(true);
    expect(f.messages.some(message => message.severity === 'urgent')).toBe(true);
  });

  test('changing the active armed policy stops an approved wave before its next effect', async () => {
    const f = await fixture();
    const armed = f.arm();
    f.deps.shouldStop = async () => { f.state.armedPlanId = 'a-new-active-plan'; return false; };
    await executeApprovedAction({ ...f.approval(), armed }, f.deps);
    expect(f.provider.keys.size).toBe(1);
    expect(f.host.writes).toEqual([]);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.messages.some(message => message.severity === 'urgent')).toBe(true);
  });

  test('approved execution honors signed health checks and never revokes after their failure', async () => {
    const f = await fixture();
    const armed = f.arm({ healthChecks: [{ serviceKey: f.serviceKeys[0]!, url: 'https://health.example/' }] });
    const http = new FakeHttp().on('GET', /^https:\/\/health\.example\/$/, () => text(500, f.old.value));
    f.deps.engine.providerCtx.http = http;
    const result = await executeApprovedAction({ ...f.approval(), armed }, f.deps);
    expect(http.calls).toHaveLength(3);
    expect(f.host.redeploys).toHaveLength(1);
    expect(result.report?.status).toBe('partial');
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.provider.revoked).toEqual([]);
    expect(JSON.stringify([f.messages, f.audits, result.report])).not.toContain(f.old.value);
  });

  test('a completed approved execution cannot be replayed', async () => {
    const f = await fixture();
    const input = f.approval();
    await executeApprovedAction(input, f.deps);
    const writes = f.host.writes.length;
    const keys = f.provider.keys.size;
    const replay = await executeApprovedAction(input, f.deps);
    expect(replay.executed).toEqual([]);
    expect(f.host.writes).toHaveLength(writes);
    expect(f.provider.keys.size).toBe(keys);
    expect(f.state.waves).toHaveLength(1);
  });

  test('approved grace settles through the shared recovery path after a fresh complete scan', async () => {
    const f = await fixture();
    await executeApprovedAction(f.approval(), f.deps);
    const deadline = Date.parse(f.state.waves[0]!.deadline!);
    expect(deadline).toBeGreaterThan(f.clock.ms);
    f.clock.ms = deadline + 1;
    const result = await settleWaves({ state: f.state, disarmed: false, now: f.deps.engine.now!(),
      inventory: await f.freshInventory() }, f.deps);
    expect(result.settled).toHaveLength(1);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(false);
    expect(f.state.waves[0]?.status).toBe('done');
  });

  test('approved grace holds all revocations while any platform scan has errors', async () => {
    const f = await fixture();
    await executeApprovedAction(f.approval(), f.deps);
    f.clock.ms = Date.parse(f.state.waves[0]!.deadline!) + 1;
    const inventory = await f.freshInventory();
    inventory.errors = [{ host: 'render', message: 'unavailable' }];
    await settleWaves({ state: f.state, disarmed: false, now: f.deps.engine.now!(), inventory }, f.deps);
    expect(f.provider.revoked).toEqual([]);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.state.waves[0]?.status).toBe('grace');
  });

  test('a crash resumes the exact approved plan without issuing a second replacement', async () => {
    const f = await fixture();
    const death = new Error('simulated process death');
    f.deps.engine.crashHook = point => { if (point === 'after-write') throw death; };
    await expect(executeApprovedAction(f.approval(), f.deps)).rejects.toBe(death);
    expect(f.state.waves[0]?.status).toBe('running');
    delete f.deps.engine.crashHook;
    const resumed = await resumeWaves({ state: f.state, disarmed: false, now: f.deps.engine.now!() }, f.deps);
    expect(resumed.resumed).toHaveLength(1);
    expect(f.trace.filter(entry => entry === 'rotate:openai')).toHaveLength(1);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.state.waves[0]?.status).toBe('grace');
  });

  test('a crash after provider creation cannot be mistaken for a notification-only interruption', async () => {
    const f = await fixture();
    const death = new Error('simulated process death');
    f.deps.engine.crashHook = point => { if (point === 'after-create') throw death; };
    await expect(executeApprovedAction(f.approval(), f.deps)).rejects.toBe(death);
    expect(f.provider.keys.size).toBe(2);
    delete f.deps.engine.crashHook;
    await resumeWaves({ state: f.state, disarmed: false, now: f.deps.engine.now!() }, f.deps);
    expect(f.provider.keys.size).toBe(2);
    expect(f.host.writes).toEqual([]);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.state.waves[0]?.status).toBe('stopped');
  });

  test('approved execution saves its recovery plan before the first provider mutation', async () => {
    const f = await fixture();
    const rotate = f.provider.rotate.bind(f.provider);
    f.provider.rotate = async (value, ctx) => {
      expect(f.saved.some(snapshot => snapshot.waves.some(wave => wave.status === 'running'
        && wave.plan?.id === wave.planId && wave.plan.steps.some(step => step.clusterId === f.clusterId)))).toBe(true);
      return rotate(value, ctx);
    };
    await executeApprovedAction(f.approval(), f.deps);
  });

  test('failed persistence cannot consume the approval by starting provider work', async () => {
    const f = await fixture();
    f.deps.saveState = async () => { throw new Error('disk unavailable'); };
    await expect(executeApprovedAction(f.approval(), f.deps)).rejects.toThrow();
    expect(f.provider.keys.size).toBe(1);
    expect(f.host.writes).toEqual([]);
  });

  test('changing both saved plan and inventory cannot widen approved crash recovery', async () => {
    const f = await fixture();
    const death = new Error('simulated process death');
    f.deps.engine.crashHook = point => { if (point === 'after-write') throw death; };
    await expect(executeApprovedAction(f.approval(), f.deps)).rejects.toBe(death);
    delete f.deps.engine.crashHook;
    const wave = f.state.waves[0]!;
    const added = { ...structuredClone(wave.plan!.steps[0]!.consumers[0]!), varName: 'OTHER_OPENAI_KEY' };
    wave.plan!.steps[0]!.consumers.push(added);
    wave.inventory!.clusters.find(cluster => cluster.id === f.clusterId)!.consumers.push(structuredClone(added));
    const writes = f.host.writes.length;
    const result = await resumeWaves({ state: f.state, disarmed: false, now: f.deps.engine.now!() }, f.deps);
    expect(result.resumed).toEqual([]);
    expect(f.host.writes).toHaveLength(writes);
    expect(f.provider.keys.size).toBe(2);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
  });

  test('approved settlement checks health again and holds the old key when it fails', async () => {
    const f = await fixture();
    const armed = f.arm({ healthChecks: [{ serviceKey: f.serviceKeys[0]!, url: 'https://health.example/' }] });
    let healthy = true;
    const http = new FakeHttp().on('GET', /^https:\/\/health\.example\/$/, () => text(healthy ? 200 : 503, ''));
    f.deps.engine.providerCtx.http = http;
    await executeApprovedAction({ ...f.approval(), armed }, f.deps);
    healthy = false;
    f.clock.ms = Date.parse(f.state.waves[0]!.deadline!) + 1;
    await settleWaves({ state: f.state, disarmed: false, now: f.deps.engine.now!(),
      inventory: await f.freshInventory() }, f.deps);
    expect(http.calls.length).toBeGreaterThan(3);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.provider.revoked).toEqual([]);
    expect(f.state.waves[0]?.status).toBe('stopped');
  });

  test.each([false, true])('by-reference execution requires verified signed adoption (signed=%s)', async signed => {
    const f = await fixture();
    const cluster = f.inv.clusters.find(item => item.id === f.clusterId)! as Cluster & { adopted?: ArmedCluster['adopted'] };
    cluster.adopted = { keyRef: f.old.ref, fingerprint: f.clusterId, at: f.deps.engine.now!().toISOString() };
    for (const consumer of cluster.consumers) { consumer.sealed = true; consumer.fingerprint = null; }
    f.host.capabilities.readValues = false;
    const byRef = Object.assign(f.provider, {
      async rotateByRef(ref: string, ctx: Parameters<typeof f.provider.rotate>[1]) {
        expect(ref).toBe(f.old.ref);
        return f.provider.rotate(f.old.value, ctx);
      },
    });
    const providers = f.deps.engine.providers;
    f.deps.engine.providers = id => id === 'openai' ? byRef : providers(id);
    const input = f.approval();
    const result = await executeApprovedAction({ ...input, ...(signed ? { armed: f.arm() } : {}) }, f.deps);
    if (signed) {
      expect(result.executed).toEqual([f.clusterId]);
      expect(f.host.writes).toHaveLength(2);
      expect(f.provider.keys.size).toBe(2);
    } else {
      expect(result.executed).toEqual([]);
      expect(result.guided).toContain(f.clusterId);
      expect(f.host.writes).toEqual([]);
      expect(f.provider.keys.size).toBe(1);
    }
  });

  test('tampered signed adoption cannot authorize by-reference creation', async () => {
    const f = await fixture();
    const cluster = f.inv.clusters.find(item => item.id === f.clusterId)! as Cluster & { adopted?: ArmedCluster['adopted'] };
    cluster.adopted = { keyRef: f.old.ref, fingerprint: f.clusterId, at: f.deps.engine.now!().toISOString() };
    for (const consumer of cluster.consumers) { consumer.sealed = true; consumer.fingerprint = null; }
    f.host.capabilities.readValues = false;
    const byRef = Object.assign(f.provider, {
      async rotateByRef(_ref: string, ctx: Parameters<typeof f.provider.rotate>[1]) {
        return f.provider.rotate(f.old.value, ctx);
      },
    });
    const providers = f.deps.engine.providers;
    f.deps.engine.providers = id => id === 'openai' ? byRef : providers(id);
    const armed = f.arm();
    armed.clusters[0]!.adopted!.keyRef = 'tampered-ref';
    const result = await executeApprovedAction({ ...f.approval(), armed }, f.deps);
    expect(result.executed).toEqual([]);
    expect(f.provider.keys.size).toBe(1);
    expect(f.host.writes).toEqual([]);
  });

  test('an unavailable changed readable key never falls back to a stale adopted provider reference', async () => {
    const f = await fixture();
    const cluster = f.inv.clusters.find(item => item.id === f.clusterId)! as Cluster & { adopted?: ArmedCluster['adopted'] };
    cluster.adopted = { keyRef: f.old.ref, fingerprint: f.clusterId, at: f.deps.engine.now!().toISOString() };
    const armed = f.arm();
    const manual = f.provider.issue('newer manual credential');
    for (const service of f.services) await f.host.writeVariables(service, { OPENAI_API_KEY: manual.value }, { skipDeploy: true });
    f.host.writes.length = 0;
    const inventory = await f.freshInventory();
    // Adopted sealed clusters can retain their identity while readable copies change.
    // Preserve the identity here to exercise a signed reference attached to that identity.
    const current = inventory.clusters.find(item => item.provider === 'openai')!;
    current.id = f.clusterId;
    const newFingerprint = fingerprint(manual.value, f.deps.engine.fingerprintKey);
    expect(current.consumers.every(consumer => consumer.fingerprint === newFingerprint)).toBe(true);
    let references = 0;
    const byRef = Object.assign(f.provider, {
      async rotateByRef(_ref: string, ctx: Parameters<typeof f.provider.rotate>[1]) {
        references++;
        return f.provider.rotate(f.old.value, ctx);
      },
    });
    const providers = f.deps.engine.providers;
    f.deps.engine.providers = id => id === 'openai' ? byRef : providers(id);
    f.host.readVariables = async () => { throw new Error('current values unavailable'); };
    await executeApprovedAction({ ...f.approval([f.clusterId], inventory), armed }, f.deps);
    expect(references).toBe(0);
    expect(f.host.writes).toEqual([]);
    expect(f.provider.keys.size).toBe(2);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.provider.keys.get(manual.ref)?.active).toBe(true);
  });
});
