import { describe, expect, test } from 'vitest';
import { buildArmedPlan, signArmedPlan } from '../../src/autopilot/armed-plan.js';
import { isAlertOnly } from '../../src/autopilot/kill-switch.js';
import { runAutopilot, resumeWaves, settleWaves, retryPendingAsks, planHashFor, type AutopilotState, type PendingAutopilotAction } from '../../src/autopilot/runner.js';
import { generateDeviceKey } from '../../src/security/index.js';
import { buildInventory, buildPlan } from '../../src/core/index.js';
import type { ArmedCluster, AuditEvent, AuditLog, Cluster, Incident, NotifyMessage } from '../../src/types.js';
import { FakeHttp, text } from '../helpers/fake-http.js';
import { recoveryFixture } from '../rotate/recovery-fixture.js';

async function fixture() {
  const f = await recoveryFixture();
  const key = generateDeviceKey();
  function arm(options: Parameters<typeof buildArmedPlan>[0]['options'] = {}, clusterIds = [f.clusterId]) {
    return signArmedPlan(buildArmedPlan({ projectId: 'project', inventory: f.inv, clusterIds,
      hosts: ['railway'], options, now: f.deps.now!() }).plan, key);
  }
  const armed = arm();
  const incident: Incident = { id: 'incident-1', host: 'railway', openedAt: f.deps.now!().toISOString(),
    status: 'triggered', evidence: [], trigger: { at: f.deps.now!().toISOString(), rule: 'official' } };
  const state: AutopilotState = { armedPlanId: armed.id, disarmed: false, waves: [] };
  const notifications: NotifyMessage[] = [];
  const approvals: { ids: string[]; reasons: string[]; actionId?: string }[] = [];
  const saved: AutopilotState[] = [];
  const auditEvents: AuditEvent[] = [];
  const audit: AuditLog = { async append(event) { auditEvents.push(structuredClone(event)); },
    async checkpoint() {}, async verify() { return { ok: true, entries: auditEvents.length, checkpoints: 0 }; } };
  const deps = { engine: f.deps, options: f.opts, audit,
    async notify(message: NotifyMessage) { notifications.push(message); },
    async requestApproval(ids: string[], reasons: string[], actionId?: string) { approvals.push({ ids, reasons, actionId }); },
    async saveState(value: AutopilotState) { saved.push(structuredClone(value)); },
  };
  const input = { incident, armed, trustedKeyIds: [key.keyId], inventory: f.inv, state,
    selfCheck: { ok: true, reasons: [] as string[] }, env: {}, now: f.deps.now!() };
  const recoveryDeps = { ...deps, trustedKeyIds: [key.keyId], env: {}, selfCheck: input.selfCheck };
  return { ...f, key, armed, arm, input, state, deps, recoveryDeps, notifications, approvals, saved, auditEvents };
}

describe('autopilot runner', () => {
  test('an incomplete scan asks about the whole wave without rotating', async () => {
    const f = await fixture();
    f.input.inventory = { ...f.inv, errors: [{ host: 'render', message: 'private error' }] };
    const result = await runAutopilot(f.input, f.deps);
    expect(result.executed).toEqual([]);
    expect(result.asked).toEqual([f.clusterId, f.generatedClusterId]);
    expect(f.host.writes).toHaveLength(0);
    expect(f.approvals[0]?.reasons).toContain("Some platforms could not be scanned (Render); keysentry won't rotate automatically until every copy can be checked.");
  });

  test('settlement holds revocation while the latest scan has any error and retries a complete scan', async () => {
    const f = await fixture();
    await runAutopilot(f.input, f.deps);
    f.clock.ms += 900_001;
    await settleWaves({ state: f.state, inventory: { ...f.inv, errors: [{ host: 'render', message: 'private error' }] },
      now: f.deps.engine.now!(), disarmed: false }, f.recoveryDeps);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.state.waves[0]?.status).toBe('grace');
    await settleWaves({ state: f.state, inventory: f.inv, now: f.deps.engine.now!(), disarmed: false }, f.recoveryDeps);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(false);
  });

  test.each(['request', 'notification'] as const)('a failed ask %s cannot block armed work and is retried with backoff', async failure => {
    const f = await fixture();
    let calls = 0;
    const deps = { ...f.deps,
      async requestApproval(ids: string[], reasons: string[], actionId?: string) {
        calls++;
        if (failure === 'request' && calls === 1) throw new Error('private error');
        await f.deps.requestApproval(ids, reasons, actionId);
      },
      async notify(message: NotifyMessage) {
        if (failure === 'notification' && message.kind === 'autopilot:ask' && calls === 1) throw new Error('private error');
        await f.deps.notify(message);
      },
    };
    const result = await runAutopilot(f.input, deps);
    expect(result.executed).toEqual([f.clusterId]);
    expect(f.host.writes).toHaveLength(2);
    expect(f.state.pendingAsks).toHaveLength(1);
    const id = f.state.pendingAsks![0]!.actionId;
    await runAutopilot(f.input, deps);
    expect(calls).toBe(1);
    f.clock.ms += 60_000;
    await runAutopilot({ ...f.input, now: f.deps.engine.now!() }, deps);
    expect(calls).toBe(2);
    expect(f.approvals.at(-1)?.actionId).toBe(id);
    expect(f.state.pendingAsks).toHaveLength(0);
    expect(f.state.waves).toHaveLength(1);
  });

  test('an ask retries on a later tick without an incident and retains the exact requested plan hash', async () => {
    const f = await fixture();
    const actions: PendingAutopilotAction[] = [];
    const deps = { ...f.deps, async requestApproval(_ids: string[], _reasons: string[], _id?: string, action?: PendingAutopilotAction) {
      actions.push(structuredClone(action!));
      if (actions.length === 1) throw new Error('delivery unavailable');
    } };
    await runAutopilot(f.input, deps);
    expect(actions[0]?.planHash).toBe(planHashFor(buildPlan(f.inv, { clusterIds: [f.generatedClusterId] })));
    const restored = structuredClone(f.state);
    f.clock.ms += 60_000;
    await retryPendingAsks({ state: restored, now: f.deps.engine.now!() }, deps);
    expect(actions[1]).toEqual(actions[0]);
    expect(restored.pendingAsks).toHaveLength(0);
    expect(restored.waves).toHaveLength(1);
  });

  test('a failed start notification leaves a journaled plan that resumes without an orphan', async () => {
    const f = await fixture();
    await expect(runAutopilot(f.input, { ...f.deps, async notify(message) {
      if (message.kind === 'autopilot:start') throw new Error('delivery unavailable');
    } })).rejects.toThrow('delivery unavailable');
    const wave = f.state.waves[0]!;
    expect(f.journal.entries.some(entry => entry.planId === wave.planId && entry.event === 'plan-start')).toBe(true);
    await resumeWaves({ state: f.state, now: f.deps.engine.now!(), disarmed: false }, f.recoveryDeps);
    expect(f.state.waves[0]?.status).toBe('grace');
    expect(f.host.writes).toHaveLength(2);
  });

  test('a crash after an unjournaled creation still resumes as an orphan and never creates twice', async () => {
    const f = await fixture();
    const death = new Error('process death');
    f.deps.engine.crashHook = point => { if (point === 'after-create') throw death; };
    await expect(runAutopilot(f.input, f.deps)).rejects.toBe(death);
    expect(f.state.waves[0]?.executionStarted).toBe(true);
    delete f.deps.engine.crashHook;
    await resumeWaves({ state: f.state, now: f.deps.engine.now!(), disarmed: false }, f.recoveryDeps);
    expect(f.trace.filter(item => item === 'rotate:openai')).toHaveLength(1);
    expect(f.host.writes).toHaveLength(0);
    expect(f.state.waves[0]?.status).toBe('stopped');
  });

  test('a polled stop between writes stops the wave and urgently reports the retained old key', async () => {
    const f = await fixture();
    f.deps.engine.shouldStop = async () => f.host.writes.length > 0;
    await runAutopilot(f.input, f.deps);
    expect(f.host.writes).toHaveLength(1);
    expect(f.host.redeploys).toHaveLength(0);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.state.waves[0]?.status).toBe('stopped');
    expect(f.notifications.some(message => message.severity === 'urgent')).toBe(true);
  });

  test('a stop detected by the inner adapter check retains a prepared replacement for reconciliation', async () => {
    const f = await fixture();
    f.input.armed = f.arm({}, [f.clusterId, f.generatedClusterId]);
    f.state.armedPlanId = f.input.armed.id;
    let afterFirst = 0;
    f.deps.engine.shouldStop = async () => f.trace.includes('rotated:openai') && ++afterFirst >= 2;
    await runAutopilot(f.input, f.deps);
    expect(f.trace.filter(item => item === 'rotate:app-secret')).toHaveLength(0);
    expect(f.provider.keys.size).toBe(2);
    expect(await f.inflight.get(f.state.waves[0]!.planId, `new:${f.clusterId}`)).not.toBeNull();
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
  });

  test('a stop at the inner cleanup check keeps recovery values for the unrevoked replacement', async () => {
    const f = await fixture();
    f.provider.failVerifyOfNew = true;
    let afterFirst = 0;
    f.deps.engine.shouldStop = async () => f.trace.includes('rotated:openai') && ++afterFirst >= 2;
    await runAutopilot(f.input, f.deps);
    expect(f.provider.keys.size).toBe(2);
    expect(f.provider.revoked).toEqual([]);
    expect(await f.inflight.get(f.state.waves[0]!.planId, `new:${f.clusterId}`)).not.toBeNull();
  });

  test('own credentials are skipped as a whole cluster and the other armed keys still rotate', async () => {
    const f = await fixture();
    const own = structuredClone(f.inv.clusters.find(cluster => cluster.id === f.clusterId)!);
    own.id = 'watcher-credential';
    own.consumers = [{ ...own.consumers[0]!, varName: 'RAILWAY_TOKEN' }];
    f.input.inventory = { ...f.inv, clusters: [...f.inv.clusters, own] };
    const result = await runAutopilot(f.input, f.deps);
    expect(result.executed).toEqual([f.clusterId]);
    expect(result.asked).not.toContain(own.id);
    expect(JSON.stringify(f.notifications)).toContain('RAILWAY_TOKEN');
    expect(JSON.stringify(f.notifications)).toContain('OPENAI_API_KEY');
    expect(f.host.writes.every(write => !Object.hasOwn(write.vars, 'RAILWAY_TOKEN'))).toBe(true);
  });

  test('autopilot rotates armed clusters for an official incident and asks for the rest', async () => {
    const f = await fixture();
    const result = await runAutopilot(f.input, f.deps);
    expect(result.executed).toEqual([f.clusterId]);
    expect(result.asked).toEqual([f.generatedClusterId]);
    expect(result.report?.status).toBe('grace-pending');
    expect(f.host.writes).toHaveLength(2);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.notifications.find(m => m.kind === 'autopilot:start')?.title)
      .toBe('Railway reported a security incident. Rotating 1 keys you armed for this.');
    expect(f.notifications.find(m => m.kind === 'autopilot:ask')).toMatchObject({ severity: 'warning', actionId: f.approvals[0]?.actionId });
  });

  test('wave is persisted before the engine starts, with the original plan for recovery', async () => {
    const f = await fixture();
    const rotate = f.provider.rotate.bind(f.provider);
    f.provider.rotate = async (value, ctx) => {
      expect(f.saved[0]?.waves[0]).toMatchObject({ id: 'wave-incident-1', incidentId: 'incident-1', status: 'running' });
      expect(f.saved[0]?.waves[0]?.planId).toBeTruthy();
      return rotate(value, ctx);
    };
    await runAutopilot(f.input, f.deps);
    expect(f.state.waves[0]?.status).toBe('grace');
    expect(f.state.waves[0]?.deadline).toBe('2026-10-27T08:15:00.002Z');
    expect(f.trace).not.toContain('sleep:900000');
  });

  test.each(['env', 'disarmed', 'self-check'] as const)('%s only alerts and asks', async mode => {
    const f = await fixture();
    if (mode === 'env') f.input.env = { KEYSENTRY_ALERT_ONLY: '1' };
    if (mode === 'disarmed') f.state.disarmed = true;
    if (mode === 'self-check') f.input.selfCheck = { ok: false, reasons: ['Notification unavailable.'] };
    const result = await runAutopilot(f.input, f.deps);
    expect(result.executed).toEqual([]);
    expect(new Set(result.asked)).toEqual(new Set([f.clusterId, f.generatedClusterId]));
    expect(f.host.writes).toEqual([]);
    expect(f.trace.filter(c => c === 'rotate:openai')).toEqual([]);
    expect(f.state.waves).toEqual([]);
  });

  test('a news-only incident alerts and requests approval without rotating', async () => {
    const f = await fixture();
    f.input.incident = { ...f.input.incident, status: 'alerted', trigger: undefined };
    const result = await runAutopilot(f.input, f.deps);
    expect(result.executed).toEqual([]);
    expect(result.asked).toHaveLength(2);
    expect(f.host.writes).toEqual([]);
  });

  test('a second incident evaluation starts no second wave or approval', async () => {
    const f = await fixture();
    await runAutopilot(f.input, f.deps);
    const calls = f.trace.filter(c => /^(rotate|rotated|verify|resolve|list|revoke):openai/.test(c)).length;
    const notifications = f.notifications.length;
    const approvals = f.approvals.length;
    expect(await runAutopilot(f.input, f.deps)).toEqual({ executed: [], asked: [] });
    expect(f.trace.filter(c => /^(rotate|rotated|verify|resolve|list|revoke):openai/.test(c))).toHaveLength(calls);
    expect(f.notifications).toHaveLength(notifications);
    expect(f.approvals).toHaveLength(approvals);
    expect(f.state.waves).toHaveLength(1);
  });

  test.each(['tampered', 'expired', 'untrusted'] as const)('%s armed plan executes nothing and sends one urgent notification', async mode => {
    const f = await fixture();
    if (mode === 'tampered') f.input.armed = { ...f.armed, graceSeconds: 1 };
    if (mode === 'expired') f.input.now = new Date('2027-12-01T00:00:00Z');
    if (mode === 'untrusted') f.input.trustedKeyIds = [];
    const result = await runAutopilot(f.input, f.deps);
    expect(result.executed).toEqual([]);
    expect(result.asked).toHaveLength(2);
    expect(f.notifications.filter(m => m.severity === 'urgent')).toHaveLength(1);
    expect(f.notifications.find(m => m.severity === 'urgent')?.title)
      .toMatch(/^Your armed plan could not be verified \(.+\); nothing was rotated\.$/);
    expect(f.trace.filter(c => /^(rotate|rotated|verify|resolve|list|revoke):openai/.test(c))).toEqual([]);
    expect(f.host.writes).toEqual([]);
  });

  test('changed scope is sent for approval and never reaches the engine', async () => {
    const f = await fixture();
    const current = structuredClone(f.inv);
    current.clusters.find(c => c.id === f.clusterId)!.consumers[0]!.fingerprint = 'f'.repeat(32);
    f.input.inventory = current;
    const result = await runAutopilot(f.input, f.deps);
    expect(result.executed).toEqual([]);
    expect(f.approvals.flatMap(a => a.reasons)).toContain("a consumer's value changed since arming");
    expect(f.host.writes).toEqual([]);
  });

  test('health check makes three guarded GETs 20 seconds apart and never reflects response bodies', async () => {
    const f = await fixture();
    const http = new FakeHttp().on('GET', /^https:\/\/health\.example\/private\/token$/, () => text(500, f.old.value));
    f.deps.engine.providerCtx.http = http;
    f.input.armed = f.arm({ healthChecks: [{ serviceKey: f.serviceKeys[0]!, url: 'https://health.example/private/token' }] });
    f.state.armedPlanId = f.input.armed.id;
    const result = await runAutopilot(f.input, f.deps);
    expect(http.calls.map(c => c.method)).toEqual(['GET', 'GET', 'GET']);
    expect(f.trace.filter(c => c === 'sleep:20000')).toHaveLength(2);
    expect(result.report?.deployments[0]?.state).toBe('failed');
    expect(result.report?.steps[0]?.warnings.join(' ')).toContain('HTTP 500');
    expect(f.host.redeploys).toHaveLength(1);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    const publicText = JSON.stringify([f.notifications, f.auditEvents, result.report]);
    expect(publicText).not.toContain(f.old.value);
    expect(publicText).not.toContain('/private/token');
    expect(f.notifications.filter(m => m.severity === 'urgent')).toHaveLength(1);
    expect(f.notifications.find(m => m.severity === 'urgent')?.title)
      .toBe('Stopped: health check failed. Every old key is still valid.');
    expect(f.state.waves[0]?.status).toBe('stopped');
  });

  test('three successful probes accept any 2xx status by default', async () => {
    const f = await fixture();
    const http = new FakeHttp().on('GET', /^https:\/\/health\.example\/$/, () => text(204, ''));
    f.deps.engine.providerCtx.http = http;
    f.input.armed = f.arm({ healthChecks: [{ serviceKey: f.serviceKeys[0]!, url: 'https://health.example/' }] });
    f.state.armedPlanId = f.input.armed.id;
    const result = await runAutopilot(f.input, f.deps);
    expect(http.calls).toHaveLength(3);
    expect(result.report?.status).toBe('grace-pending');
  });

  test('expectStatus overrides the 2xx default and transport errors have a fixed diagnostic', async () => {
    const f = await fixture();
    const http = new FakeHttp().on('GET', /^https:\/\/health\.example\/$/, () => { throw new Error(`${f.old.value} https://health.example/private`); });
    f.deps.engine.providerCtx.http = http;
    f.input.armed = f.arm({ healthChecks: [{ serviceKey: f.serviceKeys[0]!, url: 'https://health.example/', expectStatus: 204 }] });
    f.state.armedPlanId = f.input.armed.id;
    const result = await runAutopilot(f.input, f.deps);
    expect(result.report?.status).toBe('partial');
    expect(JSON.stringify(f.notifications)).not.toContain(f.old.value);
    expect(JSON.stringify(result.report)).not.toContain('https://health.example');
  });

  test('every decision and engine outcome is audited and notifications contain no hints by default', async () => {
    const f = await fixture();
    await runAutopilot(f.input, f.deps);
    const kinds = f.auditEvents.map(e => e.kind);
    expect(kinds).toEqual(expect.arrayContaining(['autopilot:verified', 'autopilot:scope', 'autopilot:ask',
      'autopilot:start', 'autopilot:created', 'autopilot:written', 'autopilot:deploy-result', 'autopilot:grace-start', 'autopilot:end']));
    for (const event of f.auditEvents) {
      expect(event.kind).toMatch(/^autopilot:/);
      expect(event.data).toMatchObject({ incidentId: 'incident-1', waveId: 'wave-incident-1' });
    }
    const messages = JSON.stringify(f.notifications);
    expect(messages).not.toContain(f.old.value);
    expect(messages).not.toContain(f.inv.clusters[0]!.hint);
    expect(messages).not.toContain(f.clusterId);
  });

  test('showHints explicitly enables only key hints', async () => {
    const f = await fixture();
    await runAutopilot(f.input, { ...f.deps, options: { ...f.opts, showHints: true } });
    expect(JSON.stringify(f.notifications)).toContain(f.inv.clusters.find(c => c.id === f.clusterId)!.hint);
    expect(JSON.stringify(f.notifications)).not.toContain(f.old.value);
  });

  test('failed saveState never starts provider or host work', async () => {
    const f = await fixture();
    await expect(runAutopilot(f.input, { ...f.deps, async saveState() { throw new Error('disk'); } })).rejects.toThrow();
    expect(f.host.writes).toEqual([]);
    expect(f.trace.filter(c => /^(rotate|rotated|verify|resolve|list|revoke):openai/.test(c))).toEqual([]);
  });

  test('crash mid-wave resumes its saved plan and never creates a second replacement', async () => {
    const f = await fixture();
    const death = new Error('simulated process death');
    f.deps.engine.crashHook = point => { if (point === 'after-write') throw death; };
    await expect(runAutopilot(f.input, f.deps)).rejects.toBe(death);
    expect(f.state.waves[0]?.status).toBe('running');
    delete f.deps.engine.crashHook;
    await resumeWaves({ state: f.state, now: f.deps.engine.now!(), disarmed: false }, f.recoveryDeps);
    expect(f.trace.filter(c => c === 'rotate:openai')).toHaveLength(1);
    expect(f.state.waves[0]?.status).toBe('grace');
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.journal.entries.some(e => e.event === 'resume')).toBe(true);
  });

  test('settleWaves finishes only after grace expires', async () => {
    const f = await fixture();
    await runAutopilot(f.input, f.deps);
    await settleWaves({ state: f.state, inventory: f.input.inventory, now: f.deps.engine.now!(), disarmed: false }, f.recoveryDeps);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    f.clock.ms += 900_001;
    await settleWaves({ state: f.state, inventory: f.input.inventory, now: f.deps.engine.now!(), disarmed: false }, f.recoveryDeps);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(false);
    expect(f.state.waves[0]?.status).toBe('done');
  });

  test.each(['disarmed', 'env', 'self-check'] as const)('settlement while %s keeps old keys valid', async mode => {
    const f = await fixture();
    await runAutopilot(f.input, f.deps);
    f.clock.ms += 900_001;
    const deps = { ...f.recoveryDeps };
    if (mode === 'env') deps.env = { KEYSENTRY_ALERT_ONLY: '1' };
    if (mode === 'self-check') deps.selfCheck = { ok: false, reasons: ['Offline.'] };
    await settleWaves({ state: f.state, inventory: f.input.inventory, now: f.deps.engine.now!(), disarmed: mode === 'disarmed' }, deps);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.state.waves[0]?.status).toBe('grace');
  });

  test('resume while disarmed performs no provider, write, or deployment operation', async () => {
    const f = await fixture();
    f.deps.engine.crashHook = point => { if (point === 'after-store') throw new Error('death'); };
    await expect(runAutopilot(f.input, f.deps)).rejects.toThrow('death');
    delete f.deps.engine.crashHook;
    const before = f.trace.filter(c => /^(rotate|rotated|verify|resolve|list|revoke):openai/.test(c)).length;
    await resumeWaves({ state: f.state, now: f.deps.engine.now!(), disarmed: true }, f.recoveryDeps);
    expect(f.trace.filter(c => /^(rotate|rotated|verify|resolve|list|revoke):openai/.test(c))).toHaveLength(before);
    expect(f.host.writes).toEqual([]);
  });

  test('an expired saved armed plan cannot resume or settle unattended', async () => {
    const f = await fixture();
    await runAutopilot(f.input, f.deps);
    const calls = f.trace.filter(c => /^(rotate|rotated|verify|resolve|list|revoke):openai/.test(c)).length;
    await settleWaves({ state: f.state, inventory: f.input.inventory, now: new Date('2027-12-01T00:00:00Z'), disarmed: false }, f.recoveryDeps);
    expect(f.trace.filter(c => /^(rotate|rotated|verify|resolve|list|revoke):openai/.test(c))).toHaveLength(calls);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
  });

  test('overlapping ticks persist and start only one wave', async () => {
    const f = await fixture();
    const results = await Promise.all([runAutopilot(f.input, f.deps), runAutopilot(f.input, f.deps)]);
    expect(results.flatMap(result => result.executed)).toEqual([f.clusterId]);
    expect(f.trace.filter(line => line === 'rotate:openai')).toHaveLength(1);
    expect(f.state.waves).toHaveLength(1);
  });

  test('disarm during preparation stops further rotations and keeps every old key valid', async () => {
    const f = await fixture();
    f.input.armed = f.arm({}, [f.clusterId, f.generatedClusterId]);
    f.state.armedPlanId = f.input.armed.id;
    const rotate = f.provider.rotate.bind(f.provider);
    f.provider.rotate = async (value, ctx) => { const result = await rotate(value, ctx); f.state.disarmed = true; return result; };
    await runAutopilot(f.input, f.deps);
    expect(f.trace).not.toContain('rotate:app-secret');
    expect(f.host.writes).toEqual([]);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.generate.keys.get(f.oldGenerated.ref)?.active).toBe(true);
    expect(f.state.waves[0]?.status).toBe('stopped');
  });

  test('disarm during deploy prevents another deployment and leaves staged replacements available', async () => {
    const f = await fixture();
    const redeploy = f.host.redeploy.bind(f.host);
    f.host.redeploy = async service => { const result = await redeploy(service); f.state.disarmed = true; return result; };
    const result = await runAutopilot(f.input, f.deps);
    expect(f.host.redeploys).toHaveLength(1);
    expect(f.host.writes).toHaveLength(2);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.provider.keys.get(result.report!.steps[0]!.newKeyRef!)?.active).toBe(true);
  });

  test('zero grace still returns without automatic immediate revocation', async () => {
    const f = await fixture();
    f.input.armed = f.arm({ graceSeconds: 0 });
    f.state.armedPlanId = f.input.armed.id;
    const result = await runAutopilot(f.input, f.deps);
    expect(result.report?.status).toBe('grace-pending');
    expect(f.state.waves[0]?.status).toBe('grace');
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
  });

  test('ask notification carries the actual action id returned by the approval service', async () => {
    const f = await fixture();
    await runAutopilot(f.input, { ...f.deps, async requestApproval() { return { actionId: 'action-actual' }; } });
    expect(f.notifications.find(m => m.kind === 'autopilot:ask')?.actionId).toBe('action-actual');
  });

  test('a valid 2xx that differs from expectStatus fails health checks', async () => {
    const f = await fixture();
    const http = new FakeHttp().on('GET', /^https:\/\/health\.example\/$/, () => text(200, ''));
    f.deps.engine.providerCtx.http = http;
    f.input.armed = f.arm({ healthChecks: [{ serviceKey: f.serviceKeys[0]!, url: 'https://health.example/', expectStatus: 204 }] });
    f.state.armedPlanId = f.input.armed.id;
    const result = await runAutopilot(f.input, f.deps);
    expect(http.calls).toHaveLength(3);
    expect(result.report?.deployments[0]?.state).toBe('failed');
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
  });

  test('a slow approval request runs only after the armed work has finished', async () => {
    const f = await fixture();
    await runAutopilot(f.input, { ...f.deps, async requestApproval() { f.clock.ms = Date.parse('2027-12-01T00:00:00Z'); } });
    expect(f.trace.filter(line => line === 'rotate:openai')).toHaveLength(1);
    expect(f.host.writes).toHaveLength(2);
  });

  test('changing the input inventory during approval cannot widen the checked scope', async () => {
    const f = await fixture();
    const extra = f.host.addService('unarmed', { OPENAI_API_KEY: f.old.value });
    await runAutopilot(f.input, { ...f.deps, async requestApproval() {
      const cluster = f.input.inventory.clusters.find(c => c.id === f.clusterId)!;
      cluster.consumers.push({ ...cluster.consumers[0]!, service: extra });
      f.input.inventory.services.push(extra);
    } });
    expect(f.host.writes.map(write => write.serviceId)).not.toContain('unarmed');
  });

  test('recovery without a self-check fails closed', async () => {
    const f = await fixture();
    await runAutopilot(f.input, f.deps);
    f.clock.ms += 900_001;
    const { selfCheck: _selfCheck, ...deps } = f.recoveryDeps;
    await settleWaves({ state: f.state, inventory: f.input.inventory, now: f.deps.engine.now!(), disarmed: false }, deps);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
  });

  test('settlement uses the supplied tick time even when the dependency clock has an older baseline', async () => {
    const f = await fixture();
    await runAutopilot(f.input, f.deps);
    await settleWaves({ state: f.state, inventory: f.input.inventory, now: new Date('2026-10-27T09:00:00Z'), disarmed: false }, f.recoveryDeps);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(false);
  });

  test('a settlement revoke failure does not claim that every old key is still valid', async () => {
    const f = await fixture();
    f.input.armed = f.arm({}, [f.clusterId, f.generatedClusterId]);
    f.state.armedPlanId = f.input.armed.id;
    await runAutopilot(f.input, f.deps);
    f.generate.revoke = async () => { throw new Error('ambiguous response'); };
    f.clock.ms += 900_001;
    await settleWaves({ state: f.state, inventory: f.input.inventory, now: f.deps.engine.now!(), disarmed: false }, f.recoveryDeps);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(false);
    const failure = f.notifications.find(m => m.kind === 'autopilot:failure');
    expect(failure).toBeDefined();
    expect(failure!.title).not.toContain('Every old key is still valid.');
    expect(failure!.title).toContain('Some old keys may already be revoked.');
  });

  test('adopted auto keys with no readable previous value ask rather than entering a guided unattended wave', async () => {
    const f = await fixture();
    const cluster = f.inv.clusters.find(c => c.id === f.clusterId)! as Cluster & { adopted?: ArmedCluster['adopted'] };
    for (const consumer of cluster.consumers) { consumer.sealed = true; consumer.fingerprint = null; }
    cluster.fingerprint = null;
    cluster.adopted = { fingerprint: f.clusterId, keyRef: f.old.ref, at: f.input.now.toISOString() };
    f.host.capabilities.readValues = false;
    f.input.armed = f.arm();
    f.state.armedPlanId = f.input.armed.id;
    const result = await runAutopilot(f.input, f.deps);
    expect(result.executed).toEqual([]);
    expect(result.asked).toContain(f.clusterId);
    expect(f.state.waves).toEqual([]);
    expect(f.host.writes).toEqual([]);
  });

  test('expiration during the start notification prevents the first provider mutation', async () => {
    const f = await fixture();
    await runAutopilot(f.input, { ...f.deps, async notify(message) {
      f.notifications.push(message);
      if (message.kind === 'autopilot:start') f.clock.ms = Date.parse('2027-12-01T00:00:00Z');
    } });
    expect(f.trace.filter(line => line === 'rotate:openai')).toEqual([]);
    expect(f.host.writes).toEqual([]);
    expect(f.state.waves[0]?.status).toBe('stopped');
  });

  test('grace can settle using a state restored from serialized storage', async () => {
    const f = await fixture();
    await runAutopilot(f.input, f.deps);
    const restored = JSON.parse(JSON.stringify(f.saved.at(-1))) as AutopilotState;
    f.clock.ms += 900_001;
    await settleWaves({ state: restored, inventory: f.input.inventory, now: f.deps.engine.now!(), disarmed: false }, f.recoveryDeps);
    expect(restored.waves[0]?.status).toBe('done');
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(false);
  });

  test('a disarm decision during grace is audited without calling the engine', async () => {
    const f = await fixture();
    await runAutopilot(f.input, f.deps);
    f.clock.ms += 900_001;
    const traceLength = f.trace.length;
    await settleWaves({ state: f.state, inventory: f.input.inventory, now: f.deps.engine.now!(), disarmed: true }, f.recoveryDeps);
    expect(f.trace).toHaveLength(traceLength);
    expect(f.auditEvents.map(event => event.kind)).toContain('autopilot:settle-alert-only');
  });

  test('an interrupted settlement never later claims that already revoked old keys remain valid', async () => {
    const f = await fixture();
    f.input.armed = f.arm({}, [f.clusterId, f.generatedClusterId]);
    f.state.armedPlanId = f.input.armed.id;
    await runAutopilot(f.input, f.deps);
    f.clock.ms += 900_001;
    const death = new Error('settlement process death');
    f.deps.engine.crashHook = (point, detail) => { if (point === 'after-revoke' && detail.clusterId === f.clusterId) throw death; };
    await expect(settleWaves({ state: f.state, inventory: f.input.inventory, now: f.deps.engine.now!(), disarmed: false }, f.recoveryDeps)).rejects.toBe(death);
    delete f.deps.engine.crashHook;
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(false);
    f.generate.failVerifyOfNew = true;
    await settleWaves({ state: f.state, inventory: f.input.inventory, now: f.deps.engine.now!(), disarmed: false }, f.recoveryDeps);
    expect(f.notifications.find(m => m.kind === 'autopilot:failure')?.title).toContain('Some old keys may already be revoked.');
  });

  test('settlement retains every old key if a consumer was manually reverted during grace', async () => {
    const f = await fixture();
    await runAutopilot(f.input, f.deps);
    await f.host.writeVariables(f.services[1]!, { OPENAI_API_KEY: f.old.value }, { skipDeploy: true });
    f.clock.ms += 900_001;
    await settleWaves({ state: f.state, inventory: f.input.inventory, now: f.deps.engine.now!(), disarmed: false }, f.recoveryDeps);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.state.waves[0]?.status).toBe('stopped');
  });

  test('settlement passes a fresh scan so an old key used by a new consumer is kept', async () => {
    const f = await fixture();
    await runAutopilot(f.input, f.deps);
    f.host.addService('new-consumer', { OPENAI_API_KEY: f.old.value });
    const inventory = buildInventory([{ host: 'railway', services: await Promise.all((await f.host.listServices()).map(async service => ({
      service, vars: await f.host.readVariables(service),
    }))) }], f.deps.engine.fingerprintKey);
    f.clock.ms += 900_001;
    const result = await settleWaves({ state: f.state, inventory, now: f.deps.engine.now!(), disarmed: false }, f.recoveryDeps);
    expect(result.settled).toEqual(['wave-incident-1']);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.state.waves[0]?.status).toBe('stopped');
    expect(f.host.peek('new-consumer', 'OPENAI_API_KEY')).toBe(f.old.value);
  });

  test('a JavaScript settlement caller omitting the latest inventory cannot revoke', async () => {
    const f = await fixture();
    await runAutopilot(f.input, f.deps);
    f.clock.ms += 900_001;
    await settleWaves({ state: f.state, now: f.deps.engine.now!(), disarmed: false } as Parameters<typeof settleWaves>[0], f.recoveryDeps);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    expect(f.state.waves[0]?.status).toBe('grace');
    expect(f.auditEvents.map(event => event.kind)).toContain('autopilot:settle-blocked');
  });

  test('recovery rechecks saved scope against the signed plan before any write', async () => {
    const f = await fixture();
    f.deps.engine.crashHook = point => { if (point === 'after-store') throw new Error('death'); };
    await expect(runAutopilot(f.input, f.deps)).rejects.toThrow('death');
    delete f.deps.engine.crashHook;
    const extra = f.host.addService('unarmed', { OPENAI_API_KEY: f.old.value });
    const wave = f.state.waves[0]!;
    const consumer = { ...wave.plan!.steps[0]!.consumers[0]!, service: extra };
    wave.plan!.steps[0]!.consumers.push(consumer);
    wave.plan!.services.push(extra);
    wave.inventory!.clusters.find(c => c.id === f.clusterId)!.consumers.push(consumer);
    wave.inventory!.services.push(extra);
    await resumeWaves({ state: f.state, now: f.deps.engine.now!(), disarmed: false }, f.recoveryDeps);
    expect(f.host.writes).toEqual([]);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
  });
});

test('isAlertOnly combines the environment, disarm and self-check without changing state', () => {
  const state: AutopilotState = { armedPlanId: null, disarmed: true, waves: [] };
  const result = isAlertOnly({ env: { KEYSENTRY_ALERT_ONLY: '1' }, state, selfCheck: { ok: false, reasons: ['Offline.'] } });
  expect(result.alertOnly).toBe(true);
  expect(result.reasons).toHaveLength(3);
  expect(state).toEqual({ armedPlanId: null, disarmed: true, waves: [] });
  expect(isAlertOnly({ env: { KEYSENTRY_ALERT_ONLY: '0' }, state: { ...state, disarmed: false }, selfCheck: { ok: true, reasons: [] } }))
    .toEqual({ alertOnly: false, reasons: [] });
});
