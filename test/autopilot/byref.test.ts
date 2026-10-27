import { expect, test } from 'vitest';
import { buildArmedPlan, signArmedPlan } from '../../src/autopilot/armed-plan.js';
import { runAutopilot, resumeWaves, settleWaves, type AutopilotState } from '../../src/autopilot/runner.js';
import { buildInventory, fingerprint } from '../../src/core/index.js';
import { openrouterProvider } from '../../src/providers/openrouter.js';
import { generateDeviceKey } from '../../src/security/index.js';
import type { ArmedCluster, AuditEvent, Cluster, Incident, NotifyMessage } from '../../src/types.js';
import { FakeHttp, json } from '../helpers/fake-http.js';
import { FakeHost } from '../helpers/fakes.js';
import { recoveryFixture } from '../rotate/recovery-fixture.js';

async function fixture() {
  const f = await recoveryFixture();
  const host = new FakeHost('fly', { readValues: false });
  const oldValue = `sk-or-v1-${'a'.repeat(50)}`;
  const service = host.addService('worker', { OPENROUTER_API_KEY: oldValue });
  const inventory = buildInventory([{ host: 'fly', services: [{ service, vars: await host.readVariables(service) }] }], f.deps.fingerprintKey);
  const cluster = inventory.clusters[0]! as Cluster & { adopted?: ArmedCluster['adopted'] };
  cluster.adopted = { fingerprint: fingerprint(oldValue, f.deps.fingerprintKey), keyRef: 'old-hash', at: f.deps.now!().toISOString() };
  const key = generateDeviceKey();
  const arm = () => signArmedPlan(buildArmedPlan({ projectId: 'project', inventory, clusterIds: [cluster.id], hosts: ['fly'],
    options: { graceSeconds: 1 }, now: f.deps.now!() }).plan, key);
  const armed = arm();
  const keys = new Map([['old-hash', { value: oldValue, active: true, label: 'old-label' }]]);
  let creates = 0;
  const http = new FakeHttp()
    .on('GET', /^https:\/\/openrouter.ai\/api\/v1\/keys\/([\w-]+)$/, (_request, match) => {
      const current = keys.get(match[1]!);
      return json(current ? 200 : 404, { data: { hash: match[1], name: 'worker', limit: 12, disabled: !current?.active } });
    })
    .on('POST', /^https:\/\/openrouter.ai\/api\/v1\/keys$/, request => {
      expect(JSON.parse(request.body!)).toEqual({ name: 'worker', limit: 12 });
      const ref = `new-hash-${++creates}`;
      const value = `sk-or-v1-${String(creates).repeat(50)}`;
      keys.set(ref, { value, active: true, label: `label-${creates}` });
      return json(200, { key: value, data: { hash: ref } });
    })
    .on('GET', /^https:\/\/openrouter.ai\/api\/v1\/key$/, request => {
      const value = request.headers?.Authorization?.replace('Bearer ', '');
      const current = [...keys.values()].find(key => key.value === value);
      return json(current?.active ? 200 : 401, { data: { label: current?.label } });
    })
    .on('GET', /^https:\/\/openrouter.ai\/api\/v1\/keys\?include_disabled=true$/, () => json(200, {
      data: [...keys].map(([hash, key]) => ({ hash, label: key.label, disabled: !key.active, created_at: f.deps.now!().toISOString() })),
    }))
    .on('DELETE', /^https:\/\/openrouter.ai\/api\/v1\/keys\/([\w-]+)$/, (_request, match) => {
      keys.get(match[1]!)!.active = false;
      return json(200, {});
    });
  f.deps.hosts = { fly: host };
  f.deps.providers = () => openrouterProvider;
  f.deps.providerCtx.http = http;
  f.deps.providerCtx.credentials = { OPENROUTER_PROVISIONING_KEY: 'management-token' };
  const notifications: NotifyMessage[] = [];
  const events: AuditEvent[] = [];
  const saved: AutopilotState[] = [];
  const state: AutopilotState = { armedPlanId: armed.id, disarmed: false, waves: [] };
  const incident: Incident = { id: 'fly-incident', host: 'fly', openedAt: f.deps.now!().toISOString(),
    status: 'triggered', evidence: [], trigger: { at: f.deps.now!().toISOString(), rule: 'official' } };
  const input = { incident, armed, trustedKeyIds: [key.keyId], inventory, state,
    selfCheck: { ok: true, reasons: [] as string[] }, env: {}, now: f.deps.now!() };
  const deps = { engine: f.deps, options: f.opts,
    async notify(message: NotifyMessage) { notifications.push(message); },
    async requestApproval() {},
    audit: { async append(event: AuditEvent) { events.push(event); }, async checkpoint() {},
      async verify() { return { ok: true, entries: events.length, checkpoints: 0 }; } },
    async saveState(state: AutopilotState) { saved.push(structuredClone(state)); },
  };
  const recoveryDeps = { ...deps, trustedKeyIds: [key.keyId], selfCheck: input.selfCheck, env: {} };
  return { ...f, input, deps, recoveryDeps, host, keys, inventory, cluster, state, notifications, events, saved, arm, http, service, oldValue };
}

test('a Fly-only adopted OpenRouter key rotates, retains its next adoption and settles by reference', async () => {
  const f = await fixture();
  const result = await runAutopilot(f.input, f.deps);
  expect(result.executed).toEqual([f.cluster.id]);
  expect(result.report?.status).toBe('grace-pending');
  const nextValue = f.keys.get('new-hash-1')!.value;
  const update = { fingerprint: fingerprint(nextValue, f.deps.engine.fingerprintKey), keyRef: 'new-hash-1', at: expect.any(String) };
  expect(result.adoptionUpdates).toEqual({ [f.cluster.id]: update });
  expect(f.state.adoptionUpdates).toEqual(result.adoptionUpdates);
  expect(f.saved.at(-1)?.adoptionUpdates).toEqual(result.adoptionUpdates);
  expect(f.host.peek('worker', 'OPENROUTER_API_KEY')).toBe(nextValue);
  expect(f.keys.get('old-hash')!.active).toBe(true);
  expect(result.report!.pendingRevocations![0]!.undoAvailable).toBe(false);
  f.clock.ms += 1_001;
  await settleWaves({ state: f.state, now: f.deps.engine.now!(), disarmed: false, inventory: f.inventory }, f.recoveryDeps);
  expect(f.keys.get('old-hash')!.active).toBe(false);
  expect(f.keys.get('new-hash-1')!.active).toBe(true);
  expect(f.notifications.filter(message => message.kind === 'autopilot:adoption-rearm')).toHaveLength(1);
  expect(f.notifications.find(message => message.kind === 'autopilot:adoption-rearm')).toMatchObject({ severity: 'info' });
  const publicText = JSON.stringify([result, f.notifications, f.events]);
  expect(publicText).not.toContain(f.oldValue);
  expect(publicText).not.toContain(nextValue);
});

test('pending adoption changes ask for re-arming and cannot reuse a stale signed provider reference', async () => {
  const f = await fixture();
  await runAutopilot(f.input, f.deps);
  const second = await runAutopilot({ ...f.input, incident: { ...f.input.incident, id: 'second-incident' } }, f.deps);
  expect(second.executed).toEqual([]);
  expect(second.asked).toEqual([f.cluster.id]);
  expect(f.http.callsTo('POST', /\/keys$/)).toHaveLength(1);
  expect(f.notifications.filter(message => message.kind === 'autopilot:adoption-rearm')).toHaveLength(1);
});

test('a locally re-signed adoption permits the next incident to rotate the replacement again', async () => {
  const f = await fixture();
  const first = await runAutopilot(f.input, f.deps);
  f.cluster.adopted = first.adoptionUpdates![f.cluster.id]!;
  const armed = f.arm();
  f.state.armedPlanId = armed.id;
  const second = await runAutopilot({ ...f.input, armed, incident: { ...f.input.incident, id: 'second-incident' } }, f.deps);
  expect(second.executed).toEqual([f.cluster.id]);
  expect(second.report!.steps[0]).toMatchObject({ oldKeyRef: 'new-hash-1', newKeyRef: 'new-hash-2' });
  expect(second.adoptionUpdates![f.cluster.id]!.keyRef).toBe('new-hash-2');
});

test('by-reference recovery returns adoption updates after a crash following storage', async () => {
  const f = await fixture();
  f.deps.engine.crashHook = point => { if (point === 'after-store') throw new Error('death'); };
  await expect(runAutopilot(f.input, f.deps)).rejects.toThrow('death');
  delete f.deps.engine.crashHook;
  const result = await resumeWaves({ state: f.state, now: f.deps.engine.now!(), disarmed: false }, f.recoveryDeps);
  expect(result.resumed).toEqual(['wave-fly-incident']);
  expect(result.adoptionUpdates![f.cluster.id]).toMatchObject({ keyRef: 'new-hash-1' });
  expect(f.http.callsTo('POST', /\/keys$/)).toHaveLength(1);
});

test('an unsuccessful re-arm notification is retried on recovery without repeating creation', async () => {
  const f = await fixture();
  await expect(runAutopilot(f.input, { ...f.deps, async notify(message) {
    if (message.kind === 'autopilot:adoption-rearm') throw new Error('channel unavailable');
    f.notifications.push(message);
  } })).rejects.toThrow('channel unavailable');
  const result = await resumeWaves({ state: f.state, now: f.deps.engine.now!(), disarmed: false }, f.recoveryDeps);
  expect(result.resumed).toEqual(['wave-fly-incident']);
  expect(f.notifications.filter(message => message.kind === 'autopilot:adoption-rearm')).toHaveLength(1);
  expect(f.http.callsTo('POST', /\/keys$/)).toHaveLength(1);
});

test('expiration during start notification prevents a rotateByRef mutation', async () => {
  const f = await fixture();
  await runAutopilot(f.input, { ...f.deps, async notify(message) {
    f.notifications.push(message);
    if (message.kind === 'autopilot:start') f.clock.ms = Date.parse('2027-12-01T00:00:00Z');
  } });
  expect(f.http.callsTo('POST', /\/keys$/)).toHaveLength(0);
  expect(f.host.writes).toEqual([]);
});

test.each(['disarmed', 'expired'] as const)('%s during reference metadata lookup prevents the subsequent create request', async mode => {
  const f = await fixture();
  const request = f.http.request.bind(f.http);
  f.http.request = async input => {
    const response = await request(input);
    if (input.method === 'GET' && input.url.endsWith('/keys/old-hash')) {
      if (mode === 'disarmed') f.state.disarmed = true;
      else f.clock.ms = Date.parse('2027-12-01T00:00:00Z');
    }
    return response;
  };
  await runAutopilot(f.input, f.deps);
  expect(f.http.callsTo('POST', /\/keys$/)).toHaveLength(0);
  expect(f.host.writes).toEqual([]);
  expect(f.keys.get('old-hash')!.active).toBe(true);
});

test('unattended execution takes the adopted reference only from its signed plan', async () => {
  const f = await fixture();
  f.deps.options.adoptedKeyRefs = { [f.cluster.id]: 'unsigned-reference' };
  const result = await runAutopilot(f.input, f.deps);
  expect(result.report!.steps[0]!.oldKeyRef).toBe('old-hash');
  expect(f.http.callsTo('GET', /\/keys\/old-hash$/)).toHaveLength(1);
  expect(f.http.callsTo('GET', /unsigned-reference/)).toEqual([]);
});

test('a failed by-reference verification cleans up and records no replacement adoption', async () => {
  const f = await fixture();
  const request = f.http.request.bind(f.http);
  f.http.request = input => input.url === 'https://openrouter.ai/api/v1/key'
    ? Promise.resolve(json(401, {})) : request(input);
  const result = await runAutopilot(f.input, f.deps);
  expect(result.report?.status).toBe('failed');
  expect(f.keys.get('old-hash')!.active).toBe(true);
  expect(f.keys.get('new-hash-1')!.active).toBe(false);
  expect(result.adoptionUpdates).toBeUndefined();
  expect(f.state.adoptionUpdates).toBeUndefined();
  expect(f.notifications.filter(message => message.kind === 'autopilot:adoption-rearm')).toEqual([]);
});

test.each(['deployment', 'health', 'uncertain-write'] as const)('a %s failure retains delivered adoption metadata and prevents a stale reference next incident', async mode => {
  const f = await fixture();
  if (mode === 'deployment') f.host.failDeploysFor.add('worker');
  if (mode === 'health') f.deps.engine.healthCheck = async () => ({ ok: false, detail: 'Health check failed.' });
  if (mode === 'uncertain-write') {
    const write = f.host.writeVariables.bind(f.host);
    f.host.writeVariables = async (...args) => { await write(...args); throw new Error('response lost'); };
  }
  const first = await runAutopilot(f.input, f.deps);
  expect(first.report?.status).toBe('partial');
  expect(f.state.waves[0]?.status).toBe('stopped');
  expect(f.host.peek('worker', 'OPENROUTER_API_KEY')).toBe(f.keys.get('new-hash-1')!.value);
  expect(f.state.adoptionUpdates?.[f.cluster.id]).toMatchObject({ keyRef: 'new-hash-1' });
  const second = await runAutopilot({ ...f.input, incident: { ...f.input.incident, id: 'second-incident' } }, f.deps);
  expect(second.executed).toEqual([]);
  expect(second.asked).toEqual([f.cluster.id]);
  expect(f.http.callsTo('POST', /\/keys$/)).toHaveLength(1);
  expect(f.keys.get('old-hash')!.active).toBe(true);
});

test('settlement keeps an adopted old key that a fresh scan finds on another readable consumer', async () => {
  const f = await fixture();
  await runAutopilot(f.input, f.deps);
  const otherHost = new FakeHost('railway');
  const service = otherHost.addService('reappeared', { OPENROUTER_API_KEY: f.oldValue });
  f.deps.engine.hosts.railway = otherHost;
  const inventory = buildInventory([
    { host: 'fly', services: [{ service: f.service, vars: await f.host.readVariables(f.service) }] },
    { host: 'railway', services: [{ service, vars: await otherHost.readVariables(service) }] },
  ], f.deps.engine.fingerprintKey);
  f.clock.ms += 1_001;
  await settleWaves({ state: f.state, now: f.deps.engine.now!(), disarmed: false, inventory }, f.recoveryDeps);
  expect(f.keys.get('old-hash')!.active).toBe(true);
  expect(f.state.waves[0]?.status).toBe('stopped');
});
