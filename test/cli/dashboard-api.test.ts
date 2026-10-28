import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createRuntime } from '../../src/cli/runtime.js';
import { createDashboardApi, createDashboardPasskeyStore } from '../../src/cli/dashboard-api.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { getProvider } from '../../src/providers/index.js';
import { createMonitorState } from '../../src/monitor/index.js';
import { createApprovalService } from '../../src/approvals/index.js';
import { createFakeAuthenticator } from '../dashboard/helpers/fake-authenticator.js';

const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map(path => rm(path, { recursive: true, force: true }))); });
async function setup() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-api-')); dirs.push(cwd);
  const host = new FakeHost('railway'); host.pendingPolls = 0;
  const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-0123456789abcdef');
  const old = provider.issue(); host.addService('api', { OPENROUTER_API_KEY: old.value });
  const vault = createFakeVault();
  const runtime = await createRuntime({ cwd, userDir: join(cwd, '.user'), env: {}, hosts: [host],
    providers: id => id === provider.id ? provider : getProvider(id), vault, http: new FakeHttp(),
    inflight: createFakeInFlight(), log: silentLogger, stdinIsTTY: false, stdoutIsTTY: false, sleep: async () => {}, firstRunGit: async () => ({ code: 0 }) });
  const api = createDashboardApi(runtime);
  const call = async (route: string, body?: unknown) => api[route]!.handler(body, { session: 'test-session' });
  return { runtime, api, call, host, provider, vault, old };
}

describe('dashboard runtime routes', () => {
  it('declares exactly the documented routes and passkey requirements', async () => {
    const { api } = await setup();
    const get = ['overview', 'keys', 'platforms', 'access', 'network', 'rotations', 'autopilot', 'autopilot/eligibility', 'activity', 'notifications', 'approvals', 'settings', 'hygiene',
      'team/candidates'];
    const readPost = ['rotate/preview', 'drill', 'timeline', 'card', 'notifications/verify', 'autopilot/disarm'];
    const writePost = ['vault/store', 'vault/remove', 'rotate/execute', 'rotation/finish', 'rotation/undo', 'autopilot/arm', 'notifications/add', 'notifications/remove', 'notifications/test', 'approvals/approve', 'approvals/dismiss', 'settings/update', 'spend-limits/apply', 'reveal'];
    expect(Object.keys(api).sort()).toEqual([...get, ...readPost, ...writePost].sort());
    for (const route of get) expect(api[route]).toMatchObject({ method: 'GET', mutating: false });
    for (const route of readPost) expect(api[route]).toMatchObject({ method: 'POST', mutating: false });
    for (const route of writePost) expect(api[route]).toMatchObject({ method: 'POST', mutating: true });
    // Disarm stays passkey-free on the local dashboard; the team dashboard asks for the member's passkey (review M3).
    expect(Object.entries(api).filter(([, route]) => route.teamPasskey).map(([name]) => name)).toEqual(['autopilot/disarm']);
  });

  it.each([
    ['vault/store', { name: 'unknown', role: 'write', value: 'private-value' }],
    ['vault/store', { name: 'RAILWAY_TOKEN', role: 'other', value: 'private-value' }],
    ['vault/remove', { name: '../key', role: 'write' }],
    ['rotate/preview', { clusterIds: [3] }],
    ['rotate/execute', { planId: '../../secret', planHash: 'a'.repeat(64) }],
    ['rotation/finish', { planId: 'plan-20261027000000-abcd', early: 'yes' }],
    ['rotation/undo', { planId: 'plan-20261027000000-abcd', clusterIds: [] }],
    ['autopilot/arm', { clusterIds: ['one'], adopt: [], graceMinutes: 0, maxServices: 0, validDays: 1 }],
    ['autopilot/arm', { clusterIds: ['one'], adopt: [], graceMinutes: 0, maxServices: 1, validDays: 366 }],
    ['settings/update', { rotateEveryDays: 0 }],
    ['settings/update', { spendCapsUsd: { openrouter: -1 } }],
    ['settings/update', { digestDay: 'today' }],
    ['settings/update', { showHints: 'yes' }],
    ['card', { platform: false, counts: false, extra: true }],
    ['notifications/add', { kind: 'smtp', label: 'Email', settings: { host: 'mail.example.test', port: '25' } }],
    ['notifications/add', { kind: 'console', label: 'Console', settings: { value: 'private-value' } }],
    ['notifications/add', { kind: 'webhook', label: 'Webhook', settings: { url: 'http://evil.example.test' } }],
    ['notifications/add', { kind: 'resend', label: 'Email', settings: { apiKey: 're_privatevalue', from: 'missing-address', to: 'also-invalid' } }],
    ['notifications/test', { extra: true }],
    ['autopilot/disarm', { extra: true }],
    ['reveal', { clusterId: '' }],
  ])('revalidates %s input without reflecting values', async (route, body) => {
    const { call } = await setup();
    await expect(call(route as string, body)).rejects.toThrow();
    try { await call(route as string, body); } catch (error) { expect(String(error)).not.toContain('private-value'); }
  });

  it('stores credentials through the common runtime without a terminal and never returns the value', async () => {
    const { call, vault } = await setup();
    expect(await call('vault/store', { name: 'RAILWAY_TOKEN', role: 'read', value: 'private-platform-token' })).toEqual({ stored: true });
    expect((await vault.get('cred/RAILWAY_TOKEN@read'))?.toString()).toBe('private-platform-token');
    const platforms = await call('platforms') as { platforms: { host: string; availableRoles: string[]; storedRoles: string[] }[] };
    expect(platforms.platforms.find(platform => platform.host === 'railway')).toMatchObject({ availableRoles: ['read', 'write'], storedRoles: ['read'] });
    expect(await call('vault/remove', { name: 'RAILWAY_TOKEN', role: 'read' })).toEqual({ removed: true });
  });

  it('offers supported roles before any token has been stored', async () => {
    const { call } = await setup();
    const result = await call('platforms') as { platforms: { host: string; availableRoles: string[]; storedRoles: string[] }[] };
    expect(result.platforms.find(platform => platform.host === 'railway')).toMatchObject({ availableRoles: ['read', 'write'], storedRoles: [] });
  });

  it('refreshes the local summary within 60 seconds when files change', async () => {
    const { call, runtime } = await setup();
    let at = new Date('2026-10-27T12:00:00Z');
    runtime.now = () => at;
    expect(await call('overview')).toMatchObject({ firstRun: { findings: [] } });
    await writeFile(join(runtime.config.cwd, '.env'), `OPENROUTER_API_KEY=sk-or-v1-${'d'.repeat(64)}\n`);
    at = new Date(at.getTime() + 60_000);
    expect(await call('overview')).toMatchObject({ firstRun: { findings: [expect.any(Object)] } });
  });

  it('accepts a partial provider spending cap and returns the persisted settings', async () => {
    const { call } = await setup();
    const updated = await call('settings/update', { spendCapsUsd: { openrouter: 15 }, rotateEveryDays: 45 }) as { spendCapsUsd: Record<string, number>; rotateEveryDays: number };
    expect(updated.spendCapsUsd).toEqual({ openrouter: 15 });
    expect(updated.rotateEveryDays).toBe(45);
    expect(await call('settings')).toEqual(updated);
  });

  it('returns every GET projection without secret values', async () => {
    const { call, old } = await setup();
    for (const route of ['overview', 'keys', 'platforms', 'access', 'network', 'rotations', 'autopilot', 'autopilot/eligibility', 'activity', 'notifications', 'approvals', 'settings', 'hygiene']) {
      const response = await call(route);
      expect(response).toBeTypeOf('object');
      expect(JSON.stringify(response)).not.toContain(old.value);
    }
  });

  it('marks committed keys when Keys is the first requested screen', async () => {
    const { runtime, call, old } = await setup();
    runtime.firstRunGit = async (_args, opts) => {
      for (const line of [`\x00${'a'.repeat(40)}\x002026-10-27T12:00:00Z`, '+++ b/.env', '@@ -0,0 +1 @@', `+OPENROUTER_API_KEY=${old.value}`]) opts.onLine(line);
      return { code: 0 };
    };
    expect(await call('keys')).toMatchObject({ keys: [{ inGitHistory: true, state: 'attention' }] });
  });

  it('uses the shared watcher health and notification adapters for armed status', async () => {
    const { runtime, call } = await setup();
    await call('drill', {}); const inv = await runtime.inventory();
    await call('autopilot/arm', { clusterIds: inv.clusters.map(cluster => cluster.id), adopt: [], graceMinutes: 15, maxServices: 10, validDays: 1 });
    const at = runtime.now().toISOString();
    await runtime.store.writeJson('plan', join(runtime.paths.dir, 'watcher-tick.json'), { startedAt: at, lastNotifySuccessAt: at });
    await runtime.store.writeJson('plan', join(runtime.paths.dir, 'notification-messages.json'), { messages: [], lastSuccessAt: at });
    expect(await call('autopilot')).toMatchObject({ state: 'armed', reasons: [], lastNotificationAt: at });
  });

  it('does not attribute a global notification success to channels with unknown delivery history', async () => {
    const { runtime, call } = await setup();
    runtime.config.settings.notify.channels = [{ id: 'one', kind: 'console' }, { id: 'two', kind: 'console' }];
    const at = runtime.now().toISOString();
    await runtime.store.writeJson('plan', join(runtime.paths.dir, 'notification-messages.json'), { messages: [], lastSuccessAt: at, channelSuccessAt: { one: at } });
    expect(await call('notifications')).toMatchObject({ channels: [{ id: 'one', lastSuccessAt: at }, { id: 'two', lastSuccessAt: null }] });
  });

  it('adds a labeled notification channel, tests it, verifies its signed code and removes it', async () => {
    const { runtime, call } = await setup();
    const channel = await call('notifications/add', { kind: 'console', label: 'Local console', settings: {} }) as { id: string };
    expect(await call('notifications')).toMatchObject({ channels: [{ id: channel.id, label: 'Local console', kind: 'console' }] });
    expect(await call('notifications/test', {})).toEqual({ delivered: [channel.id], failed: [] });
    const cache = await runtime.store.readJson<{ messages: { code: string }[] }>('plan', join(runtime.paths.dir, 'notification-messages.json'));
    expect(await call('notifications/verify', { code: cache!.messages[0]!.code })).toEqual({ valid: true, message: 'Notification signature verified.' });
    expect(await call('notifications/remove', { id: channel.id })).toEqual({ removed: true });
    expect(await call('notifications')).toMatchObject({ channels: [] });
  });

  it('does not reflect a secret as a notification label', async () => {
    const { call, old } = await setup();
    await expect(call('notifications/add', { kind: 'console', label: old.value, settings: {} })).rejects.toThrow();
  });

  it('marks keys unarmed after disarm and keeps the safe stop available to an agent-marked runtime', async () => {
    const { runtime, call } = await setup();
    await call('drill', {}); const inv = await runtime.inventory();
    await call('autopilot/arm', { clusterIds: inv.clusters.map(cluster => cluster.id), adopt: [], graceMinutes: 15, maxServices: 10, validDays: 1 });
    expect(await call('keys')).toMatchObject({ keys: [{ armed: true }] });
    runtime.mutationContext.env.CODEX_CI = '1';
    expect(await call('autopilot/disarm', {})).toEqual({ state: 'disarmed' });
    expect(await call('keys')).toMatchObject({ keys: [{ armed: false }] });
  });

  it('returns only the documented spend application fields', async () => {
    const { runtime, call } = await setup(); const inv = await runtime.scan();
    const result = await call('spend-limits/apply', { clusterIds: inv.clusters.map(cluster => cluster.id) });
    expect(Object.keys(result as object).sort()).toEqual(['applied', 'skipped']);
  });

  it('returns the actual completed monitor approval result for containment actions', async () => {
    const { runtime, call, provider, old } = await setup(); const inv = await runtime.scan();
    const cluster = inv.clusters[0]!; const state = createMonitorState();
    state.keyRefs[cluster.id] = old.ref;
    state.pendingActions.push({ id: 'action-cap', action: 'cap', signalId: 'signal-cap', clusterIds: [cluster.id], status: 'pending', createdAt: runtime.now().toISOString() });
    await runtime.store.writeJson('monitor', runtime.paths.monitor, state);
    const review = await call('approvals') as { pending: { id: string; changes: string[]; reviewHash: string }[] };
    expect(review.pending[0]!.changes.join(' ')).toMatch(/caps|disables|disable/i);
    expect(review.pending[0]!.reviewHash).toMatch(/^[a-f0-9]{64}$/);
    expect(await call('approvals/approve', { id: 'action-cap', reviewHash: review.pending[0]!.reviewHash })).toEqual({ result: 'executed' });
    expect(provider.keys.get(old.ref)?.active).toBe(false);
  });

  it('refuses an approval when the reviewed action changed', async () => {
    const { runtime, call, provider, old } = await setup(); const inv = await runtime.scan();
    const cluster = inv.clusters[0]!; const state = createMonitorState();
    state.keyRefs[cluster.id] = old.ref;
    state.pendingActions.push({ id: 'action-change', action: 'cap', signalId: 'signal', clusterIds: [cluster.id], status: 'pending', createdAt: runtime.now().toISOString() });
    await runtime.store.writeJson('monitor', runtime.paths.monitor, state);
    const review = await call('approvals') as { pending: { reviewHash: string }[] };
    state.pendingActions[0]!.action = 'rotate';
    await runtime.store.writeJson('monitor', runtime.paths.monitor, state);
    await expect(call('approvals/approve', { id: 'action-change', reviewHash: review.pending[0]!.reviewHash })).rejects.toThrow(/changed/i);
    expect(provider.keys.get(old.ref)?.active).toBe(true);
    expect(provider.keys.size).toBe(1);
  });

  it('describes autopilot approvals and rejects a replaced request after review', async () => {
    const { runtime, call, provider } = await setup(); const inv = await runtime.scan();
    const service = createApprovalService({ store: runtime.store, audit: runtime.audit, deviceKeys: async () => [], credentials: async () => [],
      now: runtime.now, rpId: 'localhost', origins: ['http://localhost'] });
    const action = { id: 'autopilot-review', kind: 'autopilot', clusterIds: [inv.clusters[0]!.id], planHash: 'a'.repeat(64) };
    const request = await service.request(action, false);
    await runtime.store.writeJson('pending', join(runtime.paths.dir, 'watcher-approvals.json'), { actions: [{ action, request }] });
    const review = await call('approvals') as { pending: { changes: string[]; reviewHash: string }[] };
    expect(review.pending[0]!.changes.join(' ')).toContain('OPENROUTER_API_KEY');
    expect(review.pending[0]!.changes.join(' ')).toContain('redeploy');
    const changed = { ...action, planHash: 'b'.repeat(64) };
    const updatedRequest = await service.request(changed, false);
    await runtime.store.writeJson('pending', join(runtime.paths.dir, 'watcher-approvals.json'), { actions: [{ action: changed, request: updatedRequest }] });
    await expect(call('approvals/approve', { id: action.id, reviewHash: review.pending[0]!.reviewHash })).rejects.toThrow(/changed/i);
    expect(provider.keys.size).toBe(1);
    expect(await service.status(action.id)).toBe('pending');
  });

  it('disarms while arming is waiting for a scan, and the older request cannot re-arm', async () => {
    const { runtime, call, host, provider } = await setup();
    await call('drill', {});
    const inv = await runtime.inventory();
    let continueScan!: () => void; let enteredScan!: () => void;
    const entered = new Promise<void>(resolve => { enteredScan = resolve; });
    const continued = new Promise<void>(resolve => { continueScan = resolve; });
    const list = host.listServices.bind(host);
    host.listServices = async () => { enteredScan(); await continued; return list(); };
    const arming = call('autopilot/arm', { clusterIds: inv.clusters.map(cluster => cluster.id), adopt: [], graceMinutes: 15, maxServices: 10, validDays: 1 });
    const outcome = arming.catch(error => error);
    await entered;
    expect(await call('autopilot/disarm', {})).toEqual({ state: 'disarmed' });
    continueScan();
    expect(String(await outcome)).toContain('cancelled');
    expect((await runtime.autopilotManager().loadState()).disarmed).toBe(true);
    expect(provider.keys.size).toBe(1);
  });

  it('returns value-free key views and only reveals readable values with a minimal audit', async () => {
    const { runtime, call, old } = await setup();
    const inv = await runtime.scan();
    const keys = await call('keys') as { keys: { id: string; places: { writeOnly: boolean }[] }[] };
    expect(keys.keys).toHaveLength(1);
    expect(keys.keys[0]?.places[0]?.writeOnly).toBe(false);
    expect(JSON.stringify(keys)).not.toContain(old.value);
    expect(await call('reveal', { clusterId: inv.clusters[0]!.id })).toEqual({ value: old.value });
    const missing = 'sealed:missing';
    await expect(call('reveal', { clusterId: missing })).rejects.toThrow();
    expect(await runtime.audit.verify()).toMatchObject({ ok: true });
  });

  it('binds execution to a saved preview hash and returns grace-pending before finish', async () => {
    const { runtime, call, provider, old } = await setup();
    const inv = await runtime.scan();
    const preview = await call('rotate/preview', { clusterIds: [inv.clusters[0]!.id] }) as { planId: string; planHash: string; changes: string[] };
    expect(preview.changes.join('\n')).not.toContain(old.value);
    await expect(call('rotate/execute', { planId: preview.planId, planHash: 'f'.repeat(64) })).rejects.toThrow();
    expect(provider.keys.size).toBe(1);
    const rotation = await call('rotate/execute', preview && { planId: preview.planId, planHash: preview.planHash }) as { report: { status: string } };
    expect(rotation.report.status).toBe('grace-pending');
    expect(provider.keys.get(old.ref)?.active).toBe(true);
    const finished = await call('rotation/finish', { planId: preview.planId, early: true }) as { report: { status: string } };
    expect(finished.report.status).toBe('complete');
    expect(provider.keys.get(old.ref)?.active).toBe(false);
  });
});

describe('dashboard encrypted-state passkeys', () => {
  it('persists encrypted state and updates counters without adding duplicates', async () => {
    const { runtime, vault } = await setup(); const store = createDashboardPasskeyStore(runtime.store, vault);
    const credential = createFakeAuthenticator().credential();
    await store.add(credential);
    expect(await vault.list('passkey/')).toEqual([]);
    expect(await runtime.store.readJson('passkeys', join(runtime.paths.dir, 'passkeys.json'))).toEqual([credential]);
    await expect(store.add(credential)).rejects.toThrow();
    await store.update({ ...credential, signCount: 4 });
    expect(await store.list()).toEqual([{ ...credential, signCount: 4 }]);
    await expect(store.update({ ...credential, signCount: 1 })).rejects.toThrow();
  });
});
