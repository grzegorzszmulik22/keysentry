import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, test, vi } from 'vitest';
import { createRuntime } from '../../src/cli/runtime.js';
import { createPhase3Runtime } from '../../src/cli/phase3-runtime.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { FakeHttp, json, silentLogger } from '../helpers/fake-http.js';
import { FakeHost } from '../helpers/fakes.js';
import { createMonitorState } from '../../src/monitor/index.js';
import { createHygieneStateStore } from '../../src/hygiene/index.js';

const dirs: string[] = [];
afterEach(async () => { vi.restoreAllMocks(); for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
async function setup(tty = true) {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-phase3-runtime-')); dirs.push(cwd);
  const http = new FakeHttp(), vault = createFakeVault(), host = new FakeHost('railway');
  const value = `sk-or-v1-${'0123456789abcdef'.repeat(4)}`;
  host.addService('api', { OPENROUTER_API_KEY: value });
  const rt = await createRuntime({ cwd, userDir: join(cwd, 'user'), vault, http, env: {}, hosts: [host],
    inflight: createFakeInFlight(), log: silentLogger, stdinIsTTY: tty, stdoutIsTTY: tty,
    now: () => new Date('2026-10-27T12:00:00.000Z'), firstRunGit: async () => ({ code: 0 }) });
  await rt.scan();
  return { rt, api: createPhase3Runtime(rt), http, vault, host, value };
}

test('settings persist encrypted and update rotation and hygiene engine settings', async () => {
  const { rt, api } = await setup();
  expect(await api.settings()).toMatchObject({ rotateEveryDays: 90, digestDay: 'off' });
  const updated = await api.updateSettings({ graceMinutes: 7, rotateEveryDays: 30, spendCapsUsd: { openrouter: 12 }, digestDay: 'fri', showHints: true });
  expect(await createPhase3Runtime(rt).settings()).toEqual(updated);
  expect(rt.config.rotation.graceMs).toBe(420_000);
  expect((await createHygieneStateStore(rt.store).load()).settings).toEqual({ rotateEveryDays: 30, spendCapsUsd: { openrouter: 12 } });
  expect(await readFile(join(rt.paths.dir, 'dashboard-settings.json'), 'utf8')).toMatch(/^keysentry-encrypted:v1\n/);
});

test.each([{ graceMinutes: -1 }, { rotateEveryDays: 0 }, { spendCapsUsd: { unknownField: 1 } }, { digestDay: 'tomorrow' }, { showHints: 'yes' }])('invalid settings are rejected before storage: %j', async patch => {
  const { api } = await setup();
  await expect(api.updateSettings(patch as never)).rejects.toThrow();
  expect(await api.settings()).toMatchObject({ rotateEveryDays: 90, digestDay: 'off', showHints: false });
});

test('settings and notification sends retain the human mutation gate', async () => {
  const { api } = await setup(false);
  await expect(api.updateSettings({ rotateEveryDays: 30 })).rejects.toThrow(/interactive terminal/);
  await expect(api.digest(true)).rejects.toThrow(/interactive terminal/);
  await expect(api.spendLimits(true)).rejects.toThrow(/interactive terminal/);
});

test('card reads saved inventory without scanning, network, or recording a drill', async () => {
  const { rt, api, http, host, value } = await setup();
  host.listServices = async () => { throw new Error('card must use saved inventory'); };
  const card = await api.card({ platform: false, counts: false });
  expect(card.svg).toContain('<svg');
  expect(card.svg).not.toContain(value);
  expect(card.svg).not.toContain('api');
  expect(http.calls).toEqual([]);
  expect(await rt.store.readJson('plan', join(rt.paths.dir, 'drill.json'))).toBeNull();
});

test('dashboard first run rescans with the project key and caches the result for this facade', async () => {
  const { rt, api, value } = await setup();
  await writeFile(join(rt.config.cwd, '.env'), `OPENROUTER_API_KEY=${value}\n`);
  const previous = { scannedFiles: 0, scannedCommits: 0, historyComplete: false, elapsedMs: 0, findings: [], deployTargets: [], nextSteps: [] };
  await rt.store.writeJson('report', join(rt.paths.dir, 'first-run.json'), previous);
  const summary = await api.firstRun();
  expect(summary.findings[0]?.id).toBe((await rt.inventory()).clusters[0]?.id);
  await writeFile(join(rt.config.cwd, '.env'), '');
  expect(await api.firstRun()).toBe(summary);
});

test('dashboard first run refreshes changed files within sixty seconds', async () => {
  const { rt, api, value } = await setup();
  let now = new Date('2026-10-27T12:00:00.000Z');
  vi.spyOn(rt, 'now').mockImplementation(() => now);
  await writeFile(join(rt.config.cwd, '.env'), `OPENROUTER_API_KEY=${value}\n`);
  expect((await api.firstRun()).findings).toHaveLength(1);
  await writeFile(join(rt.config.cwd, '.env'), '');
  now = new Date(now.getTime() + 60_000);
  expect((await api.firstRun()).findings).toHaveLength(0);
});

test('timeline selects only the requested plan and verifies audit before reading it', async () => {
  const { rt, api } = await setup();
  const id = 'plan-20261027120000-abcd', other = 'plan-20261027120000-abce';
  await rt.store.journal().append({ at: '2026-10-27T12:00:00Z', planId: id, event: 'plan-start' });
  await rt.store.journal().append({ at: '2026-10-27T12:01:00Z', planId: id, event: 'revoked', clusterId: 'one' });
  await rt.store.journal().append({ at: '2026-10-27T12:02:00Z', planId: other, event: 'failed', clusterId: 'other' });
  const result = await api.timeline(id);
  expect(result.events.some(event => event.kind === 'revoked')).toBe(true);
  expect(result.events.some(event => event.kind === 'failed')).toBe(false);
  expect(result.markdown).toContain('1 key rotated');
  vi.spyOn(rt.audit, 'verify').mockResolvedValue({ ok: false, problem: 'invalid' } as never);
  await expect(api.timeline(id)).rejects.toThrow(/audit/);
});

test('digest is calm and value-free without sending or network calls', async () => {
  const { api, http, value } = await setup();
  const result = await api.digest(false);
  expect(result.message.lines).toEqual(['Nothing needed your attention this week.']);
  expect(JSON.stringify(result)).not.toContain(value);
  expect(http.calls).toEqual([]);
});

test('digest accepts the plaintext metadata saved by an initial tokenless first run', async () => {
  const { rt, api, http } = await setup();
  await writeFile(join(rt.paths.dir, 'first-run.json'), JSON.stringify({ scannedFiles: 0, scannedCommits: 0,
    historyComplete: true, elapsedMs: 0, findings: [], deployTargets: [], nextSteps: [] }));
  expect((await api.digest(false)).message.lines).toEqual(['Nothing needed your attention this week.']);
  expect(http.calls).toEqual([]);
});

test('spend limit preview uses fresh usage and never overwrites a tighter provider limit', async () => {
  const { rt, api, http, vault } = await setup();
  const inv = await rt.inventory(); const id = inv.clusters[0]!.id;
  await vault.set('cred/OPENROUTER_PROVISIONING_KEY@read', Buffer.from('management-read-token'));
  const monitor = createMonitorState(); monitor.keyRefs[id] = 'key_1';
  await rt.store.writeJson('monitor', rt.paths.monitor, monitor);
  await api.updateSettings({ spendCapsUsd: { openrouter: 12 } });
  http.on('GET', /^https:\/\/openrouter.ai\/api\/v1\/keys\?/, () => json(200, { data: [{ hash: 'key_1', limit: 5, usage: 2 }] }));
  const result = await api.spendLimits(false);
  expect(result.plans).toEqual([]);
  expect(http.calls.some(call => call.method === 'GET')).toBe(true);
  expect(http.calls.some(call => call.method !== 'GET')).toBe(false);
});

test('spend limit apply uses write-role credential and a selected key only', async () => {
  const { rt, api, http, vault } = await setup();
  const inv = await rt.inventory(); const id = inv.clusters[0]!.id;
  await vault.set('cred/OPENROUTER_PROVISIONING_KEY@read', Buffer.from('management-read-token'));
  await vault.set('cred/OPENROUTER_PROVISIONING_KEY', Buffer.from('management-write-token'));
  const monitor = createMonitorState(); monitor.keyRefs[id] = 'key_1';
  await rt.store.writeJson('monitor', rt.paths.monitor, monitor);
  await api.updateSettings({ spendCapsUsd: { openrouter: 12 } });
  http.on('GET', /^https:\/\/openrouter.ai\/api\/v1\/keys\?/, () => json(200, { data: [{ hash: 'key_1', limit: null, usage: 2 }] }));
  http.on('PATCH', /^https:\/\/openrouter.ai\/api\/v1\/keys\/key_1$/, req => {
    expect(req.headers?.Authorization).toBe('Bearer management-write-token'); expect(JSON.parse(req.body!)).toEqual({ limit: 12 });
    return json(200, {});
  });
  expect((await api.spendLimits(true, [id])).applied).toEqual([{ clusterId: id, limitUsd: 12 }]);
});

test('spend limit batch audits completed keys and a later failure before stopping', async () => {
  const { rt, api, http, vault, host, value } = await setup();
  const secondValue = `sk-or-v1-${'fedcba9876543210'.repeat(4)}`;
  host.addService('worker', { OPENROUTER_API_KEY: secondValue });
  const inventory = await rt.scan();
  const firstId = inventory.clusters[0]!.id;
  const secondId = inventory.clusters[1]!.id;
  await vault.set('cred/OPENROUTER_PROVISIONING_KEY', Buffer.from('management-private-token'));
  const monitor = createMonitorState(); monitor.keyRefs[firstId] = 'key_1'; monitor.keyRefs[secondId] = 'key_2';
  await rt.store.writeJson('monitor', rt.paths.monitor, monitor);
  await api.updateSettings({ spendCapsUsd: { openrouter: 12 } });
  http.on('GET', /^https:\/\/openrouter.ai\/api\/v1\/keys\?/, () => json(200, {
    data: [{ hash: 'key_1', limit: null, usage: 2 }, { hash: 'key_2', limit: null, usage: 3 }],
  }));
  http.on('PATCH', /^https:\/\/openrouter.ai\/api\/v1\/keys\/key_1$/, () => json(200, {}));
  http.on('PATCH', /^https:\/\/openrouter.ai\/api\/v1\/keys\/key_2$/, () => json(500, { error: secondValue }));
  await expect(api.spendLimits(true, [firstId, secondId])).rejects.toThrow();
  const log = await readFile(rt.paths.audit, 'utf8');
  const events = log.trim().split('\n').map(line => JSON.parse(line));
  expect(events).toContainEqual(expect.objectContaining({ kind: 'spend-limits:applied', data: { clusterId: firstId, limitUsd: 12 } }));
  expect(events).toContainEqual(expect.objectContaining({ kind: 'spend-limits:failed', data: { clusterId: secondId } }));
  expect(log).not.toContain(value); expect(log).not.toContain(secondValue); expect(log).not.toContain('management-private-token');
});

test('digest includes persisted usage anomaly approvals and signs sent digests', async () => {
  const { rt, api, value } = await setup();
  const inv = await rt.inventory(), monitor = createMonitorState();
  monitor.pendingActions.push({ id: 'action-usage', signalId: 'usage-spike', createdAt: '2026-10-27T11:00:00Z', action: 'alert',
    clusterIds: [inv.clusters[0]!.id], status: 'pending' });
  await rt.store.writeJson('monitor', rt.paths.monitor, monitor);
  rt.config.settings.notify.channels = [{ id: 'local', kind: 'console' }];
  const digest = await api.digest(true);
  expect(digest.message.lines).toContain('A spend spike needs review.');
  expect(digest.delivered).toEqual(['local']);
  const cache = await rt.store.readJson<{ messages: { sig: string }[] }>('plan', join(rt.paths.dir, 'notification-messages.json'));
  expect(cache?.messages[0]?.sig).toBeTruthy();
  expect(JSON.stringify(cache)).not.toContain(value);
});

test('timeline resolves a wave id to its plan without including another wave', async () => {
  const { rt, api } = await setup();
  const planId = 'plan-20261027120000-abcd';
  await rt.autopilotManager().saveState({ armedPlanId: null, disarmed: true, waves: [{ id: 'wave-one', incidentId: 'incident-one', planId,
    startedAt: '2026-10-27T12:00:00Z', status: 'grace' }] });
  await rt.store.journal().append({ at: '2026-10-27T12:00:00Z', planId, event: 'grace-start', clusterId: 'one' });
  await rt.audit.append({ kind: 'autopilot:detected', summary: 'Detected.', data: { waveId: 'wave-one' } });
  await rt.audit.append({ kind: 'autopilot:failed', summary: 'Other wave failed.', data: { waveId: 'wave-two' } });
  await rt.checkpoint();
  const result = await api.timeline('wave-one');
  expect(result.events.some(event => event.kind === 'grace')).toBe(true);
  expect(result.events.some(event => event.kind === 'detected')).toBe(true);
  expect(result.events.some(event => event.kind === 'failed')).toBe(false);
});
