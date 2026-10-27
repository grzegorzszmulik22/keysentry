import { afterEach, expect, test } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRuntime } from '../../src/cli/runtime.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { FakeHttp, json, text, silentLogger } from '../helpers/fake-http.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { createMonitorState, defaultPolicy } from '../../src/monitor/index.js';
import { getProvider } from '../../src/providers/index.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
async function setup() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-phase2-runtime-')); dirs.push(cwd);
  return { cwd, vault: createFakeVault(), fake: new FakeHttp() };
}

test('runtime trusts configured private channel URLs and receipts contain host metadata only', async () => {
  const { cwd, vault, fake } = await setup();
  const url = 'https://notify.example.test/private-webhook?token=private-token';
  await vault.set('notify/ops/url', Buffer.from(url));
  await writeFile(join(cwd, 'keysentry.yaml'), 'notify:\n  channels:\n    - id: ops\n      kind: webhook\n');
  fake.on('POST', /^https:\/\/notify\.example\.test\//, () => json(200, {}));
  const rt = await createRuntime({ cwd, vault, userDir: join(cwd, 'user'), env: {}, hosts: [], http: fake, log: silentLogger });
  expect(rt.rules).toContainEqual({ host: 'notify.example.test', owner: 'user', purpose: 'notification channel you configured' });
  expect((await rt.http.request({ method: 'POST', url, body: '{}' })).status).toBe(200);
  expect(JSON.stringify(await rt.receipt.summarize())).not.toContain('private-token');
});

test('passing drill time is encrypted and recorded for the arming gate', async () => {
  const { cwd, vault, fake } = await setup();
  const now = new Date('2026-10-27T12:00:00Z');
  const rt = await createRuntime({ cwd, vault, userDir: join(cwd, 'user'), env: {}, hosts: [], http: fake, log: silentLogger, now: () => now });
  await rt.drill();
  expect(await rt.store.readJson('plan', join(rt.paths.dir, 'drill.json'))).toEqual({ passed: true, at: now.toISOString() });
});

test('unconfigured hosts without known consumers do not prevent drill and arming enabled keys', async () => {
  const { cwd, vault, fake } = await setup();
  await writeFile(join(cwd, '.env'), 'JWT_SECRET=abcdef0123456789abcdef0123456789\n');
  const rt = await createRuntime({ cwd, vault, userDir: join(cwd, 'user'), env: {}, http: fake, log: silentLogger,
    stdinIsTTY: true, stdoutIsTTY: true });
  await rt.drill();
  expect(await rt.store.readJson('plan', join(rt.paths.dir, 'drill.json'))).toMatchObject({ passed: true });
  expect((await rt.autopilotManager().arm()).plan.clusters).toHaveLength(1);
});

test.each([false, true])('watcher monitor preserves policy only when healthy (alert-only=%s)', async alertOnly => {
  const { cwd, vault, fake } = await setup();
  const now = new Date('2026-10-27T12:00:00Z');
  const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-0123456789abcdef');
  const app = provider.issue(), own = provider.issue();
  const host = new FakeHost('railway'); host.pendingPolls = 0;
  host.addService('app', { OPENROUTER_API_KEY: app.value });
  host.addService('own', { OPENROUTER_PROVISIONING_KEY: own.value });
  const policy = defaultPolicy(); policy.autoExecute = true;
  const rt = await createRuntime({ cwd, vault, userDir: join(cwd, 'user'), env: {}, hosts: [host], http: fake, log: silentLogger,
    stdinIsTTY: true, stdoutIsTTY: true,
    providers: id => id === 'openrouter' ? provider : getProvider(id), policy, now: () => now, sleep: async () => {} });
  rt.config.rotation.graceMs = 0;
  const inv = await rt.scan(); const state = createMonitorState();
  for (const cluster of inv.clusters) state.lastVerify[cluster.id] = { ok: true, fingerprint: cluster.fingerprint!, at: '2026-10-27T10:00:00Z' };
  await rt.store.writeJson('monitor', rt.paths.monitor, state);
  provider.revokeUpstream(app.ref); provider.revokeUpstream(own.ref);
  await rt.watcherMonitor({ alertOnly, reasons: [], excludedTokenNames: ['OPENROUTER_PROVISIONING_KEY'], ownHost: null }, { notify: async () => {} });
  expect(host.writes.length > 0).toBe(!alertOnly);
  expect(host.writes.every(write => write.serviceId === 'app')).toBe(true);
});

test('watcher legacy monitor cannot rotate a news-only breach feed', async () => {
  const { cwd, vault, fake } = await setup();
  const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-0123456789abcdef');
  const key = provider.issue(); const host = new FakeHost('railway'); host.pendingPolls = 0;
  host.addService('app', { OPENROUTER_API_KEY: key.value });
  const url = 'https://news.example.test/rss';
  fake.on('GET', /^https:\/\/news\.example\.test\/rss$/, () => text(200,
    '<rss><channel><item><guid>news-one</guid><title>Railway security incident exposes environment variables</title><description>Railway tokens were exposed.</description></item></channel></rss>'));
  const policy = defaultPolicy(); policy.autoExecute = true; policy.rules.host_breach_advisory.action = 'rotate';
  const rt = await createRuntime({ cwd, vault, userDir: join(cwd, 'user'), env: {}, hosts: [host], http: fake, log: silentLogger,
    stdinIsTTY: true, stdoutIsTTY: true, providers: id => id === 'openrouter' ? provider : getProvider(id), policy,
    feeds: [{ url, host: 'railway' }], sleep: async () => {} });
  rt.config.rotation.graceMs = 0;
  await rt.watcherMonitor({ alertOnly: false, reasons: [], excludedTokenNames: [], ownHost: null }, { notify: async () => {} });
  expect(fake.callsTo('GET', /^https:\/\/news\.example\.test/)).toEqual([]);
  expect(host.writes).toEqual([]);
});

test('disarm during a watcher monitor scan prevents later automatic writes', async () => {
  const { cwd, vault, fake } = await setup();
  const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-0123456789abcdef');
  const key = provider.issue(), host = new FakeHost('railway'); host.pendingPolls = 0;
  host.addService('app', { OPENROUTER_API_KEY: key.value });
  const policy = defaultPolicy(); policy.autoExecute = true;
  const rt = await createRuntime({ cwd, vault, userDir: join(cwd, 'user'), env: {}, hosts: [host], http: fake, log: silentLogger,
    stdinIsTTY: true, stdoutIsTTY: true, providers: id => id === 'openrouter' ? provider : getProvider(id), policy,
    now: () => new Date('2026-10-27T12:00:00Z'), sleep: async () => {} });
  rt.config.rotation.graceMs = 0;
  const inventory = await rt.scan(), state = createMonitorState();
  state.lastVerify[inventory.clusters[0]!.id] = { at: '2026-10-27T10:00:00Z', ok: true, fingerprint: inventory.clusters[0]!.fingerprint! };
  await rt.store.writeJson('monitor', rt.paths.monitor, state); provider.revokeUpstream(key.ref);
  let active = true; const list = host.listServices.bind(host);
  host.listServices = async () => { active = false; return list(); };
  await rt.watcherMonitor({ alertOnly: false, reasons: [], excludedTokenNames: [], ownHost: null }, { notify: async () => {} },
    async () => { if (!active) throw new Error('disarmed'); });
  expect(host.writes).toEqual([]);
  expect(provider.keys.size).toBe(1);
});


