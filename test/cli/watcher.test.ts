import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, test } from 'vitest';
import { APPROVAL_REQUEST_PREFIX, createWatchRuntime, passkeysForWatcherOrigin, runWatch, type WatchRuntimeDependencies } from '../../src/cli/watcher.js';
import { buildInventory, createStateCipher, createStateStore } from '../../src/core/index.js';
import { buildArmedPlan, signArmedPlan } from '../../src/autopilot/index.js';
import { canonicalJson, generateDeviceKey, verifyDetached } from '../../src/security/index.js';
import { verifyMessage } from '../../src/notify/index.js';
import type { FeedSource, PasskeyCredential, SignedNotifyMessage } from '../../src/types.js';
import { FakeHttp, text } from '../helpers/fake-http.js';
import { recoveryFixture } from '../rotate/recovery-fixture.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
async function fixture() {
  const f = await recoveryFixture();
  const dir = await mkdtemp(join(tmpdir(), 'keysentry-watch-cli-')); dirs.push(dir);
  const store = createStateStore({ cwd: dir, cipher: createStateCipher(Buffer.alloc(32, 1)) });
  const key = generateDeviceKey();
  const armed = signArmedPlan(buildArmedPlan({ projectId: 'project', inventory: f.inv, clusterIds: [f.clusterId], hosts: ['railway'], options: {}, now: f.deps.now!() }).plan, key);
  await store.writeJson('plan', join(store.paths.dir, 'armed-plan.json'), armed);
  await store.writeJson('plan', join(store.paths.dir, 'autopilot.json'), { armedPlanId: armed.id, disarmed: false, waves: [] });
  const source: FeedSource = { id: 'railway-blog', kind: 'official', hosts: ['railway'], url: 'https://blog.railway.com/rss.xml', owner: 'Railway', outlet: 'Railway' };
  const xml = await readFile('test/fixtures/feeds/railway-official-2026-10.xml', 'utf8');
  const http = new FakeHttp().on('GET', /blog\.railway\.com/, () => text(200, xml));
  const messages: SignedNotifyMessage[] = [];
  const events: unknown[] = [];
  const audit = { async append(event: unknown) { events.push(event); }, async checkpoint() {}, async verify() { return { ok: true, entries: events.length, checkpoints: 0 }; } };
  let scans = 0; let gates = 0; let monitors = 0;
  const deps: WatchRuntimeDependencies = {
    store, audit, http, log: f.deps.log, rotation: f.opts, now: f.deps.now, env: {}, fingerprintKey: f.deps.fingerprintKey,
    signingKey: async () => key, deviceKeys: async () => [{ keyId: key.keyId, publicKeyDer: key.publicKeyDer }], passkeys: async () => [],
    channels: async () => [{ id: 'test', kind: 'console', async send(message) { messages.push(message); } }],
    sources: [source], engine: async () => f.deps,
    async freshInventory() {
      scans++;
      return buildInventory([{ host: f.host.id, services: await Promise.all(f.services.map(async service => ({ service, vars: await f.host.readVariables(service) }))) }], f.deps.fingerprintKey, f.deps.now!());
    },
    async monitor() { monitors++; }, assertHuman() { gates++; },
  };
  return { ...f, store, deps, messages, key, http, get scans() { return scans; }, get gates() { return gates; }, get monitors() { return monitors; } };
}

test('watch composes guarded feed fetch, durable incidents, signed notifications and fresh settlement scans', async () => {
  const f = await fixture();
  const watcher = await createWatchRuntime(f.deps);
  expect(await watcher.tick()).toEqual({ status: 'ok', errors: [], reasons: [] });
  expect(watcher.state.waves).toHaveLength(1);
  expect(watcher.state.waves[0]?.status).toBe('grace');
  expect(f.monitors).toBe(1);
  expect(f.messages.length).toBeGreaterThan(0);
  expect(f.messages.every(message => verifyMessage(message, f.key.publicKeyDer))).toBe(true);
  const scans = f.scans;
  f.clock.ms += 901_000;
  await watcher.settle();
  expect(f.scans).toBeGreaterThan(scans);
  expect(f.provider.keys.get(f.old.ref)?.active).toBe(false);
  expect(watcher.state.waves[0]?.status).toBe('done');
  const incidents = await f.store.readJson<{ incidents: unknown[] }>('plan', join(f.store.paths.dir, 'watcher-incidents.json'));
  expect(incidents?.incidents).toHaveLength(1);
});

test('watch reloads a local disarm before grace settlement and keeps the old key', async () => {
  const f = await fixture(); const watcher = await createWatchRuntime(f.deps); await watcher.tick();
  await f.store.writeJson('plan', join(f.store.paths.dir, 'autopilot.json'), { ...watcher.state, disarmed: true });
  f.clock.ms += 901_000;
  await watcher.settle();
  expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
  expect(watcher.state.disarmed).toBe(true);
});

test('watch --once gates local mutations and returns the watcher exit status', async () => {
  const f = await fixture();
  expect(await runWatch(f.deps, { once: true })).toBe(0);
  expect(f.gates).toBe(1);
});

test('watch fails closed when no notification channel delivers', async () => {
  const f = await fixture(); f.deps.channels = async () => [];
  const watcher = await createWatchRuntime(f.deps);
  await watcher.tick();
  expect(f.host.writes).toHaveLength(0);
  expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
});

test('watch publishes signed approval metadata through the relay for local review', async () => {
  const f = await fixture();
  f.deps.relay = { server: 'https://ntfy.sh', topic: 'setup-topic', token: 'relay-token' };
  f.http.on('GET', /ntfy\.sh/, () => text(200, ''));
  f.http.on('POST', /ntfy\.sh/, () => text(200, '{}'));
  const watcher = await createWatchRuntime(f.deps); await watcher.tick();
  const published = f.http.calls.filter(call => call.method === 'POST').map(call => JSON.parse(String(call.body))).find(body => body.type === 'keysentry-approval-request');
  expect(published.request).toMatchObject({ kind: 'autopilot', keyCount: 1 });
  expect(verifyDetached(f.key.publicKeyDer, Buffer.from(APPROVAL_REQUEST_PREFIX + canonicalJson({ request: published.request, keyId: published.keyId })), Buffer.from(published.sig, 'base64'))).toBe(true);
  expect(JSON.stringify(published)).not.toContain(f.oldGenerated.value);
  expect(JSON.stringify(published)).not.toContain(f.old.value);
});

test('localhost passkeys work on the current exact approval origin without widening public credentials', () => {
  const local: PasskeyCredential = { id: 'id', publicKeyCose: 'cose', alg: -7, signCount: 0, backupEligible: false,
    rpId: 'localhost', origins: ['http://localhost:1234'], label: 'local', createdAt: '2026-10-27T08:00:00.000Z' };
  const remote = { ...local, id: 'public', rpId: 'watcher.example', origins: ['https://watcher.example'] };
  expect(passkeysForWatcherOrigin([local, remote], 'http://localhost:9876')).toEqual([
    { ...local, origins: ['http://localhost:9876'] }, remote,
  ]);
  expect(local.origins).toEqual(['http://localhost:1234']);
  expect(passkeysForWatcherOrigin([local, remote], 'https://watcher.example')).toEqual([local, remote]);
});

test('local adoption refresh waits for completed waves and reloads the replaced state', async () => {
  const f = await fixture();
  let calls = 0;
  f.deps.applyAdoptionUpdates = async () => {
    calls++;
    const state = await f.store.readJson<Record<string, unknown>>('plan', join(f.store.paths.dir, 'autopilot.json'));
    const updated = { ...state, armedPlanId: 'refreshed-plan' };
    delete updated.adoptionUpdates; delete updated.adoptionUpdatesPlanId;
    await f.store.writeJson('plan', join(f.store.paths.dir, 'autopilot.json'), updated);
  };
  const watcher = await createWatchRuntime(f.deps); await watcher.tick();
  expect(calls).toBe(0);
  watcher.state.adoptionUpdates = { [f.clusterId]: { fingerprint: 'f'.repeat(32), keyRef: 'replacement', at: f.deps.now!().toISOString() } };
  await f.store.writeJson('plan', join(f.store.paths.dir, 'autopilot.json'), watcher.state);
  f.clock.ms += 901_000;
  await watcher.settle();
  expect(calls).toBe(1);
  expect(watcher.state.armedPlanId).toBe('refreshed-plan');
  expect(watcher.state.adoptionUpdates).toBeUndefined();
});

test('a durable relay inbox applies a disarm before advancing to new messages', async () => {
  const f = await fixture(); f.deps.relay = { server: 'https://ntfy.sh', topic: 'setup-topic' };
  await f.store.writeJson('pending', join(f.store.paths.dir, 'watcher-relay.json'), { cursor: 'old-cursor',
    pendingApprovals: [], pendingDisarms: [{ keyId: f.key.keyId, at: f.deps.now!().toISOString(), sig: 'authenticated-inbox-message' }] });
  const watcher = await createWatchRuntime(f.deps); await watcher.tick();
  expect(watcher.state.disarmed).toBe(true);
  expect(f.http.calls.some(call => call.method === 'GET' && call.url.includes('ntfy.sh'))).toBe(false);
  expect(await f.store.readJson('pending', join(f.store.paths.dir, 'watcher-relay.json'))).toMatchObject({ cursor: 'old-cursor', pendingDisarms: [] });
});

test('an idle watcher reloads a newly signed local re-arm instead of restoring its old disarm', async () => {
  const f = await fixture(); const watcher = await createWatchRuntime(f.deps); await watcher.disarm();
  const plan = await f.store.readJson<Record<string, unknown>>('plan', join(f.store.paths.dir, 'armed-plan.json'));
  const { signer: _signer, sig: _sig, ...body } = plan!;
  const armed = signArmedPlan({ ...body, id: 'arm-20261027-abcd1234' } as Parameters<typeof signArmedPlan>[0], f.key);
  await f.store.writeJson('plan', join(f.store.paths.dir, 'armed-plan.json'), armed);
  await f.store.writeJson('plan', join(f.store.paths.dir, 'autopilot.json'), { armedPlanId: armed.id, disarmed: false, waves: [] });
  expect((await watcher.check()).ok).toBe(true);
  expect(watcher.state).toMatchObject({ armedPlanId: armed.id, disarmed: false });
});

test('relay disarm retries a failed durable state write before acknowledging the inbox', async () => {
  const f = await fixture(); f.deps.relay = { server: 'https://ntfy.sh', topic: 'setup-topic' };
  f.http.on('POST', /ntfy\.sh/, () => text(200, '{}'));
  await f.store.writeJson('pending', join(f.store.paths.dir, 'watcher-relay.json'), { cursor: 'old-cursor',
    pendingApprovals: [], pendingDisarms: [{ keyId: f.key.keyId, at: f.deps.now!().toISOString(), sig: 'authenticated-inbox-message' }] });
  const write = f.store.writeJson.bind(f.store); let failed = false;
  f.store.writeJson = async (kind, file, value, options) => {
    if (!failed && file.endsWith('autopilot.json') && (value as { disarmed?: boolean }).disarmed) { failed = true; throw new Error('disk temporarily unavailable'); }
    return write(kind, file, value, options);
  };
  const watcher = await createWatchRuntime(f.deps); await watcher.tick();
  expect(await f.store.readJson('plan', join(f.store.paths.dir, 'autopilot.json'))).toMatchObject({ disarmed: false });
  await watcher.tick();
  expect(await f.store.readJson('plan', join(f.store.paths.dir, 'autopilot.json'))).toMatchObject({ disarmed: true });
  expect(await f.store.readJson('pending', join(f.store.paths.dir, 'watcher-relay.json'))).toMatchObject({ pendingDisarms: [] });
});

test('watch observes a local disarm that happens during the fresh scan', async () => {
  const f = await fixture(); const scan = f.deps.freshInventory;
  f.deps.freshInventory = async () => {
    const inventory = await scan();
    const state = await f.store.readJson('plan', join(f.store.paths.dir, 'autopilot.json'));
    await f.store.writeJson('plan', join(f.store.paths.dir, 'autopilot.json'), { ...state as object, disarmed: true });
    return inventory;
  };
  const watcher = await createWatchRuntime(f.deps); await watcher.tick();
  expect(f.host.writes).toHaveLength(0);
});

test('invalid approval port releases watcher signal handlers', async () => {
  const f = await fixture(); const listeners = process.listenerCount('SIGINT');
  await expect(runWatch(f.deps, { once: true, port: -1 })).rejects.toThrow('port');
  expect(process.listenerCount('SIGINT')).toBe(listeners);
});

test.each(['mismatch', 'unavailable'] as const)('watcher integrity %s forces alert-only before automatic effects', async failure => {
  const f = await fixture(); let checks = 0; const monitorModes: boolean[] = [];
  f.deps.integrityCheck = async () => {
    checks++;
    if (failure === 'unavailable') throw new Error('untrusted private details');
    return { ok: false, reasons: ['The local installation check did not match.'] };
  };
  f.deps.monitor = async context => { monitorModes.push(context.alertOnly); };
  const watcher = await createWatchRuntime(f.deps);
  const result = await watcher.tick();
  expect(result.status).toBe('alert-only');
  expect(result.reasons).not.toHaveLength(0);
  expect(f.host.writes).toHaveLength(0);
  expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
  expect(monitorModes).toEqual([true]);
  const previous = checks; await watcher.check(); expect(checks).toBe(previous + 1);
  expect(JSON.stringify(result)).not.toContain('untrusted private details');
});

test('monitor receives a fresh action guard that rejects a disarm during its work', async () => {
  const f = await fixture(); let guarded = false;
  f.deps.sources = [];
  f.deps.monitor = async (_context, _notify, assertActive) => {
    await assertActive();
    const saved = await f.store.readJson<object>('plan', join(f.store.paths.dir, 'autopilot.json'));
    await f.store.writeJson('plan', join(f.store.paths.dir, 'autopilot.json'), { ...saved, disarmed: true });
    await expect(assertActive()).rejects.toThrow('Automatic actions are paused.');
    guarded = true;
  };
  const watcher = await createWatchRuntime(f.deps); await watcher.tick();
  expect(guarded).toBe(true);
});
