import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, test } from 'vitest';
import { request as httpRequest } from 'node:http';
import { createServer as createNetServer, type AddressInfo } from 'node:net';
import type { ServerHealth } from '../../src/approvals/server.js';
import { APPROVAL_REQUEST_PREFIX, approvalProxyHops, createWatchRuntime, passkeysForWatcherOrigin, runWatch, type WatchRuntimeDependencies } from '../../src/cli/watcher.js';
import { buildInventory, createStateCipher, createStateStore } from '../../src/core/index.js';
import { buildArmedPlan, planHashFor, signArmedPlan } from '../../src/autopilot/index.js';
import { buildPlan } from '../../src/core/index.js';
import { canonicalJson, generateDeviceKey, signDetached, verifyDetached } from '../../src/security/index.js';
import { verifyMessage } from '../../src/notify/index.js';
import { APPROVAL_PREFIX, signDisarm } from '../../src/approvals/index.js';
import type { FeedSource, PasskeyCredential, RotationReport, SignedNotifyMessage } from '../../src/types.js';
import { FakeHttp, text } from '../helpers/fake-http.js';
import { recoveryFixture } from '../rotate/recovery-fixture.js';
import { createWatcherStateStore } from '../../src/cli/watcher-state.js';
import { signWatcherResume } from '../../src/watcher/index.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
async function fixture(options: { coldStart?: boolean; exposure?: boolean; actions?: boolean; noState?: boolean; noArm?: boolean } = {}) {
  const f = await recoveryFixture();
  const dir = await mkdtemp(join(tmpdir(), 'keysentry-watch-cli-')); dirs.push(dir);
  const store = createWatcherStateStore(createStateStore({ cwd: dir, cipher: createStateCipher(Buffer.alloc(32, 1)) }), options.actions === true);
  const key = generateDeviceKey();
  const armed = signArmedPlan(buildArmedPlan({ projectId: 'project', inventory: f.inv, clusterIds: [f.clusterId], hosts: ['railway'], options: {}, now: f.deps.now!() }).plan, key);
  if (!options.noArm) await store.writeJson('plan', join(store.paths.dir, 'armed-plan.json'), armed);
  if (!options.noState && !options.noArm) await store.writeJson('plan', join(store.paths.dir, 'autopilot.json'), { armedPlanId: armed.id, disarmed: false, waves: [] });
  const source: FeedSource = { id: 'railway-blog', kind: 'official', hosts: ['railway'], url: 'https://blog.railway.com/rss.xml', owner: 'Railway', outlet: 'Railway' };
  // Replay the recorded content as a fresh publication. Freshness and startup
  // baselining have their own regressions below; these fixtures exercise waves.
  const publishedAt = new Date(f.deps.now!().getTime() - 3_600_000).toUTCString();
  const xml = (await readFile('test/fixtures/feeds/railway-official-2026-10.xml', 'utf8'))
    .replace(/<pubDate>[^<]*<\/pubDate>/g, `<pubDate>${publishedAt}</pubDate>`)
    // Abbreviated recorded descriptions omit the exposure facts. Include the
    // explicit exposure/rotation scenario also used by the incidents tests.
    .replace(/<\/description>/g, options.exposure === false ? '</description>'
      : ' Customer environment variables were accessed. Railway urges users to rotate credentials after the security incident.</description>');
  let feedBody = xml, feedStatus = 200;
  const http = new FakeHttp().on('GET', /blog\.railway\.com/, () => text(feedStatus, feedBody));
  if (!options.coldStart) await store.writeJson('plan', join(store.paths.dir, 'watcher-incidents.json'), { incidents: [], sources: {
    [source.id]: { baselineAt: new Date(f.deps.now!().getTime() - 7_200_000).toISOString(), seenItemKeys: [], undatedFirstSeenAt: {} },
  } });
  const messages: SignedNotifyMessage[] = [];
  const events: unknown[] = [];
  const audit = { async append(event: unknown) { events.push(event); }, async checkpoint() {}, async verify() { return { ok: true, entries: events.length, checkpoints: 0 }; } };
  let scans = 0; let gates = 0; let monitors = 0;
  const deps: WatchRuntimeDependencies = {
    store, audit, http, log: f.deps.log, rotation: f.opts, now: f.deps.now, env: options.actions ? { GITHUB_ACTIONS: 'true' } : {}, fingerprintKey: f.deps.fingerprintKey, projectId: 'project',
    signingKey: async () => key, deviceKeys: async () => [{ keyId: key.keyId, publicKeyDer: key.publicKeyDer }], passkeys: async () => [],
    channels: async () => [{ id: 'test', kind: 'console', async send(message) { messages.push(message); } }],
    sources: [source], engine: async () => f.deps,
    async freshInventory() {
      scans++;
      return buildInventory([{ host: f.host.id, services: await Promise.all(f.services.map(async service => ({ service, vars: await f.host.readVariables(service) }))) }], f.deps.fingerprintKey, f.deps.now!());
    },
    async monitor() { monitors++; }, assertHuman() { gates++; },
  };
  return { ...f, store, deps, messages, key, http, xml,
    setFeed(body: string, status = 200) { feedBody = body; feedStatus = status; },
    get scans() { return scans; }, get gates() { return gates; }, get monitors() { return monitors; } };
}

test('cold feeds baseline silently after content, survive restart, and trigger only a later fresh item', async () => {
  const f = await fixture({ coldStart: true });
  f.setFeed('', 304);
  const first = await createWatchRuntime(f.deps); await first.tick();
  const file = join(f.store.paths.dir, 'watcher-incidents.json');
  expect((await f.store.readJson<{ sources?: object }>('plan', file))?.sources).toBeUndefined();
  expect(first.state.waves).toHaveLength(0);
  f.setFeed(f.xml);
  await first.tick();
  const baseline = await f.store.readJson<{ incidents: unknown[]; sources: Record<string, { seenItemKeys: string[] }> }>('plan', file);
  expect(baseline?.sources['railway-blog']?.seenItemKeys.length).toBeGreaterThan(0);
  expect(baseline?.incidents).toEqual([]);
  expect(first.state.waves).toHaveLength(0);
  expect(f.host.writes).toHaveLength(0);
  const restarted = await createWatchRuntime(f.deps);
  await restarted.tick();
  expect(restarted.state.waves).toHaveLength(0);
  f.clock.ms += 1000;
  f.setFeed(f.xml.replace(/https:\/\/blog\.railway\.com\/p\//g, 'https://blog.railway.com/p/new-publication-'));
  await restarted.tick();
  expect(restarted.state.waves).toHaveLength(1);
  expect(restarted.state.waves[0]?.status).toBe('grace');
  const after = await f.store.readJson<{ sources: Record<string, { seenItemKeys: string[] }> }>('plan', file);
  expect(after?.sources['railway-blog']?.seenItemKeys.length).toBeGreaterThan(baseline!.sources['railway-blog']!.seenItemKeys.length);
});

test('fresh abbreviated recorded summaries remain alerts without an explicit exposure claim', async () => {
  const f = await fixture({ exposure: false });
  const watcher = await createWatchRuntime(f.deps); await watcher.tick();
  const saved = await f.store.readJson<{ incidents: { status: string; evidence: { credentialExposure: boolean }[] }[] }>('plan', join(f.store.paths.dir, 'watcher-incidents.json'));
  expect(saved?.incidents.length).toBeGreaterThan(0);
  expect(saved?.incidents.every(incident => incident.status === 'alerted' && incident.evidence.every(item => !item.credentialExposure))).toBe(true);
  expect(watcher.state.waves).toHaveLength(0);
  expect(f.host.writes).toHaveLength(0);
});

test('watch composes guarded feed fetch, durable incidents, signed notifications and fresh settlement scans', async () => {
  const f = await fixture();
  const watcher = await createWatchRuntime(f.deps);
  expect(await watcher.tick()).toEqual({ status: 'ok', errors: [], reasons: [] });
  expect(watcher.state.waves).toHaveLength(1);
  expect(watcher.state.waves[0]?.status).toBe('grace');
  const planId = watcher.state.waves[0]!.planId;
  expect(await f.store.readJson<RotationReport>('report', join(f.store.paths.dir, 'reports', `${planId}.json`))).toMatchObject({ planId, status: 'grace-pending' });
  expect(f.monitors).toBe(1);
  expect(f.messages.length).toBeGreaterThan(0);
  expect(f.messages.every(message => verifyMessage(message, f.key.publicKeyDer))).toBe(true);
  const scans = f.scans;
  f.clock.ms += 901_000;
  await watcher.settle();
  expect(f.scans).toBeGreaterThan(scans);
  expect(f.provider.keys.get(f.old.ref)?.active).toBe(false);
  expect(watcher.state.waves[0]?.status).toBe('done');
  expect(await f.store.readJson<RotationReport>('report', join(f.store.paths.dir, 'reports', `${planId}.json`))).toMatchObject({ planId, status: 'complete' });
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

test.each(['project', 'other-project'])('relay disarm is accepted only for this watcher project: %s', async watcherId => {
  const f = await fixture();
  f.deps.relay = { server: 'https://ntfy.sh', topic: 'saved-topic' };
  f.deps.sources = [];
  const signed = signDisarm(f.key, { watcherId, at: f.deps.now!().toISOString() });
  f.http.on('GET', /ntfy\.sh/, () => text(200, JSON.stringify({ id: 'message-one', time: Math.floor(f.deps.now!().getTime() / 1000),
    event: 'message', topic: 'saved-topic', message: JSON.stringify({ type: 'keysentry-disarm', v: 2, ...signed }) })));
  const watcher = await createWatchRuntime(f.deps);
  await watcher.tick();
  expect(watcher.state.disarmed).toBe(watcherId === 'project');
});

test('a saved relay inbox cannot apply a disarm addressed to another project', async () => {
  const f = await fixture();
  f.deps.relay = { server: 'https://ntfy.sh', topic: 'saved-topic' }; f.deps.sources = [];
  f.http.on('GET', /ntfy\.sh/, () => text(200, ''));
  await f.store.writeJson('pending', join(f.store.paths.dir, 'watcher-relay.json'), { cursor: 'cursor-one', pendingApprovals: [],
    pendingDisarms: [signDisarm(f.key, { watcherId: 'other-project', at: f.deps.now!().toISOString() })] });
  const watcher = await createWatchRuntime(f.deps); await watcher.tick();
  expect(watcher.state.disarmed).toBe(false);
  expect(await f.store.readJson('pending', join(f.store.paths.dir, 'watcher-relay.json'))).toMatchObject({ pendingDisarms: [] });
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
  f.http.on('GET', /ntfy\.sh/, () => text(200, ''));
  await f.store.writeJson('pending', join(f.store.paths.dir, 'watcher-relay.json'), { cursor: 'old-cursor',
    pendingApprovals: [], pendingDisarms: [signDisarm(f.key, { watcherId: 'project', at: f.deps.now!().toISOString() })] });
  const watcher = await createWatchRuntime(f.deps); await watcher.tick();
  expect(watcher.state.disarmed).toBe(true);
  expect(f.http.calls.some(call => call.method === 'GET' && call.url.includes('ntfy.sh'))).toBe(true);
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
  f.http.on('GET', /ntfy\.sh/, () => text(200, ''));
  f.http.on('POST', /ntfy\.sh/, () => text(200, '{}'));
  await f.store.writeJson('pending', join(f.store.paths.dir, 'watcher-relay.json'), { cursor: 'old-cursor',
    pendingApprovals: [], pendingDisarms: [signDisarm(f.key, { watcherId: 'project', at: f.deps.now!().toISOString() })] });
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

test('console delivery cannot renew the external notification self-check across restarts', async () => {
  const f = await fixture(); f.deps.sources = [];
  const first = await createWatchRuntime(f.deps); await first.tick();
  f.clock.ms += 86_400_001;
  await first.tick();
  expect((await first.check()).ok).toBe(false);
  const restarted = await createWatchRuntime(f.deps);
  expect((await restarted.check()).ok).toBe(false);
});

test('trusted plan-bound approvals execute once and are marked executed after the wave reaches grace', async () => {
  const f = await fixture(); f.deps.sources = [];
  const watcher = await createWatchRuntime(f.deps);
  const inventory = await f.deps.freshInventory();
  const action = { id: 'approved-key', kind: 'autopilot', clusterIds: [f.clusterId],
    planHash: planHashFor(buildPlan(inventory, { clusterIds: [f.clusterId] })) };
  const request = await watcher.approvals.request(action, false);
  const body = { actionId: action.id, digest: request.digest, at: f.deps.now!().toISOString() };
  await watcher.approvals.approveWithDevice(action.id, { ...body, keyId: f.key.keyId,
    sig: signDetached(f.key.privateKeyDer, Buffer.from(APPROVAL_PREFIX + canonicalJson(body))).toString('base64') });
  await watcher.tick();
  expect(f.host.writes.length).toBeGreaterThan(0);
  expect(await watcher.approvals.status(action.id)).toBe('executed');
  const writes = f.host.writes.length;
  await watcher.tick();
  expect(f.host.writes.length).toBe(writes);
  expect(watcher.state.waves).toHaveLength(1);
  const planId = watcher.state.waves[0]!.planId;
  expect(await f.store.readJson<RotationReport>('report', join(f.store.paths.dir, 'reports', `${planId}.json`))).toMatchObject({ planId, status: 'grace-pending' });
});

test('relay ask failures retry on an idle tick without delaying the armed wave', async () => {
  const f = await fixture();
  f.deps.relay = { server: 'https://ntfy.sh', topic: 'setup-topic' };
  let fail = true;
  f.http.on('GET', /ntfy\.sh/, () => text(200, ''));
  f.http.on('POST', /ntfy\.sh/, () => text(fail ? 503 : 200, '{}'));
  const watcher = await createWatchRuntime(f.deps); await watcher.tick();
  expect(watcher.state.waves).toHaveLength(1);
  expect(watcher.state.pendingAsks?.length).toBeGreaterThan(0);
  fail = false; f.clock.ms += 61_000; f.deps.sources = [];
  await watcher.tick();
  expect(watcher.state.pendingAsks).toEqual([]);
});

test('a local disarm received during provider rotation stops the following host write', async () => {
  const f = await fixture();
  const rotate = f.provider.rotate.bind(f.provider);
  f.provider.rotate = async (...args) => {
    const result = await rotate(...args);
    const saved = await f.store.readJson<object>('plan', join(f.store.paths.dir, 'autopilot.json'));
    await f.store.writeJson('plan', join(f.store.paths.dir, 'autopilot.json'), { ...saved, disarmed: true });
    return result;
  };
  const watcher = await createWatchRuntime(f.deps); await watcher.tick();
  expect(f.host.writes).toHaveLength(0);
  expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
  expect(watcher.state.disarmed).toBe(true);
});

test('approval notifications offer the local command when the public origin has no registered passkey', async () => {
  const f = await fixture({ exposure: false }); f.deps.publicOrigin = 'https://watcher.example';
  const watcher = await createWatchRuntime(f.deps); await watcher.tick();
  const asks = f.messages.filter(message => message.actionId);
  expect(asks.length).toBeGreaterThan(0);
  for (const message of asks) {
    expect(message.approveUrl).toBeUndefined();
    expect(message.lines).toContain(`Approve with keysentry approve ${message.actionId} on your computer.`);
  }
});

test('saved same-project relay disarms are authenticated again before durable application', async () => {
  const f = await fixture(); f.deps.sources = []; f.deps.relay = { server: 'https://ntfy.sh', topic: 'saved-topic' };
  f.http.on('GET', /ntfy\.sh/, () => text(200, ''));
  await f.store.writeJson('pending', join(f.store.paths.dir, 'watcher-relay.json'), { cursor: null, pendingApprovals: [],
    pendingDisarms: [{ ...signDisarm(f.key, { watcherId: 'project', at: f.deps.now!().toISOString() }), sig: 'forged' }] });
  const watcher = await createWatchRuntime(f.deps); await watcher.tick();
  expect(watcher.state.disarmed).toBe(false);
});

test('Actions persists a missing-state pause and accepts only a trusted signed resume on its independent relay cursor', async () => {
  const f = await fixture({ actions: true }); f.deps.sources = [];
  f.deps.relay = { server: 'https://ntfy.sh', topic: 'saved-topic' };
  let inbox = '';
  f.http.on('GET', /ntfy\.sh/, () => text(200, inbox));
  const first = await createWatchRuntime(f.deps);
  expect((await first.check()).ok).toBe(false);
  await first.tick();
  expect(await f.store.readJson('plan', join(f.store.paths.dir, 'watcher-recovery.json'))).toMatchObject({ requiresResume: true });
  const resumed = signWatcherResume({ watcherId: 'project', at: f.deps.now!().toISOString() }, f.key);
  inbox = JSON.stringify({ id: 'resume-message', time: Math.floor(f.deps.now!().getTime() / 1000),
    event: 'message', topic: 'saved-topic', message: JSON.stringify(resumed) });
  f.clock.ms += 60_000;
  const restarted = await createWatchRuntime(f.deps); await restarted.tick();
  expect((await restarted.check()).ok).toBe(true);
  expect(await f.store.readJson('pending', join(f.store.paths.dir, 'watcher-relay.json'))).toMatchObject({ resumeCursor: 'resume-message', pendingResumes: [] });
  const recovery = await f.store.readJson<{ usedResumeSignatures: string[] }>('plan', join(f.store.paths.dir, 'watcher-recovery.json'));
  expect(recovery?.usedResumeSignatures).toEqual([resumed.sig]);
});

test('Actions approval requests allow the scheduled watcher time to receive approval', async () => {
  const f = await fixture({ actions: true });
  const watcher = await createWatchRuntime(f.deps);
  const request = await watcher.approvals.request({ id: 'scheduled-request', kind: 'autopilot', clusterIds: [] }, false);
  expect(Date.parse(request.expiresAt) - Date.parse(request.createdAt)).toBe(3_600_000);
});

test('a cold Actions watcher initializes signed scope only after a new signed resume, preserving a concurrent disarm', async () => {
  for (const disarmed of [false, true]) {
    const f = await fixture({ actions: true, noState: true }); f.deps.sources = [];
    f.deps.relay = { server: 'https://ntfy.sh', topic: 'saved-topic' };
    let message = '';
    f.http.on('GET', /ntfy\.sh/, () => text(200, message));
    const watcher = await createWatchRuntime(f.deps); await watcher.tick();
    expect(await f.store.readJson('plan', join(f.store.paths.dir, 'autopilot.json'))).toBeNull();
    if (disarmed) await watcher.disarm();
    f.clock.ms += 60_000;
    const resume = signWatcherResume({ watcherId: 'project', at: f.deps.now!().toISOString() }, f.key);
    message = JSON.stringify({ id: 'resume', time: Math.floor(f.clock.ms / 1000), event: 'message', topic: 'saved-topic', message: JSON.stringify(resume) });
    await watcher.tick();
    expect(watcher.state.disarmed).toBe(disarmed);
    if (!disarmed) expect((await watcher.check()).ok).toBe(true);
  }
});

test('a retained resume from before a new cache-loss episode cannot release its pause', async () => {
  const f = await fixture({ actions: true, noState: true }); f.deps.sources = [];
  f.deps.relay = { server: 'https://ntfy.sh', topic: 'saved-topic' };
  const resume = signWatcherResume({ watcherId: 'project', at: new Date(f.clock.ms - 60_000).toISOString() }, f.key);
  f.http.on('GET', /ntfy\.sh/, () => text(200, JSON.stringify({ id: 'old-resume', time: Math.floor(f.clock.ms / 1000),
    event: 'message', topic: 'saved-topic', message: JSON.stringify(resume) })));
  const watcher = await createWatchRuntime(f.deps); await watcher.tick();
  expect((await watcher.check()).ok).toBe(false);
  expect(await f.store.readJson('plan', join(f.store.paths.dir, 'watcher-recovery.json'))).toMatchObject({ requiresResume: true });
});

test('an approved action without an arm executes and settles through the same rails', async () => {
  const f = await fixture({ noArm: true }); f.deps.sources = [];
  const watcher = await createWatchRuntime(f.deps);
  const inventory = await f.deps.freshInventory();
  const action = { id: 'approved-no-arm', kind: 'autopilot', clusterIds: [f.clusterId],
    planHash: planHashFor(buildPlan(inventory, { clusterIds: [f.clusterId] })) };
  const request = await watcher.approvals.request(action, false);
  const body = { actionId: action.id, digest: request.digest, at: f.deps.now!().toISOString() };
  await watcher.approvals.approveWithDevice(action.id, { ...body, keyId: f.key.keyId,
    sig: signDetached(f.key.privateKeyDer, Buffer.from(APPROVAL_PREFIX + canonicalJson(body))).toString('base64') });
  await watcher.tick();
  expect(f.host.writes.length).toBeGreaterThan(0);
  f.clock.ms += 901_000;
  await watcher.settle();
  expect(f.provider.keys.get(f.old.ref)?.active).toBe(false);
});

test('a pending approval cannot prevent polling and applying a newer disarm', async () => {
  const f = await fixture(); f.deps.sources = []; f.deps.relay = { server: 'https://ntfy.sh', topic: 'saved-topic' };
  await f.store.writeJson('pending', join(f.store.paths.dir, 'watcher-relay.json'), { cursor: 'earlier', pendingApprovals: [
    { actionId: 'unknown', digest: '0'.repeat(64), at: f.deps.now!().toISOString(), keyId: f.key.keyId, sig: 'old-approval' }], pendingDisarms: [] });
  const signed = signDisarm(f.key, { watcherId: 'project', at: f.deps.now!().toISOString() });
  f.http.on('GET', /ntfy\.sh/, () => text(200, JSON.stringify({ id: 'new-disarm', time: Math.floor(f.clock.ms / 1000), event: 'message', topic: 'saved-topic',
    message: JSON.stringify({ type: 'keysentry-disarm', v: 2, ...signed }) })));
  const watcher = await createWatchRuntime(f.deps); await watcher.tick();
  expect(watcher.state.disarmed).toBe(true);
});

test.each([
  ['https://watcher.fly.dev', {}, 1], ['https://watcher.up.railway.app', {}, 1], ['https://watcher.onrender.com', {}, 1],
  ['https://custom.example', { RAILWAY_ENVIRONMENT: 'production' }, 1], ['http://localhost:9999', {}, 0],
  ['https://custom.example', {}, 0], ['https://evilfly.dev', {}, 0],
] as const)('approval forwarding trust is limited to hosted HTTPS ingress: %s', (origin, env, hops) => {
  expect(approvalProxyHops(origin, env)).toBe(hops);
});

test('an own-platform incident still executes app keys and names operating credentials in coverage', async () => {
  const f = await fixture(); f.deps.env = { RAILWAY_ENVIRONMENT: 'production' };
  const watcher = await createWatchRuntime(f.deps); await watcher.tick();
  expect(watcher.state.waves).toHaveLength(1);
  expect(f.host.writes.length).toBeGreaterThan(0);
  const coverage = f.messages.find(message => message.kind === 'autopilot:own-credentials');
  expect(coverage?.lines.join('\n')).toContain('RAILWAY_TOKEN');
});

test('approval URLs are included only for passkeys registered to the exact public origin', async () => {
  const f = await fixture({ exposure: false }); f.deps.publicOrigin = 'https://watcher.example';
  f.deps.passkeys = async () => [{ id: 'credential', publicKeyCose: 'cose', alg: -7, signCount: 0, backupEligible: false,
    rpId: 'watcher.example', origins: ['https://watcher.example'], label: 'watcher', createdAt: f.deps.now!().toISOString() }];
  const watcher = await createWatchRuntime(f.deps); await watcher.tick();
  const message = f.messages.find(message => message.actionId)!;
  expect(message.approveUrl).toBe(`https://watcher.example/a/${message.actionId}`);
});

test('watch runs the audit export hook after each cycle, and a failing hook only logs fixed text', async () => {
  const f = await fixture();
  const warnings: string[] = [];
  let calls = 0;
  const deps: WatchRuntimeDependencies = { ...f.deps, log: { ...f.deps.log, warn: (message: string) => { warnings.push(message); } },
    afterCycle: async () => { calls++; throw new Error('upstream-body-with-secret-value'); } };
  expect(await runWatch(deps, { once: true })).toBe(0);
  expect(calls).toBe(1);
  expect(warnings).toContain('Audit export did not finish after this cycle. Run keysentry audit export status.');
  expect(warnings.join(' ')).not.toContain('secret-value');
});

test('a slow audit export runs beside the loop, one at a time, and never delays the next cycle (review L10)', async () => {
  const f = await fixture();
  let calls = 0, cycles = 0;
  let release!: () => void;
  const hung = new Promise<void>(resolve => { release = resolve; });
  const controller = new AbortController();
  const deps: WatchRuntimeDependencies = { ...f.deps,
    afterCycle: async () => { calls++; await hung; },
    sleep: async () => { cycles++; if (cycles >= 3) controller.abort(); } };
  let finished = false;
  const run = runWatch(deps, { signal: controller.signal }).then(code => { finished = true; return code; });
  for (let wait = 0; wait < 200 && !controller.signal.aborted; wait++) await new Promise(resolve => setTimeout(resolve, 5));
  // Three cycles ran while the first export was still hanging, and no second export started beside it.
  expect(cycles).toBe(3);
  expect(calls).toBe(1);
  await new Promise(resolve => setTimeout(resolve, 20));
  expect(finished).toBe(false); // stopping waits for the export in progress
  release();
  expect(await run).toBe(0);
});

test('the approval server reports a watcher whose network settings refuse every request as unhealthy (review H1)', async () => {
  const f = await fixture();
  const reason = "The watcher's proxy or certificate settings cannot be used, so it refuses every outbound request.";
  let health: ServerHealth = { problem: { code: 'network', reason } };
  const watcher = await createWatchRuntime({ ...f.deps, health: () => health });
  const port = await new Promise<number>((resolve, reject) => {
    const probe = createNetServer().listen(0, '127.0.0.1', () => { const bound = probe.address() as AddressInfo; probe.close(() => resolve(bound.port)); });
    probe.on('error', reject);
  });
  const server = await watcher.server(port);
  try {
    const get = () => new Promise<{ status: number; body: string }>((resolve, reject) => {
      const req = httpRequest({ host: '127.0.0.1', port, path: '/healthz', agent: false, headers: { Host: `localhost:${port}` } }, res => {
        const chunks: Buffer[] = []; res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => resolve({ status: res.statusCode!, body: Buffer.concat(chunks).toString('utf8') }));
      });
      req.on('error', reject); req.end();
    });
    const unhealthy = await get();
    expect(unhealthy.status).toBe(503);
    expect(JSON.parse(unhealthy.body)).toMatchObject({ ok: false, problem: 'network', reason });
    health = { feedsOffline: true };
    const offline = await get();
    expect(offline.status).toBe(200);
    expect(JSON.parse(offline.body)).toMatchObject({ ok: true, feeds: 'offline' });
  } finally { await server.close(); }
});
