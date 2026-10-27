import { afterEach, describe, expect, test } from 'vitest';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  buildArmedPlan, classifyItem, DEFAULT_SOURCES, runAutopilot, settleWaves, signArmedPlan, updateIncidents,
  type AutopilotDeps, type AutopilotState,
} from '../../src/autopilot/index.js';
import { createApprovalService } from '../../src/approvals/index.js';
import { buildInventory, createRedactor, createStateCipher, createStateStore, fingerprint, serviceKey } from '../../src/core/index.js';
import { fetchFeed } from '../../src/feeds/index.js';
import { createGuardedHttp, EGRESS_RULES, rulesForUserUrls } from '../../src/net/index.js';
import { createDispatcher, createWebhookChannel, signMessage, verifyMessage } from '../../src/notify/index.js';
import { generateDeviceKey } from '../../src/security/index.js';
import type { AuditEvent, AuditLog, Incident, NetworkReceipt, NetworkReceiptEntry, SignedNotifyMessage } from '../../src/types.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { FakeHttp, silentLogger, text } from '../helpers/fake-http.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

const directories: string[] = [];
afterEach(async () => { for (const path of directories.splice(0)) await rm(path, { recursive: true, force: true }); });

async function filesUnder(path: string): Promise<Buffer[]> {
  const entries = await readdir(path, { withFileTypes: true });
  return (await Promise.all(entries.map(entry => entry.isDirectory()
    ? filesUnder(join(path, entry.name)) : readFile(join(path, entry.name)).then(value => [value])))).flat();
}

async function fixture() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-autopilot-e2e-')); directories.push(cwd);
  const clock = { ms: Date.parse('2026-10-26T08:00:00.000Z') };
  const now = () => new Date(clock.ms);
  const key = generateDeviceKey();
  const vault = createFakeVault({ 'state-key': Buffer.alloc(32, 0x41) });
  const store = createStateStore({ cwd, cipher: createStateCipher((await vault.get('state-key'))!) });
  const fingerprintKey = Buffer.alloc(32, 0x42);
  const openai = new FakeProvider('openai', 'auto', 'sk-proj-'); openai.now = now;
  const openrouter = new FakeProvider('openrouter', 'auto', 'sk-or-v1-0123456789abcdef'); openrouter.now = now;
  const oldOpenai = openai.issue('armed-openai');
  const oldOpenrouter = openrouter.issue('armed-openrouter');
  clock.ms = Date.parse('2026-10-27T08:00:00.000Z');
  const host = new FakeHost('railway');
  const services = [
    host.addService('api', { OPENAI_API_KEY: oldOpenai.value, OPENROUTER_API_KEY: oldOpenrouter.value, NODE_ENV: 'production' }),
    host.addService('worker', { OPENAI_API_KEY: oldOpenai.value, OPENROUTER_API_KEY: oldOpenrouter.value, NODE_ENV: 'production' }),
  ];
  const scan = async () => buildInventory([{ host: host.id, services: await Promise.all((await host.listServices()).map(async service => ({
    service, vars: await host.readVariables(service),
  }))) }], fingerprintKey, now());
  const inventory = await scan(); await store.saveInventory(inventory);
  expect(inventory.clusters.map(cluster => cluster.provider).sort()).toEqual(['openai', 'openrouter']);
  const healthUrls = services.map(service => `https://health.example/${service.serviceId}`);
  const webhook = 'https://notifications.example/keysentry';
  const messages: SignedNotifyMessage[] = [];
  const receiptEntries: NetworkReceiptEntry[] = [];
  const receipt: NetworkReceipt = { async record(entry) { receiptEntries.push(entry); }, async summarize() { return []; } };
  const transport = new FakeHttp()
    .on('GET', /^https:\/\/health\.example\/(api|worker)$/, () => text(204, ''))
    .on('POST', /^https:\/\/notifications\.example\/keysentry$/, request => {
      messages.push(JSON.parse(request.body!) as SignedNotifyMessage); return text(204, '');
    });
  const rules = [...EGRESS_RULES, ...rulesForUserUrls(healthUrls, 'health check you configured'),
    ...rulesForUserUrls([webhook], 'notifications you configured')];
  const http = createGuardedHttp(transport, { rules, trustedUrls: [webhook], receipt, now });
  const redactor = createRedactor();
  const dispatcher = createDispatcher([createWebhookChannel({ id: 'test-webhook', url: webhook }, { http, redactor })], {
    log: silentLogger, now, retries: 1,
  });
  const auditEvents: AuditEvent[] = [];
  const audit: AuditLog = { async append(event) { auditEvents.push(structuredClone(event)); }, async checkpoint() {},
    async verify() { return { ok: true, entries: auditEvents.length, checkpoints: 0 }; } };
  const approvalService = createApprovalService({ store, audit, now, credentials: async () => [],
    deviceKeys: async () => [{ keyId: key.keyId, publicKeyDer: key.publicKeyDer }], rpId: 'localhost', origins: ['http://localhost:3000'] });
  const approvalIds: string[] = [];
  const built = buildArmedPlan({ projectId: 'e2e-project', inventory, clusterIds: inventory.clusters.map(cluster => cluster.id),
    hosts: ['railway'], now: now(), options: { graceSeconds: 900, healthChecks: services.map((service, index) => ({
      serviceKey: serviceKey(service), url: healthUrls[index]!, expectStatus: 204,
    })) } });
  expect(built.refused).toEqual([]);
  const armed = signArmedPlan(built.plan, key);
  await store.writeJson('plan', join(store.paths.dir, 'armed-plan.json'), armed);
  const state: AutopilotState = { armedPlanId: armed.id, disarmed: false, waves: [] };
  const trace: string[] = [];
  const active = new Set<string>(); let maxActive = 0;
  const deploy = host.redeploy.bind(host);
  host.redeploy = async service => {
    trace.push(`start:${service.serviceId}`); active.add(service.serviceId); maxActive = Math.max(maxActive, active.size);
    return deploy(service);
  };
  const deploymentStatus = host.deploymentStatus.bind(host);
  host.deploymentStatus = async (service, id) => {
    const status = await deploymentStatus(service, id);
    if (status !== 'pending') { trace.push(`${status}:${service.serviceId}`); active.delete(service.serviceId); }
    return status;
  };
  const deps: AutopilotDeps = {
    engine: { hosts: { railway: host }, providers: id => {
      if (id === 'openai') return openai; if (id === 'openrouter') return openrouter; throw new Error('Unexpected provider.');
    }, providerCtx: { http, credentials: {}, log: silentLogger }, journal: store.journal(), inflight: createFakeInFlight(),
    prompt: async () => null, fingerprintKey, redactor, log: silentLogger, now,
    sleep: async ms => { clock.ms += ms; } },
    options: { dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 1,
      revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 0 },
    async notify(message) { const result = await dispatcher.send(signMessage(message, key)); expect(result.delivered).toEqual(['test-webhook']); },
    async requestApproval(clusterIds, _reasons, actionId) {
      const id = actionId ?? `approval-e2e-${approvalIds.length}`;
      await approvalService.request({ id, kind: 'autopilot-rotation', clusterIds }, false); approvalIds.push(id); return id;
    }, audit,
    async saveState(saved) { await store.writeJson('monitor', join(store.paths.dir, 'autopilot.json'), saved); },
  };
  const selfCheck = { ok: true, reasons: [] as string[] };
  const recoveryDeps = { ...deps, trustedKeyIds: [key.keyId], env: {}, selfCheck };
  async function feed(fixtureName: string, sourceId: string) {
    const source = DEFAULT_SOURCES.find(candidate => candidate.id === sourceId)!;
    // Replay the recorded content as a newly published item for this rotation
    // scenario. Historical-feed freshness is covered by the incidents tests.
    const publishedAt = new Date(now().getTime() - 3_600_000).toUTCString();
    let xml = (await readFile(new URL(`../fixtures/feeds/${fixtureName}`, import.meta.url), 'utf8'))
      .replace(/<pubDate>[^<]*<\/pubDate>/g, `<pubDate>${publishedAt}</pubDate>`);
    if (source.kind === 'official') {
      // Recorded descriptions omit the article's exposure facts; this fresh
      // scenario explicitly supplies the same claim as the incidents tests.
      xml = xml.replace(/<\/description>/g, ' Customer environment variables were accessed. Railway urges users to rotate credentials after the security incident.</description>');
    }
    transport.on('GET', new RegExp(`^${source.url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`), () => text(200, xml));
    const result = await fetchFeed(http, source, {});
    const evidence = result.items.map(item => classifyItem(item, source, id => fingerprint(`${source.id}:${id}`, fingerprintKey)))
      .filter((item): item is NonNullable<typeof item> => item !== null);
    const updated = updateIncidents({ incidents: [] }, evidence, now());
    await store.writeJson('monitor', join(store.paths.dir, 'incidents.json'), { incidents: updated.incidents });
    return updated;
  }
  const run = (incident: Incident) => runAutopilot({ incident, armed, trustedKeyIds: [key.keyId], inventory, state,
    selfCheck, env: {}, now: now() }, deps);
  const settle = async () => settleWaves({ state, inventory: await scan(), now: now(), disarmed: state.disarmed }, recoveryDeps);
  const planted = () => [...openai.keys.values(), ...openrouter.keys.values()].map(value => value.value);
  return { cwd, clock, now, store, key, inventory, host, services, openai, openrouter, oldOpenai, oldOpenrouter, state,
    messages, receiptEntries, transport, auditEvents, approvalIds, approvalService, feed, run, settle, scan, trace,
    maxActive: () => maxActive, planted };
}

describe('breach autopilot end to end', () => {
  test('a fresh synthetic replay of the Railway advisory rotates armed keys with serial deployments, health checks, grace and revocation', async () => {
    const f = await fixture();
    const incidentUpdate = await f.feed('railway-official-2026-10.xml', 'railway-blog');
    expect(incidentUpdate.triggered).toHaveLength(1);
    const incident = incidentUpdate.triggered[0]!;
    expect(incident.trigger?.rule).toBe('official');
    const result = await f.run(incident);
    expect(result.executed.sort()).toEqual(f.inventory.clusters.map(cluster => cluster.id).sort());
    expect(result.asked).toEqual([]); expect(result.report?.status).toBe('grace-pending');
    expect(f.state.waves).toHaveLength(1); expect(f.state.waves[0]?.status).toBe('grace');
    expect(f.host.writes).toHaveLength(2); expect(f.host.redeploys).toEqual(['api', 'worker']);
    expect(f.trace).toEqual(['start:api', 'success:api', 'start:worker', 'success:worker']); expect(f.maxActive()).toBe(1);
    for (const service of f.services) {
      expect(f.transport.callsTo('GET', new RegExp(`^https://health\\.example/${service.serviceId}$`))).toHaveLength(3);
      expect(f.host.peek(service.serviceId, 'OPENAI_API_KEY') === f.oldOpenai.value).toBe(false);
      expect(f.host.peek(service.serviceId, 'OPENROUTER_API_KEY') === f.oldOpenrouter.value).toBe(false);
      expect(f.host.peek(service.serviceId, 'NODE_ENV')).toBe('production');
    }
    expect(f.openai.keys.get(f.oldOpenai.ref)?.active).toBe(true); expect(f.openrouter.keys.get(f.oldOpenrouter.ref)?.active).toBe(true);
    await f.run(incident); expect(f.state.waves).toHaveLength(1); expect(f.host.redeploys).toHaveLength(2);
    await f.settle(); expect(f.openai.revoked).toEqual([]); expect(f.openrouter.revoked).toEqual([]);
    f.clock.ms = Date.parse(f.state.waves[0]!.deadline!) + 1;
    const settled = await f.settle();
    expect(settled.settled).toEqual([f.state.waves[0]!.id]); expect(f.state.waves[0]?.status).toBe('done');
    expect(f.openai.revoked).toEqual([f.oldOpenai.ref]); expect(f.openrouter.revoked).toEqual([f.oldOpenrouter.ref]);
    expect(f.openai.keys.get(f.oldOpenai.ref)?.active).toBe(false); expect(f.openrouter.keys.get(f.oldOpenrouter.ref)?.active).toBe(false);
    expect(f.receiptEntries.length).toBeGreaterThan(6);
    expect(f.receiptEntries.every(entry => entry.allowed && ['blog.railway.com', 'health.example', 'notifications.example'].includes(entry.host))).toBe(true);
    expect(f.receiptEntries.filter(entry => entry.host === 'health.example').every(entry => entry.purpose === 'health check you configured')).toBe(true);
  });

  test('news-only fixtures alert and request a real pending approval but rotate nothing', async () => {
    const f = await fixture();
    const update = await f.feed('news-bleepingcomputer-railway.xml', 'bleepingcomputer');
    expect(update.triggered).toEqual([]); expect(update.changed).toHaveLength(1); expect(update.changed[0]?.status).toBe('alerted');
    const result = await f.run(update.changed[0]!);
    expect(result.executed).toEqual([]); expect(result.asked).toHaveLength(2);
    expect(f.host.writes).toEqual([]); expect(f.host.redeploys).toEqual([]); expect(f.state.waves).toEqual([]);
    expect(f.openai.keys.size).toBe(1); expect(f.openrouter.keys.size).toBe(1);
    expect(f.approvalIds).toHaveLength(1); expect(await f.approvalService.status(f.approvalIds[0]!)).toBe('pending');
    expect(f.messages.some(message => message.actionId === f.approvalIds[0])).toBe(true);
    expect(f.messages.every(message => verifyMessage(message, f.key.publicKeyDer))).toBe(true);
    for (const value of f.planted()) expect(JSON.stringify(f.messages).includes(value)).toBe(false);
  });

  test('outage, phishing and another company\'s breach remain alerts without credential-exposure authorization', async () => {
    const f = await fixture();
    const update = await f.feed('news-synthetic-negatives.xml', 'bleepingcomputer');
    expect(update.triggered).toEqual([]);
    const railway = update.changed.find(incident => incident.host === 'railway')!;
    expect(railway.status).toBe('alerted'); expect(railway.evidence).toHaveLength(3);
    expect(railway.evidence.every(evidence => !evidence.credentialExposure)).toBe(true);
    const result = await f.run(railway);
    expect(result.executed).toEqual([]); expect(result.asked).toHaveLength(2);
    expect(f.approvalIds).toHaveLength(1); expect(await f.approvalService.status(f.approvalIds[0]!)).toBe('pending');
    expect(f.host.writes).toEqual([]); expect(f.host.redeploys).toEqual([]);
    expect(f.openai.keys.size).toBe(1); expect(f.openrouter.keys.size).toBe(1);
  });

  test('disarming during grace keeps both old keys valid and starts no later rotation', async () => {
    const f = await fixture(); const update = await f.feed('railway-official-2026-10.xml', 'railway-blog');
    await f.run(update.triggered[0]!); f.state.disarmed = true; f.state.disarmedAt = f.now().toISOString();
    await f.store.writeJson('monitor', join(f.store.paths.dir, 'autopilot.json'), f.state);
    f.clock.ms = Date.parse(f.state.waves[0]!.deadline!) + 1;
    await f.settle();
    await f.run({ ...update.triggered[0]!, id: 'incident-after-disarm' });
    expect(f.openai.revoked).toEqual([]); expect(f.openrouter.revoked).toEqual([]);
    expect(f.openai.keys.get(f.oldOpenai.ref)?.active).toBe(true); expect(f.openrouter.keys.get(f.oldOpenrouter.ref)?.active).toBe(true);
    expect(f.openai.keys.size).toBe(2); expect(f.openrouter.keys.size).toBe(2);
    expect(f.state.waves).toHaveLength(1); expect(f.state.waves[0]?.status).toBe('grace'); expect(f.host.redeploys).toHaveLength(2);
  });

  test('all run notifications verify with the device public key and contain no planted value; state and receipt are secret-free', async () => {
    const f = await fixture(); const update = await f.feed('railway-official-2026-10.xml', 'railway-blog');
    await f.run(update.triggered[0]!); f.clock.ms = Date.parse(f.state.waves[0]!.deadline!) + 1; await f.settle();
    expect(f.messages.length).toBeGreaterThan(2); expect(f.messages.every(message => verifyMessage(message, f.key.publicKeyDer))).toBe(true);
    const metadata = await filesUnder(f.store.paths.dir);
    const publicText = JSON.stringify([f.messages, f.receiptEntries, f.auditEvents]);
    for (const value of f.planted()) {
      expect(publicText.includes(value)).toBe(false); expect(metadata.some(bytes => bytes.includes(Buffer.from(value)))).toBe(false);
    }
    expect(f.receiptEntries.every(entry => !('url' in entry) && !('body' in entry) && !('headers' in entry))).toBe(true);
  });

  test('fresh settlement inventory detects a late consumer still holding an old key and preserves the old key', async () => {
    const f = await fixture(); const update = await f.feed('railway-official-2026-10.xml', 'railway-blog');
    await f.run(update.triggered[0]!);
    f.host.addService('new-consumer', { OPENAI_API_KEY: f.oldOpenai.value });
    f.clock.ms = Date.parse(f.state.waves[0]!.deadline!) + 1;
    await f.settle();
    expect(f.openai.revoked).toEqual([]); expect(f.openai.keys.get(f.oldOpenai.ref)?.active).toBe(true);
    expect(f.host.peek('new-consumer', 'OPENAI_API_KEY') === f.oldOpenai.value).toBe(true);
  });
});
