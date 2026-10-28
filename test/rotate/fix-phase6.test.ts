// fix-phase6: engine fixes (notes/fix-phase6.md H1, H2, H4).
import { describe, expect, it } from 'vitest';
import { buildInventory, buildPlan, createLogger, createRedactor } from '../../src/core/index.js';
import { executePlan, type EngineDeps, type RotateOptions } from '../../src/rotate/engine.js';
import { finishRotation } from '../../src/rotate/grace.js';
import { GoogleGuidedRotationRequiredError, publicGoogleKeyGuidance } from '../../src/providers/google.js';
import { ProviderMutationUncertainError } from '../../src/providers/shared.js';
import { upstashProvider } from '../../src/providers/upstash.js';
import type { GuidedPrompt, Inventory, JournalEntry, ProviderAdapter, ProviderContext, RotationPlan } from '../../src/types.js';
import { FakeHttp, json } from '../helpers/fake-http.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';

const key = Buffer.alloc(32, 0x66);
const options: RotateOptions = {
  dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 1,
  revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 0,
};

async function inventoryOf(host: FakeHost): Promise<Inventory> {
  return buildInventory([{ host: host.id, services: await Promise.all((await host.listServices())
    .map(async service => ({ service, vars: await host.readVariables(service) }))) }], key);
}

function harness(host: FakeHost, provider: ProviderAdapter, extra: Partial<EngineDeps> & { credentials?: ProviderContext['credentials']; http?: FakeHttp } = {}) {
  const entries: JournalEntry[] = [];
  const prompts: GuidedPrompt[] = [];
  const inflight = createFakeInFlight();
  const redactor = createRedactor();
  const log = createLogger({ redactor, level: 'debug', json: true, sink: () => undefined });
  const deps: EngineDeps = {
    hosts: { [host.id]: host }, providers: () => provider,
    providerCtx: { http: extra.http ?? new FakeHttp(), credentials: extra.credentials ?? {}, log },
    journal: { async append(entry) { entries.push(structuredClone(entry)); }, async read() { return entries; } },
    prompt: async (prompt) => { prompts.push(prompt); return null; }, reveal: async () => true,
    fingerprintKey: key, redactor, log, sleep: async () => undefined, inflight, ...extra,
  };
  return { deps, entries, prompts, inflight };
}

describe('provider changes with an unknown outcome (H4)', () => {
  it('records a possible stray key, keeps in-flight data and says what to check', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    provider.rotate = async () => { throw new ProviderMutationUncertainError('OpenAI request failed (no answer); a replacement key may already exist.', false, 'key_99'); };
    const host = new FakeHost('railway');
    host.addService('api', { OPENAI_API_KEY: old.value });
    const inv = await inventoryOf(host);
    const h = harness(host, provider);

    const report = await executePlan(buildPlan(inv), inv, h.deps, options);

    expect(report.status).toBe('partial');
    expect(report.orphanSuspects).toEqual([expect.objectContaining({ keyRef: 'key_99', provider: 'openai' })]);
    expect(report.steps[0]).toMatchObject({ status: 'failed' });
    expect(report.steps[0]!.error).toMatch(/may already have created a replacement key.*example\.invalid\/openai\/keys.*old key, which stays active/);
    expect(report.steps[0]!.error).not.toMatch(/no consumer was changed/);
    expect(h.entries).toContainEqual(expect.objectContaining({ event: 'orphan-suspected',
      data: expect.objectContaining({ keyRef: 'key_99', reason: 'mutation-uncertain', atomic: false }) }));
    expect(h.inflight.calls).not.toContain('shred');
    expect(host.writes).toEqual([]);
  });

  it('says that an atomic roll may already have invalidated the old credential', async () => {
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'cf-token-');
    provider.rotate = async () => { throw new ProviderMutationUncertainError('cloudflare request failed (HTTP 502)', true); };
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    host.addService('api', { CLOUDFLARE_API_TOKEN: 'Zx8Kq2Lm9Pw4Rt7Ys1Vb6Nc3Hd5Jf0Ga' });
    const inv = await inventoryOf(host);
    const h = harness(host, provider);

    const report = await executePlan(buildPlan(inv), inv, h.deps, options);

    expect(report.status).toBe('partial');
    expect(report.orphanSuspects ?? []).toEqual([]);
    expect(report.steps[0]!.error).toMatch(/^URGENT: the cloudflare reset may already have happened.*old credential is already invalid/);
    expect(h.entries).toContainEqual(expect.objectContaining({ event: 'orphan-suspected', data: expect.objectContaining({ atomic: true, keyRef: null }) }));
  });
});

describe('unknown outcomes with the real adapters (H4)', () => {
  it('Upstash: a reset that timed out is reported as possibly done, with the old credential possibly dead', async () => {
    const endpoint = 'eu1-slow-hare-5150';
    const token = `AX${'z'.repeat(8)}Kp3Lq5Mr7Ns9Ot1Pu2Qv4Rw6Sx8Ty0U`;
    const http = new FakeHttp()
      .on('GET', /\/v2\/redis\/databases$/, () => json(200, [{ database_id: 'db-5', endpoint, state: 'active', password: 'b1c2d3e4f5a60718293a4b5c6d7e8f90', rest_token: token }]))
      .on('POST', /\/v2\/redis\/reset-password\/db-5$/, () => { throw new Error('socket timeout'); });
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    host.addService('api', { UPSTASH_REDIS_REST_URL: `https://${endpoint}.upstash.io`, UPSTASH_REDIS_REST_TOKEN: token });
    const inv = await inventoryOf(host);
    const h = harness(host, upstashProvider, { http, credentials: { UPSTASH_ADMIN_EMAIL: 'ops@example.com', UPSTASH_ADMIN_KEY: '5e4d3c2b-1a09-4f8e-9d7c-6b5a49382716' } });

    const report = await executePlan(buildPlan(inv), inv, h.deps, options);

    expect(http.callsTo('POST', /reset-password/)).toHaveLength(1);
    expect(report.status).toBe('partial');
    expect(report.steps[0]!.error).toMatch(/^URGENT: the upstash reset may already have happened.*https:\/\/console\.upstash\.com\//);
    expect(h.entries).toContainEqual(expect.objectContaining({ event: 'orphan-suspected', data: expect.objectContaining({ reason: 'mutation-uncertain', atomic: true }) }));
    expect(JSON.stringify([report, h.entries])).not.toContain(token);
  });

  it('Google: a key creation still running is reported as a possible unused key', async () => {
    const { createGoogleProvider } = await import('../../src/providers/google.js');
    const oldKey = `AIza${'Q'.repeat(12)}7hZ-k2_${'w'.repeat(16)}`;
    const name = 'projects/demo-project/locations/global/keys/old-key';
    const http = new FakeHttp()
      .on('GET', /\/v2\/projects\/demo-project\/locations\/global\/keys$/, () => json(200, { keys: [{ name }] }))
      .on('GET', /\/keys\/old-key\/keyString$/, () => json(200, { keyString: oldKey }))
      .on('GET', /\/keys\/old-key$/, () => json(200, { name, displayName: 'api', restrictions: { apiTargets: [{ service: 'generativelanguage.googleapis.com' }] } }))
      .on('POST', /\/locations\/global\/keys$/, () => json(200, { name: 'operations/stuck', done: false }))
      .on('GET', /\/v2\/operations\/stuck$/, () => json(200, { name: 'operations/stuck', done: false }));
    const host = new FakeHost('render');
    host.addService('api', { GEMINI_API_KEY: oldKey });
    const inv = await inventoryOf(host);
    const h = harness(host, createGoogleProvider({ sleep: async () => {} }), { http,
      credentials: { GOOGLE_OAUTH_ACCESS_TOKEN: `ya29.${'a'.repeat(40)}`, GOOGLE_API_KEYS_PROJECT: 'demo-project' } });

    const report = await executePlan(buildPlan(inv), inv, h.deps, options);

    expect(report.status).toBe('partial');
    expect(report.steps[0]!.error).toMatch(/google may already have created a replacement key.*console\.cloud\.google\.com/);
    expect(h.entries).toContainEqual(expect.objectContaining({ event: 'orphan-suspected', data: expect.objectContaining({ reason: 'mutation-uncertain', atomic: false }) }));
    expect(host.writes).toEqual([]);
  });
});

describe('public Google API keys (H1)', () => {
  function google() {
    const provider = new FakeProvider('google', 'auto', 'AIzaSyAB');
    const old = provider.issue('web');
    expect(old.value).toMatch(/^AIza[A-Za-z0-9_-]{35}$/);
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    host.addService('web', { NEXT_PUBLIC_FIREBASE_API_KEY: old.value });
    return { provider, old, host };
  }

  it('is replaced only by hand with public-key guidance, and its old key is never revoked', async () => {
    const { provider, old, host } = google();
    const inv = await inventoryOf(host);
    expect(inv.clusters[0]!.method).toBe('guided');
    const plan: RotationPlan = buildPlan(inv);
    // Even a plan saved before this fix (method auto) is executed as guided.
    plan.steps[0]!.method = 'auto';
    const replacement = provider.issue('replacement');
    const h = harness(host, provider);
    h.deps.prompt = async (prompt) => { h.prompts.push(prompt); return replacement.value; };
    const rotate = provider.rotate.bind(provider);
    let rotations = 0;
    provider.rotate = async (value, ctx) => { rotations += 1; return rotate(value, ctx); };

    const report = await executePlan(plan, inv, h.deps, options);

    expect(rotations).toBe(0);
    expect(h.prompts[0]!.guidance).toEqual(publicGoogleKeyGuidance());
    expect(host.peek('web', 'NEXT_PUBLIC_FIREBASE_API_KEY')).toBe(replacement.value);
    expect(provider.revoked).toEqual([]);
    expect(provider.keys.get(old.ref)!.active).toBe(true);
    expect(report.steps[0]!.warnings.join(' ')).toMatch(/old key was kept because it ships inside web pages or mobile apps/);
    expect(h.entries.some(entry => typeof entry.data?.oldKeyRef === 'string')).toBe(false);
  });

  it('keeps the old key of a client-restricted server key through guided fallback and finish', async () => {
    const provider = new FakeProvider('google', 'auto', 'AIzaSyAB');
    const old = provider.issue('maps');
    provider.rotate = async () => { throw new GoogleGuidedRotationRequiredError('restricted to websites', { retainOldKey: true }); };
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    host.addService('api', { GOOGLE_MAPS_API_KEY: old.value });
    const inv = await inventoryOf(host);
    expect(inv.clusters[0]!.method).toBe('auto');
    const plan = buildPlan(inv);
    const replacement = provider.issue('replacement');
    const h = harness(host, provider, { grace: async () => 'defer' });
    h.deps.prompt = async () => replacement.value;

    const report = await executePlan(plan, inv, h.deps, { ...options, graceMs: 60_000 });
    expect(report.status).toBe('grace-pending');
    expect(h.entries).toContainEqual(expect.objectContaining({ event: 'created', data: expect.objectContaining({ phase: 'guided-fallback', retainOldKey: true }) }));
    expect(report.steps[0]!.warnings.join(' ')).toMatch(/keysentry will not delete the old key/);

    const finished = await finishRotation({ plan, inventory: inv, entries: [...h.entries] }, h.deps, { ...options, early: true });
    expect(provider.revoked).toEqual([]);
    expect(provider.keys.get(old.ref)!.active).toBe(true);
    expect(finished.steps[0]!.warnings.join(' ')).toMatch(/old key was kept because it ships inside web pages or mobile apps/);
  });
});

describe('Upstash resets cover every form of the credential (H2)', () => {
  const endpoint = 'eu1-brave-owl-4040';
  const dbHost = `${endpoint}.upstash.io`;
  function upstash() {
    const state = { password: 'a0b1c2d3e4f5061728394a5b6c7d8e9f', token: `AX${'k'.repeat(10)}Q7rT9vW2yZ4bD6fH8jL0nP3sU5wX`,
      readOnly: `Ar${'m'.repeat(10)}Z9yX8wV7uT6sR5qP4oN3mL2kJ`, resets: 0, rotateReadOnly: true };
    const http = new FakeHttp()
      .on('GET', /^https:\/\/api\.upstash\.com\/v2\/redis\/databases$/, () => json(200, [{
        database_id: 'db-1', endpoint, state: 'active', password: state.password, rest_token: state.token, read_only_rest_token: state.readOnly }]))
      .on('POST', /^https:\/\/api\.upstash\.com\/v2\/redis\/reset-password\/db-1$/, () => {
        state.resets += 1;
        state.password = `f${state.resets}e1d2c3b4a5968778695a4b3c2d1e0f0`;
        state.token = `AY${'q'.repeat(10)}${state.resets}Gh7Jk9Lm2Np4Qr6St8Uv0Wx3Yz5Ab`;
        if (state.rotateReadOnly) state.readOnly = `As${'r'.repeat(10)}${state.resets}Bc7De9Fg2Hi4Jk6Lm8No0Pq3Rs5Tu`;
        return json(200, { database_id: 'db-1', endpoint, password: state.password, rest_token: state.token, read_only_rest_token: state.readOnly });
      })
      .on('GET', new RegExp(`^https://${endpoint}\\.upstash\\.io/ping$`), req =>
        [state.token, state.readOnly].some(token => req.headers?.Authorization === `Bearer ${token}`) ? json(200, { result: 'PONG' }) : json(401, {}));
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    const url = () => `rediss://default:${state.password}@${dbHost}:6379`;
    const credentials = { UPSTASH_ADMIN_EMAIL: 'ops@example.com', UPSTASH_ADMIN_KEY: '0f9e8d7c-6b5a-4938-2716-05f4e3d2c1b0' };
    return { state, http, host, url, credentials };
  }
  const clusterOf = (inv: Inventory, name: string) => inv.clusters.find(cluster => cluster.consumers.some(consumer => consumer.varName === name))!;

  it('rolls once and delivers each planned form, the REST token and another service\'s Redis URL', async () => {
    const u = upstash();
    u.host.addService('api', { UPSTASH_REDIS_REST_URL: `https://${dbHost}`, UPSTASH_REDIS_REST_TOKEN: u.state.token });
    u.host.addService('worker', { REDIS_URL: u.url() });
    const inv = await inventoryOf(u.host);
    const plan = buildPlan(inv, { clusterIds: [clusterOf(inv, 'UPSTASH_REDIS_REST_TOKEN').id, clusterOf(inv, 'REDIS_URL').id] });
    const h = harness(u.host, upstashProvider, { http: u.http, credentials: u.credentials });

    const report = await executePlan(plan, inv, h.deps, options);

    expect(u.state.resets).toBe(1);
    expect(u.host.peek('api', 'UPSTASH_REDIS_REST_TOKEN')).toBe(u.state.token);
    expect(u.host.peek('worker', 'REDIS_URL')).toBe(u.url());
    expect(report.steps.map(step => step.status)).toEqual(['deployed', 'deployed'].map(() => expect.stringMatching(/deployed|revoked/)));
    expect(report.status).toBe('complete');
    // Both rolled values were stored before delivery, so recovery could deliver either one.
    expect(h.inflight.calls.filter(call => call.startsWith('put:new:'))).toHaveLength(2);
  });

  it('lets the primary companions update another form held in the same service', async () => {
    const u = upstash();
    u.host.addService('api', { UPSTASH_REDIS_REST_URL: `https://${dbHost}`, UPSTASH_REDIS_REST_TOKEN: u.state.token, REDIS_URL: u.url() });
    const inv = await inventoryOf(u.host);
    const plan = buildPlan(inv, { clusterIds: [clusterOf(inv, 'UPSTASH_REDIS_REST_TOKEN').id] });
    const h = harness(u.host, upstashProvider, { http: u.http, credentials: u.credentials });

    await executePlan(plan, inv, h.deps, options);

    expect(u.state.resets).toBe(1);
    expect(u.host.peek('api', 'REDIS_URL')).toBe(u.url());
  });

  it('does not reset when a form it would change is not in the plan, including one keysentry did not inventory', async () => {
    const u = upstash();
    u.host.addService('api', { UPSTASH_REDIS_REST_URL: `https://${dbHost}`, UPSTASH_REDIS_REST_TOKEN: u.state.token });
    u.host.addService('api2', { UPSTASH_REDIS_REST_URL: `https://${dbHost}`, UPSTASH_REDIS_REST_TOKEN: u.state.token, REDIS_PW: u.state.password });
    const inv = await inventoryOf(u.host);
    expect(inv.findings.some(finding => finding.varName === 'REDIS_PW')).toBe(false);
    const h = harness(u.host, upstashProvider, { http: u.http, credentials: u.credentials });

    const report = await executePlan(buildPlan(inv), inv, h.deps, options);

    expect(u.state.resets).toBe(0);
    expect(report.steps[0]).toMatchObject({ status: 'skipped' });
    expect(report.steps[0]!.warnings.join(' ')).toMatch(/Not reset: an Upstash reset also changes the same credential at railway\/api2:REDIS_PW/);
  });

  it('turns every Upstash reset into a guided one when a possible form cannot be read', async () => {
    const u = upstash();
    u.host.addService('api', { UPSTASH_REDIS_REST_URL: `https://${dbHost}`, UPSTASH_REDIS_REST_TOKEN: u.state.token });
    u.host.addService('worker', { REDIS_URL: u.url() }, ['REDIS_URL']);
    const inv = await inventoryOf(u.host);
    const plan = buildPlan(inv, { clusterIds: [clusterOf(inv, 'UPSTASH_REDIS_REST_TOKEN').id] });
    const h = harness(u.host, upstashProvider, { http: u.http, credentials: u.credentials });

    const report = await executePlan(plan, inv, h.deps, options);

    expect(u.state.resets).toBe(0);
    expect(h.prompts).toHaveLength(1);
    expect(report.steps[0]!.warnings.join(' ')).toMatch(/Guided reset: .*cannot read every place that may hold one: railway\/worker:REDIS_URL/);
  });

  it('skips a planned read-only form that the reset left unchanged', async () => {
    const u = upstash();
    u.state.rotateReadOnly = false;
    u.host.addService('api', { UPSTASH_REDIS_REST_URL: `https://${dbHost}`, UPSTASH_REDIS_REST_TOKEN: u.state.token });
    u.host.addService('reader', { UPSTASH_REDIS_REST_URL: `https://${dbHost}`, UPSTASH_REDIS_REST_READ_ONLY_TOKEN: u.state.readOnly });
    const inv = await inventoryOf(u.host);
    const readOnly = u.state.readOnly;
    const h = harness(u.host, upstashProvider, { http: u.http, credentials: u.credentials });

    const report = await executePlan(buildPlan(inv), inv, h.deps, options);

    expect(u.state.resets).toBe(1);
    expect(u.host.peek('api', 'UPSTASH_REDIS_REST_TOKEN')).toBe(u.state.token);
    expect(u.host.peek('reader', 'UPSTASH_REDIS_REST_READ_ONLY_TOKEN')).toBe(readOnly);
    const step = report.steps.find(item => item.clusterId === clusterOf(inv, 'UPSTASH_REDIS_REST_READ_ONLY_TOKEN').id)!;
    expect(step.status).toBe('skipped');
    expect(step.warnings.join(' ')).toMatch(/left this form of the credential unchanged/);
  });
});
