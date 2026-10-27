import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import type { ArmedCluster, ArmedPlan, Cluster, HostId, Inventory } from '../../src/types.js';
import { canonicalJson, generateDeviceKey, signDetached } from '../../src/security/index.js';
import { getProvider } from '../../src/providers/index.js';
import { serviceKey } from '../../src/core/service-key.js';
import {
  ARMED_PLAN_PREFIX, adoptionNeeded, autopilotEligibility, buildArmedPlan, signArmedPlan, verifyArmedPlan,
} from '../../src/autopilot/armed-plan.js';

const now = new Date('2026-10-27T12:00:00.000Z');
const key = generateDeviceKey();
const adopted = { fingerprint: 'f'.repeat(32), keyRef: 'key-ref', at: now.toISOString() };
function cluster(overrides: Partial<Cluster> & { adopted?: ArmedCluster['adopted'] } = {}): Cluster {
  return {
    id: 'cluster-1', fingerprint: 'f'.repeat(32), provider: 'openai', tier: 'ai', method: 'auto', hint: null,
    consumers: [{
      service: { host: 'railway', projectId: 'p', projectName: 'P', environmentId: 'e', environmentName: 'E', serviceId: 's', serviceName: 'S' },
      varName: 'OPENAI_API_KEY', fingerprint: 'f'.repeat(32), hint: null, sealed: false,
    }], ...overrides,
  };
}
function inventory(clusters = [cluster()]): Inventory {
  return { version: 1, scannedAt: now.toISOString(), hosts: ['railway'], services: clusters.flatMap(c => c.consumers.map(c => c.service)), findings: [], clusters, errors: [] };
}
function body(options: Parameters<typeof buildArmedPlan>[0]['options'] = {}) {
  return buildArmedPlan({ projectId: 'project', inventory: inventory(), clusterIds: ['cluster-1'], hosts: ['railway'], options, now }).plan;
}
function verify(plan: unknown, at = now) { return verifyArmedPlan(plan, { now: at, trustedKeyIds: [key.keyId] }); }
function signedMutation(edit: (plan: ArmedPlan) => void): ArmedPlan {
  const plan = signArmedPlan(body(), key);
  edit(plan);
  const { sig: _, ...unsigned } = plan;
  plan.sig = signDetached(key.privateKeyDer, Buffer.from(ARMED_PLAN_PREFIX + canonicalJson(unsigned))).toString('base64');
  return plan;
}

describe('eligibility and adoption', () => {
  test('only provider-API and allow-listed generate clusters are eligible', () => {
    for (const provider of ['openai', 'openrouter', 'resend', 'aws'] as const) {
      expect(autopilotEligibility(cluster({ provider, tier: provider === 'aws' ? 'cloud' : 'ai' }))).toEqual({ eligible: true, method: 'auto' });
    }
    const app = cluster({ provider: 'app-secret', tier: 'app', method: 'generate' });
    for (const varName of ['JWT_SECRET', 'JWT_SIGNING_SECRET', 'SESSION_SECRET', 'COOKIE_SECRET', 'NEXTAUTH_SECRET', 'AUTH_SECRET', 'BETTER_AUTH_SECRET', 'SECRET_KEY_BASE', 'CSRF_SECRET']) {
      app.consumers[0]!.varName = varName;
      expect(autopilotEligibility(app)).toEqual({ eligible: true, method: 'generate' });
    }
    for (const varName of ['MY_SESSION_SECRET', 'STRIPE_WEBHOOK_SECRET', 'ENCRYPTION_KEY', 'APP_KEY', 'ARBITRARY_SECRET']) {
      app.consumers[0]!.varName = varName;
      expect(autopilotEligibility(app)).toMatchObject({ eligible: false, reason: expect.any(String) });
    }
    for (const bad of [
      cluster({ provider: 'stripe', tier: 'payments', method: 'guided' }),
      cluster({ provider: 'database', tier: 'database', method: 'guided' }),
      cluster({ provider: 'cloudflare', tier: 'cloud', method: 'atomic-roll' }),
      cluster({ provider: 'anthropic', method: 'guided' }),
      cluster({ provider: 'encryption-key', tier: 'app', method: 'generate' }),
      cluster({ provider: 'crypto-wallet', tier: 'crypto' }),
      cluster({ provider: 'private-key', tier: 'cloud' }),
      cluster({ tier: 'payments' }), cluster({ tier: 'database' }), cluster({ tier: 'crypto' }),
      cluster({ method: 'guided' }), cluster({ method: 'generate' }), cluster({ consumers: [] }),
    ]) expect(autopilotEligibility(bad)).toMatchObject({ eligible: false, reason: expect.any(String) });
  });

  test.each(['rotate', 'revoke', 'verify'] as const)('auto requires the real adapter %s capability', capability => {
    const adapter = getProvider('openai');
    const original = adapter[capability];
    try {
      Object.assign(adapter, { [capability]: undefined });
      expect(autopilotEligibility(cluster())).toMatchObject({ eligible: false });
    } finally { Object.assign(adapter, { [capability]: original }); }
  });

  test('adoption is needed for sealed, Fly and Actions consumers without a usable provider reference', () => {
    expect(adoptionNeeded(cluster())).toBe(false);
    for (const host of ['railway', 'fly', 'github-actions'] as HostId[]) {
      const c = cluster(); c.consumers[0]!.service.host = host; c.consumers[0]!.sealed = host === 'railway';
      expect(adoptionNeeded(c)).toBe(true);
      expect(autopilotEligibility(c)).toMatchObject({ eligible: false, reason: expect.stringMatching(/adopt/i) });
      Object.assign(c, { adopted });
      expect(adoptionNeeded(c)).toBe(false);
      expect(autopilotEligibility(c)).toEqual({ eligible: true, method: 'auto' });
    }
  });

  test.each(['railway', 'fly', 'github-actions'] as const)('write-only %s adoption requires a non-null key reference', host => {
    const c = cluster({ adopted: { ...adopted, keyRef: null } });
    c.consumers[0]!.service.host = host;
    c.consumers[0]!.sealed = host === 'railway';
    expect(adoptionNeeded(c)).toBe(true);
    expect(autopilotEligibility(c)).toMatchObject({ eligible: false, reason: expect.stringMatching(/adopt/i) });
    const result = buildArmedPlan({ projectId: 'p', inventory: inventory([c]), clusterIds: [c.id], hosts: [host], options: {}, now });
    expect(result.plan.clusters).toEqual([]);
    expect(result.refused).toEqual([{ clusterId: c.id, reason: expect.stringMatching(/adopt/i) }]);
  });

  test('write-only adoption requires the provider reference-rotation capability', () => {
    const c = cluster({ adopted }); c.consumers[0]!.sealed = true;
    const adapter = getProvider(c.provider);
    const original = adapter.rotateByRef;
    try {
      adapter.rotateByRef = undefined;
      expect(adoptionNeeded(c)).toBe(true);
      expect(autopilotEligibility(c)).toMatchObject({ eligible: false, reason: expect.stringMatching(/adopt/i) });
    } finally { adapter.rotateByRef = original; }
  });

  test('write-only generated secrets require reference-rotation adoption too', () => {
    const c = cluster({ provider: 'app-secret', tier: 'app', method: 'generate', adopted: { ...adopted, keyRef: null } });
    c.consumers[0]!.sealed = true; c.consumers[0]!.varName = 'SESSION_SECRET';
    expect(adoptionNeeded(c)).toBe(true);
    expect(autopilotEligibility(c)).toMatchObject({ eligible: false, reason: expect.stringMatching(/adopt/i) });
  });
});

describe('build and sign armed plans', () => {
  test('builds the fixed format with defaults and reports every refused cluster', () => {
    const inv = inventory([cluster(), cluster({ id: 'stripe', provider: 'stripe', tier: 'payments', method: 'guided' })]);
    const { plan, refused } = buildArmedPlan({ projectId: 'project', inventory: inv, clusterIds: ['cluster-1', 'stripe', 'missing'], hosts: ['railway'], options: {}, now });
    expect(plan).toMatchObject({ v: 1, id: expect.stringMatching(/^arm-20261027-[a-f0-9]{8}$/), projectId: 'project', createdAt: now.toISOString(), expiresAt: '2027-01-25T12:00:00.000Z', maxServicesPerWave: 10, graceSeconds: 900, healthChecks: [], nextDeployAcceptance: [], quiet: {} });
    expect(plan.clusters).toEqual([{ clusterId: 'cluster-1', provider: 'openai', method: 'auto', consumers: [{ serviceKey: serviceKey(inv.clusters[0]!.consumers[0]!.service), varName: 'OPENAI_API_KEY', fingerprint: 'f'.repeat(32) }] }]);
    expect(refused).toEqual([{ clusterId: 'stripe', reason: 'Stripe keys are never rotated automatically.' }, { clusterId: 'missing', reason: expect.any(String) }]);
    expect(body().id).not.toBe(body().id);
  });

  test('copies adopted consumers, fingerprints and options without retaining input references', () => {
    const c = cluster({ adopted }); c.consumers[0]!.fingerprint = null; c.consumers[0]!.sealed = true;
    const options = { validDays: 2, graceSeconds: 30, maxServicesPerWave: 2, healthChecks: [{ serviceKey: 'railway:p/e/s', url: 'https://app.example/health', expectStatus: 204 }], nextDeployAcceptance: [{ host: 'github-actions' as const, maxHours: 24, revokeAfterMax: false }], quiet: { lowPriorityHours: { start: '22:00', end: '07:00', timeZone: 'Europe/Warsaw' } } };
    const result = buildArmedPlan({ projectId: 'p', inventory: inventory([c]), clusterIds: [c.id, c.id], hosts: ['railway'], options, now });
    expect(result.plan.expiresAt).toBe('2026-10-29T12:00:00.000Z');
    expect(result.plan.clusters).toHaveLength(1);
    expect(result.plan.clusters[0]).toMatchObject({ adopted, consumers: [{ fingerprint: null }] });
    options.healthChecks[0]!.url = 'http://changed'; c.consumers[0]!.varName = 'CHANGED';
    expect(result.plan.healthChecks[0]!.url).toBe('https://app.example/health');
    expect(result.plan.clusters[0]!.consumers[0]!.varName).toBe('OPENAI_API_KEY');
  });

  test.each([0, -1, 366, 1.5, Infinity, NaN])('rejects invalid validDays %s', validDays => {
    expect(() => body({ validDays })).toThrow();
  });

  test('signed plan verifies and binds its signer as well as all policy fields', () => {
    expect(ARMED_PLAN_PREFIX).toBe('keysentry-armed-plan:v1\n');
    const signed = signArmedPlan(body(), key);
    expect(verify(signed)).toEqual({ ok: true, plan: signed });
    const edits: ((p: ArmedPlan) => void)[] = [p => { p.graceSeconds++; }, p => { p.projectId = 'different'; }, p => { p.clusters[0]!.consumers[0]!.fingerprint = null; }, p => { p.quiet = { lowPriorityHours: { start: '01:00', end: '02:00', timeZone: 'UTC' } }; }];
    for (const edit of edits) { const changed = structuredClone(signed); edit(changed); expect(verify(changed)).toEqual({ ok: false, reason: expect.stringMatching(/signature/i) }); }
    const { sig, ...unsigned } = signed;
    const expected = signDetached(key.privateKeyDer, Buffer.from(ARMED_PLAN_PREFIX + canonicalJson(unsigned))).toString('base64');
    expect(sig).toBe(expected);
  });

  test('expired or tampered plan executes nothing', () => {
    let executions = 0;
    const signed = signArmedPlan(body(), key);
    for (const result of [verify(signed, new Date(signed.expiresAt)), verify({ ...signed, graceSeconds: 1 })]) {
      if (result.ok) executions++;
      expect(result).toMatchObject({ ok: false, reason: expect.any(String) });
    }
    expect(executions).toBe(0);
    expect(verify(signed, new Date(signed.expiresAt))).toMatchObject({ reason: expect.stringMatching(/expired/i) });
  });

  test('untrusted signer key and mismatched public-key IDs are rejected', () => {
    expect(verifyArmedPlan(signArmedPlan(body(), key), { now, trustedKeyIds: [] })).toMatchObject({ ok: false, reason: expect.stringMatching(/trusted/i) });
    const mismatch = signedMutation(p => { p.signer.keyId = '0'.repeat(16); });
    expect(verifyArmedPlan(mismatch, { now, trustedKeyIds: [mismatch.signer.keyId] })).toMatchObject({ ok: false, reason: expect.stringMatching(/key.*id/i) });
  });

  test('creation clock skew allows five minutes and rejects anything later', () => {
    const p = signArmedPlan(body(), key);
    expect(verify(p, new Date(now.getTime() - 300_000)).ok).toBe(true);
    expect(verify(p, new Date(now.getTime() - 300_001))).toMatchObject({ ok: false, reason: expect.stringMatching(/future/i) });
    expect(verify(p, new Date(NaN)).ok).toBe(false);
  });

  test.each([
    (p: ArmedPlan) => { Object.assign(p, { extra: true }); },
    (p: ArmedPlan) => { Object.assign(p.clusters[0]!, { extra: true }); },
    (p: ArmedPlan) => { Object.assign(p.clusters[0]!.consumers[0]!, { extra: true }); },
    (p: ArmedPlan) => { Object.assign(p.signer, { extra: true }); },
    (p: ArmedPlan) => { p.createdAt = 'October 27, 2026'; },
    (p: ArmedPlan) => { p.hosts = ['invalid' as HostId]; },
    (p: ArmedPlan) => { p.signer.publicKeyDer = 'not-base64'; },
    (p: ArmedPlan) => { p.clusters = Array.from({ length: 501 }, (_, i) => ({ ...p.clusters[0]!, clusterId: `c${i}` })); },
    (p: ArmedPlan) => { p.healthChecks = Array.from({ length: 51 }, () => ({ serviceKey: 's', url: 'https://app.example/health' })); },
    (p: ArmedPlan) => { p.maxServicesPerWave = 0; },
    (p: ArmedPlan) => { p.graceSeconds = -1; },
    (p: ArmedPlan) => { p.nextDeployAcceptance = [{ host: 'fly', maxHours: 0, revokeAfterMax: false }]; },
    (p: ArmedPlan) => { p.quiet = { lowPriorityHours: { start: '25:00', end: '01:00', timeZone: 'UTC' } }; },
    (p: ArmedPlan) => { p.quiet = { lowPriorityHours: { start: '23:00', end: '01:00', timeZone: 'No/Such_Zone' } }; },
    (p: ArmedPlan) => { p.expiresAt = p.createdAt; },
    (p: ArmedPlan) => { p.clusters.push(structuredClone(p.clusters[0]!)); },
    (p: ArmedPlan) => { p.clusters[0]!.consumers.push(structuredClone(p.clusters[0]!.consumers[0]!)); },
    (p: ArmedPlan) => { p.clusters[0]!.adopted = { ...adopted, extra: true } as typeof adopted; },
    (p: ArmedPlan) => { p.healthChecks = [{ serviceKey: 's', url: 'https://app.example/health', extra: true } as ArmedPlan['healthChecks'][number]]; },
    (p: ArmedPlan) => { p.nextDeployAcceptance = [{ host: 'fly', maxHours: 1, revokeAfterMax: false, extra: true } as ArmedPlan['nextDeployAcceptance'][number]]; },
    (p: ArmedPlan) => { Object.assign(p.quiet, { extra: true }); },
    (p: ArmedPlan) => { p.quiet = { lowPriorityHours: { start: '01:00', end: '02:00', timeZone: 'UTC', extra: true } as NonNullable<ArmedPlan['quiet']['lowPriorityHours']> }; },
  ])('strict schema rejects malformed or unknown fields (%#)', edit => {
    expect(verify(signedMutation(edit))).toEqual({ ok: false, reason: 'Armed plan format is invalid.' });
  });

  test('malformed base64 signatures fail format validation', () => {
    const p = signArmedPlan(body(), key); p.sig = 'not-base64';
    expect(verify(p)).toEqual({ ok: false, reason: 'Armed plan format is invalid.' });
  });

  test.each(['http://app.example/health', 'https://user:pass@app.example/health', 'https://@app.example/health', 'https://app.example:8443/health', 'https://127.0.0.1/health', 'https://[::1]/health', 'https://0x7f000001/health', 'https://2130706433/health'])('rejects unsafe health-check URL %s', url => {
    expect(verify(signedMutation(p => { p.healthChecks = [{ serviceKey: 's', url }]; })).ok).toBe(false);
    expect(() => body({ healthChecks: [{ serviceKey: 's', url }] })).toThrow();
  });

  test('accepts the 500-cluster and 50-health-check limits', () => {
    const p = signedMutation(p => {
      p.clusters = Array.from({ length: 500 }, (_, i) => ({ ...p.clusters[0]!, clusterId: `c${i}` }));
      p.healthChecks = Array.from({ length: 50 }, (_, i) => ({ serviceKey: `s${i}`, url: `https://app.example/health/${i}` }));
    });
    expect(verify(p).ok).toBe(true);
    expect(verify(signArmedPlan(body({ validDays: 365 }), key)).ok).toBe(true);
  });

  test('rejects malformed DER and non-Ed25519 keys without exposing input', () => {
    const invalid = signedMutation(p => { p.signer.publicKeyDer = Buffer.from('malformed private input').toString('base64'); p.signer.keyId = createHash('sha256').update(Buffer.from(p.signer.publicKeyDer, 'base64')).digest('hex').slice(0, 16); });
    expect(verifyArmedPlan(invalid, { now, trustedKeyIds: [invalid.signer.keyId] })).toEqual({ ok: false, reason: expect.stringMatching(/signature/i) });
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const p = signArmedPlan(body(), key); p.signer.publicKeyDer = rsa.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'); p.signer.keyId = createHash('sha256').update(Buffer.from(p.signer.publicKeyDer, 'base64')).digest('hex').slice(0, 16);
    const { sig: _, ...unsigned } = p; p.sig = sign('sha256', Buffer.from(ARMED_PLAN_PREFIX + canonicalJson(unsigned)), rsa.privateKey).toString('base64');
    expect(verifyArmedPlan(p, { now, trustedKeyIds: [p.signer.keyId] }).ok).toBe(false);
  });
});
