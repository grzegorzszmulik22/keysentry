import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { JsonWebKey } from 'node:crypto';
import { challengeNonce, verifyAttestation } from '../../../src/box/attestation/index.js';
import { exchangeForAccessToken, kmsDecrypt, kmsEncrypt } from '../../../src/box/seal/index.js';
import { startEmulator, type Emulator } from '../src/emulator/index.js';
import type { AttestationPolicy } from '../../../src/types.js';
import { createProvisioner } from '../src/provision.js';

const now = Date.parse('2026-10-27T12:00:00.000Z');
let emulator: Emulator;
const nonces = [Buffer.alloc(32, 1).toString('base64url'), Buffer.alloc(32, 2).toString('base64url')];
const audience = 'keysentry-test-session';
function policy(): AttestationPolicy {
  return { audience, projectIds: [emulator.policy.projectId], serviceAccounts: [emulator.policy.serviceAccount],
    allowedDigests: [...emulator.policy.allowedDigests], hardwareModels: ['GCP_INTEL_TDX'], maxTokenAgeSeconds: 300, clockSkewSeconds: 60 };
}
async function verifyToken(token: string, expectedNonces = nonces, pki = false) {
  return verifyAttestation({ token, jwks: async () => emulator.jwks, policy: policy(), expectedNonces,
    now: new Date(now), ...(pki ? { root: emulator.root } : {}) });
}

beforeAll(async () => { emulator = await startEmulator({ now: () => now }); });
afterAll(async () => { await emulator?.close(); });

describe('local attestation service', () => {
  it('issues OIDC tokens verified by the real verifier using its served JWKS', async () => {
    const response = await emulator.http.request({ method: 'GET', url: emulator.endpoints.jwks });
    expect(response.status).toBe(200);
    const token = emulator.mintToken({ audience, nonces });
    const result = await verifyAttestation({ token, jwks: async () => response.json<{keys: JsonWebKey[]}>().keys,
      policy: policy(), expectedNonces: nonces, now: new Date(now) });
    expect(result.checks.filter(check => !check.ok)).toEqual([]);
    expect(result.ok).toBe(true);
  });
  it('issues PKI tokens verified against its independent local root', async () => {
    const token = emulator.mintToken({ audience, nonces, tokenType: 'PKI' });
    expect((await verifyToken(token, nonces, true)).ok).toBe(true);
    expect((await verifyToken(token)).ok).toBe(false);
  });
  it.each([
    ['debugImage', 'debug'], ['otherProject', 'project'], ['otherServiceAccount', 'service-account'],
    ['missingStable', 'support-stable'], ['wrongDigest', 'image-digest'], ['staleIat', 'time'],
  ] as const)('rejects %s tokens through the real verifier', async (flag, failedCheck) => {
    const token = emulator.mintToken({ audience, nonces, switches: { [flag]: true } });
    const result = await verifyToken(token);
    expect(result.ok).toBe(false);
    expect(result.checks.find(check => check.name === failedCheck)?.ok).toBe(false);
  });
  it('replays the previous token and fails the fresh session nonce check', async () => {
    const old = emulator.mintToken({ audience, nonces });
    const fresh = [nonces[0]!, challengeNonce()];
    const replay = emulator.mintToken({ audience, nonces: fresh, switches: { replay: true } });
    expect(replay).toBe(old);
    const result = await verifyToken(replay, fresh);
    expect(result.ok).toBe(false);
    expect(result.checks.find(check => check.name === 'nonce-challenge')?.ok).toBe(false);
  });
  it('serves the launcher token API and rejects unknown fields and oversized nonces', async () => {
    const request = (body: unknown) => emulator.http.request({ method: 'POST', url: emulator.endpoints.attestation,
      headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const valid = await request({ audience, nonces, token_type: 'OIDC' });
    expect(valid.status).toBe(200);
    expect((await verifyToken(valid.text)).ok).toBe(true);
    expect((await request({ audience, nonces, token_type: 'OIDC', token_type_options: {} })).status).toBe(400);
    expect((await request({ audience, nonces: ['x'.repeat(75)], token_type: 'OIDC' })).status).toBe(400);
  });
});

describe('STS and KMS release policy', () => {
  it('wraps and unwraps a data key using the real STS and KMS clients', async () => {
    const token = emulator.mintToken({ audience: 'https://sts.googleapis.com', nonces: [] });
    const accessToken = await exchangeForAccessToken(emulator.http, { audience: emulator.audience, subjectToken: token });
    const key = Buffer.alloc(32, 37), aad = Buffer.from('keysentry-box-dek:v1:box-a');
    const wrapped = await kmsEncrypt(emulator.http, accessToken, emulator.keyName, key, aad);
    expect(wrapped.includes(key)).toBe(false);
    expect(await kmsDecrypt(emulator.http, accessToken, emulator.keyName, wrapped, aad)).toEqual(key);
    await expect(kmsDecrypt(emulator.http, accessToken, emulator.keyName, wrapped, Buffer.from('other-box'))).rejects.toThrow('KMS refused');
  });
  it.each(['debugImage', 'otherProject', 'otherServiceAccount', 'missingStable', 'wrongDigest', 'staleIat'] as const)(
    'refuses release for %s', async flag => {
      const token = emulator.mintToken({ audience: 'https://sts.googleapis.com', nonces: [], switches: { [flag]: true } });
      await expect(exchangeForAccessToken(emulator.http, { audience: emulator.audience, subjectToken: token })).rejects.toThrow('STS refused');
    });
  it('rejects the wrong workload audience and unissued bearer tokens', async () => {
    const token = emulator.mintToken({ audience: 'https://sts.googleapis.com', nonces: [] });
    await expect(exchangeForAccessToken(emulator.http, { audience: emulator.audience.replace('/providers/box-provider', '/providers/other'), subjectToken: token })).rejects.toThrow('STS refused');
    await expect(kmsEncrypt(emulator.http, 'unissued', emulator.keyName, Buffer.alloc(32), Buffer.alloc(0))).rejects.toThrow('KMS refused');
  });
  it('rechecks the current digest policy at KMS after STS exchange', async () => {
    const token = emulator.mintToken({ audience: 'https://sts.googleapis.com', nonces: [] });
    const access = await exchangeForAccessToken(emulator.http, { audience: emulator.audience, subjectToken: token });
    const saved = [...emulator.policy.allowedDigests];
    emulator.updateReleasePolicy({ allowedDigests: [`sha256:${'c'.repeat(64)}`] });
    try { await expect(kmsEncrypt(emulator.http, access, emulator.keyName, Buffer.alloc(32), Buffer.alloc(0))).rejects.toThrow('KMS refused'); }
    finally { emulator.updateReleasePolicy({ allowedDigests: saved }); }
  });
  it.each([
    { projectId: 'other-project' }, { serviceAccount: 'box@other-project.iam.gserviceaccount.com' },
  ])('rechecks the current identity policy at KMS after STS exchange: %j', async change => {
    const token = emulator.mintToken({ audience: 'https://sts.googleapis.com', nonces: [] });
    const access = await exchangeForAccessToken(emulator.http, { audience: emulator.audience, subjectToken: token });
    const saved = emulator.policy;
    emulator.updateReleasePolicy(change);
    try { await expect(kmsEncrypt(emulator.http, access, emulator.keyName, Buffer.alloc(32), Buffer.alloc(0))).rejects.toThrow('KMS refused'); }
    finally { emulator.updateReleasePolicy(saved); }
  });
  it('refuses a forged subject token before issuing an access token', async () => {
    const token = emulator.mintToken({ audience: 'https://sts.googleapis.com', nonces: [] });
    const [head, payload, signature] = token.split('.');
    const forged = `${head}.${payload}.${signature!.slice(0, -1)}${signature!.endsWith('A') ? 'B' : 'A'}`;
    await expect(exchangeForAccessToken(emulator.http, { audience: emulator.audience, subjectToken: forged })).rejects.toThrow('STS refused');
  });
  it('refuses outbound destinations outside the local emulator', async () => {
    await expect(emulator.http.request({ method: 'GET', url: 'https://example.com' })).rejects.toThrow('Emulator destination is not supported');
    await expect(emulator.http.request({ method: 'GET', url: `${emulator.baseUrl.replace('127.0.0.1', 'localhost')}/health` })).rejects.toThrow();
  });
});

it('expires issued KMS access when its attestation expires', async () => {
  let clock = now;
  const local = await startEmulator({ now: () => clock });
  try {
    const token = local.mintToken({ audience: 'https://sts.googleapis.com', nonces: [] });
    const access = await exchangeForAccessToken(local.http, { audience: local.audience, subjectToken: token });
    clock += 3_600_001;
    await expect(kmsEncrypt(local.http, access, local.keyName, Buffer.alloc(32), Buffer.alloc(0))).rejects.toThrow('KMS refused');
  } finally { await local.close(); }
});

it('Compute boots only an injected in-process box and rejects unsafe metadata', async () => {
  let started: unknown;
  const local = await startEmulator({ now: () => now, startBox: config => { started = config; } });
  try {
    const url = `${local.computeOrigin}/compute/v1/projects/${local.policy.projectId}/zones/us-central1-a/instances`;
    const instance = { name: 'box-one', metadata: { items: [{ key: 'tee-image-reference', value: `registry/box@${local.policy.allowedDigests[0]}` }] } };
    const response = await local.http.request({ method: 'POST', url, headers: { 'content-type': 'application/json' }, body: JSON.stringify(instance) });
    expect(response.status).toBe(200);
    expect(response.json<{status: string}>().status).toBe('DONE');
    expect(started).toEqual({ projectId: local.policy.projectId, zone: 'us-central1-a', instanceName: 'box-one', instance });
    expect((await local.http.request({ method: 'POST', url, headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...instance, name: 'a' }) })).status).toBe(200);
    const refused = await local.http.request({ method: 'POST', url, headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'box-two', metadata: { items: [{ key: 'tee-env-SECRET', value: 'planted-token-value' }] } }) });
    expect(refused.status).toBe(400);
    expect(refused.text).not.toContain('planted-token-value');
  } finally { await local.close(); }
});

it('provisions Terraform-shaped settings through the real provisioner into the injected box', async () => {
  let started: Record<string, unknown> | undefined;
  const local = await startEmulator({ startBox: config => { started = config.instance; } });
  try {
    const provisioner = createProvisioner({ http: local.http, emulatorOrigin: local.computeOrigin,
      projectId: local.policy.projectId, zone: 'us-central1-a',
      subnetwork: `projects/${local.policy.projectId}/regions/us-central1/subnetworks/box-subnet`,
      serviceAccount: local.policy.serviceAccount, imageReference: `registry.invalid/box@${local.policy.allowedDigests[0]}`,
      allowedDigests: local.policy.allowedDigests });
    const result = await provisioner.provision({ name: 'keysentry-box' });
    expect(result.status).toBe('DONE');
    expect(started?.machineType).toBe('zones/us-central1-a/machineTypes/c3-standard-4');
    expect(started?.confidentialInstanceConfig).toEqual({ enableConfidentialCompute: true, confidentialInstanceType: 'TDX' });
    expect(started?.networkInterfaces).toEqual([{ subnetwork: `projects/${local.policy.projectId}/regions/us-central1/subnetworks/box-subnet` }]);
  } finally { await local.close(); }
});

it('boots a concurrently requested instance name once and permits retry after a failed boot', async () => {
  let starts = 0, failBoot = false;
  const local = await startEmulator({ startBox: async () => {
    starts++;
    await new Promise(resolve => setTimeout(resolve, 30));
    if (failBoot) throw new Error('not available');
  } });
  try {
    const post = (name: string) => local.http.request({ method: 'POST',
      url: `${local.computeOrigin}/compute/v1/projects/${local.policy.projectId}/zones/us-central1-a/instances`,
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name }) });
    const responses = await Promise.all([post('same-box'), post('same-box')]);
    expect(responses.map(response => response.status).sort()).toEqual([200, 409]);
    expect(starts).toBe(1);
    failBoot = true;
    expect((await post('retry-box')).status).toBe(400);
    failBoot = false;
    expect((await post('retry-box')).status).toBe(200);
    expect(starts).toBe(3);
  } finally { await local.close(); }
});
