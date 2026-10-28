import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateKeyPairSync, type JsonWebKey } from 'node:crypto';
import { request as rawRequest } from 'node:http';
import { challengeNonce, verifyAttestation } from '../../../src/box/attestation/index.js';
import { exchangeForAccessToken, kmsDecrypt, kmsEncrypt } from '../../../src/box/seal/index.js';
import { startEmulator, type Emulator } from '../src/emulator/index.js';
import type { AttestationPolicy } from '../../../src/types.js';
import { createProvisioner } from '../src/provision.js';

const now = Date.parse('2026-10-27T12:00:00.000Z');
let emulator: Emulator;
const nonces = [Buffer.alloc(32, 1).toString('base64url'), Buffer.alloc(32, 2).toString('base64url')];
const audience = 'keysentry-test-session';
const deviceKey = generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
/** Exactly what the provisioner sends for a box, so each test changes one property. */
function instance(local: Emulator, name: string, change: (body: Record<string, any>) => void = () => undefined) {
  const body: Record<string, any> = {
    name, machineType: 'zones/us-central1-a/machineTypes/c3-standard-4',
    confidentialInstanceConfig: { enableConfidentialCompute: true, confidentialInstanceType: 'TDX' },
    shieldedInstanceConfig: { enableSecureBoot: true }, scheduling: { onHostMaintenance: 'TERMINATE', automaticRestart: true },
    disks: [{ boot: true, autoDelete: true, initializeParams: { sourceImage: 'projects/confidential-space-images/global/images/family/confidential-space',
      diskType: 'zones/us-central1-a/diskTypes/pd-balanced', diskSizeGb: '20' } }],
    networkInterfaces: [{ subnetwork: `projects/${local.policy.projectId}/regions/us-central1/subnetworks/box-subnet` }],
    serviceAccounts: [{ email: local.policy.serviceAccount, scopes: ['https://www.googleapis.com/auth/cloud-platform'] }],
    metadata: { items: [
      { key: 'tee-image-reference', value: `registry.invalid/box@${local.policy.allowedDigests[0]}` }, { key: 'tee-restart-policy', value: 'Always' },
      { key: 'keysentry-box-id', value: name }, { key: 'keysentry-relay-origin', value: 'https://control.example' },
      { key: 'keysentry-enroll-device-key', value: deviceKey },
    ] },
  };
  change(body);
  return body;
}
/** A raw loopback request with no emulator caller secret, as a web page or another local user would send. */
function raw(url: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = rawRequest(url, { method: init.method ?? 'GET', headers: init.headers, agent: false }, res => { res.resume(); res.on('end', () => resolve(res.statusCode!)); });
    req.on('error', reject); req.end(init.body);
  });
}
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
    const body = instance(local, 'box-one');
    const response = await local.http.request({ method: 'POST', url, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    expect(response.status).toBe(200);
    expect(response.json<{status: string}>().status).toBe('DONE');
    expect(started).toEqual({ projectId: local.policy.projectId, zone: 'us-central1-a', instanceName: 'box-one', instance: body });
    expect((await local.http.request({ method: 'POST', url, headers: { 'content-type': 'application/json' },
      body: JSON.stringify(instance(local, 'a')) })).status).toBe(200);
    const refused = await local.http.request({ method: 'POST', url, headers: { 'content-type': 'application/json' },
      body: JSON.stringify(instance(local, 'box-two', b => { b.metadata.items.push({ key: 'tee-env-SECRET', value: 'planted-token-value' }); })) });
    expect(refused.status).toBe(400);
    expect(refused.text).not.toContain('planted-token-value');
  } finally { await local.close(); }
});

it.each([
  ['the debug image', (b: Record<string, any>) => { b.disks[0].initializeParams.sourceImage = 'projects/confidential-space-images/global/images/family/confidential-space-debug'; }],
  ['an external IP', (b: Record<string, any>) => { b.networkInterfaces[0].accessConfigs = [{ type: 'ONE_TO_ONE_NAT' }]; }],
  ['no TDX', (b: Record<string, any>) => { delete b.confidentialInstanceConfig; }],
  ['SEV on a C3 machine', (b: Record<string, any>) => { b.confidentialInstanceConfig.confidentialInstanceType = 'SEV'; }],
  ['no secure boot', (b: Record<string, any>) => { b.shieldedInstanceConfig.enableSecureBoot = false; }],
  ['live migration', (b: Record<string, any>) => { b.scheduling.onHostMaintenance = 'MIGRATE'; }],
  ['another service account', (b: Record<string, any>) => { b.serviceAccounts[0].email = 'other@keysentry-box.iam.gserviceaccount.com'; }],
  ['a box id that is not the instance', (b: Record<string, any>) => { b.metadata.items[2].value = 'other-box'; }],
  ['a missing routing attribute', (b: Record<string, any>) => { b.metadata.items.pop(); }],
  ['an unsigned image tag', (b: Record<string, any>) => { b.metadata.items[0].value = 'registry.invalid/box:latest'; }],
  ['a bad enrollment key', (b: Record<string, any>) => { b.metadata.items[4].value = Buffer.alloc(44).toString('base64'); }],
  ['a plain-HTTP public relay', (b: Record<string, any>) => { b.metadata.items[3].value = 'http://control.example'; }],
])('L6: Compute refuses an instance Confidential Space would not run as a box: %s', async (_name, change) => {
  let starts = 0;
  const local = await startEmulator({ now: () => now, startBox: () => { starts++; } });
  try {
    const url = `${local.computeOrigin}/compute/v1/projects/${local.policy.projectId}/zones/us-central1-a/instances`;
    const response = await local.http.request({ method: 'POST', url, headers: { 'content-type': 'application/json' }, body: JSON.stringify(instance(local, 'box-one', change)) });
    expect(response.status).toBe(400);
    expect(starts).toBe(0);
  } finally { await local.close(); }
});

describe('L6: the emulator listener is not a local token mint', () => {
  it('refuses token, STS, KMS and Compute calls without the per-start secret, but serves public anchors', async () => {
    const local = await startEmulator({ now: () => now });
    try {
      const jsonPost = (path: string, body: unknown) => raw(`${local.baseUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
      expect(await raw(`${local.baseUrl}/v1/token`)).toBe(403);
      expect(await jsonPost('/v1/token', { audience, nonces, token_type: 'OIDC' })).toBe(403);
      expect(await jsonPost('/v1/sts/token', {})).toBe(403);
      expect(await jsonPost(`/v1/${local.keyName}:encrypt`, {})).toBe(403);
      expect(await jsonPost(`/compute/v1/projects/${local.policy.projectId}/zones/us-central1-a/instances`, instance(local, 'box-one'))).toBe(403);
      expect(await raw(`${local.baseUrl}/v1/token`, { headers: { 'x-keysentry-emulator-token': 'guessed-value' } })).toBe(403);
      expect(await raw(`${local.baseUrl}/jwks`)).toBe(200);
      expect(await raw(`${local.baseUrl}/health`)).toBe(200);
      expect((await local.http.request({ method: 'GET', url: `${local.baseUrl}/v1/token` })).status).toBe(200);
    } finally { await local.close(); }
  });
  it('refuses a rebinding Host header on every route', async () => {
    const local = await startEmulator({ now: () => now });
    try {
      const port = new URL(local.baseUrl).port;
      for (const host of [`localhost:${port}`, `attacker.example:${port}`, '127.0.0.1']) {
        expect(await raw(`${local.baseUrl}/jwks`, { headers: { host } })).toBe(403);
      }
    } finally { await local.close(); }
  });
  it('names the booted instance in its tokens when asked', async () => {
    const token = emulator.mintToken({ audience, nonces, instanceName: 'box-one' });
    const claims = JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString('utf8'));
    expect(claims.submods.gce.instance_name).toBe('box-one');
    expect(claims.sub).toMatch(/\/instances\/box-one$/);
    expect(() => emulator.mintToken({ audience, nonces, instanceName: 'Bad_Name' })).toThrow();
  });
});

it('provisions Terraform-shaped settings through the real provisioner into the injected box', async () => {
  let started: Record<string, unknown> | undefined;
  const local = await startEmulator({ startBox: config => { started = config.instance; } });
  try {
    const provisioner = createProvisioner({ http: local.http, emulatorOrigin: local.computeOrigin, relayOrigin: 'https://control.example',
      projectId: local.policy.projectId, zone: 'us-central1-a',
      subnetwork: `projects/${local.policy.projectId}/regions/us-central1/subnetworks/box-subnet`,
      serviceAccount: local.policy.serviceAccount, imageReference: `registry.invalid/box@${local.policy.allowedDigests[0]}`,
      allowedDigests: local.policy.allowedDigests });
    const result = await provisioner.provision({ name: 'keysentry-box', deviceKey });
    expect(result.status).toBe('DONE');
    expect(started?.machineType).toBe('zones/us-central1-a/machineTypes/c3-standard-4');
    expect(started?.confidentialInstanceConfig).toEqual({ enableConfidentialCompute: true, confidentialInstanceType: 'TDX' });
    expect(started?.networkInterfaces).toEqual([{ subnetwork: `projects/${local.policy.projectId}/regions/us-central1/subnetworks/box-subnet` }]);
  } finally { await local.close(); }
});

it('models instances.get, stop and start for the instances it created, with no request body', async () => {
  const local = await startEmulator({ now: () => now });
  try {
    const base = `${local.computeOrigin}/compute/v1/projects/${local.policy.projectId}/zones/us-central1-a/instances`;
    const get = async (name: string) => local.http.request({ method: 'GET', url: `${base}/${name}` });
    expect((await get('box-one')).status).toBe(404);
    const body = instance(local, 'box-one');
    expect((await local.http.request({ method: 'POST', url: base, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).status).toBe(200);
    expect((await get('box-one')).json()).toMatchObject({ name: 'box-one', status: 'RUNNING', metadata: body.metadata });
    const stopped = await local.http.request({ method: 'POST', url: `${base}/box-one/stop` });
    expect(stopped.json()).toMatchObject({ status: 'DONE', operationType: 'stop' });
    expect((await get('box-one')).json<{ status: string }>().status).toBe('TERMINATED');
    expect((await local.http.request({ method: 'POST', url: `${base}/box-one/start` })).json()).toMatchObject({ operationType: 'start' });
    expect((await get('box-one')).json<{ status: string }>().status).toBe('RUNNING');
    expect((await local.http.request({ method: 'POST', url: `${base}/box-one/stop`, headers: { 'content-type': 'application/json' }, body: '{}' })).status).toBe(400);
    expect((await local.http.request({ method: 'GET', url: `${base}/box-one/stop` })).status).toBe(405);
    expect((await local.http.request({ method: 'POST', url: `${base}/box-two/stop` })).status).toBe(404);
    expect((await local.http.request({ method: 'GET', url: `${local.computeOrigin}/compute/v1/projects/other-project/zones/us-central1-a/instances/box-one` })).status).toBe(404);
    expect(await raw(`${base}/box-one`)).toBe(403);
    expect((await get('box-one')).json<{ status: string }>().status).toBe('RUNNING');
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
      headers: { 'content-type': 'application/json' }, body: JSON.stringify(instance(local, name)) });
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
