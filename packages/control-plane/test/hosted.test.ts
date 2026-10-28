import { createHash, createHmac, generateKeyPairSync, randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { request } from 'node:http';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { encode } from '../../../test/approvals/webauthn/helpers.js';
import { json, text } from '../../../test/helpers/fake-http.js';
import type { HttpClient, HttpRequest } from '../../../src/types.js';
import { createHostedHttp, createMetadataHttp, createSecretManagerHttp, DestinationRefusedError, METADATA_TOKEN_URL } from '../src/egress.js';
import { HostedStartError, startHosted, stopOnSignals, type HostedLogEntry } from '../src/entry.js';
import { createHostedControlPlane, HOSTED_SETTINGS, hostedConfigFromEnv } from '../src/hosted.js';
import { crc32c, readSecret } from '../src/secrets.js';
import { createMemoryStorage } from '../src/storage.js';

const ORIGIN = 'https://control.example';
const WEBHOOK_REF = 'projects/keysentry-control/secrets/stripe-webhook/versions/latest';
const API_KEY_REF = 'projects/keysentry-control/secrets/stripe-api-key/versions/3';
const WEBHOOK_SECRET = 'whsec_planted0secret0value';
const API_KEY = 'rk_live_planted0api0key0value';
const DIGEST_A = `sha256:${'a'.repeat(64)}`;
const env: Record<string, string> = {
  KEYSENTRY_CONTROL_ORIGIN: ORIGIN, PORT: '0', KEYSENTRY_CONTROL_BUCKET: 'ks-control-state', KEYSENTRY_STRIPE_PRICE_ID: 'price_plan',
  KEYSENTRY_BOX_PROJECT_ID: 'keysentry-box', KEYSENTRY_BOX_SERVICE_ACCOUNT: 'keysentry-box@keysentry-box.iam.gserviceaccount.com',
  KEYSENTRY_BOX_ALLOWED_DIGESTS: `${DIGEST_A},sha256:${'b'.repeat(64)}`,
  KEYSENTRY_STRIPE_WEBHOOK_SECRET_REF: WEBHOOK_REF, KEYSENTRY_STRIPE_API_KEY_REF: API_KEY_REF,
};
const live = {
  KEYSENTRY_CONTROL_PLANE_LIVE: '1', KEYSENTRY_BOX_ZONE: 'us-central1-a',
  KEYSENTRY_BOX_SUBNETWORK: 'projects/keysentry-box/regions/us-central1/subnetworks/keysentry-box-subnet',
  KEYSENTRY_BOX_IMAGE_REFERENCE: `us-docker.pkg.dev/keysentry-box/box/keysentry@${DIGEST_A}`,
};
const deviceKey = generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64');

function secretReply(value: string, crc: unknown = String(crc32c(Buffer.from(value)))) {
  return json(200, { name: 'projects/123/secrets/x/versions/7', payload: { data: Buffer.from(value).toString('base64'), ...(crc === undefined ? {} : { dataCrc32c: crc }) } });
}

/** The Google and Stripe endpoints the hosted process uses, in memory, recording every request. */
function cloud(options: { secrets?: Record<string, ReturnType<typeof json>> } = {}) {
  const objects = new Map<string, string>();
  const calls: HttpRequest[] = [];
  const transport: HttpClient = { async request(req) {
    calls.push(req);
    const url = new URL(req.url);
    if (req.url === METADATA_TOKEN_URL) return json(200, { access_token: 'ya29.hosted', expires_in: 3600, token_type: 'Bearer' }, { 'metadata-flavor': 'Google' });
    if (req.headers?.authorization !== 'Bearer ya29.hosted' && url.origin !== 'https://api.stripe.com') return json(403, {});
    if (url.origin === 'https://secretmanager.googleapis.com') {
      const ref = url.pathname.slice('/v1/'.length, -':access'.length);
      return options.secrets?.[ref] ?? (ref === WEBHOOK_REF ? secretReply(`${WEBHOOK_SECRET}\n`) : ref === API_KEY_REF ? secretReply(API_KEY) : json(404, {}));
    }
    if (url.origin === 'https://compute.googleapis.com') return json(200, { name: 'operation-1', status: 'PENDING' });
    if (url.origin === 'https://api.stripe.com') return json(500, {});
    if (req.method === 'POST' && url.pathname === '/upload/storage/v1/b/ks-control-state/o') { objects.set(url.searchParams.get('name')!, req.body!); return json(200, {}); }
    const object = /^\/storage\/v1\/b\/ks-control-state\/o\/([^/]+)$/.exec(url.pathname);
    if (object && req.method === 'GET') { const name = decodeURIComponent(object[1]!); return objects.has(name) ? text(200, objects.get(name)!) : json(404, {}); }
    if (object && req.method === 'DELETE') return objects.delete(decodeURIComponent(object[1]!)) ? text(204, '') : json(404, {});
    if (req.method === 'GET' && url.pathname === '/storage/v1/b/ks-control-state/o') {
      return json(200, { items: [...objects.keys()].filter(name => name.startsWith(url.searchParams.get('prefix') ?? '')).map(name => ({ name })) });
    }
    return json(599, {});
  } };
  return { transport, calls, objects, origins: () => [...new Set(calls.map(call => new URL(call.url).origin))].sort() };
}
function call(port: number, path: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}) {
  return new Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }>((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method: init.method ?? 'GET', agent: false, headers: { Host: 'control.example', ...init.headers } }, res => {
      let body = ''; res.on('data', chunk => { body += chunk; }); res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body }));
    });
    req.on('error', reject); req.end(init.body);
  });
}
/** A software passkey's registration (UP+UV, `none` attestation) for the hosted origin. */
function passkey() {
  const { publicKey } = generateKeyPairSync('ed25519');
  const credentialId = randomBytes(16);
  const cose = encode(new Map<number, unknown>([[1, 1], [3, -8], [-1, 6], [-2, Buffer.from(publicKey.export({ format: 'jwk' }).x!, 'base64url')]]));
  return (challenge: string) => {
    const length = Buffer.alloc(2); length.writeUInt16BE(credentialId.length);
    const authData = Buffer.concat([createHash('sha256').update('control.example').digest(), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), length, credentialId, cose]);
    return { clientDataJSON: Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin: ORIGIN })).toString('base64url'),
      attestationObject: encode(new Map<string, unknown>([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]])).toString('base64url') };
  };
}
async function signUp(port: number) {
  const browser = { Origin: ORIGIN, 'Content-Type': 'application/json' };
  const challenge = JSON.parse((await call(port, '/auth/register/challenge', { method: 'POST', headers: browser, body: '{}' })).body) as { id: string; challenge: string };
  const registered = await call(port, '/auth/register/finish', { method: 'POST', headers: browser, body: JSON.stringify({ challengeId: challenge.id, ...passkey()(challenge.challenge) }) });
  expect(registered.status).toBe(200);
  const { account, csrf } = JSON.parse(registered.body) as { account: { id: string }; csrf: string };
  return { cookie: String(registered.headers['set-cookie']).split(';')[0]!, csrf, accountId: account.id, page: { ...browser, Cookie: String(registered.headers['set-cookie']).split(';')[0]!, 'X-CSRF-Token': csrf } };
}
function refusal(fn: () => unknown): Error | null { try { fn(); } catch (error) { return error as Error; } return null; }

const stops: (() => Promise<unknown>)[] = [];
afterEach(async () => { await Promise.all(stops.splice(0).map(stop => stop().catch(() => undefined))); vi.unstubAllEnvs(); });

describe('hosted configuration', () => {
  it('reads the Terraform environment: settings and Secret Manager references, no secret values', () => {
    expect(hostedConfigFromEnv(env)).toEqual({ origin: ORIGIN, port: 0, bucket: 'ks-control-state', priceId: 'price_plan', boxProjectId: 'keysentry-box',
      boxServiceAccount: 'keysentry-box@keysentry-box.iam.gserviceaccount.com', allowedDigests: [DIGEST_A, `sha256:${'b'.repeat(64)}`],
      trustedProxyHops: 1, boxQuota: 1, secretRefs: { stripeWebhookSecret: WEBHOOK_REF, stripeApiKey: API_KEY_REF }, live: null });
    expect(hostedConfigFromEnv({ ...env, PORT: undefined }).port).toBe(8080);
  });
  it.each([
    ['KEYSENTRY_CONTROL_ORIGIN', 'http://control.example'], ['KEYSENTRY_CONTROL_ORIGIN', 'https://control.example/'], ['KEYSENTRY_CONTROL_ORIGIN', 'https://control.example:8443'],
    ['KEYSENTRY_CONTROL_ORIGIN', undefined], ['KEYSENTRY_CONTROL_BUCKET', 'Planted_Bucket'], ['KEYSENTRY_STRIPE_PRICE_ID', 'prod_planted'],
    ['KEYSENTRY_BOX_ALLOWED_DIGESTS', 'latest'], ['KEYSENTRY_BOX_PROJECT_ID', 'x'], ['KEYSENTRY_BOX_SERVICE_ACCOUNT', 'planted@gmail.com'],
    ['KEYSENTRY_TRUSTED_PROXY_HOPS', '0'], ['KEYSENTRY_TRUSTED_PROXY_HOPS', '11'], ['KEYSENTRY_BOX_QUOTA', '-1'], ['PORT', '70000'],
    ['KEYSENTRY_STRIPE_WEBHOOK_SECRET_REF', 'whsec_planted0value'], ['KEYSENTRY_STRIPE_WEBHOOK_SECRET_REF', 'projects/keysentry-control/secrets/planted'],
    ['KEYSENTRY_STRIPE_API_KEY_REF', undefined], ['KEYSENTRY_STRIPE_API_KEY_REF', 'projects/keysentry-control/secrets/planted/versions/0'],
    ['KEYSENTRY_CONTROL_PLANE_LIVE', 'true'],
  ])('names a missing or invalid %s without echoing its value', (name, value) => {
    const error = refusal(() => hostedConfigFromEnv({ ...env, [name]: value }));
    expect(error?.message).toBe(`${name} is missing or invalid.`);
    expect(error).toMatchObject({ setting: name });
    expect(error?.message).not.toContain('planted');
  });
  it.each(['KEYSENTRY_STRIPE_WEBHOOK_SECRET', 'KEYSENTRY_STRIPE_API_KEY'])('refuses a plaintext %s in the environment', name => {
    const error = refusal(() => hostedConfigFromEnv({ ...env, [name]: 'planted0value' }));
    expect(error?.message).toBe(`${name} must not be set. Give ${name}_REF, a Secret Manager reference, instead.`);
    expect(error?.message).not.toContain('planted');
  });
  it('reads live provisioning only with KEYSENTRY_CONTROL_PLANE_LIVE=1 and checks it against the box settings', () => {
    expect(hostedConfigFromEnv({ ...env, ...live, KEYSENTRY_CONTROL_PLANE_LIVE: '0' }).live).toBeNull();
    expect(hostedConfigFromEnv({ ...env, ...live }).live).toEqual({ zone: 'us-central1-a', subnetwork: live.KEYSENTRY_BOX_SUBNETWORK, imageReference: live.KEYSENTRY_BOX_IMAGE_REFERENCE });
    for (const [name, value] of [
      ['KEYSENTRY_BOX_ZONE', undefined], ['KEYSENTRY_BOX_ZONE', 'us-central1'],
      ['KEYSENTRY_BOX_SUBNETWORK', 'projects/other-project/regions/us-central1/subnetworks/keysentry-box-subnet'],
      ['KEYSENTRY_BOX_SUBNETWORK', 'projects/keysentry-box/regions/europe-west4/subnetworks/keysentry-box-subnet'],
      ['KEYSENTRY_BOX_IMAGE_REFERENCE', `us-docker.pkg.dev/keysentry-box/box/keysentry@sha256:${'c'.repeat(64)}`],
      ['KEYSENTRY_BOX_IMAGE_REFERENCE', 'us-docker.pkg.dev/keysentry-box/box/keysentry:latest'],
    ] as const) {
      expect(refusal(() => hostedConfigFromEnv({ ...env, ...live, [name]: value })), `${name}=${value}`).toMatchObject({ setting: name });
    }
    expect(refusal(() => hostedConfigFromEnv({ ...env, ...live, KEYSENTRY_BOX_SERVICE_ACCOUNT: 'keysentry-box@other-project.iam.gserviceaccount.com' })))
      .toMatchObject({ setting: 'KEYSENTRY_BOX_SERVICE_ACCOUNT' });
  });
  it('lists every variable it reads', () => {
    expect([...HOSTED_SETTINGS].sort()).toEqual([...Object.keys(env), ...Object.keys(live), 'KEYSENTRY_BOX_QUOTA', 'KEYSENTRY_TRUSTED_PROXY_HOPS'].sort());
  });
});

describe('guarded clients', () => {
  function recorder() {
    const calls: HttpRequest[] = [];
    return { calls, transport: { async request(req: HttpRequest) { calls.push(req); return json(200, { ok: true }); } } satisfies HttpClient };
  }
  const allowed: HttpRequest[] = [
    { method: 'GET', url: 'https://storage.googleapis.com/storage/v1/b/ks-control-state/o/sessions%2Fabc?alt=media' },
    { method: 'GET', url: 'https://storage.googleapis.com/storage/v1/b/ks-control-state/o?prefix=relay-index%2F&maxResults=1000' },
    { method: 'POST', url: 'https://storage.googleapis.com/upload/storage/v1/b/ks-control-state/o?uploadType=media&name=accounts%2Fx', body: '{}' },
    { method: 'DELETE', url: 'https://storage.googleapis.com/storage/v1/b/ks-control-state/o/accounts%2Fx' },
    { method: 'GET', url: 'https://api.stripe.com/v1/subscriptions/sub_123' },
    { method: 'POST', url: 'https://api.stripe.com/v1/checkout/sessions', body: 'mode=subscription' },
    { method: 'GET', url: 'https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com' },
  ];
  it('the hosted client reaches exactly the calls the control plane makes', async () => {
    const { calls, transport } = recorder();
    const http = createHostedHttp(transport, { bucket: 'ks-control-state' });
    for (const req of allowed) expect((await http.request(req)).status, req.url).toBe(200);
    expect(calls).toHaveLength(allowed.length);
  });
  it.each([
    ['another host', { method: 'GET', url: 'https://example.com/' }],
    ['the metadata server', { method: 'GET', url: METADATA_TOKEN_URL }],
    ['Secret Manager', { method: 'GET', url: `https://secretmanager.googleapis.com/v1/${WEBHOOK_REF}:access` }],
    ['plain HTTP to an allowed host', { method: 'GET', url: 'http://storage.googleapis.com/storage/v1/b/ks-control-state/o' }],
    ['another bucket', { method: 'GET', url: 'https://storage.googleapis.com/storage/v1/b/someone-else/o/x?alt=media' }],
    ['another Stripe endpoint', { method: 'POST', url: 'https://api.stripe.com/v1/refunds' }],
    ['a different method', { method: 'DELETE', url: 'https://api.stripe.com/v1/subscriptions/sub_123' }],
    ['another JWKS', { method: 'GET', url: 'https://www.googleapis.com/oauth2/v3/certs' }],
    ['Compute while live provisioning is off', { method: 'POST', url: 'https://compute.googleapis.com/compute/v1/projects/keysentry-box/zones/us-central1-a/instances' }],
    ['credentials in the URL', { method: 'GET', url: 'https://user:pass@api.stripe.com/v1/subscriptions/sub_1' }],
    ['an IP address', { method: 'GET', url: 'https://142.250.1.1/storage/v1/b/ks-control-state/o' }],
    ['an unparseable URL', { method: 'GET', url: 'not a url' }],
  ] as const)('the hosted client refuses %s before any I/O, with fixed text', async (_name, req) => {
    const { calls, transport } = recorder();
    const http = createHostedHttp(transport, { bucket: 'ks-control-state' });
    const error = await http.request(req as HttpRequest).then(() => null, (value: unknown) => value as Error);
    expect(error).toBeInstanceOf(Error);
    expect(error!.message).not.toMatch(/example\.com|someone-else|refunds|user:pass|142\.250/);
    expect(calls).toEqual([]);
  });
  it('reaches Compute only with live provisioning, only to create instances in the box project and zone', async () => {
    const { calls, transport } = recorder();
    const http = createHostedHttp(transport, { bucket: 'ks-control-state', compute: { projectId: 'keysentry-box', zone: 'us-central1-a' } });
    expect((await http.request({ method: 'POST', url: 'https://compute.googleapis.com/compute/v1/projects/keysentry-box/zones/us-central1-a/instances', body: '{}' })).status).toBe(200);
    for (const url of ['https://compute.googleapis.com/compute/v1/projects/other-project/zones/us-central1-a/instances',
      'https://compute.googleapis.com/compute/v1/projects/keysentry-box/zones/us-central1-a/instances/box-one']) {
      await expect(http.request({ method: 'POST', url })).rejects.toBeInstanceOf(DestinationRefusedError);
    }
    await expect(http.request({ method: 'DELETE', url: 'https://compute.googleapis.com/compute/v1/projects/keysentry-box/zones/us-central1-a/instances' })).rejects.toThrow();
    expect(calls).toHaveLength(1);
  });
  it('storage names the control plane writes never look like a provider key to the guard', async () => {
    const { calls, transport } = recorder();
    const http = createHostedHttp(transport, { bucket: 'ks-control-state' });
    const object = (key: string) => `https://storage.googleapis.com/storage/v1/b/ks-control-state/o/${encodeURIComponent(key)}?alt=media`;
    // Why account and blob ids are hex: a base64url id can contain a key prefix such as re_ and 16 more characters.
    await expect(http.request({ method: 'GET', url: object('accounts/Xre_AAAAAAAAAAAAAAAAAAX') })).rejects.toThrow();
    expect(calls).toEqual([]);
    for (let i = 0; i < 200; i++) {
      const account = randomBytes(32).toString('hex'), session = createHash('sha256').update(randomBytes(32)).digest('hex');
      for (const key of [`accounts/${account}`, `account-sessions/${account}`, `account-boxes/${account}`, `sessions/${session}`,
        `blobs/box-one/${randomBytes(16).toString('hex')}`, `credentials/${session}`]) await http.request({ method: 'GET', url: object(key) });
    }
    expect(calls).toHaveLength(1200);
  });
  it('the hosted client never follows a redirect', async () => {
    const calls: HttpRequest[] = [];
    const http = createHostedHttp({ async request(req) { calls.push(req); return json(302, {}, { location: 'https://evil.example/collect' }); } }, { bucket: 'ks-control-state' });
    await expect(http.request(allowed[0]!)).rejects.toThrow();
    expect(calls).toHaveLength(1);
  });
  it('the metadata client reaches only the token URL, with the Metadata-Flavor header', async () => {
    const { calls, transport } = recorder();
    const metadata = createMetadataHttp(transport);
    expect((await metadata.request({ method: 'GET', url: METADATA_TOKEN_URL, headers: { 'Metadata-Flavor': 'Google' } })).status).toBe(200);
    for (const req of [
      { method: 'GET', url: METADATA_TOKEN_URL },
      { method: 'GET', url: 'http://metadata.google.internal/computeMetadata/v1/instance/attributes/?recursive=true', headers: { 'Metadata-Flavor': 'Google' } },
      { method: 'GET', url: 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=x', headers: { 'Metadata-Flavor': 'Google' } },
      { method: 'POST', url: METADATA_TOKEN_URL, headers: { 'Metadata-Flavor': 'Google' }, body: '' },
      { method: 'GET', url: 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token', headers: { 'Metadata-Flavor': 'Google' } },
      { method: 'GET', url: 'https://storage.googleapis.com/storage/v1/b/ks-control-state/o', headers: { 'Metadata-Flavor': 'Google' } },
    ] as HttpRequest[]) await expect(metadata.request(req)).rejects.toBeInstanceOf(DestinationRefusedError);
    expect(calls).toEqual([{ method: 'GET', url: METADATA_TOKEN_URL, headers: { 'Metadata-Flavor': 'Google' } }]);
  });
  it('the Secret Manager client reaches only the configured references', async () => {
    const { calls, transport } = recorder();
    const secrets = createSecretManagerHttp(transport, [WEBHOOK_REF, API_KEY_REF]);
    for (const ref of [WEBHOOK_REF, API_KEY_REF]) expect((await secrets.request({ method: 'GET', url: `https://secretmanager.googleapis.com/v1/${ref}:access` })).status).toBe(200);
    for (const url of [
      'https://secretmanager.googleapis.com/v1/projects/keysentry-control/secrets/other/versions/latest:access',
      'https://secretmanager.googleapis.com/v1/projects/keysentry-control/secrets/stripe-webhook/versions/1:access',
      'https://secretmanager.googleapis.com/v1/projects/keysentry-control/secrets',
      `http://secretmanager.googleapis.com/v1/${WEBHOOK_REF}:access`,
    ]) await expect(secrets.request({ method: 'GET', url })).rejects.toThrow();
    expect(calls).toHaveLength(2);
    expect(() => createSecretManagerHttp(transport, ['projects/x/secrets/y'])).toThrow('Invalid egress configuration.');
  });
});

describe('Secret Manager values', () => {
  const token = async () => 'ya29.token';
  it('computes CRC32C (Castagnoli)', () => {
    expect(crc32c(Buffer.from('123456789'))).toBe(0xe3069283);
  });
  it('reads a version with the metadata token, checks its CRC32C and drops one trailing newline', async () => {
    const calls: HttpRequest[] = [];
    const http: HttpClient = { async request(req) { calls.push(req); return secretReply('whsec_value\n'); } };
    expect(await readSecret({ http, accessToken: token, reference: WEBHOOK_REF, setting: 'S' })).toBe('whsec_value');
    expect(calls).toEqual([{ method: 'GET', url: `https://secretmanager.googleapis.com/v1/${WEBHOOK_REF}:access`, headers: { authorization: 'Bearer ya29.token', accept: 'application/json' } }]);
    const numeric: HttpClient = { async request() { return secretReply('whsec_value', crc32c(Buffer.from('whsec_value'))); } };
    expect(await readSecret({ http: numeric, accessToken: token, reference: WEBHOOK_REF, setting: 'S' })).toBe('whsec_value');
  });
  it.each([
    ['a CRC32C mismatch', () => secretReply('whsec_value', '12345')],
    ['an empty payload', () => json(200, { payload: { data: '' } })],
    ['a value with an inner newline', () => secretReply('whsec_a\nwhsec_b')],
    ['a non-JSON body', () => text(200, 'planted')],
    ['403', () => json(403, { error: { message: 'planted permission detail' } })],
    ['404', () => json(404, {})],
  ])('refuses %s with fixed text and no retry', async (_name, reply) => {
    let count = 0;
    const http: HttpClient = { async request() { count++; return reply(); } };
    const error = await readSecret({ http, accessToken: token, reference: API_KEY_REF, setting: 'KEYSENTRY_STRIPE_API_KEY_REF' }).then(() => null, (value: unknown) => value as Error);
    expect(error?.message).toBe('KEYSENTRY_STRIPE_API_KEY_REF could not be read from Secret Manager.');
    expect(count).toBe(1);
  });
  it('retries 429, 5xx and transport failures a bounded number of times', async () => {
    let count = 0;
    const replies = [() => json(503, {}), () => { throw new Error('planted'); }, () => json(429, {}), () => secretReply(API_KEY)];
    const http: HttpClient = { async request() { return replies[count++]!(); } };
    expect(await readSecret({ http, accessToken: token, reference: API_KEY_REF, setting: 'S', sleep: async () => undefined })).toBe(API_KEY);
    count = 0;
    const down: HttpClient = { async request() { count++; return json(500, {}); } };
    await expect(readSecret({ http: down, accessToken: token, reference: API_KEY_REF, setting: 'S', sleep: async () => undefined })).rejects.toThrow('S could not be read');
    expect(count).toBe(4);
  });
});

describe('hosted process', () => {
  async function launch(extraEnv: Record<string, string | undefined> = {}, cloudOptions: Parameters<typeof cloud>[0] = {}) {
    const c = cloud(cloudOptions);
    const logs: HostedLogEntry[] = [];
    const running = await startHosted({ env: { ...env, ...extraEnv }, transport: c.transport, log: entry => logs.push(entry), sleep: async () => undefined });
    stops.push(() => running.stop());
    return { ...c, logs, running };
  }
  async function refused(extraEnv: Record<string, string | undefined>, cloudOptions: Parameters<typeof cloud>[0] = {}) {
    const c = cloud(cloudOptions);
    const logs: HostedLogEntry[] = [];
    const error = await startHosted({ env: { ...env, ...extraEnv }, transport: c.transport, log: entry => logs.push(entry), sleep: async () => undefined })
      .then(running => { stops.push(() => running.stop()); return null; }, (value: unknown) => value as Error);
    expect(error).toBeInstanceOf(HostedStartError);
    expect(error!.message).toBe('The control plane could not start.');
    return { ...c, logs };
  }

  it('resolves both Stripe secrets through the metadata token, serves the page and health, and logs event and status only', async () => {
    const ctx = await launch();
    expect((await call(ctx.running.port, '/health')).status).toBe(200);
    const page = await call(ctx.running.port, '/');
    expect(page.status).toBe(200);
    expect(page.headers['content-type']).toBe('text/html; charset=utf-8');
    const secretCalls = ctx.calls.filter(item => item.url.startsWith('https://secretmanager.googleapis.com/'));
    expect(secretCalls.map(item => item.url)).toEqual([`https://secretmanager.googleapis.com/v1/${WEBHOOK_REF}:access`, `https://secretmanager.googleapis.com/v1/${API_KEY_REF}:access`]);
    expect(secretCalls.every(item => item.headers?.authorization === 'Bearer ya29.hosted')).toBe(true);
    // One token request serves Secret Manager and storage.
    expect(ctx.calls.filter(item => item.url === METADATA_TOKEN_URL)).toHaveLength(1);
    await ctx.running.stop();
    expect(ctx.logs.map(entry => entry.event)).toEqual(['started', 'request', 'request', 'stopping', 'stopped']);
    for (const entry of ctx.logs) expect(Object.keys(entry).sort()).toEqual(['event', 'status']);
    expect(JSON.stringify(ctx.logs)).not.toMatch(/planted|whsec|rk_live|ya29/);
  });
  it('keeps sessions in the bucket by hash, so a restart does not sign anyone out', async () => {
    const gcs = cloud();
    const config = hostedConfigFromEnv(env);
    const secrets = { stripeWebhookSecret: WEBHOOK_SECRET, stripeApiKey: API_KEY };
    const http = createHostedHttp(gcs.transport, { bucket: config.bucket });
    const metadata = createMetadataHttp(gcs.transport);
    const first = createHostedControlPlane({ config, secrets, http, metadata });
    stops.push(() => first.close());
    let { port } = await first.listen();
    const user = await signUp(port);
    expect(user.cookie).toMatch(/^__Host-ks_control_session=/);
    await first.close();

    const second = createHostedControlPlane({ config, secrets, http, metadata });
    stops.push(() => second.close());
    ({ port } = await second.listen());
    const session = await call(port, '/session', { headers: { Cookie: user.cookie } });
    expect(session.status).toBe(200);
    expect(JSON.parse(session.body)).toEqual({ accountId: user.accountId, csrf: user.csrf });
    const sessionId = user.cookie.split('=')[1]!;
    expect([...gcs.objects.values()].some(value => value.includes(sessionId))).toBe(false);
    expect([...gcs.objects.keys()].some(name => name === `sessions/${createHash('sha256').update(sessionId).digest('hex')}`)).toBe(true);
    expect(gcs.origins()).toEqual(['http://metadata.google.internal', 'https://storage.googleapis.com']);
    // Live provisioning is off: no box is created.
    expect((await call(port, '/boxes', { method: 'POST', headers: user.page, body: JSON.stringify({ name: 'box-one', deviceKey }) })).status).toBe(503);
  });
  it('creates boxes through Compute with the metadata token only when live provisioning is on', async () => {
    vi.stubEnv('KEYSENTRY_CONTROL_PLANE_LIVE', '1');
    const ctx = await launch(live);
    const user = await signUp(ctx.running.port);
    // Pay through a verified webhook (Stripe's subscription check is answered below).
    const subscription = { id: 'sub_live', customer: 'cus_live', status: 'active', items: { has_more: false, data: [{ price: { id: 'price_plan' } }] } };
    const transport = ctx.transport.request.bind(ctx.transport);
    ctx.transport.request = async req => req.url === 'https://api.stripe.com/v1/subscriptions/sub_live' ? json(200, subscription) : transport(req);
    const raw = JSON.stringify({ id: 'evt_live', type: 'checkout.session.completed', created: Math.floor(Date.now() / 1000), data: { object: {
      mode: 'subscription', status: 'complete', payment_status: 'paid', client_reference_id: user.accountId, customer: 'cus_live', subscription: 'sub_live' } } });
    const t = Math.floor(Date.now() / 1000);
    const paid = await call(ctx.running.port, '/billing/webhook', { method: 'POST', body: raw, headers: { 'Content-Type': 'application/json',
      'Stripe-Signature': `t=${t},v1=${createHmac('sha256', WEBHOOK_SECRET).update(`${t}.${raw}`).digest('hex')}` } });
    expect(JSON.parse(paid.body)).toMatchObject({ applied: true });
    const created = await call(ctx.running.port, '/boxes', { method: 'POST', headers: user.page, body: JSON.stringify({ name: 'box-one', deviceKey }) });
    expect(created.status).toBe(201);
    const insert = ctx.calls.find(item => item.url.startsWith('https://compute.googleapis.com/'))!;
    expect(insert.url).toBe('https://compute.googleapis.com/compute/v1/projects/keysentry-box/zones/us-central1-a/instances');
    expect(insert.headers?.authorization).toBe('Bearer ya29.hosted');
    const metadata = (JSON.parse(insert.body!) as { metadata: { items: { key: string; value: string }[] } }).metadata.items;
    expect(Object.fromEntries(metadata.map(item => [item.key, item.value]))).toMatchObject({
      'tee-image-reference': live.KEYSENTRY_BOX_IMAGE_REFERENCE, 'keysentry-box-id': 'box-one', 'keysentry-relay-origin': ORIGIN, 'keysentry-enroll-device-key': deviceKey });
  });
  it.each([
    [{ KEYSENTRY_CONTROL_ORIGIN: 'http://planted.example' }, 'KEYSENTRY_CONTROL_ORIGIN'],
    [{ KEYSENTRY_STRIPE_API_KEY: API_KEY }, 'KEYSENTRY_STRIPE_API_KEY'],
    [{ KEYSENTRY_CONTROL_PLANE_LIVE: '1' }, 'KEYSENTRY_BOX_ZONE'],
  ])('refuses to start on a configuration error, naming the setting, before any request', async (extra, setting) => {
    const ctx = await refused(extra);
    expect(ctx.logs).toEqual([{ event: 'config-invalid', status: 1, setting }]);
    expect(ctx.calls).toEqual([]);
  });
  it.each([
    ['a secret that cannot be read', { [API_KEY_REF]: json(403, { error: { message: 'planted' } }) }, 'KEYSENTRY_STRIPE_API_KEY_REF'],
    ['a webhook secret that is not one', { [WEBHOOK_REF]: secretReply('planted-not-a-webhook-secret') }, 'KEYSENTRY_STRIPE_WEBHOOK_SECRET_REF'],
    ['an API key that is not one', { [API_KEY_REF]: secretReply('pk_live_planted0publishable') }, 'KEYSENTRY_STRIPE_API_KEY_REF'],
  ])('refuses to start with %s and never listens', async (_name, secrets, setting) => {
    const ctx = await refused({}, { secrets });
    expect(ctx.logs).toEqual([{ event: 'secret-unavailable', status: 1, setting }]);
    expect(ctx.calls.every(item => !item.url.startsWith('https://storage.googleapis.com'))).toBe(true);
    expect(JSON.stringify(ctx.logs)).not.toContain('planted');
  });
  it('stops gracefully on SIGTERM and reports the exit code', async () => {
    const ctx = await launch();
    const signals = new EventEmitter();
    const codes: number[] = [];
    stopOnSignals(signals as never, ctx.running, code => codes.push(code));
    signals.emit('SIGTERM');
    await vi.waitFor(() => expect(codes).toEqual([0]));
    expect(ctx.logs.slice(-2)).toEqual([{ event: 'stopping', status: 0 }, { event: 'stopped', status: 0 }]);
    await expect(call(ctx.running.port, '/health')).rejects.toThrow();
    signals.emit('SIGINT');
    await ctx.running.stop();
    expect(ctx.logs.filter(entry => entry.event === 'stopping')).toHaveLength(1);
  });
});
