import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { request } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import { encode } from '../../../test/approvals/webauthn/helpers.js';
import { json, text } from '../../../test/helpers/fake-http.js';
import type { HttpClient } from '../../../src/types.js';
import { createHostedControlPlane, hostedConfigFromEnv } from '../src/hosted.js';

const ORIGIN = 'https://control.example';
const env = {
  KEYSENTRY_CONTROL_ORIGIN: ORIGIN, PORT: '0', KEYSENTRY_CONTROL_BUCKET: 'ks-control-state', KEYSENTRY_STRIPE_PRICE_ID: 'price_plan',
  KEYSENTRY_BOX_PROJECT_ID: 'keysentry-box', KEYSENTRY_BOX_SERVICE_ACCOUNT: 'keysentry-box@keysentry-box.iam.gserviceaccount.com',
  KEYSENTRY_BOX_ALLOWED_DIGESTS: `sha256:${'a'.repeat(64)},sha256:${'b'.repeat(64)}`,
  KEYSENTRY_STRIPE_WEBHOOK_SECRET: 'whsec_planted0secret0value', KEYSENTRY_STRIPE_API_KEY: 'rk_live_planted0api0key0value',
};

/** Metadata server and Cloud Storage JSON API in memory: the only destinations hosted state uses. */
function google() {
  const objects = new Map<string, string>();
  const hosts = new Set<string>();
  const http: HttpClient = { async request(req) {
    const url = new URL(req.url);
    hosts.add(url.origin);
    if (url.origin === 'http://metadata.google.internal') return json(200, { access_token: 'ya29.hosted', expires_in: 3600, token_type: 'Bearer' }, { 'metadata-flavor': 'Google' });
    if (url.origin !== 'https://storage.googleapis.com' || req.headers?.authorization !== 'Bearer ya29.hosted') return json(403, {});
    if (req.method === 'POST' && url.pathname === '/upload/storage/v1/b/ks-control-state/o') { objects.set(url.searchParams.get('name')!, req.body!); return json(200, {}); }
    const object = /^\/storage\/v1\/b\/ks-control-state\/o\/([^/]+)$/.exec(url.pathname);
    if (object && req.method === 'GET') { const name = decodeURIComponent(object[1]!); return objects.has(name) ? text(200, objects.get(name)!) : json(404, {}); }
    if (object && req.method === 'DELETE') return objects.delete(decodeURIComponent(object[1]!)) ? text(204, '') : json(404, {});
    if (req.method === 'GET' && url.pathname === '/storage/v1/b/ks-control-state/o') {
      return json(200, { items: [...objects.keys()].filter(name => name.startsWith(url.searchParams.get('prefix') ?? '')).map(name => ({ name })) });
    }
    return json(599, {});
  } };
  return { http, objects, hosts };
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

const servers: { close(): Promise<void> }[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });

describe('hosted configuration', () => {
  it('reads the Terraform environment', () => {
    const { config, secrets } = hostedConfigFromEnv(env);
    expect(config).toEqual({ origin: ORIGIN, port: 0, bucket: 'ks-control-state', priceId: 'price_plan', boxProjectId: 'keysentry-box',
      boxServiceAccount: 'keysentry-box@keysentry-box.iam.gserviceaccount.com', allowedDigests: [`sha256:${'a'.repeat(64)}`, `sha256:${'b'.repeat(64)}`],
      trustedProxyHops: 1, boxQuota: 1 });
    expect(secrets.stripeApiKey).toBe(env.KEYSENTRY_STRIPE_API_KEY);
  });
  it.each([
    ['KEYSENTRY_CONTROL_ORIGIN', 'http://control.example'], ['KEYSENTRY_BOX_ALLOWED_DIGESTS', 'latest'], ['KEYSENTRY_TRUSTED_PROXY_HOPS', '0'],
    ['KEYSENTRY_STRIPE_API_KEY', 'planted-not-a-key-value'], ['KEYSENTRY_STRIPE_WEBHOOK_SECRET', undefined],
  ])('names a missing or invalid %s without echoing its value', (name, value) => {
    const error = (() => { try { hostedConfigFromEnv({ ...env, [name]: value }); } catch (e) { return e as Error; } return null; })();
    expect(error?.message).toBe(`${name} is missing or invalid.`);
    expect(error?.message).not.toContain('planted');
  });
});

describe('hosted control plane', () => {
  it('keeps sessions in the bucket by hash, so a restart does not sign anyone out', async () => {
    const gcs = google();
    const { config, secrets } = hostedConfigFromEnv(env);
    const first = createHostedControlPlane({ config, secrets, http: gcs.http, metadata: gcs.http });
    servers.push(first);
    let { port } = await first.listen();
    const browser = { Origin: ORIGIN, 'Content-Type': 'application/json' };
    const challenge = JSON.parse((await call(port, '/auth/register/challenge', { method: 'POST', headers: browser, body: '{}' })).body) as { id: string; challenge: string };
    const registered = await call(port, '/auth/register/finish', { method: 'POST', headers: browser, body: JSON.stringify({ challengeId: challenge.id, ...passkey()(challenge.challenge) }) });
    expect(registered.status).toBe(200);
    const cookie = String(registered.headers['set-cookie']).split(';')[0]!;
    expect(cookie).toMatch(/^__Host-ks_control_session=/);
    const { account, csrf } = JSON.parse(registered.body) as { account: { id: string }; csrf: string };
    await first.close();

    const second = createHostedControlPlane({ config, secrets, http: gcs.http, metadata: gcs.http });
    servers.push(second);
    ({ port } = await second.listen());
    const session = await call(port, '/session', { headers: { Cookie: cookie } });
    expect(session.status).toBe(200);
    expect(JSON.parse(session.body)).toEqual({ accountId: account.id, csrf });
    const sessionId = cookie.split('=')[1]!;
    expect([...gcs.objects.values()].some(value => value.includes(sessionId))).toBe(false);
    expect([...gcs.objects.keys()].some(name => name === `sessions/${createHash('sha256').update(sessionId).digest('hex')}`)).toBe(true);
    expect([...gcs.hosts].sort()).toEqual(['http://metadata.google.internal', 'https://storage.googleapis.com']);
    // Live provisioning stays off in the hosted composition.
    expect((await call(port, '/boxes', { method: 'POST', headers: { ...browser, Cookie: cookie, 'X-CSRF-Token': csrf }, body: '{"name":"box-one"}' })).status).toBe(503);
  });
});
