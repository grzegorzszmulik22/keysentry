import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  createJwksSource, createOidcClient, discoveryUrl, OidcError, parseJwks, verifyIdToken, type OidcFailure,
} from '../../../src/dashboard/oidc/index.js';
import { memberForIdentity } from '../../../src/dashboard/oidc/members.js';
import { FakeHttp, json } from '../../helpers/fake-http.js';
import type { TeamMember } from '../../../src/types.js';
import {
  ACCESS_TOKEN, CLIENT_ID, CLIENT_SECRET, createFakeIdp, ecKey, ISSUER, mint, REDIRECT_URI, rsaKey, segment,
} from './fake-idp.js';

const T0 = Date.parse('2026-10-28T12:00:00Z');
const user = { sub: 'user-1', email: 'Ana@Example.test', email_verified: true };

function setup(opts: { discovery?: Record<string, unknown>; publicClient?: boolean; allowedHosts?: string[]; secret?: () => Promise<string | null> } = {}) {
  let now = T0;
  const idp = createFakeIdp({ now: () => now, discovery: opts.discovery, publicClient: opts.publicClient });
  const client = createOidcClient({
    issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, http: idp.http, now: () => now, allowedHosts: opts.allowedHosts,
    ...(opts.publicClient ? {} : { clientSecret: opts.secret ?? (async () => CLIENT_SECRET) }),
  });
  async function signIn(extra: Record<string, string> = {}, who = user) {
    const authorization = await client.authorize();
    const params = new URLSearchParams(idp.authorize(authorization.url, who, extra));
    return client.complete({ code: params.get('code') ?? undefined, state: params.get('state') ?? undefined, iss: params.get('iss') ?? undefined, error: params.get('error') ?? undefined }, authorization);
  }
  return { idp, client, signIn, advance(ms: number) { now += ms; }, get now() { return now; } };
}

async function reason(promise: Promise<unknown>): Promise<OidcFailure> {
  try { await promise; } catch (error) { if (error instanceof OidcError) return error.reason; throw error; }
  throw new Error('expected a refusal');
}

describe('OIDC discovery', () => {
  it('builds the well-known URL as Discovery 1.0 §4.1 says, and accepts only https issuers', () => {
    expect(discoveryUrl('https://idp.example.test')).toBe('https://idp.example.test/.well-known/openid-configuration');
    expect(discoveryUrl('https://idp.example.test/')).toBe('https://idp.example.test/.well-known/openid-configuration');
    expect(discoveryUrl('https://idp.example.test/tenant/v2.0')).toBe('https://idp.example.test/tenant/v2.0/.well-known/openid-configuration');
    for (const issuer of ['http://idp.example.test', 'https://idp.example.test?x=1', 'https://idp.example.test#f', 'https://user:pw@idp.example.test', 'idp.example.test']) {
      expect(() => createOidcClient({ issuer, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, http: new FakeHttp() })).toThrow('issuer');
    }
    expect(() => createOidcClient({ issuer: ISSUER, clientId: CLIENT_ID, redirectUri: 'http://keysentry.example.test/auth/callback', http: new FakeHttp() })).toThrow('redirect');
  });

  it('requires the published issuer to match exactly', async () => {
    for (const issuer of [`${ISSUER}/`, 'https://IDP.example.test', 'https://evil.example.test']) {
      const { client } = setup({ discovery: { issuer } });
      expect(await reason(client.metadata())).toBe('configuration');
    }
  });

  it.each([
    ['plain-http token endpoint', { token_endpoint: 'http://idp.example.test/token' }],
    ['plain-http jwks', { jwks_uri: 'http://idp.example.test/jwks' }],
    ['credentials in an endpoint', { authorization_endpoint: 'https://u:p@idp.example.test/authorize' }],
    ['no code flow', { response_types_supported: ['id_token'] }],
    ['no S256', { code_challenge_methods_supported: ['plain'] }],
    ['no RS256 or ES256', { id_token_signing_alg_values_supported: ['HS256', 'none'] }],
    ['missing subject types', { subject_types_supported: undefined }],
    ['no authorization_code grant', { grant_types_supported: ['implicit'] }],
  ])('refuses a discovery document with %s', async (_name, change) => {
    const { client } = setup({ discovery: change });
    expect(await reason(client.metadata())).toBe('configuration');
  });

  it('contacts token and key endpoints only on allowed hosts', async () => {
    const moved = { token_endpoint: 'https://tokens.example.test/token' };
    expect(await reason(setup({ discovery: moved }).client.metadata())).toBe('configuration');
    expect((await setup({ discovery: moved, allowedHosts: ['tokens.example.test'] }).client.metadata()).tokenEndpoint).toBe('https://tokens.example.test/token');
  });

  it('reports an unreachable provider without upstream detail', async () => {
    const http = new FakeHttp().on('GET', /openid-configuration$/, () => json(500, { error: 'planted-upstream-detail' }));
    const client = createOidcClient({ issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, http });
    const error = await client.metadata().catch(e => e);
    expect(error).toBeInstanceOf(OidcError);
    expect(error.reason).toBe('unavailable');
    expect(String(error.message)).not.toContain('planted');
  });
});

describe('OIDC authorization code flow', () => {
  it('sends PKCE S256, state and nonce, keeps the endpoint query, and verifies the ID token', async () => {
    const { client, idp, signIn } = setup({ discovery: { authorization_endpoint: `${ISSUER}/authorize?tenant=t1` } });
    const authorization = await client.authorize();
    const url = new URL(authorization.url);
    expect(url.searchParams.get('tenant')).toBe('t1');
    expect(Object.fromEntries(url.searchParams)).toMatchObject({ response_type: 'code', client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
      scope: 'openid email', state: authorization.state, nonce: authorization.nonce, code_challenge_method: 'S256' });
    expect(url.searchParams.get('code_challenge')).toBe(createHash('sha256').update(authorization.verifier).digest('base64url'));
    for (const value of [authorization.state, authorization.nonce, authorization.verifier]) expect(value).toMatch(/^[A-Za-z0-9_-]{43}$/);
    idp.state.discovery.authorization_endpoint = `${ISSUER}/authorize`;
    const identity = await signIn();
    expect(identity).toEqual({ issuer: ISSUER, subject: 'user-1', email: 'Ana@Example.test', emailVerified: true });
    expect(JSON.stringify(identity)).not.toContain(ACCESS_TOKEN);
    const token = idp.state.tokenRequests.at(-1)!;
    expect(token.headers).toMatchObject({ 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64')}` });
    expect(new URLSearchParams(token.body).has('client_secret')).toBe(false);
  });

  it('form-encodes the client id and secret before Basic encoding (RFC 6749 §2.3.1)', async () => {
    const { idp, signIn } = setup({ secret: async () => 'a b:c%d' });
    await reason(signIn());
    expect(idp.state.tokenRequests[0]!.headers!.Authorization).toBe(`Basic ${Buffer.from(`${CLIENT_ID}:a+b%3Ac%25d`).toString('base64')}`);
  });

  it('uses client_secret_post when Basic is not offered, and refuses when no secret method fits', async () => {
    const post = setup({ discovery: { token_endpoint_auth_methods_supported: ['client_secret_post'] } });
    await post.signIn();
    const body = new URLSearchParams(post.idp.state.tokenRequests[0]!.body);
    expect(body.get('client_id')).toBe(CLIENT_ID); expect(body.get('client_secret')).toBe(CLIENT_SECRET);
    expect(post.idp.state.tokenRequests[0]!.headers!.Authorization).toBeUndefined();
    expect(await reason(setup({ discovery: { token_endpoint_auth_methods_supported: ['private_key_jwt'] } }).signIn())).toBe('configuration');
  });

  it('signs in a public client with PKCE alone, and refuses a missing vault secret for a confidential client', async () => {
    const pub = setup({ publicClient: true });
    expect((await pub.signIn()).subject).toBe('user-1');
    const body = new URLSearchParams(pub.idp.state.tokenRequests[0]!.body);
    expect(body.get('client_id')).toBe(CLIENT_ID); expect(body.has('client_secret')).toBe(false);
    expect(await reason(setup({ secret: async () => null }).signIn())).toBe('configuration');
    expect(await reason(setup({ secret: async () => { throw new Error('planted vault failure'); } }).signIn())).toBe('configuration');
  });

  it('checks state before contacting the provider, and refuses provider errors without echoing them', async () => {
    const { client, idp } = setup();
    const authorization = await client.authorize();
    expect(await reason(client.complete({ code: 'x', state: 'wrong' }, authorization))).toBe('state');
    expect(await reason(client.complete({ code: 'x' }, authorization))).toBe('state');
    const error = await client.complete({ state: authorization.state, error: 'access_denied' }, authorization).catch(e => e);
    expect(error.reason).toBe('provider-error'); expect(error.message).not.toContain('access_denied');
    expect(idp.state.tokenRequests).toHaveLength(0);
  });

  it('checks the RFC 9207 iss parameter', async () => {
    expect(await reason(setup().signIn({ iss: 'https://evil.example.test' }))).toBe('issuer');
    expect((await setup().signIn({ iss: ISSUER })).subject).toBe('user-1');
    const required = setup({ discovery: { authorization_response_iss_parameter_supported: true } });
    expect(await reason(required.signIn())).toBe('issuer');
    expect((await required.signIn({ iss: ISSUER })).subject).toBe('user-1');
  });

  it('refuses a failed or malformed token response without upstream detail', async () => {
    const failed = setup(); failed.idp.state.tokenStatus = 500;
    const error = await failed.signIn().catch(e => e);
    expect(error.reason).toBe('token-response'); expect(error.message).not.toContain('planted');
    const reused = setup();
    const authorization = await reused.client.authorize();
    const params = new URLSearchParams(reused.idp.authorize(authorization.url, user));
    const callback = { code: params.get('code')!, state: params.get('state')! };
    await reused.client.complete(callback, authorization);
    expect(await reason(reused.client.complete(callback, authorization))).toBe('token-response');
  });
});

describe('ID token verification', () => {
  const tamper = (s: ReturnType<typeof setup>, claims: Record<string, unknown> = {}, header: Record<string, unknown> = {}) => {
    s.idp.state.claims = base => ({ ...base, ...claims });
    s.idp.state.header = base => ({ ...base, ...header });
  };

  it.each<[string, Record<string, unknown>, Record<string, unknown>, OidcFailure]>([
    ['wrong issuer', { iss: 'https://evil.example.test' }, {}, 'issuer'],
    ['wrong audience', { aud: 'someone-else' }, {}, 'audience'],
    ['no audience', { aud: [] }, {}, 'audience'],
    ['several audiences without azp', { aud: [CLIENT_ID, 'other'] }, {}, 'authorized-party'],
    ['azp for another client', { azp: 'other' }, {}, 'authorized-party'],
    ['bad nonce', { nonce: 'replayed-nonce' }, {}, 'nonce'],
    ['missing nonce', { nonce: undefined }, {}, 'nonce'],
    ['missing subject', { sub: '' }, {}, 'subject'],
    ['alg none', {}, { alg: 'none' }, 'algorithm'],
    ['HS256 with the client secret', {}, { alg: 'HS256' }, 'algorithm'],
    ['RS512', {}, { alg: 'RS512' }, 'algorithm'],
    ['an access-token type', {}, { typ: 'at+jwt' }, 'malformed'],
    ['critical extensions', {}, { crit: ['exp'] }, 'malformed'],
    ['an unpublished kid', {}, { kid: 'k-unknown' }, 'unknown-key'],
  ])('refuses %s', async (_name, claims, header, expected) => {
    const s = setup(); tamper(s, claims, header);
    expect(await reason(s.signIn())).toBe(expected);
  });

  it('accepts several audiences when azp names this client', async () => {
    const s = setup(); tamper(s, { aud: [CLIENT_ID, 'other'], azp: CLIENT_ID });
    expect((await s.signIn()).subject).toBe('user-1');
  });

  it('applies 60 seconds of skew to exp, iat and nbf, and refuses stale tokens', async () => {
    const at = (offset: number) => Math.floor(T0 / 1000) + offset;
    const cases: [Record<string, unknown>, OidcFailure | null][] = [
      [{ exp: at(-59) }, null], [{ exp: at(-60) }, 'expired'], [{ exp: at(-3600), iat: at(-3700) }, 'expired'],
      [{ iat: at(59) }, null], [{ iat: at(61) }, 'not-yet-valid'], [{ nbf: at(61) }, 'not-yet-valid'], [{ nbf: at(30) }, null],
      [{ iat: at(-600 - 59) }, null], [{ iat: at(-600 - 61) }, 'stale'], [{ exp: 'soon' }, 'malformed'], [{ iat: undefined }, 'malformed'],
    ];
    for (const [claims, expected] of cases) {
      const s = setup(); tamper(s, claims);
      if (expected === null) expect((await s.signIn()).subject).toBe('user-1');
      else expect(await reason(s.signIn())).toBe(expected);
    }
  });

  it('verifies ES256 provider keys and refuses a provider that does not list the algorithm', async () => {
    const s = setup();
    const ec = ecKey('ec1'); s.idp.state.published.push(ec); s.idp.state.signer = ec;
    expect((await s.signIn()).subject).toBe('user-1');
    const rsOnly = setup({ discovery: { id_token_signing_alg_values_supported: ['RS256'] } });
    const ec2 = ecKey('ec2'); rsOnly.idp.state.published.push(ec2); rsOnly.idp.state.signer = ec2;
    expect(await reason(rsOnly.signIn())).toBe('algorithm');
  });

  it('refuses a token signed by a key the provider did not publish under that kid', async () => {
    const s = setup();
    s.idp.state.signer = { ...rsaKey('k1') };
    expect(await reason(s.signIn())).toBe('signature');
  });

  it('refuses a key confusion between RS256 header and an EC key', async () => {
    const s = setup();
    const ec = ecKey('ec1'); s.idp.state.published.push(ec); s.idp.state.signer = ec;
    tamper(s, {}, { alg: 'RS256' });
    expect(await reason(s.signIn())).toBe('unknown-key');
  });

  it('parses only well-formed tokens and selects keys only from jwks_uri', async () => {
    const key = rsaKey('k1');
    const keys = async () => parseJwks({ keys: [key.jwk] });
    const base = { issuer: ISSUER, clientId: CLIENT_ID, nonce: 'n', algs: ['RS256' as const], now: T0 };
    const claims = { iss: ISSUER, aud: CLIENT_ID, sub: 's', nonce: 'n', exp: T0 / 1000 + 60, iat: T0 / 1000 };
    const good = mint(key, { alg: 'RS256', kid: 'k1' }, claims);
    expect((await verifyIdToken(good, keys, base)).subject).toBe('s');
    const [h, p, sig] = good.split('.');
    for (const token of [`${h}.${p}`, `${good}.x.y`, `${h}.${p}.${sig}=`, `${h}.${segment({ ...claims, sub: 't' })}.${sig}`, 42, '']) {
      await expect(verifyIdToken(token, keys, base)).rejects.toBeInstanceOf(OidcError);
    }
    const attacker = rsaKey('k1');
    const embedded = mint(attacker, { alg: 'RS256', kid: 'k1', jwk: attacker.jwk }, claims);
    expect(await reason(verifyIdToken(embedded, keys, base))).toBe('signature');
  });
});

describe('JWKS', () => {
  it('skips unrelated keys, refuses private or ambiguous sets', () => {
    const rsa = rsaKey('a');
    const ec = ecKey('b');
    const keys = parseJwks({ keys: [{ ...rsa.jwk, use: 'enc' }, { kty: 'OKP', crv: 'Ed25519', x: 'AA' }, { ...rsa.jwk, alg: 'RS384', kid: 'c' }, ec.jwk, rsa.jwk] });
    expect(keys.map(key => [key.kid, key.alg])).toEqual([['b', 'ES256'], ['a', 'RS256']]);
    const privateJwk = rsa.privateKey.export({ format: 'jwk' });
    expect(() => parseJwks({ keys: [{ ...privateJwk, kid: 'p' }] })).toThrow(OidcError);
    expect(() => parseJwks({ keys: [{ kty: 'oct', k: 'c2VjcmV0', kid: 'h' }] })).toThrow(OidcError);
    expect(() => parseJwks({ keys: [rsa.jwk, { ...rsa.jwk }] })).toThrow(OidcError);
    expect(() => parseJwks({ keys: [{ ...rsa.jwk, use: 'enc' }] })).toThrow(OidcError);
    expect(() => parseJwks({ keys: [] })).toThrow(OidcError);
    expect(parseJwks({ keys: [rsaKey('weak', 1024).jwk, rsa.jwk] })).toHaveLength(1);
  });

  it('caches keys, forces one refresh for an unknown kid, and throttles forced refreshes', async () => {
    let now = T0;
    const http = new FakeHttp().on('GET', /jwks$/, () => json(200, { keys: [rsaKey('a').jwk] }, { 'cache-control': 'max-age=60' }));
    const source = createJwksSource(http, 'https://idp.example.test/jwks', { now: () => now });
    await source(false); await source(false);
    expect(http.calls).toHaveLength(1);
    await source(true); expect(http.calls).toHaveLength(2);
    await source(true); expect(http.calls).toHaveLength(2);
    now += 10_000; await source(true); expect(http.calls).toHaveLength(3);
    now += 61_000; await source(false); expect(http.calls).toHaveLength(4);
  });
});

describe('roster mapping', () => {
  const members: TeamMember[] = [
    { id: 'ana', name: 'Ana', role: 'operator', email: 'ana@example.test', passkeys: [], deviceKeys: [] },
    { id: 'bo', name: 'Bo', role: 'viewer', passkeys: [], deviceKeys: [] },
    { id: 'dup1', name: 'D1', role: 'admin', email: 'dup@example.test', passkeys: [], deviceKeys: [] },
    { id: 'dup2', name: 'D2', role: 'viewer', email: 'DUP@example.test', passkeys: [], deviceKeys: [] },
  ];
  const identity = (email: string | undefined, emailVerified: boolean) => ({ issuer: ISSUER, subject: 's', emailVerified, ...(email ? { email } : {}) });
  it('maps a verified email to exactly one member', () => {
    expect(memberForIdentity(identity('ANA@example.test', true), members).id).toBe('ana');
    expect(() => memberForIdentity(identity('ana@example.test', false), members)).toThrow(expect.objectContaining({ reason: 'email-unverified' }));
    expect(() => memberForIdentity(identity(undefined, true), members)).toThrow(expect.objectContaining({ reason: 'email-missing' }));
    expect(() => memberForIdentity(identity('eve@example.test', true), members)).toThrow(expect.objectContaining({ reason: 'not-member' }));
    expect(() => memberForIdentity(identity('dup@example.test', true), members)).toThrow(expect.objectContaining({ reason: 'not-member' }));
  });
});
