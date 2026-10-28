import { createHash, createHmac, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import { FakeHttp, json } from '../../helpers/fake-http.js';
import type { HttpRequest } from '../../../src/types.js';

export const ISSUER = 'https://idp.example.test';
export const CLIENT_ID = 'keysentry-dashboard';
export const CLIENT_SECRET = 'client-secret-planted-value';
export const PUBLIC_ORIGIN = 'https://keysentry.example.test';
export const PUBLIC_HOST = 'keysentry.example.test';
export const REDIRECT_URI = `${PUBLIC_ORIGIN}/auth/callback`;
export const ACCESS_TOKEN = 'access-token-planted-value';

export interface SigningKey { kid: string; alg: 'RS256' | 'ES256'; privateKey: KeyObject; jwk: Record<string, unknown> }

export function rsaKey(kid: string, modulusLength = 2048): SigningKey {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength });
  return { kid, alg: 'RS256', privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' } };
}

export function ecKey(kid: string): SigningKey {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return { kid, alg: 'ES256', privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, alg: 'ES256', use: 'sig' } };
}

export const segment = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

/** Sign a JWT the way a provider would; `alg: none` and HS256 produce the tokens a forger would try. */
export function mint(key: SigningKey, header: Record<string, unknown>, claims: Record<string, unknown>): string {
  const input = `${segment(header)}.${segment(claims)}`;
  const alg = header.alg;
  if (alg === 'none') return `${input}.`;
  if (alg === 'HS256') return `${input}.${createHmac('sha256', CLIENT_SECRET).update(input).digest('base64url')}`;
  const signature = key.alg === 'ES256'
    ? sign('sha256', Buffer.from(input), { key: key.privateKey, dsaEncoding: 'ieee-p1363' })
    : sign('sha256', Buffer.from(input), key.privateKey);
  return `${input}.${signature.toString('base64url')}`;
}

export interface FakeUser { sub: string; email?: string; email_verified?: unknown }

interface Grant { nonce: string; challenge: string; redirectUri: string; clientId: string; user: FakeUser }

/**
 * An identity provider behind FakeHttp: discovery, JWKS and a token endpoint that enforces PKCE, the redirect
 * URI, single-use codes and client authentication like a real provider. Tests tamper with the next ID token
 * through `claims`, `header` and `signer`.
 */
export function createFakeIdp(opts: { now: () => number; discovery?: Record<string, unknown>; publicClient?: boolean }) {
  const http = new FakeHttp();
  const signing = rsaKey('k1');
  const state = {
    discovery: {
      issuer: ISSUER, authorization_endpoint: `${ISSUER}/authorize`, token_endpoint: `${ISSUER}/token`, jwks_uri: `${ISSUER}/jwks`,
      response_types_supported: ['code'], subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['RS256', 'ES256'],
      code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      ...opts.discovery,
    } as Record<string, unknown>,
    published: [signing] as SigningKey[],
    signer: signing,
    jwksHeaders: { 'cache-control': 'max-age=300' } as Record<string, string>,
    claims: (claims: Record<string, unknown>) => claims,
    header: (header: Record<string, unknown>) => header,
    tokenStatus: 200,
    grants: new Map<string, Grant>(),
    tokenRequests: [] as HttpRequest[],
    issued: [] as string[],
  };
  http.on('GET', /^https:\/\/idp\.example\.test\/\.well-known\/openid-configuration$/, () => json(200, state.discovery));
  http.on('GET', /^https:\/\/idp\.example\.test\/jwks$/, () => json(200, { keys: state.published.map(key => key.jwk) }, state.jwksHeaders));
  http.on('POST', /^https:\/\/idp\.example\.test\/token$/, req => {
    state.tokenRequests.push(req);
    const params = new URLSearchParams(req.body ?? '');
    const grant = state.grants.get(params.get('code') ?? '');
    state.grants.delete(params.get('code') ?? '');
    const basic = req.headers?.Authorization;
    const authenticated = opts.publicClient
      ? basic === undefined && params.get('client_id') === CLIENT_ID && !params.has('client_secret')
      : basic === `Basic ${Buffer.from(`${CLIENT_ID}:${encodeURIComponent(CLIENT_SECRET)}`).toString('base64')}`
        || (params.get('client_id') === CLIENT_ID && params.get('client_secret') === CLIENT_SECRET);
    if (!grant || params.get('grant_type') !== 'authorization_code' || params.get('redirect_uri') !== grant.redirectUri || !authenticated
      || createHash('sha256').update(params.get('code_verifier') ?? '').digest('base64url') !== grant.challenge) {
      return json(400, { error: 'invalid_grant', error_description: 'planted-upstream-detail' });
    }
    if (state.tokenStatus !== 200) return json(state.tokenStatus, { error: 'server_error', error_description: 'planted-upstream-detail' });
    const now = Math.floor(opts.now() / 1000);
    const claims = state.claims({ iss: ISSUER, sub: grant.user.sub, aud: CLIENT_ID, exp: now + 300, iat: now, nonce: grant.nonce,
      ...(grant.user.email === undefined ? {} : { email: grant.user.email }), ...(grant.user.email_verified === undefined ? {} : { email_verified: grant.user.email_verified }) });
    const header = state.header({ alg: state.signer.alg, kid: state.signer.kid, typ: 'JWT' });
    const idToken = mint(state.signer, header, claims);
    state.issued.push(idToken);
    return json(200, { access_token: ACCESS_TOKEN, token_type: 'Bearer', expires_in: 300, refresh_token: 'refresh-planted-value', id_token: idToken }, { 'cache-control': 'no-store' });
  });

  return {
    http,
    state,
    signing,
    /** The user's browser at the provider: check the request and return the redirect back with a fresh code. */
    authorize(location: string, user: FakeUser, extra: Record<string, string> = {}): string {
      const url = new URL(location);
      if (`${url.origin}${url.pathname}` !== state.discovery.authorization_endpoint) throw new Error('unexpected authorization endpoint');
      const params = url.searchParams;
      if (params.get('response_type') !== 'code' || params.get('code_challenge_method') !== 'S256') throw new Error('unexpected authorization request');
      const code = randomBytes(24).toString('base64url');
      state.grants.set(code, { nonce: params.get('nonce')!, challenge: params.get('code_challenge')!, redirectUri: params.get('redirect_uri')!, clientId: params.get('client_id')!, user });
      return new URLSearchParams({ code, state: params.get('state')!, ...extra }).toString();
    },
    jwksFetches: () => http.callsTo('GET', /\/jwks$/).length,
  };
}
