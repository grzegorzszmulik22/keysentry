import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { HttpClient } from '../../types.js';
import { checkIssuer, discover, hostOf, type OidcProviderMetadata } from './discovery.js';
import { fail, OidcError } from './errors.js';
import { requestJson } from './fetch.js';
import { verifyIdToken, type VerifiedIdentity } from './id-token.js';
import { createJwksSource, type KeySource } from './jwks.js';

export interface OidcClientOptions {
  /** Exactly as the provider publishes it; compared byte for byte. */
  issuer: string;
  clientId: string;
  /** `${publicOrigin}/auth/callback`, registered at the provider. */
  redirectUri: string;
  /** The runtime's egress-guarded client. */
  http: HttpClient;
  /**
   * Confidential client: returns the client secret from the vault for each token request. Omit it for a public
   * client (PKCE only). Never read from a flag or keysentry.yaml.
   */
  clientSecret?: () => Promise<string | null>;
  /** Extra hosts the token and key endpoints may use; the issuer's host is always allowed. */
  allowedHosts?: readonly string[];
  scopes?: readonly string[];
  now?: () => number;
  skewSeconds?: number;
  metadataTtlMs?: number;
}

/** Everything the browser-bound transaction must remember to finish the sign-in. */
export interface OidcAuthorization { state: string; nonce: string; verifier: string; url: string }

/** Authorization response parameters, already checked for duplicates by the caller. */
export interface OidcCallback { code?: string; state?: string; iss?: string; error?: string }

export interface OidcClient {
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  metadata(): Promise<OidcProviderMetadata>;
  authorize(): Promise<OidcAuthorization>;
  complete(callback: OidcCallback, expected: { state: string; nonce: string; verifier: string }): Promise<VerifiedIdentity>;
}

const random = () => randomBytes(32).toString('base64url');

function same(actual: string, expected: string): boolean {
  const a = Buffer.from(actual, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

/** RFC 6749 §2.3.1: form-encode the client id and secret before HTTP Basic encoding. */
function formEncode(value: string): string {
  return new URLSearchParams([['v', value]]).toString().slice(2);
}

export function pkceChallenge(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

/** Authorization code flow with PKCE S256 for one provider. All provider HTTP goes through `options.http`. */
export function createOidcClient(options: OidcClientOptions): OidcClient {
  let issuer: string;
  try { issuer = checkIssuer(options.issuer); } catch { throw new Error('Use the identity provider issuer as an https URL without a query or fragment.'); }
  if (typeof options.clientId !== 'string' || !/^[\x21-\x7e]{1,512}$/.test(options.clientId)) throw new Error('Use the client id registered at your identity provider.');
  let redirect: URL;
  try { redirect = new URL(options.redirectUri); } catch { throw new Error('Use an https redirect address on the public origin.'); }
  if (redirect.protocol !== 'https:' || redirect.username || redirect.password || redirect.search || redirect.hash || redirect.href !== options.redirectUri) {
    throw new Error('Use an https redirect address on the public origin.');
  }
  const now = options.now ?? Date.now;
  const ttl = options.metadataTtlMs ?? 3_600_000;
  const scopes = options.scopes ?? ['openid', 'email'];
  if (!scopes.includes('openid') || !scopes.every(scope => /^[\x21\x23-\x5b\x5d-\x7e]{1,128}$/.test(scope))) throw new Error('Request the openid scope.');
  const allowed = new Set([hostOf(issuer), ...(options.allowedHosts ?? []).map(host => host.toLowerCase().replace(/\.$/, ''))]);
  let cached: { value: OidcProviderMetadata; expires: number } | undefined;
  let inFlight: Promise<OidcProviderMetadata> | undefined;
  let keys: { uri: string; source: KeySource } | undefined;

  async function metadata(): Promise<OidcProviderMetadata> {
    if (cached && now() < cached.expires) return structuredClone(cached.value);
    if (inFlight) return structuredClone(await inFlight);
    inFlight = (async () => {
      const value = await discover(options.http, issuer);
      // keysentry contacts only hosts the user allowed; the authorization endpoint is visited by the browser.
      if (!allowed.has(hostOf(value.tokenEndpoint)) || !allowed.has(hostOf(value.jwksUri))) return fail('configuration');
      cached = { value, expires: now() + ttl };
      return value;
    })();
    try { return structuredClone(await inFlight); } finally { inFlight = undefined; }
  }

  function keySource(uri: string): KeySource {
    if (!keys || keys.uri !== uri) keys = { uri, source: createJwksSource(options.http, uri, { now }) };
    return keys.source;
  }

  async function exchange(provider: OidcProviderMetadata, code: string, verifier: string): Promise<string> {
    const params = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: options.redirectUri, code_verifier: verifier });
    const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
    if (options.clientSecret) {
      let secret: string | null;
      try { secret = await options.clientSecret(); } catch { return fail('configuration'); }
      if (typeof secret !== 'string' || secret.length === 0) return fail('configuration');
      if (provider.tokenAuthMethods.includes('client_secret_basic')) {
        headers.Authorization = `Basic ${Buffer.from(`${formEncode(options.clientId)}:${formEncode(secret)}`, 'utf8').toString('base64')}`;
      } else if (provider.tokenAuthMethods.includes('client_secret_post')) {
        params.set('client_id', options.clientId);
        params.set('client_secret', secret);
      } else return fail('configuration');
    } else params.set('client_id', options.clientId);
    const { body } = await requestJson(options.http, { method: 'POST', url: provider.tokenEndpoint, headers, body: params.toString() }, 64 * 1024, 'token-response');
    // Access and refresh tokens are never kept: only the ID token is read, verified and dropped.
    if (typeof body.id_token !== 'string') return fail('token-response');
    return body.id_token;
  }

  return {
    issuer,
    clientId: options.clientId,
    redirectUri: options.redirectUri,
    metadata,
    async authorize() {
      const provider = await metadata();
      const state = random();
      const nonce = random();
      const verifier = random();
      const url = new URL(provider.authorizationEndpoint);
      for (const [name, value] of Object.entries({
        response_type: 'code', client_id: options.clientId, redirect_uri: options.redirectUri, scope: scopes.join(' '),
        state, nonce, code_challenge: pkceChallenge(verifier), code_challenge_method: 'S256',
      })) url.searchParams.set(name, value);
      return { state, nonce, verifier, url: url.href };
    },
    async complete(callback, expected) {
      // The browser binding comes first, before any provider request or error reporting.
      if (typeof callback.state !== 'string' || typeof expected.state !== 'string' || !same(callback.state, expected.state)) return fail('state');
      if (callback.error !== undefined) return fail('provider-error');
      const provider = await metadata();
      if (callback.iss !== undefined ? callback.iss !== issuer : provider.issParameterSupported) return fail('issuer');
      if (typeof callback.code !== 'string' || !/^[\x21-\x7e]{1,4096}$/.test(callback.code)) return fail('provider-error');
      try {
        const token = await exchange(provider, callback.code, expected.verifier);
        return await verifyIdToken(token, keySource(provider.jwksUri), {
          issuer, clientId: options.clientId, nonce: expected.nonce, algs: provider.signingAlgs, now: now(), skewSeconds: options.skewSeconds,
        });
      } catch (error) {
        if (error instanceof OidcError) throw error;
        return fail('unavailable');
      }
    },
  };
}
