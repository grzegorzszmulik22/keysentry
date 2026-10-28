import { createPublicKey, type JsonWebKey, type KeyObject } from 'node:crypto';
import type { HttpClient } from '../../types.js';
import type { IdTokenAlg } from './discovery.js';
import { fail, OidcError } from './errors.js';
import { header, record, requestJson } from './fetch.js';

/** A public key the provider published for ID token signatures. */
export interface VerificationKey { kid?: string; alg: IdTokenAlg; key: KeyObject }

const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];
const MAX_KEYS = 100;
const MAX_DOCUMENT = 512 * 1024;
const DEFAULT_CACHE_SECONDS = 300;
const MAX_CACHE_SECONDS = 3600;
const FORCED_REFRESH_INTERVAL_MS = 10_000;

/** Node's base64url decoder is permissive; JWK members must be canonical. */
function canonical(value: unknown, bytes?: number): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  const decoded = Buffer.from(value, 'base64url');
  return decoded.toString('base64url') === value && (bytes === undefined || decoded.length === bytes);
}

/**
 * Import one JWK for RS256 or ES256, following the attestation verifier's approach (src/box/attestation/jwks.ts):
 * strict members, Node's JWK import, then a check of the imported key. Keys for other algorithms or for
 * encryption return null so a mixed set still works; private or symmetric material refuses the whole set.
 */
export function importJwk(jwk: unknown): VerificationKey | null {
  if (!record(jwk)) return fail('configuration');
  if (PRIVATE_MEMBERS.some(field => Object.hasOwn(jwk, field))) return fail('configuration');
  if (jwk.kid !== undefined && (typeof jwk.kid !== 'string' || jwk.kid.length === 0 || jwk.kid.length > 256)) return fail('configuration');
  if (jwk.use !== undefined && jwk.use !== 'sig') return null;
  if (jwk.key_ops !== undefined && (!Array.isArray(jwk.key_ops) || !jwk.key_ops.includes('verify'))) return null;
  let alg: IdTokenAlg;
  let input: JsonWebKey;
  if (jwk.kty === 'RSA') {
    if (jwk.alg !== undefined && jwk.alg !== 'RS256') return null;
    if (!canonical(jwk.n) || Buffer.from(jwk.n, 'base64url')[0] === 0 || jwk.e !== 'AQAB') return null;
    alg = 'RS256'; input = { kty: 'RSA', n: jwk.n, e: jwk.e };
  } else if (jwk.kty === 'EC') {
    if (jwk.alg !== undefined && jwk.alg !== 'ES256') return null;
    if (jwk.crv !== 'P-256') return null;
    if (!canonical(jwk.x, 32) || !canonical(jwk.y, 32)) return fail('configuration');
    alg = 'ES256'; input = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  } else return null;
  let key: KeyObject;
  try { key = createPublicKey({ key: input, format: 'jwk' }); } catch { return fail('configuration'); }
  const details = key.asymmetricKeyDetails;
  if (alg === 'RS256' && (key.asymmetricKeyType !== 'rsa' || !details || (details.modulusLength ?? 0) < 2048 || details.publicExponent !== 65537n)) return null;
  if (alg === 'ES256' && (key.asymmetricKeyType !== 'ec' || details?.namedCurve !== 'prime256v1')) return fail('configuration');
  return { ...(typeof jwk.kid === 'string' ? { kid: jwk.kid } : {}), alg, key };
}

/** Parse a JWK Set; refuse ambiguous sets (two usable keys with one kid and algorithm) and empty results. */
export function parseJwks(value: unknown): VerificationKey[] {
  if (!record(value) || !Array.isArray(value.keys) || value.keys.length === 0 || value.keys.length > MAX_KEYS) return fail('configuration');
  const keys: VerificationKey[] = [];
  for (const candidate of value.keys) {
    const key = importJwk(candidate);
    if (!key) continue;
    if (keys.some(existing => existing.alg === key.alg && existing.kid === key.kid)) return fail('configuration');
    keys.push(key);
  }
  if (keys.length === 0) return fail('configuration');
  return keys;
}

function cacheSeconds(headers: Record<string, string>): number {
  const directives = header(headers, 'cache-control').split(',').map(part => part.trim().toLowerCase()).filter(Boolean);
  if (directives.some(part => /^(?:no-store|no-cache)(?:\s*=|$)/.test(part))) return 0;
  const maxAges = directives.filter(part => /^max-age(?:\s*=|$)/.test(part));
  if (maxAges.length === 0) return DEFAULT_CACHE_SECONDS;
  if (maxAges.length !== 1) return 0;
  const match = /^max-age\s*=\s*(?:"(\d+)"|(\d+))$/.exec(maxAges[0]!);
  if (!match) return 0;
  const ageValue = header(headers, 'age').trim();
  const age = /^\d+$/.test(ageValue) ? Number(ageValue) : 0;
  return Math.max(0, Math.min(Number(match[1] ?? match[2]), MAX_CACHE_SECONDS) - age);
}

export type KeySource = (forceRefresh: boolean) => Promise<VerificationKey[]>;

/**
 * Cache the provider's keys. A forced refresh (unknown kid) bypasses the cache at most once every ten seconds,
 * so a burst of unknown key ids cannot turn into a burst of requests. The injected client owns egress.
 */
export function createJwksSource(http: HttpClient, jwksUri: string, options: { now?: () => number } = {}): KeySource {
  const now = options.now ?? Date.now;
  let cached: VerificationKey[] | undefined;
  let expiresAt = 0;
  let lastForced = Number.NEGATIVE_INFINITY;
  let inFlight: Promise<VerificationKey[]> | undefined;

  async function fetchKeys(): Promise<VerificationKey[]> {
    const startedAt = now();
    try {
      const { body, headers } = await requestJson(http, { method: 'GET', url: jwksUri, headers: { Accept: 'application/json' } }, MAX_DOCUMENT);
      const keys = parseJwks(body);
      cached = keys;
      expiresAt = startedAt + cacheSeconds(headers) * 1000;
      return keys;
    } catch (error) {
      if (error instanceof OidcError) throw error;
      return fail('unavailable');
    }
  }

  return async (forceRefresh: boolean) => {
    if (inFlight) return [...await inFlight];
    const time = now();
    if (cached && (forceRefresh ? time - lastForced < FORCED_REFRESH_INTERVAL_MS : time < expiresAt)) return [...cached];
    if (forceRefresh) lastForced = time;
    inFlight = fetchKeys();
    try { return [...await inFlight]; } finally { inFlight = undefined; }
  };
}
