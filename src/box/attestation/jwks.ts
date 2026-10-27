import { createPublicKey, type JsonWebKey, type KeyObject } from 'node:crypto';
import type { HttpClient } from '../../types.js';

export const CONFIDENTIAL_SPACE_JWKS_URL = 'https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com';

const MAX_CACHE_SECONDS = 24 * 60 * 60;

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function base64urlUInt(value: unknown): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length > 0 && bytes[0] !== 0 && bytes.toString('base64url') === value;
}

/** Import only a public RS256 RSA key with the strength and exponent used by the attestation service. */
export function jwkPublicKey(jwk: JsonWebKey): KeyObject {
  try {
    if (!record(jwk) || jwk.kty !== 'RSA' || !base64urlUInt(jwk.n) || jwk.e !== 'AQAB' ||
      (jwk.alg !== undefined && jwk.alg !== 'RS256') ||
      (jwk.use !== undefined && jwk.use !== 'sig') ||
      (jwk.key_ops !== undefined && (!Array.isArray(jwk.key_ops) || jwk.key_ops.length !== 1 || jwk.key_ops[0] !== 'verify')) ||
      ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some((field) => Object.hasOwn(jwk, field))) {
      throw new Error();
    }
    const key = createPublicKey({ key: jwk, format: 'jwk' });
    const details = key.asymmetricKeyDetails;
    if (key.asymmetricKeyType !== 'rsa' || !details || (details.modulusLength ?? 0) < 2048 || details.publicExponent !== 65537n) {
      throw new Error();
    }
    return key;
  } catch {
    throw new Error('Attestation signing key is invalid.');
  }
}

/** Reject ambiguous or malformed sets rather than selecting a key from a partially parsed response. */
export function parseJwks(value: unknown): JsonWebKey[] {
  try {
    if (!record(value) || !Array.isArray(value.keys) || value.keys.length === 0) throw new Error();
    const kids = new Set<string>();
    return value.keys.map((candidate: unknown) => {
      if (!record(candidate) || typeof candidate.kid !== 'string' || candidate.kid.trim().length === 0 || kids.has(candidate.kid)) throw new Error();
      jwkPublicKey(candidate);
      kids.add(candidate.kid);
      return structuredClone(candidate);
    });
  } catch {
    throw new Error('Attestation key set is invalid.');
  }
}

function header(headers: Record<string, string>, name: string): string {
  return Object.entries(headers).find(([key]) => key.toLowerCase() === name)?.[1] ?? '';
}

function cacheSeconds(headers: Record<string, string>): number {
  const directives = header(headers, 'cache-control').split(',').map((part) => part.trim().toLowerCase());
  if (directives.some((part) => /^(?:no-store|no-cache)(?:\s*=|$)/.test(part))) return 0;
  const maxAges = directives.filter((part) => /^max-age(?:\s*=|$)/.test(part));
  if (maxAges.length !== 1) return 0;
  const match = /^max-age\s*=\s*(?:"(\d+)"|(\d+))$/.exec(maxAges[0]!);
  if (!match) return 0;
  const ageValue = header(headers, 'age').trim();
  const age = /^\d+$/.test(ageValue) ? Number(ageValue) : 0;
  const maxAge = Number(match[1] ?? match[2]);
  return Math.max(0, Math.min(maxAge, MAX_CACHE_SECONDS) - age);
}

export type JwksFetcher = (forceRefresh?: boolean) => Promise<JsonWebKey[]>;

/** The injected guarded client owns egress enforcement; this function never opens a connection itself. */
export function createJwksFetcher(http: HttpClient, options: { now?: () => Date; url?: string } = {}): JwksFetcher {
  const now = options.now ?? (() => new Date());
  const url = options.url ?? CONFIDENTIAL_SPACE_JWKS_URL;
  let cached: JsonWebKey[] | undefined;
  let expiresAt = 0;
  let inFlight: Promise<JsonWebKey[]> | undefined;

  async function fetchKeys(): Promise<JsonWebKey[]> {
    try {
      const startedAt = now().getTime();
      if (!Number.isFinite(startedAt)) throw new Error();
      const response = await http.request({ method: 'GET', url });
      if (response.status !== 200) throw new Error();
      const keys = parseJwks(response.json());
      cached = keys;
      expiresAt = startedAt + cacheSeconds(response.headers) * 1000;
      return keys;
    } catch {
      throw new Error('Attestation signing keys could not be fetched.');
    }
  }

  return async (forceRefresh = false) => {
    // An already-running refresh takes precedence over a still-valid older cache.
    if (inFlight) return structuredClone(await inFlight);
    if (!forceRefresh && cached && now().getTime() < expiresAt) return structuredClone(cached);
    inFlight = fetchKeys();
    try {
      return structuredClone(await inFlight);
    } finally {
      inFlight = undefined;
    }
  };
}
