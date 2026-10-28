import { constants, timingSafeEqual, verify } from 'node:crypto';
import { decodeBase64url } from '../../box/attestation/jwt.js';
import type { IdTokenAlg } from './discovery.js';
import { fail } from './errors.js';
import type { KeySource, VerificationKey } from './jwks.js';
import { record } from './fetch.js';

export interface IdTokenExpectations {
  issuer: string;
  clientId: string;
  nonce: string;
  /** Algorithms both keysentry and the provider accept. */
  algs: readonly IdTokenAlg[];
  /** Milliseconds since the epoch. */
  now: number;
  skewSeconds?: number;
  /** Refuse ID tokens issued longer ago than this (the token was just returned by the token endpoint). */
  maxAgeSeconds?: number;
}

/** The verified facts keysentry uses. Nothing else from the ID token leaves this module. */
export interface VerifiedIdentity {
  issuer: string;
  subject: string;
  email?: string;
  emailVerified: boolean;
}

const MAX_TOKEN = 64 * 1024;

function object(segment: string): Record<string, unknown> {
  let value: unknown;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(decodeBase64url(segment))); }
  catch { return fail('malformed'); }
  if (!record(value)) return fail('malformed');
  return value;
}

function same(actual: string, expected: string): boolean {
  const a = Buffer.from(actual, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

function numericDate(value: unknown, required: boolean): number | undefined {
  if (value === undefined && !required) return undefined;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return fail('malformed');
  return value;
}

function checkSignature(alg: IdTokenAlg, key: VerificationKey, input: Buffer, signature: Buffer): boolean {
  try {
    if (alg === 'ES256') {
      // JWS ES256 signatures are the raw 64-byte R || S form (RFC 7518 §3.4).
      if (signature.length !== 64) return false;
      return verify('sha256', input, { key: key.key, dsaEncoding: 'ieee-p1363' }, signature);
    }
    const bytes = Math.ceil((key.key.asymmetricKeyDetails?.modulusLength ?? 0) / 8);
    if (signature.length !== bytes) return false;
    return verify('sha256', input, { key: key.key, padding: constants.RSA_PKCS1_PADDING }, signature);
  } catch { return false; }
}

/**
 * Verify an ID token from the token endpoint (OpenID Connect Core 1.0 §3.1.3.7) without dependencies:
 * only RS256/ES256 with the provider's published keys, exact issuer, audience and authorized party, time
 * claims with skew, and the nonce bound to this browser's sign-in.
 */
export async function verifyIdToken(token: unknown, keys: KeySource, expected: IdTokenExpectations): Promise<VerifiedIdentity> {
  const skew = expected.skewSeconds ?? 60;
  const maxAge = expected.maxAgeSeconds ?? 600;
  if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN) return fail('malformed');
  const parts = token.split('.');
  // Five parts would be an encrypted ID token, which keysentry never negotiates.
  if (parts.length !== 3) return fail('malformed');
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];
  const header = object(headerPart);
  // The algorithm decides everything else, so check it before any other part is trusted or even parsed.
  if (typeof header.alg !== 'string' || !expected.algs.includes(header.alg as IdTokenAlg)) return fail('algorithm');
  const alg = header.alg as IdTokenAlg;
  if (header.crit !== undefined) return fail('malformed');
  if (header.typ !== undefined && (typeof header.typ !== 'string' || header.typ.toUpperCase() !== 'JWT')) return fail('malformed');
  if (header.kid !== undefined && (typeof header.kid !== 'string' || header.kid.length === 0 || header.kid.length > 256)) return fail('malformed');
  const kid = header.kid as string | undefined;
  const claims = object(payloadPart);
  let signature: Buffer;
  try { signature = decodeBase64url(signaturePart); } catch { return fail('malformed'); }

  // Embedded keys (jwk, jku, x5u, x5c) are ignored: only keys from the provider's jwks_uri are used.
  const candidates = (set: VerificationKey[]) => set.filter(key => key.alg === alg && (kid === undefined || key.kid === kid));
  let matches = candidates(await keys(false));
  if (matches.length === 0) matches = candidates(await keys(true));
  // Without a kid the set must hold exactly one key for the algorithm (Core §10.1).
  if (matches.length !== 1) return fail('unknown-key');
  if (!checkSignature(alg, matches[0]!, Buffer.from(`${headerPart}.${payloadPart}`, 'ascii'), signature)) return fail('signature');

  if (typeof claims.iss !== 'string' || claims.iss !== expected.issuer) return fail('issuer');
  const aud = claims.aud;
  const audiences = typeof aud === 'string' ? [aud] : Array.isArray(aud) && aud.length > 0 && aud.every(item => typeof item === 'string') ? aud as string[] : null;
  if (!audiences || !audiences.includes(expected.clientId)) return fail('audience');
  if (claims.azp !== undefined && claims.azp !== expected.clientId) return fail('authorized-party');
  if (audiences.length > 1 && claims.azp !== expected.clientId) return fail('authorized-party');

  const now = expected.now / 1000;
  const exp = numericDate(claims.exp, true)!;
  const iat = numericDate(claims.iat, true)!;
  const nbf = numericDate(claims.nbf, false);
  if (now >= exp + skew) return fail('expired');
  if (iat > now + skew || (nbf !== undefined && nbf > now + skew)) return fail('not-yet-valid');
  if (iat < now - maxAge - skew) return fail('stale');

  if (typeof claims.nonce !== 'string' || !same(claims.nonce, expected.nonce)) return fail('nonce');
  if (typeof claims.sub !== 'string' || claims.sub.length === 0 || claims.sub.length > 255) return fail('subject');

  const identity: VerifiedIdentity = { issuer: claims.iss, subject: claims.sub, emailVerified: claims.email_verified === true };
  if (typeof claims.email === 'string' && claims.email.length <= 320 && /^[^\s@\u0000-\u001f\u007f]+@[^\s@\u0000-\u001f\u007f]+$/.test(claims.email)) {
    identity.email = claims.email;
  }
  return identity;
}
