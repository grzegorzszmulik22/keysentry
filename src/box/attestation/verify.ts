import { verify, type JsonWebKey, type KeyObject, type X509Certificate } from 'node:crypto';
import type { AttestationClaims, AttestationPolicy, AttestationResult } from '../../types.js';
import { checkClaims, type AttestationCheck } from './claims.js';
import { jwkPublicKey, type JwksFetcher } from './jwks.js';
import { parseJwt, type ParsedJwt } from './jwt.js';
import { verifyCertificateChain } from './pki.js';

export interface VerifyAttestationInput {
  token: string;
  /** Pass createJwksFetcher to support forced refresh when a signing key rotates. */
  jwks: JwksFetcher;
  root?: X509Certificate;
  policy: AttestationPolicy;
  /** [boxKeyNonce(rawPublicKey), challengeNonce()] for this session. */
  expectedNonces: string[];
  now: Date;
}

function validHeader(header: Record<string, unknown>): boolean {
  return header.alg === 'RS256' && header.typ === 'JWT' &&
    typeof header.kid === 'string' && header.kid.trim().length > 0 &&
    header.crit === undefined && header.b64 === undefined;
}

function matchingKeys(keys: JsonWebKey[], kid: string): JsonWebKey[] {
  return keys.filter((key) => key !== null && typeof key === 'object' && key.kid === kid);
}

async function signingKey(parsed: ParsedJwt, input: VerifyAttestationInput): Promise<KeyObject> {
  // An x5c token has one trust path: failure must not fall back to OIDC keys.
  if (Object.hasOwn(parsed.header, 'x5c')) {
    return verifyCertificateChain(parsed.header.x5c, input.now, input.root);
  }
  const kid = parsed.header.kid as string;
  let matches = matchingKeys(await input.jwks(), kid);
  if (matches.length === 0) matches = matchingKeys(await input.jwks(true), kid);
  if (matches.length !== 1) throw new Error('Signing key could not be selected.');
  return jwkPublicKey(matches[0]!);
}

/** Verify trust, signature and every release-policy check before a caller sends tokens. */
export async function verifyAttestation(input: VerifyAttestationInput): Promise<AttestationResult> {
  const checks: AttestationCheck[] = [];
  let parsed: ParsedJwt | undefined;
  try { parsed = parseJwt(input.token); } catch { /* Never expose token or parser diagnostics. */ }
  checks.push({ name: 'jwt-format', ok: parsed !== undefined,
    detail: parsed ? 'JWT compact encoding is valid.' : 'JWT compact encoding is invalid.' });

  const headerOk = parsed !== undefined && validHeader(parsed.header);
  checks.push({ name: 'jwt-header', ok: headerOk,
    detail: headerOk ? 'RS256 JWT header and key ID are present.' : 'Expected an RS256 JWT header with a key ID.' });

  let key: KeyObject | undefined;
  if (parsed && headerOk) {
    try { key = await signingKey(parsed, input); } catch { /* Fail closed on key fetch, import or chain failure. */ }
  }
  checks.push({ name: 'signing-key', ok: key !== undefined,
    detail: key ? (Object.hasOwn(parsed!.header, 'x5c')
      ? 'Certificate chain matches the pinned root.' : 'Signing key matches the trusted JWKS.')
      : 'Signing key or certificate chain could not be verified.' });

  let signatureOk = false;
  if (parsed && key) {
    try { signatureOk = verify('RSA-SHA256', parsed.signingInput, key, parsed.signature); } catch { /* Invalid signature. */ }
  }
  checks.push({ name: 'signature', ok: signatureOk,
    detail: signatureOk ? 'RS256 signature is valid.' : 'RS256 signature could not be verified.' });

  const claimChecks = checkClaims(signatureOk ? parsed!.claims : null, input.policy, input.expectedNonces, input.now);
  checks.push(...claimChecks.map((check) => signatureOk ? check : {
    name: check.name, ok: false, detail: 'Not checked because the token signature was not verified.',
  }));
  const ok = checks.every((check) => check.ok);
  return {
    ok, checks,
    boxKeyHash: ok ? input.expectedNonces[0]! : null,
    claims: signatureOk ? parsed!.claims as unknown as AttestationClaims : null,
  };
}
