import { constants, createHash, timingSafeEqual, verify } from 'node:crypto';
import type { PasskeyCredential } from '../../types.js';
import { AuthDataError, parseAuthData } from './authdata.js';
import type { AuthData } from './authdata.js';
import { CborError, decodeCbor } from './cbor.js';
import { coseToPublicKey } from './cose.js';

export class WebAuthnError extends Error {
  readonly code = 'WEBAUTHN_REJECTED';
  readonly reason: string;
  constructor(reason: string) {
    super(`WebAuthn verification rejected: ${reason}`);
    this.name = 'WebAuthnError';
    this.reason = reason;
  }
}

interface CommonInput {
  clientDataJSON: Buffer;
  expectedChallenge: Buffer;
  expectedOrigins: string[];
  requireUserVerification: boolean;
}
export interface RegistrationInput extends CommonInput { attestationObject: Buffer; rpId: string }
export interface AssertionInput extends CommonInput {
  credential: PasskeyCredential;
  authenticatorData: Buffer;
  signature: Buffer;
}

function reject(reason: string): never { throw new WebAuthnError(reason); }
function sha256(data: Buffer | string): Buffer { return createHash('sha256').update(data).digest(); }

function base64url(value: unknown, field: string, maxBytes: number): Buffer {
  if (typeof value !== 'string' || value.length === 0 || value.length > Math.ceil(maxBytes * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) {
    return reject(`${field} must be canonical base64url`);
  }
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length > maxBytes || bytes.toString('base64url') !== value) reject(`${field} must be canonical base64url`);
  return bytes;
}

function clientData(input: CommonInput, type: 'webauthn.create' | 'webauthn.get'): string {
  if (!Buffer.isBuffer(input.clientDataJSON) || input.clientDataJSON.length > 8192) reject('clientDataJSON exceeds its 8 KiB size limit');
  let data: unknown;
  try { data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(input.clientDataJSON)); }
  catch { return reject('clientDataJSON must contain valid UTF-8 JSON'); }
  if (typeof data !== 'object' || data === null || Array.isArray(data)) reject('clientDataJSON must contain an object');
  const c = data as Record<string, unknown>;
  if (c.type !== type) reject('clientDataJSON type does not match this ceremony');
  const challenge = base64url(c.challenge, 'challenge', 8192);
  if (!Buffer.isBuffer(input.expectedChallenge) || challenge.length !== input.expectedChallenge.length || !timingSafeEqual(challenge, input.expectedChallenge)) {
    reject('challenge does not match the expected challenge');
  }
  if (typeof c.origin !== 'string' || !input.expectedOrigins.includes(c.origin)) reject('origin is not an expected origin');
  // Name topOrigin first: the W3C topOrigin vector also sets crossOrigin=true.
  if (Object.hasOwn(c, 'topOrigin')) reject('topOrigin is not supported by this page policy');
  if (c.crossOrigin !== undefined && c.crossOrigin !== false) reject('crossOrigin is not supported by this page policy');
  return c.origin;
}

function parseAuthenticator(buf: Buffer): AuthData {
  try { return parseAuthData(buf); }
  catch (error) {
    if (error instanceof AuthDataError) return reject(error.message);
    return reject('authenticatorData contains invalid CBOR');
  }
}

function authenticatorPolicy(data: AuthData, rpId: string, requireUV: boolean): void {
  if (typeof rpId !== 'string' || rpId.length === 0 || !timingSafeEqual(data.rpIdHash, sha256(rpId))) reject('rpId hash does not match');
  if (!data.flags.up) reject('UP user presence is required');
  if (requireUV && !data.flags.uv) reject('UV user verification is required');
  if (data.flags.bs && !data.flags.be) reject('BS backup state requires BE backup eligibility');
}

function publicKey(coseBytes: Buffer): ReturnType<typeof coseToPublicKey> {
  try {
    const cose = decodeCbor(coseBytes);
    if (!(cose instanceof Map)) return reject('credential public key must be a COSE map');
    return coseToPublicKey(cose as Map<number, unknown>);
  } catch (error) {
    if (error instanceof WebAuthnError) throw error;
    return reject('credential public key or algorithm is not supported');
  }
}

export function verifyRegistration(input: RegistrationInput): PasskeyCredential {
  clientData(input, 'webauthn.create');
  let decoded: unknown;
  try { decoded = decodeCbor(input.attestationObject); }
  catch (error) {
    if (error instanceof CborError) return reject('attestationObject contains invalid CBOR');
    return reject('attestationObject is invalid');
  }
  if (!(decoded instanceof Map)) reject('attestationObject must be a map');
  if (decoded.get('fmt') !== 'none') reject('only the none attestation format is accepted');
  const statement: unknown = decoded.get('attStmt');
  if (!(statement instanceof Map) || statement.size !== 0) reject('none attestation statement must be an empty map');
  const authData: unknown = decoded.get('authData');
  if (!Buffer.isBuffer(authData)) reject('attestationObject authData must be bytes');
  const data = parseAuthenticator(authData);
  authenticatorPolicy(data, input.rpId, input.requireUserVerification);
  if (!data.credential) reject('registration requires attested credential data');
  const { alg } = publicKey(data.credential.publicKeyCose);
  return {
    id: data.credential.id.toString('base64url'), publicKeyCose: data.credential.publicKeyCose.toString('base64url'),
    alg, signCount: data.signCount, backupEligible: data.flags.be, rpId: input.rpId,
    origins: [...input.expectedOrigins], label: '', createdAt: new Date().toISOString(),
  };
}

/** ES256 WebAuthn signatures use two positive, minimally encoded DER INTEGERs. */
function isEs256Der(signature: Buffer): boolean {
  if (signature.length < 8 || signature.length > 72 || signature[0] !== 0x30 || signature[1] !== signature.length - 2) return false;
  let offset = 2;
  for (let i = 0; i < 2; i++) {
    if (signature[offset++] !== 2) return false;
    const size = signature[offset++];
    if (size === undefined || size < 1 || size > 33 || offset + size > signature.length) return false;
    const first = signature[offset]!;
    if ((first & 0x80) !== 0 || (first === 0 && (size === 1 || (signature[offset + 1]! & 0x80) === 0))) return false;
    offset += size;
  }
  return offset === signature.length;
}

export function verifyAssertion(input: AssertionInput): { signCount: number; cloneWarning: boolean } {
  const origin = clientData(input, 'webauthn.get');
  const credential = input.credential;
  if (!Array.isArray(credential.origins) || !credential.origins.includes(origin)) reject('origin was not registered for this credential');
  if (!Number.isInteger(credential.signCount) || credential.signCount < 0 || credential.signCount > 0xffffffff) reject('stored signCount counter is invalid');
  const data = parseAuthenticator(input.authenticatorData);
  authenticatorPolicy(data, credential.rpId, input.requireUserVerification);
  if (data.flags.at) reject('assertion must not contain AT attested credential data');
  if (data.flags.be !== credential.backupEligible) reject('BE backup eligibility changed from the stored credential');
  const { key, alg } = publicKey(base64url(credential.publicKeyCose, 'credential public key', 65536));
  if (credential.alg !== alg) reject('stored algorithm does not match the credential public key');
  if (!Buffer.isBuffer(input.signature) || input.signature.length === 0 || input.signature.length > 1024) reject('signature has an invalid length');
  if (alg === -7 && !isEs256Der(input.signature)) reject('signature must use strict ES256 DER encoding');
  if (alg === -8 && input.signature.length !== 64) reject('Ed25519 signature must be 64 bytes');
  const signedData = Buffer.concat([input.authenticatorData, sha256(input.clientDataJSON)]);
  let valid = false;
  try {
    if (alg === -8) valid = verify(null, signedData, key, input.signature);
    else if (alg === -7) valid = verify('sha256', signedData, { key, dsaEncoding: 'der' }, input.signature);
    else valid = verify('sha256', signedData, { key, padding: constants.RSA_PKCS1_PADDING }, input.signature);
  } catch { return reject('signature could not be verified'); }
  if (!valid) reject('signature does not verify');
  return { signCount: data.signCount, cloneWarning: (credential.signCount !== 0 || data.signCount !== 0) && data.signCount <= credential.signCount };
}
