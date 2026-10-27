import { createHash, createPrivateKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { PasskeyCredential } from '../../../src/types.js';
import { decodeCbor } from '../../../src/approvals/webauthn/cbor.js';
import { coseToPublicKey } from '../../../src/approvals/webauthn/cose.js';
import { parseAuthData } from '../../../src/approvals/webauthn/authdata.js';

interface Vector {
  registration: Record<string, string>;
  authentication: Record<string, string>;
}
export const fixture = JSON.parse(readFileSync(new URL('../../fixtures/webauthn/vectors.json', import.meta.url), 'utf8')) as {
  rpId: string; origin: string; vectors: Record<string, Vector>;
};
export const hex = (value: string): Buffer => Buffer.from(value, 'hex');
export const vector = (name = 'none-es256'): Vector => fixture.vectors[name]!;

// A test-only encoder lets malformed/boundary cases use independent, readable inputs.
export function encode(value: unknown): Buffer {
  function head(major: number, n: number): Buffer {
    if (n < 24) return Buffer.from([(major << 5) | n]);
    if (n < 256) return Buffer.from([(major << 5) | 24, n]);
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(n, 1);
    return b;
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  if (typeof value === 'string') {
    const b = Buffer.from(value);
    return Buffer.concat([head(3, b.length), b]);
  }
  if (typeof value === 'number' && Number.isInteger(value)) return head(value >= 0 ? 0 : 1, value >= 0 ? value : -1 - value);
  if (value instanceof Map) return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [encode(k), encode(v)])]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(encode)]);
  if (value === null || typeof value === 'boolean') return Buffer.from([value === null ? 0xf6 : value ? 0xf5 : 0xf4]);
  throw new Error('Unsupported test CBOR value');
}

export function registrationInput(name = 'none-es256') {
  const r = vector(name).registration;
  return {
    clientDataJSON: hex(r.clientDataJSON!), attestationObject: hex(r.attestationObject!),
    expectedChallenge: hex(r.challenge!), expectedOrigins: [fixture.origin], rpId: fixture.rpId,
    requireUserVerification: false,
  };
}

export function registrationAuthData(name = 'none-es256'): Buffer {
  return (decodeCbor(registrationInput(name).attestationObject) as Map<string, unknown>).get('authData') as Buffer;
}

export function credentialFromVector(name = 'none-es256'): PasskeyCredential {
  const data = parseAuthData(registrationAuthData(name));
  const credential = data.credential!;
  const { alg } = coseToPublicKey(decodeCbor(credential.publicKeyCose) as Map<number, unknown>);
  return {
    id: credential.id.toString('base64url'), publicKeyCose: credential.publicKeyCose.toString('base64url'),
    alg, signCount: data.signCount, backupEligible: data.flags.be,
    rpId: fixture.rpId, origins: [fixture.origin], label: '', createdAt: '2026-10-27T00:00:00.000Z',
  };
}

export function assertionInput(name = 'none-es256', credential = credentialFromVector(name)) {
  const a = vector(name).authentication;
  return {
    credential, clientDataJSON: hex(a.clientDataJSON!), authenticatorData: hex(a.authenticatorData!),
    signature: hex(a.signature!), expectedChallenge: hex(a.challenge!), expectedOrigins: [fixture.origin],
    requireUserVerification: false,
  };
}

export function noneAttestation(authData: Buffer): Buffer {
  return encode(new Map<string, unknown>([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
}

export function resign(input: ReturnType<typeof assertionInput>): ReturnType<typeof assertionInput> {
  const { key } = coseToPublicKey(decodeCbor(Buffer.from(input.credential.publicKeyCose, 'base64url')) as Map<number, unknown>);
  const privateKey = createPrivateKey({ format: 'jwk', key: {
    ...key.export({ format: 'jwk' }), d: hex(vector().registration.credential_private_key!).toString('base64url'),
  } });
  const data = Buffer.concat([input.authenticatorData, createHash('sha256').update(input.clientDataJSON).digest()]);
  return { ...input, signature: sign('sha256', data, { key: privateKey, dsaEncoding: 'der' }) };
}
