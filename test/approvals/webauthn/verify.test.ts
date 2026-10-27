import { createHash, createPrivateKey, sign } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { decodeCbor } from '../../../src/approvals/webauthn/cbor.js';
import { coseToPublicKey } from '../../../src/approvals/webauthn/cose.js';
import { WebAuthnError, verifyAssertion, verifyRegistration } from '../../../src/approvals/webauthn/verify.js';
import {
  assertionInput, credentialFromVector, encode, fixture, hex, noneAttestation,
  registrationAuthData, registrationInput, resign, vector,
} from './helpers.js';

function changedClient(input: ReturnType<typeof registrationInput> | ReturnType<typeof assertionInput>, changes: Record<string, unknown>) {
  return { ...input, clientDataJSON: Buffer.from(JSON.stringify({ ...JSON.parse(input.clientDataJSON.toString()), ...changes })) };
}

function expectRejected(fn: () => unknown, reason?: RegExp): void {
  try { fn(); } catch (error) {
    expect(error).toBeInstanceOf(WebAuthnError);
    expect((error as WebAuthnError).code).toBe('WEBAUTHN_REJECTED');
    if (reason) expect((error as WebAuthnError).reason).toMatch(reason);
    return;
  }
  throw new Error('Expected verification to reject');
}

describe('W3C vectors', () => {
  test.each(['none-es256', 'none-es256-long-credential-id'])('registration and assertion vector %s verify', (name) => {
    const input = registrationInput(name);
    const credential = verifyRegistration(input);
    expect(credential.id).toBe(hex(vector(name).registration.credential_id!).toString('base64url'));
    expect(credential.alg).toBe(-7);
    expect(credential.signCount).toBe(0);
    expect(credential.backupEligible).toBe(true);
    expect(credential.origins).toEqual([fixture.origin]);
    expect(credential.rpId).toBe(fixture.rpId);
    expect(credential.label).toBe('');
    expect(Number.isFinite(Date.parse(credential.createdAt))).toBe(true);
    expect(verifyAssertion(assertionInput(name, credential))).toEqual({ signCount: 0, cloneWarning: false });
    input.expectedOrigins.push('https://other.example');
    expect(credential.origins).toEqual([fixture.origin]);
  });

  test('the long credential vector is exactly 1023 bytes and a synthetic 1024 byte id is rejected', () => {
    expect(hex(vector('none-es256-long-credential-id').registration.credential_id!).length).toBe(1023);
    const data = registrationAuthData('none-es256-long-credential-id');
    const malformed = Buffer.concat([data.subarray(0, 55), Buffer.alloc(1024), data.subarray(55 + 1023)]);
    malformed.writeUInt16BE(1024, 53);
    expectRejected(() => verifyRegistration({ ...registrationInput('none-es256-long-credential-id'), attestationObject: noneAttestation(malformed) }), /credential.*id|credential.*length/i);
  });

  test.each([
    ['none-es256-crossOrigin', /crossOrigin/], ['none-es256-topOrigin', /topOrigin/],
  ] as const)('%s is rejected for its named framing field in both ceremonies', (name, reason) => {
    expectRejected(() => verifyRegistration(registrationInput(name)), reason);
    expectRejected(() => verifyAssertion(assertionInput(name)), reason);
  });

  test.each([
    ['packed-self-es256', -7], ['packed-es256', -7], ['packed-rs256', -257], ['packed-eddsa', -8],
  ] as const)('%s assertion verifies using its attested public key; packed registration is refused', (name, alg) => {
    const credential = credentialFromVector(name);
    expect(credential.alg).toBe(alg);
    expect(verifyAssertion(assertionInput(name, credential))).toEqual({ signCount: 0, cloneWarning: false });
    expectRejected(() => verifyRegistration(registrationInput(name)), /attestation|format/i);
  });

  test.each(['none-es256', 'packed-rs256', 'packed-eddsa'])('every flipped byte in %s assertion inputs is rejected', (name) => {
    const input = assertionInput(name);
    for (const field of ['clientDataJSON', 'authenticatorData', 'signature'] as const) {
      for (let i = 0; i < input[field].length; i++) {
        const altered = Buffer.from(input[field]);
        altered[i] = altered[i]! ^ 1;
        expectRejected(() => verifyAssertion({ ...input, [field]: altered }));
      }
    }
  });
});

describe('client data policy', () => {
  test.each(['registration', 'assertion'] as const)('%s validates required type, challenge, exact origin and framing fields', (ceremony) => {
    const input = ceremony === 'registration' ? registrationInput() : assertionInput();
    const verify = (value: typeof input) => ceremony === 'registration'
      ? verifyRegistration(value as ReturnType<typeof registrationInput>)
      : verifyAssertion(value as ReturnType<typeof assertionInput>);
    const client = JSON.parse(input.clientDataJSON.toString());
    for (const [field, value] of [
      ['type', 'webauthn.wrong'], ['type', null], ['challenge', 'AA'], ['challenge', 1],
      ['challenge', `${client.challenge}=`], ['challenge', `${client.challenge}!`],
      ['origin', 'https://example.org/'], ['origin', 'https://example.org.evil.test'],
      ['origin', null], ['crossOrigin', true], ['crossOrigin', 'false'], ['topOrigin', null],
    ] as const) expectRejected(() => verify(changedClient(input, { [field]: value })), new RegExp(field));
    for (const field of ['type', 'challenge', 'origin']) {
      const missing = { ...client };
      delete missing[field];
      expectRejected(() => verify({ ...input, clientDataJSON: Buffer.from(JSON.stringify(missing)) }), new RegExp(field));
    }
    expectRejected(() => verify({ ...input, expectedChallenge: Buffer.alloc(32) }), /challenge/);
    expectRejected(() => verify({ ...input, expectedOrigins: [] }), /origin/);
  });

  test.each(['registration', 'assertion'] as const)('%s rejects malformed, non-object, oversized or invalid UTF-8 JSON', (ceremony) => {
    const input = ceremony === 'registration' ? registrationInput() : assertionInput();
    const verify = (clientDataJSON: Buffer) => ceremony === 'registration'
      ? verifyRegistration({ ...input as ReturnType<typeof registrationInput>, clientDataJSON })
      : verifyAssertion({ ...input as ReturnType<typeof assertionInput>, clientDataJSON });
    for (const invalid of [Buffer.alloc(0), Buffer.from('{'), Buffer.from('[]'), Buffer.from('null'), Buffer.alloc(8193, 0x20), Buffer.from([0xff])]) {
      expectRejected(() => verify(invalid), /clientDataJSON/);
    }
  });

  test('accepts unknown client fields and exactly 8 KiB while rejecting 8 KiB plus one', () => {
    const input = registrationInput();
    const base = changedClient(input, { futureField: 'supported' });
    expect(verifyRegistration(base).id).toBe(credentialFromVector().id);
    const padded = Buffer.concat([base.clientDataJSON, Buffer.alloc(8192 - base.clientDataJSON.length, 0x20)]);
    expect(verifyRegistration({ ...input, clientDataJSON: padded }).id).toBe(credentialFromVector().id);
    expectRejected(() => verifyRegistration({ ...input, clientDataJSON: Buffer.concat([padded, Buffer.from(' ')]) }), /clientDataJSON/);
  });

  test('challenge uses canonical base64url even when ignored low bits decode to the same bytes', () => {
    const input = registrationInput();
    const client = JSON.parse(input.clientDataJSON.toString());
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = alphabet.indexOf(client.challenge.at(-1));
    const challenge = client.challenge.slice(0, -1) + alphabet[last + 1];
    expect(Buffer.from(challenge, 'base64url')).toEqual(input.expectedChallenge);
    expectRejected(() => verifyRegistration(changedClient(input, { challenge })), /challenge/);
  });

  test('assertion origin must also have been stored on the credential', () => {
    const input = assertionInput();
    expectRejected(() => verifyAssertion({ ...input, credential: { ...input.credential, origins: ['https://other.example'] } }), /origin/);
  });
});

describe('authenticator and signature policy', () => {
  test('registration checks rpId, UP, UV, backup state, AT and a none attestation statement', () => {
    const input = registrationInput();
    expectRejected(() => verifyRegistration({ ...input, rpId: 'other.example' }), /rpId/);
    expectRejected(() => verifyRegistration({ ...input, requireUserVerification: true }), /UV|verification/i);
    for (const [flags, reason] of [[0x58, /UP|presence/i], [0x51, /BS|backup/i], [0x19, /attested|credential/i]] as const) {
      const data = registrationAuthData();
      data[32] = flags;
      const authData = (flags & 0x40) === 0 ? data.subarray(0, 37) : data;
      expectRejected(() => verifyRegistration({ ...input, attestationObject: noneAttestation(authData) }), reason);
    }
    const attestation = new Map<string, unknown>([['fmt', 'none'], ['attStmt', new Map([['sig', Buffer.alloc(1)]])], ['authData', registrationAuthData()]]);
    expectRejected(() => verifyRegistration({ ...input, attestationObject: encode(attestation) }), /attestation|statement/i);
  });

  test('registration accepts required UV when set and assertions always require UP', () => {
    const registrationData = registrationAuthData();
    registrationData[32] = registrationData[32]! | 4;
    expect(verifyRegistration({ ...registrationInput(), attestationObject: noneAttestation(registrationData), requireUserVerification: true }).alg).toBe(-7);
    const input = assertionInput();
    expectRejected(() => verifyAssertion({ ...input, requireUserVerification: true }), /UV|verification/i);
    for (const [flags, reason] of [[0x18, /UP|presence/i], [0x01, /BE|backup/i], [0x11, /BS|backup/i]] as const) {
      const data = Buffer.from(input.authenticatorData);
      data[32] = flags;
      expectRejected(() => verifyAssertion(resign({ ...input, authenticatorData: data })), reason);
    }
    expectRejected(() => verifyAssertion({ ...input, credential: { ...input.credential, rpId: 'other.example' } }), /rpId/);
    const uv = Buffer.from(input.authenticatorData);
    uv[32] = uv[32]! | 4;
    expect(verifyAssertion({ ...resign({ ...input, authenticatorData: uv }), requireUserVerification: true }).cloneWarning).toBe(false);
  });

  test.each([
    [0, 0, false], [0, 1, false], [1, 2, false], [1, 1, true], [2, 1, true], [1, 0, true], [0xffffffff, 0, true],
  ])('stored counter %i and new %i produce cloneWarning %s after signature verification', (stored, current, warning) => {
    const input = assertionInput();
    const data = Buffer.from(input.authenticatorData);
    data.writeUInt32BE(current, 33);
    const credential = { ...input.credential, signCount: stored };
    expect(verifyAssertion(resign({ ...input, credential, authenticatorData: data }))).toEqual({ signCount: current, cloneWarning: warning });
    expect(credential.signCount).toBe(stored);
    const signature = Buffer.from(input.signature);
    signature[0] = 0;
    expectRejected(() => verifyAssertion({ ...input, credential, authenticatorData: data, signature }), /signature/i);
  });

  test('backup status may change when backup eligibility remains true', () => {
    const input = assertionInput();
    const data = Buffer.from(input.authenticatorData);
    data[32] = data[32]! & ~0x10;
    expect(verifyAssertion(resign({ ...input, authenticatorData: data })).cloneWarning).toBe(false);
  });

  test('rejects assertion AT data, mismatched stored algorithms, malformed stored keys and invalid counters', () => {
    const input = assertionInput();
    const data = registrationAuthData();
    expectRejected(() => verifyAssertion(resign({ ...input, authenticatorData: data })), /attested|AT/i);
    expectRejected(() => verifyAssertion({ ...input, credential: { ...input.credential, alg: -8 } }), /alg|algorithm/i);
    for (const publicKeyCose of ['', '!', 'AA', `${input.credential.publicKeyCose}=`]) {
      expectRejected(() => verifyAssertion({ ...input, credential: { ...input.credential, publicKeyCose } }));
    }
    for (const signCount of [-1, 1.5, NaN, 0x100000000]) {
      expectRejected(() => verifyAssertion({ ...input, credential: { ...input.credential, signCount } }), /count|counter/i);
    }
  });

  test('ECDSA accepts only strict DER, rejecting P1363 and nonminimal ASN.1', () => {
    const input = assertionInput();
    const { key } = coseToPublicKey(decodeCbor(Buffer.from(input.credential.publicKeyCose, 'base64url')) as Map<number, unknown>);
    const privateKey = createPrivateKey({ format: 'jwk', key: { ...key.export({ format: 'jwk' }), d: hex(vector().registration.credential_private_key!).toString('base64url') } });
    const data = Buffer.concat([input.authenticatorData, createHash('sha256').update(input.clientDataJSON).digest()]);
    const raw = sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
    expect(raw.length).toBe(64);
    expectRejected(() => verifyAssertion({ ...input, signature: raw }), /DER|signature/i);
    const longLength = Buffer.concat([hex('3081'), input.signature.subarray(1)]);
    expectRejected(() => verifyAssertion({ ...input, signature: longLength }), /DER|signature/i);
    expectRejected(() => verifyAssertion({ ...input, signature: Buffer.concat([input.signature, hex('00')]) }), /DER|signature/i);
  });

  test('registration refuses an Ed25519 identity point that needs no private key', () => {
    const identity = Buffer.alloc(32);
    identity[0] = 1;
    const publicKeyCose = encode(new Map<number, unknown>([[1, 1], [3, -8], [-1, 6], [-2, identity]]));
    const data = registrationAuthData();
    const keyStart = 55 + data.readUInt16BE(53);
    expectRejected(() => verifyRegistration({
      ...registrationInput(), attestationObject: noneAttestation(Buffer.concat([data.subarray(0, keyStart), publicKeyCose])),
    }), /key|algorithm/i);
  });

  test('stored Ed25519 identity keys cannot approve fresh challenges with a constant forged signature', () => {
    const identity = Buffer.alloc(32);
    identity[0] = 1;
    const publicKeyCose = encode(new Map<number, unknown>([[1, 1], [3, -8], [-1, 6], [-2, identity]]));
    const credential = { ...credentialFromVector(), alg: -8 as const, publicKeyCose: publicKeyCose.toString('base64url') };
    const input = assertionInput('none-es256', credential);
    const signature = Buffer.alloc(64);
    signature[0] = 1;
    for (const expectedChallenge of [input.expectedChallenge, Buffer.alloc(32, 0x42)]) {
      const changed = changedClient(input, { challenge: expectedChallenge.toString('base64url') });
      expectRejected(() => verifyAssertion({ ...changed, expectedChallenge, signature }), /key|algorithm/i);
    }
  });

  test('malformed CBOR, authData and oversized inputs become safe WebAuthnErrors', () => {
    const input = registrationInput();
    for (const attestationObject of [hex('bf'), hex('a0'), hex('01'), Buffer.alloc(65537)]) {
      expectRejected(() => verifyRegistration({ ...input, attestationObject }));
    }
    const assertion = assertionInput();
    expectRejected(() => verifyAssertion({ ...assertion, authenticatorData: Buffer.alloc(36) }));
    expectRejected(() => verifyAssertion({ ...assertion, signature: Buffer.alloc(1025) }), /signature/i);
    try { verifyRegistration({ ...input, clientDataJSON: Buffer.from('{"private":"SENTINEL-DO-NOT-ECHO"') }); }
    catch (error) { expect(String(error)).not.toContain('SENTINEL'); }
  });
});
