import { generateKeyPairSync, sign, verify, type KeyObject } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { coseToPublicKey } from '../../../src/approvals/webauthn/cose.js';

const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const ed = generateKeyPairSync('ed25519');
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 65537 });
const smallRsa = generateKeyPairSync('rsa', { modulusLength: 1024, publicExponent: 65537 });
const message = Buffer.from('one approval action');

function publicMap(key: KeyObject): Map<number, unknown> {
  const jwk = key.export({ format: 'jwk' });
  const bytes = (s: string | undefined): Buffer => Buffer.from(s!, 'base64url');
  if (jwk.kty === 'EC') {
    return new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, bytes(jwk.x)], [-3, bytes(jwk.y)]]);
  }
  if (jwk.kty === 'OKP') {
    return new Map<number, unknown>([[1, 1], [3, -8], [-1, 6], [-2, bytes(jwk.x)]]);
  }
  return new Map<number, unknown>([[1, 3], [3, -257], [-1, bytes(jwk.n)], [-2, bytes(jwk.e)]]);
}

function changed(key: KeyObject, label: number, value: unknown): Map<number, unknown> {
  return publicMap(key).set(label, value);
}

describe('coseToPublicKey', () => {
  test.each([
    { name: 'ES256 P-256', pair: ec, alg: -7, digest: 'sha256' },
    { name: 'EdDSA Ed25519', pair: ed, alg: -8, digest: null },
    { name: 'RS256 2048-bit RSA', pair: rsa, alg: -257, digest: 'sha256' },
  ])('imports $name as a public key that verifies a signature', ({ pair, alg, digest }) => {
    const result = coseToPublicKey(publicMap(pair.publicKey));
    expect(result.alg).toBe(alg);
    expect(result.key.type).toBe('public');
    expect(verify(digest, message, result.key, sign(digest, message, pair.privateKey))).toBe(true);
    expect(verify(digest, Buffer.from('a different approval action'), result.key,
      sign(digest, message, pair.privateKey))).toBe(false);
  });

  test.each([ec, ed, rsa])('accepts explicit verify-only operations and public metadata', (pair) => {
    const cose = publicMap(pair.publicKey)
      .set(2, Buffer.from('credential key identifier'))
      .set(4, [2])
      .set(5, Buffer.from('initialization vector'));
    expect(coseToPublicKey(cose).key.type).toBe('public');
  });

  test.each([
    { name: 'an unsupported algorithm', key: ec.publicKey, label: 3, value: -35 },
    { name: 'a string algorithm', key: ec.publicKey, label: 3, value: '-7' },
    { name: 'ES256 with OKP key type', key: ec.publicKey, label: 1, value: 1 },
    { name: 'EdDSA with EC2 key type', key: ed.publicKey, label: 1, value: 2 },
    { name: 'RS256 with EC2 key type', key: rsa.publicKey, label: 1, value: 2 },
    { name: 'a symmetric key type', key: rsa.publicKey, label: 1, value: 4 },
    { name: 'P-384 coordinates under ES256', key: ec.publicKey, label: -1, value: 2 },
    { name: 'a string P-256 curve', key: ec.publicKey, label: -1, value: '1' },
    { name: 'Ed448 under EdDSA', key: ed.publicKey, label: -1, value: 7 },
    { name: 'X25519 under EdDSA', key: ed.publicKey, label: -1, value: 4 },
  ])('rejects $name', ({ key, label, value }) => {
    expect(() => coseToPublicKey(changed(key, label, value))).toThrow();
  });

  test.each([1, 3, -1, -2, -3])('requires ES256 field %i', (label) => {
    const cose = publicMap(ec.publicKey);
    cose.delete(label);
    expect(() => coseToPublicKey(cose)).toThrow();
  });

  test.each([
    { name: 'short x', label: -2, value: Buffer.alloc(31) },
    { name: 'long x', label: -2, value: Buffer.alloc(33) },
    { name: 'a string x', label: -2, value: 'untrusted coordinate text' },
    { name: 'a Uint8Array x', label: -2, value: new Uint8Array(32) },
    { name: 'short y', label: -3, value: Buffer.alloc(31) },
    { name: 'long y', label: -3, value: Buffer.alloc(33) },
    { name: 'compressed positive y', label: -3, value: true },
    { name: 'compressed negative y', label: -3, value: false },
  ])('rejects ES256 with $name', ({ label, value }) => {
    expect(() => coseToPublicKey(changed(ec.publicKey, label, value))).toThrow();
  });

  test.each([0, 255])('rejects an invalid P-256 point filled with %i', (byte) => {
    const cose = changed(ec.publicKey, -2, Buffer.alloc(32, byte)).set(-3, Buffer.alloc(32, byte));
    expect(() => coseToPublicKey(cose)).toThrow();
  });

  test.each([Buffer.alloc(0), Buffer.alloc(31), Buffer.alloc(33), 'untrusted public key', true])(
    'rejects malformed Ed25519 x %s', (value) => {
      expect(() => coseToPublicKey(changed(ed.publicKey, -2, value))).toThrow();
    },
  );

  for (const signBit of [0, 0x80]) {
    test.each([
      { name: 'order-four y=0', hex: '00'.repeat(32) },
      { name: 'identity y=1', hex: `01${'00'.repeat(31)}` },
      { name: 'order-two y=p-1', hex: `ec${'ff'.repeat(30)}7f` },
      { name: 'first order-eight y', hex: '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05' },
      { name: 'second order-eight y', hex: 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a' },
    ])(`rejects Ed25519 small-order $name with sign bit ${signBit === 0 ? 0 : 1}`, ({ hex }) => {
      const encoding = Buffer.from(hex, 'hex');
      encoding[31] = encoding[31]! | signBit;
      const original = Buffer.from(encoding);
      expect(() => coseToPublicKey(changed(ed.publicKey, -2, encoding))).toThrow();
      expect(encoding).toEqual(original);
    });

    test.each(Array.from({ length: 19 }, (_, offset) => ({ offset }))) (
      `rejects noncanonical Ed25519 y=p+$offset with sign bit ${signBit === 0 ? 0 : 1}`,
      ({ offset }) => {
        // All 19 noncanonical field values fit in the 255-bit y encoding.
        const encoding = Buffer.alloc(32, 0xff);
        encoding[0] = 0xed + offset;
        encoding[31] = 0x7f | signBit;
        const original = Buffer.from(encoding);
        expect(() => coseToPublicKey(changed(ed.publicKey, -2, encoding))).toThrow();
        expect(encoding).toEqual(original);
      },
    );
  }

  test('rejects RSA below 2048 bits', () => {
    expect(() => coseToPublicKey(publicMap(smallRsa.publicKey))).toThrow();
  });

  test.each([
    { name: '2047 actual bits in 256 bytes', n: Buffer.concat([Buffer.from([0x7f]), Buffer.alloc(255, 0xff)]) },
    { name: 'a leading zero padding an undersized modulus', n: Buffer.concat([Buffer.from([0]), Buffer.alloc(255, 0xff)]) },
    { name: 'a leading zero padding a valid modulus', n: Buffer.concat([Buffer.from([0]), publicMap(rsa.publicKey).get(-1) as Buffer]) },
    { name: 'an even modulus', n: Buffer.concat([Buffer.from([0x80]), Buffer.alloc(255)]) },
    { name: 'more than 8192 bits', n: Buffer.alloc(1025, 0xff) },
    { name: 'an empty modulus', n: Buffer.alloc(0) },
    { name: 'a string modulus', n: 'untrusted modulus text' },
  ])('rejects RSA with $name', ({ n }) => {
    expect(() => coseToPublicKey(changed(rsa.publicKey, -1, n))).toThrow();
  });

  test.each([Buffer.from([3]), Buffer.from([0, 1, 0, 1]), Buffer.alloc(0), 65537, 'AQAB'])(
    'rejects noncanonical or unsupported RSA exponent %s', (value) => {
      expect(() => coseToPublicKey(changed(rsa.publicKey, -2, value))).toThrow();
    },
  );

  test.each([
    { name: 'EC private d', key: ec.publicKey, label: -4 },
    { name: 'OKP private d', key: ed.publicKey, label: -4 },
    ...[-3, -4, -5, -6, -7, -8, -9, -10, -11, -12].map((label) => (
      { name: `RSA private parameter ${label}`, key: rsa.publicKey, label }
    )),
  ])('rejects $name, including an undefined value', ({ key, label }) => {
    expect(() => coseToPublicKey(changed(key, label, Buffer.from('private component')))).toThrow();
    expect(() => coseToPublicKey(changed(key, label, undefined))).toThrow();
  });

  test.each([
    { name: 'an empty operation list', value: [] },
    { name: 'sign only', value: [1] },
    { name: 'sign and verify', value: [1, 2] },
    { name: 'duplicate verify operations', value: [2, 2] },
    { name: 'encrypt only', value: [3] },
    { name: 'a text operation', value: ['verify'] },
    { name: 'a string', value: 'verify' },
    { name: 'a byte string', value: Buffer.from([2]) },
    { name: 'undefined', value: undefined },
  ])(
    'rejects key_ops containing $name', ({ value }) => {
      expect(() => coseToPublicKey(changed(ec.publicKey, 4, value))).toThrow();
    },
  );

  test.each([2, 5])('requires public metadata field %i to contain bounded bytes', (label) => {
    expect(() => coseToPublicKey(changed(ec.publicKey, label, 'untrusted metadata'))).toThrow();
    expect(() => coseToPublicKey(changed(ec.publicKey, label, Buffer.alloc(1025)))).toThrow();
  });

  test.each([
    { name: 'an unsupported Ed25519 y coordinate', cose: changed(ed.publicKey, -3, Buffer.alloc(32)) },
    { name: 'an unsupported public label', cose: changed(ec.publicKey, 99, Buffer.from('unknown')) },
    { name: 'an unsupported negative label', cose: changed(ec.publicKey, -99, Buffer.from('unknown')) },
    { name: 'a noninteger label', cose: changed(ec.publicKey, 1.5, 2) },
  ])('rejects $name', ({ cose }) => {
    expect(() => coseToPublicKey(cose)).toThrow();
  });

  test('rejects string labels and non-map inputs at runtime', () => {
    const cose = publicMap(ec.publicKey) as Map<unknown, unknown>;
    cose.set('3', -7);
    expect(() => coseToPublicKey(cose as Map<number, unknown>)).toThrow();
    expect(() => coseToPublicKey({} as Map<number, unknown>)).toThrow();
  });

  test('errors contain no input material or underlying crypto details', () => {
    const sentinel = 'untrusted public key marker';
    const failures = [
      changed(ec.publicKey, -2, sentinel),
      changed(ec.publicKey, -2, Buffer.alloc(32)).set(-3, Buffer.alloc(32)),
      changed(rsa.publicKey, -3, Buffer.from(sentinel)),
    ];
    const messages = failures.map((cose) => {
      let rejection: unknown;
      try {
        coseToPublicKey(cose);
      } catch (error) {
        rejection = error;
      }
      expect(rejection).toBeInstanceOf(Error);
      expect((rejection as Error).message).not.toContain(sentinel);
      expect(rejection).not.toHaveProperty('cause');
      return (rejection as Error).message;
    });
    expect(new Set(messages).size).toBe(1);
  });
});
