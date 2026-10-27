import { createPublicKey, type JsonWebKey, type KeyObject } from 'node:crypto';

const REJECTION = 'The credential public key is not supported or is invalid.';
const COMMON_LABELS = [1, 2, 3, 4, 5];
const ED25519_FIELD_PRIME_BE = Buffer.from(`7f${'ff'.repeat(30)}ed`, 'hex');
// Canonical small-order y encodings, also present in libsodium's Ed25519 blocklist.
// Matching after masking x's sign bit covers both signs, including negative zero.
const ED25519_SMALL_ORDER_Y = new Set([
  '00'.repeat(32),
  `01${'00'.repeat(31)}`,
  `ec${'ff'.repeat(30)}7f`,
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
]);

function reject(): never {
  throw new Error(REJECTION);
}

function bytes(value: unknown, length: number): Buffer {
  if (!Buffer.isBuffer(value) || value.length !== length) reject();
  return value;
}

function validateEd25519Encoding(x: Buffer): void {
  // Ed25519 encodes y little-endian with x's sign in the highest bit.
  // Copy before masking and reversing so the caller's COSE bytes stay intact.
  const y = Buffer.from(x);
  y[31] = y[31]! & 0x7f;
  if (ED25519_SMALL_ORDER_Y.has(y.toString('hex'))) reject();
  // A byte comparison in big-endian order checks y < 2^255 - 19.
  if (y.reverse().compare(ED25519_FIELD_PRIME_BE) >= 0) reject();
}

function validateLabels(cose: Map<number, unknown>, publicLabels: number[]): void {
  const allowed = new Set([...COMMON_LABELS, ...publicLabels]);
  for (const label of cose.keys()) {
    if (!allowed.has(label)) reject();
  }
  for (const label of [2, 5]) {
    if (!cose.has(label)) continue;
    const metadata = cose.get(label);
    if (!Buffer.isBuffer(metadata) || metadata.length > 1024) reject();
  }
  if (cose.has(4)) {
    const operations = cose.get(4);
    if (!Array.isArray(operations) || operations.length !== 1 || operations[0] !== 2) reject();
  }
}

/** Imports only public keys for the three supported WebAuthn signature algorithms. */
export function coseToPublicKey(cose: Map<number, unknown>): { key: KeyObject; alg: -7 | -8 | -257 } {
  try {
    if (!(cose instanceof Map) || cose.size > 8) reject();
    const alg = cose.get(3);
    let jwk: JsonWebKey;

    if (alg === -7 && cose.get(1) === 2) {
      validateLabels(cose, [-1, -2, -3]);
      if (cose.get(-1) !== 1) reject();
      const x = bytes(cose.get(-2), 32);
      // A boolean y is the compressed COSE representation, which is not supported.
      const y = bytes(cose.get(-3), 32);
      jwk = { kty: 'EC', crv: 'P-256', x: x.toString('base64url'), y: y.toString('base64url') };
    } else if (alg === -8 && cose.get(1) === 1) {
      validateLabels(cose, [-1, -2]);
      if (cose.get(-1) !== 6) reject();
      const x = bytes(cose.get(-2), 32);
      validateEd25519Encoding(x);
      jwk = { kty: 'OKP', crv: 'Ed25519', x: x.toString('base64url') };
    } else if (alg === -257 && cose.get(1) === 3) {
      validateLabels(cose, [-1, -2]);
      const n = cose.get(-1);
      const e = bytes(cose.get(-2), 3);
      // COSE unsigned integers have no leading zero; cap the modulus at 8192 bits.
      if (!Buffer.isBuffer(n) || n.length < 256 || n.length > 1024 || n[0] === 0) reject();
      const bitLength = (n.length - 1) * 8 + 32 - Math.clz32(n[0]!);
      if (bitLength < 2048 || (n[n.length - 1]! & 1) !== 1) reject();
      if (e[0] !== 1 || e[1] !== 0 || e[2] !== 1) reject();
      jwk = { kty: 'RSA', n: n.toString('base64url'), e: e.toString('base64url') };
    } else {
      reject();
    }

    // The EC import also rejects coordinates that are not a point on P-256.
    return { key: createPublicKey({ key: jwk, format: 'jwk' }), alg };
  } catch {
    // Crypto diagnostics can contain supplied input; expose only a static error.
    throw new Error(REJECTION);
  }
}
