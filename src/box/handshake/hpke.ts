// keysentry's versioned hybrid envelope; this is not an RFC 9180 HPKE encoding.
// Wire: ASCII KSB1 | 0x01 | ephemeral X25519 public (32) | GCM tag (16) | ciphertext.
import {
  KeyObject, createCipheriv, createDecipheriv, createPrivateKey, createPublicKey,
  diffieHellman, generateKeyPairSync, hkdfSync,
} from 'node:crypto';
import { DecryptError } from '../../security/index.js';

const MAGIC = Buffer.from('KSB1', 'ascii');
const VERSION = 1;
const PUBLIC_KEY_BYTES = 32;
const EPHEMERAL_OFFSET = 5;
const TAG_OFFSET = EPHEMERAL_OFFSET + PUBLIC_KEY_BYTES;
const CIPHERTEXT_OFFSET = TAG_OFFSET + 16;
const KDF_PREFIX = 'keysentry-box-seal:v1|';

export interface BoxKeyPair {
  publicKeyRaw: Buffer;
  privateKey: KeyObject;
}

function rawPublicKey(publicKey: KeyObject): Buffer {
  if (publicKey.asymmetricKeyType !== 'x25519' || publicKey.type !== 'public') throw new TypeError('Expected an X25519 public key.');
  const jwk = publicKey.export({ format: 'jwk' });
  if (typeof jwk.x !== 'string') throw new TypeError('Expected an X25519 public key.');
  const raw = Buffer.from(jwk.x, 'base64url');
  if (raw.length !== PUBLIC_KEY_BYTES) throw new TypeError('Expected a 32-byte X25519 public key.');
  return raw;
}

function importPublicKey(raw: Buffer): KeyObject {
  return createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: raw.toString('base64url') }, format: 'jwk' });
}

function deriveMaterial(privateKey: KeyObject, peer: KeyObject, ephemeralRaw: Buffer, boxRaw: Buffer, info: string): Buffer {
  const shared = diffieHellman({ privateKey, publicKey: peer });
  try {
    // OpenSSL rejects low-order inputs; keep the zero check explicit across implementations.
    if (shared.length !== 32 || shared.every((byte) => byte === 0)) throw new Error('Invalid X25519 shared secret.');
    return Buffer.from(hkdfSync('sha256', shared, Buffer.concat([ephemeralRaw, boxRaw]),
      Buffer.from(KDF_PREFIX + info, 'utf8'), 44));
  } finally {
    shared.fill(0);
  }
}

export function generateBoxKeyPair(): BoxKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  return { publicKeyRaw: rawPublicKey(publicKey), privateKey };
}

/** Fresh ephemeral key per call; key and nonce are derived together, never caller supplied. */
export function sealToBox(boxPublicKeyRaw: Buffer, plaintext: Buffer, info: string): Buffer {
  if (!Buffer.isBuffer(boxPublicKeyRaw) || boxPublicKeyRaw.length !== PUBLIC_KEY_BYTES) {
    throw new TypeError('Box public key must be exactly 32 bytes.');
  }
  if (!Buffer.isBuffer(plaintext)) throw new TypeError('Box plaintext must be a Buffer.');
  if (typeof info !== 'string') throw new TypeError('Box encryption context must be a string.');
  let material: Buffer | undefined;
  try {
    const ephemeral = generateKeyPairSync('x25519');
    const ephemeralRaw = rawPublicKey(ephemeral.publicKey);
    material = deriveMaterial(ephemeral.privateKey, importPublicKey(boxPublicKeyRaw), ephemeralRaw, boxPublicKeyRaw, info);
    const cipher = createCipheriv('aes-256-gcm', material.subarray(0, 32), material.subarray(32), { authTagLength: 16 });
    cipher.setAAD(Buffer.from(info, 'utf8'));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([MAGIC, Buffer.of(VERSION), ephemeralRaw, cipher.getAuthTag(), ciphertext]);
  } catch {
    throw new Error('Could not encrypt for this box.');
  } finally {
    material?.fill(0);
  }
}

/** Buffer private keys use PKCS8 DER. Failures expose neither plaintext nor key material. */
export function openAsBox(boxPrivateKey: KeyObject | Buffer, sealed: Buffer, info: string): Buffer {
  let material: Buffer | undefined;
  let opened: Buffer | undefined;
  try {
    if (!Buffer.isBuffer(sealed) || sealed.length < CIPHERTEXT_OFFSET || typeof info !== 'string') throw new Error();
    if (!sealed.subarray(0, MAGIC.length).equals(MAGIC) || sealed[MAGIC.length] !== VERSION) throw new Error();
    const privateKey = Buffer.isBuffer(boxPrivateKey)
      ? createPrivateKey({ key: boxPrivateKey, format: 'der', type: 'pkcs8' }) : boxPrivateKey;
    if (!(privateKey instanceof KeyObject) || privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'x25519') throw new Error();
    const boxRaw = rawPublicKey(createPublicKey(privateKey));
    const ephemeralRaw = sealed.subarray(EPHEMERAL_OFFSET, TAG_OFFSET);
    material = deriveMaterial(privateKey, importPublicKey(ephemeralRaw), ephemeralRaw, boxRaw, info);
    const decipher = createDecipheriv('aes-256-gcm', material.subarray(0, 32), material.subarray(32), { authTagLength: 16 });
    decipher.setAAD(Buffer.from(info, 'utf8'));
    decipher.setAuthTag(sealed.subarray(TAG_OFFSET, CIPHERTEXT_OFFSET));
    opened = decipher.update(sealed.subarray(CIPHERTEXT_OFFSET));
    return Buffer.concat([opened, decipher.final()]);
  } catch {
    throw new DecryptError();
  } finally {
    opened?.fill(0);
    material?.fill(0);
  }
}
