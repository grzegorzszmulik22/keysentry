// Authenticated encryption for everything keysentry writes to disk.
// Format: ASCII "KS1" + version 0x01 + 12-byte IV + 16-byte GCM tag + ciphertext (AES-256-GCM, aad = UTF-8 label).
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const MAGIC = Buffer.from('KS1', 'ascii');
const VERSION = 0x01;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const HEADER_BYTES = MAGIC.length + 1;
const MIN_BYTES = HEADER_BYTES + IV_BYTES + TAG_BYTES;

/** The data was altered, the label differs, or the key is wrong. The message never includes data or keys. */
export class DecryptError extends Error {
  readonly code = 'DECRYPT_FAILED';
  constructor(message = 'Could not decrypt: the data was changed, or it was encrypted with a different key.') {
    super(message);
    this.name = 'DecryptError';
  }
}

function assertKey(key: Buffer): void {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new TypeError('Encryption key must be exactly 32 bytes.');
}

export function sealBytes(key: Buffer, plaintext: Buffer, aad: string): Buffer {
  assertKey(key);
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([MAGIC, Buffer.of(VERSION), iv, cipher.getAuthTag(), ct]);
}

export function openBytes(key: Buffer, sealed: Buffer, aad: string): Buffer {
  assertKey(key);
  if (!Buffer.isBuffer(sealed) || sealed.length < MIN_BYTES) throw new DecryptError('Could not decrypt: the data is truncated.');
  if (!sealed.subarray(0, MAGIC.length).equals(MAGIC) || sealed[MAGIC.length] !== VERSION) {
    throw new DecryptError('Could not decrypt: unknown format.');
  }
  const iv = sealed.subarray(HEADER_BYTES, HEADER_BYTES + IV_BYTES);
  const tag = sealed.subarray(HEADER_BYTES + IV_BYTES, MIN_BYTES);
  const ct = sealed.subarray(MIN_BYTES);
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new DecryptError();
  }
}
