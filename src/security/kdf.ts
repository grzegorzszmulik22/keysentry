// Passphrase-derived keys for the encrypted-file vault (scrypt; parameters stored next to the data).
import { scrypt } from 'node:crypto';

export interface ScryptParams {
  N: number;
  r: number;
  p: number;
}

export const DEFAULT_SCRYPT: ScryptParams = { N: 131072, r: 8, p: 1 };

const MAXMEM = 256 * 1024 * 1024;

export function deriveKeyFromPassphrase(passphrase: Buffer, salt: Buffer, params: ScryptParams = DEFAULT_SCRYPT): Promise<Buffer> {
  if (!Buffer.isBuffer(salt) || salt.length < 16) return Promise.reject(new TypeError('scrypt salt must be at least 16 bytes.'));
  return new Promise((resolve, reject) => {
    scrypt(passphrase, salt, 32, { N: params.N, r: params.r, p: params.p, maxmem: MAXMEM }, (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}
