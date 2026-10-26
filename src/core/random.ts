import { randomBytes } from 'node:crypto';

/** Generates 256 bits of entropy, keeping an unambiguous nearby input format. */
export function generateSecret(likeValue?: string): string {
  const bytes = randomBytes(32);

  // Nearby formats mean 28–36 decoded bytes; output always contains 32 bytes.
  if (likeValue !== undefined && /^(?:[a-fA-F0-9]{2}){28,36}$/.test(likeValue)) {
    return bytes.toString('hex');
  }

  if (likeValue !== undefined
    && likeValue.length >= 38 && likeValue.length <= 48
    && /[+/=]/.test(likeValue)
    && /^[A-Za-z0-9+/]+={0,2}$/.test(likeValue)) {
    const decoded = Buffer.from(likeValue, 'base64');
    const canonical = decoded.toString('base64');
    if (decoded.length >= 28 && decoded.length <= 36
      && (canonical === likeValue || canonical.replace(/=+$/, '') === likeValue)) {
      return bytes.toString('base64');
    }
  }

  return bytes.toString('base64url');
}
