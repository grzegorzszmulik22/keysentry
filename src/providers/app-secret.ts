import { randomBytes } from 'node:crypto';
import type { ProviderAdapter } from '../types.js';

/** Generate locally; plaintext is returned only in the rotation contract. */
function generateSecret(likeValue: string): string {
  const bytes = randomBytes(32);

  if (/^[0-9a-f]{32,128}$/i.test(likeValue) && likeValue.length % 2 === 0) {
    const value = bytes.toString('hex');
    return /[A-F]/.test(likeValue) && !/[a-f]/.test(likeValue) ? value.toUpperCase() : value;
  }

  // Padding or the standard-only alphabet makes base64 distinguishable from
  // base64url. Canonical round-tripping rejects arbitrary padded strings.
  if (/^[A-Za-z0-9+/]{32,126}={0,2}$/.test(likeValue) && /[+/=]/.test(likeValue)) {
    const decoded = Buffer.from(likeValue, 'base64');
    const canonical = decoded.toString('base64').replace(/=+$/, '');
    if (decoded.length >= 24 && decoded.length <= 64 && canonical === likeValue.replace(/=+$/, '')) {
      return bytes.toString('base64');
    }
  }

  return bytes.toString('base64url');
}

export const appSecretProvider: ProviderAdapter = {
  id: 'app-secret',
  method: 'generate',

  async verify() {
    return { ok: true };
  },

  async rotate(oldValue) {
    return {
      newValue: generateSecret(oldValue),
      oldKeyRef: null,
      newKeyRef: null,
      oldRevoked: false,
      notes: 'Sessions and JWTs signed with the old secret become invalid after consumers switch to the new secret.',
    };
  },

  guidance() {
    return {
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
      steps: [
        'Generate a fresh secret and update every consumer before redeploying each service.',
        'Sessions and JWTs signed with the old secret become invalid; plan for users to sign in again.',
      ],
    };
  },
};
