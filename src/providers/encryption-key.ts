import type { ProviderAdapter } from '../types.js';

/** Data migration is application-specific and cannot safely be automated here. */
export const encryptionKeyProvider: ProviderAdapter = {
  id: 'encryption-key',
  method: 'guided',
  async verify() {
    return { ok: true, identity: 'unverified' };
  },
  guidance() {
    return {
      url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
      steps: [
        'Replacing a data-encryption key requires re-encrypting existing data first; never swap the variable on its own.',
        'Use the application’s supported key migration procedure, retaining access to the old key until existing data is re-encrypted and verified with the replacement.',
        'After the migration, update every consumer, redeploy, and verify that both existing and newly written data can be decrypted before retiring the old key.',
      ],
    };
  },
};
