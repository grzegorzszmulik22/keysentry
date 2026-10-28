import type { ProviderAdapter } from '../types.js';
import { safeIdentity, verifyRead } from './shared.js';

// Replicate documents no API for creating or deleting API tokens (https://replicate.com/docs/reference/http), so
// rotation stays guided. verify reads the account the token belongs to. Details: notes/providers-b.md.

const PROVIDER = 'Replicate';
/** Shared safeIdentity does not know Replicate token shapes. */
const TOKEN_SHAPE = /r8_[A-Za-z0-9]{20,}/;

export const replicateProvider: ProviderAdapter = {
  id: 'replicate',
  method: 'guided',

  verify(value, ctx) {
    return verifyRead(ctx, {
      method: 'GET',
      url: 'https://api.replicate.com/v1/account',
      headers: { Authorization: `Bearer ${value}` },
    }, PROVIDER, (data) => {
      if (data === null || typeof data !== 'object' || Array.isArray(data)) throw new Error('Invalid Replicate account response');
      const username = safeIdentity((data as Record<string, unknown>).username, '', [value]);
      return username && !TOKEN_SHAPE.test(username) ? username : 'Replicate account';
    });
  },

  guidance() {
    return {
      url: 'https://replicate.com/account/api-tokens',
      steps: [
        'Create a replacement API token for the same user or organization account in Replicate.',
        'Update every consumer and redeploy, then verify the replacement token.',
        'Delete the exposed token on the API tokens page; Replicate documents no API for creating or deleting tokens.',
      ],
    };
  },
};
