import type { ProviderAdapter } from '../types.js';
import { verifyRead } from './shared.js';

// Clerk instance secret keys are created and deleted in the Dashboard (https://clerk.com/docs/guides/secure/rotate-api-keys).
// The Platform API's rotate_secret_keys (private beta) rotates an instance's secret keys as a whole and cannot target
// one exposed key, so rotation stays guided. verify reads the instance JWKS with the key. Details: notes/providers-b.md.

const PROVIDER = 'Clerk';
const SECRET_KEY = /^sk_(live|test)_[A-Za-z0-9]+$/;

export const clerkProvider: ProviderAdapter = {
  id: 'clerk',
  method: 'guided',

  async verify(value, ctx) {
    const kind = SECRET_KEY.exec(value)?.[1];
    // Webhook signing secrets and other Clerk values have no authenticated read.
    if (!kind) return { ok: true, identity: 'unverified' };
    return verifyRead(ctx, {
      method: 'GET',
      url: 'https://api.clerk.com/v1/jwks',
      headers: { Authorization: `Bearer ${value}` },
    }, PROVIDER, (data) => {
      if (data === null || typeof data !== 'object' || !Array.isArray((data as Record<string, unknown>).keys)) {
        throw new Error('Invalid Clerk JWKS response');
      }
      return kind === 'live' ? 'Clerk production instance' : 'Clerk development instance';
    });
  },

  guidance() {
    return {
      url: 'https://dashboard.clerk.com/last-active?path=api-keys',
      steps: [
        'In the Clerk Dashboard, select the application and environment, open API keys, and under Secret keys add a new key named for its consumer; give it the same IP restriction as the exposed key, if it had one.',
        'Update CLERK_SECRET_KEY in every consumer and redeploy, then confirm the new key shows recent use.',
        'Delete the exposed key under Secret keys once its Last used time stops advancing. For a webhook signing secret, create a new webhook endpoint, switch to its signing secret, then delete the old endpoint.',
      ],
    };
  },
};
