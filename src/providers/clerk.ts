import type { ProviderAdapter } from '../types.js';

/** Placeholder until the phase 6 adapter lands: guided rotation only, no network. */
export const clerkProvider: ProviderAdapter = {
  id: 'clerk',
  method: 'guided',
  async verify() { return { ok: true, identity: 'unverified' }; },
  guidance: () => ({ url: 'https://dashboard.clerk.com/', steps: [
    'Create a replacement key in the Clerk dashboard with the same access as the exposed one.',
    'Update every consumer and redeploy, verify the new key works, then delete the exposed key.',
  ] }),
};
