import type { ProviderAdapter } from '../types.js';

/** Placeholder until the phase 6 adapter lands: guided rotation only, no network. */
export const upstashProvider: ProviderAdapter = {
  id: 'upstash',
  method: 'guided',
  async verify() { return { ok: true, identity: 'unverified' }; },
  guidance: () => ({ url: 'https://console.upstash.com/', steps: [
    'Create a replacement key in the Upstash dashboard with the same access as the exposed one.',
    'Update every consumer and redeploy, verify the new key works, then delete the exposed key.',
  ] }),
};
