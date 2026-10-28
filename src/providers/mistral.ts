import type { ProviderAdapter } from '../types.js';

/** Placeholder until the phase 6 adapter lands: guided rotation only, no network. */
export const mistralProvider: ProviderAdapter = {
  id: 'mistral',
  method: 'guided',
  async verify() { return { ok: true, identity: 'unverified' }; },
  guidance: () => ({ url: 'https://console.mistral.ai/api-keys', steps: [
    'Create a replacement key in the Mistral dashboard with the same access as the exposed one.',
    'Update every consumer and redeploy, verify the new key works, then delete the exposed key.',
  ] }),
};
