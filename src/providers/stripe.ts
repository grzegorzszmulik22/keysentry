import type { ProviderAdapter } from '../types.js';
import { verifyRead } from './shared.js';

export const stripeProvider: ProviderAdapter = {
  id: 'stripe',
  method: 'guided',
  async verify(value, ctx) {
    // A webhook signing secret cannot authenticate a Stripe API request.
    if (value.startsWith('whsec_')) return { ok: true, identity: 'unverified' };
    return verifyRead(ctx, {
      method: 'GET',
      url: 'https://api.stripe.com/v1/balance',
      headers: { Authorization: `Bearer ${value}` },
    }, 'Stripe', () => 'Stripe account');
  },
  guidance() {
    return {
      url: 'https://dashboard.stripe.com/apikeys',
      steps: [
        'Roll the API key in the Stripe dashboard and give the old key an expiry that allows time to update every consumer.',
        'For a webhook signing secret, open the webhook endpoint settings and roll its signing secret there; the API key page cannot roll webhook secrets.',
        'Update every consumer and redeploy, then verify API calls or webhook signature validation before the old secret expires.',
      ],
    };
  },
};
