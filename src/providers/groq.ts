import type { ProviderAdapter } from '../types.js';
import { verifyRead } from './shared.js';

// Groq documents no API for creating or deleting API keys (https://console.groq.com/docs/api-reference), so
// rotation stays guided. verify lists models with the key itself. Details: notes/providers-b.md.

const PROVIDER = 'Groq';

export const groqProvider: ProviderAdapter = {
  id: 'groq',
  method: 'guided',

  verify(value, ctx) {
    return verifyRead(ctx, {
      method: 'GET',
      url: 'https://api.groq.com/openai/v1/models',
      headers: { Authorization: `Bearer ${value}` },
    }, PROVIDER, (data) => {
      if (data === null || typeof data !== 'object' || !Array.isArray((data as Record<string, unknown>).data)) {
        throw new Error('Invalid Groq models response');
      }
      return 'Groq API key';
    });
  },

  guidance() {
    return {
      url: 'https://console.groq.com/keys',
      steps: [
        'Create a replacement API key in the Groq console, in the same organization and project as the exposed key.',
        'Update every consumer and redeploy, then verify the replacement key.',
        'Delete the exposed key in the Groq console; Groq documents no API for creating or deleting keys.',
      ],
    };
  },
};
