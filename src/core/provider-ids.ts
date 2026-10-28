import type { ProviderId } from '../types.js';

/** Every ProviderId, for runtime schemas (saved inventories, plans, hygiene state, dashboard settings). */
export const PROVIDER_IDS = ['openai', 'anthropic', 'openrouter', 'stripe', 'resend', 'cloudflare', 'github', 'aws', 'supabase', 'database',
  'slack', 'sendgrid', 'twilio', 'google', 'private-key', 'crypto-wallet', 'app-secret', 'encryption-key', 'unknown',
  'groq', 'mistral', 'replicate', 'postmark', 'clerk', 'upstash', 'neon'] as const satisfies readonly ProviderId[];

// Compile-time check that the list names every ProviderId.
const complete: [Exclude<ProviderId, typeof PROVIDER_IDS[number]>] extends [never] ? true : never = true;
void complete;
