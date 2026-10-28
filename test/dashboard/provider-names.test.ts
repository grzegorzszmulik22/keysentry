// @vitest-environment happy-dom
import { expect, test } from 'vitest';
import { providerName as cliName } from '../../src/cli/provider-names.js';
import { providerName as dashboardName } from '../../src/dashboard/client/screens/components-a.js';

// The browser bundle cannot import CLI code, so the dashboard keeps its own copy of the display names.
test('dashboard and terminal show the same provider names', () => {
  const ids = ['openai', 'anthropic', 'openrouter', 'stripe', 'resend', 'cloudflare', 'github', 'aws', 'supabase', 'database',
    'slack', 'sendgrid', 'twilio', 'google', 'private-key', 'crypto-wallet', 'app-secret', 'encryption-key', 'unknown',
    'groq', 'mistral', 'replicate', 'postmark', 'clerk', 'upstash', 'neon'];
  for (const id of ids) expect(dashboardName(id), id).toBe(cliName(id));
});
