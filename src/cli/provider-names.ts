/** Product names for human-facing views. The dashboard keeps a browser-side copy; test/dashboard/provider-names.test.ts keeps them equal. */
const providers: Readonly<Record<string, string>> = {
  openai: 'OpenAI', anthropic: 'Anthropic', openrouter: 'OpenRouter', stripe: 'Stripe', resend: 'Resend',
  cloudflare: 'Cloudflare', github: 'GitHub', aws: 'AWS', supabase: 'Supabase', database: 'Database', slack: 'Slack',
  sendgrid: 'SendGrid', twilio: 'Twilio', google: 'Google', 'private-key': 'Private key', 'crypto-wallet': 'Wallet',
  'app-secret': 'App secret', 'encryption-key': 'Encryption key', unknown: 'Unknown provider',
  groq: 'Groq', mistral: 'Mistral', replicate: 'Replicate', postmark: 'Postmark', clerk: 'Clerk', upstash: 'Upstash', neon: 'Neon',
};

export function providerName(provider: string): string { return providers[provider] ?? provider; }

/** Core reports delimit provider labels with a middle dot; IDs, URLs and variable names stay untouched. */
export function humanizeProviderNames(text: string): string {
  return text.replace(/( · )([a-z][a-z-]*)(?= ·|\r?$)/gm, (_match, separator: string, provider: string) => separator + providerName(provider));
}
