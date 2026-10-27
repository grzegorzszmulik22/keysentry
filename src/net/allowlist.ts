import { isIP } from 'node:net';
import { createRedactor } from '../core/redact.js';
import type { EgressRule } from '../types.js';

/** Reviewed network destinations. Guidance URLs alone never grant network access. */
export const EGRESS_RULES: readonly EgressRule[] = [
  { host: 'backboard.railway.com', owner: 'railway', purpose: 'Railway GraphQL API' },
  { host: 'api.vercel.com', owner: 'vercel', purpose: 'Vercel projects, variables and deployments' },
  { host: 'api.render.com', owner: 'render', purpose: 'Render services, variables and deployments' },
  { host: 'api.machines.dev', owner: 'fly', purpose: 'Fly Machines API' },
  { host: 'api.fly.io', owner: 'fly', purpose: 'Fly GraphQL secrets API' },
  { host: 'api.github.com', owner: 'github-actions', purpose: 'GitHub API (Actions secrets, secret-scanning alerts)' },
  { host: 'api.openai.com', owner: 'openai', purpose: 'OpenAI key verification, management and usage' },
  { host: 'api.anthropic.com', owner: 'anthropic', purpose: 'Anthropic key verification, management and usage' },
  { host: 'openrouter.ai', owner: 'openrouter', purpose: 'OpenRouter key verification, management and usage' },
  { host: 'api.resend.com', owner: 'resend', purpose: 'Resend key verification and management' },
  { host: 'api.cloudflare.com', owner: 'cloudflare', purpose: 'Cloudflare token verification and rotation' },
  { host: 'iam.amazonaws.com', owner: 'aws', purpose: 'AWS IAM access key creation and deletion' },
  { host: 'sts.amazonaws.com', owner: 'aws', purpose: 'AWS STS caller identity verification' },
  { host: 'api.supabase.com', owner: 'supabase', purpose: 'Supabase management API' },
  { host: '*.supabase.co', owner: 'supabase', purpose: 'Supabase hosted project key verification' },
  { host: 'api.stripe.com', owner: 'stripe', purpose: 'Stripe API key verification' },
  { host: 'api.sendgrid.com', owner: 'sendgrid', purpose: 'SendGrid API key verification' },
  { host: 'slack.com', owner: 'slack', purpose: 'Slack API token verification' },
  { host: 'blog.railway.com', owner: 'feed', purpose: 'Railway blog breach advisory feed' },
  { host: 'railway.com', owner: 'feed', purpose: 'Railway changelog breach advisory feed' },
  { host: 'vercel.com', owner: 'feed', purpose: 'Vercel breach advisory feed' },
  { host: 'www.vercel-status.com', owner: 'feed', purpose: 'Vercel status breach advisory feed' },
  { host: 'render.com', owner: 'feed', purpose: 'Render blog breach advisory feed' },
  { host: 'status.render.com', owner: 'feed', purpose: 'Render status breach advisory feed' },
  { host: 'fly.io', owner: 'feed', purpose: 'Fly blog breach advisory feed' },
  { host: 'status.flyio.net', owner: 'feed', purpose: 'Fly status breach advisory feed' },
  { host: 'github.blog', owner: 'feed', purpose: 'GitHub changelog breach advisory feed' },
  { host: 'github.com', owner: 'release', purpose: 'keysentry release downloads' },
  { host: 'objects.githubusercontent.com', owner: 'release', purpose: 'GitHub release download assets' },
  { host: 'release-assets.githubusercontent.com', owner: 'release', purpose: 'GitHub release download assets' },
];

/** Dashboard and documentation destinations that the adapters only show to people. */
export const DISPLAY_ONLY_URL_HOSTS: readonly string[] = [
  'api.slack.com',
  'app.sendgrid.com',
  'cheatsheetseries.owasp.org',
  'console.aws.amazon.com',
  'console.cloud.google.com',
  'console.twilio.com',
  'dash.cloudflare.com',
  'dashboard.stripe.com',
  'ethereum.org',
  'owasp.org',
  'platform.claude.com',
  'platform.openai.com',
  'resend.com',
  'supabase.com',
  'www.openssh.com',
];

function normalizedHost(host: string): string {
  return host.toLowerCase().replace(/\.$/, '');
}

function validAuthority(url: URL): boolean {
  const host = normalizedHost(url.hostname);
  return url.protocol === 'https:' && !url.username && !url.password
    && (!url.port || url.port === '443') && host.length > 0 && !host.includes('*')
    && isIP(host.replace(/^\[|\]$/g, '')) === 0;
}

/** Match hosts only after enforcing the transport and authority restrictions. */
export function matchRule(url: URL, rules: readonly EgressRule[]): EgressRule | null {
  if (!validAuthority(url)) return null;
  const host = normalizedHost(url.hostname);
  // An exact rule is more specific than a suffix rule, including user additions.
  const exact = rules.find(rule => normalizedHost(rule.host) === host);
  if (exact) return exact;
  return rules.find(rule => {
    const allowed = normalizedHost(rule.host);
    return allowed.startsWith('*.') && allowed.length > 2 && host.endsWith(allowed.slice(1))
      && host.length > allowed.length - 1;
  }) ?? null;
}

/** User configuration authorizes only the named host, never its siblings or parent. */
export function rulesForUserUrls(urls: string[], purpose: string): EgressRule[] {
  const rules = new Map<string, EgressRule>();
  for (const value of urls) {
    let url: URL;
    try { url = new URL(value); }
    catch { throw new TypeError('Invalid user URL host: (unparseable)'); }
    const host = normalizedHost(url.hostname);
    if (!validAuthority(url)) throw new TypeError(`Invalid user URL host: ${createRedactor().redact(host) || '(unparseable)'}`);
    rules.set(host, { host, purpose, owner: 'user' });
  }
  return [...rules.values()];
}

export function rulesForUserFeeds(urls: string[]): EgressRule[] {
  return rulesForUserUrls(urls, 'breach feed you configured');
}
