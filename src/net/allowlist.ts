import { isIP } from 'node:net';
import { createRedactor } from '../core/redact.js';
import type { EgressRule } from '../types.js';

/** Provenance for user additions; kept local until it is part of the shared contract. */
export type SourcedEgressRule = EgressRule & { source?: 'config' | 'env' };

export function describeRuleSource(rule: SourcedEgressRule):
  'built in' | 'added by you in keysentry.yaml' | 'added by an environment variable' {
  if (rule.source === 'env') return 'added by an environment variable';
  if (rule.source === 'config' || rule.owner === 'user') return 'added by you in keysentry.yaml';
  return 'built in';
}

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
  { host: 'api.cloudflare.com', owner: 'cloudflare', purpose: 'Cloudflare token verification and rotation; Workers and Pages variables' },
  { host: 'iam.amazonaws.com', owner: 'aws', purpose: 'AWS IAM access key creation and deletion' },
  { host: 'sts.amazonaws.com', owner: 'aws', purpose: 'AWS STS caller identity verification' },
  { host: 'api.supabase.com', owner: 'supabase', purpose: 'Supabase management API (keys and Edge Function secrets)' },
  { host: '*.supabase.co', owner: 'supabase', purpose: 'Supabase hosted project key verification' },
  { host: 'api.stripe.com', owner: 'stripe', purpose: 'Stripe API key verification' },
  { host: 'api.sendgrid.com', owner: 'sendgrid', purpose: 'SendGrid API key verification and management' },
  { host: 'slack.com', owner: 'slack', purpose: 'Slack API token verification' },
  // Phase 6 deploy platforms (notes/hosts-a.md, notes/hosts-b.md). Self-hosted Coolify comes from your settings.
  { host: 'api.netlify.com', owner: 'netlify', purpose: 'Netlify sites, variables and builds' },
  { host: 'api.heroku.com', owner: 'heroku', purpose: 'Heroku apps, config vars and releases' },
  { host: 'api.digitalocean.com', owner: 'digitalocean', purpose: 'DigitalOcean App Platform apps and deployments' },
  { host: 'api.zeabur.com', owner: 'zeabur', purpose: 'Zeabur GraphQL API (projects, variables, restarts)' },
  { host: 'app.coolify.io', owner: 'coolify', purpose: 'Coolify Cloud API' },
  // Phase 5 secret stores (notes/secret-stores.md). AWS regions, Kubernetes, Vault and self-hosted Infisical servers
  // come from your settings.
  { host: 'api.doppler.com', owner: 'doppler', purpose: 'Doppler projects, configs and secrets' },
  { host: 'app.infisical.com', owner: 'infisical', purpose: 'Infisical Cloud (US) secrets and machine identity login' },
  { host: 'eu.infisical.com', owner: 'infisical', purpose: 'Infisical Cloud (EU) secrets and machine identity login' },
  // Phase 6 providers (notes/providers-a.md, notes/providers-b.md).
  { host: 'apikeys.googleapis.com', owner: 'google', purpose: 'Google Cloud API key lookup, creation and deletion' },
  { host: 'oauth2.googleapis.com', owner: 'google', purpose: 'Google OAuth token exchange for service-account keys' },
  { host: 'generativelanguage.googleapis.com', owner: 'google', purpose: 'Gemini API key verification' },
  { host: 'api.groq.com', owner: 'groq', purpose: 'Groq API key verification' },
  { host: 'api.mistral.ai', owner: 'mistral', purpose: 'Mistral API key verification and Admin API key management' },
  { host: 'api.replicate.com', owner: 'replicate', purpose: 'Replicate API token verification' },
  { host: 'api.clerk.com', owner: 'clerk', purpose: 'Clerk secret key verification' },
  { host: 'api.twilio.com', owner: 'twilio', purpose: 'Twilio credential verification' },
  { host: 'iam.twilio.com', owner: 'twilio', purpose: 'Twilio API key management' },
  { host: 'api.postmarkapp.com', owner: 'postmark', purpose: 'Postmark token verification' },
  { host: 'console.neon.tech', owner: 'neon', purpose: 'Neon API key verification and management' },
  { host: 'api.upstash.com', owner: 'upstash', purpose: 'Upstash management API (Redis password and QStash token resets)' },
  { host: '*.upstash.io', owner: 'upstash', purpose: 'Upstash Redis REST and QStash token verification' },
  { host: 'blog.railway.com', owner: 'feed', purpose: 'Railway blog breach advisory feed' },
  { host: 'railway.com', owner: 'feed', purpose: 'Railway changelog breach advisory feed' },
  { host: 'vercel.com', owner: 'feed', purpose: 'Vercel breach advisory feed' },
  { host: 'www.vercel-status.com', owner: 'feed', purpose: 'Vercel status breach advisory feed' },
  { host: 'render.com', owner: 'feed', purpose: 'Render blog breach advisory feed' },
  { host: 'status.render.com', owner: 'feed', purpose: 'Render status breach advisory feed' },
  { host: 'fly.io', owner: 'feed', purpose: 'Fly blog breach advisory feed' },
  { host: 'status.flyio.net', owner: 'feed', purpose: 'Fly status breach advisory feed' },
  { host: 'github.blog', owner: 'feed', purpose: 'GitHub changelog breach advisory feed' },
  // Phase 2 official sources (notes/phase2-facts.md §8).
  { host: 'community.fly.io', owner: 'feed', purpose: 'Fly community announcements feed' },
  { host: 'www.githubstatus.com', owner: 'feed', purpose: 'GitHub status feed' },
  // Phase 2 security news (notes/phase2-facts.md §7). News alone never rotates a key; it raises an alert.
  { host: 'www.bleepingcomputer.com', owner: 'feed', purpose: 'Security news feed (BleepingComputer)' },
  { host: 'therecord.media', owner: 'feed', purpose: 'Security news feed (The Record)' },
  { host: 'www.securityweek.com', owner: 'feed', purpose: 'Security news feed (SecurityWeek)' },
  { host: 'www.theregister.com', owner: 'feed', purpose: 'Security news feed (The Register)' },
  { host: 'api.theregister.com', owner: 'feed', purpose: 'Security news feed (The Register, redirect target)' },
  { host: 'krebsonsecurity.com', owner: 'feed', purpose: 'Security news feed (KrebsOnSecurity)' },
  { host: 'www.darkreading.com', owner: 'feed', purpose: 'Security news feed (Dark Reading)' },
  { host: 'arstechnica.com', owner: 'feed', purpose: 'Security news feed (Ars Technica)' },
  { host: 'feeds.feedburner.com', owner: 'feed', purpose: 'Security news feed (The Hacker News)' },
  { host: 'www.cisa.gov', owner: 'feed', purpose: 'Security news feed (CISA advisories)' },
  { host: 'www.helpnetsecurity.com', owner: 'feed', purpose: 'Security news feed (Help Net Security)' },
  // Phase 6 official sources (notes/hosts-a.md, notes/hosts-b.md; src/autopilot/sources.ts gives each reason).
  { host: 'www.netlifystatus.com', owner: 'feed', purpose: 'Netlify status breach advisory feed' },
  { host: 'www.netlify.com', owner: 'feed', purpose: 'Netlify blog and changelog feeds' },
  { host: 'status.heroku.com', owner: 'feed', purpose: 'Heroku status breach advisory feed' },
  { host: 'www.heroku.com', owner: 'feed', purpose: 'Heroku blog feed' },
  { host: 'devcenter.heroku.com', owner: 'feed', purpose: 'Heroku changelog feed' },
  { host: 'status.digitalocean.com', owner: 'feed', purpose: 'DigitalOcean status breach advisory feed' },
  { host: 'www.digitalocean.com', owner: 'feed', purpose: 'DigitalOcean blog feed' },
  { host: 'www.cloudflarestatus.com', owner: 'feed', purpose: 'Cloudflare status breach advisory feed' },
  { host: 'blog.cloudflare.com', owner: 'feed', purpose: 'Cloudflare blog breach advisory feed' },
  { host: 'status.supabase.com', owner: 'feed', purpose: 'Supabase status breach advisory feed' },
  { host: 'supabase.com', owner: 'feed', purpose: 'Supabase blog breach advisory feed' },
  { host: 'status.zeabur.com', owner: 'feed', purpose: 'Zeabur status breach advisory feed' },
  // Phase 4 cloud box (notes/phase4-facts.md): attestation keys for the CLI's verifier, and the box's own key release.
  { host: 'www.googleapis.com', owner: 'box', purpose: 'Google signing keys for cloud box attestation checks' },
  { host: 'confidentialcomputing.googleapis.com', owner: 'box', purpose: 'Confidential Space attestation discovery' },
  { host: 'sts.googleapis.com', owner: 'box', purpose: 'Cloud box key release (token exchange inside the box)' },
  { host: 'cloudkms.googleapis.com', owner: 'box', purpose: 'Cloud box key release (KMS decrypt inside the box)' },
  // Phase 2 notification channels (notes/phase2-facts.md §2). Webhook URLs themselves come from your settings.
  { host: 'api.telegram.org', owner: 'notify', purpose: 'Telegram notifications you configured' },
  { host: 'discord.com', owner: 'notify', purpose: 'Discord webhook notifications you configured' },
  { host: 'hooks.slack.com', owner: 'notify', purpose: 'Slack webhook notifications you configured' },
  { host: 'ntfy.sh', owner: 'notify', purpose: 'ntfy push notifications and approval relay you configured' },
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
  'www.openssh.com',
  // Phase 6 provider dashboards (guidance links only).
  'account.postmarkapp.com',
  'console.groq.com',
  'console.mistral.ai',
  'console.upstash.com',
  'dashboard.clerk.com',
  'replicate.com',
  // Phase 6 provider documentation cited in source comments and guidance.
  'clerk.com',
  'docs.cloud.google.com',
  'docs.mistral.ai',
  'neon.com',
  'postmarkapp.com',
  'upstash.com',
  'www.twilio.com',
];

function normalizedHost(host: string): string {
  return host.toLowerCase().replace(/\.$/, '');
}

/** HTTPS without credentials to a DNS name; any port here, the rule decides which one (`portOf`). */
function validAuthority(url: URL): boolean {
  const host = normalizedHost(url.hostname);
  return url.protocol === 'https:' && !url.username && !url.password
    && host.length > 0 && !host.includes('*') && isIP(host.replace(/^\[|\]$/g, '')) === 0;
}

function portOf(url: URL): number {
  return url.port === '' ? 443 : Number(url.port);
}

/** A rule without a port allows only 443; a port-carrying (self-hosted, user) rule allows exactly its port. */
function rulePort(rule: EgressRule): number {
  return rule.port ?? 443;
}

/** Match hosts only after enforcing the transport and authority restrictions. */
export function matchRule(url: URL, rules: readonly EgressRule[]): EgressRule | null {
  if (!validAuthority(url)) return null;
  const host = normalizedHost(url.hostname);
  const port = portOf(url);
  // An exact rule is more specific than a suffix rule, including user additions.
  const exact = rules.find(rule => normalizedHost(rule.host) === host && rulePort(rule) === port);
  if (exact) return exact;
  if (port !== 443) return null;
  return rules.find(rule => {
    const allowed = normalizedHost(rule.host);
    return rule.port === undefined && allowed.startsWith('*.') && allowed.length > 2 && host.endsWith(allowed.slice(1))
      && host.length > allowed.length - 1;
  }) ?? null;
}

/**
 * User configuration authorizes only the named host, never its siblings or parent. Only 443 unless `allowPort` is set
 * for a self-hosted base URL you configured; then the rule carries the URL's explicit port and allows exactly that.
 */
export function rulesForUserUrls(urls: string[], purpose: string, source?: 'config' | 'env', options: { allowPort?: boolean } = {}): SourcedEgressRule[] {
  const rules = new Map<string, SourcedEgressRule>();
  for (const value of urls) {
    let url: URL;
    try { url = new URL(value); }
    catch { throw new TypeError('Invalid user URL host: (unparseable)'); }
    const host = normalizedHost(url.hostname);
    const port = portOf(url);
    if (!validAuthority(url) || port !== 443 && options.allowPort !== true) {
      throw new TypeError(`Invalid user URL host: ${createRedactor().redact(host) || '(unparseable)'}`);
    }
    rules.set(`${host}:${port}`, { host, purpose, owner: 'user', ...(port === 443 ? {} : { port }), ...(source === undefined ? {} : { source }) });
  }
  return [...rules.values()];
}

/** `host` or `host:port` for display. */
export function ruleAuthority(rule: EgressRule): string {
  return rule.port === undefined ? rule.host : `${rule.host}:${rule.port}`;
}

export function rulesForUserFeeds(urls: string[]): EgressRule[] {
  return rulesForUserUrls(urls, 'breach feed you configured');
}
