import type { Classification, ProviderId, RiskTier, RotationMethod } from '../types.js';

const TIERS: Record<ProviderId, RiskTier> = {
  'crypto-wallet': 'crypto', aws: 'cloud', cloudflare: 'cloud', github: 'cloud', google: 'cloud', 'private-key': 'cloud',
  database: 'database', supabase: 'database', stripe: 'payments', openai: 'ai', anthropic: 'ai', openrouter: 'ai',
  resend: 'comms', sendgrid: 'comms', slack: 'comms', twilio: 'comms', 'app-secret': 'app', 'encryption-key': 'app', unknown: 'unknown',
  groq: 'ai', mistral: 'ai', replicate: 'ai', postmark: 'comms', clerk: 'cloud', upstash: 'database', neon: 'database',
};

export function tierFor(provider: ProviderId): RiskTier {
  return TIERS[provider];
}

export function methodFor(provider: ProviderId): RotationMethod {
  // Upstash documents no second password or token beside the old one: a reset replaces it at once.
  if (provider === 'cloudflare' || provider === 'upstash') return 'atomic-roll';
  if (provider === 'app-secret') return 'generate';
  if (provider === 'openai' || provider === 'openrouter' || provider === 'resend' || provider === 'aws'
    || provider === 'google' || provider === 'sendgrid' || provider === 'twilio' || provider === 'neon') return 'auto';
  return 'guided';
}

/**
 * The rotation method for one readable value. Google service-account JSON keys share the `google` provider with API
 * keys, but their rotation is always guided, so they are never planned (or armed) as automatic. So are Google API keys
 * held in a variable whose name marks them public or client-side (pass the variable name): see isPublicGoogleKeyName.
 */
export function methodForValue(provider: ProviderId, value: string | undefined, name?: string): RotationMethod {
  if (provider === 'google' && value !== undefined && isGoogleAccount(value.trim())) return 'guided';
  if (provider === 'google' && name !== undefined && isPublicGoogleKeyName(name)) return 'guided';
  // The Twilio adapter rotates an account Auth Token only by hand (promoting a secondary token ends the old one for
  // every consumer). It treats a value as an Auth Token by its name, else by its 32-lowercase-hex shape.
  if (provider === 'twilio' && name !== undefined && (/AUTH_TOKEN$/i.test(name)
    || !/SECRET$/i.test(name) && value !== undefined && /^[0-9a-f]{32}$/.test(value.trim()))) return 'guided';
  // Neon organization and project API keys are created per organization or project; the adapter rotates only
  // personal keys. A name that says organization or project is planned as guided up front.
  if (provider === 'neon' && name !== undefined && /(?:^|_)(?:ORG|ORGANIZATION|PROJECT)(?:_|$)/i.test(name)) return 'guided';
  return methodFor(provider);
}

// Build tools put these variables into browser bundles or app binaries (Next.js, Vite, Expo, Create React App,
// SvelteKit/Astro, Nuxt, Gatsby, Vue CLI).
const CLIENT_PREFIX = /^(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_|NUXT_ENV_|GATSBY_|VUE_APP_)/;
const CLIENT_WORDS = new Set(['BROWSER', 'CLIENT', 'FRONTEND', 'ANDROID', 'IOS', 'MOBILE']);
const MAPS_CLIENT_WORDS = new Set(['WEB', 'JS', 'JAVASCRIPT', 'EMBED', 'PUBLIC']);

/**
 * Google API keys that are public by design: Firebase web config keys, Maps keys for browsers and apps, and any key in
 * a variable that a build tool ships to clients. Such a key is protected by its restrictions, not by secrecy, and it
 * lives in shipped web bundles and app builds that keysentry cannot redeploy. It is never rotated automatically.
 */
export function isPublicGoogleKeyName(name: string): boolean {
  const upper = name.toUpperCase();
  // Whatever a client-prefixed variable holds is shipped to clients.
  if (CLIENT_PREFIX.test(upper)) return true;
  // Service-account keys, admin keys and CI tokens (FIREBASE_TOKEN) are real secrets, never public config.
  if (/SERVICE_?ACCOUNT|ADMIN|PRIVATE|CREDENTIAL|SECRET|PASSWORD/.test(upper)) return false;
  if (/FIREBASE/.test(upper)) return /API_?KEY|(?:^|_)KEY$/.test(upper);
  const words = upper.split(/[^A-Z0-9]+/);
  if (words.some(word => CLIENT_WORDS.has(word))) return true;
  return words.some(word => word === 'MAPS' || word === 'MAP') && words.some(word => MAPS_CLIENT_WORDS.has(word));
}

/** Plain explanation shown wherever a public Google API key is listed or planned. */
export const PUBLIC_GOOGLE_KEY_EXPLANATION = 'This Google API key is public by design: it ships inside web pages or mobile apps, so its restrictions (allowed websites, apps and APIs) protect it, not secrecy. Rotating it breaks every installed app and cached page that still uses the old key, so keysentry never rotates it automatically.';

function result(provider: ProviderId, isSecret: boolean, confidence: Classification['confidence']): Classification {
  return { provider, tier: tierFor(provider), isSecret, confidence };
}

// Specific sk- families precede the legacy OpenAI pattern. These rules are also
// used for pattern-only redaction, so identification and masking cannot drift.
const KEY_RULES: readonly { provider: ProviderId; pattern: RegExp }[] = [
  { provider: 'openrouter', pattern: /^sk-or-v1-[A-Fa-f0-9]{32,}$/ },
  { provider: 'anthropic', pattern: /^sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{16,}$/ },
  { provider: 'openai', pattern: /^sk-(?:proj-|svcacct-)[A-Za-z0-9_-]{16,}$/ },
  { provider: 'openai', pattern: /^sk-(?!(?:ant-|or-))[A-Za-z0-9_-]{40,}$/ },
  { provider: 'stripe', pattern: /^(?:[sr]k_(?:live|test)_|whsec_)[A-Za-z0-9_-]{16,}$/ },
  { provider: 'resend', pattern: /^re_[A-Za-z0-9_-]{16,}$/ },
  { provider: 'github', pattern: /^(?:gh[pous]_|github_pat_)[A-Za-z0-9_]{20,}$/ },
  { provider: 'supabase', pattern: /^sb_secret_[A-Za-z0-9_-]{16,}$/ },
  { provider: 'slack', pattern: /^xox[bp]-[A-Za-z0-9-]{20,}$/ },
  { provider: 'slack', pattern: /^(?:https:\/\/)?hooks\.slack\.com\/services\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+$/ },
  { provider: 'sendgrid', pattern: /^SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{20,}$/ },
  // Phase 6 value shapes. Twilio SK… values are public key SIDs (handled in classify), not secrets.
  { provider: 'groq', pattern: /^gsk_[A-Za-z0-9]{20,}$/ },
  { provider: 'replicate', pattern: /^r8_[A-Za-z0-9]{20,}$/ },
  { provider: 'neon', pattern: /^napi_[A-Za-z0-9]{32,}$/ },
  { provider: 'google', pattern: /^AIza[A-Za-z0-9_-]{35}$/ },
  { provider: 'private-key', pattern: /^-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY)-----[\s\S]*?-----END \1-----$/ },
];

const JWT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
function jwtRole(value: string): string | undefined {
  if (!JWT.test(value)) return undefined;
  try {
    const payload: unknown = JSON.parse(Buffer.from(value.split('.')[1]!, 'base64url').toString('utf8'));
    if (payload && typeof payload === 'object' && 'role' in payload && typeof payload.role === 'string') return payload.role;
  } catch { /* Invalid JWTs are ordinary unknown values, never error messages. */ }
  return undefined;
}

function isGoogleAccount(value: string): boolean {
  if (!value.startsWith('{')) return false;
  try {
    const data: unknown = JSON.parse(value);
    return !!data && typeof data === 'object' && 'type' in data && data.type === 'service_account'
      && 'private_key' in data && typeof data.private_key === 'string' && data.private_key.trim().length > 0;
  } catch { return false; }
}

function passwordInUrl(value: string): boolean {
  // URL rejects Mongo replica-set authorities; extracting the authority also
  // handles those without decoding or ever returning the credential.
  const authority = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?#]*)/.exec(value)?.[1];
  if (authority) {
    const at = authority.lastIndexOf('@');
    const credentials = authority.slice(0, at);
    const colon = credentials.indexOf(':');
    if (at >= 0 && colon >= 0 && literalCredential(credentials.slice(colon + 1))) return true;
  }
  const query = value.indexOf('?');
  if (query < 0) return false;
  const parameters = new URLSearchParams(value.slice(query + 1).split('#', 1)[0]);
  for (const [name, password] of parameters) {
    if (/^(?:password|passwd|pwd|sslpassword)$/i.test(name) && literalCredential(password)) return true;
  }
  return false;
}

function literalCredential(value: string): boolean {
  // A password supplied entirely through Railway references is not readable.
  // References elsewhere in a URL must not hide a hardcoded password.
  return value.replace(/\$\{\{[\s\S]*?\}\}/g, '').trim().length > 0;
}

function randomLooking(value: string): boolean {
  if (value.length < 16 || /\s/.test(value) || /^(?:your[-_]|example|placeholder|replace[-_]|changeme)/i.test(value)) return false;
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  if (counts.size < 6) return false;
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy >= 2.8;
}

const SECRET_NAME = /KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL/;
const PUBLIC_NAME = /^(?:NEXT_PUBLIC_|VITE_|PUBLIC_)/;
const APP_NAME = /^(?:JWT_SECRET|JWT_SIGNING_SECRET|SESSION_SECRET|COOKIE_SECRET|NEXTAUTH_SECRET|AUTH_SECRET|BETTER_AUTH_SECRET|SECRET_KEY_BASE|CSRF_SECRET)$/;
const ENCRYPTION_NAME = /^(?:ENCRYPTION_KEY|MASTER_KEY|DATA_KEY|APP_KEY)$|_(?:ENCRYPTION_KEY|CIPHER_KEY)$/;
const ISSUED_SECRET_NAME = /_(?:CLIENT_SECRET|WEBHOOK_SECRET|API_SECRET|APP_SECRET|SIGNING_SECRET|SESSION_SECRET|JWT_SECRET)$/;
const WALLET_NAME = /(?:^|_)(?:PRIVATE_?KEY|WALLET|MNEMONIC|SEED)(?:_|$)/;

function providerFromName(name: string): ProviderId | undefined {
  if (/CLOUDFLARE/.test(name) && /TOKEN|KEY/.test(name)) return 'cloudflare';
  if (/AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN/.test(name)) return 'aws';
  if (/SUPABASE/.test(name) && /SERVICE_ROLE|SECRET/.test(name)) return 'supabase';
  if (/TWILIO/.test(name) && /AUTH_TOKEN|API_KEY|API_SECRET/.test(name)) return 'twilio';
  if (/(?:DATABASE|POSTGRES|POSTGRESQL|MYSQL|MONGO(?:DB)?|REDIS).*(?:URL|URI)/.test(name)) return 'database';
  if (!SECRET_NAME.test(name)) return undefined;
  const names: readonly [RegExp, ProviderId][] = [
    [/OPENROUTER/, 'openrouter'], [/OPENAI/, 'openai'], [/ANTHROPIC/, 'anthropic'], [/STRIPE/, 'stripe'],
    [/RESEND/, 'resend'], [/GITHUB|(?:^|_)GH_TOKEN$/, 'github'], [/SLACK/, 'slack'], [/SENDGRID/, 'sendgrid'],
    [/GOOGLE|GCP|FIREBASE|GEMINI/, 'google'],
    // Phase 6 (names alone are medium confidence).
    [/GROQ/, 'groq'], [/MISTRAL/, 'mistral'], [/REPLICATE/, 'replicate'], [/CLERK/, 'clerk'],
    [/POSTMARK/, 'postmark'], [/NEON.*(?:API_KEY|TOKEN)/, 'neon'], [/UPSTASH|QSTASH|^KV_REST_API_(?:READ_ONLY_)?TOKEN$/, 'upstash'],
  ];
  return names.find(([pattern]) => pattern.test(name))?.[1];
}

/** Classifies values in memory; the result never contains the value itself. */
export function classify(name: string, value: string | undefined): Classification {
  const upper = name.toUpperCase();
  const text = value?.trim();
  const no = () => result('unknown', false, 'high');
  if (text !== undefined) {
    if (!text || /^(?:true|false|null|undefined)$/i.test(text)
      || /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?$/i.test(text)) return no();
    // Clerk and Stripe share the pk_/sk_ prefixes: only a CLERK name decides Clerk.
    if (/^pk_/.test(text)) return result(/CLERK/.test(upper) ? 'clerk' : 'stripe', false, 'high');
    if (/^(?:AKIA|ASIA)[A-Z0-9]{16}$/.test(text)) return result('aws', false, 'high');
    // Twilio Account and API key SIDs are public identifiers that name a credential pair (like AKIA ids).
    if (/^(?:AC|SK)[0-9a-fA-F]{32}$/.test(text)) return result('twilio', false, 'high');
    // Postmark's documented test token delivers nothing.
    if (text === 'POSTMARK_API_TEST') return result('postmark', false, 'high');
    // A whole-value reference such as DigitalOcean's ${db.PASSWORD} or Doppler's ${OTHER} names a secret defined elsewhere.
    if (/^\$\{[A-Za-z_][\w.-]*\}$/.test(text)) return no();
    if (/^sb_publishable_/.test(text)) return result('supabase', false, 'high');
    const role = jwtRole(text);
    if (role === 'anon') return result('supabase', false, 'high');
    if (role === 'service_role') return result('supabase', true, 'high');
    if (isGoogleAccount(text)) return result('google', true, 'high');
    // Clerk webhooks use whsec_ and Clerk secret keys sk_live_/sk_test_, like Stripe: a CLERK name decides.
    if (/CLERK/.test(upper) && /^(?:sk_(?:live|test)_|whsec_)[A-Za-z0-9+/=_-]{16,}$/.test(text)) return result('clerk', true, 'high');
    if (/MISTRAL/.test(upper) && /^[A-Za-z0-9]{32}$/.test(text)) return result('mistral', true, 'high');
    for (const rule of KEY_RULES) {
      if (rule.pattern.test(text)) return result(rule.provider, true, 'high');
    }
    if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(text)) {
      if (passwordInUrl(text)) {
        if (/^rediss?:\/\/[^/?#]*@[a-z0-9-]+\.upstash\.io(?::\d+)?(?:[/?#]|$)/i.test(text)) return result('upstash', true, 'high');
        return result(/^(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?):\/\//i.test(text) ? 'database' : 'unknown', true, 'high');
      }
      return no();
    }
    if (/^-----BEGIN (?:[A-Z0-9]+ )*PUBLIC KEY-----/.test(text)) return no();
    if (/\$\{\{[\s\S]*?\}\}/.test(text)) return no();
    if (WALLET_NAME.test(upper)) {
      if (/^0x[A-Fa-f0-9]{64}$/.test(text) || /^[1-9A-HJ-NP-Za-km-z]{64,88}$/.test(text)) return result('crypto-wallet', true, 'high');
      const words = text.split(/\s+/);
      if ((words.length === 12 || words.length === 24) && words.every((word) => /^[a-z]+$/i.test(word))) return result('crypto-wallet', true, 'medium');
    }
  }

  // Names alone are weaker evidence. A recognizable secret shape above still
  // wins when someone accidentally puts a private key in a public variable.
  if (PUBLIC_NAME.test(upper) || /^(?:NODE_ENV|PORT|HOST)$/.test(upper)
    || /(?:^|_)AWS_ACCESS_KEY_ID$/.test(upper) || /SUPABASE.*ANON/.test(upper)
    || /STRIPE.*PUBLISHABLE/.test(upper) || /(?:^|_)(?:PUBLIC_KEY|WALLET_ADDRESS)$/.test(upper)) {
    if (/SUPABASE.*ANON/.test(upper)) return result('supabase', false, 'high');
    if (/STRIPE.*PUBLISHABLE/.test(upper)) return result('stripe', false, 'high');
    return no();
  }
  if (upper === 'AWS_SECRET_ACCESS_KEY' && text !== undefined && /^[A-Za-z0-9/+]{40}$/.test(text)) return result('aws', true, 'high');
  // Structured credentials/configuration cannot be replaced by random bytes.
  // Keep them guided even when formatting whitespace defeats the entropy test.
  if (text !== undefined && (text.startsWith('{') || text.startsWith('[')) && SECRET_NAME.test(upper)) {
    return result('unknown', true, 'low');
  }
  if (text !== undefined && !randomLooking(text)) return no();
  if (ENCRYPTION_NAME.test(upper)) return result('encryption-key', true, 'medium');
  if (APP_NAME.test(upper)) return result('app-secret', true, 'medium');
  // Issuer-specific secrets cannot be replaced by locally generated bytes or
  // assumed to use a provider's ordinary API-key rotation endpoint. Recognized
  // value shapes have already been handled above. Twilio's API key secret (TWILIO_API_SECRET) is the documented
  // exception: the Twilio adapter rotates it with its SID.
  if (/TWILIO/.test(upper) && /AUTH_TOKEN|API_KEY|API_SECRET|_SECRET$/.test(upper)) return result('twilio', true, 'medium');
  if (ISSUED_SECRET_NAME.test(upper)) return result('unknown', true, 'low');
  const namedProvider = providerFromName(upper);
  if (namedProvider) return result(namedProvider, true, 'medium');
  if (SECRET_NAME.test(upper)) return result('unknown', true, 'low');
  return result('unknown', false, 'low');
}

/** Internal shared matching rules; callers should normally use createRedactor. */
export function secretPatternRanges(text: string): [number, number][] {
  const ranges: [number, number][] = [];
  function collect(pattern: RegExp, accept: (value: string) => boolean = () => true): void {
    for (const match of text.matchAll(pattern)) {
      if (accept(match[0])) ranges.push([match.index, match.index + match[0].length]);
    }
  }

  // Mask the JSON field contents even when PEM newlines have been escaped.
  for (const match of text.matchAll(/("private_key"\s*:\s*)"(?:\\.|[^"\\])*"/g)) {
    ranges.push([match.index + match[1]!.length + 1, match.index + match[0].length - 1]);
  }
  for (const { pattern } of KEY_RULES) {
    collect(new RegExp(pattern.source.slice(1, -1), 'g'));
  }
  collect(/(?<![A-Za-z0-9_-])[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, (candidate) => jwtRole(candidate) === 'service_role');
  collect(/(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s<>"'`]+/g, passwordInUrl);
  return ranges;
}
