import type { Classification, ProviderId, RiskTier, RotationMethod } from '../types.js';

const TIERS: Record<ProviderId, RiskTier> = {
  'crypto-wallet': 'crypto', aws: 'cloud', cloudflare: 'cloud', github: 'cloud', google: 'cloud', 'private-key': 'cloud',
  database: 'database', supabase: 'database', stripe: 'payments', openai: 'ai', anthropic: 'ai', openrouter: 'ai',
  resend: 'comms', sendgrid: 'comms', slack: 'comms', twilio: 'comms', 'app-secret': 'app', unknown: 'unknown',
};

export function tierFor(provider: ProviderId): RiskTier {
  return TIERS[provider];
}

export function methodFor(provider: ProviderId): RotationMethod {
  if (provider === 'cloudflare') return 'atomic-roll';
  if (provider === 'app-secret') return 'generate';
  if (provider === 'openai' || provider === 'openrouter' || provider === 'resend' || provider === 'aws') return 'auto';
  return 'guided';
}

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
  { provider: 'twilio', pattern: /^SK[A-Fa-f0-9]{32}$/ },
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
const APP_NAME = /(?:^|_)(?:JWT_SECRET|SESSION_SECRET|NEXTAUTH_SECRET|ENCRYPTION_KEY|COOKIE_SECRET)$|_SECRET$/;
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
    [/GOOGLE|GCP|FIREBASE/, 'google'],
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
    if (/^pk_/.test(text)) return result('stripe', false, 'high');
    if (/^(?:AKIA|ASIA)[A-Z0-9]{16}$/.test(text)) return result('aws', false, 'high');
    if (/^sb_publishable_/.test(text)) return result('supabase', false, 'high');
    const role = jwtRole(text);
    if (role === 'anon') return result('supabase', false, 'high');
    if (role === 'service_role') return result('supabase', true, 'high');
    if (isGoogleAccount(text)) return result('google', true, 'high');
    for (const rule of KEY_RULES) {
      if (rule.pattern.test(text)) return result(rule.provider, true, 'high');
    }
    if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(text)) {
      if (passwordInUrl(text)) {
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
  if (text !== undefined && !randomLooking(text)) return no();
  const namedProvider = providerFromName(upper);
  if (namedProvider) return result(namedProvider, true, 'medium');
  if (APP_NAME.test(upper)) return result('app-secret', true, 'medium');
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
