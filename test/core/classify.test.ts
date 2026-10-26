import { describe, expect, it } from 'vitest';
import { classify, methodFor, tierFor } from '../../src/core/classify.js';
import type { ProviderId } from '../../src/types.js';

const hex = '0123456789abcdef'.repeat(4);
const random = 'aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY';
const jwt = (role: string) => `${Buffer.from('{"alg":"HS256"}').toString('base64url')}.${Buffer.from(JSON.stringify({ role, iss: 'supabase' })).toString('base64url')}.fake_signature`;
type Case = [string, string, string | undefined, ProviderId, boolean];

// Every fixture is synthetic. Literal expected providers keep the table independent of the classifier.
const cases: Case[] = [
  ['OpenAI project', 'API_KEY', `sk-proj-${random}`, 'openai', true],
  ['OpenAI service account', 'SERVICE_TOKEN', `sk-svcacct-${random}`, 'openai', true],
  ['OpenAI legacy', 'BANANA', `sk-${hex}`, 'openai', true],
  ['OpenAI shape overrides Stripe name', 'STRIPE_SECRET_KEY', `sk-${hex}`, 'openai', true],
  ['OpenAI name', 'OPENAI_API_KEY', random, 'openai', true],
  ['OpenAI sealed', 'OPENAI_API_KEY', undefined, 'openai', true],
  ['Anthropic API', 'ODD_NAME', `sk-ant-api03-${random}`, 'anthropic', true],
  ['Anthropic admin', 'OPENAI_API_KEY', `sk-ant-admin01-${random}`, 'anthropic', true],
  ['Anthropic name', 'ANTHROPIC_API_KEY', random, 'anthropic', true],
  ['OpenRouter', 'OPENAI_API_KEY', `sk-or-v1-${hex}`, 'openrouter', true],
  ['OpenRouter name', 'OPENROUTER_API_KEY', random, 'openrouter', true],
  ['Stripe live', 'API_KEY', `sk_live_${random}`, 'stripe', true],
  ['Stripe test', 'API_KEY', `sk_test_${random}`, 'stripe', true],
  ['Stripe restricted live', 'API_KEY', `rk_live_${random}`, 'stripe', true],
  ['Stripe restricted test', 'API_KEY', `rk_test_${random}`, 'stripe', true],
  ['Stripe webhook', 'API_KEY', `whsec_${random}`, 'stripe', true],
  ['Stripe public live', 'STRIPE_PUBLISHABLE_KEY', `pk_live_${random}`, 'stripe', false],
  ['Stripe public test under secret name', 'STRIPE_SECRET_KEY', `pk_test_${random}`, 'stripe', false],
  ['Stripe public generic', 'STRIPE_KEY', `pk_${random}`, 'stripe', false],
  ['Stripe sealed', 'STRIPE_SECRET_KEY', undefined, 'stripe', true],
  ['Resend', 'ODD_NAME', `re_${random}`, 'resend', true],
  ['Resend name', 'RESEND_API_KEY', random, 'resend', true],
  ['Cloudflare token', 'CLOUDFLARE_API_TOKEN', random, 'cloudflare', true],
  ['Cloudflare key', 'CLOUDFLARE_GLOBAL_API_KEY', random, 'cloudflare', true],
  ['Cloudflare account id', 'CLOUDFLARE_ACCOUNT_ID', hex, 'unknown', false],
  ['GitHub personal', 'ODD_NAME', `ghp_${random}`, 'github', true],
  ['GitHub OAuth', 'ODD_NAME', `gho_${random}`, 'github', true],
  ['GitHub app', 'ODD_NAME', `ghs_${random}`, 'github', true],
  ['GitHub user', 'ODD_NAME', `ghu_${random}`, 'github', true],
  ['GitHub fine grained', 'ODD_NAME', `github_pat_${random}`, 'github', true],
  ['GitHub name', 'GITHUB_TOKEN', random, 'github', true],
  ['AWS permanent id', 'AWS_ACCESS_KEY_ID', 'AKIA0123456789ABCDEF', 'aws', false],
  ['AWS session id', 'ODD_NAME', 'ASIA0123456789ABCDEF', 'aws', false],
  ['AWS secret', 'AWS_SECRET_ACCESS_KEY', 'aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY2zA4cD6e', 'aws', true],
  ['AWS sealed', 'AWS_SECRET_ACCESS_KEY', undefined, 'aws', true],
  ['Supabase secret', 'ODD_NAME', `sb_secret_${random}`, 'supabase', true],
  ['Supabase service JWT', 'ODD_NAME', jwt('service_role'), 'supabase', true],
  ['Supabase anon JWT', 'SUPABASE_SERVICE_ROLE_KEY', jwt('anon'), 'supabase', false],
  ['Supabase anon name', 'SUPABASE_ANON_KEY', random, 'supabase', false],
  ['Supabase publishable', 'SUPABASE_KEY', `sb_publishable_${random}`, 'supabase', false],
  ['Supabase service name', 'SUPABASE_SERVICE_ROLE_KEY', random, 'supabase', true],
  ['Postgres password', 'ODD_NAME', 'postgres://user:fake-password@localhost/db', 'database', true],
  ['Postgresql encoded password', 'ODD_NAME', 'postgresql://user:fake%40password@localhost/db', 'database', true],
  ['MySQL password', 'ODD_NAME', 'mysql://user:fake-password@localhost/db', 'database', true],
  ['Mongo password', 'ODD_NAME', 'mongodb://user:fake-password@localhost/db', 'database', true],
  ['Mongo SRV password', 'ODD_NAME', 'mongodb+srv://user:fake-password@localhost/db', 'database', true],
  ['Redis password', 'ODD_NAME', 'redis://:fake-password@localhost:6379', 'database', true],
  ['Rediss password', 'ODD_NAME', 'rediss://user:fake-password@localhost:6379', 'database', true],
  ['Database no password', 'DATABASE_URL', 'postgres://user@localhost/db', 'unknown', false],
  ['Database empty password', 'DATABASE_URL', 'postgres://user:@localhost/db', 'unknown', false],
  ['Database bare host', 'DATABASE_URL', 'postgresql://localhost/db', 'unknown', false],
  ['Database replica set', 'DATABASE_URL', 'mongodb://user:fake-password@db1:27017,db2:27017/db', 'database', true],
  ['Postgres query password', 'DATABASE_URL', 'postgresql://localhost/db?user=app&password=fake-database-password', 'database', true],
  ['Database userinfo password with reference host', 'DATABASE_URL', 'postgresql://app:fake-database-password@${{Postgres.HOST}}/db', 'database', true],
  ['Database referenced userinfo password', 'DATABASE_URL', 'postgresql://app:${{Postgres.PASSWORD}}@localhost/db', 'unknown', false],
  ['Database referenced query password', 'DATABASE_URL', 'postgresql://localhost/db?password=${{Postgres.PASSWORD}}', 'unknown', false],
  ['Google account with referenced project', 'CREDENTIALS', JSON.stringify({ type: 'service_account', project_id: '${{GCP.PROJECT_ID}}', private_key: 'fake-private-material' }), 'google', true],
  ['Slack bot', 'ODD_NAME', 'xoxb-123456789012-123456789012-fakeTOKEN123456789', 'slack', true],
  ['Slack user', 'ODD_NAME', 'xoxp-123456789012-123456789012-fakeTOKEN123456789', 'slack', true],
  ['Slack webhook', 'SLACK_WEBHOOK_URL', 'https://hooks.slack.com/services/T00000000/B00000000/fakeABC123fakeABC123fakeAB', 'slack', true],
  ['Slack name', 'SLACK_BOT_TOKEN', random, 'slack', true],
  ['SendGrid', 'ODD_NAME', `SG.${random.slice(0, 22)}.${random}${random}`, 'sendgrid', true],
  ['SendGrid name', 'SENDGRID_API_KEY', random, 'sendgrid', true],
  ['Twilio auth', 'TWILIO_AUTH_TOKEN', hex.slice(0, 32), 'twilio', true],
  ['Twilio API key id', 'TWILIO_API_KEY', `SK${hex.slice(0, 32)}`, 'twilio', true],
  ['Twilio name-free SK key', 'ODD_NAME', `SK${hex.slice(0, 32)}`, 'twilio', true],
  ['Twilio account id', 'TWILIO_ACCOUNT_SID', `AC${hex.slice(0, 32)}`, 'unknown', false],
  ['Google API', 'ODD_NAME', `AIza${random}abc`, 'google', true],
  ['Google account JSON', 'GOOGLE_CREDENTIALS', JSON.stringify({ type: 'service_account', private_key: '-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n' }), 'google', true],
  ['Google name', 'GOOGLE_API_KEY', random, 'google', true],
  ['RSA private PEM', 'ODD_NAME', '-----BEGIN RSA PRIVATE KEY-----\nFAKE\n-----END RSA PRIVATE KEY-----', 'private-key', true],
  ['EC private PEM', 'ODD_NAME', '-----BEGIN EC PRIVATE KEY-----\nFAKE\n-----END EC PRIVATE KEY-----', 'private-key', true],
  ['OpenSSH private PEM', 'ODD_NAME', '-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE\n-----END OPENSSH PRIVATE KEY-----', 'private-key', true],
  ['Encrypted private PEM', 'ODD_NAME', '-----BEGIN ENCRYPTED PRIVATE KEY-----\nFAKE\n-----END ENCRYPTED PRIVATE KEY-----', 'private-key', true],
  ['Public PEM', 'PUBLIC_KEY', '-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----', 'unknown', false],
  ['Wallet hex private', 'PRIVATE_KEY', `0x${hex}`, 'crypto-wallet', true],
  ['Wallet hex wallet', 'ETH_WALLET', `0x${hex}`, 'crypto-wallet', true],
  ['Wallet hex seed', 'SEED', `0x${hex}`, 'crypto-wallet', true],
  ['Wallet base58', 'SOLANA_PRIVATE_KEY', '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789ABCDEFG', 'crypto-wallet', true],
  ['Wallet mnemonic 12', 'MNEMONIC', 'abandon ability able about above absent absorb abstract absurd abuse access accident', 'crypto-wallet', true],
  ['Wallet mnemonic 24', 'WALLET_SEED', 'abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual', 'crypto-wallet', true],
  ['Prose no wallet name', 'DESCRIPTION', 'abandon ability able about above absent absorb abstract absurd abuse access accident', 'unknown', false],
  ['Hex no wallet name', 'COMMIT_HASH', `0x${hex}`, 'unknown', false],
  ['Wallet public address', 'WALLET_ADDRESS', `0x${hex.slice(0, 40)}`, 'unknown', false],
  ['JWT app secret', 'JWT_SECRET', random, 'app-secret', true],
  ['Session app secret', 'SESSION_SECRET', random, 'app-secret', true],
  ['NextAuth app secret', 'NEXTAUTH_SECRET', random, 'app-secret', true],
  ['JWT signing secret', 'JWT_SIGNING_SECRET', random, 'app-secret', true],
  ['Auth secret', 'AUTH_SECRET', random, 'app-secret', true],
  ['Better Auth secret', 'BETTER_AUTH_SECRET', random, 'app-secret', true],
  ['Rails secret key base', 'SECRET_KEY_BASE', random, 'app-secret', true],
  ['CSRF secret', 'CSRF_SECRET', random, 'app-secret', true],
  ['Namespaced session secret', 'ADMIN_SESSION_SECRET', random, 'unknown', true],
  ['Namespaced JWT secret', 'ADMIN_JWT_SECRET', random, 'unknown', true],
  ['Sealed namespaced session secret', 'ADMIN_SESSION_SECRET', undefined, 'unknown', true],
  ['Sealed namespaced JWT secret', 'ADMIN_JWT_SECRET', undefined, 'unknown', true],
  ['Encryption key', 'ENCRYPTION_KEY', hex, 'encryption-key', true],
  ['Namespaced encryption key', 'APP_ENCRYPTION_KEY', hex, 'encryption-key', true],
  ['Provider-named encryption key', 'OPENAI_ENCRYPTION_KEY', hex, 'encryption-key', true],
  ['Master encryption key', 'MASTER_KEY', hex, 'encryption-key', true],
  ['Data encryption key', 'DATA_KEY', hex, 'encryption-key', true],
  ['Field encryption key', 'FIELD_ENCRYPTION_KEY', hex, 'encryption-key', true],
  ['Laravel encryption key', 'APP_KEY', `base64:${random}`, 'encryption-key', true],
  ['Cipher key', 'CUSTOM_CIPHER_KEY', hex, 'encryption-key', true],
  ['Sealed encryption key', 'ENCRYPTION_KEY', undefined, 'encryption-key', true],
  ['Cookie app secret', 'COOKIE_SECRET', random, 'app-secret', true],
  ['Custom secret', 'CUSTOM_SECRET', random, 'unknown', true],
  ['Discord client secret', 'DISCORD_CLIENT_SECRET', random, 'unknown', true],
  ['PayPal client secret', 'PAYPAL_CLIENT_SECRET', random, 'unknown', true],
  ['Auth0 client secret', 'AUTH0_CLIENT_SECRET', random, 'unknown', true],
  ['OAuth client secret', 'OAUTH_CLIENT_SECRET', random, 'unknown', true],
  ['Shopify API secret', 'SHOPIFY_API_SECRET', random, 'unknown', true],
  ['Twitter API secret', 'TWITTER_API_SECRET', random, 'unknown', true],
  ['Linear webhook secret', 'LINEAR_WEBHOOK_SECRET', random, 'unknown', true],
  ['Clerk webhook secret', 'CLERK_WEBHOOK_SECRET', random, 'unknown', true],
  ['Discord app secret', 'DISCORD_APP_SECRET', random, 'unknown', true],
  ['Service signing secret', 'DISCORD_SIGNING_SECRET', random, 'unknown', true],
  ['Provider webhook secret without known value shape', 'OPENAI_WEBHOOK_SECRET', random, 'unknown', true],
  ['Known Stripe webhook shape', 'STRIPE_WEBHOOK_SECRET', `whsec_${random}`, 'stripe', true],
  ['Sealed third-party secret', 'DISCORD_CLIENT_SECRET', undefined, 'unknown', true],
  ['Sealed session secret', 'SESSION_SECRET', undefined, 'app-secret', true],
  ['Weak literal app config', 'SESSION_SECRET', 'development', 'unknown', false],
  ['Unknown key', 'CUSTOM_API_KEY', random, 'unknown', true],
  ['Unknown token', 'ACCESS_TOKEN', random, 'unknown', true],
  ['Unknown password', 'DATABASE_PASSWORD', random, 'unknown', true],
  ['Unknown sealed', 'CUSTOM_TOKEN', undefined, 'unknown', true],
  ['Random innocent name', 'BUILD_IDENTIFIER', random, 'unknown', false],
  ['Port', 'PORT', '3000', 'unknown', false],
  ['Node environment', 'NODE_ENV', 'production', 'unknown', false],
  ['Host', 'HOST', 'localhost', 'unknown', false],
  ['Next public', 'NEXT_PUBLIC_API_KEY', random, 'unknown', false],
  ['Vite public', 'VITE_API_KEY', random, 'unknown', false],
  ['Public namespace', 'PUBLIC_TOKEN', random, 'unknown', false],
  ['True', 'API_TOKEN', 'true', 'unknown', false],
  ['False', 'API_TOKEN', 'FALSE', 'unknown', false],
  ['Integer', 'API_TOKEN', '12345678901234567890', 'unknown', false],
  ['Decimal', 'API_TOKEN', '-1.25', 'unknown', false],
  ['Scientific', 'API_TOKEN', '1e10', 'unknown', false],
  ['Plain HTTPS', 'API_SECRET', 'https://example.test/path', 'unknown', false],
  ['Plain HTTP', 'DATABASE_URL', 'http://localhost:8080', 'unknown', false],
  ['Railway reference', 'DATABASE_PASSWORD', '${{Postgres.PGPASSWORD}}', 'unknown', false],
  ['Railway interpolation', 'API_TOKEN', 'prefix-${{shared.API_KEY}}-suffix', 'unknown', false],
  ['Empty', 'SECRET_KEY', '', 'unknown', false],
  ['Undefined innocent', 'DESCRIPTION', undefined, 'unknown', false],
  ['Spaces', 'SECRET_KEY', '   ', 'unknown', false],
  ['Case insensitive names', 'cloudflare_api_token', random, 'cloudflare', true],
  ['Malformed JWT safe fallback', 'ODD_NAME', 'eyJhbGciOiJIUzI1NiJ9.not-json.signature', 'unknown', false],
  ['Private shape under public name', 'NEXT_PUBLIC_API_KEY', `sk-${hex}`, 'openai', true],
];

describe('classify', () => {
  it.each(cases)('%s', (_label, name, value, provider, isSecret) => {
    expect(classify(name, value)).toMatchObject({ provider, isSecret });
    if (value && value.length >= 16) expect(JSON.stringify(classify(name, value))).not.toContain(value);
  });

  const appSecretNames = [
    'JWT_SECRET', 'JWT_SIGNING_SECRET', 'SESSION_SECRET', 'COOKIE_SECRET', 'NEXTAUTH_SECRET',
    'AUTH_SECRET', 'BETTER_AUTH_SECRET', 'SECRET_KEY_BASE', 'CSRF_SECRET',
  ];

  it.each(appSecretNames)('permits local generation only for the exact app name %s', name => {
    for (const value of [random, undefined]) {
      const classified = classify(name, value);
      expect(classified).toMatchObject({ provider: 'app-secret', isSecret: true });
      expect(methodFor(classified.provider)).toBe('generate');
    }
  });

  it.each([
    ['SUPABASE_JWT_SECRET', random],
    ['HASURA_GRAPHQL_JWT_SECRET', JSON.stringify({ type: 'HS256', key: random })],
    ['HASURA_GRAPHQL_JWT_SECRET', JSON.stringify({ type: 'HS256', key: random }, null, 2)],
    ['AUTH0_JWT_SECRET', random],
    ['CLERK_JWT_SECRET', random],
    ['KEYCLOAK_JWT_SECRET', random],
    ['FIREBASE_JWT_SECRET', random],
  ])('requires guided rotation for the third-party JWT secret %s', (name, value) => {
    const classified = classify(name!, value);
    expect(classified).toMatchObject({ provider: 'unknown', isSecret: true });
    expect(methodFor(classified.provider)).toBe('guided');
  });

  it.each(appSecretNames)('keeps JSON-looking values under %s on the guided path', name => {
    for (const value of [
      JSON.stringify({ key: random }),
      JSON.stringify([random]),
      `  { "key": "${random}" }`,
      `\n [ "${random}" ]`,
      `{${random}`,
      `[${random}`,
    ]) {
      const classified = classify(name, value);
      expect(classified).toMatchObject({ provider: 'unknown', isSecret: true });
      expect(methodFor(classified.provider)).toBe('guided');
    }
  });

  it('uses confidence to distinguish shapes, provider names, and generic names', () => {
    expect(classify('BANANA', `sk-${hex}`).confidence).toBe('high');
    expect(classify('OPENAI_API_KEY', random).confidence).toBe('medium');
    expect(classify('SOME_TOKEN', random).confidence).toBe('low');
    expect(classify('AWS_SECRET_ACCESS_KEY', `${random}2zA4cD6e`).confidence).toBe('high');
  });

  const mappings: [ProviderId, string, string][] = [
    ['crypto-wallet', 'crypto', 'guided'], ['aws', 'cloud', 'auto'], ['cloudflare', 'cloud', 'atomic-roll'],
    ['github', 'cloud', 'guided'], ['google', 'cloud', 'guided'], ['private-key', 'cloud', 'guided'],
    ['database', 'database', 'guided'], ['supabase', 'database', 'guided'], ['stripe', 'payments', 'guided'],
    ['openai', 'ai', 'auto'], ['anthropic', 'ai', 'guided'], ['openrouter', 'ai', 'auto'],
    ['resend', 'comms', 'auto'], ['sendgrid', 'comms', 'guided'], ['slack', 'comms', 'guided'],
    ['twilio', 'comms', 'guided'], ['app-secret', 'app', 'generate'], ['encryption-key', 'app', 'guided'], ['unknown', 'unknown', 'guided'],
  ];
  it.each(mappings)('maps %s to tier %s and method %s', (provider, tier, method) => {
    expect(tierFor(provider)).toBe(tier);
    expect(methodFor(provider)).toBe(method);
  });
});
