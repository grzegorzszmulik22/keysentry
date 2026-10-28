import type { ProviderAdapter, ProviderId } from '../types.js';
import { openaiProvider } from './openai.js';
import { anthropicProvider } from './anthropic.js';
import { openrouterProvider } from './openrouter.js';
import { stripeProvider } from './stripe.js';
import { resendProvider } from './resend.js';
import { cloudflareProvider } from './cloudflare.js';
import { githubProvider } from './github.js';
import { awsProvider } from './aws.js';
import { supabaseProvider } from './supabase.js';
import { databaseProvider } from './database.js';
import { slackProvider, privateKeyProvider, cryptoWalletProvider, unknownProvider } from './guided.js';
import { googleProvider } from './google.js';
import { twilioProvider } from './twilio.js';
import { sendgridProvider } from './sendgrid.js';
import { appSecretProvider } from './app-secret.js';
import { encryptionKeyProvider } from './encryption-key.js';
import { groqProvider } from './groq.js';
import { mistralProvider } from './mistral.js';
import { replicateProvider } from './replicate.js';
import { postmarkProvider } from './postmark.js';
import { clerkProvider } from './clerk.js';
import { upstashProvider } from './upstash.js';
import { neonProvider } from './neon.js';

export { openaiProvider, OpenAIGuidedRotationRequiredError, OPENAI_MODEL_PRICES, type OpenAIModelPrice } from './openai.js';
export { anthropicProvider, ANTHROPIC_MODEL_PRICES } from './anthropic.js';
export { openrouterProvider, createCanaryKey } from './openrouter.js';
export { stripeProvider } from './stripe.js';
export { resendProvider, ResendGuidedRotationRequiredError } from './resend.js';
export { cloudflareProvider } from './cloudflare.js';
export { githubProvider } from './github.js';
export { awsProvider } from './aws.js';
export { signAwsRequest, type AwsCredentials, type AwsSigningOptions } from './aws-sigv4.js';
export { supabaseProvider } from './supabase.js';
export { databaseProvider } from './database.js';
export {
  createGuidedAdapter, slackProvider, privateKeyProvider, cryptoWalletProvider, unknownProvider, type GuidedProviderId,
} from './guided.js';
export { googleProvider, createGoogleProvider, GoogleGuidedRotationRequiredError, GOOGLE_CREDENTIALS, GOOGLE_PROJECT, publicGoogleKeyGuidance } from './google.js';
export { twilioProvider, TwilioGuidedRotationRequiredError } from './twilio.js';
export { sendgridProvider, SendGridGuidedRotationRequiredError } from './sendgrid.js';
export { appSecretProvider } from './app-secret.js';
export { encryptionKeyProvider } from './encryption-key.js';
export { groqProvider } from './groq.js';
export { mistralProvider, MISTRAL_ADMIN_KEY } from './mistral.js';
export { replicateProvider } from './replicate.js';
export { postmarkProvider } from './postmark.js';
export { clerkProvider } from './clerk.js';
export { upstashProvider, UpstashGuidedRotationRequiredError } from './upstash.js';
export { neonProvider, NeonGuidedRotationRequiredError } from './neon.js';

const providers: Record<ProviderId, ProviderAdapter> = {
  openai: openaiProvider,
  anthropic: anthropicProvider,
  openrouter: openrouterProvider,
  stripe: stripeProvider,
  resend: resendProvider,
  cloudflare: cloudflareProvider,
  github: githubProvider,
  aws: awsProvider,
  supabase: supabaseProvider,
  database: databaseProvider,
  slack: slackProvider,
  sendgrid: sendgridProvider,
  twilio: twilioProvider,
  google: googleProvider,
  'private-key': privateKeyProvider,
  'crypto-wallet': cryptoWalletProvider,
  'app-secret': appSecretProvider,
  'encryption-key': encryptionKeyProvider,
  unknown: unknownProvider,
  groq: groqProvider,
  mistral: mistralProvider,
  replicate: replicateProvider,
  postmark: postmarkProvider,
  clerk: clerkProvider,
  upstash: upstashProvider,
  neon: neonProvider,
};

/** Credential names read from ProviderContext.credentials; paired AWS values use siblingVars. */
export const PROVIDER_CREDENTIALS: Record<ProviderId, string[]> = {
  openai: ['OPENAI_ADMIN_KEY'],
  anthropic: ['ANTHROPIC_ADMIN_KEY'],
  openrouter: ['OPENROUTER_PROVISIONING_KEY'],
  stripe: [],
  resend: ['RESEND_ADMIN_KEY'],
  cloudflare: ['CLOUDFLARE_ADMIN_TOKEN'],
  github: [],
  aws: [],
  supabase: [],
  database: [],
  slack: [],
  sendgrid: ['SENDGRID_ADMIN_KEY'],
  // The SIDs are identifiers stored next to their secret: a Main API key SID (SK…) or the Account SID (AC…).
  twilio: ['TWILIO_ADMIN_KEY_SID', 'TWILIO_ADMIN_KEY', 'TWILIO_ADMIN_ACCOUNT_SID'],
  // GOOGLE_API_KEYS_PROJECT is a project id or number, not a secret: it is never registered with the redactor.
  google: ['GOOGLE_API_KEYS_ADMIN_KEY', 'GOOGLE_OAUTH_ACCESS_TOKEN', 'GOOGLE_API_KEYS_PROJECT'],
  'private-key': [],
  'crypto-wallet': [],
  'app-secret': [],
  'encryption-key': [],
  unknown: [],
  groq: [],
  mistral: ['MISTRAL_ADMIN_KEY'],
  replicate: [],
  postmark: [],
  clerk: [],
  upstash: ['UPSTASH_ADMIN_EMAIL', 'UPSTASH_ADMIN_KEY'],
  neon: ['NEON_ADMIN_KEY'],
};

export { NON_SECRET_CREDENTIALS, secretCredentialValues } from './credential-kinds.js';

/**
 * The credential sets that let a provider rotate automatically: any one set, with every name in it present. Most
 * providers have one set, PROVIDER_CREDENTIALS itself. Google takes a service-account key (its project_id names the
 * project) or an OAuth access token with GOOGLE_API_KEYS_PROJECT. Twilio needs the management SID and secret;
 * TWILIO_ADMIN_ACCOUNT_SID is needed only when that SID is a Main key SID, which a list of names cannot show.
 */
export function automaticCredentialSets(provider: ProviderId): readonly (readonly string[])[] {
  if (provider === 'google') return [['GOOGLE_API_KEYS_ADMIN_KEY'], ['GOOGLE_OAUTH_ACCESS_TOKEN', 'GOOGLE_API_KEYS_PROJECT']];
  if (provider === 'twilio') return [['TWILIO_ADMIN_KEY_SID', 'TWILIO_ADMIN_KEY']];
  return [PROVIDER_CREDENTIALS[provider]];
}

/**
 * False for providers whose automatic rotation cannot name the old key (rotate returns oldKeyRef null): Neon and
 * Resend do not expose any part of existing key values. The replacement is created, but the possibly compromised old
 * key stays valid until a person deletes it, so an unattended (armed) rotation must not be offered for them.
 */
export function rotationIdentifiesOldKey(provider: ProviderId): boolean {
  return provider !== 'neon' && provider !== 'resend';
}

/** True when the configured credential names (never values) satisfy one of the provider's automatic sets. */
export function automaticCredentialsConfigured(provider: ProviderId, configured: ReadonlySet<string>): boolean {
  return automaticCredentialSets(provider).some(set => set.every(name => configured.has(name)));
}

export function getProvider(id: ProviderId): ProviderAdapter {
  if (!Object.hasOwn(providers, id)) throw new Error('Unsupported provider');
  return providers[id];
}
