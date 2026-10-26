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
import {
  slackProvider, sendgridProvider, twilioProvider, googleProvider,
  privateKeyProvider, cryptoWalletProvider, unknownProvider,
} from './guided.js';
import { appSecretProvider } from './app-secret.js';
import { encryptionKeyProvider } from './encryption-key.js';

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
  createGuidedAdapter, slackProvider, sendgridProvider, twilioProvider, googleProvider,
  privateKeyProvider, cryptoWalletProvider, unknownProvider, type GuidedProviderId,
} from './guided.js';
export { appSecretProvider } from './app-secret.js';
export { encryptionKeyProvider } from './encryption-key.js';

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
  sendgrid: [],
  twilio: [],
  google: [],
  'private-key': [],
  'crypto-wallet': [],
  'app-secret': [],
  'encryption-key': [],
  unknown: [],
};

export function getProvider(id: ProviderId): ProviderAdapter {
  if (!Object.hasOwn(providers, id)) throw new Error('Unsupported provider');
  return providers[id];
}
