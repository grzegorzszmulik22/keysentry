import { createJwksFetcher } from '../../../src/box/attestation/index.js';
import type { HttpClient } from '../../../src/types.js';
import { createAccounts } from './accounts.js';
import { createBilling } from './billing.js';
import { createRelayStore } from './relay.js';
import { createControlPlaneServer } from './server.js';
import { createGcsStorage, metadataAccessToken, type Storage } from './storage.js';

/** Non-secret settings; Terraform (infra/terraform/control-plane) sets exactly these variables. */
export interface HostedConfig {
  origin: string;
  port: number;
  bucket: string;
  priceId: string;
  boxProjectId: string;
  boxServiceAccount: string;
  allowedDigests: string[];
  trustedProxyHops: number;
  boxQuota: number;
}
/** From Secret Manager through Cloud Run secret environment variables; memory only. */
export interface HostedSecrets { stripeWebhookSecret: string; stripeApiKey: string }

function required(env: NodeJS.ProcessEnv, name: string, pattern: RegExp): string {
  const value = env[name];
  // The variable is named; its value never appears in an error.
  if (typeof value !== 'string' || !pattern.test(value)) throw new Error(`${name} is missing or invalid.`);
  return value;
}
function count(env: NodeJS.ProcessEnv, name: string, fallback: number, max: number): number {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  if (!/^[0-9]{1,4}$/.test(raw) || Number(raw) > max) throw new Error(`${name} is missing or invalid.`);
  return Number(raw);
}

export function hostedConfigFromEnv(env: NodeJS.ProcessEnv): { config: HostedConfig; secrets: HostedSecrets } {
  const config: HostedConfig = {
    origin: required(env, 'KEYSENTRY_CONTROL_ORIGIN', /^https:\/\/[a-z0-9.-]+(?::[0-9]{1,5})?$/),
    port: count(env, 'PORT', 8080, 65535),
    bucket: required(env, 'KEYSENTRY_CONTROL_BUCKET', /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/),
    priceId: required(env, 'KEYSENTRY_STRIPE_PRICE_ID', /^price_[A-Za-z0-9_]{1,120}$/),
    boxProjectId: required(env, 'KEYSENTRY_BOX_PROJECT_ID', /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/),
    boxServiceAccount: required(env, 'KEYSENTRY_BOX_SERVICE_ACCOUNT', /^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$/),
    allowedDigests: required(env, 'KEYSENTRY_BOX_ALLOWED_DIGESTS', /^sha256:[a-f0-9]{64}(?:,sha256:[a-f0-9]{64}){0,63}$/).split(','),
    trustedProxyHops: count(env, 'KEYSENTRY_TRUSTED_PROXY_HOPS', 1, 10),
    boxQuota: count(env, 'KEYSENTRY_BOX_QUOTA', 1, 1000),
  };
  if (config.trustedProxyHops < 1) throw new Error('KEYSENTRY_TRUSTED_PROXY_HOPS is missing or invalid.');
  const secrets: HostedSecrets = {
    stripeWebhookSecret: required(env, 'KEYSENTRY_STRIPE_WEBHOOK_SECRET', /^whsec_[A-Za-z0-9]{8,240}$/),
    stripeApiKey: required(env, 'KEYSENTRY_STRIPE_API_KEY', /^(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,240}$/),
  };
  return { config, secrets };
}

export interface HostedOptions {
  config: HostedConfig;
  secrets: HostedSecrets;
  /**
   * The runtime's egress-guarded HTTPS client. It must reach storage.googleapis.com, api.stripe.com and
   * www.googleapis.com (attestation JWKS), nothing else.
   */
  http: HttpClient;
  /**
   * Reaches only the metadata server's token URL (plain HTTP, link-local), which the HTTPS-only egress guard refuses.
   * Unused when `storage` is injected.
   */
  metadata: HttpClient;
  /** Tests inject a fake; production uses the bucket. */
  storage?: Storage;
  now?: () => number;
  log?: (entry: { event: 'request' | 'cleanup'; status: number }) => void;
}

/**
 * The hosted composition: Cloud Storage state, passkey accounts with durable sessions, Stripe billing, the relay and
 * attested box access. Box provisioning is not wired (live provisioning stays off); POST /boxes answers 503.
 */
export function createHostedControlPlane(options: HostedOptions) {
  const { config, secrets, http } = options;
  const now = options.now ?? Date.now;
  const storage = options.storage ?? createGcsStorage({ http, bucket: config.bucket, accessToken: metadataAccessToken(options.metadata, now) });
  const accounts = createAccounts({ storage, origin: config.origin, now, boxQuota: config.boxQuota });
  return createControlPlaneServer({
    origin: config.origin, host: '0.0.0.0', port: config.port, now,
    accounts,
    relay: createRelayStore({ storage, now }),
    billing: createBilling({ storage, accounts, endpointSecret: secrets.stripeWebhookSecret, priceId: config.priceId, stripe: { http, apiKey: secrets.stripeApiKey }, now }),
    trustedProxy: { header: 'x-forwarded-for', hops: config.trustedProxyHops },
    boxAttestation: { jwks: createJwksFetcher(http, { now: () => new Date(now()) }), projectIds: [config.boxProjectId],
      serviceAccounts: [config.boxServiceAccount], allowedDigests: config.allowedDigests, hardwareModels: ['GCP_INTEL_TDX'] },
    ...(options.log ? { log: options.log } : {}),
  });
}
