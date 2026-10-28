import { createJwksFetcher } from '../../../src/box/attestation/index.js';
import type { HttpClient } from '../../../src/types.js';
import { createAccounts } from './accounts.js';
import { createBilling } from './billing.js';
import { SECRET_REFERENCE } from './egress.js';
import { createProvisioner } from './provision.js';
import { createRelayStore } from './relay.js';
import { createControlPlaneServer } from './server.js';
import { createGcsStorage, metadataAccessToken, type Storage } from './storage.js';

/** Live provisioning settings, read only when `KEYSENTRY_CONTROL_PLANE_LIVE=1`. */
export interface HostedLiveProvisioning {
  zone: string;
  /** `projects/<box project>/regions/<region>/subnetworks/<name>`, an existing private subnet. */
  subnetwork: string;
  /** The box image `registry/path@sha256:...`; its digest must be one of `allowedDigests`. */
  imageReference: string;
}
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
  /** Secret Manager references (`projects/*\/secrets/*\/versions/*`), resolved at startup through the metadata token. */
  secretRefs: { stripeWebhookSecret: string; stripeApiKey: string };
  /** Null unless `KEYSENTRY_CONTROL_PLANE_LIVE=1`. */
  live: HostedLiveProvisioning | null;
}
/** Resolved from Secret Manager at startup; memory only. */
export interface HostedSecrets { stripeWebhookSecret: string; stripeApiKey: string }

/** A setting is missing, malformed or not allowed. Names the variable, never its value. */
export class HostedConfigError extends Error {
  constructor(readonly setting: string, message = `${setting} is missing or invalid.`) {
    super(message);
    this.name = 'HostedConfigError';
  }
}

/** Every variable the hosted entry reads (Cloud Run sets PORT). */
export const HOSTED_SETTINGS = [
  'KEYSENTRY_CONTROL_ORIGIN', 'PORT', 'KEYSENTRY_CONTROL_BUCKET', 'KEYSENTRY_STRIPE_PRICE_ID', 'KEYSENTRY_BOX_PROJECT_ID',
  'KEYSENTRY_BOX_SERVICE_ACCOUNT', 'KEYSENTRY_BOX_ALLOWED_DIGESTS', 'KEYSENTRY_TRUSTED_PROXY_HOPS', 'KEYSENTRY_BOX_QUOTA',
  'KEYSENTRY_STRIPE_WEBHOOK_SECRET_REF', 'KEYSENTRY_STRIPE_API_KEY_REF', 'KEYSENTRY_CONTROL_PLANE_LIVE', 'KEYSENTRY_BOX_ZONE',
  'KEYSENTRY_BOX_SUBNETWORK', 'KEYSENTRY_BOX_IMAGE_REFERENCE',
] as const;
/** Secret values that must never arrive through the environment; only their `_REF` references may. */
const PLAINTEXT_SECRETS = ['KEYSENTRY_STRIPE_WEBHOOK_SECRET', 'KEYSENTRY_STRIPE_API_KEY'] as const;

const PROJECT = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const SERVICE_ACCOUNT = /^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$/;
const DIGESTS = /^sha256:[a-f0-9]{64}(?:,sha256:[a-f0-9]{64}){0,63}$/;
const ZONE = /^[a-z]+(?:-[a-z]+)+[0-9]+-[a-z]$/;
const SUBNETWORK = /^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/regions\/[a-z]+(?:-[a-z]+)+[0-9]+\/subnetworks\/[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const IMAGE = /^[a-z0-9.-]+\/[A-Za-z0-9._/-]+@sha256:[a-f0-9]{64}$/;

function required(env: NodeJS.ProcessEnv, name: string, pattern: RegExp): string {
  const value = env[name];
  // The variable is named; its value never appears in an error.
  if (typeof value !== 'string' || value.length > 4096 || !pattern.test(value)) throw new HostedConfigError(name);
  return value;
}
function count(env: NodeJS.ProcessEnv, name: string, fallback: number, min: number, max: number): number {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  if (!/^[0-9]{1,5}$/.test(raw) || Number(raw) < min || Number(raw) > max) throw new HostedConfigError(name);
  return Number(raw);
}

/**
 * Reads the hosted configuration. The environment holds no secret: the Stripe webhook secret and API key are
 * Secret Manager references (`KEYSENTRY_STRIPE_WEBHOOK_SECRET_REF`, `KEYSENTRY_STRIPE_API_KEY_REF`), and a plaintext
 * `KEYSENTRY_STRIPE_WEBHOOK_SECRET` or `KEYSENTRY_STRIPE_API_KEY` refuses to start.
 */
export function hostedConfigFromEnv(env: NodeJS.ProcessEnv): HostedConfig {
  for (const name of PLAINTEXT_SECRETS) {
    if (env[name] !== undefined) throw new HostedConfigError(name, `${name} must not be set. Give ${name}_REF, a Secret Manager reference, instead.`);
  }
  const origin = required(env, 'KEYSENTRY_CONTROL_ORIGIN', /^https:\/\/[a-z0-9]([a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/);
  const allowedDigests = required(env, 'KEYSENTRY_BOX_ALLOWED_DIGESTS', DIGESTS).split(',');
  const boxProjectId = required(env, 'KEYSENTRY_BOX_PROJECT_ID', PROJECT);
  const boxServiceAccount = required(env, 'KEYSENTRY_BOX_SERVICE_ACCOUNT', SERVICE_ACCOUNT);
  const liveFlag = env.KEYSENTRY_CONTROL_PLANE_LIVE;
  if (liveFlag !== undefined && liveFlag !== '' && liveFlag !== '1' && liveFlag !== '0') throw new HostedConfigError('KEYSENTRY_CONTROL_PLANE_LIVE');
  let live: HostedLiveProvisioning | null = null;
  if (liveFlag === '1') {
    const zone = required(env, 'KEYSENTRY_BOX_ZONE', ZONE);
    const subnetwork = required(env, 'KEYSENTRY_BOX_SUBNETWORK', SUBNETWORK);
    // The box runs in the box project, in the zone's region.
    if (!subnetwork.startsWith(`projects/${boxProjectId}/regions/${zone.slice(0, -2)}/subnetworks/`)) throw new HostedConfigError('KEYSENTRY_BOX_SUBNETWORK');
    const imageReference = required(env, 'KEYSENTRY_BOX_IMAGE_REFERENCE', IMAGE);
    if (!allowedDigests.includes(imageReference.slice(imageReference.indexOf('@') + 1))) throw new HostedConfigError('KEYSENTRY_BOX_IMAGE_REFERENCE');
    if (!boxServiceAccount.endsWith(`@${boxProjectId}.iam.gserviceaccount.com`)) throw new HostedConfigError('KEYSENTRY_BOX_SERVICE_ACCOUNT');
    live = { zone, subnetwork, imageReference };
  }
  return {
    origin,
    port: count(env, 'PORT', 8080, 0, 65535),
    bucket: required(env, 'KEYSENTRY_CONTROL_BUCKET', /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/),
    priceId: required(env, 'KEYSENTRY_STRIPE_PRICE_ID', /^price_[A-Za-z0-9_]{1,120}$/),
    boxProjectId,
    boxServiceAccount,
    allowedDigests,
    trustedProxyHops: count(env, 'KEYSENTRY_TRUSTED_PROXY_HOPS', 1, 1, 10),
    boxQuota: count(env, 'KEYSENTRY_BOX_QUOTA', 1, 0, 1000),
    secretRefs: {
      stripeWebhookSecret: required(env, 'KEYSENTRY_STRIPE_WEBHOOK_SECRET_REF', SECRET_REFERENCE),
      stripeApiKey: required(env, 'KEYSENTRY_STRIPE_API_KEY_REF', SECRET_REFERENCE),
    },
    live,
  };
}

export type HostedLog = (entry: { event: 'request' | 'cleanup'; status: number }) => void;
export interface HostedOptions {
  config: HostedConfig;
  secrets: HostedSecrets;
  /**
   * The egress-guarded HTTPS client (createHostedHttp): the bucket's objects, Stripe Checkout and subscriptions, the
   * attestation JWKS and, with live provisioning only, instance creation in the box project.
   */
  http: HttpClient;
  /** Reaches only the metadata server's token URL (createMetadataHttp). Unused when `accessToken` is given. */
  metadata: HttpClient;
  /** The runtime service account's token; defaults to a cached metadata-server token. */
  accessToken?: () => Promise<string>;
  /** Tests inject a fake; production uses the bucket. */
  storage?: Storage;
  now?: () => number;
  log?: HostedLog;
}

/**
 * The hosted composition: Cloud Storage state, passkey accounts with durable sessions, Stripe billing and Checkout,
 * the relay, attested box access, the web page, and box provisioning only when `config.live` is set (the provisioner
 * itself also refuses unless `KEYSENTRY_CONTROL_PLANE_LIVE=1`). Without it, POST /boxes answers 503.
 */
export function createHostedControlPlane(options: HostedOptions) {
  const { config, secrets, http } = options;
  const now = options.now ?? Date.now;
  const accessToken = options.accessToken ?? metadataAccessToken(options.metadata, now);
  const storage = options.storage ?? createGcsStorage({ http, bucket: config.bucket, accessToken });
  const accounts = createAccounts({ storage, origin: config.origin, now, boxQuota: config.boxQuota });
  const provisioner = config.live ? createProvisioner({
    http, projectId: config.boxProjectId, zone: config.live.zone, subnetwork: config.live.subnetwork, serviceAccount: config.boxServiceAccount,
    imageReference: config.live.imageReference, allowedDigests: config.allowedDigests, relayOrigin: config.origin, accessToken,
  }) : undefined;
  return createControlPlaneServer({
    origin: config.origin, host: '0.0.0.0', port: config.port, now,
    accounts,
    relay: createRelayStore({ storage, now }),
    billing: createBilling({ storage, accounts, endpointSecret: secrets.stripeWebhookSecret, priceId: config.priceId, stripe: { http, apiKey: secrets.stripeApiKey }, now }),
    trustedProxy: { header: 'x-forwarded-for', hops: config.trustedProxyHops },
    boxAttestation: { jwks: createJwksFetcher(http, { now: () => new Date(now()) }), projectIds: [config.boxProjectId],
      serviceAccounts: [config.boxServiceAccount], allowedDigests: config.allowedDigests, hardwareModels: ['GCP_INTEL_TDX'] },
    ...(provisioner ? { provisioner } : {}),
    ...(options.log ? { log: options.log } : {}),
  });
}
