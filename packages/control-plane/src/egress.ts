import { CONFIDENTIAL_SPACE_JWKS_URL } from '../../../src/box/attestation/jwks.js';
import { createGuardedHttp } from '../../../src/net/guarded-http.js';
import type { EgressRule, HttpClient, HttpRequest } from '../../../src/types.js';

/** The only metadata-server URL the control plane reads: its service account's OAuth access token. */
export const METADATA_TOKEN_URL = 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token';
const GCS = 'https://storage.googleapis.com';
const STRIPE = 'https://api.stripe.com';
const COMPUTE = 'https://compute.googleapis.com';
const SECRET_MANAGER = 'https://secretmanager.googleapis.com';
const JWKS = new URL(CONFIDENTIAL_SPACE_JWKS_URL);

/** Fixed text: the refused destination is never echoed. */
export class DestinationRefusedError extends Error {
  readonly code = 'EGRESS_BLOCKED';
  constructor() { super('The control plane does not send requests to that destination.'); this.name = 'DestinationRefusedError'; }
}

interface Endpoint { method: HttpRequest['method']; origin: string; path: RegExp | string }

/** Method, origin and path checks in front of the host guard; anything else is refused before any I/O. */
function endpoints(inner: HttpClient, allowed: readonly Endpoint[]): HttpClient {
  return {
    async request(req) {
      let url: URL;
      try { url = new URL(req.url); } catch { throw new DestinationRefusedError(); }
      if (url.username || url.password || url.hash || !allowed.some(endpoint => endpoint.method === req.method && endpoint.origin === url.origin
        && (typeof endpoint.path === 'string' ? endpoint.path === url.pathname : endpoint.path.test(url.pathname)))) {
        throw new DestinationRefusedError();
      }
      return inner.request(req);
    },
  };
}

export interface HostedEgressOptions {
  /** The state bucket; only its objects are reachable. */
  bucket: string;
  /** Only with live provisioning: creating, reading, stopping and starting instances in this project and zone. */
  compute?: { projectId: string; zone: string } | null;
}
/** A box instance name (the provisioner's `BOX_NAME`). */
const INSTANCE_NAME = '[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?';
const instances = (compute: { projectId: string; zone: string }) => `/compute/v1/projects/${compute.projectId}/zones/${compute.zone}/instances`;

/**
 * The hosted control plane's HTTPS client: the runtime's egress guard (HTTPS only, DNS names only, no redirects across
 * owners, no secret-looking URLs) limited to Cloud Storage, Stripe, the Confidential Space signing keys and, with live
 * provisioning only, Compute Engine; then narrowed to the exact methods and paths the control plane calls.
 */
export function createHostedHttp(transport: HttpClient, options: HostedEgressOptions): HttpClient {
  if (typeof options.bucket !== 'string' || !/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(options.bucket)) throw new TypeError('Invalid egress configuration.');
  const compute = options.compute ?? null;
  if (compute && (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(compute.projectId) || !/^[a-z]+(?:-[a-z]+)+[0-9]+-[a-z]$/.test(compute.zone))) {
    throw new TypeError('Invalid egress configuration.');
  }
  const rules: EgressRule[] = [
    { host: 'storage.googleapis.com', owner: 'control-plane-storage', purpose: 'Control-plane state bucket (Cloud Storage JSON API)' },
    { host: 'api.stripe.com', owner: 'control-plane-stripe', purpose: 'Stripe Checkout Sessions and subscription confirmation' },
    { host: 'www.googleapis.com', owner: 'control-plane-attestation', purpose: 'Confidential Space token signing keys' },
    ...(compute ? [{ host: 'compute.googleapis.com', owner: 'control-plane-compute', purpose: 'Box instances: create, read, stop and start (live provisioning)' }] : []),
  ];
  const bucket = options.bucket;
  return endpoints(createGuardedHttp(transport, { rules, maxRedirects: 0 }), [
    { method: 'GET', origin: GCS, path: new RegExp(`^/storage/v1/b/${bucket}/o(?:/[^/]+)?$`) },
    { method: 'DELETE', origin: GCS, path: new RegExp(`^/storage/v1/b/${bucket}/o/[^/]+$`) },
    { method: 'POST', origin: GCS, path: `/upload/storage/v1/b/${bucket}/o` },
    { method: 'GET', origin: STRIPE, path: /^\/v1\/subscriptions\/[A-Za-z0-9_-]{1,128}$/ },
    { method: 'POST', origin: STRIPE, path: '/v1/checkout/sessions' },
    { method: 'GET', origin: JWKS.origin, path: JWKS.pathname },
    ...(compute ? [
      { method: 'POST' as const, origin: COMPUTE, path: instances(compute) },
      // N1 reconciliation (instances.get) and the downgrade stop and owner's start, for one box name each.
      { method: 'GET' as const, origin: COMPUTE, path: new RegExp(`^${instances(compute)}/${INSTANCE_NAME}$`) },
      { method: 'POST' as const, origin: COMPUTE, path: new RegExp(`^${instances(compute)}/${INSTANCE_NAME}/(?:stop|start)$`) },
    ] : []),
  ]);
}

/**
 * Reaches exactly one URL: the metadata server's token endpoint (plain HTTP on the link-local metadata host, which the
 * HTTPS-only guard refuses by design), with the required `Metadata-Flavor: Google` header and nothing else.
 */
export function createMetadataHttp(transport: HttpClient): HttpClient {
  return {
    async request(req) {
      const flavor = Object.entries(req.headers ?? {}).filter(([name]) => name.toLowerCase() === 'metadata-flavor');
      if (req.method !== 'GET' || req.url !== METADATA_TOKEN_URL || req.body !== undefined || flavor.length !== 1 || flavor[0]![1] !== 'Google') {
        throw new DestinationRefusedError();
      }
      return transport.request({ method: 'GET', url: METADATA_TOKEN_URL, headers: { 'Metadata-Flavor': 'Google' } });
    },
  };
}

/** `projects/<project id or number>/secrets/<id>/versions/<latest or number>`. */
export const SECRET_REFERENCE = /^projects\/(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{1,20})\/secrets\/[A-Za-z0-9_-]{1,255}\/versions\/(?:latest|[1-9][0-9]{0,9})$/;

/** Startup only: GET on the `:access` URL of exactly these Secret Manager references. */
export function createSecretManagerHttp(transport: HttpClient, references: readonly string[]): HttpClient {
  if (!references.length || references.some(reference => typeof reference !== 'string' || !SECRET_REFERENCE.test(reference))) {
    throw new TypeError('Invalid egress configuration.');
  }
  const guarded = createGuardedHttp(transport, { maxRedirects: 0, rules: [
    { host: 'secretmanager.googleapis.com', owner: 'control-plane-secrets', purpose: 'Stripe credentials, read once at startup' },
  ] });
  return endpoints(guarded, references.map(reference => ({ method: 'GET' as const, origin: SECRET_MANAGER, path: `/v1/${reference}:access` })));
}
