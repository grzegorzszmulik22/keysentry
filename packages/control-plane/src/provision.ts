import type { HttpClient, HttpResponse } from '../../../src/types.js';

export interface ProvisionerOptions {
  http: HttpClient;
  projectId: string;
  zone: string;
  /** Existing private subnet; provisioner does not create network or IAM resources. */
  subnetwork: string;
  serviceAccount: string;
  imageReference: string;
  /** Digests obtained from the independently verified public allow-list. */
  allowedDigests: readonly string[];
  /**
   * The control plane's own public origin, written to `keysentry-relay-origin` so the box finds its relay. HTTPS,
   * or with an emulator origin also an exact `http://127.0.0.1:<port>` loopback relay.
   */
  relayOrigin: string;
  /** Exact origin of a locally started emulator, never a request-provided URL. */
  emulatorOrigin?: string;
  /** Live-only credential provider. The live environment gate is checked first. */
  accessToken?: () => Promise<string>;
}

export interface ProvisionOperation {
  name: string;
  status: 'PENDING' | 'RUNNING' | 'DONE';
  targetId?: string;
}

export interface ProvisionInput {
  name: string;
  /** The owner's enrollment device public key: Ed25519 SPKI DER, base64 (44 bytes). Public, untrusted routing. */
  deviceKey: string;
}

/** What Compute says about one instance (`instances.get`): absent, or present with its keysentry routing metadata. */
export type InstanceState =
  | { exists: false }
  | { exists: true; status: string; boxId?: string; deviceKey?: string };

export interface Provisioner {
  provision(input: ProvisionInput): Promise<ProvisionOperation>;
  /** N1 reconciliation: `instances.get`. Throws a `ProvisionError` when Compute gives no definite answer. */
  inspect(name: string): Promise<InstanceState>;
  /** Downgrade: `instances.stop`; `absent` when the instance does not exist. Nothing is ever deleted. */
  stop(name: string): Promise<'stopping' | 'absent'>;
  /** The owner's start request once the plan is paid again: `instances.start`. */
  start(name: string): Promise<void>;
}

/**
 * Fixed text only. `refused` is a definite refusal, so no instance was created: nothing was sent, or Compute rejected
 * the request (4xx other than 408 and 409). `unknown` is everything else (409 alreadyExists, 408, 5xx, a timeout or
 * transport error after sending, an unreadable reply): the instance may exist and the reservation must be reconciled.
 */
export class ProvisionError extends Error {
  constructor(readonly outcome: 'refused' | 'unknown', message = 'Box provisioning failed.') {
    super(message);
    this.name = 'ProvisionError';
  }
}

/** Compute instance names (RFC 1035 label), excluding Google's reserved `gcp-` prefix. */
export const BOX_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
export function isBoxName(value: unknown): value is string {
  return typeof value === 'string' && BOX_NAME.test(value) && !value.startsWith('gcp-');
}
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
/** A canonical base64 Ed25519 SPKI DER public key, the form `readBoxRoute` accepts from metadata. */
export function isDeviceKey(value: unknown): value is string {
  if (typeof value !== 'string' || value.length !== 60) return false;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length === 44 && bytes.toString('base64') === value && bytes.subarray(0, 12).equals(ED25519_SPKI_PREFIX);
}
/** Instance metadata keys a box carries: two for the launcher, three non-secret routing attributes for the agent. */
export const BOX_METADATA_KEYS = ['tee-image-reference', 'tee-restart-policy', 'keysentry-box-id', 'keysentry-relay-origin', 'keysentry-enroll-device-key'] as const;

function configurationError(): never { throw new TypeError('Invalid provisioning configuration.'); }
function refused(message?: string): never { throw new ProvisionError('refused', message); }
function unknown(): never { throw new ProvisionError('unknown'); }
/** A non-2xx reply: a definite rejection, or no definite answer (see `ProvisionError`). */
function rejection(status: number): never {
  if (status >= 400 && status < 500 && status !== 408 && status !== 409) refused();
  unknown();
}

function emulatorOrigin(value: string): string {
  try {
    const url = new URL(value);
    if (!/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(value)
      || url.origin !== value || url.hostname !== '127.0.0.1' || !url.port
      || Number(url.port) > 65535 || url.username || url.password) throw new Error();
    return value;
  } catch { throw new TypeError('Invalid emulator origin.'); }
}

function relay(value: string, local: boolean): string {
  try {
    const url = new URL(value);
    if (url.origin !== value || url.username || url.password || value.length > 255) throw new Error();
    if (url.protocol === 'https:' || (local && /^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(value))) return value;
    throw new Error();
  } catch { configurationError(); }
}

function validImageReference(value: string): boolean {
  if (typeof value !== 'string' || value.length > 1024) return false;
  const match = /^([a-z0-9.-]+)\/([A-Za-z0-9._/-]+)@(sha256:[a-f0-9]{64})$/.exec(value);
  if (!match) return false;
  return match[1]!.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))
    && match[2]!.split('/').every((part) => part !== '.' && part !== '..' && /^[A-Za-z0-9._-]+$/.test(part));
}

/** Creates only the instance; its subnet, firewall, identity and KMS policy must already exist. */
export function createProvisioner(options: ProvisionerOptions): Provisioner {
  const { http, projectId, zone, subnetwork, serviceAccount, imageReference } = options;
  if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(projectId)
    || !/^[a-z]+(?:-[a-z]+)+[0-9]+-[a-z]$/.test(zone)
    || serviceAccount !== `${serviceAccount.split('@')[0]}@${projectId}.iam.gserviceaccount.com`
    || !/^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$/.test(serviceAccount)
    || !validImageReference(imageReference)
    || !Array.isArray(options.allowedDigests) || options.allowedDigests.length === 0
    || !options.allowedDigests.every((digest) => typeof digest === 'string' && /^sha256:[a-f0-9]{64}$/.test(digest))
    || !options.allowedDigests.includes(imageReference.split('@')[1]!)) configurationError();
  const region = zone.slice(0, -2);
  const subnetPrefix = `projects/${projectId}/regions/${region}/subnetworks/`;
  if (!subnetwork.startsWith(subnetPrefix) || !/^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(subnetwork.slice(subnetPrefix.length))) configurationError();
  const localOrigin = options.emulatorOrigin === undefined ? null : emulatorOrigin(options.emulatorOrigin);
  const relayOrigin = relay(options.relayOrigin, localOrigin !== null);
  const instanceUrl = `${localOrigin ?? 'https://compute.googleapis.com'}/compute/v1/projects/${projectId}/zones/${zone}/instances`;

  const live = () => {
    if (localOrigin === null && process.env.KEYSENTRY_CONTROL_PLANE_LIVE !== '1') refused('Live provisioning is disabled.');
  };
  /** The call's headers. A token that cannot be obtained means nothing was sent: a definite refusal. */
  async function headers(json: boolean): Promise<Record<string, string>> {
    const result: Record<string, string> = json ? { 'content-type': 'application/json' } : {};
    if (localOrigin === null) {
      let token: unknown;
      try { token = await options.accessToken?.(); } catch { refused(); }
      if (typeof token !== 'string' || token.length === 0 || token.length > 16_384 || /[\r\n\x00]/.test(token)) refused();
      result.authorization = `Bearer ${token}`;
    }
    return result;
  }
  async function send(method: 'GET' | 'POST', url: string, body: string | undefined, maxBytes: number): Promise<HttpResponse> {
    const sent = await headers(body !== undefined);
    let response: HttpResponse;
    try { response = await http.request({ method, url, headers: sent, ...(body === undefined ? {} : { body }) }); }
    catch (error) {
      // The egress guard refuses before any I/O; every other transport failure may have reached Compute.
      if ((error as { code?: unknown } | null)?.code === 'EGRESS_BLOCKED') refused();
      unknown();
    }
    if (typeof response?.status !== 'number' || typeof response.text !== 'string' || Buffer.byteLength(response.text) > maxBytes) unknown();
    return response;
  }
  function record(response: HttpResponse): Record<string, unknown> {
    let data: unknown;
    try { data = response.json<unknown>(); } catch { unknown(); }
    if (!data || typeof data !== 'object' || Array.isArray(data)) unknown();
    return data as Record<string, unknown>;
  }
  function instance(name: unknown): string {
    if (!isBoxName(name)) refused('Invalid box name.');
    return `${instanceUrl}/${name}`;
  }

  return {
    async provision(input): Promise<ProvisionOperation> {
      const { name, deviceKey } = input ?? {} as ProvisionInput;
      instance(name);
      if (!isDeviceKey(deviceKey)) refused('Invalid enrollment device key.');
      live();
      const body = {
        name,
        machineType: `zones/${zone}/machineTypes/c3-standard-4`,
        confidentialInstanceConfig: { enableConfidentialCompute: true, confidentialInstanceType: 'TDX' },
        shieldedInstanceConfig: { enableSecureBoot: true },
        scheduling: { onHostMaintenance: 'TERMINATE', automaticRestart: true },
        disks: [{ boot: true, autoDelete: true, initializeParams: {
          sourceImage: 'projects/confidential-space-images/global/images/family/confidential-space',
          diskType: `zones/${zone}/diskTypes/pd-balanced`, diskSizeGb: '20',
        } }],
        networkInterfaces: [{ subnetwork }],
        serviceAccounts: [{ email: serviceAccount, scopes: ['https://www.googleapis.com/auth/cloud-platform'] }],
        // Only the launcher's two keys and three non-secret routing attributes; never a secret or a tee-env-*.
        metadata: { items: [
          { key: 'tee-image-reference', value: imageReference }, { key: 'tee-restart-policy', value: 'Always' },
          { key: 'keysentry-box-id', value: name }, { key: 'keysentry-relay-origin', value: relayOrigin },
          { key: 'keysentry-enroll-device-key', value: deviceKey },
        ] },
      };
      const response = await send('POST', instanceUrl, JSON.stringify(body), 64 * 1024);
      if (response.status < 200 || response.status >= 300) rejection(response.status);
      // Accepted: from here on the instance may exist, so a malformed or failed operation is `unknown`, not a refusal.
      const data = record(response);
      if (data.error !== undefined || typeof data.name !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(data.name)
        || (data.status !== 'PENDING' && data.status !== 'RUNNING' && data.status !== 'DONE')
        || (data.targetId !== undefined && (typeof data.targetId !== 'string' || !/^[0-9]{1,32}$/.test(data.targetId)))) unknown();
      return {
        name: data.name,
        status: data.status,
        ...(data.targetId === undefined ? {} : { targetId: data.targetId as string }),
      };
    },
    async inspect(name): Promise<InstanceState> {
      const url = instance(name);
      live();
      const response = await send('GET', url, undefined, 256 * 1024);
      if (response.status === 404) return { exists: false };
      if (response.status !== 200) unknown();
      const data = record(response);
      if (data.name !== name || typeof data.status !== 'string' || !/^[A-Z_]{1,32}$/.test(data.status)) unknown();
      const items = (data.metadata as { items?: unknown } | null | undefined)?.items;
      const values = new Map<string, string>();
      for (const item of Array.isArray(items) ? items : []) {
        const entry = item as { key?: unknown; value?: unknown } | null;
        if (entry && typeof entry.key === 'string' && typeof entry.value === 'string' && !values.has(entry.key)) values.set(entry.key, entry.value);
      }
      const boxId = values.get('keysentry-box-id'), deviceKey = values.get('keysentry-enroll-device-key');
      return { exists: true, status: data.status, ...(isBoxName(boxId) ? { boxId } : {}), ...(isDeviceKey(deviceKey) ? { deviceKey } : {}) };
    },
    async stop(name): Promise<'stopping' | 'absent'> {
      const url = instance(name);
      live();
      // instances.stop takes only query parameters; the request body must be empty.
      const response = await send('POST', `${url}/stop`, undefined, 64 * 1024);
      if (response.status === 404) return 'absent';
      if (response.status < 200 || response.status >= 300) rejection(response.status);
      return 'stopping';
    },
    async start(name): Promise<void> {
      const url = instance(name);
      live();
      const response = await send('POST', `${url}/start`, undefined, 64 * 1024);
      if (response.status < 200 || response.status >= 300) rejection(response.status);
    },
  };
}
