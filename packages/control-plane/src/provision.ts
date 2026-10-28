import type { HttpClient } from '../../../src/types.js';

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

export interface Provisioner {
  provision(input: ProvisionInput): Promise<ProvisionOperation>;
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
function failed(): never { throw new Error('Box provisioning failed.'); }

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

  return {
    async provision(input): Promise<ProvisionOperation> {
      const { name, deviceKey } = input ?? {} as ProvisionInput;
      if (!isBoxName(name)) throw new TypeError('Invalid box name.');
      if (!isDeviceKey(deviceKey)) throw new TypeError('Invalid enrollment device key.');
      if (localOrigin === null && process.env.KEYSENTRY_CONTROL_PLANE_LIVE !== '1') {
        throw new Error('Live provisioning is disabled.');
      }
      const instance = {
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
      try {
        const headers: Record<string, string> = { 'content-type': 'application/json' };
        if (localOrigin === null) {
          const token = await options.accessToken?.();
          if (typeof token !== 'string' || token.length === 0 || token.length > 16_384 || /[\r\n\x00]/.test(token)) failed();
          headers.authorization = `Bearer ${token}`;
        }
        const response = await http.request({ method: 'POST', url: instanceUrl, headers, body: JSON.stringify(instance) });
        if (response.status < 200 || response.status >= 300 || Buffer.byteLength(response.text) > 64 * 1024) failed();
        const data = response.json<unknown>();
        if (!data || typeof data !== 'object' || Array.isArray(data)) failed();
        const record = data as Record<string, unknown>;
        if (record.error !== undefined || typeof record.name !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(record.name)
          || (record.status !== 'PENDING' && record.status !== 'RUNNING' && record.status !== 'DONE')
          || (record.targetId !== undefined && (typeof record.targetId !== 'string' || !/^[0-9]{1,32}$/.test(record.targetId)))) failed();
        return {
          name: record.name,
          status: record.status,
          ...(record.targetId === undefined ? {} : { targetId: record.targetId as string }),
        };
      } catch { failed(); }
    },
  };
}
