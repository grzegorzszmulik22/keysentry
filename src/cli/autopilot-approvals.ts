import type { StateStore } from '../core/index.js';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { canonicalJson, signDetached, verifyDetached, type DeviceKey } from '../security/index.js';
import type { ApprovalRequest, AuditLog, HttpClient, PasskeyCredential } from '../types.js';
import { actionDigest, APPROVAL_PREFIX, ApprovalError, createApprovalService, createRelay } from '../approvals/index.js';
import type { ApprovalAction, SignedDeviceApproval } from '../approvals/index.js';
import { APPROVAL_REQUEST_PREFIX } from './watcher.js';
import { CliError } from './errors.js';

export interface AutopilotApprovalDependencies {
  store: StateStore; audit: AuditLog; http: HttpClient;
  deviceKey(): Promise<DeviceKey>; watcherPublicKeys(): Promise<Buffer[]>;
  deviceKeys(): Promise<{keyId: string; publicKeyDer: Buffer}[]>; passkeys(): Promise<PasskeyCredential[]>;
  now?: () => Date; relay?: {server: string; topic: string; token?: string} | null; assertHuman(action: string): void;
}

interface PendingAutopilot { action: ApprovalAction; request: ApprovalRequest }
interface RequestMetadata { actionId: string; digest: string; expiresAt: string; kind: 'autopilot'; keyCount: number }
const MAX_RESPONSE = 4 * 1024 * 1024;
const MAX_LINE = 16 * 1024;
const WINDOW = 10 * 60 * 1000;
const record = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
function fields(value: Record<string, unknown>, expected: string[]): boolean {
  const keys = Object.keys(value); return keys.length === expected.length && keys.every(key => expected.includes(key));
}
function timestamp(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) return false;
  const at = Date.parse(value);
  if (!Number.isFinite(at)) return false;
  const canonical = new Date(at).toISOString(); return value === canonical || value === canonical.replace('.000Z', 'Z');
}
function assertRequestCurrent(expiresAt: unknown, now: Date): asserts expiresAt is string {
  if (!timestamp(expiresAt)) throw new CliError('The autopilot approval request is invalid.');
  if (Date.parse(expiresAt) <= now.getTime()) throw new CliError('The autopilot approval request has expired.');
  if (Date.parse(expiresAt) > now.getTime() + WINDOW) throw new CliError('The autopilot approval request expiry is invalid.');
}
function checkLocal(entry: PendingAutopilot, id: string, now: Date): RequestMetadata {
  try {
    if (!entry.action || entry.action.id !== id || entry.action.kind !== 'autopilot' || !entry.request || entry.request.actionId !== id
      || entry.request.widening !== false || actionDigest(entry.action) !== entry.request.digest) throw new Error();
  } catch { throw new CliError('The saved autopilot approval request does not match this action.'); }
  assertRequestCurrent(entry.request.expiresAt, now);
  return { actionId: id, digest: entry.request.digest, expiresAt: entry.request.expiresAt, kind: 'autopilot', keyCount: entry.action.clusterIds.length };
}
function relayConfiguration(deps: AutopilotApprovalDependencies): { url: string; headers: Record<string, string> } {
  const relay = deps.relay;
  if (!relay) throw new CliError('No approval relay is configured.');
  try {
    const server = new URL(relay.server);
    if (server.protocol !== 'https:' || server.username || server.password || server.pathname !== '/' || server.search || server.hash || server.port
      || !/^[A-Za-z0-9_-]{1,64}$/.test(relay.topic) || relay.token !== undefined && /[\x00-\x1f\x7f]/.test(relay.token)) throw new Error();
    return { url: `${server.origin}/${relay.topic}`, headers: relay.token ? { Authorization: `Bearer ${relay.token}` } : {} };
  } catch { throw new CliError('The approval relay configuration is invalid.'); }
}

/** Only a known watcher's signed action digest can become a remote device approval. */
async function remoteRequest(id: string, deps: AutopilotApprovalDependencies, now: Date): Promise<RequestMetadata> {
  const { url, headers } = relayConfiguration(deps);
  const keys = await deps.watcherPublicKeys();
  if (!keys.length) throw new CliError('A trusted watcher public key is required before approving through the relay.');
  let body: string;
  try {
    const response = await deps.http.request({ method: 'GET', url: url + '/json?poll=1', headers });
    if (response.status < 200 || response.status >= 300) throw new Error(); body = response.text;
  } catch { throw new CliError('The autopilot approval request could not be read from the relay.'); }
  if (Buffer.byteLength(body) > MAX_RESPONSE) throw new CliError('The approval relay response is too large.');
  const publicKeys = new Map(keys.map(key => [createHash('sha256').update(key).digest('hex').slice(0, 16), key]));
  let offset = 0;
  while (offset < body.length) {
    const end = body.indexOf('\n', offset); const line = body.slice(offset, end < 0 ? body.length : end); offset = end < 0 ? body.length : end + 1;
    if (!line.trim()) continue;
    if (Buffer.byteLength(line) > MAX_LINE) throw new CliError('An approval relay message is too large.');
    let wrapper: unknown; let input: unknown;
    try { wrapper = JSON.parse(line); } catch { continue; }
    if (!record(wrapper) || wrapper.event !== 'message' || wrapper.topic !== deps.relay!.topic || typeof wrapper.id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(wrapper.id)
      || typeof wrapper.time !== 'number' || !Number.isSafeInteger(wrapper.time) || wrapper.time < 0 || typeof wrapper.message !== 'string') continue;
    try { input = JSON.parse(wrapper.message); } catch { continue; }
    if (!record(input) || !fields(input, ['type', 'v', 'request', 'keyId', 'sig']) || input.type !== 'keysentry-approval-request' || input.v !== 1
      || !record(input.request) || !fields(input.request, ['actionId', 'digest', 'expiresAt', 'kind', 'keyCount'])) continue;
    const request = input.request;
    if (request.actionId !== id || request.kind !== 'autopilot' || typeof request.digest !== 'string' || !/^[a-f0-9]{64}$/.test(request.digest)
      || typeof request.keyCount !== 'number' || !Number.isInteger(request.keyCount) || request.keyCount < 0 || request.keyCount > 10_000
      || typeof input.keyId !== 'string' || typeof input.sig !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(input.sig)) continue;
    const key = publicKeys.get(input.keyId); if (!key) continue;
    const sig = Buffer.from(input.sig, 'base64'); if (sig.length !== 64 || sig.toString('base64') !== input.sig) continue;
    if (!verifyDetached(key, Buffer.from(APPROVAL_REQUEST_PREFIX + canonicalJson({ request, keyId: input.keyId })), sig)) continue;
    assertRequestCurrent(request.expiresAt, now);
    return request as unknown as RequestMetadata;
  }
  throw new CliError('A current signed autopilot approval request was not found on the relay.');
}

/** Returns null only for an unknown local id, allowing the existing monitor approval path to run. */
export async function approveAutopilot(id: string, options: {relay?: boolean}, deps: AutopilotApprovalDependencies): Promise<{actionId: string; digest: string; status: 'approved' | 'published'} | null> {
  deps.assertHuman('approve an autopilot action');
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(id)) throw new CliError('The autopilot approval id is invalid.');
  try {
    const now = deps.now?.() ?? new Date();
    if (!Number.isFinite(now.getTime())) throw new CliError('The approval clock could not be read.');
    const pending = await deps.store.readJson<{ actions: PendingAutopilot[] }>('pending', join(deps.store.paths.dir, 'watcher-approvals.json'));
    const local = pending?.actions.find(entry => entry.action?.id === id || entry.request?.actionId === id);
    if (!local && !options.relay) return null;
    const request = local ? checkLocal(local, id, now) : await remoteRequest(id, deps, now);
    const key = await deps.deviceKey();
    const signedData = { actionId: id, digest: request.digest, at: now.toISOString() };
    const signed: SignedDeviceApproval = { ...signedData, keyId: key.keyId, sig: signDetached(key.privateKeyDer, Buffer.from(APPROVAL_PREFIX + canonicalJson(signedData))).toString('base64') };
    if (options.relay) {
      relayConfiguration(deps);
      const relay = createRelay({ ...deps.relay!, http: deps.http, audit: deps.audit, deviceKeys: deps.deviceKeys,
        trustedKeyIds: (await deps.deviceKeys()).map(key => key.keyId), now: deps.now });
      await relay.publishApproval(signed);
      await deps.audit.append({ kind: 'autopilot-approval-published', summary: 'A device-signed autopilot approval was published to the configured relay.', data: { actionId: id } });
      return { actionId: id, digest: request.digest, status: 'published' };
    }
    const service = createApprovalService({ store: deps.store, audit: deps.audit, credentials: deps.passkeys, deviceKeys: deps.deviceKeys,
      rpId: 'localhost', origins: ['http://localhost'], now: deps.now });
    await service.approveWithDevice(id, signed);
    return { actionId: id, digest: request.digest, status: 'approved' };
  } catch (error) {
    await deps.audit.append({ kind: 'autopilot-approval-rejected', summary: 'An autopilot approval was not accepted.' });
    if (error instanceof CliError) throw error;
    if (error instanceof ApprovalError) throw new CliError(error.message);
    throw new CliError('The autopilot approval could not be completed.');
  }
}
