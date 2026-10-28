import type { StateStore } from '../core/index.js';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { canonicalJson, signDetached, verifyDetached, type DeviceKey } from '../security/index.js';
import type { ApprovalRequest, AuditLog, HttpClient, PasskeyCredential } from '../types.js';
import { actionDigest, APPROVAL_PREFIX, ApprovalError, ApprovalPendingError, createApprovalService, createRelay } from '../approvals/index.js';
import type { ApprovalAction, ApprovalCluster, ApprovalQuorum, SignedDeviceApproval } from '../approvals/index.js';
import { pendingText } from './team-governance.js';
import { APPROVAL_REQUEST_PREFIX } from './watcher.js';
import { CliError } from './errors.js';

export interface AutopilotApprovalDependencies {
  store: StateStore; audit: AuditLog; http: HttpClient;
  deviceKey(): Promise<DeviceKey>; watcherPublicKeys(): Promise<Buffer[]>;
  deviceKeys(): Promise<{keyId: string; publicKeyDer: Buffer}[]>; passkeys(): Promise<PasskeyCredential[]>;
  now?: () => Date; relay?: {server: string; topic: string; token?: string} | null; assertHuman(action: string): void;
  review?(request: AutopilotApprovalReview): void;
  confirm?(actionId: string): Promise<boolean>;
  executeApprovedAction?(actionId: string): Promise<{ executed: boolean; reason?: string }>;
  /** Team mode: the roster and policy decide how many distinct members must approve (src/cli/team-governance.ts). */
  quorum?: ApprovalQuorum | null;
  /**
   * Team dashboard: the signed-in member whose own roster passkey the dashboard's gate verified over this request.
   * Counted as that member instead of this computer's device key.
   */
  member?: { memberId: string; credentialId: string };
}

interface PendingAutopilot { action: ApprovalAction; request: ApprovalRequest }
export interface AutopilotApprovalReview { actionId: string; clusters: ApprovalCluster[] }
interface RequestMetadata extends AutopilotApprovalReview {
  digest: string; expiresAt: string; kind: 'autopilot'; keyCount: number; watcherCheckMinutes: number;
}
export interface AutopilotApprovalResult {
  /** `recorded`: a team approval was saved and more distinct members must approve before anything runs. */
  actionId: string; digest: string; status: 'approved' | 'published' | 'executed' | 'cancelled' | 'recorded';
  watcherCheckMinutes?: number; reason?: string;
  /** Team quorum progress (status `recorded`). */
  approvals?: number; required?: number; role?: 'operator' | 'admin'; text?: string;
}
const MAX_RESPONSE = 4 * 1024 * 1024;
const MAX_LINE = 16 * 1024;
const MAX_REQUEST_TTL = 7 * 24 * 60 * 60 * 1000;
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
  if (Date.parse(expiresAt) > now.getTime() + MAX_REQUEST_TTL) throw new CliError('The autopilot approval request expiry is invalid.');
}
function checkLocal(entry: PendingAutopilot, id: string, now: Date, approvedDigest?: string): RequestMetadata {
  try {
    if (!entry.action || entry.action.id !== id || entry.action.kind !== 'autopilot' || !entry.request || entry.request.actionId !== id
      || entry.request.widening !== false || !/^[a-f0-9]{64}$/.test(entry.action.planHash ?? '')
      || actionDigest(entry.action) !== entry.request.digest) throw new Error();
  } catch { throw new CliError('The saved autopilot approval request does not match this action.'); }
  if (approvedDigest !== entry.request.digest) assertRequestCurrent(entry.request.expiresAt, now);
  return { actionId: id, digest: entry.request.digest, expiresAt: entry.request.expiresAt, kind: 'autopilot', keyCount: entry.action.clusterIds.length,
    clusters: entry.action.clusters ?? entry.action.clusterIds.map(clusterId => ({ clusterId, hint: null })), watcherCheckMinutes: 10 };
}
function validClusters(value: unknown, count: number): value is ApprovalCluster[] {
  return Array.isArray(value) && value.length === count && value.every(cluster => record(cluster)
    && fields(cluster, ['clusterId', 'hint']) && typeof cluster.clusterId === 'string' && cluster.clusterId.length > 0 && cluster.clusterId.length <= 512
    && !/[\u0000-\u001f\u007f]/.test(cluster.clusterId)
    && (cluster.hint === null || typeof cluster.hint === 'string' && cluster.hint.length <= 80 && !/[\u0000-\u001f\u007f]/.test(cluster.hint)))
    && new Set(value.map(cluster => cluster.clusterId)).size === count;
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
  let current: RequestMetadata | null = null;
  let ambiguous = false;
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
      || !record(input.request) || !fields(input.request, ['actionId', 'digest', 'expiresAt', 'kind', 'keyCount', 'clusters', 'watcherCheckMinutes'])) continue;
    const request = input.request;
    if (request.actionId !== id || request.kind !== 'autopilot' || typeof request.digest !== 'string' || !/^[a-f0-9]{64}$/.test(request.digest)
      || typeof request.keyCount !== 'number' || !Number.isInteger(request.keyCount) || request.keyCount < 0 || request.keyCount > 10_000
      || !validClusters(request.clusters, request.keyCount)
      || typeof request.watcherCheckMinutes !== 'number' || !Number.isSafeInteger(request.watcherCheckMinutes) || request.watcherCheckMinutes < 1 || request.watcherCheckMinutes > 10_080
      || typeof input.keyId !== 'string' || typeof input.sig !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(input.sig)) continue;
    const key = publicKeys.get(input.keyId); if (!key) continue;
    const sig = Buffer.from(input.sig, 'base64'); if (sig.length !== 64 || sig.toString('base64') !== input.sig) continue;
    if (!verifyDetached(key, Buffer.from(APPROVAL_REQUEST_PREFIX + canonicalJson({ request, keyId: input.keyId })), sig)) continue;
    try { assertRequestCurrent(request.expiresAt, now); } catch { continue; }
    // A deployment uses a fixed request lifetime. Its signed expiry orders
    // replacements without trusting the relay's editable timestamps or order.
    const candidate = request as unknown as RequestMetadata;
    if (!current || Date.parse(candidate.expiresAt) > Date.parse(current.expiresAt)) {
      current = candidate; ambiguous = false;
    } else if (Date.parse(candidate.expiresAt) === Date.parse(current.expiresAt) && candidate.digest !== current.digest) {
      ambiguous = true;
    }
  }
  if (current && !ambiguous) return current;
  throw new CliError('A current signed autopilot approval request was not found on the relay.');
}

/** Returns null only for an unknown local id, allowing the existing monitor approval path to run. */
export async function approveAutopilot(id: string, options: {relay?: boolean; reviewDigest?: string}, deps: AutopilotApprovalDependencies): Promise<AutopilotApprovalResult | null> {
  deps.assertHuman('approve an autopilot action');
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(id)) throw new CliError('The autopilot approval id is invalid.');
  let approvalAccepted = false;
  try {
    const now = deps.now?.() ?? new Date();
    if (!Number.isFinite(now.getTime())) throw new CliError('The approval clock could not be read.');
    const pending = await deps.store.readJson<{ actions: PendingAutopilot[] }>('pending', join(deps.store.paths.dir, 'watcher-approvals.json'));
    const local = pending?.actions.find(entry => entry.action?.id === id || entry.request?.actionId === id);
    if (!local && !options.relay) return null;
    const service = !options.relay ? createApprovalService({ store: deps.store, audit: deps.audit, credentials: deps.passkeys, deviceKeys: deps.deviceKeys,
      rpId: 'localhost', origins: ['http://localhost'], now: deps.now, ...(deps.quorum ? { quorum: deps.quorum } : {}) }) : null;
    const priorGrant = service ? (await service.approved()).find(entry => entry.action.id === id) : undefined;
    const request = local ? checkLocal(local, id, now, priorGrant?.grant.digest) : await remoteRequest(id, deps, now);
    if (options.reviewDigest !== undefined && request.digest !== options.reviewDigest) throw new CliError('The action changed. Review it again before approving.');
    deps.review?.({ actionId: id, clusters: request.clusters });
    if (!deps.confirm) throw new CliError('Review and confirm this autopilot action before approving it.');
    if (!await deps.confirm(id)) return { actionId: id, digest: request.digest, status: 'cancelled' };
    const execute = async (): Promise<AutopilotApprovalResult> => {
      if (deps.executeApprovedAction) {
        const result = await deps.executeApprovedAction(id);
        return { actionId: id, digest: request.digest, status: result.executed ? 'executed' : 'approved',
          ...(result.reason ? { reason: result.reason } : {}) };
      }
      return { actionId: id, digest: request.digest, status: 'approved' };
    };
    if (priorGrant?.grant.digest === request.digest) { approvalAccepted = true; return await execute(); }
    const recorded = async (error: ApprovalPendingError): Promise<AutopilotApprovalResult> => {
      // Recorded, and more team members must approve: progress, not a failure, and nothing runs yet.
      await deps.audit.append({ kind: 'autopilot-approval-recorded', summary: 'A team approval was recorded; more approvals are needed.', data: { actionId: id } });
      return { actionId: id, digest: request.digest, status: 'recorded', approvals: error.approvals, required: error.required, role: error.role, text: pendingText(error) };
    };
    if (deps.member && !options.relay) {
      try { await service!.approveAsMember(id, deps.member, request.digest); }
      catch (error) { if (error instanceof ApprovalPendingError) return await recorded(error); throw error; }
      approvalAccepted = true;
      return await execute();
    }
    const key = await deps.deviceKey();
    const signingAt = deps.now?.() ?? new Date();
    if (!Number.isFinite(signingAt.getTime())) throw new CliError('The approval clock could not be read.');
    assertRequestCurrent(request.expiresAt, signingAt);
    const signedData = { actionId: id, digest: request.digest, at: signingAt.toISOString() };
    const signed: SignedDeviceApproval = { ...signedData, keyId: key.keyId, sig: signDetached(key.privateKeyDer, Buffer.from(APPROVAL_PREFIX + canonicalJson(signedData))).toString('base64') };
    if (options.relay) {
      relayConfiguration(deps);
      const relay = createRelay({ ...deps.relay!, http: deps.http, audit: deps.audit, deviceKeys: deps.deviceKeys,
        trustedKeyIds: (await deps.deviceKeys()).map(key => key.keyId), now: deps.now });
      await relay.publishApproval(signed);
      await deps.audit.append({ kind: 'autopilot-approval-published', summary: 'A device-signed autopilot approval was published to the configured relay.', data: { actionId: id } });
      return { actionId: id, digest: request.digest, status: 'published', watcherCheckMinutes: request.watcherCheckMinutes };
    }
    try { await service!.approveWithDevice(id, signed); }
    catch (error) { if (error instanceof ApprovalPendingError) return await recorded(error); throw error; }
    approvalAccepted = true;
    return await execute();
  } catch (error) {
    await deps.audit.append(approvalAccepted
      ? { kind: 'autopilot-approval-execution-held', summary: 'An autopilot approval was saved, but execution did not complete.' }
      : { kind: 'autopilot-approval-rejected', summary: 'An autopilot approval was not accepted.' });
    if (approvalAccepted) throw new CliError('The autopilot action was approved, but execution did not complete. The approval is saved; inspect the watcher and try again.');
    if (error instanceof CliError) throw error;
    if (error instanceof ApprovalError) throw new CliError(error.message);
    throw new CliError('The autopilot approval could not be completed.');
  }
}
