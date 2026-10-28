// Team quorum for monitor actions (`keysentry approve <id>` and the dashboard's Approve button). Autopilot actions
// already carry an approval request from the watcher; a monitor action gets one here, bound to the reviewed plan, so
// N-of-M applies to it too. Without a team roster this returns null and the single-user path runs unchanged.
import { canonicalJson, signDetached } from '../security/index.js';
import { actionDigest, APPROVAL_PREFIX, ApprovalError, ApprovalPendingError, createApprovalService, type ApprovalAction } from '../approvals/index.js';
import { CliError } from './errors.js';
import type { KeysentryRuntime } from './runtime.js';
import { pendingText } from './team-governance.js';

/** Team approvals for a monitor action stay open for an hour, so members in other places can approve. */
const TEAM_REQUEST_TTL_MS = 60 * 60 * 1000;

export type TeamApprover = { kind: 'device' } | { kind: 'member'; memberId: string; credentialId: string };
export type TeamApprovalOutcome =
  | { status: 'approved' }
  | { status: 'recorded'; approvals: number; required: number; role: 'operator' | 'admin'; text: string };

/**
 * Record this approver for the reviewed monitor action. `approved` means the quorum is met: run the action with
 * runtime.approve, which checks the grant again and marks it used. `recorded` means more members must approve; null
 * means this project has no team.
 */
export async function approveMonitorAsTeam(rt: KeysentryRuntime, input: { id: string; reviewHash: string; clusterIds: string[]; approver: TeamApprover }):
  Promise<TeamApprovalOutcome | null> {
  const quorum = rt.teamQuorum();
  if (!quorum) return null;
  try { if (await quorum.team() === null) return null; }
  catch { throw new CliError('The team roster or policy could not be verified, so approvals are paused.'); }
  const deviceKeys = async () => {
    const key = await rt.signingKey();
    try { return [{ keyId: key.keyId, publicKeyDer: key.publicKeyDer }]; } finally { key.privateKeyDer.fill(0); }
  };
  const service = createApprovalService({ store: rt.store, audit: rt.audit, credentials: async () => [], deviceKeys,
    rpId: 'localhost', origins: ['http://localhost'], now: rt.now, requestTtlMs: TEAM_REQUEST_TTL_MS, quorum });
  // The review hash binds the approval to the exact plan the approver saw; a changed action starts a new request.
  const action: ApprovalAction = { id: input.id, kind: 'monitor', clusterIds: [...input.clusterIds], planHash: input.reviewHash };
  const digest = actionDigest(action);
  if ((await service.approved()).some(entry => entry.action.id === input.id && entry.request.digest === digest)) return { status: 'approved' };
  try {
    await service.request(action, false);
    if (input.approver.kind === 'member') await service.approveAsMember(input.id, input.approver, digest);
    else {
      const key = await rt.signingKey();
      try {
        const signedData = { actionId: input.id, digest, at: rt.now().toISOString() };
        const sig = signDetached(key.privateKeyDer, Buffer.from(APPROVAL_PREFIX + canonicalJson(signedData))).toString('base64');
        await service.approveWithDevice(input.id, { ...signedData, keyId: key.keyId, sig });
      } finally { key.privateKeyDer.fill(0); }
    }
  } catch (error) {
    if (error instanceof ApprovalPendingError) return { status: 'recorded', approvals: error.approvals, required: error.required, role: error.role, text: pendingText(error) };
    if (error instanceof ApprovalError) throw new CliError(error.message);
    throw error;
  }
  return { status: 'approved' };
}
