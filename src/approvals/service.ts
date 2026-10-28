import { createHash, randomBytes } from 'node:crypto';
import type { StateStore } from '../core/store.js';
import { canonicalJson, verifyDetached } from '../security/index.js';
import type { ApprovalApprover, ApprovalGrant, ApprovalRequest, AuditEvent, AuditLog, PasskeyCredential, RiskTier, TeamMember, TeamPolicy, TeamRoster } from '../types.js';
import { approvalsRequired } from '../policy/effective.js';
import { hasRole, memberForDeviceKey, memberForPasskey } from '../team/roster.js';
import { verifyAssertion } from './webauthn/index.js';
import { transactApprovals } from './store.js';
import type { ApprovalAction, ApprovalCluster, ApprovalQuorumState, ApprovalState, ApprovalStatus, StoredApproval } from './store.js';

export type { ApprovalAction, ApprovalCluster } from './store.js';
export interface ApprovalRequestDetails extends ApprovalRequest { clusters: ApprovalCluster[] }
export interface ApprovedAction { action: ApprovalAction; request: ApprovalRequestDetails; grant: ApprovalGrant }
export interface PasskeyAssertion { credentialId: string; clientDataJSON: Buffer; authenticatorData: Buffer; signature: Buffer }
export interface DeviceApproval { keyId: string; digest: string; at: string; sig: string }
/**
 * Team quorum (phase 5). With a roster, an action needs `requiredByTier[tier] ?? required` distinct members with role
 * operator or admin (policy-widening actions: `wideningAdmins` admins); the request stays pending until then.
 */
export interface ApprovalQuorum {
  /** The verified roster and policy in force, read at every request and approval; null means no team. A throw pauses approvals. */
  team(): Promise<{ roster: TeamRoster; policy: TeamPolicy | null } | null>;
  /** Risk tiers the action touches. Unknown (null, or a throw) applies the strictest tier rule. */
  tiers?(action: ApprovalAction): Promise<RiskTier[] | null> | RiskTier[] | null;
}
export interface ApprovalServiceOptions {
  store: StateStore;
  audit: AuditLog;
  credentials: () => Promise<PasskeyCredential[]>;
  deviceKeys: () => Promise<{ keyId: string; publicKeyDer: Buffer }[]>;
  rpId: string;
  origins: string[];
  now?: () => Date;
  mode?: 'interactive' | 'actions';
  /** Defaults to ten minutes interactively, or sixty minutes in Actions mode. */
  requestTtlMs?: number;
  /** Without it (or while it returns no team) the service behaves exactly as the single-user service. */
  quorum?: ApprovalQuorum;
}
export interface ApprovalDescription { kind: string; keyCount: number; digest: string; expiresAt: string; status: ApprovalStatus;
  /** Team quorum progress; absent without a team. */
  quorum?: { approvals: number; required: number } }
export interface ApprovalChallenge { challenge: string; rpId: string; allowCredentials: { type: 'public-key'; id: string }[] }
export interface ApprovalRequestOptions {
  /**
   * Team mode: the request needs the admins a policy-widening action needs (`approvals.wideningAdmins`, or the roster's
   * threshold without a policy), but unlike a widening action each admin may approve it with a passkey. Used for team
   * dashboard changes that handle secrets or change settings (reveal, vault, channels, settings, arming).
   */
  admins?: boolean;
}
export interface ApprovalService {
  request(action: ApprovalAction, widening: boolean, options?: ApprovalRequestOptions): Promise<ApprovalRequestDetails>;
  approveWithPasskey(actionId: string, assertion: PasskeyAssertion, expectedDigest?: string): Promise<ApprovalGrant>;
  approveWithDevice(actionId: string, signed: DeviceApproval): Promise<ApprovalGrant>;
  /**
   * Team mode only: count a roster member whose own passkey the caller has already verified over this exact request
   * (the team dashboard's passkey gate). The credential must be that member's roster passkey; without a team this refuses.
   */
  approveAsMember(actionId: string, approver: { memberId: string; credentialId: string }, expectedDigest?: string): Promise<ApprovalGrant>;
  status(actionId: string): Promise<ApprovalStatus>;
  describe(actionId: string): Promise<ApprovalDescription | null>;
  challenge(actionId: string, expectedDigest?: string): Promise<ApprovalChallenge>;
  recordDisarm(clientHash: string): Promise<void>;
  /** Approved current versions remain available until their executor records completion. */
  approved(): Promise<ApprovedAction[]>;
  /**
   * Run-time check of an approved request before its action runs: it must still be approved and not executed, and in
   * team mode its approvers must still meet the current roster's and policy's quorum (removed or demoted members stop
   * counting, a raised requirement applies). Returns the grant, or refuses.
   */
  checkGrant(actionId: string, expectedDigest?: string): Promise<ApprovalGrant>;
  /**
   * `checkGrant`, then record that a run of this approved change has started, before it runs (review L-c). A claimed
   * approval is refused here ever after, so a change runs at most once even when marking it executed later fails or
   * the process stops; `checkGrant` (the run's own entry-point checks) still accepts it until it is executed.
   */
  claim(actionId: string, expectedDigest?: string): Promise<ApprovalGrant>;
  markExecuted(actionId: string, expectedDigest?: string): Promise<void>;
}

/** Distinct members among a request's approvers who still qualify under `roster` (the "n" of "n of m"). */
export function qualifyingApprovals(quorum: Pick<ApprovalQuorumState, 'admins' | 'approvers'>, roster: TeamRoster): number {
  return new Set(quorum.approvers.filter(approver => approverQualifies(roster, approver, quorum.admins)).map(approver => approver.memberId)).size;
}

function approverQualifies(roster: TeamRoster, approver: ApprovalApprover, admins: boolean): boolean {
  const member = approver.memberId === undefined ? undefined : roster.members.find(candidate => candidate.id === approver.memberId);
  if (!member || !hasRole(member, admins ? 'admin' : 'operator')) return false;
  return approver.kind === 'passkey' ? member.passkeys.some(passkey => passkey.id === approver.credentialId)
    : member.deviceKeys.some(key => key.keyId === approver.keyId);
}
export class ApprovalError extends Error {
  readonly code = 'APPROVAL_REJECTED';
  constructor(message: string) { super(message); this.name = 'ApprovalError'; }
}
/** A team approval was verified and recorded, but more distinct members must approve before the action may run. */
export class ApprovalPendingError extends ApprovalError {
  readonly pending = true;
  /** How many more distinct members must approve. */
  readonly remaining: number;
  constructor(readonly approvals: number, readonly required: number, readonly role: 'operator' | 'admin' = 'operator') {
    super(`Your approval was recorded: ${approvals} of ${required} team approvals so far. The action runs only after ${required} different team members approve it.`);
    this.name = 'ApprovalPendingError';
    this.remaining = Math.max(0, required - approvals);
  }
  /** Who still needs to approve, in plain words, e.g. "1 more approval from a team operator or admin". */
  get needed(): string {
    const who = this.role === 'admin' ? (this.remaining === 1 ? 'a team admin' : 'team admins') : (this.remaining === 1 ? 'a team operator or admin' : 'team operators or admins');
    return `${this.remaining} more approval${this.remaining === 1 ? '' : 's'} from ${who} who ${this.remaining === 1 ? 'has' : 'have'} not approved yet`;
  }
}
const TEN_MINUTES = 10 * 60 * 1000;
const SEVEN_DAYS = 7 * 24 * 60 * 60 * 1000;
const WIDENING = 'This change can only be approved on your own computer with `keysentry approve`.';
const REJECTED = 'This approval could not be verified.';
const PAUSED = 'The team roster or policy could not be verified, so approvals are paused.';
/** A request created under a team quorum is never satisfied by a single approval because the team stopped being visible. */
const TEAM_GONE = 'This request needs team approvals, but the team roster is not available here, so approvals are paused. Restore the roster with keysentry team apply.';
type Team = { roster: TeamRoster; policy: TeamPolicy | null };
const APPROVAL_PREFIX = 'keysentry-approval:v1\n';
function reject(message = REJECTED): never { throw new ApprovalError(message); }
function sha256(value: string): string { return createHash('sha256').update(value).digest('hex'); }
function actionCopy(action: ApprovalAction): ApprovalAction {
  if (!action || typeof action.id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(action.id) || typeof action.kind !== 'string' || !action.kind.length || action.kind.length > 80 || /[\u0000-\u001f\u007f]/.test(action.kind) ||
      !Array.isArray(action.clusterIds) || action.clusterIds.length > 10000 || action.clusterIds.some((id) => typeof id !== 'string' || !id.length || id.length > 512) ||
      (action.planHash !== undefined && (typeof action.planHash !== 'string' || action.planHash.length > 512)) ||
      (action.rotates !== undefined && (!Array.isArray(action.rotates) || !action.rotates.length || action.rotates.length > 10000
        || action.rotates.some((id) => typeof id !== 'string' || !id.length || id.length > 512) || new Set(action.rotates).size !== action.rotates.length))) reject('This action description is not valid.');
  if (new Set(action.clusterIds).size !== action.clusterIds.length || (action.clusters !== undefined &&
      (!Array.isArray(action.clusters) || action.clusters.length !== action.clusterIds.length || action.clusters.some((cluster, index) =>
        !cluster || cluster.clusterId !== action.clusterIds[index] || (cluster.hint !== null &&
          (typeof cluster.hint !== 'string' || cluster.hint.length > 80 || /[\u0000-\u001f\u007f]/.test(cluster.hint))))))) reject('This action description is not valid.');
  return { id: action.id, kind: action.kind, clusterIds: [...action.clusterIds],
    ...(action.clusters === undefined ? {} : { clusters: action.clusters.map(cluster => ({ clusterId: cluster.clusterId, hint: cluster.hint })) }),
    ...(action.planHash === undefined ? {} : { planHash: action.planHash }),
    ...(action.rotates === undefined ? {} : { rotates: [...action.rotates] }) };
}
export function actionDigest(action: ApprovalAction): string { return sha256(canonicalJson(actionCopy(action))); }
function requestCopy(request: StoredApproval): ApprovalRequestDetails {
  return { actionId: request.actionId, digest: request.digest, createdAt: request.createdAt, expiresAt: request.expiresAt,
    challenge: request.challenge, widening: request.widening, clusters: structuredClone(request.clusters ?? []) };
}
function currentRequest(state: ApprovalState, actionId: string): StoredApproval | undefined {
  return state.requests.find(request => request.actionId === actionId && request.status !== 'superseded');
}

export function createApprovalService(opts: ApprovalServiceOptions): ApprovalService {
  const now = opts.now ?? (() => new Date());
  if (!opts.rpId || !opts.origins.length) throw new TypeError('An approval RP ID and trusted origins are required.');
  const requestTtlMs = opts.requestTtlMs ?? (opts.mode === 'actions' ? 60 * 60 * 1000 : TEN_MINUTES);
  if ((opts.mode !== undefined && opts.mode !== 'interactive' && opts.mode !== 'actions') ||
      !Number.isSafeInteger(requestTtlMs) || requestTtlMs <= 0 || requestTtlMs > SEVEN_DAYS) throw new TypeError('The approval request lifetime is not valid.');
  // Configuration is copied so later caller mutations cannot widen allowed origins.
  const origins = [...opts.origins];
  const event = (kind: string, actionId?: string): AuditEvent => ({ kind: `approvals:${kind}`, summary: `Approval ${kind.replaceAll('-', ' ')}.`, ...(actionId ? { data: { actionId } } : {}) });

  function transaction<T>(operation: (state: ApprovalState, events: AuditEvent[], at: Date) => Promise<T>, flushBefore = true): Promise<T> {
    return transactApprovals(opts.store, async (state, commit) => {
      async function flushAudit(): Promise<void> {
        while (state.auditPending.length) {
          await opts.audit.append(state.auditPending[0]!);
          state.auditPending.shift();
          await commit();
        }
      }
      // A durable outbox prevents a transient audit failure from losing an outcome.
      // No method exposes the new state until the previous audit backlog is recorded.
      if (flushBefore) await flushAudit();
      const at = now();
      const events: AuditEvent[] = [];
      for (const request of state.requests) {
        if (request.status === 'pending' && Date.parse(request.expiresAt) <= at.getTime()) {
          request.status = 'expired';
          events.push(event('expired', request.actionId));
        }
      }
      state.requests = state.requests.filter((r) => r.status !== 'expired' || Date.parse(r.expiresAt) + SEVEN_DAYS > at.getTime());
      let result: T | undefined;
      let failure: unknown;
      try { result = await operation(state, events, at); }
      catch (error) { failure = error; }
      // Persist attempts, counters, consumed challenges and terminal outcomes before returning.
      state.auditPending.push(...events);
      await commit();
      await flushAudit();
      if (failure) throw failure;
      return result as T;
    });
  }
  function pending(state: ApprovalState, actionId: string, events: AuditEvent[], expectedDigest?: string): StoredApproval {
    const request = currentRequest(state, actionId);
    if (!request) { events.push(event('rejected')); return reject('This approval request was not found.'); }
    if (expectedDigest !== undefined && expectedDigest !== request.digest) {
      events.push(event('rejected', request.actionId)); return reject('This approval request has changed. Open it again to review the current action.');
    }
    if (request.status === 'expired') { events.push(event('rejected', actionId)); return reject('This approval request has expired.'); }
    if (request.status === 'approved' || request.status === 'executed' || state.usedChallenges.includes(request.challenge)) {
      events.push(event('replay', actionId));
      return reject('This approval has already been used.');
    }
    if (request.status === 'rejected') { events.push(event('rejected', actionId)); return reject('This approval request has been rejected.'); }
    return request;
  }
  function attemptFailed(request: StoredApproval, events: AuditEvent[], message = REJECTED, kind = 'rejected'): never {
    request.attempts++;
    if (request.attempts >= 5) request.status = 'rejected';
    events.push(event(kind, request.actionId));
    return reject(message);
  }
  async function registered(state: ApprovalState): Promise<PasskeyCredential[]> {
    return (await opts.credentials()).filter((credential) => credential.rpId === opts.rpId).map((credential) => {
      const saved = state.counters.find((counter) => counter.credentialId === credential.id && counter.publicKeyCose === credential.publicKeyCose);
      return { ...credential, origins: [...credential.origins], signCount: Math.max(credential.signCount, saved?.signCount ?? 0) };
    });
  }
  function approve(state: ApprovalState, request: StoredApproval, by: ApprovalGrant['by'], at: Date, events: AuditEvent[], approvers?: ApprovalApprover[]): ApprovalGrant {
    const grant: ApprovalGrant = { actionId: request.actionId, digest: request.digest, at: at.toISOString(), by, ...(approvers ? { approvers } : {}) };
    request.status = 'approved';
    request.grant = grant;
    state.usedChallenges.push(request.challenge);
    events.push(event('approved', request.actionId));
    return structuredClone(grant);
  }

  // ---------------------------------------------------------------------------------------------- team quorum
  async function teamNow(): Promise<Team | null> {
    if (!opts.quorum) return null;
    let team: Team | null;
    try { team = await opts.quorum.team(); } catch { return reject(PAUSED); }
    if (team === null) return null;
    if (!team || !team.roster || !Array.isArray(team.roster.members)) return reject(PAUSED);
    return team;
  }
  async function requirement(team: Team, request: StoredApproval): Promise<{ required: number; admins: boolean }> {
    let tiers: RiskTier[] | null = null;
    if (request.action && opts.quorum?.tiers) {
      try { tiers = (await opts.quorum.tiers(actionCopy(request.action))) ?? null; } catch { tiers = null; }
    }
    // An admin-quorum request (created with `admins`) keeps the widening rule's count and role.
    const rule = approvalsRequired({ widening: request.widening || request.quorum?.admins === true, tiers }, team.policy, team.roster);
    // Keys the action also rotates at once (arming with adoption) need the rotation's count too, by their tiers.
    let rotation = 0;
    if (request.action?.rotates?.length) {
      let rotated: RiskTier[] | null = null;
      if (opts.quorum?.tiers) {
        try { rotated = (await opts.quorum.tiers({ id: request.action.id, kind: request.action.kind, clusterIds: [...request.action.rotates] })) ?? null; } catch { rotated = null; }
      }
      rotation = approvalsRequired({ widening: false, tiers: rotated }, team.policy, team.roster).count;
    }
    // A rule that changes while a request is pending can only make it stricter.
    return { required: Math.max(rule.count, rotation, request.quorum?.required ?? 0), admins: rule.role === 'admin' || request.quorum?.admins === true };
  }
  /** An earlier approver still counts only while the same credential belongs to a member with the needed role. */
  function stillEligible(team: Team, approver: ApprovalApprover, admins: boolean): boolean {
    return approverQualifies(team.roster, approver, admins);
  }
  function sameCredential(approver: ApprovalApprover, by: ApprovalGrant['by']): boolean {
    return approver.kind === 'passkey' ? by.kind === 'passkey' && approver.credentialId === by.credentialId : by.kind === 'device' && approver.keyId === by.keyId;
  }
  /** Count a verified approver toward the quorum; approve when it is met, otherwise persist and report progress. */
  async function recordApprover(state: ApprovalState, request: StoredApproval, team: Team, by: ApprovalGrant['by'], member: TeamMember | undefined,
    at: Date, events: AuditEvent[]): Promise<ApprovalGrant> {
    if (!member) { events.push(event('not-a-member', request.actionId)); return reject('This passkey or device key is not on the team roster.'); }
    if (!hasRole(member, 'operator')) { events.push(event('role-refused', request.actionId)); return reject('Viewers can see approval requests but cannot approve them.'); }
    const need = await requirement(team, request);
    if (need.admins && !hasRole(member, 'admin')) { events.push(event('role-refused', request.actionId)); return reject('This change needs approval from team admins.'); }
    const quorum = request.quorum ??= { required: need.required, admins: need.admins, approvers: [] };
    quorum.required = need.required; quorum.admins = need.admins;
    if (quorum.approvers.some(approver => sameCredential(approver, by))) { events.push(event('replay', request.actionId)); return reject('This approval has already been used.'); }
    const counted = quorum.approvers.filter(approver => stillEligible(team, approver, need.admins));
    if (counted.some(approver => approver.memberId === member.id)) {
      events.push(event('duplicate-member', request.actionId));
      return reject('You have already approved this action. Another team member needs to approve it.');
    }
    const approver: ApprovalApprover = { ...by, memberId: member.id, at: at.toISOString() };
    quorum.approvers.push(approver);
    counted.push(approver);
    if (counted.length < need.required) {
      events.push({ kind: 'approvals:quorum-progress', summary: 'Team approval recorded; more approvals are needed.',
        data: { actionId: request.actionId, memberId: member.id, approvals: counted.length, required: need.required } });
      throw new ApprovalPendingError(counted.length, need.required, need.admins ? 'admin' : 'operator');
    }
    return approve(state, request, by, at, events, counted.map(entry => ({ ...entry })));
  }
  /** Locally registered credentials first (callers may adapt their origins), then members' passkeys from the roster. */
  async function teamCredential(state: ApprovalState, team: Team, credentialId: unknown): Promise<PasskeyCredential | undefined> {
    if (typeof credentialId !== 'string') return undefined;
    const local = (await registered(state)).find((c) => c.id === credentialId);
    if (local) return local;
    for (const member of team.roster.members) {
      const passkey = member.passkeys.find(candidate => candidate.id === credentialId && candidate.rpId === opts.rpId);
      if (!passkey) continue;
      const saved = state.counters.find((c) => c.credentialId === passkey.id && c.publicKeyCose === passkey.publicKeyCose);
      return { ...passkey, origins: [...passkey.origins], signCount: Math.max(passkey.signCount, saved?.signCount ?? 0) };
    }
    return undefined;
  }

  /** The approved grant of `actionId`, if its approvers still meet the current roster's and policy's quorum. */
  async function grantInForce(state: ApprovalState, events: AuditEvent[], actionId: string, expectedDigest?: string): Promise<ApprovalGrant> {
    const request = currentRequest(state, actionId);
    if (!request || request.status !== 'approved' || !request.grant || (expectedDigest !== undefined && request.digest !== expectedDigest)) {
      events.push(event('rejected', request?.actionId)); return reject('This action has no approval to run. Request it again.');
    }
    const team = await teamNow();
    if (!team) {
      if (request.quorum) { events.push(event('team-unavailable', actionId)); return reject(TEAM_GONE); }
      return structuredClone(request.grant);
    }
    const need = await requirement(team, request);
    const approvers = request.grant.approvers ?? request.quorum?.approvers ?? [];
    const counted = new Set(approvers.filter(approver => stillEligible(team, approver, need.admins)).map(approver => approver.memberId));
    if (counted.size < need.required) {
      events.push(event('quorum-lapsed', actionId));
      return reject(`The approvals for this action no longer meet the team policy (${counted.size} of ${need.required} still count). Ask team members to approve it again.`);
    }
    return structuredClone(request.grant);
  }

  return {
    request(input, widening, options = {}) {
      return transaction(async (state, events, at) => {
        let action: ApprovalAction;
        try { action = actionCopy(input); if (typeof widening !== 'boolean') reject(); }
        catch { events.push(event('rejected')); return reject('This action description is not valid.'); }
        const digest = actionDigest(action);
        const team = await teamNow();
        const admins = options?.admins === true;
        const existing = currentRequest(state, action.id);
        if (existing?.digest === digest && (existing.widening !== widening || existing.quorum !== undefined && admins && existing.quorum.admins !== true)) {
          events.push(event('rejected', action.id)); return reject('This approval request has different authorization requirements.');
        }
        if (existing?.digest === digest && existing.status === 'pending') {
          existing.action = action;
          existing.clusters = action.clusters ?? action.clusterIds.map(clusterId => ({ clusterId, hint: null }));
          return requestCopy(existing);
        }
        if (existing?.digest === digest) {
          events.push(event('rejected', action.id)); return reject('This action already has an approval request.');
        }
        const pendingCount = state.requests.filter((r) => r.status === 'pending').length - (existing?.status === 'pending' ? 1 : 0);
        if (pendingCount >= 100) { events.push(event('rejected')); return reject('There are already 100 pending approval requests.'); }
        if (existing) { existing.status = 'superseded'; events.push(event('superseded', action.id)); }
        let challenge: string;
        do { challenge = randomBytes(32).toString('base64url'); }
        while (state.requests.some((r) => r.challenge === challenge) || state.usedChallenges.includes(challenge));
        const request: StoredApproval = { actionId: action.id, digest, createdAt: at.toISOString(), expiresAt: new Date(at.getTime() + requestTtlMs).toISOString(), challenge, widening,
          kind: action.kind, keyCount: action.clusterIds.length, status: 'pending', attempts: 0, action,
          clusters: action.clusters ?? action.clusterIds.map(clusterId => ({ clusterId, hint: null })) };
        if (team) {
          if (admins) request.quorum = { required: 1, admins: true, approvers: [] };
          const need = await requirement(team, request);
          request.quorum = { required: need.required, admins: need.admins, approvers: [] };
        }
        state.requests.push(request);
        events.push(event('requested', action.id));
        return requestCopy(request);
      });
    },
    approveWithPasskey(actionId, input, expectedDigest) {
      return transaction(async (state, events, at) => {
        const request = pending(state, actionId, events, expectedDigest);
        if (request.widening) return attemptFailed(request, events, WIDENING, 'widening-refused');
        const team = await teamNow();
        if (team) {
          // Every member asserts the same single-use challenge; each credential may be counted once.
          let credential: PasskeyCredential | undefined;
          try {
            credential = await teamCredential(state, team, input?.credentialId);
            if (!credential) reject();
            const result = verifyAssertion({ credential, clientDataJSON: input.clientDataJSON, authenticatorData: input.authenticatorData, signature: input.signature,
              expectedChallenge: Buffer.from(request.challenge, 'base64url'), expectedOrigins: origins, requireUserVerification: true });
            if (result.cloneWarning) reject();
            const saved = state.counters.find((c) => c.credentialId === credential!.id && c.publicKeyCose === credential!.publicKeyCose);
            if (saved) saved.signCount = result.signCount;
            else state.counters.push({ credentialId: credential.id, publicKeyCose: credential.publicKeyCose, signCount: result.signCount });
          } catch { return attemptFailed(request, events); }
          return recordApprover(state, request, team, { kind: 'passkey', credentialId: credential.id }, memberForPasskey(team.roster, credential), at, events);
        }
        if (request.quorum) { events.push(event('team-unavailable', actionId)); return reject(TEAM_GONE); }
        try {
          const credential = (await registered(state)).find((c) => c.id === input?.credentialId);
          if (!credential) reject();
          const result = verifyAssertion({ credential, clientDataJSON: input.clientDataJSON, authenticatorData: input.authenticatorData, signature: input.signature,
            expectedChallenge: Buffer.from(request.challenge, 'base64url'), expectedOrigins: origins, requireUserVerification: true });
          if (result.cloneWarning) reject();
          const saved = state.counters.find((c) => c.credentialId === credential.id && c.publicKeyCose === credential.publicKeyCose);
          if (saved) saved.signCount = result.signCount;
          else state.counters.push({ credentialId: credential.id, publicKeyCose: credential.publicKeyCose, signCount: result.signCount });
          return approve(state, request, { kind: 'passkey', credentialId: credential.id }, at, events);
        } catch { return attemptFailed(request, events); }
      });
    },
    approveWithDevice(actionId, signed) {
      return transaction(async (state, events, at) => {
        const request = pending(state, actionId, events);
        const team = await teamNow();
        if (!team && request.quorum) { events.push(event('team-unavailable', actionId)); return reject(TEAM_GONE); }
        let verified: { keyId: string; member: TeamMember | undefined } | undefined;
        try {
          if (!signed || typeof signed.keyId !== 'string' || signed.digest !== request.digest || typeof signed.at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(signed.at) || !Number.isFinite(Date.parse(signed.at)) || Math.abs(at.getTime() - Date.parse(signed.at)) > TEN_MINUTES || typeof signed.sig !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(signed.sig)) reject();
          const bytes = Buffer.from(signed.sig, 'base64');
          if (bytes.length !== 64 || bytes.toString('base64') !== signed.sig) reject();
          const message = APPROVAL_PREFIX + canonicalJson({ actionId, digest: signed.digest, at: signed.at });
          const replayId = sha256(canonicalJson({ keyId: signed.keyId, message }));
          if (state.usedDeviceApprovals.includes(replayId)) { events.push(event('replay', actionId)); return reject('This approval has already been used.'); }
          if (team) {
            // The roster is the authority for members' device keys; a local key outside it verifies but is not a member.
            const listed = memberForDeviceKey(team.roster, signed.keyId);
            const publicKeyDer = listed?.publicKeyDer ?? (await opts.deviceKeys()).find((k) => k.keyId === signed.keyId)?.publicKeyDer;
            if (!publicKeyDer || !verifyDetached(publicKeyDer, Buffer.from(message), bytes)) reject();
            state.usedDeviceApprovals.push(replayId);
            verified = { keyId: signed.keyId, member: listed?.member };
          } else {
            const key = (await opts.deviceKeys()).find((k) => k.keyId === signed.keyId);
            if (!key || !verifyDetached(key.publicKeyDer, Buffer.from(message), bytes)) reject();
            state.usedDeviceApprovals.push(replayId);
            return approve(state, request, { kind: 'device', keyId: key.keyId }, at, events);
          }
        } catch { return attemptFailed(request, events); }
        return recordApprover(state, request, team!, { kind: 'device', keyId: verified!.keyId }, verified!.member, at, events);
      });
    },
    approveAsMember(actionId, input, expectedDigest) {
      return transaction(async (state, events, at) => {
        const request = pending(state, actionId, events, expectedDigest);
        if (request.widening) return attemptFailed(request, events, WIDENING, 'widening-refused');
        const team = await teamNow();
        if (!team) { events.push(event('rejected', actionId)); return reject('Team approvals need a team roster.'); }
        const memberId = typeof input?.memberId === 'string' ? input.memberId : '';
        const credentialId = typeof input?.credentialId === 'string' ? input.credentialId : '';
        const member = team.roster.members.find(candidate => candidate.id === memberId);
        // The gate verified this credential; the roster must still list it for this member.
        if (member && !member.passkeys.some(passkey => passkey.id === credentialId)) return attemptFailed(request, events);
        return recordApprover(state, request, team, { kind: 'passkey', credentialId }, member, at, events);
      });
    },
    status(actionId) {
      return transaction(async (state, events) => {
        const request = currentRequest(state, actionId);
        if (!request) { events.push(event('rejected')); return reject('This approval request was not found.'); }
        return request.status;
      });
    },
    describe(actionId) {
      return transaction(async (state) => {
        const request = currentRequest(state, actionId);
        if (!request) return null;
        let quorum: ApprovalDescription['quorum'];
        if (request.quorum) {
          // "n of m" counts only approvers who still qualify under the current roster; an unreadable team counts none.
          let team: Team | null = null;
          try { team = await teamNow(); } catch { team = null; }
          quorum = { approvals: team ? qualifyingApprovals(request.quorum, team.roster) : 0, required: request.quorum.required };
        }
        return { kind: request.kind, keyCount: request.keyCount, digest: request.digest, expiresAt: request.expiresAt, status: request.status, ...(quorum ? { quorum } : {}) };
      });
    },
    challenge(actionId, expectedDigest) {
      return transaction(async (state, events) => {
        const request = pending(state, actionId, events, expectedDigest);
        if (request.widening) { events.push(event('widening-refused', actionId)); return reject(WIDENING); }
        const team = await teamNow();
        if (team) {
          // Offer only credentials of members who may still approve this request.
          const need = await requirement(team, request);
          const done = new Set((request.quorum?.approvers ?? []).filter(approver => stillEligible(team, approver, need.admins)).map(approver => approver.memberId));
          const ids = new Set<string>();
          const local = await registered(state);
          for (const member of team.roster.members) {
            if (done.has(member.id) || !hasRole(member, need.admins ? 'admin' : 'operator')) continue;
            for (const passkey of member.passkeys) {
              if (passkey.rpId === opts.rpId || local.some(c => c.id === passkey.id && c.publicKeyCose === passkey.publicKeyCose)) ids.add(passkey.id);
            }
          }
          return { challenge: request.challenge, rpId: opts.rpId, allowCredentials: [...ids].map(id => ({ type: 'public-key' as const, id })) };
        }
        if (request.quorum) { events.push(event('team-unavailable', actionId)); return reject(TEAM_GONE); }
        const credentials = await registered(state);
        return { challenge: request.challenge, rpId: opts.rpId, allowCredentials: credentials.map((c) => ({ type: 'public-key' as const, id: c.id })) };
      });
    },
    recordDisarm(clientHash) {
      return transaction(async (_state, events) => {
        if (!/^[a-f0-9]{64}$/.test(clientHash)) reject();
        events.push({ kind: 'approvals:disarm', summary: 'Autopilot was disarmed.', data: { clientHash } });
      }, false); // Disarming has already happened; retain its audit even when an older entry cannot flush.
    },
    approved() {
      return transaction(async (state) => {
        const approved: ApprovedAction[] = [];
        for (const request of state.requests) {
          if (request.status !== 'approved' || !request.grant || !request.action) continue;
          const action = actionCopy(request.action);
          if (action.id !== request.actionId || actionDigest(action) !== request.digest || request.grant.actionId !== request.actionId || request.grant.digest !== request.digest) {
            reject('Saved approval metadata could not be verified.');
          }
          approved.push({ action, request: requestCopy(request), grant: structuredClone(request.grant) });
        }
        return approved;
      });
    },
    checkGrant(actionId, expectedDigest) {
      return transaction(async (state, events) => grantInForce(state, events, actionId, expectedDigest));
    },
    claim(actionId, expectedDigest) {
      return transaction(async (state, events, at) => {
        const request = currentRequest(state, actionId);
        if (request?.claimedAt !== undefined && request.status === 'approved') {
          events.push(event('replay', actionId));
          return reject('This change has already started with this approval. Make the change again to request a new approval.');
        }
        const grant = await grantInForce(state, events, actionId, expectedDigest);
        request!.claimedAt = at.toISOString();
        events.push(event('claimed', actionId));
        return grant;
      });
    },
    markExecuted(actionId, expectedDigest) {
      return transaction(async (state, events, at) => {
        const request = currentRequest(state, actionId);
        if (request && expectedDigest !== undefined && request.digest !== expectedDigest) {
          events.push(event('rejected', request.actionId)); return reject('This approval request has changed. Its newer version has not been marked executed.');
        }
        if (request?.status === 'executed') return;
        if (!request || request.status !== 'approved' || !request.grant) {
          events.push(event('rejected', request?.actionId)); return reject('This action has no approval to execute.');
        }
        request.status = 'executed';
        request.executedAt = at.toISOString();
        events.push(event('executed', actionId));
      });
    },
  };
}
