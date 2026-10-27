import { createHash, randomBytes } from 'node:crypto';
import type { StateStore } from '../core/store.js';
import { canonicalJson, verifyDetached } from '../security/index.js';
import type { ApprovalGrant, ApprovalRequest, AuditEvent, AuditLog, PasskeyCredential } from '../types.js';
import { verifyAssertion } from './webauthn/index.js';
import { transactApprovals } from './store.js';
import type { ApprovalState, ApprovalStatus, StoredApproval } from './store.js';

export interface ApprovalAction { id: string; kind: string; clusterIds: string[]; planHash?: string }
export interface PasskeyAssertion { credentialId: string; clientDataJSON: Buffer; authenticatorData: Buffer; signature: Buffer }
export interface DeviceApproval { keyId: string; digest: string; at: string; sig: string }
export interface ApprovalServiceOptions {
  store: StateStore;
  audit: AuditLog;
  credentials: () => Promise<PasskeyCredential[]>;
  deviceKeys: () => Promise<{ keyId: string; publicKeyDer: Buffer }[]>;
  rpId: string;
  origins: string[];
  now?: () => Date;
}
export interface ApprovalDescription { kind: string; keyCount: number; expiresAt: string; status: ApprovalStatus }
export interface ApprovalChallenge { challenge: string; rpId: string; allowCredentials: { type: 'public-key'; id: string }[] }
export interface ApprovalService {
  request(action: ApprovalAction, widening: boolean): Promise<ApprovalRequest>;
  approveWithPasskey(actionId: string, assertion: PasskeyAssertion): Promise<ApprovalGrant>;
  approveWithDevice(actionId: string, signed: DeviceApproval): Promise<ApprovalGrant>;
  status(actionId: string): Promise<ApprovalStatus>;
  describe(actionId: string): Promise<ApprovalDescription | null>;
  challenge(actionId: string): Promise<ApprovalChallenge>;
  recordDisarm(clientHash: string): Promise<void>;
}
export class ApprovalError extends Error {
  readonly code = 'APPROVAL_REJECTED';
  constructor(message: string) { super(message); this.name = 'ApprovalError'; }
}
const TEN_MINUTES = 10 * 60 * 1000;
const SEVEN_DAYS = 7 * 24 * 60 * 60 * 1000;
const WIDENING = 'This change can only be approved on your own computer with `keysentry approve`.';
const REJECTED = 'This approval could not be verified.';
const APPROVAL_PREFIX = 'keysentry-approval:v1\n';
function reject(message = REJECTED): never { throw new ApprovalError(message); }
function sha256(value: string): string { return createHash('sha256').update(value).digest('hex'); }
function actionCopy(action: ApprovalAction): ApprovalAction {
  if (!action || typeof action.id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(action.id) || typeof action.kind !== 'string' || !action.kind.length || action.kind.length > 80 || /[\u0000-\u001f\u007f]/.test(action.kind) ||
      !Array.isArray(action.clusterIds) || action.clusterIds.length > 10000 || action.clusterIds.some((id) => typeof id !== 'string' || !id.length || id.length > 512) ||
      (action.planHash !== undefined && (typeof action.planHash !== 'string' || action.planHash.length > 512))) reject('This action description is not valid.');
  return { id: action.id, kind: action.kind, clusterIds: [...action.clusterIds], ...(action.planHash === undefined ? {} : { planHash: action.planHash }) };
}
export function actionDigest(action: ApprovalAction): string { return sha256(canonicalJson(actionCopy(action))); }

export function createApprovalService(opts: ApprovalServiceOptions): ApprovalService {
  const now = opts.now ?? (() => new Date());
  if (!opts.rpId || !opts.origins.length) throw new TypeError('An approval RP ID and trusted origins are required.');
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
  function pending(state: ApprovalState, actionId: string, events: AuditEvent[]): StoredApproval {
    const request = state.requests.find((r) => r.actionId === actionId);
    if (!request) { events.push(event('rejected')); return reject('This approval request was not found.'); }
    if (request.status === 'expired') { events.push(event('rejected', actionId)); return reject('This approval request has expired.'); }
    if (request.status === 'approved' || state.usedChallenges.includes(request.challenge)) {
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
  function approve(state: ApprovalState, request: StoredApproval, by: ApprovalGrant['by'], at: Date, events: AuditEvent[]): ApprovalGrant {
    const grant: ApprovalGrant = { actionId: request.actionId, digest: request.digest, at: at.toISOString(), by };
    request.status = 'approved';
    request.grant = grant;
    state.usedChallenges.push(request.challenge);
    events.push(event('approved', request.actionId));
    return structuredClone(grant);
  }

  return {
    request(input, widening) {
      return transaction(async (state, events, at) => {
        let action: ApprovalAction;
        try { action = actionCopy(input); if (typeof widening !== 'boolean') reject(); }
        catch { events.push(event('rejected')); return reject('This action description is not valid.'); }
        if (state.requests.some((r) => r.actionId === action.id)) { events.push(event('rejected', action.id)); return reject('This action already has an approval request.'); }
        if (state.requests.filter((r) => r.status === 'pending').length >= 100) { events.push(event('rejected')); return reject('There are already 100 pending approval requests.'); }
        let challenge: string;
        do { challenge = randomBytes(32).toString('base64url'); }
        while (state.requests.some((r) => r.challenge === challenge) || state.usedChallenges.includes(challenge));
        const request: ApprovalRequest = { actionId: action.id, digest: actionDigest(action), createdAt: at.toISOString(), expiresAt: new Date(at.getTime() + TEN_MINUTES).toISOString(), challenge, widening };
        state.requests.push({ ...request, kind: action.kind, keyCount: action.clusterIds.length, status: 'pending', attempts: 0 });
        events.push(event('requested', action.id));
        return { ...request };
      });
    },
    approveWithPasskey(actionId, input) {
      return transaction(async (state, events, at) => {
        const request = pending(state, actionId, events);
        if (request.widening) return attemptFailed(request, events, WIDENING, 'widening-refused');
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
        try {
          if (!signed || typeof signed.keyId !== 'string' || signed.digest !== request.digest || typeof signed.at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(signed.at) || !Number.isFinite(Date.parse(signed.at)) || Math.abs(at.getTime() - Date.parse(signed.at)) > TEN_MINUTES || typeof signed.sig !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(signed.sig)) reject();
          const bytes = Buffer.from(signed.sig, 'base64');
          if (bytes.length !== 64 || bytes.toString('base64') !== signed.sig) reject();
          const message = APPROVAL_PREFIX + canonicalJson({ actionId, digest: signed.digest, at: signed.at });
          const replayId = sha256(canonicalJson({ keyId: signed.keyId, message }));
          if (state.usedDeviceApprovals.includes(replayId)) { events.push(event('replay', actionId)); return reject('This approval has already been used.'); }
          const key = (await opts.deviceKeys()).find((k) => k.keyId === signed.keyId);
          if (!key || !verifyDetached(key.publicKeyDer, Buffer.from(message), bytes)) reject();
          state.usedDeviceApprovals.push(replayId);
          return approve(state, request, { kind: 'device', keyId: key.keyId }, at, events);
        } catch { return attemptFailed(request, events); }
      });
    },
    status(actionId) {
      return transaction(async (state, events) => {
        const request = state.requests.find((r) => r.actionId === actionId);
        if (!request) { events.push(event('rejected')); return reject('This approval request was not found.'); }
        return request.status;
      });
    },
    describe(actionId) {
      return transaction(async (state) => {
        const request = state.requests.find((r) => r.actionId === actionId);
        return request ? { kind: request.kind, keyCount: request.keyCount, expiresAt: request.expiresAt, status: request.status } : null;
      });
    },
    challenge(actionId) {
      return transaction(async (state, events) => {
        const request = pending(state, actionId, events);
        if (request.widening) { events.push(event('widening-refused', actionId)); return reject(WIDENING); }
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
  };
}
