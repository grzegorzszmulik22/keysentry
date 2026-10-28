// Team dashboard changes under the team's quorum (review C1, M2, L5). On the team dashboard one member's passkey never
// runs a change by itself: the confirmation creates an approval request bound to exactly that change (route, body and
// requester) and counts as that member's approval. The change runs once the approval service reports the request
// approved with the policy's quorum, and every runtime entry point checks the grant again against the current roster
// and policy (`KeysentryRuntime.requireTeamGrant`). Local single-user mode never comes here.
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { z } from 'zod';
import { actionDigest, ApprovalError, ApprovalPendingError, qualifyingApprovals, type ApprovalAction, type ApprovalService } from '../approvals/index.js';
import { transactApprovals, type StoredApproval } from '../approvals/store.js';
import { DashboardAccepted, type DashboardRequestContext } from '../dashboard/server/api.js';
import { DashboardError } from '../dashboard/server/security.js';
import { canonicalJson } from '../security/index.js';
import type { RotationPlan, TeamRoster } from '../types.js';
import { serviceLabel } from './display.js';
import { providerName } from './provider-names.js';
import type { KeysentryRuntime, TeamGrantRef } from './runtime.js';
import { pendingText } from './team-governance.js';

export interface TeamRouteRule {
  /**
   * Approvers are admins: `approvals.wideningAdmins` of them (the roster's threshold without a policy). Otherwise
   * `approvals.required` operators or admins, by the risk tiers of the keys involved.
   */
  admins: boolean;
  /** The body carries a secret (a token or channel credential). It is never stored: the requester submits it again after approval. */
  secret?: true;
  /** The result is a secret for the browser that runs it (reveal): only the requester runs it, after approval. */
  revealsResult?: true;
}

/**
 * Team dashboard routes that run only under a met quorum. Operator routes change keys at providers and hosts; admin
 * routes widen what may happen (arming), handle secrets (reveal, vault) or change settings and channels.
 */
export const TEAM_QUORUM_ROUTES: Readonly<Record<string, TeamRouteRule>> = Object.freeze({
  'rotate/execute': { admins: false },
  'rotation/finish': { admins: false },
  'rotation/undo': { admins: false },
  'spend-limits/apply': { admins: false },
  'approvals/dismiss': { admins: false },
  'autopilot/arm': { admins: true },
  'settings/update': { admins: true },
  'notifications/add': { admins: true, secret: true },
  'notifications/remove': { admins: true },
  'vault/store': { admins: true, secret: true },
  'vault/remove': { admins: true },
  reveal: { admins: true, revealsResult: true },
});

export function isTeamQuorumRoute(route: string): boolean {
  return Object.hasOwn(TEAM_QUORUM_ROUTES, route);
}

interface Description {
  summary: string; changes: string[]; clusterIds: string[];
  /** Keys the change also rotates at once (arming with adoption): bound into the request, which then needs their rotation's approvals too. */
  rotates?: string[];
}
type Body = Record<string, unknown>;

const count = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;
const strings = (value: unknown): string[] => Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];

/**
 * The keys a dismissal concerns (review L-a): the clusters of the pending request or monitor action it dismisses, so
 * the policy's per-tier rule applies to dismissing as it does to running it.
 */
async function dismissedClusters(rt: KeysentryRuntime, id: unknown): Promise<string[]> {
  if (typeof id !== 'string') return [];
  const request = await transactApprovals(rt.store, async state => state.requests.find(item => item.actionId === id && item.status === 'pending'));
  if (request) return [...new Set(request.action?.clusterIds ?? request.clusters?.map(cluster => cluster.clusterId) ?? [])];
  const action = (await rt.pendingActions()).find(item => item.id === id);
  return [...new Set(action?.clusterIds ?? [])];
}

async function planOf(rt: KeysentryRuntime, planId: unknown): Promise<RotationPlan | null> {
  if (typeof planId !== 'string') return null;
  try { return await rt.loadPlan(planId); } catch { return null; }
}

/** What approvers see: plain words, never a value. */
async function describe(rt: KeysentryRuntime, route: string, body: Body): Promise<Description> {
  switch (route) {
    case 'rotate/execute': {
      const plan = await planOf(rt, body.planId);
      const steps = plan?.steps ?? [];
      return { summary: `Rotate ${count(steps.length, 'key')}`, clusterIds: steps.map(step => step.clusterId), changes: [
        'Create replacement keys, write them where each key is used and redeploy, then revoke the old keys after the grace period.',
        ...steps.map(step => `${providerName(step.provider)} (${step.method}): ${step.consumers.map(consumer => `${serviceLabel(consumer.service)}:${consumer.varName}`).join(', ')}.`),
        `Rotation plan ${String(body.planId)}.`] };
    }
    case 'rotation/finish': {
      const plan = await planOf(rt, body.planId);
      return { summary: body.early === true ? 'Revoke the old keys of a rotation now' : 'Finish a rotation', clusterIds: plan?.steps.map(step => step.clusterId) ?? [],
        changes: [body.early === true
          ? `Revoke the old keys of rotation ${String(body.planId)} before its grace deadline (a team policy's minimum grace still applies).`
          : `Revoke the old keys of rotation ${String(body.planId)} whose grace period has ended.`] };
    }
    case 'rotation/undo': {
      const plan = await planOf(rt, body.planId);
      const selected = strings(body.clusterIds);
      return { summary: 'Undo a rotation', clusterIds: selected.length ? selected : plan?.steps.map(step => step.clusterId) ?? [],
        changes: [`Restore the old keys of rotation ${String(body.planId)} where they are still available, and redeploy.`] };
    }
    case 'spend-limits/apply': {
      const ids = strings(body.clusterIds);
      return { summary: `Apply spending limits to ${count(ids.length, 'key')}`, clusterIds: ids,
        changes: ['Set provider spending limits from the configured caps. A key that reaches its limit stops working until the limit is raised.'] };
    }
    case 'approvals/dismiss': {
      const clusterIds = await dismissedClusters(rt, body.id);
      return { summary: 'Dismiss a pending request', clusterIds, changes: [`Dismiss request ${String(body.id)}; it will not run.`,
        ...(clusterIds.length ? [`It concerns ${count(clusterIds.length, 'key')}, so dismissing it needs the approvals a change of ${clusterIds.length === 1 ? 'that key' : 'those keys'} needs.`] : [])] };
    }
    case 'autopilot/arm': {
      const ids = strings(body.clusterIds);
      const adopt = strings(body.adopt);
      return { summary: `Arm autopilot for ${count(ids.length, 'key')}`, clusterIds: ids, ...(adopt.length ? { rotates: [...new Set(adopt)] } : {}), changes: [
        `Let autopilot rotate ${count(ids.length, 'key')} automatically when a breach is confirmed, for ${String(body.validDays)} days.`,
        `Grace period ${String(body.graceMinutes)} minutes; at most ${String(body.maxServices)} services per wave.`,
        ...(adopt.length ? [`Rotate ${count(adopt.length, 'write-only key')} once now so autopilot knows ${adopt.length === 1 ? 'its value' : 'their values'}; this approval covers that rotation, so it also needs the approvals rotating ${adopt.length === 1 ? 'that key' : 'those keys'} needs.`] : [])] };
    }
    case 'settings/update':
      return { summary: 'Change dashboard settings', clusterIds: [],
        changes: Object.entries(body).map(([name, value]) => `${name}: ${typeof value === 'object' ? canonicalJson(value) : String(value)}`) };
    case 'notifications/add':
      return { summary: 'Add a notification channel', clusterIds: [],
        changes: [`Add a ${String(body.kind)} notification channel. Its settings are not stored with this request; the requester enters them again after approval.`] };
    case 'notifications/remove':
      return { summary: 'Remove a notification channel', clusterIds: [], changes: [`Remove notification channel ${String(body.id)}.`] };
    case 'vault/store':
      return { summary: `Store the ${String(body.name)} credential`, clusterIds: [],
        changes: [`Store ${String(body.name)} (${String(body.role)}) in the team server's vault. The value is never stored with this request; the requester enters it again after approval.`] };
    case 'vault/remove':
      return { summary: `Remove the ${String(body.name)} credential`, clusterIds: [], changes: [`Remove ${String(body.name)} (${String(body.role)}) from the team server's vault.`] };
    case 'reveal': {
      const cluster = (await rt.inventory()).clusters.find(item => item.id === body.clusterId);
      return { summary: 'Reveal a key value', clusterIds: typeof body.clusterId === 'string' ? [body.clusterId] : [], changes: [
        `Show the value of ${cluster ? `${providerName(cluster.provider)} key ${cluster.hint ?? cluster.id}` : 'a key'} in the requester's browser, once.`,
        'The team\'s notification channels are told who revealed it.'] };
    }
    default:
      throw new DashboardError(400, 'This change is not available on the team dashboard.');
  }
}

// ---------------------------------------------------------------------------------------------- request details
interface ChangeDetails {
  actionId: string;
  /** HMAC of route, body and requester: the same change by the same member finds its open request. */
  contentKey: string;
  route: string;
  requestedBy: string;
  summary: string;
  changes: string[];
  createdAt: string;
  /** The body, for changes the approver who completes the quorum may run; absent for secret-bearing changes. */
  body?: unknown;
}
const detailsSchema = z.object({ v: z.literal(1), requests: z.array(z.object({
  actionId: z.string().regex(/^team-[a-f0-9]{32}$/), contentKey: z.string().regex(/^[a-f0-9]{64}$/), route: z.string().max(80),
  requestedBy: z.string().regex(/^[a-z][a-z0-9_-]{0,31}$/), summary: z.string().max(200), changes: z.array(z.string().max(2000)).max(10_000),
  createdAt: z.string().datetime(), body: z.unknown().optional(),
}).strict()).max(500) }).strict();
const KEEP_MS = 24 * 60 * 60_000;

export interface TeamChangeItem {
  id: string; kind: string; summary: string; changes: string[]; reviewHash: string; createdAt: string; expiresAt: string; source: 'team';
  requestedBy: string; quorum: { approvals: number; required: number };
}

/** The team dashboard's change requests for one runtime. `routes` runs a route's handler with a body (approvals screen). */
export function createTeamChanges(rt: KeysentryRuntime, routes: { run(route: string, body: unknown, ctx: DashboardRequestContext, grant: TeamGrantRef): Promise<unknown> }) {
  const path = join(rt.paths.dir, 'team-dashboard-requests.json');
  const running = new Set<string>();
  let queue: Promise<unknown> = Promise.resolve();
  function details<T>(operation: (requests: ChangeDetails[], save: () => Promise<void>) => Promise<T>): Promise<T> {
    const next = queue.then(async () => {
      const raw = await rt.store.readJson('pending', path);
      const parsed = raw === null ? { success: true as const, data: { v: 1 as const, requests: [] } } : detailsSchema.safeParse(raw);
      if (!parsed.success) throw new DashboardError(503, 'The saved team requests could not be read. Ask a team admin to check keysentry.');
      const state = parsed.data as { v: 1; requests: ChangeDetails[] };
      const cutoff = rt.now().getTime() - KEEP_MS;
      state.requests = state.requests.filter(entry => Date.parse(entry.createdAt) > cutoff);
      return operation(state.requests, () => rt.store.writeJson('pending', path, state));
    });
    queue = next.catch(() => undefined);
    return next;
  }
  const contentKeyOf = (route: string, body: unknown, requestedBy: string) =>
    createHmac('sha256', rt.fingerprintKey).update(`keysentry-team-change:v1\n${canonicalJson({ route, body, requestedBy })}`).digest('hex');
  const actionOf = (entry: Pick<ChangeDetails, 'actionId' | 'route' | 'contentKey'>, description: Pick<Description, 'clusterIds' | 'rotates'>): ApprovalAction =>
    ({ id: entry.actionId, kind: `dashboard:${entry.route}`, clusterIds: [...new Set(description.clusterIds)], planHash: entry.contentKey,
      ...(description.rotates?.length ? { rotates: [...new Set(description.rotates)] } : {}) });

  async function team(): Promise<TeamRoster | null> {
    try { return (await rt.teamQuorum()?.team())?.roster ?? null; } catch { return null; }
  }
  async function requests(): Promise<StoredApproval[]> {
    return transactApprovals(rt.store, async state => state.requests.filter(request => request.kind.startsWith('dashboard:') && request.status !== 'superseded'));
  }
  function accepted(actionId: string, approvals: number, required: number, text: string): DashboardAccepted {
    return new DashboardAccepted({ teamRequest: 'recorded', id: actionId, approvals, required, text });
  }
  function nextStep(rule: TeamRouteRule): string {
    return rule.secret || rule.revealsResult
      ? ' After that, make the same change again here to run it; its values are not stored with the request.'
      : ' It runs when the last of them approves it on the Approvals screen.';
  }

  /**
   * Run an approved change once. The approval is claimed before the change runs (review L-c): the claim is saved under
   * the approvals file's cross-process lock, so no other request, process or retry can start the same approved change
   * again, even if marking it executed afterwards fails. The runtime entry points re-check the grant while it runs.
   */
  async function execute(service: ApprovalService, grant: TeamGrantRef, run: (grant: TeamGrantRef) => Promise<unknown>): Promise<unknown> {
    if (running.has(grant.actionId)) throw new DashboardError(409, 'This change is already running.');
    running.add(grant.actionId);
    try {
      try { await service.claim(grant.actionId, grant.digest); }
      catch (error) { if (error instanceof ApprovalError) throw new DashboardError(409, error.message); throw error; }
      try { return await run(grant); }
      finally {
        await service.markExecuted(grant.actionId, grant.digest)
          .catch(() => rt.log.warn('A team approval could not be marked as used. It was claimed before the change ran, so it cannot run again.'));
      }
    } finally {
      running.delete(grant.actionId);
    }
  }

  /**
   * A member's passkey-confirmed change on the team dashboard. Returns the handler's result once the quorum is met
   * (this approval may complete it), or a `DashboardAccepted` with the progress while more approvals are needed.
   */
  async function submit(route: string, body: unknown, ctx: DashboardRequestContext, run: (grant: TeamGrantRef) => Promise<unknown>): Promise<unknown> {
    const rule = TEAM_QUORUM_ROUTES[route];
    if (!rule) throw new DashboardError(400, 'This change is not available on the team dashboard.');
    if (!ctx.member || !ctx.passkey) throw new DashboardError(403, 'Confirm this change with your passkey.');
    const member = ctx.member.id;
    const contentKey = contentKeyOf(route, body, member);
    const service = rt.teamApprovalService();
    const current = await requests();
    // The same change by the same member continues its open request (pending, or approved and not yet started). An
    // approval whose run already started (claimed) is never run again: the same change opens a new request.
    const known = await details(async entries => entries.filter(entry => entry.contentKey === contentKey).map(entry => ({ ...entry })));
    const open = known.map(entry => ({ entry, request: current.find(request => request.actionId === entry.actionId
      && (request.status === 'pending' || request.status === 'approved' && request.claimedAt === undefined)) }))
      .find(item => item.request !== undefined && Date.parse(item.request.expiresAt) > rt.now().getTime());
    if (open?.request?.status === 'approved') {
      return execute(service, { actionId: open.entry.actionId, digest: open.request.digest, kind: `dashboard:${route}` }, run);
    }
    let actionId: string;
    let digest: string;
    if (open?.request) {
      actionId = open.entry.actionId; digest = open.request.digest;
      const roster = await team();
      const quorum = open.request.quorum;
      if (quorum && roster && quorum.approvers.some(approver => approver.memberId === member) && qualifyingApprovals({ admins: quorum.admins,
        approvers: quorum.approvers.filter(approver => approver.memberId === member) }, roster) > 0) {
        const approvals = qualifyingApprovals(quorum, roster);
        return accepted(actionId, approvals, quorum.required, `You already approved this change: ${approvals} of ${quorum.required} team approvals so far. It needs ${quorum.required - approvals} more from other team ${quorum.admins ? 'admins' : 'members'}.${nextStep(rule)}`);
      }
    } else {
      const description = await describe(rt, route, (body ?? {}) as Body);
      actionId = `team-${randomBytes(16).toString('hex')}`;
      const action = actionOf({ actionId, route, contentKey }, description);
      digest = actionDigest(action);
      try { await service.request(action, false, { admins: rule.admins }); }
      catch (error) { if (error instanceof ApprovalError) throw new DashboardError(409, error.message); throw error; }
      await details(async (entries, save) => {
        entries.push({ actionId, contentKey, route, requestedBy: member, summary: description.summary, changes: description.changes, createdAt: rt.now().toISOString(),
          ...(rule.secret || rule.revealsResult ? {} : { body: structuredClone(body) }) });
        await save();
      });
    }
    try { await service.approveAsMember(actionId, { memberId: member, credentialId: ctx.passkey }, digest); }
    catch (error) {
      if (error instanceof ApprovalPendingError) return accepted(actionId, error.approvals, error.required, `${pendingText(error)}${nextStep(rule)}`);
      if (error instanceof ApprovalError) throw new DashboardError(409, error.message);
      throw error;
    }
    return execute(service, { actionId, digest, kind: `dashboard:${route}` }, run);
  }

  /** Pending team dashboard requests for the Approvals screen (value-free descriptions). */
  async function pending(): Promise<TeamChangeItem[]> {
    const now = rt.now().getTime();
    const open = (await requests()).filter(request => request.status === 'pending' && Date.parse(request.expiresAt) > now);
    if (!open.length) return [];
    const roster = await team();
    const known = await details(async entries => entries.map(entry => ({ ...entry })));
    return open.map(request => {
      const entry = known.find(item => item.actionId === request.actionId);
      const summary = entry?.summary ?? 'A team dashboard change';
      const changes = entry?.changes ?? ['The details of this change are no longer available. Dismiss it, and ask the member to make the change again.'];
      const requestedBy = entry?.requestedBy ?? 'unknown';
      return { id: request.actionId, kind: request.kind.slice('dashboard:'.length), summary: `${summary} (requested by ${requestedBy})`, changes,
        reviewHash: reviewHash(request, summary, changes, requestedBy), createdAt: request.createdAt, expiresAt: request.expiresAt, source: 'team' as const, requestedBy,
        quorum: { approvals: request.quorum && roster ? qualifyingApprovals(request.quorum, roster) : 0, required: request.quorum?.required ?? 1 } };
    });
  }
  function reviewHash(request: StoredApproval, summary: string, changes: string[], requestedBy: string): string {
    return createHash('sha256').update(canonicalJson({ id: request.actionId, digest: request.digest, expiresAt: request.expiresAt, summary, changes, requestedBy })).digest('hex');
  }

  /**
   * Approve a pending team request from the Approvals screen with the member's own passkey. When this approval completes
   * the quorum, a change whose body was kept runs now, as this member; others wait for the requester to run them.
   */
  async function approve(id: string, review: string, ctx: DashboardRequestContext):
    Promise<{ result: 'recorded'; approvals: number; required: number; text: string } | { result: 'approved' | 'executed'; text: string; output?: unknown }> {
    if (!ctx.member || !ctx.passkey) throw new DashboardError(403, 'Confirm this approval with your passkey.');
    const request = (await requests()).find(item => item.actionId === id && item.status === 'pending' && Date.parse(item.expiresAt) > rt.now().getTime());
    if (!request) throw new DashboardError(409, 'This request is no longer waiting for approval.');
    const entry = await details(async entries => entries.find(item => item.actionId === id));
    if (!entry) throw new DashboardError(409, 'The details of this change are no longer available. Dismiss it, and ask the member to make the change again.');
    if (reviewHash(request, entry.summary, entry.changes, entry.requestedBy) !== review) throw new DashboardError(409, 'The change was updated. Review it again before approving.');
    const rule = TEAM_QUORUM_ROUTES[entry.route];
    if (!rule) throw new DashboardError(409, 'This change is not available on the team dashboard.');
    // The stored change must still be exactly the one the request (and its digest) was made for.
    if (request.kind !== `dashboard:${entry.route}` || request.action?.planHash !== entry.contentKey
      || (entry.body !== undefined && contentKeyOf(entry.route, entry.body, entry.requestedBy) !== entry.contentKey)) {
      throw new DashboardError(409, 'The details of this change could not be verified. Dismiss it, and ask the member to make the change again.');
    }
    const service = rt.teamApprovalService();
    try { await service.approveAsMember(id, { memberId: ctx.member.id, credentialId: ctx.passkey }, request.digest); }
    catch (error) {
      if (error instanceof ApprovalPendingError) {
        return { result: 'recorded', approvals: error.approvals, required: error.required, text: `${pendingText(error)}${nextStep(rule)}` };
      }
      if (error instanceof ApprovalError) throw new DashboardError(409, error.message);
      throw error;
    }
    if (entry.body === undefined || rule.secret || rule.revealsResult) {
      return { result: 'approved', text: `Approved by the team. ${entry.requestedBy} can now make this change: ${entry.summary}.` };
    }
    const grant = { actionId: id, digest: request.digest, kind: `dashboard:${entry.route}` };
    const output = await execute(service, grant, current => routes.run(entry.route, entry.body, ctx, current));
    return { result: 'executed', text: `Approved by the team and done: ${entry.summary}.`, output };
  }

  /** Team quorum progress of a stored approval request ("n of m"), counting only approvers who still qualify. */
  async function progress(request: Pick<StoredApproval, 'quorum'>): Promise<{ approvals: number; required: number } | undefined> {
    if (!request.quorum) return undefined;
    const roster = await team();
    return { approvals: roster ? qualifyingApprovals(request.quorum, roster) : 0, required: request.quorum.required };
  }

  return { submit, pending, approve, progress };
}
