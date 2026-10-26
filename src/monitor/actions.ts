import { randomUUID } from 'node:crypto';
import { buildPlan } from '../core/plan.js';
import type { Notifier, PendingAction, Policy, RotationPlan, RotationReport } from '../types.js';
import { findProvider, isSafeKeyRef, now, resolveClusterKeyRef, type DetectorContext } from './context.js';
import { decide, type Decision } from './policy.js';

export type RotateExecutor = (plan: RotationPlan) => Promise<RotationReport>;
export interface ActionContext extends DetectorContext {
  policy: Policy;
  notifier: Notifier;
  rotate: RotateExecutor;
  /** Called before irreversible actions and after state changes. A failed save stops execution. */
  saveState?: () => Promise<void>;
}

async function save(ctx: ActionContext): Promise<void> {
  try { await ctx.saveState?.(); } catch { throw new Error('Unable to save monitor actions.'); }
}

async function notify(ctx: ActionContext, title: string, body: string): Promise<void> {
  try { await ctx.notifier.notify(title,body); }
  catch { ctx.log.warn('Unable to deliver a monitor notification.'); }
}

async function pend(decision: Decision, ctx: ActionContext): Promise<void> {
  const ids = [...new Set(decision.clusterIds)].sort();
  let pending = ctx.state.pendingActions.find(action => action.status === 'pending' && action.action === decision.action
    && [...action.clusterIds].sort().join('\0') === ids.join('\0'));
  if (!pending) {
    pending = {id:`action-${randomUUID()}`,createdAt:now(ctx).toISOString(),signalId:decision.signalId,
      action:decision.action,clusterIds:ids,status:'pending',note:decision.reason ?? 'Approval required.'};
    ctx.state.pendingActions.push(pending);
    await save(ctx);
  }
  await notify(ctx,'keysentry: action pending',`${pending.action} requested for ${ids.length} secret cluster(s). Approve action ${pending.id}.`);
}

async function rotateClusters(ids: string[], ctx: ActionContext, automatic: boolean, pending: PendingAction): Promise<RotationReport|undefined> {
  const plan = buildPlan(ctx.inventory,{clusterIds:ids});
  if (plan.steps.length !== ids.length || ids.length === 0) {
    pending.status='failed';pending.note='Selected clusters are missing from the current inventory.';
    await save(ctx);await notify(ctx,'keysentry: rotation failed',pending.note);return;
  }
  const at = now(ctx).toISOString();
  pending.status='approved';
  const previousVerify = new Map(ids.map(id=>[id,ctx.state.lastVerify[id]]));
  for (const id of ids) {
    ctx.state.cooldowns[id]=at;
    const cluster=ctx.inventory.clusters.find(cluster=>cluster.id===id)!;
    ctx.state.lastVerify[id]={at,ok:false,fingerprint:cluster.fingerprint ?? id};
  }
  if (automatic) {
    const day=at.slice(0,10);
    ctx.state.autoRotations[day]=(ctx.state.autoRotations[day] ?? 0)+ids.length;
  }
  // Reserve first: a partially successful executor must not be retried in a loop.
  try { await save(ctx); }
  catch {
    pending.status='pending';pending.note='Reservation could not be saved; execution did not start.';
    for(const [id,previous] of previousVerify) {
      if(previous) ctx.state.lastVerify[id]=previous; else delete ctx.state.lastVerify[id];
    }
    throw new Error('Unable to save monitor actions.');
  }
  let report: RotationReport;
  try { report=await ctx.rotate(plan); }
  catch {
    pending.status='failed';pending.note='Rotation executor failed; inspect the rotation journal.';
    await save(ctx);await notify(ctx,'keysentry: rotation failed',pending.note);return;
  }
  const completed = new Set(report.steps.filter(step=>step.status==='verified' || step.status==='revoked').map(step=>step.clusterId));
  const incomplete=ids.filter(id=>!completed.has(id));
  pending.status=report.dryRun || report.planId!==plan.id || report.steps.some(step=>step.status==='failed')
    ? 'failed' : incomplete.length ? 'pending':'executed';
  pending.note=pending.status==='failed' ? 'Rotation did not complete; inspect the rotation report.'
    : pending.status==='pending' ? 'Some selected clusters were skipped or incomplete; human remediation is required.' : 'Rotation executor completed.';
  if(pending.status==='pending') pending.clusterIds=incomplete;
  for(const step of report.steps) {
    if (report.dryRun || report.planId!==plan.id || !ids.includes(step.clusterId) || !completed.has(step.clusterId)) continue;
    if (step.newFingerprint && /^[a-f0-9]{32}$/.test(step.newFingerprint)) {
      ctx.state.cooldowns[step.newFingerprint]=at;
      delete ctx.state.keyRefs[step.clusterId];
      if (step.newKeyRef && isSafeKeyRef(step.newKeyRef,ctx)) {
        ctx.state.keyRefs[step.newFingerprint]=step.newKeyRef;
        const cluster=ctx.inventory.clusters.find(cluster=>cluster.id===step.clusterId);
        if(cluster?.fingerprint===null) ctx.state.keyRefs[step.clusterId]=step.newKeyRef;
      }
    }
  }
  await save(ctx);
  await notify(ctx,`keysentry: rotation ${pending.status}`,`${ids.length} secret cluster(s): ${pending.note}${pending.status==='pending' ? ` Approve action ${pending.id}.`:''}`);
  return report;
}

async function executeCurrent(decision: Decision, ctx: ActionContext): Promise<void> {
  if (decision.action==='alert') {
    await notify(ctx,'keysentry: monitor alert',`${decision.signal.kind}: ${decision.clusterIds.length} secret cluster(s) implicated.`);
    return;
  }
  if (decision.action==='cap') {
    const failed:string[]=[];
    for(const id of decision.clusterIds) {
      const cluster=ctx.inventory.clusters.find(cluster=>cluster.id===id);
      const provider=cluster ? findProvider(ctx,cluster.provider):undefined;
      if (!cluster || !provider?.cap) { failed.push(id);continue; }
      const previousVerify=ctx.state.lastVerify[id];
      try {
        const ref=await resolveClusterKeyRef(cluster,ctx);
        if(!ref) { failed.push(id);continue; }
        // Preserve the locally intended revocation, so it cannot masquerade as an upstream event.
        ctx.state.lastVerify[id]={at:now(ctx).toISOString(),ok:false,fingerprint:cluster.fingerprint ?? id};
        await save(ctx);
        await provider.cap(ref,ctx.providerCtx);
      } catch {
        if(previousVerify) ctx.state.lastVerify[id]=previousVerify; else delete ctx.state.lastVerify[id];
        failed.push(id);ctx.log.warn('Unable to contain a monitored key.');
      }
    }
    await save(ctx);
    if(failed.length) await notify(ctx,'keysentry: containment unavailable',`${failed.length} secret cluster(s) could not be contained; review provider access.`);
    await notify(ctx,'keysentry: containment',`${decision.clusterIds.length-failed.length} secret cluster(s) contained.`);
    return;
  }
  if (!decision.automatic || !ctx.policy.autoExecute) { await pend(decision,ctx);return; }
  const pending:PendingAction={id:`action-${randomUUID()}`,createdAt:now(ctx).toISOString(),signalId:decision.signalId,
    action:decision.action,clusterIds:[...decision.clusterIds],status:'approved'};
  ctx.state.pendingActions.push(pending);
  await rotateClusters(decision.clusterIds,ctx,true,pending);
}

/** Re-evaluate at execution time so stale decisions cannot bypass policy or reserved limits. */
export async function executeDecisions(decisions: readonly Decision[], ctx: ActionContext): Promise<void> {
  for(const decision of decisions) {
    if(!decision.automatic) { await executeCurrent(decision,ctx);continue; }
    const current=decide({...decision.signal,at:now(ctx).toISOString()},ctx.inventory,ctx.policy,ctx.state);
    for(const next of current) {
      const ids=next.clusterIds.filter(id=>decision.clusterIds.includes(id));
      if(ids.length) await executeCurrent({...next,clusterIds:ids},ctx);
    }
  }
}

/** Explicit approval authorizes exactly the recorded clusters, without automatic limits. */
export async function approve(actionId: string, ctx: ActionContext): Promise<RotationReport|undefined> {
  const pending=ctx.state.pendingActions.find(action=>action.id===actionId);
  if(!pending || pending.status!=='pending') throw new Error('No pending monitor action with this identifier.');
  if(pending.action!=='rotate' && pending.action!=='breach-mode') throw new Error('Only rotation actions can be approved.');
  return rotateClusters([...new Set(pending.clusterIds)],ctx,false,pending);
}

export async function dismiss(actionId: string, ctx: ActionContext): Promise<void> {
  const pending=ctx.state.pendingActions.find(action=>action.id===actionId && action.status==='pending');
  if(!pending) throw new Error('No pending monitor action with this identifier.');
  pending.status='dismissed';await save(ctx);
}
