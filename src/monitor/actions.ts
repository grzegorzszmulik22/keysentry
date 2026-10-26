import { randomUUID } from 'node:crypto';
import { buildPlan } from '../core/plan.js';
import type { Notifier, Policy, RotationPlan, RotationReport, Signal } from '../types.js';
import { findProvider, isSafeKeyRef, now, resolveClusterKeyRef, type DetectorContext } from './context.js';
import { decide, type Decision } from './policy.js';
import { usageKey, type MonitorPendingAction } from './state.js';

export type RotateExecutor = (plan: RotationPlan, opts: { revokeUnconfirmed: boolean; allowGenerate: false }) => Promise<RotationReport>;
export interface ActionContext extends DetectorContext {
  policy: Policy;
  notifier: Notifier;
  rotate: RotateExecutor;
  /** True only when approval uses an interactive executor that can prompt and reveal replacement values. */
  interactive?: boolean;
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

function highConfidence(signal: Signal): boolean {
  return signal.confidence === 'high'
    && ['canary_triggered','leak_detected','revoked_upstream'].includes(signal.kind);
}

function approvalRequirements(action: MonitorPendingAction['action'], ids: readonly string[], isHighConfidence: boolean, ctx: ActionContext) {
  const rotation = action === 'rotate' || action === 'breach-mode';
  return {
    requiresInteractive: rotation && ctx.inventory.clusters.some(cluster => ids.includes(cluster.id) && cluster.method === 'atomic-roll'),
    revokeUnconfirmed: rotation && isHighConfidence && ctx.policy.revokeUnconfirmedOnHighConfidence,
  };
}

async function pend(decision: Decision, ctx: ActionContext): Promise<void> {
  const ids = [...new Set(decision.clusterIds)].sort();
  let pending = ctx.state.pendingActions.find(action => action.status === 'pending' && action.action === decision.action
    && [...action.clusterIds].sort().join('\0') === ids.join('\0'));
  if (!pending) {
    pending = {id:`action-${randomUUID()}`,createdAt:now(ctx).toISOString(),signalId:decision.signalId,
      action:decision.action,clusterIds:ids,status:'pending',note:decision.reason ?? 'Approval required.',
      highConfidence:highConfidence(decision.signal),
      ...approvalRequirements(decision.action,ids,highConfidence(decision.signal),ctx)};
    ctx.state.pendingActions.push(pending);
    await save(ctx);
  } else {
    const isHighConfidence=pending.highConfidence === true || highConfidence(decision.signal);
    const requirements=approvalRequirements(pending.action,ids,isHighConfidence,ctx);
    requirements.requiresInteractive ||= pending.requiresInteractive === true;
    if(pending.highConfidence !== isHighConfidence || pending.requiresInteractive !== requirements.requiresInteractive
      || pending.revokeUnconfirmed !== requirements.revokeUnconfirmed) {
      Object.assign(pending,{highConfidence:isHighConfidence,...requirements});
      await save(ctx);
    }
  }
  const interactive=pending.requiresInteractive ? ' An atomic roll kills the old key immediately and needs a human present; interactive approval is required.' : '';
  const revocation=pending.revokeUnconfirmed ? ' Approval will revoke old keys even when consumer activation is unconfirmed.' : '';
  await notify(ctx,'keysentry: action pending',`${pending.action} requested for ${ids.length} secret cluster(s).${interactive}${revocation} Approve action ${pending.id}.`);
}

async function rotateClusters(ids: string[], ctx: ActionContext, automatic: boolean, pending: MonitorPendingAction): Promise<RotationReport|undefined> {
  const plan = buildPlan(ctx.inventory,{clusterIds:ids});
  if (plan.steps.length !== ids.length || ids.length === 0) {
    pending.status='failed';pending.note='Selected clusters are missing from the current inventory.';
    await save(ctx);await notify(ctx,'keysentry: rotation failed',pending.note);return;
  }
  if (plan.steps.some(step=>step.method==='generate')) {
    pending.status='failed';pending.note='The monitor cannot generate secrets; human remediation is required.';
    await save(ctx);await notify(ctx,'keysentry: monitor alert',pending.note);return;
  }
  // Recheck the live plan: historical pending records may predate the interactive requirement.
  if(plan.steps.some(step=>step.method==='atomic-roll')) pending.requiresInteractive=true;
  if(pending.requiresInteractive && (automatic || ctx.interactive !== true)) {
    pending.status='pending';
    pending.note='An atomic roll kills the old key immediately and needs a human present; approval requires an interactive run.';
    await save(ctx);await notify(ctx,'keysentry: action pending',pending.note);
    if(automatic) return;
    throw new Error(pending.note);
  }
  // A later policy can narrow a recorded choice, but must never silently broaden it during approval.
  pending.revokeUnconfirmed=pending.revokeUnconfirmed === true && ctx.policy.revokeUnconfirmedOnHighConfidence;
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
  try { report=await ctx.rotate(plan, {
    revokeUnconfirmed:pending.revokeUnconfirmed,
    allowGenerate:false,
  }); }
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

async function containClusters(ids: string[], ctx: ActionContext, automatic: boolean, pending: MonitorPendingAction, signal?: Signal): Promise<void> {
  const incomplete: string[]=[];
  pending.status='approved';
  for(const id of ids) {
    const cluster=ctx.inventory.clusters.find(cluster=>cluster.id===id);
    const provider=cluster ? findProvider(ctx,cluster.provider):undefined;
    if(!cluster || !provider?.cap) { incomplete.push(id);continue; }
    let ref: string|null;
    try { ref=await resolveClusterKeyRef(cluster,ctx); }
    catch { incomplete.push(id);ctx.log.warn('Unable to resolve a monitored key for containment.');continue; }
    if(!ref) { incomplete.push(id);continue; }
    // Resolution may discover that another cluster is the same provider key.
    // Recheck after that await and reserve synchronously before the provider call.
    if(automatic && signal) {
      const eligible=decide({...signal,at:now(ctx).toISOString()},ctx.inventory,ctx.policy,ctx.state)
        .some(decision=>decision.automatic && decision.action==='cap' && decision.clusterIds.includes(id));
      if(!eligible) { incomplete.push(id);continue; }
    }
    const at=now(ctx).toISOString();
    const previousVerify=ctx.state.lastVerify[id];
    ctx.state.containCooldowns[id]=at;
    ctx.state.containCooldowns[usageKey(cluster.provider,ref)]=at;
    if(automatic) ctx.state.autoContainments[at.slice(0,10)]=(ctx.state.autoContainments[at.slice(0,10)] ?? 0)+1;
    // Preserve the locally intended revocation, so it cannot masquerade as an upstream event.
    ctx.state.lastVerify[id]={at,ok:false,fingerprint:cluster.fingerprint ?? id};
    try { await save(ctx); }
    catch {
      pending.status='pending';pending.note='Reservation could not be saved; containment did not start.';
      if(previousVerify) ctx.state.lastVerify[id]=previousVerify; else delete ctx.state.lastVerify[id];
      throw new Error('Unable to save monitor actions.');
    }
    try { await provider.cap(ref,ctx.providerCtx); }
    catch {
      if(previousVerify) ctx.state.lastVerify[id]=previousVerify; else delete ctx.state.lastVerify[id];
      incomplete.push(id);ctx.log.warn('Unable to contain a monitored key.');
    }
  }
  pending.status=incomplete.length ? 'pending':'executed';
  pending.note=incomplete.length ? 'Some keys could not be contained; approval or human remediation is required.' : 'Containment completed.';
  if(incomplete.length) pending.clusterIds=incomplete;
  await save(ctx);
  await notify(ctx,`keysentry: containment ${pending.status}`,`${ids.length-incomplete.length} secret cluster(s) contained. ${pending.note}${incomplete.length ? ` Approve action ${pending.id}.`:''}`);
}

async function executeCurrent(decision: Decision, ctx: ActionContext): Promise<void> {
  if (decision.action==='alert') {
    const note=decision.reason==='incomplete-scan' ? ' Automatic action excluded because a consumer host failed to scan.'
      : decision.reason==='generate-disabled' ? ' The monitor cannot generate secrets; human remediation is required.'
      : decision.reason==='atomic-roll-disabled' ? ' Automatic rotation excluded because an atomic roll kills the old key immediately and needs a human present.' : '';
    await notify(ctx,'keysentry: monitor alert',`${decision.signal.kind}: ${decision.clusterIds.length} secret cluster(s) implicated.${note}`);
    return;
  }
  const enabled=decision.action==='cap' ? ctx.policy.autoContain : ctx.policy.autoExecute;
  if (!decision.automatic || !enabled) { await pend(decision,ctx);return; }
  const pending:MonitorPendingAction={id:`action-${randomUUID()}`,createdAt:now(ctx).toISOString(),signalId:decision.signalId,
    action:decision.action,clusterIds:[...decision.clusterIds],status:'approved',highConfidence:highConfidence(decision.signal),
    ...approvalRequirements(decision.action,decision.clusterIds,highConfidence(decision.signal),ctx)};
  ctx.state.pendingActions.push(pending);
  if(decision.action==='cap') { await containClusters(decision.clusterIds,ctx,true,pending,decision.signal);return; }
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
  if(pending.action==='cap') { await containClusters([...new Set(pending.clusterIds)],ctx,false,pending);return; }
  if(pending.action!=='rotate' && pending.action!=='breach-mode') throw new Error('Only rotation or containment actions can be approved.');
  return rotateClusters([...new Set(pending.clusterIds)],ctx,false,pending);
}

export async function dismiss(actionId: string, ctx: ActionContext): Promise<void> {
  const pending=ctx.state.pendingActions.find(action=>action.id===actionId && action.status==='pending');
  if(!pending) throw new Error('No pending monitor action with this identifier.');
  pending.status='dismissed';await save(ctx);
}
