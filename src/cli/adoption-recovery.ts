import { verifyArmedPlan, type AutopilotState } from '../autopilot/index.js';
import type { UndoReport } from '../rotate/undo.js';
import type { ArmedPlan, Inventory, JournalEntry, RotationReport } from '../types.js';
import type { AdoptionUpdates, CliAutopilotState } from './autopilot.js';
import { CliError } from './errors.js';

interface ManualAdoptionInput {
  report: RotationReport; armed: ArmedPlan | null; state: AutopilotState; inventory: Inventory;
  trustedKeyIds: string[]; now?: Date; entries?: JournalEntry[];
  saveState: (state: AutopilotState) => Promise<void>;
  applyUpdates: (updates: AdoptionUpdates, options: { inventory: Inventory; reports: RotationReport[] }) => Promise<unknown>;
}

function completed(report: RotationReport): boolean {
  return !report.dryRun && report.status === 'complete' && !report.pendingRevocations?.length
    && report.steps.length > 0 && report.steps.every(s => ['deployed', 'verified', 'revoked'].includes(s.status))
    && report.deployments.every(d => d.state === 'success');
}

/** Preserve observed replacement references without making a partial delivery an authorization. */
export async function persistManualAdoption(input: ManualAdoptionInput): Promise<{ recorded: number; refreshed: boolean }> {
  const { report } = input;
  const state = input.state as CliAutopilotState;
  const ignored = { recorded: 0, refreshed: false };
  if (report.dryRun || !input.armed) return ignored;
  const at = input.now ?? new Date();
  const verified = verifyArmedPlan(input.armed, { now: at, trustedKeyIds: input.trustedKeyIds });
  if (!verified.ok || state.armedPlanId !== verified.plan.id) return ignored;
  const updates: AdoptionUpdates = {};
  const entries = input.entries?.filter(e => e.planId === report.planId) ?? [];
  for (const step of report.steps) {
    const signed = verified.plan.clusters.find(c => c.clusterId === step.clusterId && c.adopted);
    if (!signed || !step.newKeyRef || !step.newFingerprint) continue;
    if (!['written', 'deployed', 'verified', 'revoked', 'failed'].includes(step.status)) continue;
    const cleaned = entries.some(e => e.event === 'revoked' && e.clusterId === step.clusterId
      && e.data?.cleanup === true && e.data.keyRef === step.newKeyRef);
    if (cleaned) continue;
    if (step.status === 'failed') {
      const services = new Set(signed.consumers.map(c => c.serviceKey));
      const mayHaveBeenDelivered = report.deployments.some(d => services.has(d.serviceKey) && d.state !== 'skipped')
        || entries.some(e => e.clusterId === step.clusterId && e.event === 'written'
          || e.serviceKey && services.has(e.serviceKey) && e.event === 'failed' && e.data?.partialWritePossible === true);
      if (!mayHaveBeenDelivered) continue;
    }
    updates[step.clusterId] = { fingerprint: step.newFingerprint, keyRef: step.newKeyRef, at: at.toISOString() };
  }
  if (!Object.keys(updates).length) return ignored;
  if (state.adoptionUpdates && Object.keys(state.adoptionUpdates).length && state.adoptionUpdatesPlanId !== verified.plan.id) {
    throw new CliError('Saved adopted-key observations belong to another armed plan. Review them before refreshing keys.');
  }
  state.adoptionUpdates = { ...state.adoptionUpdates, ...updates };
  state.adoptionUpdatesPlanId = verified.plan.id;
  state.adoptionNoticeSent = false;
  for (const clusterId of Object.keys(updates)) {
    if (!completed(report)) {
      state.manualAdoptionPending ??= {};
      state.manualAdoptionPending[clusterId] ??= report.planId;
    } else if (state.manualAdoptionPending?.[clusterId] === report.planId) delete state.manualAdoptionPending[clusterId];
  }
  if (state.manualAdoptionPending && !Object.keys(state.manualAdoptionPending).length) delete state.manualAdoptionPending;
  await input.saveState(state);
  // A new plan id would invalidate pending grace/recovery, even for another cluster.
  if (!completed(report) || state.waves.some(w => w.status !== 'done') || Object.keys(state.manualAdoptionPending ?? {}).length || input.inventory.errors.length) {
    return { recorded: Object.keys(updates).length, refreshed: false };
  }
  await input.applyUpdates(state.adoptionUpdates, { inventory: input.inventory, reports: [report] });
  return { recorded: Object.keys(updates).length, refreshed: true };
}

/** Call after a human recovery operation, then save changed state before refreshing the plan. */
export function reconcileAutopilotRecovery(state: AutopilotState, input: {
  planId: string; report?: RotationReport; undo?: UndoReport; entries?: JournalEntry[];
}): boolean {
  let changed = false;
  const localState = state as CliAutopilotState;
  let done = input.report ? completed(input.report) && input.report.planId === input.planId : false;
  if (input.undo) {
    for (const restored of input.undo.restored) {
      if (state.adoptionUpdates?.[restored.clusterId]) { delete state.adoptionUpdates[restored.clusterId]; changed = true; }
      if (localState.manualAdoptionPending?.[restored.clusterId] === input.planId) {
        delete localState.manualAdoptionPending[restored.clusterId]; changed = true;
      }
    }
    if (state.adoptionUpdates && Object.keys(state.adoptionUpdates).length === 0) {
      delete state.adoptionUpdates; delete state.adoptionUpdatesPlanId; delete state.adoptionNoticeSent; changed = true;
    }
    const end = input.entries?.filter(e => e.planId === input.planId && e.event === 'plan-end').at(-1);
    done = input.undo.unavailable.length === 0 && end?.data?.status === 'complete' && end.data.undone === true;
  }
  if (done) for (const wave of state.waves) {
    if (wave.planId !== input.planId || wave.status === 'done') continue;
    wave.status = 'done'; delete wave.deadline; changed = true;
  }
  if (done) for (const [clusterId, planId] of Object.entries(localState.manualAdoptionPending ?? {})) {
    if (planId === input.planId) { delete localState.manualAdoptionPending![clusterId]; changed = true; }
  }
  if (localState.manualAdoptionPending && !Object.keys(localState.manualAdoptionPending).length) {
    delete localState.manualAdoptionPending; changed = true;
  }
  return changed;
}
