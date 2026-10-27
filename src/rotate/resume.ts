import type { RotationReport } from '../types.js';
import { runRotation, type EngineDeps, type RotateOptions } from './engine.js';
import type { RecoveryInput } from './recovery.js';

/** Resume from durable values; terminal plans have no further effects. */
export async function resumeRotation(input: RecoveryInput, deps: EngineDeps, opts: RotateOptions): Promise<RotationReport> {
  const entries = input.entries.filter(entry => entry.planId === input.plan.id);
  const last = entries.at(-1);
  const allSettled = input.plan.steps.every(step => entries.some(entry => entry.clusterId === step.clusterId
    && (entry.event === 'undo' || entry.event === 'revoked' && entry.data?.cleanup !== true && entry.data?.undo !== true)));
  if (last?.event === 'plan-end' && (last.data?.pending === false
    || last.data?.pending !== true && (allSettled || last.data?.dryRun === true || ['complete', 'failed', 'dry-run'].includes(String(last.data?.status))))) {
    const saved = last.data?.report;
    if (saved && typeof saved === 'object' && 'planId' in saved && saved.planId === input.plan.id) return saved as RotationReport;
    const dryRun = last.data?.status === 'dry-run' || last.data?.dryRun === true;
    return { planId: input.plan.id, dryRun, status: dryRun ? 'dry-run' : last.data?.status === 'failed' ? 'failed' : 'complete',
      startedAt: entries.find(entry => entry.event === 'plan-start')?.at ?? input.plan.createdAt, finishedAt: last.at,
      deployments: [], diff: [], steps: input.plan.steps.map(step => ({ clusterId: step.clusterId,
        status: entries.some(entry => entry.clusterId === step.clusterId && entry.event === 'undo') ? 'skipped' : 'revoked', warnings: [] })) };
  }
  return runRotation(input.plan, input.inventory, deps, opts, entries);
}
