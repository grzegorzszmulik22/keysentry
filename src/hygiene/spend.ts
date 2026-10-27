import { createRedactor } from '../core/redact.js';
import { usageKey, type MonitorState } from '../monitor/state.js';
import { openrouterProvider } from '../providers/openrouter.js';
import type { Inventory, ProviderContext, ProviderId, ProviderKeyInfo } from '../types.js';
import type { HygieneState } from './age.js';

export interface SpendLimitPlan {
  clusterId: string;
  keyRef: string;
  limitUsd: number;
  reason: string;
}

export interface SpendLimitAvailability {
  clusterId: string;
  provider: ProviderId;
  available: boolean;
  reason?: string;
}

export interface SpendLimitsInput {
  inventory: Inventory;
  state: HygieneState;
  monitor: MonitorState;
  providerKeys?: Partial<Record<ProviderId, readonly ProviderKeyInfo[]>>;
  /** Fresh spend for the limit's current period, keyed by cluster id or usageKey(provider, keyRef). */
  currentPeriodSpendUsd?: Record<string, number>;
}

export function spendLimitAvailability(inventory: Inventory): SpendLimitAvailability[] {
  return inventory.clusters.map(cluster => ({ clusterId: cluster.id, provider: cluster.provider,
    available: cluster.provider === 'openrouter',
    ...(cluster.provider === 'openrouter' ? {} : { reason: 'not available from this provider' }) }));
}

function amount(value: number, message: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) throw new Error(message);
  return value;
}

/** A cap is a per-key ceiling; known tighter provider limits are preserved. */
export function planSpendLimits(input: SpendLimitsInput): SpendLimitPlan[] {
  const plans: SpendLimitPlan[] = [];
  for (const cap of Object.values(input.state.settings.spendCapsUsd)) amount(cap, 'Invalid spending cap.');
  const redactor = createRedactor();
  for (const cluster of input.inventory.clusters) {
    if (cluster.provider !== 'openrouter') continue;
    const cap = input.state.settings.spendCapsUsd.openrouter;
    const keyRef = input.monitor.keyRefs[cluster.id];
    if (cap === undefined || !keyRef) continue;
    if (!/^[A-Za-z0-9_-]+$/.test(keyRef) || redactor.redact(keyRef) !== keyRef) {
      throw new Error('Invalid spending key reference.');
    }
    const key = usageKey(cluster.provider, keyRef);
    const periods = input.currentPeriodSpendUsd;
    // Lifetime spend is a conservative upper bound when a reset-period counter
    // is unavailable. Hourly buckets alone cannot prove current-period spend.
    const spent = periods && Object.hasOwn(periods, cluster.id) ? periods[cluster.id]
      : periods && Object.hasOwn(periods, key) ? periods[key] : input.monitor.cumulativeTotals[key]?.costUsd;
    if (spent === undefined) continue;
    if (amount(spent, 'Invalid spending counter.') > cap) continue;
    const existing = input.providerKeys?.openrouter?.find(entry => entry.keyRef === keyRef)?.limitUsd;
    if (existing !== undefined && existing !== null && amount(existing, 'Invalid spending limit.') <= cap) continue;
    plans.push({ clusterId: cluster.id, keyRef, limitUsd: cap,
      reason: 'Set the key limit to the configured provider cap.' });
  }
  return plans;
}

export interface SpendLimitsResult {
  dryRun: boolean;
  plans: SpendLimitPlan[];
  applied: string[];
  unavailable: SpendLimitAvailability[];
}

/** Callers must obtain human approval and supply fresh usage before dryRun: false. */
export async function applySpendLimits(input: SpendLimitsInput, ctx: ProviderContext,
  opts: { dryRun?: boolean } = {}): Promise<SpendLimitsResult> {
  // Validate every proposed limit before issuing the first mutation.
  const plans = planSpendLimits(input);
  const result: SpendLimitsResult = { dryRun: opts.dryRun !== false, plans, applied: [],
    unavailable: spendLimitAvailability(input.inventory).filter(entry => !entry.available) };
  if (!result.dryRun) {
    for (const plan of plans) {
      await openrouterProvider.setLimit(plan.keyRef, plan.limitUsd, ctx);
      result.applied.push(plan.clusterId);
    }
  }
  return result;
}
