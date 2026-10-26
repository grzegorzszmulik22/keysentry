import { randomUUID } from 'node:crypto';
import { fingerprint } from '../../core/fingerprint.js';
import type { Signal, UsageSample } from '../../types.js';
import { findProvider, now, resolveClusterKeyRef, type DetectorContext } from '../context.js';
import { usageKey, type UsageBucket } from '../state.js';

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

export interface UsageOptions {
  floorUsd?: number;
  /** Budgets can be keyed by inventory cluster id or by usageKey(provider, keyRef). */
  hourlyBudgets?: Record<string, number>;
}

function amount(value: number | undefined): number {
  if (value === undefined) return 0;
  if (!Number.isFinite(value) || value < 0) throw new Error('Invalid usage counter.');
  return value;
}

function quantile(sorted: number[], fraction: number): number {
  if (sorted.length === 0) return 0;
  return sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)]!;
}

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle]! : (sorted[middle - 1]! + sorted[middle]!) / 2;
}

/** Model labels are untrusted provider data; retain only keyed identifiers on disk. */
function models(sample: UsageSample, ctx: DetectorContext): Record<string, number> {
  const result: Record<string, number> = {};
  for (const [model, cost] of Object.entries(sample.byModel ?? {})) {
    result[fingerprint(model, ctx.fingerprintKey)] = amount(cost);
  }
  return result;
}

function addModels(target: Record<string, number>, incoming: Record<string, number>): void {
  for (const [model, cost] of Object.entries(incoming)) target[model] = (target[model] ?? 0) + cost;
}

export async function detectUsage(ctx: DetectorContext, opts: UsageOptions = {}): Promise<Signal[]> {
  const signals: Signal[] = [];
  const at = now(ctx);
  const timestamp = at.toISOString();
  const hour = new Date(Math.floor(at.getTime() / HOUR) * HOUR).toISOString();
  const floor = amount(opts.floorUsd ?? 2);

  for (const cluster of ctx.inventory.clusters) {
    const provider = findProvider(ctx, cluster.provider);
    if (!provider?.usage) continue;
    try {
      const ref = await resolveClusterKeyRef(cluster, ctx);
      if (!ref) continue;
      const key = usageKey(provider.id, ref);
      // Window reporters give an hour-to-date snapshot, not a delta. Cumulative
      // reporters ignore this window and are diffed against the previous poll.
      const from = new Date(hour);
      const to = at.getTime() > from.getTime() ? at : new Date(at.getTime() + 1);
      const sample = await provider.usage(ref, { from, to }, ctx.providerCtx);
      if (sample.keyRef !== ref) throw new Error('Usage key reference mismatch.');
      let costUsd = amount(sample.costUsd);
      let requests = sample.requests === undefined ? undefined : amount(sample.requests);
      let byModel = models(sample, ctx);
      let history = (ctx.state.usageHistory[key] ?? [])
        .filter(bucket => Date.parse(bucket.hour) >= at.getTime() - 30 * DAY && bucket.hour <= hour);

      const cumulative = sample.cumulativeCostUsd !== undefined;
      if (cumulative) {
        const total = amount(sample.cumulativeCostUsd);
        const previous = ctx.state.cumulativeTotals[key];
        const reset = previous !== undefined && total < previous.costUsd;
        if (reset) history = [];
        costUsd = previous && !reset ? total - previous.costUsd : 0;
        requests = requests === undefined ? undefined
          : previous?.requests !== undefined && !reset ? Math.max(0, requests - previous.requests) : 0;
        const currentModels = byModel;
        byModel = {};
        if (previous && !reset) {
          for (const [model, cost] of Object.entries(currentModels)) {
            byModel[model] = Math.max(0, cost - (previous.byModel?.[model] ?? 0));
          }
        }
        ctx.state.cumulativeTotals[key] = {
          costUsd: total, at: timestamp,
          ...(sample.requests !== undefined ? { requests: amount(sample.requests) } : {}),
          ...(sample.byModel !== undefined ? { byModel: currentModels } : {}),
        };
      }

      const past = history.filter(bucket => bucket.hour < hour);
      const previousHour = history.find(bucket => bucket.hour === hour);
      const bucket: UsageBucket = {
        hour, costUsd: cumulative ? (previousHour?.costUsd ?? 0) + costUsd : costUsd,
        ...(requests !== undefined ? { requests: cumulative ? (previousHour?.requests ?? 0) + requests : requests } : {}),
        byModel: cumulative ? { ...(previousHour?.byModel ?? {}) } : { ...byModel },
      };
      if (cumulative) addModels(bucket.byModel!, byModel);
      history = [...past, bucket].sort((a, b) => a.hour.localeCompare(b.hour));
      ctx.state.usageHistory[key] = history;

      const baselineBuckets = past.filter(entry => Date.parse(entry.hour) >= at.getTime() - 7 * DAY);
      const costs = baselineBuckets.map(entry => entry.costUsd);
      const baseline = median(costs);
      const mad = median(costs.map(cost => Math.abs(cost - baseline)));
      const p95 = quantile([...costs].sort((a, b) => a - b), 0.95);
      const threshold = costs.length < 24 ? floor : Math.max(floor, baseline + 8 * mad, 5 * p95);
      const budget = opts.hourlyBudgets?.[cluster.id] ?? opts.hourlyBudgets?.[key];
      const exceededBudget = budget !== undefined && bucket.costUsd > amount(budget);
      const anomalousSpend = bucket.costUsd > threshold;
      const knownModels = new Set(past.flatMap(entry => Object.keys(entry.byModel ?? {})));
      const newModels = Object.entries(bucket.byModel ?? {})
        .filter(([model, cost]) => cost > 1 && !knownModels.has(model));
      if (!anomalousSpend && !exceededBudget && newModels.length === 0) continue;

      const confidence = exceededBudget || (anomalousSpend && costs.length >= 24 && bucket.costUsd > 20 * baseline)
        ? 'high' : 'medium';
      signals.push({
        id: `usage-${randomUUID()}`, kind: 'usage_anomaly', at: timestamp, confidence,
        clusterIds: [cluster.id],
        summary: exceededBudget ? 'Hourly usage exceeded its configured budget.'
          : anomalousSpend ? 'Hourly usage exceeded its normal spending threshold.' : 'A previously unseen model incurred significant usage.',
        evidence: { costUsd: bucket.costUsd, baselineUsd: baseline, thresholdUsd: threshold,
          baselineHours: costs.length, newModelCount: newModels.length,
          ...(budget !== undefined ? { hourlyBudgetUsd: budget } : {}) },
      });
    } catch {
      // Provider diagnostics can include credentials or returned bodies.
      ctx.log.warn('Unable to check usage for a monitored cluster.');
    }
  }
  return signals;
}
