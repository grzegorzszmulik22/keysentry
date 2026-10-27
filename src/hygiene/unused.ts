import type { UsageBucket } from '../monitor/state.js';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

/** Evidence that the supplied counters cover this entire interval, including between polls. */
export interface UsageCoverage { from: string; to: string }

/** Missing hours or missing request counters are unknown, never evidence of no use. */
export function unusedDays(history: readonly UsageBucket[], now: string | Date,
  coverage?: UsageCoverage): number | undefined {
  const timestamp = now instanceof Date ? now.getTime() : Date.parse(now);
  if (!Number.isFinite(timestamp)) throw new Error('Invalid hygiene date.');
  // Existing monitor buckets may be hour-to-date snapshots. Their presence does
  // not prove that requests later in those hours were observed.
  const coveredFrom = Date.parse(coverage?.from ?? '');
  const coveredTo = Date.parse(coverage?.to ?? '');
  if (!Number.isFinite(coveredFrom) || !Number.isFinite(coveredTo)
      || coveredFrom > timestamp || coveredTo < timestamp) return undefined;
  const currentHour = Math.floor(timestamp / HOUR) * HOUR;
  const hours = new Map<number, boolean>();
  for (const bucket of history) {
    const at = Date.parse(bucket.hour);
    if (!Number.isFinite(at) || at > currentHour || at % HOUR !== 0) continue;
    const zero = bucket.costUsd === 0 && bucket.requests === 0;
    // Conflicting observations must not let a later zero hide recorded usage.
    hours.set(at, (hours.get(at) ?? true) && zero);
  }
  let oldest = currentHour;
  if (hours.get(oldest) !== true) return undefined;
  while (hours.get(oldest - HOUR) === true) oldest -= HOUR;
  const days = Math.floor((timestamp - Math.max(oldest, coveredFrom)) / DAY);
  return days >= 30 ? days : undefined;
}
