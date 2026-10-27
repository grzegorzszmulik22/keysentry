import type { HttpClient } from '../types.js';

const DAY_MS = 86_400_000;
const PROCESS_STARTED_AT = new Date();

export interface SelfCheckInput {
  /** Legacy field; callers must supply only external deliveries here. Prefer lastExternalSuccessAt. */
  lastNotifySuccessAt?: string | null;
  /** Console output never satisfies the notification check. Explicit null overrides legacy history. */
  lastExternalSuccessAt?: string | null;
  now: Date;
  stateWritable: boolean;
  armedValid: boolean;
  clockSkewSeconds?: number;
  /** Preserve this across ticks. Supply the original runtime start, not the current tick time. */
  startedAt?: Date;
}

export interface SelfCheckResult { ok: boolean; reasons: string[] }

export function selfCheck(input: SelfCheckInput): SelfCheckResult {
  const reasons: string[] = [];
  const now = input.now.getTime();
  const delivered = input.lastExternalSuccessAt !== undefined ? input.lastExternalSuccessAt : input.lastNotifySuccessAt ?? null;
  const last = delivered === null
    ? (input.startedAt ?? PROCESS_STARTED_AT).getTime() : Date.parse(delivered);
  if (!Number.isFinite(now) || !Number.isFinite(last) || last > now) {
    reasons.push('The watcher clock or notification timestamp needs checking.');
  } else if (now - last >= DAY_MS) {
    reasons.push('No notification has succeeded in the last 24 hours.');
  }
  if (!input.stateWritable) reasons.push('The watcher state directory is not writable.');
  if (!input.armedValid) reasons.push('The armed plan is not valid for automatic actions.');
  if (input.clockSkewSeconds !== undefined
    && (!Number.isFinite(input.clockSkewSeconds) || Math.abs(input.clockSkewSeconds) > 300)) {
    reasons.push('The watcher clock differs from the last HTTP response by more than five minutes.');
  }
  return { ok: reasons.length === 0, reasons };
}

/** Calendar heartbeat, with a 24-hour delivery fallback. Failed sends must not update lastHeartbeatAt. */
export function heartbeatDue(input: {
  startedAt: Date; lastNotifySuccessAt: string | null; lastHeartbeatAt: string | null; now: Date;
}): boolean {
  const now = input.now.getTime();
  const last = input.lastNotifySuccessAt === null ? input.startedAt.getTime() : Date.parse(input.lastNotifySuccessAt);
  const previous = input.lastHeartbeatAt === null ? input.startedAt.getTime() : Date.parse(input.lastHeartbeatAt);
  if (![now, last, previous].every(Number.isFinite)) return true;
  if (now - last >= DAY_MS) return true;
  const next = new Date(previous);
  next.setUTCHours(9, 0, 0, 0);
  if (next.getTime() <= previous) next.setUTCDate(next.getUTCDate() + 1);
  return now >= next.getTime();
}

/** Wrap the already guarded client; this observes responses and never performs a separate clock request. */
export function trackHttpClock(http: HttpClient, now: () => Date = () => new Date()): {
  http: HttpClient; clockSkewSeconds(): number | undefined;
} {
  let skew: number | undefined;
  return {
    http: {
      async request(request) {
        const response = await http.request(request);
        const date = Object.entries(response.headers).find(([name]) => name.toLowerCase() === 'date')?.[1];
        const remote = date === undefined ? NaN : Date.parse(date);
        // Compare clocks at receipt time. Reusing a stale server timestamp later would invent clock skew.
        // A response without clock evidence cannot clear a previously unsafe measurement.
        if (Number.isFinite(remote)) skew = (now().getTime() - remote) / 1_000;
        return response;
      },
    },
    clockSkewSeconds: () => skew,
  };
}
