import type { Logger, NotifyChannel, SignedNotifyMessage } from '../types.js';
import { CHANNEL_LABELS, NotifyDeliveryError } from './message.js';

export interface DispatcherOptions {
  log: Logger;
  now?: () => Date;
  /** Total attempts per channel, including the first send. */
  retries?: number;
  sleep?: (ms: number) => Promise<void>;
}

export function createDispatcher(channels: NotifyChannel[], opts: DispatcherOptions) {
  const attempts = opts.retries ?? 3;
  if (!Number.isInteger(attempts) || attempts < 1 || new Set(channels.map(channel => channel.id)).size !== channels.length) throw new Error('Invalid notification dispatcher configuration');
  const now = opts.now ?? (() => new Date());
  const sleep = opts.sleep ?? (ms => new Promise<void>(resolve => setTimeout(resolve, ms)));
  let last: string | null = null;
  return {
    lastSuccessAt: (): string | null => last,
    async send(m: SignedNotifyMessage): Promise<{ delivered: string[]; failed: { id: string; reason: string }[] }> {
      const results = await Promise.all(channels.map(async channel => {
        let reason = `${CHANNEL_LABELS[channel.kind]} delivery failed`;
        for (let attempt = 0; attempt < attempts; attempt++) {
          try {
            await channel.send(m);
            last = now().toISOString();
            return { id: channel.id, ok: true as const };
          } catch (error) {
            // Never trust an exception's message, including custom channel implementations.
            const safe = error instanceof NotifyDeliveryError && error.channel === channel.kind ? error : undefined;
            const status = safe?.status;
            reason = typeof status === 'number' && Number.isInteger(status) && status >= 100 && status <= 599
              ? `${CHANNEL_LABELS[channel.kind]} returned ${status}` : `${CHANNEL_LABELS[channel.kind]} delivery failed`;
            const retryAfter = safe?.retryAfterMs;
            const delay = typeof retryAfter === 'number' && Number.isFinite(retryAfter) && retryAfter >= 0 ? retryAfter : 1000 * 2 ** attempt;
            if (attempt + 1 < attempts) await sleep(Math.min(60_000, delay));
          }
        }
        // Channel ids are returned to the local caller, but are not logged: callers may use addresses as ids.
        try { opts.log.warn(reason); } catch { /* Logging must not block other notification results. */ }
        return { id: channel.id, ok: false as const, reason };
      }));
      return { delivered: results.filter(r => r.ok).map(r => r.id), failed: results.filter(r => !r.ok).map(r => ({ id: r.id, reason: r.reason })) };
    },
  };
}
