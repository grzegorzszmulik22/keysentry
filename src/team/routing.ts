// Per-member notification routing. Channels assigned to members receive only messages at or above the lowest
// minSeverity among those members; channels assigned to nobody receive everything (the single-user behaviour).
import { createDispatcher, type DispatcherOptions } from '../notify/dispatch.js';
import type { NotifyChannel, NotifyMessage, NotifySeverity, SignedNotifyMessage, TeamRoster } from '../types.js';

const SEVERITY_RANK: Readonly<Record<NotifySeverity, number>> = { info: 0, warning: 1, urgent: 2 };

function rank(severity: unknown): number {
  // An unknown severity is treated as urgent so it is never silently dropped.
  return typeof severity === 'string' && Object.hasOwn(SEVERITY_RANK, severity) ? SEVERITY_RANK[severity as NotifySeverity] : SEVERITY_RANK.urgent;
}

/** The channel ids (in the given order) that `message` goes to. */
export function routeChannels(roster: TeamRoster | null | undefined, channelIds: readonly string[], message: Pick<NotifyMessage, 'severity'>): string[] {
  if (!roster) return [...channelIds];
  const lowest = new Map<string, number>();
  for (const member of roster.members) {
    if (!member.notify) continue;
    for (const channel of member.notify.channels) {
      const value = rank(member.notify.minSeverity);
      lowest.set(channel, Math.min(lowest.get(channel) ?? Number.POSITIVE_INFINITY, value));
    }
  }
  const severity = rank(message.severity);
  return channelIds.filter(id => !lowest.has(id) || severity >= lowest.get(id)!);
}

export interface RoutedSendResult {
  delivered: string[];
  failed: { id: string; reason: string }[];
  /** Channels this message was not routed to. When every channel is skipped, nothing was expected to deliver. */
  skipped: string[];
}

/**
 * Same surface as `createDispatcher`, routed per message. One inner dispatcher per channel keeps retries, failure
 * reasons and success timestamps exactly as today.
 */
export function createRoutedDispatcher(channels: NotifyChannel[], roster: TeamRoster | null | (() => TeamRoster | null), opts: DispatcherOptions) {
  if (new Set(channels.map(channel => channel.id)).size !== channels.length) throw new Error('Invalid notification dispatcher configuration');
  const inner = new Map(channels.map(channel => [channel.id, createDispatcher([channel], opts)] as const));
  const current = typeof roster === 'function' ? roster : () => roster;
  const latest = (pick: (dispatcher: ReturnType<typeof createDispatcher>) => string | null): string | null =>
    [...inner.values()].map(pick).filter((value): value is string => value !== null).sort().at(-1) ?? null;
  return {
    lastSuccessAt: (): string | null => latest(dispatcher => dispatcher.lastSuccessAt()),
    lastExternalSuccessAt: (): string | null => latest(dispatcher => dispatcher.lastExternalSuccessAt()),
    async send(m: SignedNotifyMessage): Promise<RoutedSendResult> {
      const ids = channels.map(channel => channel.id);
      const routed = new Set(routeChannels(current(), ids, m));
      const results = await Promise.all(ids.filter(id => routed.has(id)).map(id => inner.get(id)!.send(m)));
      return {
        delivered: results.flatMap(result => result.delivered),
        failed: results.flatMap(result => result.failed),
        skipped: ids.filter(id => !routed.has(id)),
      };
    },
  };
}
