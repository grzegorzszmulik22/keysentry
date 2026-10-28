import type { EgressRule, TeamPolicy } from '../types.js';

/**
 * Offline mode (phase 5): no breach feed or security news is polled. Provider and host APIs the user configured keep
 * working. The switch is applied where sources are chosen (selectFeedSources) and, as a backstop, by removing feed
 * destinations from the egress allow-list (offlineEgressRules), so a forgotten call site is blocked, not polled.
 */
export interface FeedMode {
  offline: boolean;
  /** Who turned offline mode on; null when feeds are polled. A signed policy wins over local configuration. */
  source: 'config' | 'policy' | null;
}

/** Pass only a policy whose signatures were verified; an unverifiable policy must stop the command before this. */
export function resolveFeedMode(input: { configOffline?: boolean; policy?: Pick<TeamPolicy, 'network'> | null }): FeedMode {
  if (input.policy?.network?.offline === true) return { offline: true, source: 'policy' };
  if (input.configOffline === true) return { offline: true, source: 'config' };
  return { offline: false, source: null };
}

/** Every polled list goes through here: watcher sources, monitor breach feeds and user-configured feeds. */
export function selectFeedSources<T>(sources: readonly T[], mode: FeedMode): T[] {
  return mode.offline ? [] : [...sources];
}

/** Purpose that rulesForUserFeeds gives user-configured feed hosts. */
const USER_FEED_PURPOSE = 'breach feed you configured';

/** Drop built-in feed destinations and user-configured feed hosts from the egress rules. */
export function offlineEgressRules<R extends EgressRule>(rules: readonly R[]): R[] {
  return rules.filter(rule => rule.owner !== 'feed' && !(rule.owner === 'user' && rule.purpose === USER_FEED_PURPOSE));
}

/** One calm paragraph for doctor, `watch` and the network receipt; null when feeds are polled. */
export function offlineNotice(mode: FeedMode): string | null {
  if (!mode.offline) return null;
  const who = mode.source === 'policy' ? 'The signed team policy turns on offline mode' : 'Offline mode is on in keysentry.yaml';
  return `${who}. keysentry does not poll breach feeds or security news, so a platform advisory or news report cannot`
    + ' start an autopilot wave or an alert. Provider and host APIs you configured still work, and automatic actions start'
    + ' only from your own signals: GitHub secret-scanning alerts, canary tokens, keys revoked upstream and usage anomalies.'
    + ' You can still rotate any key yourself.';
}
