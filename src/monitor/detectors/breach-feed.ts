import { fingerprint } from '../../core/fingerprint.js';
import { fetchFeed, feedItemTexts } from '../../feeds/index.js';
import { HIGH_CONFIDENCE_TITLE, isSecurityAdvisory, mentionsHost } from '../../autopilot/sources.js';
import type { HostId, Signal } from '../../types.js';
import { now, type DetectorContext } from '../context.js';

export interface BreachFeed {
  url: string;
  host?: HostId;
}

export interface BreachFeedOptions {
  /** Ignore dated items older than this many days after the baseline poll; defaults to 7. */
  maxAgeDays?: number;
}

/** Advisory RSS/Atom defaults verified live by the orchestrator on 26 Oct 2026. */
export const DEFAULT_BREACH_FEEDS: readonly BreachFeed[] = [
  { host: 'railway', url: 'https://blog.railway.com/rss.xml' },
  { host: 'railway', url: 'https://railway.com/changelog/rss.xml' },
  { host: 'vercel', url: 'https://vercel.com/atom' },
  { host: 'vercel', url: 'https://www.vercel-status.com/history.rss' },
  { host: 'render', url: 'https://render.com/blog/feed.xml' },
  { host: 'render', url: 'https://status.render.com/history.rss' },
  { host: 'fly', url: 'https://fly.io/blog/feed.xml' },
  { host: 'fly', url: 'https://status.flyio.net/history.rss' },
  { host: 'github-actions', url: 'https://github.blog/changelog/feed/' },
];

const MAX_FEED_BYTES = 16 * 1024 * 1024;

function safeFeedUrl(value: string, ctx: DetectorContext): boolean {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password) return false;
    const decoded = decodeURIComponent(value);
    return !Object.values(ctx.providerCtx.credentials).some(secret => !!secret && decoded.includes(secret));
  } catch {
    return false;
  }
}

/** Poll untrusted feed content, retaining only keyed item identifiers and fixed, secret-free signals. */
export async function detectBreachFeeds(
  ctx: DetectorContext,
  feeds: readonly BreachFeed[] = DEFAULT_BREACH_FEEDS,
  options: BreachFeedOptions = {},
): Promise<Signal[]> {
  const maxAgeDays = options.maxAgeDays ?? 7;
  if (!Number.isFinite(maxAgeDays) || maxAgeDays < 0) throw new Error('Feed maximum age must be nonnegative and finite.');
  const advisories = new Map<HostId, { itemIds: Set<string>; confidence: 'high' | 'medium' }>();
  // Items repeated in another feed during this poll can still contribute confidence and host attribution.
  const seenBefore = new Set(Object.keys(ctx.state.seenFeedItems));
  const polledAt = now(ctx);
  const at = polledAt.toISOString();
  const cutoff = polledAt.getTime() - maxAgeDays * 24 * 60 * 60 * 1000;
  // Feed publication times can run ahead within today's UTC date; later dates are not yet eligible.
  const nextDay = Date.UTC(polledAt.getUTCFullYear(), polledAt.getUTCMonth(), polledAt.getUTCDate() + 1);
  for (const feed of feeds) {
    try {
      if (!safeFeedUrl(feed.url, ctx)) throw new Error();
      const feedId = fingerprint(feed.url, ctx.fingerprintKey);
      const { items } = await fetchFeed(ctx.providerCtx.http, {
        id: feedId, kind: 'official', url: feed.url, hosts: feed.host ? [feed.host] : [],
        outlet: 'Configured advisory feed', owner: 'feed', maxBytes: MAX_FEED_BYTES,
      }, {});
      const baseline = !ctx.state.feedBaselines[feedId];
      for (const item of items) {
        const itemId = fingerprint(item.id, ctx.fingerprintKey);
        if (baseline) {
          ctx.state.seenFeedItems[itemId] = at;
          continue;
        }
        if (seenBefore.has(itemId)) continue;
        const datedAt = item.publishedAt === null ? undefined : Date.parse(item.publishedAt);
        if (datedAt !== undefined && (datedAt < cutoff || datedAt >= nextDay)) continue;
        const title = item.title;
        const texts = feedItemTexts(item);
        if (!isSecurityAdvisory(title, texts)) continue;
        const searchable = texts.join(' ');
        const hosts = ctx.inventory.hosts.filter(host => host === feed.host
          || mentionsHost(host, searchable));
        if (hosts.length === 0) continue;
        for (const host of hosts) {
          const advisory = advisories.get(host) ?? { itemIds: new Set<string>(), confidence: 'medium' };
          advisory.itemIds.add(itemId);
          if (host === feed.host && HIGH_CONFIDENCE_TITLE.test(title)) advisory.confidence = 'high';
          advisories.set(host, advisory);
        }
        ctx.state.seenFeedItems[itemId] = at;
      }
      if (baseline) ctx.state.feedBaselines[feedId] = at;
    } catch {
      // HTTP errors, XML diagnostics and titles may embed secrets: never relay their text.
      ctx.log.warn('Unable to poll a breach advisory feed.');
    }
  }
  return [...advisories].map(([host, advisory]) => {
    const itemIds = [...advisory.itemIds].sort();
    return {
      id: `feed-${fingerprint(JSON.stringify(itemIds), ctx.fingerprintKey)}-${host}`,
      kind: 'host_breach_advisory', at, confidence: advisory.confidence, host,
      clusterIds: ctx.inventory.clusters.filter(cluster => cluster.consumers.some(consumer => consumer.service.host === host))
        .map(cluster => cluster.id),
      summary: `A security advisory concerns ${host}; review the affected host.`,
      evidence: { itemIds, count: itemIds.length },
    };
  });
}
