import { XMLParser, XMLValidator } from 'fast-xml-parser';
import { fingerprint } from '../../core/fingerprint.js';
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
// General security words in tutorial bodies are common; only titles get these broader patterns.
const SECURITY_TITLE = /\b(?:security[\s-]+(?:incident|disclosure|advisory|notice|update)|(?:data[\s-]+)?breach|compromis(?:e|ed)|unauthori[sz]ed[\s-]+access|credentials?[\s-]+(?:leak|exposure))\b/i;
const SECURITY_PHRASE = /\b(?:rotate[\s-]+(?:all|your)[\s-]+(?:environment[\s-]+variables|secrets|keys|credentials)|unauthori[sz]ed[\s-]+(?:third[\s-]+party|access)|(?:may[\s-]+have|have[\s-]+been)[\s-]+(?:accessed|exposed|compromised))\b/i;
const HIGH_CONFIDENCE_TITLE = /\b(?:security[\s-]+(?:incident|disclosure)|breach)\b/i;
// Domain mentions may include subdomains or a sentence-ending period, but never another domain's label.
// Product names are case-sensitive and cannot match inside domain names or identifiers.
const HOST_MENTIONS: Record<HostId, RegExp[]> = {
  railway: [/(?<![\w-])railway\.(?:com|app)(?![\w-]|\.[\w-])/i, /(?<![\w.-])Railway(?![\w-]|\.[\w-])/],
  vercel: [/(?<![\w-])vercel\.com(?![\w-]|\.[\w-])/i, /(?<![\w.-])Vercel(?![\w-]|\.[\w-])/],
  render: [/(?<![\w-])render\.com(?![\w-]|\.[\w-])/i],
  fly: [/(?<![\w-])fly\.io(?![\w-]|\.[\w-])/i],
  'github-actions': [/(?<![\w-])github\.com(?![\w-]|\.[\w-])/i, /(?<![\w.-])GitHub(?![\w-]|\.[\w-])/],
  dotenv: [],
};

type Row = Record<string, unknown>;

function row(value: unknown): Row | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Row : undefined;
}

function array(value: unknown): unknown[] {
  return value === undefined ? [] : Array.isArray(value) ? value : [value];
}

function content(value: unknown): string {
  if (typeof value === 'string' || typeof value === 'number') return String(value).trim();
  if (Array.isArray(value)) return value.map(content).filter(Boolean).join(' ');
  const object = row(value);
  return object ? content([object['#text'], object['__cdata']]) : '';
}

function itemLink(item: Row): string {
  const links = array(item.link);
  const alternate = links.find(link => {
    const object = row(link);
    return object && (object['@_rel'] === undefined || object['@_rel'] === 'alternate');
  });
  const selected = alternate ?? links[0];
  return content(row(selected)?.['@_href']) || content(selected) || content(item.guid) || content(item.id);
}

function itemDate(item: Row): number | undefined {
  let latest: number | undefined;
  // removeNSPrefix maps dc:date to date. Prefer a recent update to an older publication date.
  for (const field of ['pubDate', 'published', 'updated', 'date']) {
    for (const value of array(item[field])) {
      const timestamp = Date.parse(content(value));
      if (Number.isFinite(timestamp) && (latest === undefined || timestamp > latest)) latest = timestamp;
    }
  }
  return latest;
}

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
      const response = await ctx.providerCtx.http.request({ method: 'GET', url: feed.url,
        headers: { Accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml' } });
      if (response.status < 200 || response.status >= 300 || Buffer.byteLength(response.text, 'utf8') > MAX_FEED_BYTES) throw new Error();
      if (XMLValidator.validate(response.text) !== true) throw new Error();
      // Concatenate CDATA in document order before trimming, preserving spaces within split phrases.
      const parsed = row(new XMLParser({ ignoreAttributes: false, removeNSPrefix: true,
        processEntities: false, parseTagValue: false, trimValues: false }).parse(response.text));
      const rss = row(parsed?.rss);
      const channel = row(rss?.channel);
      const atom = row(parsed?.feed);
      if (rss?.channel === undefined && parsed?.feed === undefined) throw new Error();
      const items = [...array(channel?.item), ...array(atom?.entry)];
      const feedId = fingerprint(feed.url, ctx.fingerprintKey);
      const baseline = !ctx.state.feedBaselines[feedId];
      for (const raw of items) {
        const item = row(raw);
        if (!item) continue;
        const link = itemLink(item);
        if (!link) continue;
        const itemId = fingerprint(link, ctx.fingerprintKey);
        if (baseline) {
          ctx.state.seenFeedItems[itemId] = at;
          continue;
        }
        if (seenBefore.has(itemId)) continue;
        const datedAt = itemDate(item);
        if (datedAt !== undefined && (datedAt < cutoff || datedAt >= nextDay)) continue;
        const [title = '', ...descriptions] = [item.title, item.description, item.summary, item.content, item['encoded']]
          .map(value => content(value).replace(/<[^>]*>/g, ' '));
        const texts = [title, ...descriptions];
        if (!SECURITY_TITLE.test(title) && !texts.some(text => SECURITY_PHRASE.test(text))) continue;
        const searchable = texts.join(' ');
        const hosts = ctx.inventory.hosts.filter(host => host === feed.host
          || HOST_MENTIONS[host].some(pattern => pattern.test(searchable)));
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
