import { XMLParser, XMLValidator } from 'fast-xml-parser';
import { fingerprint } from '../../core/fingerprint.js';
import type { HostId, Signal } from '../../types.js';
import { now, type DetectorContext } from '../context.js';

export interface BreachFeed {
  url: string;
  host?: HostId;
}

/** Advisory defaults, not verified live. Operators should check these URLs before enabling a daemon. */
export const DEFAULT_BREACH_FEEDS: readonly BreachFeed[] = [
  { host: 'railway', url: 'https://railway.com/changelog/rss.xml' },
  { host: 'vercel', url: 'https://vercel.com/atom' },
  { host: 'render', url: 'https://render.com/changelog/rss.xml' },
  { host: 'fly', url: 'https://fly.io/changelog/feed.xml' },
  { host: 'github-actions', url: 'https://github.blog/changelog/label/security/feed/' },
];

const SECURITY_WORDS = /security[\s-]+incident|unauthorized[\s-]+access|\bbreach\b|\bcompromised\b|\brotate\b|environment[\s-]+variables/i;
const HOST_MENTIONS: Record<HostId, RegExp> = {
  railway: /\brailway\b/i,
  vercel: /\bvercel\b/i,
  render: /\brender\b/i,
  fly: /\bfly(?:\.io)?\b/i,
  'github-actions': /\bgithub\b/i,
  dotenv: /\bdotenv\b/i,
};

type Row = Record<string, unknown>;

function row(value: unknown): Row | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Row : undefined;
}

function array(value: unknown): unknown[] {
  return value === undefined ? [] : Array.isArray(value) ? value : [value];
}

function content(value: unknown): string {
  if (typeof value === 'string' || typeof value === 'number') return String(value);
  const object = row(value);
  return object ? content(object['#text'] ?? object['__cdata']) : '';
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
): Promise<Signal[]> {
  const signals: Signal[] = [];
  const at = now(ctx).toISOString();
  for (const feed of feeds) {
    try {
      if (!safeFeedUrl(feed.url, ctx)) throw new Error();
      const response = await ctx.providerCtx.http.request({ method: 'GET', url: feed.url,
        headers: { Accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml' } });
      if (response.status < 200 || response.status >= 300 || response.text.length > 2_000_000) throw new Error();
      if (XMLValidator.validate(response.text) !== true) throw new Error();
      const parsed = row(new XMLParser({ ignoreAttributes: false, removeNSPrefix: true,
        processEntities: false, parseTagValue: false }).parse(response.text));
      const rss = row(parsed?.rss);
      const channel = row(rss?.channel);
      const atom = row(parsed?.feed);
      const items = [...array(channel?.item), ...array(atom?.entry)];
      for (const raw of items) {
        const item = row(raw);
        if (!item) continue;
        const link = itemLink(item);
        if (!link) continue;
        const itemId = fingerprint(link, ctx.fingerprintKey);
        if (ctx.state.seenFeedItems[itemId]) continue;
        const searchable = [item.title, item.description, item.summary, item.content, item['encoded']]
          .map(content).join(' ').replace(/<[^>]*>/g, ' ');
        if (!SECURITY_WORDS.test(searchable)) continue;
        const hosts = ctx.inventory.hosts.filter(host => HOST_MENTIONS[host].test(searchable));
        if (hosts.length === 0) continue;
        for (const host of hosts) {
          signals.push({
            id: `feed-${itemId}-${host}`,
            kind: 'host_breach_advisory', at, confidence: 'medium', host,
            clusterIds: ctx.inventory.clusters.filter(cluster => cluster.consumers.some(consumer => consumer.service.host === host))
              .map(cluster => cluster.id),
            summary: `A security advisory mentions ${host}; review the affected host.`,
            evidence: { itemId },
          });
        }
        ctx.state.seenFeedItems[itemId] = at;
      }
    } catch {
      // HTTP errors, XML diagnostics and titles may embed secrets: never relay their text.
      ctx.log.warn('Unable to poll a breach advisory feed.');
    }
  }
  return signals;
}
