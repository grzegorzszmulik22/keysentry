import { XMLParser, XMLValidator } from 'fast-xml-parser';

export interface FeedItem {
  id: string;
  title: string;
  link: string | null;
  publishedAt: string | null;
  summary: string;
}

type XmlNode = Record<string, unknown>;
// Preserve field boundaries for the existing advisory detector without persisting extra feed text.
const textFields = new WeakMap<FeedItem, readonly string[]>();
const MAX_XML_BYTES = 16 * 1024 * 1024;

function decodeEntities(value: string): string {
  const named: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
  // Consume nested ampersand encodings in one pass rather than repeatedly decoding the whole string.
  return value.replace(/&(?:amp;|#(?:0{0,5}38|x0{0,4}26);)*(#x[0-9a-f]{1,6}|#[0-9]{1,7}|amp|lt|gt|quot|apos|nbsp);/gi, (match, entity: string) => {
    if (!entity.startsWith('#')) return named[entity.toLowerCase()] ?? match;
    const point = entity[1]?.toLowerCase() === 'x' ? Number.parseInt(entity.slice(2), 16) : Number.parseInt(entity.slice(1), 10);
    return point <= 0x10ffff && !(point >= 0xd800 && point <= 0xdfff) ? String.fromCodePoint(point) : '';
  });
}

/** Feed text is untrusted even when it arrives from a configured official source. */
export function sanitizeFeedText(value: string, maxLength: number): string {
  return decodeEntities(value)
    // Excluding both delimiters keeps an unterminated sequence of '<' characters linear to scan.
    .replace(/<[^<>]*>/g, ' ')
    .replace(/[<>]/g, ' ')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/\s+/g, ' ').trim().slice(0, maxLength);
}

/** Individual text fields prevent matching an advisory phrase invented across adjacent fields. */
export function feedItemTexts(item: FeedItem): readonly string[] {
  return textFields.get(item) ?? [item.title, item.summary];
}

function nodes(value: unknown): XmlNode[] {
  return Array.isArray(value) ? value.filter((part): part is XmlNode => part !== null && typeof part === 'object' && !Array.isArray(part)) : [];
}

function children(parent: XmlNode[], tag: string): XmlNode[] {
  return parent.filter(node => Object.hasOwn(node, tag));
}

function contents(node: XmlNode, tag: string): XmlNode[] {
  return nodes(node[tag]);
}

function content(value: unknown): string {
  return nodes(value).map(node => Object.entries(node).filter(([key]) => key !== ':@').map(([key, child]) => {
    if (key === '#text') return typeof child === 'string' || typeof child === 'number' ? String(child) : '';
    // Tag boundaries separate words; adjacent text and CDATA concatenate in document order.
    return ` ${content(child)} `;
  }).join('')).join('');
}

function field(item: XmlNode[], tag: string): string {
  return children(item, tag).map(node => content(node[tag])).join(' ').trim();
}

function link(item: XmlNode[]): string | null {
  const links = children(item, 'link');
  const attributes = (node: XmlNode): Record<string, unknown> => node[':@'] as Record<string, unknown> | undefined ?? {};
  const selected = links.find(node => attributes(node)['@_rel'] === undefined || attributes(node)['@_rel'] === 'alternate') ?? links[0];
  if (!selected) return null;
  const href = attributes(selected)['@_href'];
  const value = typeof href === 'string' ? href.trim() : content(selected.link).trim();
  return value ? decodeEntities(value) : null;
}

function publishedAt(item: XmlNode[]): string | null {
  let latest: number | undefined;
  for (const tag of ['pubDate', 'published', 'updated', 'date']) {
    for (const node of children(item, tag)) {
      // Some official RSS feeds use two-digit RFC years; interpret all of these as 20xx.
      const date = content(node[tag]).trim().replace(/(\b\d{1,2}\s+[A-Za-z]{3}\s+)(\d{2})(?=\s)/, '$120$2');
      const timestamp = Date.parse(date);
      if (Number.isFinite(timestamp) && (latest === undefined || timestamp > latest)) latest = timestamp;
    }
  }
  return latest === undefined ? null : new Date(latest).toISOString();
}

/** Parse size-limited RSS 2.0 or Atom without DTD/entity expansion or parser diagnostics in errors. */
export function parseFeed(xml: string): FeedItem[] {
  try {
    if (xml.length > MAX_XML_BYTES || Buffer.byteLength(xml, 'utf8') > MAX_XML_BYTES
      || /<!DOCTYPE|<!ENTITY/i.test(xml) || XMLValidator.validate(xml) !== true) throw new Error();
    const document = nodes(new XMLParser({ preserveOrder: true, ignoreAttributes: false, removeNSPrefix: true,
      processEntities: false, parseTagValue: false, trimValues: false, maxNestedTags: 100 }).parse(xml));
    const rss = children(document, 'rss')[0];
    const channel = rss && children(contents(rss, 'rss'), 'channel')[0];
    const atom = children(document, 'feed')[0];
    if (!channel && !atom) throw new Error();
    const rawItems = [...(channel ? children(contents(channel, 'channel'), 'item').map(node => contents(node, 'item')) : []),
      ...(atom ? children(contents(atom, 'feed'), 'entry').map(node => contents(node, 'entry')) : [])];
    const items: FeedItem[] = [];
    for (const raw of rawItems) {
      const itemLink = link(raw);
      const id = itemLink || field(raw, 'guid') || field(raw, 'id');
      if (!id) continue;
      const title = sanitizeFeedText(field(raw, 'title'), 300);
      const bodies = ['description', 'summary', 'content', 'encoded'].map(tag => sanitizeFeedText(field(raw, tag), 600)).filter(Boolean);
      const item: FeedItem = { id, title, link: itemLink, publishedAt: publishedAt(raw), summary: bodies.join(' ').slice(0, 600) };
      textFields.set(item, Object.freeze([title, ...bodies]));
      items.push(item);
    }
    return items;
  } catch {
    throw new Error('Unable to read feed XML.');
  }
}
