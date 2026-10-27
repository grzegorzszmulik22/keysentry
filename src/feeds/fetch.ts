import type { FeedSource, HttpClient } from '../types.js';
import { BUILD_VERSION, RELEASE_REPO } from '../release/build-info.js';
import { createRedactor } from '../core/redact.js';
import { parseFeed, sanitizeFeedText, type FeedItem } from './parse.js';

export interface FeedCache { etag?: string; lastModified?: string }
export interface FeedResult extends FeedCache { status: 'ok' | 'not-modified'; items: FeedItem[] }

/** Conditional, size-capped feed reads; redirects and the upstream 16 MiB cap belong to HttpClient. */
export async function fetchFeed(http: HttpClient, source: FeedSource, cache: FeedCache): Promise<FeedResult> {
  const outlet = createRedactor().redact(sanitizeFeedText(source.outlet, 120));
  const maxBytes = source.maxBytes ?? 8 * 1024 * 1024;
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) throw new Error(`The feed size limit for ${outlet} must be a positive integer.`);
  let response;
  try {
    response = await http.request({ method: 'GET', url: source.url, headers: {
      Accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml',
      'User-Agent': `keysentry/${BUILD_VERSION} (+https://github.com/${RELEASE_REPO})`,
      ...(cache.etag ? { 'If-None-Match': cache.etag } : {}),
      ...(cache.lastModified ? { 'If-Modified-Since': cache.lastModified } : {}),
    } });
  } catch {
    throw new Error(`Unable to fetch the feed from ${outlet}.`);
  }
  const headers = Object.fromEntries(Object.entries(response.headers).map(([key, value]) => [key.toLowerCase(), value]));
  const validators = { etag: headers.etag, lastModified: headers['last-modified'] };
  if (response.status === 304) return { status: 'not-modified', items: [], etag: validators.etag ?? cache.etag,
    lastModified: validators.lastModified ?? cache.lastModified };
  if (response.status < 200 || response.status >= 300) throw new Error(`Unable to fetch the feed from ${outlet} (HTTP ${response.status}).`);
  // HttpResponse has a materialized body; reject its size before parsing, independent of Content-Type/Length.
  if (response.text.length > maxBytes || Buffer.byteLength(response.text, 'utf8') > maxBytes) {
    throw new Error(`Feed from ${outlet} exceeds the ${maxBytes} byte limit.`);
  }
  let items: FeedItem[];
  try { items = parseFeed(response.text); }
  catch { throw new Error(`Unable to read the feed from ${outlet}.`); }
  if (source.linkPrefix !== undefined) items = items.filter(item => item.link?.startsWith(source.linkPrefix!));
  return { status: 'ok', items, ...validators };
}
