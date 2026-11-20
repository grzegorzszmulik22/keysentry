import { describe, expect, test } from 'vitest';
import { fetchFeed } from '../../src/feeds/index.js';
import type { FeedSource } from '../../src/types.js';
import { FakeHttp, text } from '../helpers/fake-http.js';

const source: FeedSource = { id: 'outlet', kind: 'news', url: 'https://example.com/feed', hosts: ['railway'], outlet: 'Example News', owner: 'Example Publisher' };
const rss = (body = '') => `<rss><channel>${body}</channel></rss>`;

describe('fetchFeed', () => {
  test('sends conditional headers, descriptive user agent and returns cache validators', async () => {
    const http = new FakeHttp().on('GET', /^https:\/\/example.com\/feed$/, () => text(200, rss(), { ETag: '"new"', 'Last-Modified': 'Mon, 26 Oct 2026 12:00:00 GMT' }));
    const result = await fetchFeed(http, source, { etag: '"old"', lastModified: 'Sun, 25 Oct 2026 12:00:00 GMT' });
    expect(result).toEqual({ status: 'ok', items: [], etag: '"new"', lastModified: 'Mon, 26 Oct 2026 12:00:00 GMT' });
    expect(http.calls[0]?.headers).toMatchObject({ 'If-None-Match': '"old"', 'If-Modified-Since': 'Sun, 25 Oct 2026 12:00:00 GMT' });
    expect(http.calls[0]?.headers?.['User-Agent']).toMatch(/^keysentry\/[^\s]+ \(\+https:\/\/github.com\/grzegorzszmulik22\/keysentry\)$/);
  });

  test('handles 304 without parsing a body and preserves cached validators', async () => {
    const http = new FakeHttp().on('GET', /./, () => text(304, 'not xml'));
    expect(await fetchFeed(http, source, { etag: '"old"', lastModified: 'yesterday' })).toEqual({ status: 'not-modified', items: [], etag: '"old"', lastModified: 'yesterday' });
  });

  test.each([200, 201, 206])('treats %i HTML content-type as XML when its body is a feed', async status => {
    const http = new FakeHttp().on('GET', /./, () => text(status, rss('<item><guid>one</guid><title>Railway update</title></item>'), { 'content-type': 'text/html' }));
    expect((await fetchFeed(http, source, {})).items[0]?.title).toBe('Railway update');
  });

  test('keeps only items within linkPrefix', async () => {
    const http = new FakeHttp().on('GET', /./, () => text(200, rss('<item><link>https://vercel.com/kb/bulletin/incident</link></item><item><link>https://vercel.com/kb/guide</link></item><item><guid>urn:no-link</guid></item>')));
    const result = await fetchFeed(http, { ...source, linkPrefix: 'https://vercel.com/kb/bulletin/' }, {});
    expect(result.items.map(entry => entry.link)).toEqual(['https://vercel.com/kb/bulletin/incident']);
  });

  test('rejects oversized bodies using UTF-8 bytes before parsing even without content-length', async () => {
    const http = new FakeHttp().on('GET', /./, () => text(200, 'é'.repeat(60)));
    await expect(fetchFeed(http, { ...source, maxBytes: 100 }, {})).rejects.toThrow('Feed from Example News exceeds the 100 byte limit.');
  });

  test('accepts a body exactly at its byte limit', async () => {
    const body = rss();
    const http = new FakeHttp().on('GET', /./, () => text(200, body));
    expect((await fetchFeed(http, { ...source, maxBytes: Buffer.byteLength(body) }, {})).status).toBe('ok');
  });

  test('rejects the default limit above 8 MiB', async () => {
    const http = new FakeHttp().on('GET', /./, () => text(200, 'x'.repeat(8 * 1024 * 1024 + 1)));
    await expect(fetchFeed(http, source, {})).rejects.toThrow('Example News');
  });

  test('HTTP and malformed body errors name only the outlet without response content or URL', async () => {
    for (const response of [text(503, 'private-response-body'), text(200, '<broken>private-response-body')]) {
      const http = new FakeHttp().on('GET', /./, () => response);
      const error = await fetchFeed(http, source, {}).catch(error => error as Error);
      expect(error.message).toContain('Example News');
      expect(error.message).not.toMatch(/private-response-body|example\.com/);
    }
  });

  test('transport failures do not reflect arbitrary error content', async () => {
    const http = new FakeHttp().on('GET', /./, () => { throw new Error('private-transport-detail'); });
    await expect(fetchFeed(http, source, {})).rejects.toThrow('Unable to fetch the feed from Example News.');
  });
});
