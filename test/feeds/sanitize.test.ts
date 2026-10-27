import { describe, expect, test } from 'vitest';
import { classifyItem } from '../../src/autopilot/sources.js';
import { fingerprint } from '../../src/core/fingerprint.js';
import { feedItemTexts, parseFeed, sanitizeFeedText, type FeedItem } from '../../src/feeds/index.js';
import type { FeedSource } from '../../src/types.js';

const source: FeedSource = {
  id: 'sanitization-news', kind: 'news', url: 'https://example.invalid/feed', hosts: ['railway'],
  outlet: 'Test news', owner: 'Test publisher',
};
const itemKey = (id: string) => fingerprint(id, Buffer.alloc(32, 19));

describe('feed text normalization', () => {
  test('normalizes compatibility and decomposed characters before applying the length cap', () => {
    expect(sanitizeFeedText('\ufb03 \uff21 \u212a e\u0301', 300)).toBe('ffi A K \u00e9');
    expect(sanitizeFeedText('\ufb03 \uff21 extra', 5)).toBe('ffi A');
  });

  test('strips markup introduced by compatibility normalization', () => {
    expect(sanitizeFeedText('\uff1cb\uff1eRailway\uff1c/b\uff1e', 300)).toBe('Railway');
  });

  test('removes every Unicode format character inside words', () => {
    for (let point = 0; point <= 0x10ffff; point++) {
      const character = String.fromCodePoint(point);
      if (!/\p{Cf}/u.test(character)) continue;
      expect(sanitizeFeedText(`phi${character}shing no${character}t breached`, 300),
        `format character U+${point.toString(16).toUpperCase()}`).toBe('phishing not breached');
    }
  });

  test('normalizes parsed titles, summaries and preserved classification fields', () => {
    const [entry] = parseFeed('<rss><channel><item><guid>format-fields</guid>'
      + '<title>Railway phi\u200dshing</title><description>Was n\u200dot breached.</description>'
      + '<summary>\uff2e\uff4f customer secrets were exposed.</summary></item></channel></rss>');
    expect(entry).toMatchObject({ title: 'Railway phishing', summary: 'Was not breached. No customer secrets were exposed.' });
    expect(feedItemTexts(entry!)).toEqual(['Railway phishing', 'Was not breached.', 'No customer secrets were exposed.']);
  });
});

describe('normalized negative classification cues', () => {
  test.each([
    ['joiners inside phishing in the title', 'Railway phi\u200dshing campaign exposes API keys', 'Customer credentials were exposed.'],
    ['joiners inside phishing in the summary', 'Railway breach exposes API keys', 'Customer credentials were exposed in a phi\u200dshing campaign.'],
    ['joiners inside not breached', 'Railway breach exposes API keys', 'Railway was n\u200dot brea\u200dched. Customer credentials were exposed.'],
    ['fullwidth phishing', 'Railway breach exposes API keys', 'Customer credentials were exposed in a \uff50\uff48\uff49\uff53\uff48\uff49\uff4e\uff47 campaign.'],
    ['fullwidth not breached', 'Railway breach exposes API keys', 'Railway was \uff4e\uff4f\uff54 \uff42\uff52\uff45\uff41\uff43\uff48\uff45\uff44. Customer credentials were exposed.'],
  ])('%s cannot establish credential exposure', (_name, title, summary) => {
    const direct: FeedItem = {
      id: 'negative-cue', title, summary, link: null, publishedAt: '2026-10-27T12:00:00.000Z',
    };
    const [parsed] = parseFeed(`<rss><channel><item><guid>negative-cue</guid><title>${title}</title>`
      + `<description>${summary}</description><pubDate>2026-10-27T12:00:00Z</pubDate></item></channel></rss>`);
    for (const entry of [direct, parsed!]) {
      expect(classifyItem(entry, source, itemKey)).toMatchObject({ credentialExposure: false });
    }
  });
});
