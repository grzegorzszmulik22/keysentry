import { readFile } from 'node:fs/promises';
import { describe, expect, test } from 'vitest';
import { feedItemTexts, parseFeed, sanitizeFeedText } from '../../src/feeds/index.js';

const rss = (items = '') => `<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/"><channel>${items}</channel></rss>`;
const item = (body: string) => `<item>${body}</item>`;

describe('parseFeed', () => {
  test('reads RSS, two-digit years, entities and strips markup', () => {
    expect(parseFeed(rss(item('<guid>urn:post:1</guid><title><![CDATA[<b>Railway</b> &amp; security]]></title><pubDate>Mon, 26 Oct 26 12:00:00 +0000</pubDate><description><![CDATA[<p>Customer secrets&#32;were exposed.</p>]]></description>')))).toEqual([{
      id: 'urn:post:1', title: 'Railway & security', link: null,
      publishedAt: '2026-10-26T12:00:00.000Z', summary: 'Customer secrets were exposed.',
    }]);
  });

  test('reads namespaced Atom entries and prefers alternate links', () => {
    expect(parseFeed('<atom:feed xmlns:atom="http://www.w3.org/2005/Atom"><atom:entry><atom:id>urn:1</atom:id><atom:title>Vercel security incident</atom:title><atom:link rel="self" href="https://example.com/self"/><atom:link rel="alternate" href="https://example.com/post"/><atom:summary>Details</atom:summary><atom:published>2026-10-20T00:00:00Z</atom:published><atom:updated>2026-10-26T12:00:00Z</atom:updated></atom:entry></atom:feed>')).toEqual([{
      id: 'https://example.com/post', title: 'Vercel security incident', link: 'https://example.com/post',
      publishedAt: '2026-10-26T12:00:00.000Z', summary: 'Details',
    }]);
  });

  test('keeps mixed text, CDATA and nested markup in document order', () => {
    const [entry] = parseFeed(rss(item('<guid>mixed</guid><title>Update: <![CDATA[Security]]><![CDATA[ Disclosure]]> <b>today</b></title>')));
    expect(entry?.title).toBe('Update: Security Disclosure today');
  });

  test('removes control and bidi characters and caps untrusted text', () => {
    const [entry] = parseFeed(rss(item(`<guid>caps</guid><title><![CDATA[<b>A\u202e\u2066\u0001</b> ${'t'.repeat(350)}]]></title><description><![CDATA[<p> x\u202a\u2069\u0007 \n y ${'s'.repeat(650)}</p>]]></description>`)));
    expect(entry?.title).toHaveLength(300);
    expect(entry?.title.startsWith('A ')).toBe(true);
    expect(entry?.summary).toHaveLength(600);
    expect(entry?.summary.startsWith('x y ')).toBe(true);
    expect(JSON.stringify(entry)).not.toMatch(/[\u0000-\u001f\u202a-\u202e\u2066-\u2069]/);
  });

  test('removes a large unterminated markup title before storing it', () => {
    const [entry] = parseFeed(rss(item(`<guid>unfinished-markup</guid><title><![CDATA[${'<'.repeat(64 * 1024)}]]></title>`)));
    expect(entry?.title).toBe('');
  });

  test('strips nested escaped markup and remaining angle brackets in plain text', () => {
    expect(sanitizeFeedText('&amp;lt;b&amp;gt;Railway&amp;lt;/b&amp;gt; &amp;amp; customers', 300)).toBe('Railway & customers');
    expect(sanitizeFeedText('1 < 2 and 3 > 2; <<unfinished', 300)).toBe('1 2; unfinished');
    expect(sanitizeFeedText(`${'&amp;'.repeat(1)}${'amp;'.repeat(16 * 1024)}lt;b&gt;Railway&lt;/b&gt;`, 300)).toBe('Railway');
  });

  test('keeps individual fields for advisory phrase boundaries', () => {
    const [entry] = parseFeed(rss(item('<guid>fields</guid><title>Railway: rotate</title><description>your secrets with this tutorial</description><summary>Safe deployment</summary>')));
    expect(feedItemTexts(entry!)).toEqual(['Railway: rotate', 'your secrets with this tutorial', 'Safe deployment']);
  });

  test('uses the latest parseable publication field and leaves unknown dates null', () => {
    const entries = parseFeed(rss(item('<guid>latest</guid><pubDate>unknown</pubDate><updated>2026-10-01T00:00:00Z</updated><dc:date>2026-10-26T00:00:00Z</dc:date>') + item('<guid>unknown</guid><pubDate>unknown</pubDate>')));
    expect(entries.map(entry => entry.publishedAt)).toEqual(['2026-10-26T00:00:00.000Z', null]);
  });

  test('uses link identity before changing guid and skips unidentifiable entries', () => {
    const entries = parseFeed(rss(item('<guid>first</guid><link>https://example.com/post</link>') + item('<title>Nothing identifiable</title>')));
    expect(entries.map(entry => entry.id)).toEqual(['https://example.com/post']);
  });

  test('accepts empty RSS and Atom feeds', () => {
    expect(parseFeed(rss())).toEqual([]);
    expect(parseFeed('<feed xmlns="http://www.w3.org/2005/Atom"/>')).toEqual([]);
  });

  test.each(['<html><body>not a feed</body></html>', '<rss><channel></rss>', 'not xml'])('rejects malformed or non-feed bodies with content-free diagnostics: %s', body => {
    expect(() => parseFeed(body)).toThrow('Unable to read feed XML.');
  });

  test('rejects entity declarations and does not expand nested entities', () => {
    expect(() => parseFeed('<!DOCTYPE rss [<!ENTITY a "private-body"><!ENTITY b "&a;&a;">]><rss><channel><item><guid>one</guid><title>&b;</title></item></channel></rss>')).toThrow('Unable to read feed XML.');
  });

  test('reads the recorded official Railway items', async () => {
    const entries = parseFeed(await readFile(new URL('../fixtures/feeds/railway-official-2026-10.xml', import.meta.url), 'utf8'));
    expect(entries).toHaveLength(5);
    expect(entries[0]).toMatchObject({ title: 'Preliminary Report: Oct 21st Security Incident', publishedAt: '2026-10-22T23:31:37.000Z' });
  });
});
