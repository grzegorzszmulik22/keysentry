import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fingerprint } from '../../src/core/fingerprint.js';
import { buildInventory } from '../../src/core/inventory.js';
import { detectBreachFeeds } from '../../src/monitor/detectors/breach-feed.js';
import type { DetectorContext } from '../../src/monitor/context.js';
import { createMonitorState } from '../../src/monitor/state.js';
import type { HostId } from '../../src/types.js';
import { FakeHttp, silentLogger, text } from '../helpers/fake-http.js';
import { svc } from '../helpers/fakes.js';

const key = Buffer.alloc(32, 11);
const at = new Date('2026-10-26T12:00:00Z');
const feedUrl = 'https://example.invalid/rss';
const feeds = [{ url: feedUrl }];
const today = '2026-10-26T11:00:00Z';
const old = '2026-10-18T11:00:00Z';
const railwayFixture = readFileSync(new URL('./fixtures/railway-blog-2026-10.xml', import.meta.url), 'utf8');
const incidentLinks = [
  'https://blog.railway.com/p/preliminary-report-october-security-incident',
  'https://blog.railway.com/p/security-disclosure-recommendation-check-for-unexpected-anthropic-usage',
  'https://blog.railway.com/p/security-disclosure-recommendation-rotate-postgresql-database-credentials',
  'https://blog.railway.com/p/security-disclosure-wednesday-october-21st',
];

function rssFeed(items = ''): string {
  return `<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/"><channel><title>Updates</title>${items}</channel></rss>`;
}

function rssItem(id: string, title = 'Railway security incident', extra = ''): string {
  return `<item><title>${title}</title><link>https://example.invalid/advisory/${id}</link>${extra}</item>`;
}

const rss = rssFeed(rssItem('1', 'Railway security incident',
  '<description>Unauthorized access to environment variables</description>')
  + rssItem('product-1', 'Railway deploys faster'));

function context(http: FakeHttp, hosts: HostId | HostId[] = 'railway'): DetectorContext {
  const inventory = buildInventory((Array.isArray(hosts) ? hosts : [hosts]).map((host, index) => ({ host,
    services: [{ service: svc(host, 'api'), vars: [
      { name: 'OPENROUTER_API_KEY', value: 'sk-or-v1-' + index.toString(16).repeat(64), sealed: false },
    ] }],
  })), key, at);
  return { inventory, hosts: [], providers: [], providerCtx: { http, credentials: {}, log: silentLogger },
    state: createMonitorState(), fingerprintKey: key, log: silentLogger, clock: () => at };
}

describe('breach feeds', () => {
  it('aggregates the four real Railway incident posts into one high-confidence advisory and dedupes the next poll', async () => {
    let body = rssFeed();
    const url = 'https://blog.railway.com/rss.xml';
    const http = new FakeHttp().on('GET', url, () => text(200, body));
    const ctx = context(http);
    ctx.clock = () => new Date('2026-10-22T12:00:00Z');
    const railwayFeeds = [{ url, host: 'railway' as const }];
    expect(await detectBreachFeeds(ctx, railwayFeeds)).toEqual([]);
    body = railwayFixture;
    const signals = await detectBreachFeeds(ctx, railwayFeeds);
    expect(signals).toHaveLength(1);
    expect(signals[0]).toMatchObject({ kind: 'host_breach_advisory', host: 'railway', confidence: 'high',
      evidence: { itemIds: incidentLinks.map(link => fingerprint(link, key)).sort(), count: 4 } });
    expect(Object.keys(ctx.state.seenFeedItems).sort()).toEqual(incidentLinks.map(link => fingerprint(link, key)).sort());
    expect(await detectBreachFeeds(ctx, railwayFeeds)).toEqual([]);
  });

  it('ignores future incident dates in mid-October without consuming them before October 22', async () => {
    let body = rssFeed();
    let clock = new Date('2026-10-15T12:00:00Z');
    const http = new FakeHttp().on('GET', feedUrl, () => text(200, body));
    const ctx = context(http);
    ctx.clock = () => clock;
    const railwayFeeds = [{ url: feedUrl, host: 'railway' as const }];
    expect(await detectBreachFeeds(ctx, railwayFeeds)).toEqual([]);
    body = railwayFixture;
    expect(await detectBreachFeeds(ctx, railwayFeeds)).toEqual([]);
    expect(ctx.state.seenFeedItems).toEqual({});
    clock = new Date('2026-10-22T12:00:00Z');
    const signals = await detectBreachFeeds(ctx, railwayFeeds);
    expect(signals).toHaveLength(1);
    expect(signals[0]!.evidence.count).toBe(4);
  });

  it('rejects all five ordinary fixture posts even when their dates cannot exclude them', async () => {
    let body = rssFeed();
    const http = new FakeHttp().on('GET', feedUrl, () => text(200, body));
    const ctx = context(http);
    const railwayFeeds = [{ url: feedUrl, host: 'railway' as const }];
    expect(await detectBreachFeeds(ctx, railwayFeeds)).toEqual([]);
    const ordinary = railwayFixture.match(/<item>[\s\S]*?<\/item>/g)!.slice(4);
    expect(ordinary).toHaveLength(5);
    for (const item of ordinary) {
      body = rssFeed(item.replace(/<pubDate>[\s\S]*?<\/pubDate>/, ''));
      expect(await detectBreachFeeds(ctx, railwayFeeds)).toEqual([]);
    }
  });

  for (const [title, description] of [
    ['Managing environment variables', 'Railway configuration and deploys'],
    ['How to rotate keys', 'Railway key rotation tutorial'],
    ['Incident Report: October 26th, 2026', 'Railway API outage affecting deployments'],
    ['Secret management tutorial', 'Railway advice on a breach, compromised keys, and when to rotate environment variables'],
    ['Safer deployments', 'Railway security incident examples and credential exposure prevention'],
    ['Railway security', 'incident response tutorial'],
    ['Railway: rotate', 'your secrets with this tutorial'],
  ]) {
    it(`rejects weak keywords for blog and status feeds: ${title}`, async () => {
      for (const url of [feedUrl, 'https://status.railway.invalid/history.rss']) {
        let body = rssFeed();
        const http = new FakeHttp().on('GET', url, () => text(200, body));
        const ctx = context(http);
        const hostFeeds = [{ url, host: 'railway' as const }];
        expect(await detectBreachFeeds(ctx, hostFeeds)).toEqual([]);
        body = rssFeed(rssItem('ordinary', title!, `<description>${description}</description>`));
        expect(await detectBreachFeeds(ctx, hostFeeds)).toEqual([]);
      }
    });
  }

  for (const [title, description, confidence] of [
    ['Security Incident: investigation', '', 'high'],
    ['Security Disclosure: customer update', '', 'high'],
    ['Data breach confirmed', '', 'high'],
    ['Security Advisory: customer action', '', 'medium'],
    ['Security Notice: credentials', '', 'medium'],
    ['Security Update: remediation', '', 'medium'],
    ['Compromised credentials', '', 'medium'],
    ['Credential compromise', '', 'medium'],
    ['Unauthorised access detected', '', 'medium'],
    ['Unauthorized access detected', '', 'medium'],
    ['Credentials leak confirmed', '', 'medium'],
    ['Credential exposure', '', 'medium'],
    ['Rotate your credentials', '', 'medium'],
    ['Rotate all environment variables', '', 'medium'],
    ['Customer remediation', 'Rotate all secrets immediately.', 'medium'],
    ['Customer remediation', 'Rotate your keys immediately.', 'medium'],
    ['Customer remediation', 'An unauthorised third party accessed our systems.', 'medium'],
    ['Customer remediation', 'An unauthorized third-party accessed our systems.', 'medium'],
    ['Customer remediation', 'There was unauthorized access to customer data.', 'medium'],
    ['Customer remediation', 'An attacker may have accessed customer data.', 'medium'],
    ['Customer remediation', 'Customer keys have been exposed.', 'medium'],
    ['Customer remediation', 'Customer keys have been compromised.', 'medium'],
    ['Customer remediation', 'Customer keys have been accessed.', 'medium'],
  ]) {
    it(`qualifies strong security language with ${confidence} confidence: ${title} ${description}`, async () => {
      let body = rssFeed();
      const http = new FakeHttp().on('GET', feedUrl, () => text(200, body));
      const ctx = context(http);
      const hostFeeds = [{ url: feedUrl, host: 'railway' as const }];
      expect(await detectBreachFeeds(ctx, hostFeeds)).toEqual([]);
      body = rssFeed(rssItem('strong', title!, `<description>${description}</description>`));
      const signals = await detectBreachFeeds(ctx, hostFeeds);
      expect(signals).toHaveLength(1);
      expect(signals[0]).toMatchObject({ host: 'railway', confidence, evidence: { count: 1 } });
    });
  }

  it('uses the same strong patterns for security posts in status history feeds', async () => {
    let body = rssFeed();
    const url = 'https://status.railway.invalid/history.rss';
    const http = new FakeHttp().on('GET', url, () => text(200, body));
    const ctx = context(http);
    const statusFeeds = [{ url, host: 'railway' as const }];
    expect(await detectBreachFeeds(ctx, statusFeeds)).toEqual([]);
    body = rssFeed(rssItem('outage', 'Incident Report: degraded performance')
      + rssItem('security', 'Security incident: customer action required'));
    const signals = await detectBreachFeeds(ctx, statusFeeds);
    expect(signals).toHaveLength(1);
    expect(signals[0]).toMatchObject({ confidence: 'high', evidence: { count: 1 } });
  });

  it('aggregates across feeds with stable IDs regardless of item order, duplicates, or poll time', async () => {
    const urls = ['https://example.invalid/one', 'https://example.invalid/two'];
    let bodies = [rssFeed(), rssFeed()];
    const http = new FakeHttp().on('GET', /^https:\/\/example\.invalid\//,
      req => text(200, bodies[urls.indexOf(req.url)]!));
    const hostFeeds = urls.map(url => ({ url, host: 'railway' as const }));
    const ctx = context(http);
    const reordered = context(http);
    expect(await detectBreachFeeds(ctx, hostFeeds)).toEqual([]);
    expect(await detectBreachFeeds(reordered, hostFeeds)).toEqual([]);
    bodies = [rssFeed(rssItem('a') + rssItem('b') + rssItem('a')), rssFeed(rssItem('b') + rssItem('c'))];
    const signals = await detectBreachFeeds(ctx, hostFeeds);
    expect(signals).toHaveLength(1);
    expect(signals[0]).toMatchObject({ confidence: 'high', evidence: { count: 3 } });
    bodies = [rssFeed(rssItem('b') + rssItem('a')), rssFeed(rssItem('c') + rssItem('b'))];
    reordered.clock = () => new Date('2026-10-27T12:00:00Z');
    const reverseSignals = await detectBreachFeeds(reordered, [...hostFeeds].reverse());
    expect(reverseSignals).toHaveLength(1);
    expect(reverseSignals[0]!.id).toBe(signals[0]!.id);
    expect(reverseSignals[0]!.evidence).toEqual(signals[0]!.evidence);
    expect(await detectBreachFeeds(ctx, hostFeeds)).toEqual([]);
    bodies[0] = rssFeed(rssItem('d'));
    const nextSignals = await detectBreachFeeds(ctx, hostFeeds);
    expect(nextSignals).toHaveLength(1);
    expect(nextSignals[0]!.id).not.toBe(signals[0]!.id);
    expect(nextSignals[0]!.evidence.count).toBe(1);
  });

  it('upgrades confidence for the same item in the host own feed regardless of feed order', async () => {
    const ownUrl = 'https://blog.railway.com/rss.xml';
    for (const ownFirst of [true, false]) {
      let body = rssFeed();
      const http = new FakeHttp().on('GET', /^https:\/\//, () => text(200, body));
      const ctx = context(http);
      const sources = [{ url: feedUrl }, { url: ownUrl, host: 'railway' as const }];
      if (ownFirst) sources.reverse();
      expect(await detectBreachFeeds(ctx, sources)).toEqual([]);
      body = rssFeed(rssItem('shared', 'Railway security incident'));
      const signals = await detectBreachFeeds(ctx, sources);
      expect(signals).toHaveLength(1);
      expect(signals[0]).toMatchObject({ confidence: 'high', evidence: { count: 1 } });
    }
  });

  it('emits a new Railway advisory only for an inventoried Railway host and dedupes its link', async () => {
    let body = rssFeed();
    const http = new FakeHttp().on('GET', /^https:\/\/example\.invalid\/rss$/, () => text(200, body));
    const ctx = context(http);
    const vercelOnly = context(http, 'vercel');
    expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
    expect(await detectBreachFeeds(vercelOnly, feeds)).toEqual([]);
    body = rss;
    const signals = await detectBreachFeeds(ctx, feeds);
    expect(signals).toHaveLength(1);
    expect(signals[0]).toMatchObject({ kind: 'host_breach_advisory', confidence: 'medium', host: 'railway',
      clusterIds: [ctx.inventory.clusters[0]!.id] });
    expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
    expect(await detectBreachFeeds(vercelOnly, feeds)).toEqual([]);
  });

  it('parses namespaced Atom entries and selects an alternate link', async () => {
    let body = '<feed xmlns="http://www.w3.org/2005/Atom"/>';
    const http = new FakeHttp().on('GET', /\/atom$/, () => text(200, body));
    const ctx = context(http, 'vercel');
    const atomFeeds = [{ url: 'https://example.invalid/atom', host: 'vercel' as const }];
    expect(await detectBreachFeeds(ctx, atomFeeds)).toEqual([]);
    body = `<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Vercel security incident</title>
      <summary>Environment variables may be compromised</summary><link rel="self" href="https://example.invalid/api/2"/>
      <link rel="alternate" href="https://example.invalid/advisory/2"/></entry></feed>`;
    const signals = await detectBreachFeeds(ctx, atomFeeds);
    expect(signals).toHaveLength(1);
    expect(signals[0]).toMatchObject({ kind: 'host_breach_advisory', host: 'vercel' });
    body = rssFeed(rssItem('2', 'Vercel security incident'));
    expect(await detectBreachFeeds(ctx, atomFeeds)).toEqual([]);
  });

  it('does not copy untrusted titles, links or response failures into state or signals', async () => {
    const secret = 'secret-that-must-never-be-written';
    let body = rssFeed();
    const http = new FakeHttp().on('GET', /\/rss$/, () => text(200, body));
    const ctx = context(http);
    expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
    body = `<rss><channel><item><title>Railway breach ${secret}</title><link>https://example.invalid/${secret}</link></item></channel></rss>`;
    const signals = await detectBreachFeeds(ctx, feeds);
    expect(signals).toHaveLength(1);
    expect(JSON.stringify({ signals, state: ctx.state })).not.toContain(secret);
  });

  it('silently baselines every identifiable item, including non-security items later edited into advisories', async () => {
    const guidItem = (title: string) => `<item><guid isPermaLink="false">release-2</guid><title>${title}</title></item>`;
    let body = rssFeed(rssItem('existing-advisory') + rssItem('release', 'Faster deploys') + guidItem('New dashboard'));
    const http = new FakeHttp().on('GET', /\/rss$/, () => text(200, body));
    const ctx = context(http);
    expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
    body = rssFeed(rssItem('existing-advisory') + rssItem('release') + guidItem('Railway security incident'));
    expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
    body = rssFeed(rssItem('new-advisory'));
    expect(await detectBreachFeeds(ctx, feeds)).toHaveLength(1);
  });

  it('parses RSS above 2 MB and detects an advisory added after its large baseline', async () => {
    const archive = rssItem('archive', 'Product updates', `<description>${'x'.repeat(2_100_000)}</description>`);
    let body = rssFeed(archive);
    const http = new FakeHttp().on('GET', /\/rss$/, () => text(200, body));
    const ctx = context(http);
    expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
    body = rssFeed(archive + rssItem('new'));
    expect(await detectBreachFeeds(ctx, feeds)).toHaveLength(1);
  });

  it('rejects feeds above 16 MB without establishing their baseline', async () => {
    let body = rssFeed(rssItem('too-large', 'Railway security incident',
      `<description>${'x'.repeat(16 * 1024 * 1024)}</description>`));
    const http = new FakeHttp().on('GET', /\/rss$/, () => text(200, body));
    const ctx = context(http);
    expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
    expect(ctx.state.seenFeedItems).toEqual({});
    body = rssFeed(rssItem('first-valid'));
    expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
    body = rssFeed(rssItem('later-valid'));
    expect(await detectBreachFeeds(ctx, feeds)).toHaveLength(1);
  });

  it('counts UTF-8 bytes when rejecting a feed whose character count is below 16 MiB', async () => {
    let body = rssFeed();
    const http = new FakeHttp().on('GET', /\/rss$/, () => text(200, body));
    const ctx = context(http);
    expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
    // Each accented character occupies two UTF-8 bytes: 9 million characters exceed 16 MiB.
    body = rssFeed(rssItem('multibyte', 'Railway security incident', `<description>${'é'.repeat(9_000_000)}</description>`));
    expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
    expect(ctx.state.seenFeedItems).toEqual({});
    body = rssFeed(rssItem('normal-size'));
    expect(await detectBreachFeeds(ctx, feeds)).toHaveLength(1);
  });

  it('detects a current Railway CDATA Security Disclosure without a Railway mention', async () => {
    let body = rssFeed();
    const http = new FakeHttp().on('GET', /\/rss$/, () => text(200, body));
    const ctx = context(http);
    const railwayFeeds = [{ url: feedUrl, host: 'railway' as const }];
    expect(await detectBreachFeeds(ctx, railwayFeeds)).toEqual([]);
    body = rssFeed(rssItem('disclosure', '<![CDATA[Security Disclosure: October 26, 2026]]>',
      '<pubDate>Mon, 26 Oct 2026 11:00:00 GMT</pubDate><description><![CDATA[Details and remediation.]]></description>'));
    const signals = await detectBreachFeeds(ctx, railwayFeeds);
    expect(signals).toHaveLength(1);
    expect(signals[0]).toMatchObject({ kind: 'host_breach_advisory', host: 'railway', confidence: 'high' });
  });

  for (const [shape, title] of [
    ['ordinary text and CDATA', 'Update: <![CDATA[Security Disclosure]]>'],
    ['adjacent CDATA sections', '<![CDATA[Security]]><![CDATA[ Disclosure]]>'],
    ['a disclosure phrase split by CDATA and followed by text', 'Security <![CDATA[Disclosure]]>: October 26, 2026'],
    ['an incident phrase split by CDATA and followed by text', 'Railway security <![CDATA[incident]]> resolved'],
  ]) {
    it(`reads security keywords from a title containing ${shape}`, async () => {
      let body = rssFeed();
      const http = new FakeHttp().on('GET', /\/rss$/, () => text(200, body));
      const ctx = context(http);
      const railwayFeeds = [{ url: feedUrl, host: 'railway' as const }];
      expect(await detectBreachFeeds(ctx, railwayFeeds)).toEqual([]);
      body = rssFeed(rssItem('mixed-title', title, `<pubDate>${today}</pubDate>`));
      expect(await detectBreachFeeds(ctx, railwayFeeds)).toHaveLength(1);
    });
  }

  for (const tag of ['pubDate', 'published', 'updated', 'dc:date']) {
    it(`ignores newly discovered RSS items older than seven days using ${tag}`, async () => {
      let body = rssFeed();
      const http = new FakeHttp().on('GET', /\/rss$/, () => text(200, body));
      const ctx = context(http);
      expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
      body = rssFeed(rssItem('stale', 'Railway security incident', `<${tag}>${old}</${tag}>`));
      expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
      body = rssFeed(rssItem('current', 'Railway security incident', `<${tag}>${today}</${tag}>`));
      expect(await detectBreachFeeds(ctx, feeds)).toHaveLength(1);
    });
  }

  it('accepts an item exactly seven days old and honors maxAgeDays', async () => {
    let body = rssFeed();
    const http = new FakeHttp().on('GET', /\/rss$/, () => text(200, body));
    const ctx = context(http);
    expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
    body = rssFeed(rssItem('boundary', 'Railway security incident', '<pubDate>2026-10-19T12:00:00Z</pubDate>'));
    expect(await detectBreachFeeds(ctx, feeds)).toHaveLength(1);
    body = rssFeed(rssItem('too-old-for-one-day', 'Railway security incident', '<pubDate>2026-10-24T12:00:00Z</pubDate>'));
    expect(await detectBreachFeeds(ctx, feeds, { maxAgeDays: 1 })).toEqual([]);
    body = rssFeed(rssItem('within-ten-days', 'Railway security incident', `<pubDate>${old}</pubDate>`));
    expect(await detectBreachFeeds(ctx, feeds, { maxAgeDays: 10 })).toHaveLength(1);
  });

  it('applies Atom published and updated dates after an empty Atom baseline', async () => {
    const atomFeed = (entries = '') => `<feed xmlns="http://www.w3.org/2005/Atom">${entries}</feed>`;
    const entry = (id: string, tag: string, date: string) => `<entry><id>urn:advisory:${id}</id>
      <title>Vercel security incident</title><${tag}>${date}</${tag}></entry>`;
    let body = atomFeed();
    const http = new FakeHttp().on('GET', /\/rss$/, () => text(200, body));
    const ctx = context(http, 'vercel');
    expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
    body = atomFeed(entry('old-published', 'published', old) + entry('old-updated', 'updated', old));
    expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
    body = atomFeed(entry('new-published', 'published', today) + entry('new-updated', 'updated', today));
    const signals = await detectBreachFeeds(ctx, feeds);
    expect(signals).toHaveLength(1);
    expect(signals[0]!.evidence.count).toBe(2);
  });

  it('uses the latest parseable date when an advisory has several date fields', async () => {
    let body = rssFeed();
    const http = new FakeHttp().on('GET', /\/rss$/, () => text(200, body));
    const ctx = context(http);
    expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
    body = rssFeed(
      rssItem('recently-updated', 'Railway security incident', `<published>${old}</published><updated>${today}</updated>`)
      + rssItem('recently-published', 'Railway security incident', `<published>${today}</published><updated>${old}</updated>`)
      + rssItem('fallback-date', 'Railway security incident', `<pubDate>unknown</pubDate><published>${old}</published><dc:date>${today}</dc:date>`));
    const signals = await detectBreachFeeds(ctx, feeds);
    expect(signals).toHaveLength(1);
    expect(signals[0]!.evidence.count).toBe(3);
  });

  it('keeps new undated and unparseable-date advisories eligible after the baseline', async () => {
    let body = rssFeed();
    const http = new FakeHttp().on('GET', /\/rss$/, () => text(200, body));
    const ctx = context(http);
    expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
    body = rssFeed(rssItem('undated') + rssItem('invalid-date', 'Railway security incident', '<pubDate>unknown</pubDate>'));
    const signals = await detectBreachFeeds(ctx, feeds);
    expect(signals).toHaveLength(1);
    expect(signals[0]!.evidence.count).toBe(2);
  });

  it('establishes a separate silent baseline for each URL', async () => {
    const bodies = new Map([['https://example.invalid/one', rssFeed()], ['https://example.invalid/two', rssFeed(rssItem('historical'))]]);
    const http = new FakeHttp().on('GET', /^https:\/\/example\.invalid\/(one|two)$/, req => text(200, bodies.get(req.url)!));
    const ctx = context(http);
    expect(await detectBreachFeeds(ctx, [{ url: 'https://example.invalid/one' }])).toEqual([]);
    bodies.set('https://example.invalid/one', rssFeed(rssItem('new-one')));
    expect(await detectBreachFeeds(ctx, [{ url: 'https://example.invalid/one' }])).toHaveLength(1);
    expect(await detectBreachFeeds(ctx, [{ url: 'https://example.invalid/two' }])).toEqual([]);
    bodies.set('https://example.invalid/two', rssFeed(rssItem('new-two')));
    expect(await detectBreachFeeds(ctx, [{ url: 'https://example.invalid/two' }])).toHaveLength(1);
  });

  for (const failure of ['http', 'malformed-xml', 'non-feed-xml']) {
    it(`waits for a valid successful feed before baselining after ${failure}`, async () => {
      let response = failure === 'http' ? text(503, 'unavailable')
        : text(200, failure === 'malformed-xml' ? '<rss><channel>' : '<html><body>not a feed</body></html>');
      const http = new FakeHttp().on('GET', /\/rss$/, () => response);
      const ctx = context(http);
      expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
      response = text(200, rssFeed(rssItem('first-valid')));
      expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
      response = text(200, rssFeed(rssItem('later')));
      expect(await detectBreachFeeds(ctx, feeds)).toHaveLength(1);
    });
  }

  it('attributes the configured inventoried host and other inventoried hosts mentioned in the advisory', async () => {
    let body = rssFeed();
    const http = new FakeHttp().on('GET', /\/rss$/, () => text(200, body));
    const ctx = context(http, ['railway', 'vercel']);
    const railwayFeeds = [{ url: feedUrl, host: 'railway' as const }];
    expect(await detectBreachFeeds(ctx, railwayFeeds)).toEqual([]);
    body = rssFeed(rssItem('joint', 'Vercel security incident', '<description>Remediation coordinated with Render.</description>'));
    const signals = await detectBreachFeeds(ctx, railwayFeeds);
    expect(signals.map(signal => signal.host).sort()).toEqual(['railway', 'vercel']);
    expect(signals.find(signal => signal.host === 'railway')!.clusterIds)
      .toEqual([ctx.inventory.findings.find(finding => finding.service.host === 'railway')!.fingerprint]);
    expect(signals.find(signal => signal.host === 'vercel')!.clusterIds)
      .toEqual([ctx.inventory.findings.find(finding => finding.service.host === 'vercel')!.fingerprint]);
    expect(signals.find(signal => signal.host === 'railway')!.confidence).toBe('high');
    expect(signals.find(signal => signal.host === 'vercel')!.confidence).toBe('medium');
    expect(await detectBreachFeeds(ctx, railwayFeeds)).toEqual([]);
  });

  for (const mention of [
    'We render updates that fly through github, railway, and vercel integrations.',
    'Render and dotenv configuration were reviewed.',
    'RAILWAY VERCEL RENDER FLY GITHUB',
    'notrailway.com notrailway.app notvercel.com notrender.com notfly.io notgithub.com',
    'not-railway.com not-railway.app not-vercel.com not-render.com not-fly.io not-github.com',
    'railway.company railway.application vercel.company render.computer fly.iota github.company',
    'railway.com.evil railway.app.evil vercel.com.evil render.com.evil fly.io.evil github.com.evil',
    'Railway.com.evil Railway.app.evil Vercel.com.evil Render.com.evil Fly.io.evil GitHub.com.evil',
    'railway.com_extra railway.app_extra vercel.com_extra render.com_extra fly.io_extra github.com_extra',
    'railway.com-extra railway.app-extra vercel.com-extra render.com-extra fly.io-extra github.com-extra',
    'RailwayTools VercelTools Fly.ioTools GitHubTools',
  ]) {
    it(`does not attribute hosts from ordinary words or deceptive domain names: ${mention}`, async () => {
      let body = rssFeed();
      const http = new FakeHttp().on('GET', feedUrl, () => text(200, body));
      const ctx = context(http, ['railway', 'vercel', 'render', 'fly', 'github-actions', 'dotenv']);
      expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
      body = rssFeed(rssItem('unrelated-hosts', 'Security incident', `<description>${mention}</description>`));
      expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
    });
  }

  for (const [host, domain] of [
    ['railway', 'railway.com'],
    ['railway', 'railway.app'],
    ['vercel', 'vercel.com'],
    ['render', 'render.com'],
    ['fly', 'fly.io'],
    ['github-actions', 'github.com'],
  ] as const) {
    it(`attributes explicit ${domain} domain mentions with domain boundaries and case-insensitive matching`, async () => {
      for (const mention of [domain, domain.toUpperCase(), `https://api.${domain}/advisory`, `(${domain}).`]) {
        let body = rssFeed();
        const http = new FakeHttp().on('GET', feedUrl, () => text(200, body));
        const ctx = context(http, ['railway', 'vercel', 'render', 'fly', 'github-actions', 'dotenv']);
        expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
        body = rssFeed(rssItem('explicit-domain', 'Security incident', `<description>See ${mention}</description>`));
        const signals = await detectBreachFeeds(ctx, feeds);
        expect(signals.map(signal => signal.host)).toEqual([host]);
        expect(signals[0]).toMatchObject({ confidence: 'medium', evidence: { count: 1 } });
      }
    });
  }

  for (const [host, product] of [
    ['railway', 'Railway'],
    ['vercel', 'Vercel'],
    ['fly', 'Fly.io'],
    ['github-actions', 'GitHub'],
  ] as const) {
    it(`attributes the capitalized product ${product} in advisory text`, async () => {
      let body = rssFeed();
      const http = new FakeHttp().on('GET', feedUrl, () => text(200, body));
      const ctx = context(http, ['railway', 'vercel', 'render', 'fly', 'github-actions', 'dotenv']);
      expect(await detectBreachFeeds(ctx, feeds)).toEqual([]);
      body = rssFeed(rssItem('explicit-product', 'Security incident', `<description>Affected product: ${product}.</description>`));
      const signals = await detectBreachFeeds(ctx, feeds);
      expect(signals.map(signal => signal.host)).toEqual([host]);
      expect(signals[0]).toMatchObject({ confidence: 'medium', evidence: { count: 1 } });
    });
  }

  it('attributes every configured inventoried host without a host mention', async () => {
    for (const host of ['railway', 'vercel', 'render', 'fly', 'github-actions', 'dotenv'] as const) {
      let body = rssFeed();
      const http = new FakeHttp().on('GET', feedUrl, () => text(200, body));
      const ctx = context(http, ['railway', 'vercel', 'render', 'fly', 'github-actions', 'dotenv']);
      const ownFeed = [{ url: feedUrl, host }];
      expect(await detectBreachFeeds(ctx, ownFeed)).toEqual([]);
      body = rssFeed(rssItem('own-host', 'Security incident'));
      expect((await detectBreachFeeds(ctx, ownFeed)).map(signal => signal.host)).toEqual([host]);
    }
  });

  it('does not attribute a configured host absent from the inventory', async () => {
    let body = rssFeed();
    const http = new FakeHttp().on('GET', /\/rss$/, () => text(200, body));
    const ctx = context(http, 'vercel');
    const railwayFeeds = [{ url: feedUrl, host: 'railway' as const }];
    expect(await detectBreachFeeds(ctx, railwayFeeds)).toEqual([]);
    body = rssFeed(rssItem('unrelated', 'Security incident'));
    expect(await detectBreachFeeds(ctx, railwayFeeds)).toEqual([]);
  });

  it('polls the default feed URLs verified on 26 October 2026 and attributes their hosts', async () => {
    const defaults = [
      ['railway', 'https://blog.railway.com/rss.xml'],
      ['railway', 'https://railway.com/changelog/rss.xml'],
      ['vercel', 'https://vercel.com/atom'],
      ['vercel', 'https://www.vercel-status.com/history.rss'],
      ['render', 'https://render.com/blog/feed.xml'],
      ['render', 'https://status.render.com/history.rss'],
      ['fly', 'https://fly.io/blog/feed.xml'],
      ['fly', 'https://status.flyio.net/history.rss'],
      ['github-actions', 'https://github.blog/changelog/feed/'],
    ];
    let baseline = true;
    const http = new FakeHttp().on('GET', /^https:\/\//, req => text(200, baseline ? rssFeed()
      : rssFeed(rssItem(encodeURIComponent(req.url), 'Security incident'))));
    const ctx = context(http, ['railway', 'vercel', 'render', 'fly', 'github-actions']);
    expect(await detectBreachFeeds(ctx)).toEqual([]);
    expect(http.calls.map(call => call.url)).toEqual(defaults.map(([, url]) => url));
    baseline = false;
    const signals = await detectBreachFeeds(ctx);
    expect(signals.map(signal => signal.host)).toEqual(['railway', 'vercel', 'render', 'fly', 'github-actions']);
    expect(signals.map(signal => signal.evidence.count)).toEqual([2, 2, 2, 2, 1]);
  });
});
