import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { fingerprint } from '../../src/core/fingerprint.js';
import { parseFeed, type FeedItem } from '../../src/feeds/index.js';
import { DEFAULT_SOURCES, classifyItem } from '../../src/autopilot/sources.js';
import { updateIncidents } from '../../src/autopilot/incidents.js';
import { EGRESS_RULES, matchRule } from '../../src/net/allowlist.js';
import type { FeedSource, Incident, IncidentEvidence } from '../../src/types.js';

const key = Buffer.alloc(32, 22);
const itemKey = (id: string) => fingerprint(id, key);
// Observe the recorded October 21-22 reports while they are inside the 72-hour evidence window.
const now = new Date('2026-10-23T12:00:00Z');
const fixture = (name: string) => parseFeed(readFileSync(new URL(`../fixtures/feeds/${name}`, import.meta.url), 'utf8'));
const source = (url: string) => DEFAULT_SOURCES.find(value => value.url === url)!;
const official = () => source('https://blog.railway.com/rss.xml');
const hackerNews = () => source('https://feeds.feedburner.com/TheHackersNews');
const bleepingComputer = () => source('https://www.bleepingcomputer.com/feed/');
const report = (name: string, outlet: FeedSource): IncidentEvidence => {
  const result = classifyItem(fixture(name)[0]!, outlet, itemKey);
  expect(result).not.toBeNull();
  return result!;
};
const news = () => report('news-thehackernews-railway.xml', hackerNews());
const independentNews = () => report('news-bleepingcomputer-railway.xml', bleepingComputer());
const officialEvidence = () => fixture('railway-official-2026-10.xml')
  // The feed fixture abbreviates the posts to descriptions without their exposure facts.
  // Include the exposure/rotation scenario recorded in notes/phase2-facts.md for trigger tests.
  .map(item => ({ ...item, summary: `${item.summary} Customer environment variables were accessed. Railway urges users to rotate credentials after the security incident.` }))
  .map(item => classifyItem(item, official(), itemKey)).filter((item): item is IncidentEvidence => item !== null);
const titleItem = (title: string, summary = ''): FeedItem => ({
  id: title, title, summary, link: 'https://example.invalid/article', publishedAt: now.toISOString(),
});

describe('feed sources and classification', () => {
  it('ships the verified official and independent news feeds with guarded destinations', () => {
    expect(DEFAULT_SOURCES.map(s => s.id).length).toBe(new Set(DEFAULT_SOURCES.map(s => s.id)).size);
    for (const feed of DEFAULT_SOURCES) {
      expect(matchRule(new URL(feed.url), EGRESS_RULES)?.owner).toBe('feed');
      expect(feed.owner.trim()).not.toBe('');
      expect(feed.maxBytes).toBe(['railway', 'vercel'].some(host => feed.kind === 'official' && feed.hosts.includes(host as 'railway' | 'vercel'))
        || feed.owner === 'CISA' ? 8 * 1024 * 1024 : 4 * 1024 * 1024);
    }
    expect(DEFAULT_SOURCES.filter(s => s.kind === 'news').map(s => s.owner)).toEqual([
      'BleepingComputer LLC', 'Recorded Future', 'SecurityWeek / Wired Business Media', 'Situation Publishing',
      'Brian Krebs', 'Informa TechTarget', 'Condé Nast', 'The Hacker News', 'CISA', 'Help Net Security',
    ]);
    expect(source('https://vercel.com/kb/kb-feed').linkPrefix).toBe('https://vercel.com/kb/bulletin/');
    for (const url of ['https://render.com/changelog/feed.xml', 'https://community.fly.io/c/fresh-produce/27.rss',
      'https://www.githubstatus.com/history.rss', 'https://github.blog/security/feed/']) {
      expect(source(url).kind).toBe('official');
    }
  });

  it('classifies both real independent reports as credential exposure without high news confidence', () => {
    for (const evidence of [news(), independentNews()]) {
      expect(evidence).toMatchObject({ kind: 'news', credentialExposure: true, confidence: 'medium' });
      expect(evidence.itemKey).toMatch(/^[a-f0-9]{32}$/);
    }
    expect(news().itemKey).toBe(itemKey(fixture('news-thehackernews-railway.xml')[0]!.id));
  });

  it('rejects credential exposure for the outage, phishing and other-company breach fixtures', () => {
    const items = fixture('news-synthetic-negatives.xml');
    expect(items).toHaveLength(3);
    for (const item of items) {
      expect(classifyItem(item, hackerNews(), itemKey)).toMatchObject({ credentialExposure: false });
    }
  });

  it('only official security incident, disclosure or breach titles with exposure have high confidence', () => {
    expect(officialEvidence()).toHaveLength(4);
    expect(officialEvidence().every(e => e.confidence === 'high')).toBe(true);
    for (const item of fixture('railway-official-2026-10.xml').slice(0, 4)) {
      expect(classifyItem(item, official(), itemKey)).toMatchObject({ confidence: 'medium', credentialExposure: false });
    }
    expect(classifyItem(titleItem('Security update'), official(), itemKey)).toMatchObject({ confidence: 'medium' });
    expect(classifyItem(titleItem('Deploy faster'), official(), itemKey)).toBeNull();
    expect(classifyItem(titleItem('Railway breach'), hackerNews(), itemKey)).toMatchObject({ confidence: 'medium', credentialExposure: false });
  });

  it('does not treat a different platform title as an official advisory for the source platform', () => {
    const github = source('https://github.blog/security/feed/');
    expect(classifyItem(titleItem('Railway security incident'), github, itemKey)).toBeNull();
    expect(classifyItem(titleItem('GitHub analyzes the Railway breach'), github, itemKey)).toBeNull();
  });

  it('requires the platform in the news title with precise product and domain boundaries', () => {
    for (const title of ['A railway breach exposes tokens', 'railway.com.evil.test breach exposes tokens',
      'Our Railwayish breach exposes tokens', 'A breach at a cloud company']) {
      expect(classifyItem(titleItem(title, 'Railway customer secrets were stolen.'), hackerNews(), itemKey)).toBeNull();
    }
    expect(classifyItem(titleItem('RAILWAY.COM breach', 'Customer secrets were stolen.'), hackerNews(), itemKey))
      .toMatchObject({ credentialExposure: true });
  });

  it.each(['phishing', 'impersonating', 'look-alike', 'fake emails', 'scam',
    'was not involved', 'were not breached', 'no customer data was affected'])(
    'negative cue %s blocks otherwise matching exposure language', cue => {
      expect(classifyItem(titleItem('Railway breach exposes customer secrets', `Customer API keys were stolen; ${cue}.`),
        hackerNews(), itemKey)).toMatchObject({ credentialExposure: false });
    });

  it('does not mistake another named company hosted on a platform for that platform being breached', () => {
    expect(classifyItem(titleItem('Acme Analytics breach exposes customer keys; hosted on Railway',
      'Acme Analytics customer credentials were stolen.'), hackerNews(), itemKey))
      .toMatchObject({ credentialExposure: false });
  });

  it('does not share an exposure flag across multiple platforms, including restricted custom sources', () => {
    const item = titleItem('Railway and Vercel report a breach', 'Customer keys were stolen.');
    expect(classifyItem(item, hackerNews(), itemKey)).toMatchObject({ credentialExposure: false });
    expect(classifyItem(item, { ...hackerNews(), hosts: ['railway'] }, itemKey))
      .toMatchObject({ credentialExposure: false });
  });

  it('does not treat reporting on another breached subject as the platform own breach', () => {
    for (const title of ['Railway reports Acme Analytics breach exposes customer keys',
      'Railway customer Acme Analytics breach exposes customer keys',
      'Railway advises users after Acme Analytics breach exposes customer API keys',
      'Railway reports a breach at customer Acme Analytics exposing API keys',
      'Railway says Acme Analytics was breached and customer API keys were stolen',
      'Railway explains how to protect secrets from stolen laptops']) {
      expect(classifyItem(titleItem(title, 'Acme Analytics customer API keys were stolen.'), hackerNews(), itemKey))
        .toMatchObject({ credentialExposure: false });
    }
  });

  it.each([
    ['Railway says customer secrets were not exposed', 'An investigation confirmed that no customer credentials were accessed.'],
    ['Railway says its own systems were never accessed', 'No customer secrets were stolen.'],
    ["Railway says customer API keys weren't stolen", 'An investigation is complete.'],
    ['Railway says none of its customer secrets were exposed', 'An investigation is complete.'],
    ['Railway now lets developers access API keys in dashboard', 'Customers can access API keys through the new dashboard.'],
    ['Railway feature exposes API keys in the developer dashboard', 'Developers can view their own credentials using the authenticated dashboard.'],
  ])('does not corroborate negated claims or product features: %s', (title, summary) => {
    const item = titleItem(title, summary);
    const reports = [hackerNews(), bleepingComputer()].map(outlet => classifyItem(item, outlet, itemKey)!);
    expect(reports[0]).toMatchObject({ credentialExposure: false });
    expect(updateIncidents({ incidents: [] }, reports, now).triggered).toEqual([]);
  });

  it('recognizes own-system access, exposed customer credentials, and breach-related rotation requests', () => {
    for (const [title, summary] of [
      ['Railway reports a breach', "Railway's own systems were accessed by an unauthorized party."],
      ['Railway investigates suspicious activity', 'Customer environment variables were decrypted.'],
      ['Railway urges customers to rotate API keys after suspicious activity', 'An investigation is ongoing.'],
    ]) {
      expect(classifyItem(titleItem(title!, summary!), hackerNews(), itemKey)).toMatchObject({ credentialExposure: true });
    }
    expect(classifyItem(titleItem('Railway key rotation tutorial', 'Learn to rotate your keys to prevent a breach.'),
      hackerNews(), itemKey)).toMatchObject({ credentialExposure: false });
  });

  it('enforces bulletin filtering and sanitized evidence titles even for direct callers', () => {
    const bulletin = source('https://vercel.com/kb/kb-feed');
    expect(classifyItem(titleItem('Security incident'), bulletin, itemKey)).toBeNull();
    const item = { ...titleItem('<b>Vercel</b>\u202e security incident\u0000 ' + 'x'.repeat(300)),
      link: 'https://vercel.com/kb/bulletin/security' };
    const evidence = classifyItem(item, bulletin, itemKey)!;
    expect(evidence.title).toHaveLength(200);
    expect(evidence.title).toMatch(/^Vercel security incident /);
    expect(evidence.title).not.toMatch(/[<>\u0000\u202a-\u202e\u2066-\u2069]/);
  });

  it('does not attribute a platform that disappears beyond the persisted title cap', () => {
    expect(classifyItem(titleItem('x'.repeat(201) + ' Railway breach', 'Customer credentials were stolen.'), hackerNews(), itemKey)).toBeNull();
  });
});

describe('incidents and corroboration', () => {
  it('the recorded Railway October 2026 post triggers one incident by the official rule', () => {
    const result = updateIncidents({ incidents: [] }, officialEvidence(), now);
    expect(result.incidents).toHaveLength(1);
    expect(result.triggered).toHaveLength(1);
    expect(result.changed).toHaveLength(1);
    expect(result.triggered[0]).toMatchObject({ host: 'railway', openedAt: now.toISOString(), status: 'triggered',
      trigger: { at: now.toISOString(), rule: 'official' } });
    expect(result.triggered[0]!.id).toMatch(/^inc-railway-20261023-[a-f0-9]{8}$/);
    expect(result.triggered[0]!.evidence).toHaveLength(4);
  });

  it('one news report alone alerts and never triggers', () => {
    const result = updateIncidents({ incidents: [] }, [news()], now);
    expect(result.incidents).toHaveLength(1);
    expect(result.incidents[0]!.status).toBe('alerted');
    expect(result.triggered).toEqual([]);
  });

  it('two independent outlets with credential exposure trigger corroborated-news', () => {
    const first = updateIncidents({ incidents: [] }, [news()], now);
    const second = updateIncidents(first, [independentNews()], now);
    expect(second.triggered).toHaveLength(1);
    expect(second.triggered[0]!.trigger?.rule).toBe('corroborated-news');
    expect(first.incidents[0]!.status).toBe('alerted');
  });

  it('two outlets with the same owner do not corroborate each other', () => {
    const result = updateIncidents({ incidents: [] }, [news(), { ...independentNews(), owner: news().owner }], now);
    expect(result.triggered).toEqual([]);
    expect(result.incidents[0]!.status).toBe('alerted');
  });

  it('news naming a platform without credential exposure never triggers', () => {
    for (const item of fixture('news-synthetic-negatives.xml')) {
      const evidence = [hackerNews(), bleepingComputer()].map(outlet => classifyItem(item, outlet, itemKey)!);
      const result = updateIncidents({ incidents: [] }, evidence, now);
      expect(result.triggered).toEqual([]);
      expect(result.incidents.every(incident => incident.status === 'alerted')).toBe(true);
    }
  });

  it('requires credential exposure on both news reports', () => {
    expect(updateIncidents({ incidents: [] }, [news(), { ...independentNews(), credentialExposure: false }], now).triggered).toEqual([]);
  });

  it('requires news timestamps no more than 72 hours apart, including the boundary', () => {
    const one = { ...news(), publishedAt: '2026-10-20T12:00:00Z' };
    const two = { ...independentNews(), publishedAt: '2026-10-23T12:00:00Z' };
    expect(updateIncidents({ incidents: [] }, [one, two], now).triggered).toHaveLength(1);
    expect(updateIncidents({ incidents: [] }, [one, { ...two, publishedAt: '2026-10-23T12:00:00.001Z' }], now).triggered).toEqual([]);
    expect(updateIncidents({ incidents: [] }, [one, { ...two, publishedAt: null }], now).triggered).toEqual([]);
  });

  it('official medium and credential-exposure news corroborate in either arrival order', () => {
    const medium = classifyItem(titleItem('Security advisory'), official(), itemKey)!;
    for (const evidence of [[medium, news()], [news(), medium]]) {
      const first = updateIncidents({ incidents: [] }, evidence.slice(0, 1), now);
      expect(first.triggered).toEqual([]);
      const result = updateIncidents(first, evidence.slice(1), now);
      expect(result.triggered[0]!.trigger?.rule).toBe('official+news');
    }
    expect(updateIncidents({ incidents: [] }, [medium, { ...news(), credentialExposure: false }], now).triggered).toEqual([]);
  });

  it('a triggered incident does not trigger again within its window and preserves its wave', () => {
    const first = updateIncidents({ incidents: [] }, officialEvidence(), now);
    first.incidents[0]!.waveId = 'wave-1';
    const later = new Date('2026-10-29T00:00:00Z');
    const second = updateIncidents(first, [{ ...news(), publishedAt: later.toISOString() }], later);
    expect(second.triggered).toEqual([]);
    expect(second.incidents[0]).toMatchObject({ id: first.incidents[0]!.id, waveId: 'wave-1', trigger: first.incidents[0]!.trigger });
    expect(second.incidents[0]!.evidence).toHaveLength(5);
  });

  it('deduplicates evidence by itemKey across outlets and polls without reporting a change', () => {
    const first = updateIncidents({ incidents: [] }, [news(), { ...news(), owner: 'A different owner' }], now);
    expect(first.incidents[0]!.evidence).toHaveLength(1);
    expect(first.triggered).toEqual([]);
    const second = updateIncidents(first, [news()], now);
    expect(second.changed).toEqual([]);
    expect(second.incidents).toEqual(first.incidents);
  });

  it('closes the seven-day window from openedAt and creates a new incident at the exact boundary', () => {
    const first = updateIncidents({ incidents: [] }, [news()], now);
    const later = new Date('2026-10-30T12:00:00Z');
    const result = updateIncidents(first, [{ ...independentNews(), itemKey: itemKey('new report'), publishedAt: later.toISOString() }], later);
    expect(result.incidents).toHaveLength(2);
    expect(result.incidents[0]!.status).toBe('closed');
    expect(result.incidents[1]!.id).toMatch(/^inc-railway-20261030-[a-f0-9]{8}$/);
    expect(result.incidents[1]!.evidence).toHaveLength(1);
    expect(result.triggered).toEqual([]);
  });

  it('does not turn an expired report replay into another rotation', () => {
    const first = updateIncidents({ incidents: [] }, officialEvidence(), now);
    const result = updateIncidents(first, officialEvidence(), new Date('2026-11-04T12:00:00Z'));
    expect(result.incidents).toHaveLength(1);
    expect(result.incidents[0]!.status).toBe('closed');
    expect(result.triggered).toEqual([]);
  });

  it('does not corroborate different hosts or infer a host from a link', () => {
    const vercel = { ...independentNews(), title: 'Vercel breach exposes customer API keys' };
    const result = updateIncidents({ incidents: [] }, [news(), vercel], now);
    expect(result.incidents.map(incident => incident.host)).toEqual(['railway', 'vercel']);
    expect(result.triggered).toEqual([]);
    expect(updateIncidents({ incidents: [] }, [{ ...news(), title: 'A cloud company breach' }], now).incidents).toEqual([]);
  });

  it('never reopens an explicitly closed incident during its original window', () => {
    const first = updateIncidents({ incidents: [] }, [news()], now);
    const closed: Incident = { ...first.incidents[0]!, status: 'closed' };
    const result = updateIncidents({ incidents: [closed] }, officialEvidence(), now);
    expect(result.triggered).toEqual([]);
    expect(result.incidents).toHaveLength(1);
    expect(result.incidents[0]!.status).toBe('closed');
    const replay = updateIncidents(result, officialEvidence(), new Date('2026-11-04T12:00:00Z'));
    expect(replay.incidents).toHaveLength(1);
    expect(replay.triggered).toEqual([]);
  });
});
