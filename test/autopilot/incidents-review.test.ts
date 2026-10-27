import { describe, expect, it } from 'vitest';
import { fingerprint } from '../../src/core/fingerprint.js';
import { DEFAULT_SOURCES, classifyItem } from '../../src/autopilot/sources.js';
import * as incidents from '../../src/autopilot/incidents.js';
import type { FeedItem } from '../../src/feeds/index.js';
import type { IncidentEvidence } from '../../src/types.js';

const itemKey = (id: string) => fingerprint(id, Buffer.alloc(32, 27));
const now = new Date('2026-11-02T12:00:00.000Z');
const source = (id: string) => DEFAULT_SOURCES.find(value => value.id === id)!;
const official = source('railway-blog');
const news = source('bleepingcomputer');
const otherNews = source('the-record');
const item = (title: string, summary = 'Customer environment variables were accessed. We urge customers to rotate credentials.',
  publishedAt: string | null = now.toISOString()): FeedItem => ({ id: title, title, summary, publishedAt, link: null });
const evidence = (value: FeedItem, outlet = official): IncidentEvidence => classifyItem(value, outlet, itemKey)!;
const advisory = (publishedAt: string | null = now.toISOString()) => evidence(item('Railway security incident', undefined, publishedAt));

describe('review: official advisory qualification (H1)', () => {
  it.each([
    ['vercel-blog', 'Vercel was not affected by the Okta security incident', 'No access to Vercel systems or customer environment variables.'],
    ['railway-blog', 'How to prepare your team for a data breach', 'A practical guide to incident response planning.'],
    ['github-security', 'Introducing breach notifications for GitHub secret scanning partners', 'Partners receive notifications for leaked tokens.'],
    ['railway-blog', 'Railway was not impacted by a security incident', 'Customer environment variables were accessed at another company.'],
    ['railway-blog', 'Railway denies breach after reports claimed customer API keys were exposed', 'The reports were unfounded.'],
    ['railway-blog', 'Railway confirms no breach occurred', 'Customer API keys were exposed in an unrelated example.'],
    ...['Prepare', 'Guide', 'Announcing', 'Best practices', 'Checklist', 'Webinar'].map(cue =>
      ['railway-blog', `${cue}: Railway security incident response`, 'Customer environment variables were accessed in our example.']),
  ])('does not authorize with an excluded official title: %s %s', (sourceId, title, summary) => {
    const classified = classifyItem(item(title!, summary), source(sourceId!), itemKey);
    const result = incidents.updateIncidents({ incidents: [] }, classified ? [classified] : [], now);
    expect(result.triggered).toEqual([]);
    // An excluded title cannot supply the official half of a news corroboration either.
    expect(incidents.updateIncidents({ incidents: [] }, [
      ...(classified ? [classified] : []), evidence(item('Railway breach exposes credentials'), news),
    ], now).triggered).toEqual([]);
  });

  it('alerts for a security title without an exposure claim instead of triggering', () => {
    const value = evidence(item('Final Report: Oct 21st Security Incident', 'The investigation is complete.'));
    expect(value).toMatchObject({ confidence: 'medium', credentialExposure: false });
    const result = incidents.updateIncidents({ incidents: [] }, [value], now);
    expect(result.triggered).toEqual([]);
    expect(result.incidents[0]?.status).toBe('alerted');
  });

  it.each(['Preliminary Report: Oct 21st Security Incident', 'Security Disclosure: Wednesday October 21st',
    'Security Disclosure Recommendation: Rotate PostgreSQL Database Credentials', 'Final Report: Oct 21st Security Incident'])(
    'retains Railway exposure and rotation advisories: %s', title => {
      // Exposure text recorded in notes/phase2-facts.md; the old feed fixture has abbreviated descriptions.
      const value = evidence(item(title));
      expect(value).toMatchObject({ confidence: 'high', credentialExposure: true });
      expect(incidents.updateIncidents({ incidents: [] }, [value], now).triggered).toHaveLength(1);
    });
});

describe('review: news platform subject (H2)', () => {
  const thirdParty = [
    'Supply chain attack on popular GitHub Action exposes CI/CD secrets',
    'GitHub Action compromise exposed CI/CD secrets in 23,000 repositories',
    'Compromised npm package on Vercel exposes customer API keys',
    'Railway integration compromised, exposing customer credentials',
    'GitHub workflow breach exposes secrets',
    'GitHub library compromise exposes API keys',
    'GitHub extension breach exposes tokens',
    'Vercel plugin compromise exposes credentials',
    'Railway app breach exposes credentials',
    'GitHub worm exposes customer API keys',
    'GitHub malware campaign exposes tokens',
    'Railway customer Acme Analytics breach exposes secrets',
    'Railway customer breached, exposing API keys',
    'GitHub user accounts compromised, exposing tokens',
    'Railway reports Okta was compromised, exposing credentials',
    'Railway warns after Acme Analytics data breach exposes API keys',
    'GitHub security alert: dependency attack exposes CI/CD secrets',
  ];
  it.each(thirdParty)('does not corroborate a third-party subject: %s', title => {
    const reports = [news, otherNews].map(outlet => evidence(item(title), outlet));
    expect(reports[0]).toMatchObject({ credentialExposure: false });
    expect(incidents.updateIncidents({ incidents: [] }, reports, now).triggered).toEqual([]);
  });

  it('rejects another breached company identified only in the body', () => {
    const value = evidence(item('Railway security incident exposes credentials',
      'Acme Analytics was breached. Customer API keys were stolen.'), news);
    expect(value.credentialExposure).toBe(false);
  });

  it('rejects a third-party component identified only in the body', () => {
    const value = evidence(item('GitHub security incident exposes credentials',
      'A third-party GitHub Action was compromised. Customer API keys were stolen.'), news);
    expect(value.credentialExposure).toBe(false);
  });

  it('keeps a direct breach of the GitHub Actions platform eligible', () => {
    const reports = [news, otherNews].map(outlet => evidence(item('GitHub Actions platform breach exposes customer secrets'), outlet));
    expect(reports[0]).toMatchObject({ credentialExposure: true });
    expect(incidents.updateIncidents({ incidents: [] }, reports.map((report, i) => ({ ...report, itemKey: itemKey(`direct-${i}`) })), now).triggered).toHaveLength(1);
  });
});

describe('review: evidence age and first-read baseline (C1)', () => {
  it.each(['2026-10-30T11:59:59.999Z', '2026-11-02T13:00:00.001Z', 'invalid', null])(
    'does not accept unverified or out-of-window evidence dated %s', date => {
      expect(incidents.updateIncidents({ incidents: [] }, [advisory(date)], now).incidents).toEqual([]);
    });

  it.each(['2026-10-30T12:00:00.000Z', '2026-11-02T13:00:00.000Z'])(
    'accepts the inclusive freshness boundary %s', date => {
      expect(incidents.updateIncidents({ incidents: [] }, [advisory(date)], now).triggered).toHaveLength(1);
    });

  it('requires both corroborating reports to be fresh at decision time', () => {
    const stale = evidence(item('Railway breach exposes customer secrets', undefined, '2026-10-30T11:59:59.999Z'), news);
    const fresh = { ...evidence(item('Railway breach exposes credentials'), otherNews), itemKey: itemKey('fresh-news') };
    expect(incidents.updateIncidents({ incidents: [] }, [stale, fresh], now).triggered).toEqual([]);
    const earlier = incidents.updateIncidents({ incidents: [] }, [stale], new Date('2026-11-01T12:00:00Z'));
    expect(incidents.updateIncidents(earlier, [fresh], now).triggered).toEqual([]);
  });

  it('baselines each source once, remembers all keys, and accepts only unseen eligible items', () => {
    const existing = item('Railway security incident');
    const undated = item('Railway breach exposes tokens', undefined, null);
    const initial = { incidents: [] };
    const first = incidents.filterNewItems(initial, official, [existing, undated], now, itemKey);
    expect(first.fresh).toEqual([]);
    expect(initial).toEqual({ incidents: [] });
    const later = new Date('2026-11-02T12:10:00Z');
    const newItem = item('Railway security disclosure');
    const newUndated = item('Railway breach exposes credentials', undefined, null);
    const stale = item('Old Railway security incident', undefined, '2026-01-01T00:00:00Z');
    const future = item('Future Railway security incident', undefined, '2026-12-01T00:00:00Z');
    const second = incidents.filterNewItems(JSON.parse(JSON.stringify(first.state)), official,
      [existing, undated, newItem, newUndated, stale, future, newItem], later, itemKey);
    expect(second.fresh).toEqual([newItem, newUndated]);
    expect(JSON.stringify(second.state)).not.toContain('Railway security incident');
    const classified = second.fresh.map(value => evidence(value));
    const saved = JSON.parse(JSON.stringify(second.state));
    expect(saved.sources[official.id].undatedFirstSeenAt[itemKey(newUndated.id)]).toBe(later.toISOString());
    const updated = incidents.updateIncidents(saved, classified, later);
    expect(updated.triggered).toHaveLength(1);
    expect(updated.incidents[0]?.evidence).toHaveLength(2);
    expect(incidents.filterNewItems(updated, official, [newItem, newUndated, stale, future], later, itemKey).fresh).toEqual([]);
    expect(incidents.filterNewItems(second.state, news, [newItem], later, itemKey).fresh).toEqual([]);
  });

  it('accepts an undated item only when first observed after the source baseline and for 72 hours', () => {
    const baseline = incidents.filterNewItems({ incidents: [] }, official, [], new Date('2026-11-01T12:00:00Z'), itemKey);
    const undated = item('Railway security disclosure', undefined, null);
    const observed = incidents.filterNewItems(baseline.state, official, [undated], now, itemKey);
    const classified = evidence(undated);
    expect(incidents.updateIncidents(observed.state, [classified], now).triggered).toHaveLength(1);
    expect(incidents.updateIncidents(observed.state, [classified], new Date('2026-11-05T12:00:00.001Z')).triggered).toEqual([]);
  });

  it('can corroborate two post-baseline undated reports using their first-seen times', () => {
    const baselineAt = new Date('2026-11-01T12:00:00Z');
    const one = incidents.filterNewItems({ incidents: [] }, news, [], baselineAt, itemKey);
    const two = incidents.filterNewItems(one.state, otherNews, [], baselineAt, itemKey);
    const first = item('Railway breach exposes customer secrets', undefined, null);
    const second = item('Railway breach exposes API keys', undefined, null);
    const seenOne = incidents.filterNewItems(two.state, news, [first], now, itemKey);
    const seenTwo = incidents.filterNewItems(seenOne.state, otherNews, [second], now, itemKey);
    expect(incidents.updateIncidents(seenTwo.state, [evidence(first, news), evidence(second, otherNews)], now)
      .triggered[0]?.trigger?.rule).toBe('corroborated-news');
  });
});

describe('review: one host wave during cooldown (M1)', () => {
  const laterEvidence = (at: Date) => evidence(item('Final Report: Oct 21st Security Incident', undefined, at.toISOString()));
  it('alerts on a day-nine follow-up without another trigger and preserves the original wave', () => {
    const first = incidents.updateIncidents({ incidents: [] }, [advisory()], now);
    first.incidents[0]!.waveId = 'wave-1';
    const later = new Date('2026-11-11T12:00:00Z');
    const result = incidents.updateIncidents(first, [laterEvidence(later)], later);
    expect(result.triggered).toEqual([]);
    expect(result.incidents[0]).toMatchObject({ status: 'closed', waveId: 'wave-1' });
    expect(result.incidents[1]?.status).toBe('alerted');
    const repeated = incidents.updateIncidents(result, [{ ...laterEvidence(later), itemKey: itemKey('more followup') }], later);
    expect(repeated.triggered).toEqual([]);
  });

  it('uses trigger time for the cooldown even when the incident opened earlier', () => {
    const earlier = new Date('2026-10-28T12:00:00Z');
    const first = incidents.updateIncidents({ incidents: [] }, [evidence(item('Railway security update', 'Investigation ongoing.', earlier.toISOString()))], earlier);
    const triggered = incidents.updateIncidents(first, [advisory()], now);
    expect(triggered.triggered).toHaveLength(1);
    const later = new Date('2026-11-29T12:00:00Z');
    expect(incidents.updateIncidents(triggered, [laterEvidence(later)], later).triggered).toEqual([]);
  });

  it('permits a new incident at the cooldown boundary and supports a longer configured cooldown', () => {
    const first = incidents.updateIncidents({ incidents: [] }, [advisory()], now);
    const later = new Date('2026-12-02T12:00:00Z');
    expect(incidents.updateIncidents(first, [laterEvidence(later)], later).triggered).toHaveLength(1);
    expect(incidents.updateIncidents(first, [laterEvidence(later)], later, { cooldownDays: 60 }).triggered).toEqual([]);
  });
});
