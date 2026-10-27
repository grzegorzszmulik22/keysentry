import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import {
  DISPLAY_ONLY_URL_HOSTS, EGRESS_RULES, matchRule, rulesForUserFeeds, rulesForUserUrls,
} from '../../src/net/allowlist.js';
import type { EgressRule } from '../../src/types.js';
import { DEFAULT_BREACH_FEEDS } from '../../src/monitor/detectors/breach-feed.js';

async function sources(dir: string): Promise<string[]> {
  const files: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...await sources(path));
    else if (entry.name.endsWith('.ts')) files.push(path);
  }
  return files;
}

test('every https literal in src/hosts, src/providers and src/monitor is allow-listed or display-only', async () => {
  const templateHosts: Record<string, string[]> = {
    '${service}.amazonaws.com': ['iam.amazonaws.com', 'sts.amazonaws.com'],
  };
  let literals = 0;
  for (const dir of ['src/hosts', 'src/providers', 'src/monitor']) {
    for (const path of await sources(dir)) {
      const source = await readFile(path, 'utf8');
      const occurrences = [...source.matchAll(/https:\/\//g)].length;
      let checked = 0;
      for (const match of source.matchAll(/https:\/\/([^/'"\s`<>]+)/g)) {
        literals++;
        checked++;
        const authority = match[1]!;
        const hosts = authority.includes('${') ? templateHosts[authority] : [new URL(`https://${authority}`).hostname];
        expect(hosts, `Unreviewed URL host template in ${path}: ${authority}`).toBeDefined();
        for (const host of hosts ?? []) {
          const covered = matchRule(new URL(`https://${host}/`), EGRESS_RULES) !== null
            || DISPLAY_ONLY_URL_HOSTS.includes(host);
          expect(covered, `Unreviewed HTTPS literal in ${path}: ${host}`).toBe(true);
        }
      }
      expect(checked, `Every HTTPS literal must have a reviewed authority in ${path}`).toBe(occurrences);
    }
  }
  expect(literals).toBeGreaterThan(30);
});

test('every default breach feed has a feed-owned rule', () => {
  for (const feed of DEFAULT_BREACH_FEEDS) {
    expect(matchRule(new URL(feed.url), EGRESS_RULES)?.owner).toBe('feed');
  }
});

test('actual template expansions have narrow owners and do not allow lookalikes', () => {
  for (const host of ['iam.amazonaws.com', 'sts.amazonaws.com']) {
    expect(matchRule(new URL(`https://${host}/`), EGRESS_RULES)?.owner).toBe('aws');
  }
  expect(matchRule(new URL('https://project-abc.supabase.co/rest/v1/'), EGRESS_RULES)?.owner).toBe('supabase');
  expect(matchRule(new URL('https://project-abc.supabase.co.evil.com/rest/v1/'), EGRESS_RULES)).toBeNull();
  expect(matchRule(new URL('https://custom-project.example/rest/v1/'), EGRESS_RULES)).toBeNull();
  expect(matchRule(new URL('http://localhost:54321/rest/v1/'), EGRESS_RULES)).toBeNull();
});

test('GitHub API has the single shared host rule and release hosts share a release owner', () => {
  expect(EGRESS_RULES.filter(rule => rule.host === 'api.github.com')).toEqual([
    { host: 'api.github.com', owner: 'github-actions', purpose: 'GitHub API (Actions secrets, secret-scanning alerts)' },
  ]);
  for (const host of ['github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com']) {
    expect(matchRule(new URL(`https://${host}/`), EGRESS_RULES)?.owner).toBe('release');
  }
  expect(new Set(EGRESS_RULES.map(rule => rule.host)).size).toBe(EGRESS_RULES.length);
});

describe('matchRule', () => {
  const exact: EgressRule = { host: 'api.openai.com', purpose: 'OpenAI API', owner: 'openai' };
  const suffix: EgressRule = { host: '*.example.com', purpose: 'example API', owner: 'example' };
  test('normalises case, a trailing dot and the default HTTPS port', () => {
    expect(matchRule(new URL('https://API.OPENAI.COM.:443/v1/models'), [exact])).toBe(exact);
  });
  test.each([
    'https://api.openai.com.evil.com/x', 'https://evil.com/api.openai.com',
    'http://api.openai.com/x', 'https://1.2.3.4/x', 'https://[::1]/x',
    'https://user:pw@api.openai.com/x', 'https://api.openai.com:8443/x',
  ])('blocks an unsafe or unlisted URL: %s', url => {
    expect(matchRule(new URL(url), [exact, { ...exact, host: '1.2.3.4' }, { ...exact, host: '[::1]' }])).toBeNull();
  });
  test('suffix rules require a subdomain at a dot boundary', () => {
    expect(matchRule(new URL('https://one.two.example.com/'), [suffix])).toBe(suffix);
    for (const host of ['example.com', 'notexample.com', 'example.com.evil.com', '*.example.com']) {
      expect(matchRule(new URL(`https://${host}/`), [suffix])).toBeNull();
    }
  });
});

test('rulesForUserUrls creates exact user-owned host rules without widening siblings', () => {
  const rules = rulesForUserUrls(['https://FEEDS.EXAMPLE.COM./private?token=private', 'https://feeds.example.com/other'], 'notification webhook you configured');
  expect(rules).toEqual([{ host: 'feeds.example.com', owner: 'user', purpose: 'notification webhook you configured' }]);
  expect(matchRule(new URL('https://feeds.example.com/next'), rules)?.owner).toBe('user');
  expect(matchRule(new URL('https://sibling.example.com/'), rules)).toBeNull();
});

test('rulesForUserFeeds uses the fixed configured-feed purpose', () => {
  expect(rulesForUserFeeds(['https://feed.example.com/rss.xml'])).toEqual([
    { host: 'feed.example.com', owner: 'user', purpose: 'breach feed you configured' },
  ]);
});

test.each([
  ['http://FEED.EXAMPLE.COM/private?key=do-not-echo', 'feed.example.com'],
  ['https://name:password@feed.example.com/private?key=do-not-echo', 'feed.example.com'],
  ['https://feed.example.com:8443/private?key=do-not-echo', 'feed.example.com'],
  ['https://*.example.com/private', '*.example.com'],
  ['https://1.2.3.4/private', '1.2.3.4'],
  ['not a URL/private?key=do-not-echo', '(unparseable)'],
])('rulesForUserUrls rejects unsafe URL without exposing its path: %s', (url, host) => {
  let error: unknown;
  try { rulesForUserUrls([url], 'breach feed you configured'); } catch (caught) { error = caught; }
  expect(error).toBeInstanceOf(TypeError);
  expect((error as Error).message).toContain(host);
  for (const secret of ['private', 'do-not-echo', 'password']) expect((error as Error).message).not.toContain(secret);
});

test.each(['http://', 'https://user:password@', 'https://'])('invalid user URL errors redact secret-shaped host labels for %s', prefix => {
  const secret = `sk-or-v1-${'a'.repeat(64)}`;
  const suffix = prefix === 'https://' ? ':8443' : '';
  const url = `${prefix}${secret}.example.com${suffix}/private?query=do-not-echo`;
  let error: unknown;
  try { rulesForUserUrls([url], 'breach feed you configured'); } catch (caught) { error = caught; }
  expect(error).toBeInstanceOf(TypeError);
  expect((error as Error).message).toBe('Invalid user URL host: \u00abredacted\u00bb.example.com');
  expect((error as Error).message).not.toContain(secret);
});
