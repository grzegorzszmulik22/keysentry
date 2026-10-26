import { describe, expect, it } from 'vitest';
import { buildInventory } from '../../src/core/inventory.js';
import { detectBreachFeeds } from '../../src/monitor/detectors/breach-feed.js';
import type { DetectorContext } from '../../src/monitor/context.js';
import { createMonitorState } from '../../src/monitor/state.js';
import { FakeHttp, silentLogger, text } from '../helpers/fake-http.js';
import { svc } from '../helpers/fakes.js';

const key = Buffer.alloc(32, 11);
const at = new Date('2026-10-26T12:00:00Z');
const rss = `<rss version="2.0"><channel><title>Updates</title><item>
  <title>Railway security incident</title><description>Unauthorized access to environment variables</description>
  <link>https://example.invalid/advisory/1</link></item><item><title>Railway deploys faster</title>
  <link>https://example.invalid/product/1</link></item></channel></rss>`;

function context(http: FakeHttp, host: 'railway' | 'vercel' = 'railway'): DetectorContext {
  const inventory = buildInventory([{ host, services: [{ service: svc(host, 'api'), vars: [
    { name: 'OPENROUTER_API_KEY', value: 'sk-or-v1-' + '0123456789abcdef'.repeat(4), sealed: false },
  ] }] }], key, at);
  return { inventory, hosts: [], providers: [], providerCtx: { http, credentials: {}, log: silentLogger },
    state: createMonitorState(), fingerprintKey: key, log: silentLogger, clock: () => at };
}

describe('breach feeds', () => {
  it('emits a Railway advisory only for an inventoried Railway host and dedupes its link', async () => {
    const http = new FakeHttp().on('GET', /^https:\/\/example\.invalid\/rss$/, () => text(200, rss));
    const ctx = context(http);
    const signals = await detectBreachFeeds(ctx, [{ url: 'https://example.invalid/rss' }]);
    expect(signals).toHaveLength(1);
    expect(signals[0]).toMatchObject({ kind: 'host_breach_advisory', confidence: 'medium', host: 'railway',
      clusterIds: [ctx.inventory.clusters[0]!.id] });
    expect(await detectBreachFeeds(ctx, [{ url: 'https://example.invalid/rss' }])).toEqual([]);
    expect(await detectBreachFeeds(context(http, 'vercel'), [{ url: 'https://example.invalid/rss' }])).toEqual([]);
  });

  it('parses namespaced Atom entries and selects an alternate link', async () => {
    const atom = `<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Vercel security incident</title>
      <summary>Environment variables may be compromised</summary><link rel="self" href="https://example.invalid/api/2"/>
      <link rel="alternate" href="https://example.invalid/advisory/2"/></entry></feed>`;
    const http = new FakeHttp().on('GET', /\/atom$/, () => text(200, atom));
    const ctx = context(http, 'vercel');
    const signals = await detectBreachFeeds(ctx, [{ url: 'https://example.invalid/atom', host: 'vercel' }]);
    expect(signals).toHaveLength(1);
    expect(signals[0]).toMatchObject({ kind: 'host_breach_advisory', host: 'vercel' });
    expect(await detectBreachFeeds(ctx, [{ url: 'https://example.invalid/atom' }])).toEqual([]);
  });

  it('does not copy untrusted titles, links or response failures into state or signals', async () => {
    const secret = 'secret-that-must-never-be-written';
    const xml = `<rss><channel><item><title>Railway breach ${secret}</title><link>https://example.invalid/${secret}</link></item></channel></rss>`;
    const http = new FakeHttp().on('GET', /\/rss$/, () => text(200, xml));
    const ctx = context(http);
    const signals = await detectBreachFeeds(ctx, [{ url: 'https://example.invalid/rss' }]);
    expect(signals).toHaveLength(1);
    expect(JSON.stringify({ signals, state: ctx.state })).not.toContain(secret);
  });
});
