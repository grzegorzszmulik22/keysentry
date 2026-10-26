import { describe, expect, it } from 'vitest';
import { buildInventory } from '../../src/core/inventory.js';
import { detectGithubLeaks } from '../../src/monitor/detectors/github-leaks.js';
import type { DetectorContext } from '../../src/monitor/context.js';
import { createMonitorState } from '../../src/monitor/state.js';
import { FakeHttp, json, silentLogger } from '../helpers/fake-http.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

async function setup(http: FakeHttp) {
  const key = Buffer.alloc(32, 13);
  const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-0123456789abcdef0123456789abcdef-');
  const issued = provider.issue();
  const host = new FakeHost('railway');
  const service = host.addService('api', { OPENROUTER_API_KEY: issued.value });
  const inventory = buildInventory([{ host: host.id, services: [{ service, vars: await host.readVariables(service) }] }], key);
  const ctx: DetectorContext = { inventory, hosts: [host], providers: [provider],
    providerCtx: { http, credentials: { GITHUB_TOKEN: 'admin-token' }, log: silentLogger }, state: createMonitorState(),
    fingerprintKey: key, log: silentLogger, clock: () => new Date('2026-10-26T12:00:00Z') };
  return { ctx, issued };
}

describe('GitHub secret scanning', () => {
  it('fingerprints alert secrets, matches a host cluster, and dedupes repeated alerts', async () => {
    const http = new FakeHttp();
    const { ctx, issued } = await setup(http);
    http.on('GET', /^https:\/\/api\.github\.com\/repos\/team\/app\/secret-scanning\/alerts\?state=open&per_page=100$/, () => json(200, [
      { number: 4, secret: issued.value, html_url: `https://example.invalid/${issued.value}` },
      { number: 5, secret: 'an-unrelated-secret' },
    ]));
    const signals = await detectGithubLeaks(ctx, { repos: ['team/app'] });
    expect(signals).toHaveLength(1);
    expect(signals[0]).toMatchObject({ kind: 'leak_detected', confidence: 'high', clusterIds: [ctx.inventory.clusters[0]!.id] });
    expect(await detectGithubLeaks(ctx, { repos: ['team/app'] })).toEqual([]);
    expect(JSON.stringify({ signals, state: ctx.state })).not.toContain(issued.value);
    expect(http.calls[0]!.headers?.Authorization).toBe('Bearer admin-token');
  });

  it('keeps identical alert numbers in different repositories separate', async () => {
    const http = new FakeHttp();
    const { ctx, issued } = await setup(http);
    http.on('GET', /\/secret-scanning\/alerts\?/, () => json(200, [{ number: 1, secret: issued.value }]));
    const signals = await detectGithubLeaks(ctx, { repos: ['team/app', 'team/other'], token: 'explicit-token' });
    expect(signals).toHaveLength(2);
    expect(http.calls.every(call => call.headers?.Authorization === 'Bearer explicit-token')).toBe(true);
  });

  it('uses fixed diagnostics when a response body contains secrets', async () => {
    const http = new FakeHttp();
    const { ctx, issued } = await setup(http);
    const logged: string[] = [];
    ctx.log = { ...silentLogger, warn: message => logged.push(message) };
    http.on('GET', /\/alerts\?/, () => json(403, { message: issued.value }));
    expect(await detectGithubLeaks(ctx, { repos: ['team/app'] })).toEqual([]);
    expect(logged).toHaveLength(1);
    expect(JSON.stringify(logged)).not.toContain(issued.value);
  });
});
