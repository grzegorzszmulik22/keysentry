import { describe, expect, it } from 'vitest';
import { createMonitorState, usageKey, type UsageBucket } from '../../src/monitor/state.js';
import { detectUsage } from '../../src/monitor/detectors/usage.js';
import type { ProviderAdapter } from '../../src/types.js';
import { FakeHttp, json, silentLogger } from '../helpers/fake-http.js';
import { unusedDays } from '../../src/hygiene/unused.js';
import { createHygieneState, hygieneReport } from '../../src/hygiene/age.js';
import { FIRST, inventory, NOW } from './fixtures.js';

const HOUR = 3_600_000;
const coverage = { from: '2026-09-01T00:00:00.000Z', to: NOW };
function history(days = 30): UsageBucket[] {
  return Array.from({ length: days * 24 + 1 }, (_, index) => ({
    hour: new Date(Date.parse(NOW) - (days * 24 - index) * HOUR).toISOString(), costUsd: 0, requests: 0,
  }));
}

describe('unused keys', () => {
  it('requires continuous zero requests and cost for at least 30 days', () => {
    expect(unusedDays(history(), NOW, coverage)).toBe(30);
    expect(unusedDays(history(35), NOW, coverage)).toBe(35);
    expect(unusedDays(history(29), NOW, coverage)).toBeUndefined();
    const unsorted = history().reverse();
    expect(unusedDays(unsorted, NOW, coverage)).toBe(30);
    expect(unsorted[0]?.hour).toBe(NOW);
  });

  it('leaves unknown absent for gaps, stale data, unsupported request metrics and nonzero usage', () => {
    expect(unusedDays([], NOW, coverage)).toBeUndefined();
    expect(unusedDays(history().filter((_, index) => index !== 42), NOW, coverage)).toBeUndefined();
    expect(unusedDays(history().slice(0, -1), NOW, coverage)).toBeUndefined();
    expect(unusedDays(history().map(({ requests: _requests, ...bucket }) => bucket), NOW, coverage)).toBeUndefined();
    for (const change of [{ costUsd: 1 }, { requests: 1 }, { costUsd: NaN }, { requests: -1 }]) {
      const buckets = history();
      Object.assign(buckets[42]!, change);
      expect(unusedDays(buckets, NOW, coverage)).toBeUndefined();
    }
  });

  it('cannot hide usage with duplicate buckets or a future timestamp', () => {
    const buckets = history();
    buckets.push({ ...buckets[12]!, requests: 2 });
    expect(unusedDays(buckets, NOW, coverage)).toBeUndefined();
    expect(unusedDays([{ hour: '2099-01-01T00:00:00.000Z', costUsd: 0, requests: 0 }], NOW, coverage)).toBeUndefined();
  });

  it('looks up namespaced provider usage in hygieneReport and omits unavailable metrics', () => {
    const monitor = createMonitorState();
    monitor.keyRefs[FIRST] = 'key-ref';
    monitor.usageHistory[usageKey('openrouter', 'key-ref')] = history();
    const usageCoverage = { [usageKey('openrouter', 'key-ref')]: coverage };
    expect(hygieneReport({ state: createHygieneState(), inventory: inventory(), monitor, now: NOW, usageCoverage })[0]?.unusedDays).toBe(30);
    monitor.usageHistory[usageKey('openrouter', 'key-ref')] = [];
    expect(hygieneReport({ state: createHygieneState(), inventory: inventory(), monitor, now: NOW, usageCoverage })[0]).not.toHaveProperty('unusedDays');
  });

  it('requires evidence of complete windows, not just a sequence of zero snapshots', () => {
    expect(unusedDays(history(), NOW)).toBeUndefined();
    expect(unusedDays(history(), NOW, { ...coverage, to: '2026-10-27T11:59:59.000Z' })).toBeUndefined();
    expect(unusedDays(history(), NOW, { ...coverage, from: '2026-09-28T00:00:00.000Z' })).toBeUndefined();
    expect(unusedDays(history(), NOW, { from: 'invalid', to: NOW })).toBeUndefined();
  });

  it('does not label an active key unused when hour-to-date monitor polls miss later activity', async () => {
    const monitor = createMonitorState();
    monitor.keyRefs[FIRST] = 'key-ref';
    let clock = new Date(Date.parse(NOW) - 30 * 24 * HOUR + 5 * 60_000);
    const http = new FakeHttp().on('POST', /^https:\/\/api\.openai\.com\/usage-fixture$/, request => {
      const { from, to } = JSON.parse(request.body!);
      // The key is used at :10 every hour, after the :05 monitor poll.
      const requestAt = Math.floor(Date.parse(from) / HOUR) * HOUR + 10 * 60_000;
      const requests = Date.parse(to) >= requestAt ? 1 : 0;
      return json(200, { keyRef: 'key-ref', from, to, costUsd: requests, requests });
    });
    const provider: ProviderAdapter = { id: 'openrouter', method: 'auto',
      verify: async () => ({ ok: true }), guidance: () => ({ url: '', steps: [] }),
      async usage(_ref, window, ctx) {
        return (await ctx.http.request({ method: 'POST', url: 'https://api.openai.com/usage-fixture',
          body: JSON.stringify({ from: window.from.toISOString(), to: window.to.toISOString() }) })).json();
      } };
    const ctx = { inventory: inventory(), hosts: [], providers: [provider], state: monitor,
      fingerprintKey: Buffer.alloc(32, 1), log: silentLogger,
      providerCtx: { http, credentials: {}, log: silentLogger }, clock: () => clock };
    for (let hour = 0; hour < 720; hour++) {
      await detectUsage(ctx);
      clock = new Date(clock.getTime() + HOUR);
    }
    clock = new Date(NOW);
    await detectUsage(ctx);
    expect(monitor.usageHistory[usageKey('openrouter', 'key-ref')]).toHaveLength(721);
    expect(hygieneReport({ state: createHygieneState(), inventory: ctx.inventory, monitor, now: NOW })[0])
      .not.toHaveProperty('unusedDays');
  });
});
