import { describe, expect, it } from 'vitest';
import { FakeHttp, json, silentLogger } from '../helpers/fake-http.js';
import { createMonitorState, usageKey } from '../../src/monitor/state.js';
import { createHygieneState } from '../../src/hygiene/age.js';
import { applySpendLimits, planSpendLimits, spendLimitAvailability, type SpendLimitsInput } from '../../src/hygiene/spend.js';
import { cluster, FIRST, inventory, NOW, SECOND } from './fixtures.js';

function input(): SpendLimitsInput {
  const state = createHygieneState();
  state.settings.spendCapsUsd = { openrouter: 25, openai: 10 };
  const monitor = createMonitorState();
  monitor.keyRefs = { [FIRST]: 'key-hash', [SECOND]: 'openai-ref' };
  monitor.cumulativeTotals[usageKey('openrouter', 'key-hash')] = { at: NOW, costUsd: 4 };
  return { inventory: inventory([cluster(), cluster(SECOND, 'openai')]), state, monitor,
    providerKeys: { openrouter: [{ keyRef: 'key-hash', limitUsd: null }] } };
}

describe('spend limit planning and application', () => {
  it('proposes only OpenRouter limits within the user cap and reports unavailable providers plainly', () => {
    const source = input();
    const before = JSON.stringify(source);
    expect(planSpendLimits(source)).toEqual([{ clusterId: FIRST, keyRef: 'key-hash', limitUsd: 25,
      reason: 'Set the key limit to the configured provider cap.' }]);
    expect(spendLimitAvailability(source.inventory)).toEqual([
      { clusterId: FIRST, provider: 'openrouter', available: true },
      { clusterId: SECOND, provider: 'openai', available: false, reason: 'not available from this provider' },
    ]);
    expect(JSON.stringify(source)).toBe(before);
  });

  it('never proposes a cap below recorded current-period spend, including a zero cap', () => {
    const source = input();
    source.currentPeriodSpendUsd = { [FIRST]: 26 };
    expect(planSpendLimits(source)).toEqual([]);
    source.currentPeriodSpendUsd[FIRST] = 25;
    expect(planSpendLimits(source)[0]?.limitUsd).toBe(25);
    source.state.settings.spendCapsUsd.openrouter = 0;
    expect(planSpendLimits(source)).toEqual([]);
    source.currentPeriodSpendUsd[FIRST] = 0;
    expect(planSpendLimits(source)[0]?.limitUsd).toBe(0);
  });

  it('preserves existing tighter limits and skips keys without a configured cap, ref or known spend', () => {
    const source = input();
    source.providerKeys!.openrouter![0]!.limitUsd = 10;
    expect(planSpendLimits(source)).toEqual([]);
    source.providerKeys!.openrouter![0]!.limitUsd = 50;
    expect(planSpendLimits(source)[0]?.limitUsd).toBe(25);
    delete source.state.settings.spendCapsUsd.openrouter;
    expect(planSpendLimits(source)).toEqual([]);
    source.state.settings.spendCapsUsd.openrouter = 25;
    delete source.monitor.keyRefs[FIRST];
    expect(planSpendLimits(source)).toEqual([]);
    source.monitor.keyRefs[FIRST] = 'key-hash';
    source.monitor.cumulativeTotals = {};
    source.monitor.usageHistory[usageKey('openrouter', 'key-hash')] = [{ hour: NOW, costUsd: 0, requests: 0 }];
    expect(planSpendLimits(source)).toEqual([]);
  });

  it('uses lifetime spend conservatively unless a current-period snapshot is explicitly supplied', () => {
    const source = input();
    source.monitor.cumulativeTotals[usageKey('openrouter', 'key-hash')]!.costUsd = 100;
    expect(planSpendLimits(source)).toEqual([]);
    source.currentPeriodSpendUsd = { [usageKey('openrouter', 'key-hash')]: 5 };
    expect(planSpendLimits(source)[0]?.limitUsd).toBe(25);
  });

  it('refuses invalid caps or spend counters without echoing untrusted input', () => {
    for (const cap of [-1, NaN, Infinity]) {
      const source = input();
      source.state.settings.spendCapsUsd.openrouter = cap;
      expect(() => planSpendLimits(source)).toThrow('Invalid spending cap.');
    }
    for (const spent of [-1, NaN, Infinity]) {
      const source = input();
      source.currentPeriodSpendUsd = { [FIRST]: spent };
      expect(() => planSpendLimits(source)).toThrow('Invalid spending counter.');
    }
  });

  it('defaults to a dry run and applies only the reviewed limits through the adapter', async () => {
    const http = new FakeHttp().on('PATCH', /^https:\/\/openrouter\.ai\/api\/v1\/keys\/key-hash$/, req => {
      expect(JSON.parse(req.body!)).toEqual({ limit: 25 });
      return json(200, { data: {} });
    });
    const ctx = { http, log: silentLogger, credentials: { OPENROUTER_PROVISIONING_KEY: 'provisioning-test' } };
    const preview = await applySpendLimits(input(), ctx);
    expect(preview.dryRun).toBe(true);
    expect(preview.plans).toHaveLength(1);
    expect(preview.applied).toEqual([]);
    expect(preview.unavailable[0]?.reason).toBe('not available from this provider');
    expect(http.calls).toEqual([]);
    const result = await applySpendLimits(input(), ctx, { dryRun: false });
    expect(result.applied).toEqual([FIRST]);
    expect(http.calls).toHaveLength(1);
  });

  it('validates the entire plan before applying any change', async () => {
    const source = input();
    const key = cluster(SECOND);
    source.inventory.clusters.push(key);
    source.monitor.keyRefs[SECOND] = 'other-key';
    source.currentPeriodSpendUsd = { [FIRST]: 4, [SECOND]: NaN };
    const http = new FakeHttp();
    await expect(applySpendLimits(source, { http, log: silentLogger, credentials: {} }, { dryRun: false }))
      .rejects.toThrow('Invalid spending counter.');
    expect(http.calls).toEqual([]);
  });

  it('stops after a failed update and never reflects provider error bodies', async () => {
    const source = input();
    source.inventory.clusters = [cluster(), cluster(SECOND)];
    source.monitor.keyRefs[SECOND] = 'other-key';
    source.currentPeriodSpendUsd = { [FIRST]: 4, [SECOND]: 2 };
    const http = new FakeHttp().on('PATCH', /\/keys\/key-hash$/, () => json(503, { error: 'provider-sensitive-body' }));
    const promise = applySpendLimits(source, { http, log: silentLogger,
      credentials: { OPENROUTER_PROVISIONING_KEY: 'provisioning-test' } }, { dryRun: false });
    await expect(promise).rejects.toThrow('OpenRouter request failed (HTTP 503)');
    await expect(promise).rejects.not.toThrow('provider-sensitive-body');
    expect(http.calls).toHaveLength(1);
  });
});
