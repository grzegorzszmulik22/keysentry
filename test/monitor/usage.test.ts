import { describe, expect, it } from 'vitest';
import { scanHosts } from '../../src/core/inventory.js';
import type { ProviderAdapter } from '../../src/types.js';
import type { DetectorContext } from '../../src/monitor/context.js';
import { detectUsage } from '../../src/monitor/detectors/usage.js';
import { createMonitorState, usageKey } from '../../src/monitor/state.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';

const HOUR = 60 * 60 * 1000;

async function setup() {
  const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-aB3cD7eF9gH2iJ4kL6mN8pQ0');
  const key = provider.issue();
  const host = new FakeHost('railway');
  host.addService('api', { OPENROUTER_API_KEY: key.value });
  let time = new Date('2026-10-20T00:30:00.000Z');
  const ctx: DetectorContext = {
    inventory: await scanHosts([host], Buffer.alloc(32, 1), silentLogger),
    hosts: [host], providers: [provider],
    providerCtx: { http: new FakeHttp(), credentials: {}, log: silentLogger },
    state: createMonitorState(), fingerprintKey: Buffer.alloc(32, 1), log: silentLogger,
    clock: () => time,
  };
  return { ctx, provider, key, nextHour: () => { time = new Date(time.getTime() + HOUR); },
    advance: (ms: number) => { time = new Date(time.getTime() + ms); } };
}

async function train(hours = 72) {
  const test = await setup();
  await detectUsage(test.ctx);
  for (let i = 0; i < hours; i++) {
    test.nextHour();
    test.provider.spend(test.key.ref, 1, 10, 'normal-model');
    expect(await detectUsage(test.ctx)).toEqual([]);
  }
  test.nextHour();
  return test;
}

describe('usage detector', () => {
  it('reports a 30x hour with high confidence after three normal days', async () => {
    const { ctx, provider, key } = await train();
    provider.spend(key.ref, 30, 300, 'normal-model');
    expect(await detectUsage(ctx)).toMatchObject([{
      kind: 'usage_anomaly', confidence: 'high', clusterIds: [ctx.inventory.clusters[0]!.id],
    }]);
  });

  it('does not report a 1.5x hour', async () => {
    const { ctx, provider, key } = await train();
    provider.spend(key.ref, 1.5, 15, 'normal-model');
    expect(await detectUsage(ctx)).toEqual([]);
  });

  it('does not report a $1.50 unseen model on the first window poll', async () => {
    const { ctx, provider } = await setup();
    provider.usage = async (keyRef, window) => ({
      keyRef, from: window.from.toISOString(), to: window.to.toISOString(),
      costUsd: 1.5, requests: 1, byModel: { 'new-model': 1.5 },
    });
    expect(await detectUsage(ctx)).toEqual([]);
  });

  it('suppresses floor-only anomalies until 24 historical hourly buckets exist', async () => {
    const { ctx, provider, key, nextHour } = await setup();
    await detectUsage(ctx);
    for (let hour = 1; hour < 23; hour++) {
      nextHour();
      provider.spend(key.ref, 1, 10, 'normal-model');
      expect(await detectUsage(ctx)).toEqual([]);
    }
    nextHour();
    provider.spend(key.ref, 100, 1000, 'normal-model');
    expect(await detectUsage(ctx)).toEqual([]);
  });

  it('honors explicit hourly budgets while suppressing floor checks during warmup', async () => {
    const { ctx, provider, key, nextHour } = await setup();
    await detectUsage(ctx);
    nextHour();
    provider.spend(key.ref, 0.5, 1, 'normal-model');
    expect(await detectUsage(ctx, { floorUsd: 0.1 })).toEqual([]);
    expect(await detectUsage(ctx, { hourlyBudgets: { [ctx.inventory.clusters[0]!.id]: 0.25 } }))
      .toMatchObject([{ confidence: 'high', kind: 'usage_anomaly' }]);
    expect(await detectUsage(ctx, { hourlyBudgets: { [usageKey(provider.id, key.ref)]: 0.25 } }))
      .toMatchObject([{ confidence: 'high', kind: 'usage_anomaly' }]);
  });

  it('reports a newly expensive model with medium confidence', async () => {
    const { ctx, provider, key } = await train();
    provider.spend(key.ref, 1.2, 1, 'new-expensive-model');
    expect(await detectUsage(ctx)).toMatchObject([{ kind: 'usage_anomaly', confidence: 'medium' }]);
  });

  it('diffs cumulative costs, requests and models, accumulating partial hours', async () => {
    const { ctx, provider, key, advance } = await setup();
    provider.spend(key.ref, 100, 1000, 'normal-model');
    expect(await detectUsage(ctx)).toEqual([]);
    advance(5 * 60 * 1000);
    provider.spend(key.ref, 0.4, 4, 'normal-model');
    await detectUsage(ctx);
    advance(5 * 60 * 1000);
    provider.spend(key.ref, 0.6, 6, 'normal-model');
    await detectUsage(ctx);
    const bucket = ctx.state.usageHistory[usageKey('openrouter', key.ref)]!.at(-1)!;
    expect(bucket.costUsd).toBeCloseTo(1);
    expect(bucket.requests).toBe(10);
    expect(Object.values(bucket.byModel ?? {})).toEqual([expect.closeTo(1)]);
    expect(await detectUsage(ctx)).toEqual([]);
    expect(ctx.state.usageHistory[usageKey('openrouter', key.ref)]!.at(-1)!.costUsd).toBeCloseTo(1);
  });

  it('spreads daily cron deltas across 24 hourly buckets instead of reporting a spike', async () => {
    const { ctx, provider, key, advance } = await train();
    // train() has already advanced one hour beyond its last poll.
    advance(23 * HOUR);
    provider.spend(key.ref, 24, 240, 'normal-model');
    expect(await detectUsage(ctx)).toEqual([]);
    const spread = ctx.state.usageHistory[usageKey(provider.id, key.ref)]!.slice(-24);
    expect(spread).toHaveLength(24);
    for (const bucket of spread) {
      expect(bucket.costUsd).toBe(1);
      expect(bucket.requests).toBe(10);
      expect(Object.values(bucket.byModel ?? {})).toEqual([1]);
    }
    expect(spread[0]!.hour).toBe('2026-10-23T01:00:00.000Z');
    expect(spread[23]!.hour).toBe('2026-10-24T00:00:00.000Z');
  });

  it('compares an elevated gap average against the baseline recorded before the gap', async () => {
    const { ctx, provider, key, advance } = await train();
    advance(23 * HOUR);
    provider.spend(key.ref, 240, 2400, 'normal-model');
    expect(await detectUsage(ctx)).toMatchObject([{
      kind: 'usage_anomaly', confidence: 'medium',
      evidence: { costUsd: 10, baselineUsd: 1, baselineHours: 73, thresholdUsd: 5 },
    }]);
  });

  it('compares models from a cumulative gap against those known before the gap', async () => {
    const { ctx, provider, key, advance } = await train();
    advance(23 * HOUR);
    provider.spend(key.ref, 36, 24, 'new-expensive-model');
    expect(await detectUsage(ctx)).toMatchObject([{
      kind: 'usage_anomaly', confidence: 'medium', evidence: { costUsd: 1.5, newModelCount: 1 },
    }]);
  });

  it('preserves earlier hourly spend when distributing a multi-hour delta', async () => {
    const { ctx, provider, key, advance } = await setup();
    await detectUsage(ctx);
    advance(5 * 60 * 1000);
    provider.spend(key.ref, 0.4, 4, 'normal-model');
    await detectUsage(ctx);
    advance(3 * HOUR);
    provider.spend(key.ref, 6, 60, 'normal-model');
    expect(await detectUsage(ctx, { hourlyBudgets: { [usageKey(provider.id, key.ref)]: 3 } })).toEqual([]);
    const history = ctx.state.usageHistory[usageKey(provider.id, key.ref)]!;
    expect(history.map(bucket => bucket.costUsd)).toEqual([0.4, 2, 2, 2]);
    expect(history.map(bucket => bucket.requests)).toEqual([4, 20, 20, 20]);
    expect(history.map(bucket => Object.values(bucket.byModel ?? {}))).toEqual([[0.4], [2], [2], [2]]);
  });

  it('supports cumulative gaps of exactly seven days', async () => {
    const { ctx, provider, key, advance } = await setup();
    await detectUsage(ctx);
    advance(7 * 24 * HOUR);
    provider.spend(key.ref, 168, 1680, 'normal-model');
    expect(await detectUsage(ctx, { hourlyBudgets: { [ctx.inventory.clusters[0]!.id]: 2 } })).toEqual([]);
    const history = ctx.state.usageHistory[usageKey(provider.id, key.ref)]!;
    expect(history).toHaveLength(169);
    expect(history[0]!.costUsd).toBe(0);
    expect(history.slice(1).map(bucket => bucket.costUsd)).toEqual(Array(168).fill(1));
  });

  it('starts a silent new cumulative series after gaps longer than seven days', async () => {
    const { ctx, provider, key, nextHour, advance } = await setup();
    await detectUsage(ctx);
    nextHour();
    provider.spend(key.ref, 1, 10, 'normal-model');
    await detectUsage(ctx);
    advance(7 * 24 * HOUR + 1);
    provider.spend(key.ref, 1000, 10000, 'new-model');
    const hourlyBudgets = { [ctx.inventory.clusters[0]!.id]: 0.25 };
    expect(await detectUsage(ctx, { hourlyBudgets })).toEqual([]);
    const history = ctx.state.usageHistory[usageKey(provider.id, key.ref)]!;
    expect(history).toHaveLength(1);
    expect(history[0]).toMatchObject({ costUsd: 0, requests: 0, byModel: {} });
    nextHour();
    provider.spend(key.ref, 0.5, 5, 'normal-model');
    expect(await detectUsage(ctx, { hourlyBudgets })).toMatchObject([{
      kind: 'usage_anomaly', confidence: 'high', evidence: { costUsd: 0.5 },
    }]);
  });

  it('starts a new series when a cumulative cost counter resets', async () => {
    const { ctx, provider, key, nextHour } = await setup();
    await detectUsage(ctx);
    nextHour();
    provider.spend(key.ref, 1, 10, 'normal-model');
    await detectUsage(ctx);
    nextHour();
    const record = provider.keys.get(key.ref)!;
    record.costUsd = 0.1; record.requests = 1; record.byModel = { 'normal-model': 0.1 };
    expect(await detectUsage(ctx)).toEqual([]);
    const history = ctx.state.usageHistory[usageKey('openrouter', key.ref)]!;
    expect(history).toHaveLength(1);
    expect(history[0]!.costUsd).toBe(0);
    nextHour();
    provider.spend(key.ref, 0.3, 3, 'normal-model');
    await detectUsage(ctx);
    expect(ctx.state.usageHistory[usageKey('openrouter', key.ref)]!.at(-1)!.costUsd).toBeCloseTo(0.3);
  });

  it('replaces a window sample in the same hour and prunes history older than 30 days', async () => {
    const { ctx, provider, key, advance } = await setup();
    let amount = 0.5;
    const windowProvider: ProviderAdapter = {
      id: provider.id, method: provider.method,
      verify: provider.verify.bind(provider), guidance: provider.guidance.bind(provider),
      resolveKeyRef: provider.resolveKeyRef.bind(provider),
      usage: async (keyRef, window) => ({ keyRef, from: window.from.toISOString(), to: window.to.toISOString(),
        costUsd: amount, requests: amount * 10, byModel: { normal: amount } }),
    };
    ctx.providers = [windowProvider];
    await detectUsage(ctx);
    amount = 0.8;
    advance(5 * 60 * 1000);
    await detectUsage(ctx);
    expect(ctx.state.usageHistory[usageKey(provider.id, key.ref)]!.at(-1)!.costUsd).toBe(0.8);
    advance(31 * 24 * HOUR);
    await detectUsage(ctx);
    expect(ctx.state.usageHistory[usageKey(provider.id, key.ref)]).toHaveLength(1);
  });

  it('monitors a sealed consumer using its stored provider reference', async () => {
    const { ctx, provider, key, nextHour } = await setup();
    const cluster = ctx.inventory.clusters[0]!;
    ctx.state.keyRefs[cluster.id] = key.ref;
    ctx.hosts = [];
    await detectUsage(ctx);
    nextHour();
    provider.spend(key.ref, 3, 3, 'expensive-model');
    expect(await detectUsage(ctx, { hourlyBudgets: { [cluster.id]: 2 } }))
      .toMatchObject([{ kind: 'usage_anomaly', clusterIds: [cluster.id] }]);
  });

  it('never retains provider model labels, even when one contains a plaintext credential', async () => {
    const { ctx, provider, key, nextHour } = await setup();
    await detectUsage(ctx);
    nextHour();
    provider.spend(key.ref, 3, 1, key.value);
    const signals = await detectUsage(ctx);
    expect(JSON.stringify({ state: ctx.state, signals })).not.toContain(key.value);
  });
});
