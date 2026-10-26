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

  it('ignores cold-start spend below the floor and honors an hourly budget', async () => {
    const { ctx, provider, key, nextHour } = await setup();
    await detectUsage(ctx);
    nextHour();
    provider.spend(key.ref, 0.5, 1, 'normal-model');
    expect(await detectUsage(ctx)).toEqual([]);
    expect(await detectUsage(ctx, { hourlyBudgets: { [ctx.inventory.clusters[0]!.id]: 0.25 } }))
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
    expect(await detectUsage(ctx)).toMatchObject([{ kind: 'usage_anomaly', clusterIds: [cluster.id] }]);
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
