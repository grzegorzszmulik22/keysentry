import { describe, expect, it } from 'vitest';
import { scanHosts, serviceKey } from '../../src/core/index.js';
import { createCanary, listCanaries, removeCanary } from '../../src/monitor/canary.js';
import { detectCanaries } from '../../src/monitor/detectors/canary.js';
import { createMonitorState } from '../../src/monitor/state.js';
import type { DetectorContext } from '../../src/monitor/context.js';
import { openrouterProvider } from '../../src/providers/openrouter.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { FakeHttp, json, silentLogger } from '../helpers/fake-http.js';

const fingerprintKey = Buffer.alloc(32, 7);
const clock = () => new Date('2026-10-26T12:00:00.000Z');

async function fixture() {
  const http = new FakeHttp();
  const host = new FakeHost('railway');
  const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-0123456789abcdef');
  const primary = provider.issue();
  const second = provider.issue();
  const third = provider.issue();
  const service = host.addService('api', { OPENROUTER_API_KEY: primary.value, OTHER_SECRET: second.value });
  host.addService('worker', { OPENROUTER_API_KEY: third.value });
  const inventory = await scanHosts([host], fingerprintKey, silentLogger);
  const ctx: DetectorContext = {
    inventory, hosts: [host], providers: [provider],
    providerCtx: { http, credentials: { OPENROUTER_PROVISIONING_KEY: 'management-credential' }, log: silentLogger },
    state: createMonitorState(), fingerprintKey, log: silentLogger, clock,
  };
  return { ctx, http, host, provider, service };
}

describe('canary lifecycle', () => {
  it('creates a one-cent decoy, stages only its named variable and records no secret', async () => {
    const { ctx, http, host, service } = await fixture();
    const value = `sk-or-v1-${'a'.repeat(48)}`;
    http.on('POST', /^https:\/\/openrouter\.ai\/api\/v1\/keys$/, (request) => {
      expect(JSON.parse(request.body!)).toMatchObject({ limit: 0.01 });
      return json(200, { key: value, data: { hash: 'canary_hash' } });
    });
    const canary = await createCanary({ provider: 'openrouter', host, service, dryRun: false }, ctx);
    expect(canary).toMatchObject({ provider: 'openrouter', keyRef: 'canary_hash', service, varName: 'OPENROUTER_API_KEY_FALLBACK' });
    expect(host.writes).toEqual([{ serviceId: service.serviceId, vars: { OPENROUTER_API_KEY_FALLBACK: value }, skipDeploy: true }]);
    expect(host.redeploys).toEqual([]);
    expect(listCanaries(ctx.state)).toEqual([canary]);
    expect(JSON.stringify(ctx.state)).not.toContain(value);
  });

  it('defaults to a dry run and refuses to overwrite an existing variable', async () => {
    const { ctx, host, http, service } = await fixture();
    expect(await createCanary({ provider: 'openrouter', host, service }, ctx)).toBeNull();
    expect(http.calls).toEqual([]);
    await expect(createCanary({ provider: 'openrouter', host, service, varName: 'OPENROUTER_API_KEY', dryRun: false }, ctx)).rejects.toThrow('already exists');
    expect(http.calls).toEqual([]);
    expect(host.writes).toEqual([]);
  });

  it('revokes the unplanted key when staging fails and returns a sanitized error', async () => {
    const { ctx, host, http, service } = await fixture();
    const value = `sk-or-v1-${'b'.repeat(48)}`;
    ctx.providers = [openrouterProvider];
    host.failWritesFor.add(service.serviceId);
    http.on('POST', /\/keys$/, () => json(200, { key: value, data: { hash: 'unplanted_hash' } }));
    http.on('DELETE', /\/keys\/unplanted_hash$/, () => json(200, {}));
    await expect(createCanary({ provider: 'openrouter', host, service, dryRun: false }, ctx)).rejects.toThrow('Unable to plant canary');
    expect(http.callsTo('DELETE', /unplanted_hash/)).toHaveLength(1);
    expect(ctx.state.canaries).toEqual([]);
  });

  it('removes a canary only after explicit execution and revokes its provider key', async () => {
    const { ctx, host, provider, service } = await fixture();
    const decoy = provider.issue('decoy', 0.01);
    ctx.state.canaries.push({ id: 'canary-1', provider: 'openrouter', keyRef: decoy.ref, service, varName: 'DECOY_KEY', createdAt: clock().toISOString() });
    await removeCanary('canary-1', ctx);
    expect(listCanaries(ctx.state)).toHaveLength(1);
    await removeCanary('canary-1', ctx, { dryRun: false });
    expect(provider.revoked).toEqual([decoy.ref]);
    expect(listCanaries(ctx.state)).toEqual([]);
    expect(host.writes).toEqual([]);
  });
});

describe('canary detector', () => {
  it('stays silent before traffic and raises one high-confidence service-scoped signal on a hit', async () => {
    const { ctx, provider, service } = await fixture();
    const decoy = provider.issue('decoy', 0.01);
    ctx.state.canaries.push({ id: 'canary-1', provider: 'openrouter', keyRef: decoy.ref, service, varName: 'DECOY_KEY', createdAt: clock().toISOString() });
    expect(await detectCanaries(ctx)).toEqual([]);
    provider.spend(decoy.ref, 0.001);
    const signals = await detectCanaries(ctx);
    expect(signals).toHaveLength(1);
    expect(signals[0]).toMatchObject({ kind: 'canary_triggered', confidence: 'high', host: 'railway', serviceKeys: [serviceKey(service)] });
    const implicated = ctx.inventory.clusters.filter(cluster => cluster.consumers.some(consumer => serviceKey(consumer.service) === serviceKey(service))).map(cluster => cluster.id);
    expect(signals[0]!.clusterIds.sort()).toEqual(implicated.sort());
    expect(implicated).toHaveLength(2);
    expect(await detectCanaries(ctx)).toEqual([]);
    expect(JSON.stringify(signals)).not.toContain(decoy.value);
  });

  it('recognizes a canary disabled at its one-cent spending limit', async () => {
    const { ctx, provider, service } = await fixture();
    const decoy = provider.issue('decoy', 0.01);
    ctx.state.canaries.push({ id: 'canary-limit', provider: 'openrouter', keyRef: decoy.ref, service, varName: 'DECOY_KEY', createdAt: clock().toISOString() });
    provider.spend(decoy.ref, 0.01);
    provider.revokeUpstream(decoy.ref);
    expect(await detectCanaries(ctx)).toEqual([expect.objectContaining({ kind: 'canary_triggered', confidence: 'high' })]);
  });

  it('still observes an exhausted one-cent canary when usage is unavailable', async () => {
    const { ctx, provider, service } = await fixture();
    const decoy = provider.issue('decoy', 0.01);
    ctx.state.canaries.push({ id: 'canary-disabled', provider: 'openrouter', keyRef: decoy.ref, service, varName: 'DECOY_KEY', createdAt: clock().toISOString() });
    provider.revokeUpstream(decoy.ref);
    provider.usage = async () => { throw new Error(decoy.value); };
    const signals = await detectCanaries(ctx);
    expect(signals).toEqual([expect.objectContaining({ kind: 'canary_triggered', confidence: 'high', evidence: { canaryId: 'canary-disabled', used: false, exhausted: true } })]);
    expect(JSON.stringify({ signals, state: ctx.state })).not.toContain(decoy.value);
  });
});
