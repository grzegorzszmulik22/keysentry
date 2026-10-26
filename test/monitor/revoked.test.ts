import { describe, expect, it, vi } from 'vitest';
import { scanHosts } from '../../src/core/inventory.js';
import { detectRevoked } from '../../src/monitor/detectors/revoked.js';
import { createMonitorState } from '../../src/monitor/state.js';
import type { DetectorContext } from '../../src/monitor/context.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';

async function fixture() {
  const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
  const key = provider.issue();
  const host = new FakeHost('railway');
  const service = host.addService('api', { OPENAI_API_KEY: key.value });
  const fingerprintKey = Buffer.alloc(32, 42);
  const inventory = await scanHosts([host], fingerprintKey, silentLogger);
  let time = new Date('2026-10-01T10:00:00Z');
  const ctx: DetectorContext = {
    inventory, hosts: [host], providers: [provider], fingerprintKey,
    state: createMonitorState(), log: silentLogger,
    providerCtx: { http: new FakeHttp(), credentials: {}, log: silentLogger },
    clock: () => time,
  };
  return { ctx, provider, key, host, service, advance: (hours = 1) => { time = new Date(time.getTime() + hours * 3_600_000); } };
}

describe('revoked upstream detector', () => {
  it('reports an authenticated-to-revoked transition once and polls at most hourly', async () => {
    const { ctx, provider, key, advance } = await fixture();
    const verify = vi.spyOn(provider, 'verify');
    expect(await detectRevoked(ctx)).toEqual([]);
    provider.revokeUpstream(key.ref);
    expect(await detectRevoked(ctx)).toEqual([]);
    expect(verify).toHaveBeenCalledTimes(1);
    advance();
    const signals = await detectRevoked(ctx);
    expect(signals).toHaveLength(1);
    expect(signals[0]).toMatchObject({
      kind: 'revoked_upstream', confidence: 'high', clusterIds: [ctx.inventory.clusters[0]!.id],
      evidence: { status: 401 },
    });
    expect(JSON.stringify({ signals, state: ctx.state })).not.toContain(key.value);
    advance();
    expect(await detectRevoked(ctx)).toEqual([]);
    expect(verify).toHaveBeenCalledTimes(3);
  });

  it('does not mistake a first failed verification for upstream revocation', async () => {
    const { ctx, provider, key } = await fixture();
    provider.revokeUpstream(key.ref);
    expect(await detectRevoked(ctx)).toEqual([]);
  });

  it('preserves known authentication across transient provider failures', async () => {
    const { ctx, provider, key, advance } = await fixture();
    expect(await detectRevoked(ctx)).toEqual([]);
    advance();
    vi.spyOn(provider, 'verify').mockResolvedValueOnce({ ok: false, status: 503, error: key.value });
    expect(await detectRevoked(ctx)).toEqual([]);
    provider.revokeUpstream(key.ref);
    advance();
    expect(await detectRevoked(ctx)).toMatchObject([{ kind: 'revoked_upstream', confidence: 'high' }]);
    expect(JSON.stringify(ctx.state)).not.toContain(key.value);
  });

  it('does not compare verification results across changed credentials', async () => {
    const { ctx, provider, host, service, advance } = await fixture();
    expect(await detectRevoked(ctx)).toEqual([]);
    const replacement = provider.issue('replacement');
    provider.revokeUpstream(replacement.ref);
    await host.writeVariables(service, { OPENAI_API_KEY: replacement.value }, { skipDeploy: true });
    advance();
    // The inventory is stale; the context resolver must reject the changed value.
    expect(await detectRevoked(ctx)).toEqual([]);
    ctx.inventory = await scanHosts([host], ctx.fingerprintKey, silentLogger);
    advance();
    expect(await detectRevoked(ctx)).toEqual([]);
  });

  it('sanitizes thrown adapter errors and throttles retries', async () => {
    const { ctx, provider, key, advance } = await fixture();
    expect(await detectRevoked(ctx)).toEqual([]);
    advance();
    const verify = vi.spyOn(provider, 'verify').mockRejectedValueOnce(new Error(key.value));
    expect(await detectRevoked(ctx)).toEqual([]);
    expect(await detectRevoked(ctx)).toEqual([]);
    expect(verify).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(ctx.state)).not.toContain(key.value);
  });
});
