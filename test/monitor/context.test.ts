import { describe, expect, it } from 'vitest';
import { scanHosts } from '../../src/core/inventory.js';
import { readClusterSecret, resolveClusterKeyRef, type DetectorContext } from '../../src/monitor/context.js';
import { createMemoryMonitorStateStore, createMonitorState } from '../../src/monitor/state.js';
import type { ProviderAdapter } from '../../src/types.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';

async function fixture() {
  const host = new FakeHost('railway');
  const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-aB3cD7eF9gH2iJ4kL6mN8pQ0');
  const issued = provider.issue();
  const service = host.addService('api', { OPENROUTER_API_KEY: issued.value });
  const fingerprintKey = Buffer.alloc(32, 15);
  const ctx: DetectorContext = {
    inventory: await scanHosts([host], fingerprintKey, silentLogger),
    hosts: [host], providers: [provider], fingerprintKey,
    providerCtx: { http: new FakeHttp(), credentials: {}, log: silentLogger },
    state: createMonitorState(), log: silentLogger,
  };
  return { ctx, host, provider, issued, service, cluster: ctx.inventory.clusters[0]! };
}

describe('monitor context', () => {
  it('resolves an injected provider reference and persists only the mapping', async () => {
    const { ctx, issued, cluster } = await fixture();
    expect(await resolveClusterKeyRef(cluster, ctx)).toBe(issued.ref);
    expect(ctx.state.keyRefs).toEqual({ [cluster.id]: issued.ref });
    const store = createMemoryMonitorStateStore();
    await store.save(ctx.state);
    const saved = await store.load();
    expect(saved.keyRefs).toEqual({ [cluster.id]: issued.ref });
    expect(JSON.stringify(saved)).not.toContain(issued.value);
    ctx.hosts = [];
    ctx.state = saved;
    expect(await resolveClusterKeyRef(cluster, ctx)).toBe(issued.ref);
  });

  it('rejects an unknown-format sibling secret returned as a provider key reference', async () => {
    const { ctx, host, provider, service, cluster } = await fixture();
    const sibling = 'F9b2K7m3P0q5V8w1R4t6N9x2Z7a3D0e5';
    await host.writeVariables(service, { BACKUP_SECRET: sibling }, { skipDeploy: true });
    provider.resolveKeyRef = async (_value, providerCtx) => providerCtx.siblingVars?.BACKUP_SECRET ?? null;
    expect(await resolveClusterKeyRef(cluster, ctx)).toBeNull();
    expect(ctx.state.keyRefs).toEqual({});
    expect(JSON.stringify(ctx.state)).not.toContain(sibling);
  });

  it('ignores a stale inventory consumer after its host value changes', async () => {
    const { ctx, host, provider, service, cluster } = await fixture();
    const replacement = provider.issue('replacement');
    await host.writeVariables(service, { OPENROUTER_API_KEY: replacement.value }, { skipDeploy: true });
    expect(await readClusterSecret(cluster, ctx)).toBeNull();
    expect(await resolveClusterKeyRef(cluster, ctx)).toBeNull();
    expect(ctx.state.keyRefs).toEqual({});
  });

  it('does not guess between two provider keys sharing the same partial hint', async () => {
    const { ctx, provider, issued, cluster } = await fixture();
    const hint = `${issued.value.slice(0, 12)}...${issued.value.slice(-4)}`;
    const ambiguous: ProviderAdapter = {
      id: provider.id, method: provider.method,
      verify: provider.verify.bind(provider), guidance: provider.guidance.bind(provider),
      listKeys: async () => [{ keyRef: 'key_a', hint }, { keyRef: 'key_b', hint }],
    };
    ctx.providers = [ambiguous];
    expect(await resolveClusterKeyRef(cluster, ctx)).toBeNull();
    expect(ctx.state.keyRefs).toEqual({});
  });
});
