import { describe, expect, it } from 'vitest';
import { buildInventory, buildPlan, createRedactor } from '../../src/core/index.js';
import { executePlan, type EngineDeps, type RotateOptions } from '../../src/rotate/engine.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';

const fingerprintKey = Buffer.alloc(32, 3);
const options: RotateOptions = {
  dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 1,
  revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 0,
};

async function fixture(refs: Record<string, string>, shared = false, duplicateSource = false) {
  const host = new FakeHost('railway');
  host.pendingPolls = 0;
  const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-0123456789abcdef');
  const old = provider.issue();
  const source = host.addService(shared ? '' : 'api', { OPENROUTER_API_KEY: old.value });
  if (shared) source.serviceName = 'shared';
  if (duplicateSource) host.addService('api', { OPENROUTER_API_KEY: old.value });
  for (const [name, value] of Object.entries(refs)) host.addService(name, { AUTH_HEADER: value });
  const inv = buildInventory([{
    host: host.id,
    services: await Promise.all((await host.listServices()).map(async service => ({
      service, vars: await host.readVariables(service),
    }))),
  }], fingerprintKey);
  const plan = buildPlan(inv, { clusterIds: [inv.clusters.find(cluster => cluster.provider === provider.id)!.id] });
  const deps: EngineDeps = {
    hosts: { railway: host }, providers: () => provider,
    providerCtx: { http: new FakeHttp(), credentials: {}, log: silentLogger },
    journal: { async append() {}, async read() { return []; } },
    prompt: async () => null, reveal: async () => true,
    fingerprintKey, redactor: createRedactor(), log: silentLogger, sleep: async () => {},
  };
  return { host, provider, old, inv, plan, deps };
}

describe('Railway interpolated reference regressions', () => {
  for (const expression of [
    '${{api.OPENROUTER_API_KEY}}',
    'Bearer ${{api.OPENROUTER_API_KEY}}',
    'Bearer ${{  api . OPENROUTER_API_KEY  }}; trailing text',
    '${{missing.OTHER}} prefix ${{api.OPENROUTER_API_KEY}} suffix',
  ]) {
    it(`rotates the source and only redeploys a consumer containing ${expression}`, async () => {
      const h = await fixture({ worker: expression });
      expect(h.plan.steps[0]?.consumers).toHaveLength(2);

      const report = await executePlan(h.plan, h.inv, h.deps, options);

      expect(report.steps[0]?.status).toBe('revoked');
      expect(h.host.writes.map(write => write.serviceId)).toEqual(['api']);
      expect(h.host.peek('worker', 'AUTH_HEADER')).toBe(expression);
      expect([...h.host.redeploys].sort()).toEqual(['api', 'worker']);
      expect(h.provider.keys.size).toBe(2);
      expect(h.provider.keys.get(h.old.ref)?.active).toBe(false);
    });
  }

  const sharedCases: { name: string; refs: Record<string, string>; failed: boolean }[] = [
    { name: 'two whole references', refs: { web: '${{shared.OPENROUTER_API_KEY}}', worker: '${{shared.OPENROUTER_API_KEY}}' }, failed: false },
    { name: 'one failed reference deployment', refs: { web: '${{shared.OPENROUTER_API_KEY}}', worker: '${{shared.OPENROUTER_API_KEY}}' }, failed: true },
    { name: 'no references', refs: {}, failed: false },
    { name: 'one interpolated reference', refs: { web: '${{shared.OPENROUTER_API_KEY}}', worker: 'Bearer ${{shared.OPENROUTER_API_KEY}}' }, failed: false },
  ];
  for (const scenario of sharedCases) {
    it(`preserves shared-source activation accounting with ${scenario.name}`, async () => {
      const h = await fixture(scenario.refs, true);
      if (scenario.failed) h.host.failDeploysFor.add('worker');

      const report = await executePlan(h.plan, h.inv, h.deps, options);

      const activated = Object.keys(scenario.refs).length > 0 && !scenario.failed;
      expect(h.host.writes.map(write => write.serviceId)).toEqual(['']);
      expect([...h.host.redeploys].sort()).toEqual(Object.keys(scenario.refs).sort());
      expect(h.provider.keys.get(h.old.ref)?.active).toBe(!activated);
      expect(report.steps[0]?.status).toBe(activated ? 'revoked' : scenario.failed ? 'failed' : 'written');
      for (const [service, expression] of Object.entries(scenario.refs)) {
        expect(h.host.peek(service, 'AUTH_HEADER')).toBe(expression);
      }
    });
  }

  for (const replacement of ['no reference now', '${{missing.OPENROUTER_API_KEY}}']) {
    it(`reports a removed dependency accurately when changed to ${replacement}`, async () => {
      const h = await fixture({ worker: 'Bearer ${{api.OPENROUTER_API_KEY}}' });
      h.host.addService('worker', { AUTH_HEADER: replacement });

      const report = await executePlan(h.plan, h.inv, h.deps, options);

      expect(report.steps[0]?.status).toBe('skipped');
      expect(report.steps[0]?.warnings.join(' ')).toContain('reference removed since scan');
      expect(report.steps[0]?.warnings.join(' ')).not.toMatch(/stale inventory/i);
      expect(h.host.writes).toEqual([]);
      expect(h.host.redeploys).toEqual([]);
      expect(h.provider.keys.size).toBe(1);
    });
  }

  it('continues through an interpolated reference chain without overwriting either template', async () => {
    const h = await fixture({ middle: 'Bearer ${{api.OPENROUTER_API_KEY}}', worker: 'prefix ${{middle.AUTH_HEADER}} suffix' });

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.steps[0]?.status).toBe('revoked');
    expect(h.host.writes.map(write => write.serviceId)).toEqual(['api']);
    expect([...h.host.redeploys].sort()).toEqual(['api', 'middle', 'worker']);
  });

  it('accounts for every source when an expression contains multiple references in the cluster', async () => {
    const expression = '${{api.OPENROUTER_API_KEY}} plus ${{shared.OPENROUTER_API_KEY}}';
    const h = await fixture({ worker: expression }, true, true);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.steps[0]?.status).toBe('revoked');
    expect(h.host.writes.map(write => write.serviceId).sort()).toEqual(['', 'api']);
    expect([...h.host.redeploys].sort()).toEqual(['api', 'worker']);
    expect(report.deployments.every(deployment => deployment.state === 'success')).toBe(true);
    expect(h.host.peek('worker', 'AUTH_HEADER')).toBe(expression);
  });
});
