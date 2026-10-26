import { describe, expect, it } from 'vitest';
import {
  buildInventory, buildPlan, createLogger, createRedactor, fingerprint, serviceKey,
} from '../../src/core/index.js';
import type { HostScan } from '../../src/core/index.js';
import { executePlan } from '../../src/rotate/engine.js';
import type { EngineDeps, RotateOptions } from '../../src/rotate/engine.js';
import type { JournalEntry, RotationReport, ServiceRef } from '../../src/types.js';
import { FakeHttp } from '../helpers/fake-http.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

const fingerprintKey = Buffer.alloc(32, 0x42);
const instant = new Date('2026-10-26T17:00:00.000Z');
const options: RotateOptions = {
  dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 1,
  revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 0,
};

async function fixture(host: FakeHost, provider: FakeProvider, values?: string[]) {
  const scan: HostScan = {
    host: host.id,
    services: await Promise.all((await host.listServices()).map(async service => ({
      service, vars: await host.readVariables(service),
    }))),
  };
  const inv = buildInventory([scan], fingerprintKey, instant);
  const plan = buildPlan(inv, values === undefined ? undefined : {
    clusterIds: values.map(value => fingerprint(value, fingerprintKey)),
  });
  const entries: JournalEntry[] = [];
  const redactor = createRedactor();
  const log = createLogger({ redactor, sink: () => undefined });
  const deps: EngineDeps = {
    hosts: { [host.id]: host },
    providers(id) {
      if (id !== provider.id) throw new Error('Unexpected test provider.');
      return provider;
    },
    providerCtx: { http: new FakeHttp(), credentials: {}, log },
    journal: {
      async append(entry) { entries.push(structuredClone(entry)); },
      async read() { return entries; },
    },
    prompt: async () => null,
    fingerprintKey, redactor, log,
    sleep: async () => undefined,
    now: () => new Date(instant),
  };
  return { inv, plan, deps, entries };
}

function stepFor(report: RotationReport, oldValue: string) {
  const step = report.steps.find(candidate => candidate.clusterId === fingerprint(oldValue, fingerprintKey));
  expect(step).toBeDefined();
  return step!;
}

function deploymentFor(report: RotationReport, service: ServiceRef) {
  const deployment = report.deployments.find(candidate => candidate.serviceKey === serviceKey(service));
  expect(deployment).toBeDefined();
  return deployment!;
}

/** Match Railway's null deployment ID while recording any forbidden shared redeploy attempt. */
class SharedRailwayHost extends FakeHost {
  readonly nullDeploysFor = new Set(['']);

  constructor() {
    super('railway');
    this.pendingPolls = 0;
  }

  override async redeploy(service: ServiceRef): Promise<string | null> {
    if (this.nullDeploysFor.has(service.serviceId)) {
      this.redeploys.push(service.serviceId);
      return null;
    }
    return super.redeploy(service);
  }

  addShared(vars: Record<string, string>): ServiceRef {
    const service = this.addService('', vars);
    service.serviceName = 'shared';
    return service;
  }
}

describe('round two Railway reference preflight', () => {
  const staleCases: {
    name: string;
    change: (host: FakeHost, oldValue: string, otherValue: string) => void;
  }[] = [
    {
      name: 'a reference replaced with a plain copy of the same secret',
      change: (host, oldValue) => { host.addService('reference', { OPENAI_API_KEY: oldValue }); },
    },
    {
      name: 'a reference replaced with a different plain secret',
      change: (host, _oldValue, otherValue) => { host.addService('reference', { OPENAI_API_KEY: otherValue }); },
    },
    {
      name: 'a reference changed to a source in another cluster',
      change: host => { host.addService('reference', { OPENAI_API_KEY: '${{other.OPENAI_API_KEY}}' }); },
    },
    {
      name: 'a reference variable removed after the scan',
      change: host => { host.addService('reference', {}); },
    },
    {
      name: 'a reference variable sealed after the scan',
      change: host => { host.addService('reference', { OPENAI_API_KEY: '${{source.OPENAI_API_KEY}}' }, ['OPENAI_API_KEY']); },
    },
    {
      name: 'a reference changed to an interpolated expression',
      change: host => { host.addService('reference', { OPENAI_API_KEY: 'Bearer ${{source.OPENAI_API_KEY}}' }); },
    },
    {
      name: 'a reference changed to a missing service',
      change: host => { host.addService('reference', { OPENAI_API_KEY: '${{missing.OPENAI_API_KEY}}' }); },
    },
    {
      name: 'a reference changed to a missing variable',
      change: host => { host.addService('reference', { OPENAI_API_KEY: '${{source.MISSING_KEY}}' }); },
    },
    {
      name: 'a reference changed to a cycle',
      change: host => { host.addService('reference', { OPENAI_API_KEY: '${{reference.OPENAI_API_KEY}}' }); },
    },
    {
      name: 'an unchanged reference whose service name now resolves to another service',
      change: (host, oldValue, otherValue) => {
        host.addService('source', { OPENAI_API_KEY: oldValue }).serviceName = 'renamed';
        host.addService('other', { OPENAI_API_KEY: otherValue }).serviceName = 'source';
      },
    },
    {
      name: 'an unchanged reference whose service name became ambiguous',
      change: (host, _oldValue, otherValue) => {
        host.addService('duplicate-source', { OPENAI_API_KEY: otherValue }).serviceName = 'source';
      },
    },
  ];

  for (const scenario of staleCases) {
    it(`skips ${scenario.name} before creating or writing a replacement`, async () => {
      const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
      const old = provider.issue('selected');
      const other = provider.issue('unrelated');
      const host = new FakeHost('railway');
      host.pendingPolls = 0;
      host.addService('source', { OPENAI_API_KEY: old.value });
      host.addService('other', { OPENAI_API_KEY: other.value });
      host.addService('reference', { OPENAI_API_KEY: '${{source.OPENAI_API_KEY}}' });
      const h = await fixture(host, provider, [old.value]);
      expect(h.plan.steps).toHaveLength(1);
      expect(h.plan.steps[0]?.consumers).toHaveLength(2);
      expect(h.plan.steps[0]?.consumers.find(consumer => consumer.reference)).toMatchObject({
        varName: 'OPENAI_API_KEY', fingerprint: fingerprint(old.value, fingerprintKey),
      });

      scenario.change(host, old.value, other.value);
      const report = await executePlan(h.plan, h.inv, h.deps, options);

      expect(stepFor(report, old.value).status).toBe('skipped');
      expect(stepFor(report, old.value).warnings.join(' ')).toMatch(/stale/i);
      expect(provider.keys.size).toBe(2);
      expect(provider.revoked).toEqual([]);
      expect(host.writes).toEqual([]);
      expect(host.redeploys).toEqual([]);
      expect(host.peek('source', 'OPENAI_API_KEY')).toBe(old.value);
      expect(h.entries.some(entry => entry.event === 'created' || entry.event === 'written')).toBe(false);
    });
  }

  it('keeps a legitimate whitespace-wrapped reference intact and deploys it before ordinary revocation', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    host.addService('source', { OPENAI_API_KEY: old.value });
    const expression = '  ${{ source.OPENAI_API_KEY }}  ';
    host.addService('reference', { OPENAI_API_KEY: expression });
    const h = await fixture(host, provider);
    expect(h.plan.steps[0]?.consumers).toHaveLength(2);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(host.writes.map(write => write.serviceId)).toEqual(['source']);
    expect(host.peek('reference', 'OPENAI_API_KEY')).toBe(expression);
    expect([...host.redeploys].sort()).toEqual(['reference', 'source']);
    expect(report.deployments.every(deployment => deployment.state === 'success')).toBe(true);
    expect(stepFor(report, old.value).status).toBe('revoked');
    expect(provider.revoked).toEqual([old.ref]);
  });

  it('skips reference rotation when the current service namespace cannot be confirmed', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('source', { OPENAI_API_KEY: old.value });
    host.addService('reference', { OPENAI_API_KEY: '${{source.OPENAI_API_KEY}}' });
    const h = await fixture(host, provider);
    host.listServices = async () => { throw new Error(`unsafe API failure ${old.value}`); };

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(stepFor(report, old.value).status).toBe('skipped');
    expect(provider.keys.size).toBe(1);
    expect(provider.revoked).toEqual([]);
    expect(host.writes).toEqual([]);
    expect(JSON.stringify({ report, entries: h.entries })).not.toContain(old.value);
  });

  it('resolves unchanged reference chains with aliases instead of comparing a template to the secret fingerprint', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    host.addService('source', { OPENAI_API_KEY: old.value });
    const middle = '${{source.OPENAI_API_KEY}}';
    const leaf = '${{middle.PROVIDER_TOKEN}}';
    host.addService('middle', { PROVIDER_TOKEN: middle });
    host.addService('leaf', { APPLICATION_TOKEN: leaf });
    const h = await fixture(host, provider);
    expect(h.plan.steps[0]?.consumers).toHaveLength(3);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(host.writes.map(write => write.serviceId)).toEqual(['source']);
    expect(host.peek('middle', 'PROVIDER_TOKEN')).toBe(middle);
    expect(host.peek('leaf', 'APPLICATION_TOKEN')).toBe(leaf);
    expect([...host.redeploys].sort()).toEqual(['leaf', 'middle', 'source']);
    expect(stepFor(report, old.value).status).toBe('revoked');
    expect(provider.revoked).toEqual([old.ref]);
  });
});

describe('round two Railway shared-variable activation', () => {
  it('does not confirm an unreferenced shared key from a reference to another direct copy in the cluster', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new SharedRailwayHost();
    const shared = host.addShared({ OPENAI_API_KEY: old.value });
    host.addService('source', { OPENAI_API_KEY: old.value });
    host.addService('api', { OPENAI_API_KEY: '${{source.OPENAI_API_KEY}}' });
    const h = await fixture(host, provider);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(deploymentFor(report, shared).state).toBe('unconfirmed');
    expect(stepFor(report, old.value).status).toBe('written');
    expect(host.redeploys).not.toContain('');
    expect(provider.revoked).toEqual([]);
    expect(provider.keys.get(old.ref)?.active).toBe(true);
  });

  it('confirms shared activation from every reference deployment and permits ordinary revocation', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new SharedRailwayHost();
    const shared = host.addShared({ OPENAI_API_KEY: old.value });
    const expression = '${{shared.OPENAI_API_KEY}}';
    host.addService('api', { OPENAI_API_KEY: expression });
    host.addService('worker', { OPENAI_TOKEN: expression });
    const h = await fixture(host, provider);
    expect(h.plan.steps[0]?.consumers.filter(consumer => consumer.reference)).toHaveLength(2);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(host.writes.map(write => write.serviceId)).toEqual(['']);
    expect(host.peek('', 'OPENAI_API_KEY')).not.toBe(old.value);
    expect(host.peek('api', 'OPENAI_API_KEY')).toBe(expression);
    expect(host.peek('worker', 'OPENAI_TOKEN')).toBe(expression);
    expect([...host.redeploys].sort()).toEqual(['api', 'worker']);
    expect(deploymentFor(report, shared)).toMatchObject({ deploymentId: null, state: 'success' });
    expect(stepFor(report, old.value).status).toBe('revoked');
    expect(provider.revoked).toEqual([old.ref]);
  });

  for (const outcome of ['failed', 'unconfirmed'] as const) {
    it(`retains the old shared key when one reference deployment is ${outcome}`, async () => {
      const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
      const old = provider.issue();
      const host = new SharedRailwayHost();
      const shared = host.addShared({ OPENAI_API_KEY: old.value });
      host.addService('good', { OPENAI_API_KEY: '${{shared.OPENAI_API_KEY}}' });
      host.addService('incomplete', { OPENAI_API_KEY: '${{shared.OPENAI_API_KEY}}' });
      if (outcome === 'failed') host.failDeploysFor.add('incomplete');
      else host.nullDeploysFor.add('incomplete');
      const h = await fixture(host, provider);

      const report = await executePlan(h.plan, h.inv, h.deps, options);

      expect([...host.redeploys].sort()).toEqual(['good', 'incomplete']);
      expect(deploymentFor(report, shared)).toMatchObject({ deploymentId: null, state: 'unconfirmed' });
      expect(stepFor(report, old.value).status).toBe(outcome === 'failed' ? 'failed' : 'written');
      expect(provider.revoked).toEqual([]);
      expect((await provider.verify(old.value, h.deps.providerCtx)).ok).toBe(true);
    });
  }

  it('keeps a shared variable with no referencing services unconfirmed instead of accepting an empty success set', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new SharedRailwayHost();
    const shared = host.addShared({ OPENAI_API_KEY: old.value });
    const h = await fixture(host, provider);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(host.writes.map(write => write.serviceId)).toEqual(['']);
    expect(host.redeploys).toEqual([]);
    expect(deploymentFor(report, shared)).toMatchObject({ deploymentId: null, state: 'unconfirmed' });
    expect(stepFor(report, old.value).status).toBe('written');
    expect(provider.revoked).toEqual([]);
    expect((await provider.verify(old.value, h.deps.providerCtx)).ok).toBe(true);
  });

  it('does not confirm shared activation when redeploy is disabled', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new SharedRailwayHost();
    const shared = host.addShared({ OPENAI_API_KEY: old.value });
    host.addService('api', { OPENAI_API_KEY: '${{shared.OPENAI_API_KEY}}' });
    const h = await fixture(host, provider);

    const report = await executePlan(h.plan, h.inv, h.deps, { ...options, redeploy: false });

    expect(host.redeploys).toEqual([]);
    expect(deploymentFor(report, shared).state).toBe('unconfirmed');
    expect(stepFor(report, old.value).status).toBe('written');
    expect(provider.revoked).toEqual([]);
  });

  for (const secondOutcome of ['failed', 'unconfirmed', 'unreferenced'] as const) {
    it(`revokes only the activated key when another variable in the same shared service is ${secondOutcome}`, async () => {
      const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
      const good = provider.issue('good');
      const incomplete = provider.issue('incomplete');
      const host = new SharedRailwayHost();
      host.addShared({ OPENAI_API_KEY: good.value, OPENAI_BACKUP_KEY: incomplete.value });
      host.addService('good-app', { OPENAI_API_KEY: '${{shared.OPENAI_API_KEY}}' });
      if (secondOutcome !== 'unreferenced') {
        host.addService('incomplete-app', { OPENAI_API_KEY: '${{shared.OPENAI_BACKUP_KEY}}' });
        if (secondOutcome === 'failed') host.failDeploysFor.add('incomplete-app');
        else host.nullDeploysFor.add('incomplete-app');
      }
      const h = await fixture(host, provider);
      expect(h.plan.steps).toHaveLength(2);

      const report = await executePlan(h.plan, h.inv, h.deps, options);

      expect(host.writes).toHaveLength(1);
      expect(Object.keys(host.writes[0]!.vars).sort()).toEqual(['OPENAI_API_KEY', 'OPENAI_BACKUP_KEY']);
      expect(host.redeploys).not.toContain('');
      expect(host.redeploys.filter(serviceId => serviceId === 'good-app')).toHaveLength(1);
      expect(stepFor(report, good.value).status).toBe('revoked');
      expect(stepFor(report, incomplete.value).status).toBe(secondOutcome === 'failed' ? 'failed' : 'written');
      expect(provider.revoked).toEqual([good.ref]);
      expect((await provider.verify(incomplete.value, h.deps.providerCtx)).ok).toBe(true);
    });
  }
});
