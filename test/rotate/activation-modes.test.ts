import { describe, expect, it } from 'vitest';
import { buildInventory, buildPlan, createLogger, createRedactor } from '../../src/core/index.js';
import { executePlan } from '../../src/rotate/engine.js';
import type { EngineDeps, RotateOptions } from '../../src/rotate/engine.js';
import type { DeployState, HostCapabilities, HostId, JournalEntry, ProviderAdapter, ServiceRef } from '../../src/types.js';
import { FakeHttp } from '../helpers/fake-http.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

// Decision 1 (notes/integration-phase6.md): how a host applies new values.
const key = Buffer.alloc(32, 0x61);
const options: RotateOptions = {
  dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 1,
  revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 0,
};

/** Heroku-like: every write is a release; redeploy() reports that release and starts nothing. */
class OnWriteHost extends FakeHost {
  readonly releases: { serviceId: string; id: string }[] = [];
  readonly reported: string[] = [];
  constructor(id: HostId = 'heroku', caps: Partial<HostCapabilities> = {}) { super(id, { activation: 'on-write', ...caps }); }
  override async writeVariables(service: ServiceRef, vars: Record<string, string>, opts: { skipDeploy: boolean }): Promise<void> {
    await super.writeVariables(service, vars, opts);
    this.releases.push({ serviceId: service.serviceId, id: `release-${this.releases.length + 1}` });
  }
  override async redeploy(service: ServiceRef): Promise<string | null> {
    const latest = this.releases.filter(release => release.serviceId === service.serviceId).at(-1);
    if (latest) this.reported.push(latest.id);
    return latest?.id ?? null;
  }
  override async deploymentStatus(_service: ServiceRef, id: string): Promise<DeployState> {
    return this.releases.some(release => release.id === id) ? 'success' : 'failed';
  }
}

async function fixture(host: FakeHost, providers: ProviderAdapter[], extra: Partial<EngineDeps> = {}) {
  const inv = buildInventory([{
    host: host.id,
    services: await Promise.all((await host.listServices()).map(async service => ({ service, vars: await host.readVariables(service) }))),
  }], key);
  const plan = buildPlan(inv);
  const entries: JournalEntry[] = [];
  const lines: string[] = [];
  const redactor = createRedactor();
  const log = createLogger({ redactor, level: 'debug', json: true, sink: line => lines.push(line) });
  const deps: EngineDeps = {
    hosts: { [host.id]: host },
    providers(id) { const provider = providers.find(candidate => candidate.id === id); if (!provider) throw new Error('Missing test provider'); return provider; },
    providerCtx: { http: new FakeHttp(), credentials: {}, log },
    journal: { async append(entry) { entries.push(structuredClone(entry)); }, async read() { return entries; } },
    prompt: async () => null, reveal: async () => true, fingerprintKey: key, redactor, log,
    sleep: async () => undefined, ...extra,
  };
  return { inv, plan, deps, entries, lines };
}

describe('on-write hosts (Heroku, DigitalOcean, Cloudflare Workers)', () => {
  it('writes each service once, starts no deployment of its own, and confirms the release the write created', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const first = provider.issue('first');
    const second = provider.issue('second');
    const host = new OnWriteHost();
    host.addService('api', { OPENAI_API_KEY: first.value, OPENAI_BACKUP_KEY: second.value });
    const h = await fixture(host, [provider]);
    expect(h.plan.steps).toHaveLength(2);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    // One batched write for both clusters, staged with skipDeploy (the host deploys anyway).
    expect(host.writes).toHaveLength(1);
    expect(Object.keys(host.writes[0]!.vars).sort()).toEqual(['OPENAI_API_KEY', 'OPENAI_BACKUP_KEY']);
    expect(host.writes[0]!.skipDeploy).toBe(true);
    expect(host.releases).toHaveLength(1);
    expect(host.redeploys).toEqual([]);
    expect(host.reported).toEqual(['release-1']);
    expect(report.deployments).toEqual([{ serviceKey: expect.any(String), deploymentId: 'release-1', state: 'success' }]);
    expect(provider.revoked.sort()).toEqual([first.ref, second.ref].sort());
    expect(report.status).toBe('complete');
  });

  it('still confirms the write deployment when redeploys are turned off, and says the values went live', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new OnWriteHost('digitalocean');
    host.addService('web', { OPENAI_API_KEY: old.value });
    const h = await fixture(host, [provider]);

    const report = await executePlan(h.plan, h.inv, h.deps, { ...options, redeploy: false });

    expect(host.writes).toHaveLength(1);
    expect(report.deployments[0]).toMatchObject({ deploymentId: 'release-1', state: 'success' });
    expect(report.steps[0]!.warnings.join(' ')).toMatch(/deploys on every write/);
    expect(provider.revoked).toEqual([old.ref]);
  });

  it('lists the write-triggered deployment in a dry run instead of a redeploy', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const host = new OnWriteHost();
    host.addService('api', { OPENAI_API_KEY: provider.issue().value });
    const h = await fixture(host, [provider]);
    const report = await executePlan(h.plan, h.inv, h.deps, { ...options, dryRun: true });
    expect(report.diff.some(line => /^Writing deploys .*keysentry confirms that deployment$/.test(line))).toBe(true);
    expect(report.diff.some(line => line.startsWith('Redeploy '))).toBe(false);
    expect(host.writes).toEqual([]);
  });

  it('a grace-period undo restores old values with one write per service and confirms that release without starting one', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new OnWriteHost();
    host.addService('api', { OPENAI_API_KEY: old.value });
    host.addService('worker', { OPENAI_API_KEY: old.value });
    const h = await fixture(host, [provider], { grace: async () => 'undo' });

    const report = await executePlan(h.plan, h.inv, h.deps, { ...options, graceMs: 60_000 });

    expect(host.peek('api', 'OPENAI_API_KEY')).toBe(old.value);
    expect(host.peek('worker', 'OPENAI_API_KEY')).toBe(old.value);
    // Rotation: one write per service; undo: one restoring write per service. Never a separate deployment.
    expect(host.writes.map(write => write.serviceId).sort()).toEqual(['api', 'api', 'worker', 'worker']);
    expect(host.redeploys).toEqual([]);
    const undoResults = h.entries.filter(entry => entry.event === 'deploy-result' && entry.data?.undo === true);
    expect(undoResults.map(entry => entry.data?.state)).toEqual(['success', 'success']);
    expect(provider.keys.get(old.ref)?.active).toBe(true);
    expect(report.steps[0]!.warnings).toContain('The old credential was restored.');
  });
});

describe('immediate hosts (Supabase Edge Functions, opted-in secret stores)', () => {
  it('confirms activation once the write succeeds, without any deploy call', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('supabase-functions', { readValues: true, redeploy: false, activation: 'immediate' });
    host.addService('project', { OPENAI_API_KEY: old.value });
    const h = await fixture(host, [provider]);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(host.writes).toHaveLength(1);
    expect(host.redeploys).toEqual([]);
    expect(report.deployments).toEqual([{ serviceKey: expect.any(String), deploymentId: null, state: 'success' }]);
    expect(provider.revoked).toEqual([old.ref]);
  });

  it('runs the health check on an immediate host and keeps the old key when it fails', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('supabase-functions', { redeploy: false, activation: 'immediate' });
    host.addService('project', { OPENAI_API_KEY: old.value });
    const h = await fixture(host, [provider], { healthCheck: async () => ({ ok: false, detail: 'Health check failed.' }) });

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.deployments[0]!.state).toBe('failed');
    expect(provider.revoked).toEqual([]);
  });

  it('an undo on an immediate host restores the old value with no deployment', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('supabase-functions', { redeploy: false, activation: 'immediate' });
    host.addService('project', { OPENAI_API_KEY: old.value });
    const h = await fixture(host, [provider], { grace: async () => 'undo' });

    const report = await executePlan(h.plan, h.inv, h.deps, { ...options, graceMs: 60_000 });

    expect(host.peek('project', 'OPENAI_API_KEY')).toBe(old.value);
    expect(host.redeploys).toEqual([]);
    expect(h.entries.some(entry => entry.event === 'deploy-result' && entry.data?.undo === true && entry.data?.immediate === true)).toBe(true);
    expect(report.steps[0]!.warnings).toContain('The old credential was restored.');
  });
});

describe('manual hosts', () => {
  it('a host that declares manual activation blocks an atomic roll, like Fly and dotenv', async () => {
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'cf_TokenAz9Y8X7W6V5U4T3S2R1Q_');
    const old = provider.issue();
    const host = new FakeHost('zeabur', { activation: 'manual' });
    host.addService('api', { CLOUDFLARE_API_TOKEN: old.value });
    const h = await fixture(host, [provider]);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.steps[0]!.status).toBe('skipped');
    expect(report.steps[0]!.warnings.join(' ')).toMatch(/atomic.*activation.*unconfirmed/i);
    expect(provider.keys.get(old.ref)?.active).toBe(true);
    expect(host.writes).toEqual([]);
  });

  it('a per-service activationFor decides between services of one host', async () => {
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'cf_TokenAz9Y8X7W6V5U4T3S2R1Q_');
    const old = provider.issue();
    const host = new FakeHost('coolify');
    (host as FakeHost & { activationFor(service: ServiceRef): 'redeploy' | 'manual' }).activationFor = service =>
      service.serviceId.startsWith('application:') ? 'redeploy' : 'manual';
    host.addService('service:abc', { CLOUDFLARE_API_TOKEN: old.value });
    const h = await fixture(host, [provider]);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.steps[0]!.status).toBe('skipped');
    expect(provider.keys.get(old.ref)?.active).toBe(true);
  });
});
