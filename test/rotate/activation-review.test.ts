import { describe, expect, it, vi } from 'vitest';
import { buildInventory, buildPlan, createLogger, createRedactor, fingerprint, serviceKey } from '../../src/core/index.js';
import type { HostScan } from '../../src/core/index.js';
import { executePlan } from '../../src/rotate/engine.js';
import type { EngineDeps, RotateOptions } from '../../src/rotate/engine.js';
import type { Consumer, JournalEntry, ProviderId, ServiceRef } from '../../src/types.js';
import { FakeHttp } from '../helpers/fake-http.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

const key = Buffer.alloc(32, 0x6a);
const instant = new Date('2026-10-26T17:00:00.000Z');
const options: RotateOptions = {
  dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 1,
  revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 4,
};

async function fixture(hosts: FakeHost[], provider: FakeProvider) {
  const scans: HostScan[] = await Promise.all(hosts.map(async host => ({
    host: host.id,
    services: await Promise.all((await host.listServices()).map(async service => ({ service, vars: await host.readVariables(service) }))),
  })));
  const inv = buildInventory(scans, key, instant);
  const plan = buildPlan(inv);
  const entries: JournalEntry[] = [];
  const redactor = createRedactor();
  const log = createLogger({ redactor, sink: () => undefined });
  const deps: EngineDeps = {
    hosts: Object.fromEntries(hosts.map(host => [host.id, host])),
    providers(id: ProviderId) { if (id !== provider.id) throw new Error('Unexpected provider.'); return provider; },
    providerCtx: { http: new FakeHttp(), credentials: {}, log },
    journal: { async append(entry) { entries.push(structuredClone(entry)); }, async read() { return entries; } },
    prompt: async () => null, fingerprintKey: key, redactor, log, sleep: async () => undefined, reveal: async () => true,
    now: () => new Date(instant),
  };
  return { inv, plan, deps, entries };
}

function addReference(h: Awaited<ReturnType<typeof fixture>>, service: ServiceRef, oldValue: string): void {
  const cluster = h.inv.clusters.find(candidate => candidate.id === fingerprint(oldValue, key))!;
  const reference: Consumer = {
    service, varName: 'OPENAI_API_KEY', fingerprint: cluster.fingerprint, hint: cluster.hint,
    sealed: false, reference: true,
  };
  const same = (consumer: Consumer) => serviceKey(consumer.service) === serviceKey(service) && consumer.varName === reference.varName;
  cluster.consumers = [...cluster.consumers.filter(consumer => !same(consumer)), reference];
  h.inv.findings = [...h.inv.findings.filter(finding => !same(finding)), {
    ...reference, provider: 'openai', tier: 'ai', isSecret: true, confidence: 'high',
  }];
  h.plan = buildPlan(h.inv, { clusterIds: [cluster.id] });
}

describe('rotation activation and unseen consumer review regressions', () => {
  it('preserves reference expressions and redeploys every referring service once before revocation', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    host.addService('source', { OPENAI_API_KEY: old.value });
    const expression = '${{source.OPENAI_API_KEY}}';
    const reference = host.addService('reference', { OPENAI_API_KEY: expression });
    const h = await fixture([host], provider);
    addReference(h, reference, old.value);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(host.writes.map(write => write.serviceId)).toEqual(['source']);
    expect(host.peek('reference', 'OPENAI_API_KEY')).toBe(expression);
    expect([...host.redeploys].sort()).toEqual(['reference', 'source']);
    expect(report.deployments.map(deployment => deployment.state)).toEqual(['success', 'success']);
    expect(provider.revoked).toEqual([old.ref]);
  });

  it('retains the old key when a reference service fails activation', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    host.addService('source', { OPENAI_API_KEY: old.value });
    const reference = host.addService('reference', { OPENAI_API_KEY: '${{source.OPENAI_API_KEY}}' });
    host.failDeploysFor.add('reference');
    const h = await fixture([host], provider);
    addReference(h, reference, old.value);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(host.writes.map(write => write.serviceId)).toEqual(['source']);
    expect(provider.revoked).toEqual([]);
    expect(report.steps[0]?.status).toBe('failed');
    expect(report.steps[0]?.warnings.join(' ')).toMatch(/reference/);
  });

  it('rejects companions that target a reference variable beside a direct consumer of the same cluster', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    const expression = '${{mixed.OPENAI_API_KEY}}';
    const service = host.addService('mixed', { OPENAI_API_KEY: old.value, OPENAI_LINKED_KEY: expression });
    const h = await fixture([host], provider);
    const cluster = h.inv.clusters.find(candidate => candidate.id === fingerprint(old.value, key))!;
    const reference: Consumer = {
      service, varName: 'OPENAI_LINKED_KEY', fingerprint: cluster.fingerprint,
      hint: cluster.hint, sealed: false, reference: true,
    };
    cluster.consumers = [...cluster.consumers.filter(consumer => consumer.varName !== reference.varName), reference];
    h.inv.findings = [...h.inv.findings.filter(finding => finding.varName !== reference.varName), {
      ...reference, provider: 'openai', tier: 'ai', isSecret: true, confidence: 'high',
    }];
    h.plan = buildPlan(h.inv, { clusterIds: [cluster.id] });
    const rotate = provider.rotate.bind(provider);
    const rotation = vi.spyOn(provider, 'rotate').mockImplementation(async (value, ctx) => ({
      ...await rotate(value, ctx), companions: { OPENAI_LINKED_KEY: 'sk-proj-companion-that-must-not-replace-a-template' },
    }));

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(rotation).toHaveBeenCalledTimes(1);
    expect(host.writes).toEqual([]);
    expect(host.peek('mixed', 'OPENAI_API_KEY')).toBe(old.value);
    expect(host.peek('mixed', 'OPENAI_LINKED_KEY')).toBe(expression);
    expect(report.steps[0]?.status).toBe('failed');
    expect(report.steps[0]?.error).toMatch(/conflicting/i);
    expect(provider.revoked).not.toContain(old.ref);
    expect((await provider.verify(old.value, h.deps.providerCtx)).ok).toBe(true);
  });

  it('selects the direct AWS pair when the first consumer is a reference using a different alias', async () => {
    const provider = new FakeProvider('aws', 'auto', 'AwsCredentialAz9Y8X7W6V5U4T3S2R1Q-');
    const old = provider.issue();
    const oldId = 'AKIAABCDEFGHIJKLMNOP';
    const newId = 'AKIAQRSTUVWXYZABCDEF';
    const unrelatedId = 'AKIAAAAABBBBCCCCDDDD';
    const unrelatedSecret = 'unrelated-AwsSecret-Ab9Cd8Ef7Gh6Ij5Kl4';
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    const expression = '${{source.CUSTOM_AWS_SECRET_ACCESS_KEY}}';
    const referenceService = host.addService('reference', { AWS_SECRET_ALIAS: expression });
    host.addService('source', {
      CUSTOM_AWS_SECRET_ACCESS_KEY: old.value, CUSTOM_AWS_ACCESS_KEY_ID: oldId,
      AWS_ACCESS_KEY_ID: unrelatedId, AWS_SECRET_ACCESS_KEY: unrelatedSecret,
    });
    const h = await fixture([host], provider);
    const cluster = h.inv.clusters.find(candidate => candidate.id === fingerprint(old.value, key))!;
    const reference: Consumer = {
      service: referenceService, varName: 'AWS_SECRET_ALIAS', fingerprint: cluster.fingerprint,
      hint: cluster.hint, sealed: false, reference: true,
    };
    cluster.consumers = [reference, ...cluster.consumers.filter(consumer => !consumer.reference)];
    h.inv.findings = [...h.inv.findings.filter(finding => serviceKey(finding.service) !== serviceKey(referenceService)), {
      ...reference, provider: 'aws', tier: 'cloud', isSecret: true, confidence: 'high',
    }];
    h.plan = buildPlan(h.inv, { clusterIds: [cluster.id] });
    expect(h.plan.steps[0]?.consumers[0]).toMatchObject({ reference: true, varName: 'AWS_SECRET_ALIAS' });
    const rotate = provider.rotate.bind(provider);
    const rotation = vi.spyOn(provider, 'rotate').mockImplementation(async (value, ctx) => {
      expect(value).toBe(old.value);
      expect(ctx.siblingVars).toMatchObject({ CUSTOM_AWS_ACCESS_KEY_ID: oldId, CUSTOM_AWS_SECRET_ACCESS_KEY: old.value });
      expect(ctx.siblingVars).not.toHaveProperty('AWS_ACCESS_KEY_ID');
      expect(ctx.siblingVars).not.toHaveProperty('AWS_SECRET_ACCESS_KEY');
      return { ...await rotate(value, ctx), companions: { CUSTOM_AWS_ACCESS_KEY_ID: newId } };
    });
    const verify = provider.verify.bind(provider);
    const verification = vi.spyOn(provider, 'verify').mockImplementation(async (value, ctx) => {
      expect(ctx.siblingVars).toMatchObject({ CUSTOM_AWS_ACCESS_KEY_ID: newId, CUSTOM_AWS_SECRET_ACCESS_KEY: value });
      expect(ctx.siblingVars).not.toHaveProperty('AWS_ACCESS_KEY_ID');
      return verify(value, ctx);
    });
    const revoke = provider.revoke.bind(provider);
    const revocation = vi.spyOn(provider, 'revoke').mockImplementation(async (ref, ctx) => {
      expect(ctx.siblingVars).toMatchObject({
        CUSTOM_AWS_ACCESS_KEY_ID: newId, CUSTOM_AWS_SECRET_ACCESS_KEY: host.peek('source', 'CUSTOM_AWS_SECRET_ACCESS_KEY'),
      });
      expect(ctx.siblingVars).not.toHaveProperty('AWS_ACCESS_KEY_ID');
      return revoke(ref, ctx);
    });

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(rotation).toHaveBeenCalledTimes(1);
    expect(verification).toHaveBeenCalledTimes(1);
    expect(revocation).toHaveBeenCalledTimes(1);
    expect(report.steps[0]?.status).toBe('revoked');
    expect(host.writes).toHaveLength(1);
    expect(host.writes[0]).toMatchObject({ serviceId: 'source', vars: { CUSTOM_AWS_ACCESS_KEY_ID: newId } });
    expect(host.peek('source', 'CUSTOM_AWS_SECRET_ACCESS_KEY')).not.toBe(old.value);
    expect(host.peek('source', 'AWS_ACCESS_KEY_ID')).toBe(unrelatedId);
    expect(host.peek('source', 'AWS_SECRET_ACCESS_KEY')).toBe(unrelatedSecret);
    expect(host.peek('reference', 'AWS_SECRET_ALIAS')).toBe(expression);
    expect([...host.redeploys].sort()).toEqual(['reference', 'source']);
    expect(provider.revoked).toEqual([old.ref]);
  });

  for (const match of ['provider', 'variable'] as const) {
    it(`retains the old key and identifies unplanned sealed findings matching its ${match}`, async () => {
      const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
      const old = provider.issue();
      const host = new FakeHost('railway');
      host.pendingPolls = 0;
      host.addService('api', { OPENAI_API_KEY: old.value });
      const sealedName = match === 'provider' ? 'OPENAI_BACKUP_TOKEN' : 'OPENAI_API_KEY';
      const sealed = new FakeHost('github-actions', { redeploy: false });
      sealed.addService('ci', { [sealedName]: old.value }, [sealedName]);
      const h = await fixture([host, sealed], provider);
      if (match === 'variable') {
        const finding = h.inv.findings.find(finding => finding.service.host === 'github-actions')!;
        finding.provider = 'stripe';
      }
      h.plan = buildPlan(h.inv, { clusterIds: [fingerprint(old.value, key)] });

      const report = await executePlan(h.plan, h.inv, h.deps, options);

      expect(host.writes).toHaveLength(1);
      expect(provider.revoked).toEqual([]);
      expect(report.steps[0]?.warnings.join(' ')).toContain(`github-actions/ci:${sealedName}`);
      expect(report.steps[0]?.warnings.join(' ')).toMatch(/sealed/i);
    });
  }

  it('blocks atomic roll before provider mutation when a matching sealed copy is outside the plan', async () => {
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'cf-api-token-Az9Y8X7W6V5U4T3S2R1Q-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: old.value });
    const sealed = new FakeHost('github-actions', { redeploy: false });
    sealed.addService('ci', { CLOUDFLARE_API_TOKEN: old.value }, ['CLOUDFLARE_API_TOKEN']);
    const h = await fixture([host, sealed], provider);
    h.plan = buildPlan(h.inv, { clusterIds: [fingerprint(old.value, key)] });

    const report = await executePlan(h.plan, h.inv, h.deps, { ...options, revoke: 'never' });

    expect(provider.keys.size).toBe(1);
    expect((await provider.verify(old.value, h.deps.providerCtx)).ok).toBe(true);
    expect(host.writes).toEqual([]);
    expect(report.steps[0]?.status).toBe('skipped');
    expect(report.steps[0]?.warnings.join(' ')).toContain('github-actions/ci:CLOUDFLARE_API_TOKEN');
  });

  it('acceptUnplannedSealed permits the explicitly accepted revocation risk', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    host.addService('api', { OPENAI_API_KEY: old.value });
    const sealed = new FakeHost('github-actions', { redeploy: false });
    sealed.addService('ci', { OPENAI_API_KEY: old.value }, ['OPENAI_API_KEY']);
    const h = await fixture([host, sealed], provider);
    h.plan = buildPlan(h.inv, { clusterIds: [fingerprint(old.value, key)] });

    const report = await executePlan(h.plan, h.inv, h.deps, { ...options, acceptUnplannedSealed: true });

    expect(provider.revoked).toEqual([old.ref]);
    expect(report.steps[0]?.status).toBe('revoked');
  });

  it('checks unplanned sealed copies before immediate revocation too', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    host.addService('api', { OPENAI_API_KEY: old.value });
    const sealed = new FakeHost('github-actions', { redeploy: false });
    sealed.addService('ci', { OPENAI_API_KEY: old.value }, ['OPENAI_API_KEY']);
    const h = await fixture([host, sealed], provider);
    h.plan = buildPlan(h.inv, { clusterIds: [fingerprint(old.value, key)] });

    const report = await executePlan(h.plan, h.inv, h.deps, { ...options, revoke: 'immediately' });

    expect(host.writes).toHaveLength(1);
    expect(provider.revoked).toEqual([]);
    expect(report.steps[0]?.warnings.join(' ')).toContain('github-actions/ci:OPENAI_API_KEY');
  });

  it('does not block revocation for an unrelated unplanned sealed finding', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    host.addService('api', { OPENAI_API_KEY: old.value });
    const sealed = new FakeHost('github-actions', { redeploy: false });
    sealed.addService('ci', { STRIPE_SECRET_KEY: 'sealed-content' }, ['STRIPE_SECRET_KEY']);
    const h = await fixture([host, sealed], provider);
    h.plan = buildPlan(h.inv, { clusterIds: [fingerprint(old.value, key)] });

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(provider.revoked).toEqual([old.ref]);
    expect(report.steps[0]?.status).toBe('revoked');
  });

  it('acceptUnplannedSealed also permits an atomic roll', async () => {
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'cf-api-token-Az9Y8X7W6V5U4T3S2R1Q-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    host.addService('api', { CLOUDFLARE_API_TOKEN: old.value });
    const sealed = new FakeHost('github-actions', { redeploy: false });
    sealed.addService('ci', { CLOUDFLARE_API_TOKEN: old.value }, ['CLOUDFLARE_API_TOKEN']);
    const h = await fixture([host, sealed], provider);
    h.plan = buildPlan(h.inv, { clusterIds: [fingerprint(old.value, key)] });

    const report = await executePlan(h.plan, h.inv, h.deps, { ...options, acceptUnplannedSealed: true });

    expect(provider.keys.size).toBe(2);
    expect(host.writes).toHaveLength(1);
    expect((await provider.verify(old.value, h.deps.providerCtx)).ok).toBe(false);
    expect(report.steps[0]?.status).toBe('revoked');
  });

  for (const kind of ['dotenv', 'github-actions', 'null-id', 'redeploy-disabled'] as const) {
    it(`reports ${kind} activation as unconfirmed and lists the service needing restart or next deploy`, async () => {
      const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
      const old = provider.issue();
      const withoutDeploy = kind === 'dotenv' || kind === 'github-actions';
      const host = new FakeHost(withoutDeploy ? kind : 'railway', { redeploy: !withoutDeploy });
      const service = host.addService('manual-app', { OPENAI_API_KEY: old.value });
      if (kind === 'null-id') vi.spyOn(host, 'redeploy').mockResolvedValue(null);
      const h = await fixture([host], provider);

      const report = await executePlan(h.plan, h.inv, h.deps, { ...options, redeploy: kind !== 'redeploy-disabled' });

      expect(host.writes).toHaveLength(1);
      expect(provider.revoked).toEqual([]);
      expect(report.deployments).toEqual([{ serviceKey: serviceKey(service), deploymentId: null, state: 'unconfirmed' }]);
      expect(report.steps[0]?.status).toBe('written');
      expect(report.steps[0]?.warnings.join(' ')).toMatch(/manual-app/);
      expect(report.steps[0]?.warnings.join(' ')).toMatch(/manual restart|next deploy/i);
      expect(h.entries.some(entry => entry.event === 'deploy-result' && entry.serviceKey === serviceKey(service) && entry.data?.state === 'unconfirmed')).toBe(true);
    });
  }

  it('revokeUnconfirmed explicitly permits revocation after an unconfirmed activation and reports the choice', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('dotenv', { redeploy: false });
    host.addService('manual-app', { OPENAI_API_KEY: old.value });
    const h = await fixture([host], provider);

    const report = await executePlan(h.plan, h.inv, h.deps, { ...options, revokeUnconfirmed: true });

    expect(provider.revoked).toEqual([old.ref]);
    expect(report.deployments[0]?.state).toBe('unconfirmed');
    expect(report.steps[0]?.warnings.join(' ')).toMatch(/unconfirmed/i);
    expect(report.steps[0]?.warnings.join(' ')).toContain('manual-app');
    expect(h.entries.some(entry => entry.event === 'revoked')).toBe(true);
  });

  it('failed deployments remain failures even with revokeUnconfirmed, with distinct per-service diagnostics', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    const failed = host.addService('failed-app', { OPENAI_API_KEY: old.value });
    const manual = host.addService('manual-app', { OPENAI_API_KEY: old.value });
    host.failDeploysFor.add('failed-app');
    const redeploy = host.redeploy.bind(host);
    vi.spyOn(host, 'redeploy').mockImplementation(async service => service.serviceId === 'manual-app' ? null : redeploy(service));
    const h = await fixture([host], provider);

    const report = await executePlan(h.plan, h.inv, h.deps, { ...options, revokeUnconfirmed: true });

    expect(provider.revoked).toEqual([]);
    expect(report.steps[0]?.status).toBe('failed');
    const warnings = report.steps[0]?.warnings.join(' ');
    expect(warnings).toMatch(/failed.*failed-app|failed-app.*failed/i);
    expect(warnings).toMatch(/unconfirmed.*manual-app|manual-app.*unconfirmed/i);
    expect(h.entries.some(entry => entry.event === 'deploy-result' && entry.serviceKey === serviceKey(failed) && entry.data?.state === 'failed')).toBe(true);
    expect(h.entries.some(entry => entry.event === 'deploy-result' && entry.serviceKey === serviceKey(manual) && entry.data?.state === 'unconfirmed')).toBe(true);
  });

  it('runs at most eight redeploys concurrently and redeploys each service exactly once', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    for (let i = 0; i < 19; i++) host.addService(`app-${i}`, { OPENAI_API_KEY: old.value });
    const h = await fixture([host], provider);
    let active = 0;
    let peak = 0;
    const redeploy = host.redeploy.bind(host);
    vi.spyOn(host, 'redeploy').mockImplementation(async service => {
      active++;
      peak = Math.max(peak, active);
      await new Promise<void>(resolve => setTimeout(resolve, 2));
      const id = await redeploy(service);
      active--;
      return id;
    });

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(peak).toBe(8);
    expect(host.redeploys).toHaveLength(19);
    expect(new Set(host.redeploys).size).toBe(19);
    expect(report.deployments.every(deployment => deployment.state === 'success')).toBe(true);
    expect(provider.revoked).toEqual([old.ref]);
  });
});
