import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  buildInventory,
  buildPlan,
  createLogger,
  createRedactor,
  fingerprint,
  makeHint,
  serviceKey,
} from '../../src/core/index.js';
import type { HostScan } from '../../src/core/index.js';
import { executePlan } from '../../src/rotate/engine.js';
import type { EngineDeps, RotateOptions } from '../../src/rotate/engine.js';
import type { Journal, JournalEntry, ProviderAdapter, ProviderId, RotationReport } from '../../src/types.js';
import { FakeHttp } from '../helpers/fake-http.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

const fingerprintKey = Buffer.alloc(32, 0x57);
const instant = new Date('2026-10-26T17:00:00.000Z');
const liveOptions: RotateOptions = {
  dryRun: false,
  revoke: 'after-deploy',
  redeploy: true,
  deployTimeoutMs: 1_000,
  pollIntervalMs: 10,
  revokeUnconfirmed: false,
  acceptUnplannedSealed: false,
  allowGenerate: true,
  verifyRetries: 4,
};

function memoryJournal(): Journal & { entries: JournalEntry[] } {
  const entries: JournalEntry[] = [];
  return {
    entries,
    async append(entry) { entries.push(structuredClone(entry)); },
    async read(planId) { return entries.filter(entry => planId === undefined || entry.planId === planId); },
  };
}

async function setup(hosts: FakeHost[], providers: FakeProvider[]) {
  const scans: HostScan[] = [];
  for (const host of hosts) {
    const services = await host.listServices();
    scans.push({
      host: host.id,
      services: await Promise.all(services.map(async service => ({ service, vars: await host.readVariables(service) }))),
    });
  }
  const inv = buildInventory(scans, fingerprintKey, instant);
  const plan = buildPlan(inv);
  const redactor = createRedactor();
  const lines: string[] = [];
  const log = createLogger({ redactor, level: 'debug', json: true, sink: line => lines.push(line) });
  const journal = memoryJournal();
  const prompt = vi.fn<EngineDeps['prompt']>().mockResolvedValue(null);
  const sleep = vi.fn<NonNullable<EngineDeps['sleep']>>().mockResolvedValue(undefined);
  const byId = new Map<ProviderId, ProviderAdapter>(providers.map(provider => [provider.id, provider]));
  const deps: EngineDeps = {
    hosts: Object.fromEntries(hosts.map(host => [host.id, host])),
    providers(id) {
      const provider = byId.get(id);
      if (!provider) throw new Error(`No test provider for ${id}`);
      return provider;
    },
    providerCtx: { http: new FakeHttp(), credentials: {}, log },
    journal,
    prompt,
    fingerprintKey,
    redactor,
    log,
    sleep,
    now: () => new Date(instant),
  };
  return { inv, plan, deps, journal, prompt, sleep, redactor, log, lines };
}

function stepFor(report: RotationReport, value: string) {
  const step = report.steps.find(step => step.clusterId === fingerprint(value, fingerprintKey));
  expect(step).toBeDefined();
  return step!;
}

function expectNoSecrets(output: unknown, values: string[]) {
  const serialized = JSON.stringify(output);
  for (const value of values) expect(serialized).not.toContain(value);
}

afterEach(() => vi.restoreAllMocks());

describe('executePlan', () => {
  it('rotates a shared key once, batches its three consumers across two hosts, and revokes after both deployments succeed', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const railway = new FakeHost('railway');
    const render = new FakeHost('render');
    const api = railway.addService('api', { OPENAI_API_KEY: old.value, OPENAI_BACKUP_KEY: old.value, NODE_ENV: 'production' });
    const worker = render.addService('worker', { OPENAI_TOKEN: old.value });
    const h = await setup([railway, render], [provider]);
    expect(h.inv.clusters).toHaveLength(1);
    expect(h.plan.steps[0]?.consumers).toHaveLength(3);
    const rotate = vi.spyOn(provider, 'rotate');
    const verified = vi.spyOn(provider, 'verify');
    const completed = new Set<string>();
    for (const host of [railway, render]) {
      const original = host.deploymentStatus.bind(host);
      vi.spyOn(host, 'deploymentStatus').mockImplementation(async (service, deploymentId) => {
        const state = await original(service, deploymentId);
        if (state === 'success') completed.add(serviceKey(service));
        return state;
      });
    }
    const originalRevoke = provider.revoke.bind(provider);
    vi.spyOn(provider, 'revoke').mockImplementation(async (ref, ctx) => {
      expect(completed).toEqual(new Set([serviceKey(api), serviceKey(worker)]));
      expect(railway.writes).toHaveLength(1);
      expect(render.writes).toHaveLength(1);
      await originalRevoke(ref, ctx);
    });

    const report = await executePlan(h.plan, h.inv, h.deps, liveOptions);

    expect(rotate).toHaveBeenCalledTimes(1);
    const replacement = railway.peek('api', 'OPENAI_API_KEY')!;
    expect(replacement).not.toBe(old.value);
    expect(railway.writes).toEqual([{ serviceId: 'api', vars: { OPENAI_API_KEY: replacement, OPENAI_BACKUP_KEY: replacement }, skipDeploy: true }]);
    expect(render.writes).toEqual([{ serviceId: 'worker', vars: { OPENAI_TOKEN: replacement }, skipDeploy: true }]);
    expect(railway.peek('api', 'NODE_ENV')).toBe('production');
    expect(railway.redeploys).toEqual(['api']);
    expect(render.redeploys).toEqual(['worker']);
    expect(verified).toHaveBeenCalledWith(replacement, expect.any(Object));
    expect(provider.revoked).toEqual([old.ref]);
    expect(stepFor(report, old.value)).toMatchObject({ status: 'revoked', newFingerprint: fingerprint(replacement, fingerprintKey) });
    expect(report.deployments.map(deploy => deploy.state)).toEqual(['success', 'success']);
    expectNoSecrets({ report, journal: h.journal.entries, logs: h.lines }, [old.value, replacement]);
  });

  it('merges two independent clusters into one service write and one redeployment', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const first = provider.issue('first');
    const second = provider.issue('second');
    const host = new FakeHost('railway');
    host.addService('api', { OPENAI_API_KEY: first.value, OPENAI_SECONDARY_KEY: second.value, NODE_ENV: 'production' });
    const h = await setup([host], [provider]);
    expect(h.plan.steps).toHaveLength(2);

    const report = await executePlan(h.plan, h.inv, h.deps, liveOptions);

    const firstNew = host.peek('api', 'OPENAI_API_KEY')!;
    const secondNew = host.peek('api', 'OPENAI_SECONDARY_KEY')!;
    expect(firstNew).not.toBe(first.value);
    expect(secondNew).not.toBe(second.value);
    expect(firstNew).not.toBe(secondNew);
    expect(host.writes).toEqual([{ serviceId: 'api', vars: { OPENAI_API_KEY: firstNew, OPENAI_SECONDARY_KEY: secondNew }, skipDeploy: true }]);
    expect(host.redeploys).toEqual(['api']);
    expect(new Set(provider.revoked)).toEqual(new Set([first.ref, second.ref]));
    expect(report.steps.map(step => step.status)).toEqual(['revoked', 'revoked']);
  });

  it('dry-run shows old hints and (new), with no provider mutations, host writes, deployments, or prompts', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { OPENAI_API_KEY: old.value });
    const h = await setup([host], [provider]);
    const rotate = vi.spyOn(provider, 'rotate');
    const revoke = vi.spyOn(provider, 'revoke');
    const verify = vi.spyOn(provider, 'verify');

    const report = await executePlan(h.plan, h.inv, h.deps, { ...liveOptions, dryRun: true });

    expect(report.dryRun).toBe(true);
    expect(report.diff.join('\n')).toContain('OPENAI_API_KEY');
    expect(report.diff.join('\n')).toContain(makeHint(old.value));
    expect(report.diff.join('\n')).toContain('(new)');
    expect(report.diff.join('\n')).toMatch(/redeploy/i);
    expect(host.writes).toEqual([]);
    expect(host.redeploys).toEqual([]);
    expect(rotate).not.toHaveBeenCalled();
    expect(revoke).not.toHaveBeenCalled();
    expect(verify).not.toHaveBeenCalled();
    expect(h.prompt).not.toHaveBeenCalled();
    expect(provider.keys.size).toBe(1);
    expect(['pending', 'skipped']).toContain(report.steps[0]?.status);
    expectNoSecrets({ report, journal: h.journal.entries, logs: h.lines }, [old.value]);
  });

  it('cleans up a newly created key after failed verification, keeps the old key, and continues independent steps', async () => {
    const broken = new FakeProvider('openai', 'auto', 'sk-proj-');
    const healthy = new FakeProvider('resend', 'auto', 're_');
    const badOld = broken.issue();
    const goodOld = healthy.issue();
    broken.failVerifyOfNew = true;
    const host = new FakeHost('railway');
    host.addService('api', { OPENAI_API_KEY: badOld.value, RESEND_API_KEY: goodOld.value });
    const h = await setup([host], [broken, healthy]);

    const report = await executePlan(h.plan, h.inv, h.deps, liveOptions);

    expect(stepFor(report, badOld.value).status).toBe('failed');
    expect(stepFor(report, goodOld.value).status).toBe('revoked');
    expect(host.peek('api', 'OPENAI_API_KEY')).toBe(badOld.value);
    expect(host.peek('api', 'RESEND_API_KEY')).not.toBe(goodOld.value);
    expect(Object.keys(host.writes[0]!.vars)).toEqual(['RESEND_API_KEY']);
    expect(broken.keys.get(badOld.ref)?.active).toBe(true);
    const badNew = [...broken.keys.values()].find(key => key.ref !== badOld.ref)!;
    expect(badNew.active).toBe(false);
    expect(broken.revoked).toEqual([badNew.ref]);
    expect(healthy.revoked).toEqual([goodOld.ref]);
    expect(h.journal.entries).toContainEqual(expect.objectContaining({ event: 'failed', clusterId: fingerprint(badOld.value, fingerprintKey) }));
    expectNoSecrets({ report, journal: h.journal.entries, logs: h.lines }, [badOld.value, badNew.value, goodOld.value]);
  });

  it.each(['after-deploy', 'immediately', 'never'] as const)('blocks revocation of every cluster affected by a failed service write under %s while independent services proceed', async (revoke) => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const shared = provider.issue('shared');
    const sameService = provider.issue('also-on-failed-service');
    const independent = provider.issue('independent');
    const host = new FakeHost('railway');
    host.addService('broken', { OPENAI_API_KEY: shared.value, OPENAI_SECONDARY_KEY: sameService.value });
    host.addService('shared-copy', { OPENAI_API_KEY: shared.value });
    host.addService('healthy', { OPENAI_API_KEY: independent.value });
    host.failWritesFor.add('broken');
    const h = await setup([host], [provider]);

    const report = await executePlan(h.plan, h.inv, h.deps, { ...liveOptions, revoke });

    expect(stepFor(report, shared.value).status).toBe('failed');
    expect(stepFor(report, sameService.value).status).toBe('failed');
    expect(revoke === 'never' ? ['written', 'deployed', 'verified'] : ['revoked']).toContain(stepFor(report, independent.value).status);
    expect(provider.revoked).toEqual(revoke === 'never' ? [] : [independent.ref]);
    expect(provider.keys.get(shared.ref)?.active).toBe(true);
    expect(provider.keys.get(sameService.ref)?.active).toBe(true);
    expect(host.peek('broken', 'OPENAI_API_KEY')).toBe(shared.value);
    expect(host.peek('shared-copy', 'OPENAI_API_KEY')).not.toBe(shared.value);
    expect(host.peek('healthy', 'OPENAI_API_KEY')).not.toBe(independent.value);
    expect(host.redeploys).not.toContain('broken');
    expect(host.redeploys).toContain('healthy');
  });

  it.each([
    { revoke: 'after-deploy' as const, revoked: false, status: 'failed' },
    { revoke: 'immediately' as const, revoked: true, status: 'failed' },
    { revoke: 'never' as const, revoked: false, status: 'failed' },
  ])('uses the $revoke policy when deployment fails', async ({ revoke, revoked, status }) => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { OPENAI_API_KEY: old.value });
    host.failDeploysFor.add('api');
    const h = await setup([host], [provider]);

    const report = await executePlan(h.plan, h.inv, h.deps, { ...liveOptions, revoke });

    expect(host.peek('api', 'OPENAI_API_KEY')).not.toBe(old.value);
    expect(report.deployments).toEqual([expect.objectContaining({ state: 'failed' })]);
    expect(provider.revoked).toEqual(revoked ? [old.ref] : []);
    expect(provider.keys.get(old.ref)?.active).toBe(!revoked);
    expect(stepFor(report, old.value).status).toBe(status);
  });

  it('does not revoke again when an atomic roll already revoked the old key', async () => {
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'Cf9Q7b4T2k1D8n5P6a3-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: old.value });
    const h = await setup([host], [provider]);
    expect(h.plan.steps[0]?.method).toBe('atomic-roll');
    const revoke = vi.spyOn(provider, 'revoke');

    const report = await executePlan(h.plan, h.inv, h.deps, liveOptions);

    expect(host.peek('api', 'CLOUDFLARE_API_TOKEN')).not.toBe(old.value);
    expect(provider.keys.get(old.ref)?.active).toBe(false);
    expect(revoke).not.toHaveBeenCalled();
    expect(stepFor(report, old.value).status).toBe('revoked');
    expect(h.journal.entries).toContainEqual(expect.objectContaining({
      event: 'revoked', clusterId: fingerprint(old.value, fingerprintKey), data: expect.objectContaining({ oldRevoked: true }),
    }));
  });

  it('passes provider guidance and every consumer to a guided prompt, verifies the pasted key, and resolves both refs', async () => {
    const provider = new FakeProvider('stripe', 'guided', 'sk_live_');
    const old = provider.issue();
    const pasted = provider.issue('created-in-dashboard');
    const host = new FakeHost('railway');
    host.addService('api', { STRIPE_SECRET_KEY: old.value, STRIPE_BACKUP_KEY: old.value });
    const h = await setup([host], [provider]);
    h.prompt.mockResolvedValue(pasted.value);
    const rotate = vi.spyOn(provider, 'rotate');
    const verify = vi.spyOn(provider, 'verify');
    const resolve = vi.spyOn(provider, 'resolveKeyRef');

    const report = await executePlan(h.plan, h.inv, h.deps, liveOptions);

    expect(h.prompt).toHaveBeenCalledWith({
      clusterId: fingerprint(old.value, fingerprintKey),
      provider: 'stripe',
      hint: makeHint(old.value),
      guidance: provider.guidance(),
      consumers: h.plan.steps[0]!.consumers,
    });
    expect(rotate).not.toHaveBeenCalled();
    expect(verify).toHaveBeenCalledWith(pasted.value, expect.any(Object));
    expect(resolve).toHaveBeenCalledWith(old.value, expect.any(Object));
    expect(resolve).toHaveBeenCalledWith(pasted.value, expect.any(Object));
    expect(host.writes[0]?.vars).toEqual({ STRIPE_SECRET_KEY: pasted.value, STRIPE_BACKUP_KEY: pasted.value });
    expect(provider.revoked).toEqual([old.ref]);
    expect(stepFor(report, old.value)).toMatchObject({ status: 'revoked', oldKeyRef: old.ref, newKeyRef: pasted.ref });
    expectNoSecrets({ report, journal: h.journal.entries, logs: h.lines }, [old.value, pasted.value]);
  });

  it('skips a guided step when the prompt returns null without writing, deploying, or revoking', async () => {
    const provider = new FakeProvider('stripe', 'guided', 'sk_live_');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { STRIPE_SECRET_KEY: old.value });
    const h = await setup([host], [provider]);
    const verify = vi.spyOn(provider, 'verify');

    const report = await executePlan(h.plan, h.inv, h.deps, liveOptions);

    expect(h.prompt).toHaveBeenCalledTimes(1);
    expect(stepFor(report, old.value).status).toBe('skipped');
    expect(verify).not.toHaveBeenCalled();
    expect(host.writes).toEqual([]);
    expect(host.redeploys).toEqual([]);
    expect(provider.revoked).toEqual([]);
    expect(provider.keys.get(old.ref)?.active).toBe(true);
  });

  it('re-reads the current value and skips a stale fingerprint without creating or revoking credentials', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const changed = provider.issue('changed-outside-keysentry');
    const host = new FakeHost('railway');
    const service = host.addService('api', { OPENAI_API_KEY: old.value });
    const h = await setup([host], [provider]);
    await host.writeVariables(service, { OPENAI_API_KEY: changed.value }, { skipDeploy: true });
    host.writes.length = 0;
    const read = vi.spyOn(host, 'readVariables');
    const rotate = vi.spyOn(provider, 'rotate');

    const report = await executePlan(h.plan, h.inv, h.deps, liveOptions);

    expect(read).toHaveBeenCalledWith(service);
    expect(stepFor(report, old.value).status).toBe('skipped');
    expect(stepFor(report, old.value).warnings.join(' ')).toMatch(/stale|mismatch|changed/i);
    expect(rotate).not.toHaveBeenCalled();
    expect(host.peek('api', 'OPENAI_API_KEY')).toBe(changed.value);
    expect(host.writes).toEqual([]);
    expect(host.redeploys).toEqual([]);
    expect(provider.revoked).toEqual([]);
  });

  it('falls back to guided rotation for an automatic provider when the old value is sealed', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const pasted = provider.issue('manual-for-sealed');
    const host = new FakeHost('vercel');
    host.addService('api', { OPENAI_API_KEY: old.value }, ['OPENAI_API_KEY']);
    const h = await setup([host], [provider]);
    expect(h.inv.clusters[0]?.fingerprint).toBeNull();
    expect(h.plan.steps[0]?.method).toBe('auto');
    h.prompt.mockResolvedValue(pasted.value);
    const rotate = vi.spyOn(provider, 'rotate');
    const verify = vi.spyOn(provider, 'verify');

    const report = await executePlan(h.plan, h.inv, h.deps, liveOptions);

    expect(h.prompt).toHaveBeenCalledWith(expect.objectContaining({ guidance: provider.guidance(), hint: null, consumers: h.plan.steps[0]!.consumers }));
    expect(rotate).not.toHaveBeenCalled();
    expect(verify).toHaveBeenCalledWith(pasted.value, expect.any(Object));
    expect(host.peek('api', 'OPENAI_API_KEY')).toBe(pasted.value);
    expect(host.writes).toHaveLength(1);
    expect(provider.revoked).toEqual([]);
    expect(provider.keys.get(old.ref)?.active).toBe(true);
    expect(report.steps[0]).toMatchObject({ newKeyRef: pasted.ref, newFingerprint: fingerprint(pasted.value, fingerprintKey) });
    expect(report.steps[0]?.status).not.toBe('failed');
  });

  it('writes companion values in the same batch and uses the replacement siblings for verification and revocation', async () => {
    const provider = new FakeProvider('aws', 'auto', 'AbCdEfGhIjKlMnOpQrStUvWxYz012345-');
    const old = provider.issue();
    const oldAccessId = 'AKIAABCDEFGHIJKLMNOP';
    const newAccessId = 'AKIAQRSTUVWXYZABCDEF';
    const host = new FakeHost('railway');
    host.addService('api', { AWS_SECRET_ACCESS_KEY: old.value, AWS_ACCESS_KEY_ID: oldAccessId, AWS_REGION: 'eu-west-1' });
    const h = await setup([host], [provider]);
    const originalRotate = provider.rotate.bind(provider);
    vi.spyOn(provider, 'rotate').mockImplementation(async (value, ctx) => {
      expect(ctx.siblingVars).toMatchObject({ AWS_ACCESS_KEY_ID: oldAccessId, AWS_REGION: 'eu-west-1' });
      return {
        ...await originalRotate(value, ctx),
        oldKeyRef: oldAccessId,
        newKeyRef: newAccessId,
        companions: { AWS_ACCESS_KEY_ID: newAccessId },
      };
    });
    const originalVerify = provider.verify.bind(provider);
    vi.spyOn(provider, 'verify').mockImplementation(async (value, ctx) => {
      expect(ctx.siblingVars).toMatchObject({ AWS_ACCESS_KEY_ID: newAccessId, AWS_SECRET_ACCESS_KEY: value, AWS_REGION: 'eu-west-1' });
      ctx.log.info('Verifying AWS replacement.', { newKeyRef: newAccessId, secret: value });
      return originalVerify(value, ctx);
    });
    const originalRevoke = provider.revoke.bind(provider);
    vi.spyOn(provider, 'revoke').mockImplementation(async (ref, ctx) => {
      expect(ref).toBe(oldAccessId);
      expect(ctx.siblingVars).toMatchObject({ AWS_ACCESS_KEY_ID: newAccessId, AWS_SECRET_ACCESS_KEY: host.peek('api', 'AWS_SECRET_ACCESS_KEY'), AWS_REGION: 'eu-west-1' });
      return originalRevoke(old.ref, ctx);
    });

    const report = await executePlan(h.plan, h.inv, h.deps, liveOptions);

    const replacement = host.peek('api', 'AWS_SECRET_ACCESS_KEY')!;
    expect(host.writes).toEqual([{ serviceId: 'api', vars: { AWS_SECRET_ACCESS_KEY: replacement, AWS_ACCESS_KEY_ID: newAccessId }, skipDeploy: true }]);
    expect(host.peek('api', 'AWS_ACCESS_KEY_ID')).toBe(newAccessId);
    expect(host.peek('api', 'AWS_REGION')).toBe('eu-west-1');
    expect(host.redeploys).toEqual(['api']);
    expect(stepFor(report, old.value)).toMatchObject({ status: 'revoked', oldKeyRef: oldAccessId, newKeyRef: newAccessId });
    for (const event of ['created', 'verified', 'revoked'] as const) {
      expect(h.journal.entries).toContainEqual(expect.objectContaining({
        event,
        clusterId: fingerprint(old.value, fingerprintKey),
        data: expect.objectContaining({ oldKeyRef: oldAccessId, newKeyRef: newAccessId }),
      }));
    }
    expect(provider.revoked).toEqual([old.ref]);
    expectNoSecrets({ report, journal: h.journal.entries, logs: h.lines }, [old.value, replacement]);
    expect(h.lines.join('\n')).not.toContain(newAccessId);
    expect(h.lines.join('\n')).toContain('Verifying AWS replacement.');
    expect(h.deps.providerCtx.siblingVars).toBeUndefined();
  });

  it('journals the actual revoked state when an immediate revoke succeeds before a deployment failure', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { OPENAI_API_KEY: old.value });
    host.failDeploysFor.add('api');
    const h = await setup([host], [provider]);

    const report = await executePlan(h.plan, h.inv, h.deps, { ...liveOptions, revoke: 'immediately' });

    expect(provider.revoked).toEqual([old.ref]);
    expect(provider.keys.get(old.ref)?.active).toBe(false);
    expect(stepFor(report, old.value).status).toBe('failed');
    expect(report.deployments[0]?.state).toBe('failed');
    const clusterId = fingerprint(old.value, fingerprintKey);
    expect(h.journal.entries).toContainEqual(expect.objectContaining({
      event: 'created', clusterId, data: expect.objectContaining({ oldRevoked: false }),
    }));
    expect(h.journal.entries).toContainEqual(expect.objectContaining({
      event: 'revoked', clusterId, data: expect.objectContaining({ oldRevoked: true }),
    }));
    expect(h.journal.entries).toContainEqual(expect.objectContaining({
      event: 'failed', clusterId, data: expect.objectContaining({ oldRevoked: true }),
    }));
    expect(h.journal.entries.findIndex(entry => entry.event === 'revoked')).toBeLessThan(h.journal.entries.findIndex(entry => entry.event === 'redeploy'));
    expect(stepFor(report, old.value).warnings.join(' ')).toMatch(/already.*revoked|revoked.*already/i);
  });

  it('registers newly created secrets before logging or verification and journals every transition without plaintext', async () => {
    // These deliberately avoid known key patterns, so masking proves registration happened.
    const provider = new FakeProvider('openai', 'auto', 'Z9uQ7eW4tY6rP3aS8dF1gH5jK0lC2vB-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    const service = host.addService('api', { OPENAI_API_KEY: old.value });
    const h = await setup([host], [provider]);
    const companion = 'N8tR4mV2yQ6pD1sF7gH0jK5lB9cW3zA';
    let newValue: string | undefined;
    const registered = new Set<string>();
    const originalRegister = h.redactor.register.bind(h.redactor);
    vi.spyOn(h.redactor, 'register').mockImplementation(value => {
      registered.add(value);
      originalRegister(value);
    });
    for (const level of ['info', 'warn', 'error', 'debug'] as const) {
      const originalLog = h.log[level].bind(h.log);
      vi.spyOn(h.log, level).mockImplementation((message: string, data?: Record<string, unknown>) => {
        if (newValue !== undefined) {
          expect(registered.has(newValue)).toBe(true);
          expect(registered.has(companion)).toBe(true);
        }
        originalLog(message, data);
      });
    }
    const originalRotate = provider.rotate.bind(provider);
    vi.spyOn(provider, 'rotate').mockImplementation(async (value, ctx) => {
      const result = await originalRotate(value, ctx);
      newValue = result.newValue;
      return { ...result, companions: { OPENAI_AUX_TOKEN: companion }, notes: `Issued ${newValue}` };
    });
    const originalVerify = provider.verify.bind(provider);
    vi.spyOn(provider, 'verify').mockImplementation(async (value, ctx) => {
      expect(registered.has(value)).toBe(true);
      expect(registered.has(companion)).toBe(true);
      ctx.log.info(`Verifying ${value}`, { companion });
      return originalVerify(value, ctx);
    });

    const report = await executePlan(h.plan, h.inv, h.deps, liveOptions);

    expect(newValue).toBeDefined();
    expect(h.lines.join('\n')).toContain('«redacted»');
    expect(stepFor(report, old.value).status).toBe('revoked');
    const events = h.journal.entries.map(entry => entry.event);
    expect(events[0]).toBe('plan-start');
    expect(events.at(-1)).toBe('plan-end');
    for (const [before, after] of [
      ['created', 'verified'],
      ['verified', 'written'],
      ['written', 'redeploy'],
      ['redeploy', 'deploy-result'],
      ['deploy-result', 'revoked'],
    ] as const) {
      expect(events.indexOf(before)).toBeGreaterThanOrEqual(0);
      expect(events.indexOf(after)).toBeGreaterThan(events.indexOf(before));
    }
    expect(h.journal.entries).toContainEqual(expect.objectContaining({ event: 'written', serviceKey: serviceKey(service) }));
    expect(h.journal.entries).toContainEqual(expect.objectContaining({ event: 'created', clusterId: fingerprint(old.value, fingerprintKey) }));
    expect(JSON.stringify(h.journal.entries)).toContain(fingerprint(newValue!, fingerprintKey));
    for (const entry of h.journal.entries) {
      expect(entry.planId).toBe(h.plan.id);
      expect(Number.isNaN(Date.parse(entry.at))).toBe(false);
    }
    expectNoSecrets({ report, journal: h.journal.entries, logs: h.lines }, [old.value, newValue!, companion]);
  });

  it('polls pending deployments using the injected sleep before revoking', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.pendingPolls = 2;
    host.addService('api', { OPENAI_API_KEY: old.value });
    const h = await setup([host], [provider]);
    let elapsed = 0;
    h.sleep.mockImplementation(async ms => { elapsed += ms; });
    h.deps.now = () => new Date(instant.getTime() + elapsed);
    const status = vi.spyOn(host, 'deploymentStatus');

    const report = await executePlan(h.plan, h.inv, h.deps, liveOptions);

    expect(status).toHaveBeenCalledTimes(3);
    expect(h.sleep.mock.calls).toEqual([[10], [10]]);
    expect(report.deployments[0]?.state).toBe('success');
    expect(stepFor(report, old.value).status).toBe('revoked');
    expect(provider.revoked).toEqual([old.ref]);
  });

  it('times out a perpetually pending deployment and retains the old key', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.pendingPolls = 1_000;
    host.addService('api', { OPENAI_API_KEY: old.value });
    const h = await setup([host], [provider]);
    let elapsed = 0;
    h.sleep.mockImplementation(async ms => { elapsed += ms; });
    h.deps.now = () => new Date(instant.getTime() + elapsed);
    const status = vi.spyOn(host, 'deploymentStatus');

    const report = await executePlan(h.plan, h.inv, h.deps, { ...liveOptions, deployTimeoutMs: 25 });

    expect(h.sleep).toHaveBeenCalled();
    expect(elapsed).toBeGreaterThanOrEqual(25);
    expect(status.mock.calls.length).toBeLessThanOrEqual(5);
    expect(report.deployments[0]?.state).toBe('failed');
    expect(stepFor(report, old.value).status).toBe('failed');
    expect(JSON.stringify({ step: stepFor(report, old.value), journal: h.journal.entries, logs: h.lines })).toMatch(/timeout|timed out/i);
    expect(provider.revoked).toEqual([]);
    expect(provider.keys.get(old.ref)?.active).toBe(true);
  });

  it('revokes immediately after every consumer write and before starting any deployment', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { OPENAI_API_KEY: old.value });
    host.addService('worker', { OPENAI_API_KEY: old.value });
    const h = await setup([host], [provider]);
    const originalRevoke = provider.revoke.bind(provider);
    vi.spyOn(provider, 'revoke').mockImplementation(async (ref, ctx) => {
      expect(host.writes).toHaveLength(2);
      expect(host.redeploys).toEqual([]);
      expect(host.peek('api', 'OPENAI_API_KEY')).not.toBe(old.value);
      expect(host.peek('worker', 'OPENAI_API_KEY')).not.toBe(old.value);
      return originalRevoke(ref, ctx);
    });
    const originalRedeploy = host.redeploy.bind(host);
    vi.spyOn(host, 'redeploy').mockImplementation(async service => {
      expect(provider.revoked).toEqual([old.ref]);
      return originalRedeploy(service);
    });

    const report = await executePlan(h.plan, h.inv, h.deps, { ...liveOptions, revoke: 'immediately' });

    expect(stepFor(report, old.value).status).toBe('revoked');
    expect(host.redeploys).toEqual(['api', 'worker']);
    expect(provider.revoked).toEqual([old.ref]);
  });

  it('skips the entire shared cluster when a secondary consumer changed since the scan', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const changed = provider.issue('changed-secondary-copy');
    const host = new FakeHost('railway');
    host.addService('first', { OPENAI_API_KEY: old.value });
    const secondary = host.addService('second', { OPENAI_API_KEY: old.value });
    const h = await setup([host], [provider]);
    await host.writeVariables(secondary, { OPENAI_API_KEY: changed.value }, { skipDeploy: true });
    host.writes.length = 0;
    const rotate = vi.spyOn(provider, 'rotate');

    const report = await executePlan(h.plan, h.inv, h.deps, liveOptions);

    expect(stepFor(report, old.value).status).toBe('skipped');
    expect(stepFor(report, old.value).warnings.join(' ')).toMatch(/stale|mismatch|changed/i);
    expect(rotate).not.toHaveBeenCalled();
    expect(host.writes).toEqual([]);
    expect(host.peek('first', 'OPENAI_API_KEY')).toBe(old.value);
    expect(host.peek('second', 'OPENAI_API_KEY')).toBe(changed.value);
    expect(provider.revoked).toEqual([]);
  });

  it.each([
    { label: 'missing dryRun property', options: { revoke: 'immediately', redeploy: true } },
    { label: 'missing options object', options: undefined },
  ])('defaults to dry-run for a JavaScript caller with $label', async ({ options }) => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { OPENAI_API_KEY: old.value });
    const h = await setup([host], [provider]);
    const rotate = vi.spyOn(provider, 'rotate');

    const report = await executePlan(h.plan, h.inv, h.deps, options as unknown as RotateOptions);

    expect(report.dryRun).toBe(true);
    expect(rotate).not.toHaveBeenCalled();
    expect(h.prompt).not.toHaveBeenCalled();
    expect(host.writes).toEqual([]);
    expect(host.redeploys).toEqual([]);
    expect(provider.revoked).toEqual([]);
    expect(host.peek('api', 'OPENAI_API_KEY')).toBe(old.value);
  });

  it.each(['disabled', 'null-id'] as const)('keeps the old key when a capable host deployment is %s and cannot be confirmed', async mode => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { OPENAI_API_KEY: old.value });
    const h = await setup([host], [provider]);
    const redeploy = vi.spyOn(host, 'redeploy');
    if (mode === 'null-id') redeploy.mockResolvedValue(null);
    const status = vi.spyOn(host, 'deploymentStatus');

    const report = await executePlan(h.plan, h.inv, h.deps, { ...liveOptions, redeploy: mode !== 'disabled' });

    expect(host.writes).toHaveLength(1);
    expect(redeploy).toHaveBeenCalledTimes(mode === 'disabled' ? 0 : 1);
    expect(status).not.toHaveBeenCalled();
    expect(report.deployments).toEqual([expect.objectContaining({ deploymentId: null, state: 'unconfirmed' })]);
    expect(stepFor(report, old.value).status).not.toBe('revoked');
    expect(provider.revoked).toEqual([]);
    expect(provider.keys.get(old.ref)?.active).toBe(true);
    expect(stepFor(report, old.value).warnings.join(' ')).toMatch(/deploy|confirm/i);
  });

  it('retains the old key when a host needs a manual restart', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('dotenv', { redeploy: false });
    host.addService('.env', { OPENAI_API_KEY: old.value });
    const h = await setup([host], [provider]);
    const redeploy = vi.spyOn(host, 'redeploy');
    const status = vi.spyOn(host, 'deploymentStatus');

    const report = await executePlan(h.plan, h.inv, h.deps, liveOptions);

    expect(host.writes).toHaveLength(1);
    expect(redeploy).not.toHaveBeenCalled();
    expect(status).not.toHaveBeenCalled();
    expect(stepFor(report, old.value).status).toBe('written');
    expect(provider.revoked).toEqual([]);
    expect(report.deployments[0]?.state).toBe('unconfirmed');
  });

  it.each(['read', 'provider-lookup', 'rotate', 'verify-throws'] as const)('isolates a %s failure and lets an independent service finish', async failure => {
    const broken = new FakeProvider('openai', 'auto', 'sk-proj-');
    const healthy = new FakeProvider('resend', 'auto', 're_');
    const badOld = broken.issue();
    const goodOld = healthy.issue();
    const host = new FakeHost('railway');
    host.addService('broken', { OPENAI_API_KEY: badOld.value });
    host.addService('healthy', { RESEND_API_KEY: goodOld.value });
    const h = await setup([host], [broken, healthy]);
    const originalRead = host.readVariables.bind(host);
    if (failure === 'read') vi.spyOn(host, 'readVariables').mockImplementation(async service => {
      if (service.serviceId === 'broken') throw new Error(`Read refused ${badOld.value}`);
      return originalRead(service);
    });
    if (failure === 'provider-lookup') {
      const originalProviders = h.deps.providers;
      h.deps.providers = id => {
        if (id === 'openai') throw new Error(`Unavailable ${badOld.value}`);
        return originalProviders(id);
      };
    }
    if (failure === 'rotate') vi.spyOn(broken, 'rotate').mockRejectedValue(new Error(`Rotate refused ${badOld.value}`));
    if (failure === 'verify-throws') vi.spyOn(broken, 'verify').mockRejectedValue(new Error(`Verify refused ${badOld.value}`));

    const report = await executePlan(h.plan, h.inv, h.deps, liveOptions);

    expect(stepFor(report, badOld.value).status).toBe('failed');
    expect(stepFor(report, goodOld.value).status).toBe('revoked');
    expect(host.peek('broken', 'OPENAI_API_KEY')).toBe(badOld.value);
    expect(host.peek('healthy', 'RESEND_API_KEY')).not.toBe(goodOld.value);
    expect(host.writes.map(write => write.serviceId)).toEqual(['healthy']);
    expect(host.redeploys).toEqual(['healthy']);
    expect(broken.revoked).not.toContain(badOld.ref);
    expect(broken.keys.get(badOld.ref)?.active).toBe(true);
    expect(healthy.revoked).toEqual([goodOld.ref]);
    expectNoSecrets({ report, journal: h.journal.entries, logs: h.lines }, [badOld.value, goodOld.value]);
  });

  it('rejects conflicting companion values without clobbering either cluster or blocking an independent write', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const healthy = new FakeProvider('resend', 'auto', 're_');
    const first = provider.issue('first');
    const second = provider.issue('second');
    const other = healthy.issue();
    const host = new FakeHost('railway');
    host.addService('api', { OPENAI_API_KEY: first.value, OPENAI_SECONDARY_KEY: second.value, RESEND_API_KEY: other.value, SHARED_CONFIG: 'keep-original' });
    const h = await setup([host], [provider, healthy]);
    const originalRotate = provider.rotate.bind(provider);
    vi.spyOn(provider, 'rotate').mockImplementation(async (value, ctx) => ({
      ...await originalRotate(value, ctx),
      companions: { SHARED_CONFIG: value === first.value ? 'different-first-companion' : 'different-second-companion' },
    }));

    const report = await executePlan(h.plan, h.inv, h.deps, liveOptions);

    expect(stepFor(report, first.value).status).toBe('failed');
    expect(stepFor(report, second.value).status).toBe('failed');
    expect(stepFor(report, other.value).status).toBe('revoked');
    expect(host.writes).toEqual([{ serviceId: 'api', vars: { RESEND_API_KEY: host.peek('api', 'RESEND_API_KEY') }, skipDeploy: true }]);
    expect(host.peek('api', 'OPENAI_API_KEY')).toBe(first.value);
    expect(host.peek('api', 'OPENAI_SECONDARY_KEY')).toBe(second.value);
    expect(host.peek('api', 'SHARED_CONFIG')).toBe('keep-original');
    expect(provider.keys.get(first.ref)?.active).toBe(true);
    expect(provider.keys.get(second.ref)?.active).toBe(true);
    const unusedKeys = [...provider.keys.values()].filter(key => key.ref !== first.ref && key.ref !== second.ref);
    expect(unusedKeys).toHaveLength(2);
    expect(unusedKeys.every(key => !key.active)).toBe(true);
    expect(new Set(provider.revoked)).toEqual(new Set(unusedKeys.map(key => key.ref)));
    expect(healthy.revoked).toEqual([other.ref]);
  });

  it('rejects a companion that conflicts with its own replacement variable', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { OPENAI_API_KEY: old.value });
    const h = await setup([host], [provider]);
    const originalRotate = provider.rotate.bind(provider);
    vi.spyOn(provider, 'rotate').mockImplementation(async (value, ctx) => ({
      ...await originalRotate(value, ctx), companions: { OPENAI_API_KEY: 'conflicting-companion-value' },
    }));

    const report = await executePlan(h.plan, h.inv, h.deps, liveOptions);

    expect(stepFor(report, old.value).status).toBe('failed');
    expect(host.writes).toEqual([]);
    expect(host.redeploys).toEqual([]);
    expect(host.peek('api', 'OPENAI_API_KEY')).toBe(old.value);
    expect(provider.keys.get(old.ref)?.active).toBe(true);
    const unusedKeys = [...provider.keys.values()].filter(key => key.ref !== old.ref);
    expect(unusedKeys).toHaveLength(1);
    expect(unusedKeys[0]?.active).toBe(false);
    expect(provider.revoked).toEqual(unusedKeys.map(key => key.ref));
  });

  it.each(['plan-start', 'created', 'written'] as const)('stops further side effects when the %s journal transition cannot be recorded', async failedEvent => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { OPENAI_API_KEY: old.value });
    const h = await setup([host], [provider]);
    const originalAppend = h.journal.append.bind(h.journal);
    vi.spyOn(h.journal, 'append').mockImplementation(async entry => {
      if (entry.event === failedEvent) throw new Error('journal storage unavailable');
      return originalAppend(entry);
    });
    const rotate = vi.spyOn(provider, 'rotate');
    const verify = vi.spyOn(provider, 'verify');

    await expect(executePlan(h.plan, h.inv, h.deps, liveOptions)).rejects.toThrow(/journal|record/i);

    expect(rotate).toHaveBeenCalledTimes(failedEvent === 'plan-start' ? 0 : 1);
    expect(verify).toHaveBeenCalledTimes(failedEvent === 'written' ? 1 : 0);
    expect(host.writes).toHaveLength(failedEvent === 'written' ? 1 : 0);
    expect(host.redeploys).toEqual([]);
    expect(provider.revoked).toEqual([]);
    expect(provider.keys.get(old.ref)?.active).toBe(true);
    expect(h.journal.entries.map(entry => entry.event)).not.toContain('plan-end');
  });

  it('refuses AWS rotation before creating a key when shared consumers use incompatible companion names', async () => {
    const provider = new FakeProvider('aws', 'auto', 'AbCdEfGhIjKlMnOpQrStUvWxYz012345-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('standard', { AWS_SECRET_ACCESS_KEY: old.value, AWS_ACCESS_KEY_ID: 'AKIAABCDEFGHIJKLMNOP' });
    host.addService('backup', { BACKUP_SECRET_ACCESS_KEY: old.value, BACKUP_ACCESS_KEY_ID: 'AKIAABCDEFGHIJKLMNOP' });
    const h = await setup([host], [provider]);
    expect(h.plan.steps).toHaveLength(1);
    expect(h.plan.steps[0]?.provider).toBe('aws');
    const rotate = vi.spyOn(provider, 'rotate');

    const report = await executePlan(h.plan, h.inv, h.deps, liveOptions);

    expect(['failed', 'skipped']).toContain(stepFor(report, old.value).status);
    expect(rotate).not.toHaveBeenCalled();
    expect(host.writes).toEqual([]);
    expect(host.redeploys).toEqual([]);
    expect(host.peek('standard', 'AWS_SECRET_ACCESS_KEY')).toBe(old.value);
    expect(host.peek('backup', 'BACKUP_SECRET_ACCESS_KEY')).toBe(old.value);
    expect(provider.revoked).toEqual([]);
    expect(provider.keys.get(old.ref)?.active).toBe(true);
  });

  it('isolates a custom AWS pair from unrelated standard AWS credentials throughout rotation', async () => {
    const provider = new FakeProvider('aws', 'auto', 'AbCdEfGhIjKlMnOpQrStUvWxYz012345-');
    const backup = provider.issue('backup');
    const unrelated = provider.issue('unrelated-standard-pair');
    const backupId = 'AKIAABCDEFGHIJKLMNOP';
    const unrelatedId = 'AKIAQRSTUVWXYZABCDEF';
    const replacementId = 'AKIAZYXWVUTSRQPONMLK';
    const host = new FakeHost('railway');
    host.addService('api', {
      BACKUP_SECRET_ACCESS_KEY: backup.value,
      BACKUP_ACCESS_KEY_ID: backupId,
      AWS_SECRET_ACCESS_KEY: unrelated.value,
      AWS_ACCESS_KEY_ID: unrelatedId,
      AWS_REGION: 'eu-west-1',
    });
    const h = await setup([host], [provider]);
    // A caller that knows the issuing provider can correct name-only classification.
    // The inventory, consumers and keyed fingerprint still come from the actual scan.
    const backupCluster = h.inv.clusters.find(cluster => cluster.id === fingerprint(backup.value, fingerprintKey))!;
    backupCluster.provider = 'aws';
    backupCluster.tier = 'cloud';
    backupCluster.method = 'auto';
    const plan = buildPlan(h.inv, { clusterIds: [backupCluster.id] });
    const originalRotate = provider.rotate.bind(provider);
    const rotate = vi.spyOn(provider, 'rotate').mockImplementation(async (value, ctx) => {
      expect(value).toBe(backup.value);
      expect(ctx.siblingVars).toMatchObject({ BACKUP_SECRET_ACCESS_KEY: backup.value, BACKUP_ACCESS_KEY_ID: backupId });
      expect(ctx.siblingVars).not.toHaveProperty('AWS_ACCESS_KEY_ID');
      expect(ctx.siblingVars).not.toHaveProperty('AWS_SECRET_ACCESS_KEY');
      return { ...await originalRotate(value, ctx), companions: { BACKUP_ACCESS_KEY_ID: replacementId } };
    });
    const originalVerify = provider.verify.bind(provider);
    const verify = vi.spyOn(provider, 'verify').mockImplementation(async (value, ctx) => {
      expect(ctx.siblingVars).toMatchObject({ BACKUP_SECRET_ACCESS_KEY: value, BACKUP_ACCESS_KEY_ID: replacementId });
      expect(ctx.siblingVars).not.toHaveProperty('AWS_ACCESS_KEY_ID');
      expect(ctx.siblingVars).not.toHaveProperty('AWS_SECRET_ACCESS_KEY');
      return originalVerify(value, ctx);
    });
    const originalRevoke = provider.revoke.bind(provider);
    const revoke = vi.spyOn(provider, 'revoke').mockImplementation(async (ref, ctx) => {
      expect(ref).toBe(backup.ref);
      expect(ctx.siblingVars).toMatchObject({ BACKUP_SECRET_ACCESS_KEY: host.peek('api', 'BACKUP_SECRET_ACCESS_KEY'), BACKUP_ACCESS_KEY_ID: replacementId });
      expect(ctx.siblingVars).not.toHaveProperty('AWS_ACCESS_KEY_ID');
      expect(ctx.siblingVars).not.toHaveProperty('AWS_SECRET_ACCESS_KEY');
      return originalRevoke(ref, ctx);
    });

    const report = await executePlan(plan, h.inv, h.deps, liveOptions);

    expect(rotate).toHaveBeenCalledTimes(1);
    expect(verify).toHaveBeenCalledTimes(1);
    expect(revoke).toHaveBeenCalledTimes(1);
    expect(stepFor(report, backup.value).status).toBe('revoked');
    expect(host.writes).toEqual([{ serviceId: 'api', vars: { BACKUP_SECRET_ACCESS_KEY: host.peek('api', 'BACKUP_SECRET_ACCESS_KEY'), BACKUP_ACCESS_KEY_ID: replacementId }, skipDeploy: true }]);
    expect(host.peek('api', 'AWS_ACCESS_KEY_ID')).toBe(unrelatedId);
    expect(host.peek('api', 'AWS_SECRET_ACCESS_KEY')).toBe(unrelated.value);
    expect(host.peek('api', 'AWS_REGION')).toBe('eu-west-1');
    expect(provider.keys.get(unrelated.ref)?.active).toBe(true);
    expect(provider.revoked).toEqual([backup.ref]);
    expect(h.deps.providerCtx.siblingVars).toBeUndefined();
  });

  it('keeps service keys and report metadata exact when ordinary configuration values occur within them', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    const service = host.addService('api', { OPENAI_API_KEY: old.value, NODE_ENV: 'production', PORT: '1' });
    const h = await setup([host], [provider]);

    const report = await executePlan(h.plan, h.inv, h.deps, liveOptions);

    expect(report.planId).toBe(h.plan.id);
    expect(report.startedAt).toBe(instant.toISOString());
    expect(report.finishedAt).toBe(instant.toISOString());
    expect(report.deployments).toEqual([expect.objectContaining({ serviceKey: serviceKey(service), state: 'success' })]);
    expect(report.diff.join('\n')).toContain(`${serviceKey(service)}: OPENAI_API_KEY`);
    expect(h.journal.entries.filter(entry => entry.serviceKey !== undefined).every(entry => entry.serviceKey === serviceKey(service))).toBe(true);
    expect(h.journal.entries.every(entry => entry.planId === h.plan.id && entry.at === instant.toISOString())).toBe(true);
    expect(host.peek('api', 'NODE_ENV')).toBe('production');
    expect(host.peek('api', 'PORT')).toBe('1');
    expect(stepFor(report, old.value).status).toBe('revoked');
  });
});
