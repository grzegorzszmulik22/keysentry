import { describe, expect, it } from 'vitest';
import { buildInventory, buildPlan, createLogger, createRedactor, serviceKey } from '../../src/core/index.js';
import { executePlan, finishRotation, resumeRotation, undoRotation } from '../../src/rotate/index.js';
import type { EngineDeps, RotateOptions } from '../../src/rotate/index.js';
import type { HostId, JournalEntry } from '../../src/types.js';
import { FakeHttp, json } from '../helpers/fake-http.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

async function fixture(hostId: HostId = 'railway', sameKey = false) {
  const clock = { ms: Date.parse('2026-10-27T12:00:00.000Z') };
  const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
  provider.now = () => new Date(clock.ms - 86_400_000);
  const old = [provider.issue(), provider.issue(), provider.issue()];
  provider.now = () => new Date(clock.ms);
  const host = new FakeHost(hostId);
  host.pendingPolls = 0;
  const services = old.map((key, index) => host.addService(`service-${index}`, {
    OPENAI_API_KEY: sameKey ? old[0]!.value : key.value,
  }));
  const fingerprintKey = Buffer.alloc(32, 0x71);
  const inventory = buildInventory([{ host: hostId, services: await Promise.all(services.map(async service => ({
    service, vars: await host.readVariables(service),
  }))) }], fingerprintKey, new Date(clock.ms));
  const plan = buildPlan(inventory);
  const entries: JournalEntry[] = [];
  const redactor = createRedactor();
  const log = createLogger({ redactor, sink: () => {} });
  const inflight = createFakeInFlight();
  const deps: EngineDeps = {
    hosts: { [hostId]: host }, providers: () => provider,
    providerCtx: { http: new FakeHttp(), credentials: {}, log },
    journal: { async append(entry) { entries.push(structuredClone(entry)); }, async read() { return structuredClone(entries); } },
    prompt: async () => null, fingerprintKey, redactor, log, inflight,
    now: () => new Date(clock.ms), sleep: async ms => { clock.ms += ms; },
  };
  const opts: RotateOptions = {
    dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 1,
    revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 0,
  };
  return { clock, provider, old, host, services, inventory, plan, entries, deps, opts, inflight,
    input: () => ({ plan, inventory, entries: structuredClone(entries) }) };
}

describe('rotation wave safety rails', () => {
  it('a remote stop before creation leaves every provider key and consumer unchanged', async () => {
    const h = await fixture();
    h.deps.shouldStop = async () => true;
    const report = await executePlan(h.plan, h.inventory, h.deps, h.opts);
    expect(h.provider.keys.size).toBe(h.old.length);
    expect(h.host.writes).toEqual([]);
    expect(h.host.redeploys).toEqual([]);
    expect(h.provider.revoked).toEqual([]);
    expect(report.status).toBe('failed');
  });

  it('a remote stop between creations preserves the prepared replacement without delivering it', async () => {
    const h = await fixture();
    let stop = false;
    const rotate = h.provider.rotate.bind(h.provider);
    h.provider.rotate = async (value, ctx) => { const result = await rotate(value, ctx); stop = true; return result; };
    h.deps.shouldStop = async () => stop;
    const report = await executePlan(h.plan, h.inventory, h.deps, h.opts);
    expect(h.provider.keys.size).toBe(h.old.length + 1);
    expect(h.host.writes).toEqual([]);
    expect(h.host.redeploys).toEqual([]);
    expect(h.provider.revoked).toEqual([]);
    expect(report.status).toBe('partial');
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
    expect(await h.inflight.get(h.plan.id, `new:${h.plan.steps[0]!.clusterId}`)).not.toBeNull();
  });

  it('a remote stop after writes blocks deployment and every old-key revocation', async () => {
    const h = await fixture();
    h.deps.shouldStop = async () => h.host.writes.length === h.services.length;
    const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, deployConcurrency: 1 });
    expect(h.host.writes).toHaveLength(h.services.length);
    expect(h.host.redeploys).toEqual([]);
    expect(h.provider.revoked).toEqual([]);
    expect(report.status).toBe('partial');
  });

  it('a remote stop after deployments blocks the first old-key revocation', async () => {
    const h = await fixture();
    h.deps.shouldStop = async () => h.host.redeploys.length === h.services.length;
    const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, deployConcurrency: 1 });
    expect(h.host.redeploys).toHaveLength(h.services.length);
    expect(h.provider.revoked).toEqual([]);
    expect(report.status).toBe('partial');
    for (const old of h.old) expect(h.provider.keys.get(old.ref)?.active).toBe(true);
  });

  it('a remote stop during deferred settlement retains every old key', async () => {
    const h = await fixture();
    h.deps.grace = async () => 'defer';
    await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, graceMs: 1_000 });
    h.clock.ms += 1_000;
    let polls = 0;
    // A later empty relay response must not undo a stop already received.
    h.deps.shouldStop = async () => ++polls === 1;
    const report = await finishRotation(h.input(), h.deps, h.opts);
    expect(h.provider.revoked).toEqual([]);
    expect(report.pendingRevocations).toHaveLength(h.plan.steps.length);
    expect(report.status).toBe('partial');
    expect(polls).toBe(1);
  });

  it('resume polls for a remote stop before delivering saved replacements', async () => {
    const h = await fixture();
    const interrupted = new Error('simulated interruption');
    h.deps.crashHook = point => { if (point === 'after-store') throw interrupted; };
    await expect(executePlan(h.plan, h.inventory, h.deps, h.opts)).rejects.toBe(interrupted);
    delete h.deps.crashHook;
    h.deps.shouldStop = async () => true;
    const count = h.provider.keys.size;
    const report = await resumeRotation(h.input(), h.deps, h.opts);
    expect(h.provider.keys.size).toBe(count);
    expect(h.host.writes).toEqual([]);
    expect(h.host.redeploys).toEqual([]);
    expect(h.provider.revoked).toEqual([]);
    expect(report.status).toBe('partial');
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
  });

  it('undo polls for a remote stop before restoring any consumer', async () => {
    const h = await fixture();
    h.deps.grace = async () => 'defer';
    await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, graceMs: 1_000 });
    h.host.writes.length = 0;
    h.host.redeploys.length = 0;
    h.deps.shouldStop = async () => true;
    const report = await undoRotation(h.input(), h.deps, h.opts);
    expect(h.host.writes).toEqual([]);
    expect(h.host.redeploys).toEqual([]);
    expect(h.provider.revoked).toEqual([]);
    expect(report.restored).toEqual([]);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
  });

  it('a successful remote stop poll allows the normal rotation rails to complete', async () => {
    const h = await fixture();
    h.deps.shouldStop = async () => false;
    const report = await executePlan(h.plan, h.inventory, h.deps, h.opts);
    expect(report.status).toBe('complete');
    expect(h.provider.revoked).toEqual(h.old.map(key => key.ref));
  });

  it('a concurrent empty poll cannot clear a remote stop already received', async () => {
    const h = await fixture();
    let deployPolls = 0;
    h.deps.shouldStop = async () => {
      if (h.host.writes.length < h.services.length) return false;
      if (++deployPolls > 1) return true;
      // The first poll returns after another deployment worker received disarm.
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
      return false;
    };
    const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, deployConcurrency: 3 });
    expect(h.host.redeploys).toEqual([]);
    expect(h.provider.revoked).toEqual([]);
    expect(report.status).toBe('partial');
  });

  it('a remote stop blocking unused-key cleanup keeps its live replacement recoverable', async () => {
    const h = await fixture();
    h.provider.failVerifyOfNew = true;
    h.deps.shouldStop = async () => h.provider.keys.size > h.old.length;
    const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, stopOnFirstFailure: true });
    expect(h.provider.revoked).toEqual([]);
    expect(h.host.writes).toEqual([]);
    expect(report.status).toBe('partial');
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
    expect(await h.inflight.get(h.plan.id, `new:${h.plan.steps[0]!.clusterId}`)).not.toBeNull();
  });

  it('a remote stop during a provider metadata lookup blocks its later mutation HTTP', async () => {
    const h = await fixture();
    let stop = false;
    const http = new FakeHttp().on('GET', /metadata/, () => { stop = true; return json(200, {}); })
      .on('POST', /create/, () => json(200, {}));
    h.deps.providerCtx.http = http;
    const rotate = h.provider.rotate.bind(h.provider);
    h.provider.rotate = async (value, ctx) => {
      await ctx.http.request({ method: 'GET', url: 'https://provider.invalid/metadata' });
      await ctx.http.request({ method: 'POST', url: 'https://provider.invalid/create' });
      return rotate(value, ctx);
    };
    h.deps.shouldStop = async () => stop;
    await executePlan(h.plan, h.inventory, h.deps, h.opts);
    expect(http.calls.map(call => call.method)).toEqual(['GET']);
    expect(h.provider.keys.size).toBe(h.old.length);
    expect(h.host.writes).toEqual([]);
    expect(h.provider.revoked).toEqual([]);
  });

  it('a failed remote stop poll stops effects without reflecting the callback error', async () => {
    const h = await fixture();
    h.deps.shouldStop = async () => { throw new Error('private relay response'); };
    const report = await executePlan(h.plan, h.inventory, h.deps, h.opts);
    expect(h.provider.keys.size).toBe(h.old.length);
    expect(h.host.writes).toEqual([]);
    expect(JSON.stringify(report)).not.toContain('private relay response');
    expect(report.status).toBe('failed');
  });

  it.each([1, 0, -2])('deployConcurrency %s redeploys services one at a time', async concurrency => {
    const h = await fixture();
    let active = 0;
    let maximum = 0;
    const deploy = h.host.redeploy.bind(h.host);
    h.host.redeploy = async service => {
      maximum = Math.max(maximum, ++active);
      await Promise.resolve();
      return deploy(service);
    };
    const status = h.host.deploymentStatus.bind(h.host);
    h.host.deploymentStatus = async (service, id) => { const result = await status(service, id); active--; return result; };
    const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, deployConcurrency: concurrency });
    expect(report.status).toBe('complete');
    expect(maximum).toBe(1);
  });

  it('first failed health check stops the wave and revokes nothing', async () => {
    const h = await fixture();
    const checked: string[] = [];
    h.deps.healthCheck = async key => { checked.push(key); return { ok: false, detail: 'Health check failed (HTTP 500).' }; };
    const report = await executePlan(h.plan, h.inventory, h.deps, {
      ...h.opts, deployConcurrency: 1, stopOnFirstFailure: true, holdRevocationOnAnyFailure: true,
    });
    expect(checked).toEqual([serviceKey(h.services[0]!)]);
    expect(h.host.redeploys).toEqual([h.services[0]!.serviceId]);
    expect(report.deployments.filter(item => item.state === 'failed')).toHaveLength(1);
    expect(report.steps.flatMap(item => item.warnings)).toContain('Health check failed (HTTP 500).');
    expect(h.provider.revoked).toEqual([]);
    expect(report.status).toBe('partial');
    for (const old of h.old) expect(h.provider.keys.get(old.ref)?.active).toBe(true);
    for (const service of h.services) expect(h.host.peek(service.serviceId, 'OPENAI_API_KEY')).not.toBe(h.old[h.services.indexOf(service)]!.value);
  });

  it('holdRevocationOnAnyFailure keeps every old key when one cluster fails', async () => {
    const h = await fixture();
    h.host.failDeploysFor.add(h.services[1]!.serviceId);
    const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, holdRevocationOnAnyFailure: true });
    expect(report.status).toBe('partial');
    expect(report.pendingRevocations).toHaveLength(2);
    expect(h.provider.revoked).toEqual([]);
    const failed = report.steps.find(item => item.status === 'failed')!;
    expect(report.pendingRevocations!.map(item => item.clusterId)).not.toContain(failed.clusterId);
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
  });

  it('an unaccepted unconfirmed consumer holds every old key', async () => {
    const h = await fixture();
    const deploy = h.host.redeploy.bind(h.host);
    h.host.redeploy = async service => service.serviceId === h.services[1]!.serviceId ? null : deploy(service);
    const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, holdRevocationOnAnyFailure: true });
    expect(report.status).toBe('partial');
    expect(report.pendingRevocations).toHaveLength(2);
    expect(h.provider.revoked).toEqual([]);
  });

  it.each(['create', 'verify'])('a %s preparation failure cleans prepared unused keys and makes no host writes', async phase => {
    const h = await fixture();
    const rotate = h.provider.rotate.bind(h.provider);
    let prepared = 0;
    h.provider.rotate = async (value, ctx) => {
      if (++prepared === 2 && phase === 'create') throw new Error('upstream body must not escape');
      const result = await rotate(value, ctx);
      if (prepared === 2 && phase === 'verify') h.provider.keys.get(result.newKeyRef!)!.active = false;
      return result;
    };
    const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, stopOnFirstFailure: true });
    expect(prepared).toBe(2);
    expect(h.host.writes).toEqual([]);
    expect(h.host.redeploys).toEqual([]);
    expect(report.steps.filter(item => item.status === 'failed')).toHaveLength(1);
    expect(report.steps.filter(item => item.status === 'skipped')).toHaveLength(2);
    for (const item of report.steps.filter(item => item.status === 'skipped')) {
      expect(item.warnings).toContain('Stopped after an earlier failure in this wave.');
    }
    for (const old of h.old) expect(h.provider.keys.get(old.ref)?.active).toBe(true);
    for (const key of h.provider.keys.values()) if (key.name.startsWith('rotated')) expect(key.active).toBe(false);
    expect(report.status).toBe('failed');
    expect(h.inflight.shredded.has(h.plan.id)).toBe(true);
  });

  it('a preparation conflict stops the entire wave and cleans every unused replacement', async () => {
    const h = await fixture();
    const rotate = h.provider.rotate.bind(h.provider);
    let count = 0;
    h.provider.rotate = async (value, ctx) => ({ ...await rotate(value, ctx), companions: { SAME_COMPANION: String(++count) } });
    // All clusters share a service, so conflicting companions are detected before writes.
    const shared = h.services[0]!;
    for (let i = 1; i < h.plan.steps.length; i++) {
      const step = h.plan.steps[i]!;
      const oldValue = h.old.find(key => key.ref === h.provider.refOf(h.host.peek(step.consumers[0]!.service.serviceId, 'OPENAI_API_KEY')!))!.value;
      const name = `OPENAI_KEY_${i}`;
      await h.host.writeVariables(shared, { [name]: oldValue }, { skipDeploy: true });
      step.consumers.push({ ...step.consumers[0]!, service: shared, varName: name });
      h.inventory.clusters.find(cluster => cluster.id === step.clusterId)!.consumers.push({ ...step.consumers.at(-1)! });
    }
    h.host.writes.length = 0;
    const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, stopOnFirstFailure: true });
    expect(h.host.writes).toEqual([]);
    expect(report.steps.filter(item => item.status === 'failed')).toHaveLength(1);
    expect(report.steps.filter(item => item.status === 'skipped')).toHaveLength(2);
    for (const old of h.old) expect(h.provider.keys.get(old.ref)?.active).toBe(true);
    for (const key of h.provider.keys.values()) if (key.name.startsWith('rotated')) expect(key.active).toBe(false);
  });

  it('a failed write prevents any deployment and preserves all prepared key values', async () => {
    const h = await fixture();
    h.host.failWritesFor.add(h.services[1]!.serviceId);
    const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, stopOnFirstFailure: true, holdRevocationOnAnyFailure: true });
    expect(h.host.redeploys).toEqual([]);
    expect(h.provider.revoked).toEqual([]);
    expect(report.status).toBe('partial');
    expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
  });

  it('an unsafe preflight stops the wave before another cluster creates a replacement', async () => {
    const h = await fixture();
    await h.host.writeVariables(h.services[0]!, { OPENAI_API_KEY: 'sk-proj-changed-since-the-inventory-was-scanned' }, { skipDeploy: true });
    h.host.writes.length = 0;
    const count = h.provider.keys.size;
    const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, stopOnFirstFailure: true });
    expect(h.provider.keys.size).toBe(count);
    expect(h.host.writes).toEqual([]);
    expect(report.status).toBe('failed');
  });

  it('a guided fallback stops an unattended wave before any host write', async () => {
    const h = await fixture();
    const rotate = h.provider.rotate.bind(h.provider);
    let calls = 0;
    h.provider.rotate = async (value, ctx) => {
      if (++calls === 2) throw Object.assign(new Error('permission details'), { code: 'GUIDED_ROTATION_REQUIRED' });
      return rotate(value, ctx);
    };
    const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, stopOnFirstFailure: true });
    expect(calls).toBe(2);
    expect(h.host.writes).toEqual([]);
    expect(report.status).toBe('failed');
    for (const old of h.old) expect(h.provider.keys.get(old.ref)?.active).toBe(true);
    for (const key of h.provider.keys.values()) if (key.name.startsWith('rotated')) expect(key.active).toBe(false);
  });

  it('a hold overrides immediate revocation until every deployment result is known', async () => {
    const h = await fixture();
    h.host.failDeploysFor.add(h.services[1]!.serviceId);
    const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, revoke: 'immediately', holdRevocationOnAnyFailure: true });
    expect(report.status).toBe('partial');
    expect(report.pendingRevocations).toHaveLength(2);
    expect(h.provider.revoked).toEqual([]);
  });

  it('health-check exceptions use fixed text without reflecting callback errors', async () => {
    const h = await fixture();
    h.deps.healthCheck = async () => { throw new Error('http://credentials@private.test/secret-body'); };
    const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, deployConcurrency: 1, stopOnFirstFailure: true });
    expect(report.steps.flatMap(step => step.warnings)).toContain('Health check could not be completed.');
    expect(JSON.stringify(report)).not.toContain('credentials@private');
    expect(h.host.redeploys).toHaveLength(1);
    expect(h.provider.revoked).toEqual([]);
  });

  it.each([true, false])('next-deploy acceptance waits for maxHours and revokes only when allowed (%s)', async revokeAfterMax => {
    const h = await fixture('vercel', true);
    h.host.redeploy = async () => null;
    const options = { ...h.opts, nextDeployAcceptance: [{ host: 'vercel' as const, maxHours: 2, revokeAfterMax }] };
    h.deps.grace = async () => 'defer';
    const started = h.clock.ms;
    const report = await executePlan(h.plan, h.inventory, h.deps, options);
    const deadline = new Date(started + 2 * 3_600_000).toISOString();
    expect(report.status).toBe('grace-pending');
    expect(report.pendingRevocations).toEqual([{ clusterId: h.plan.steps[0]!.clusterId, deadline, undoAvailable: true }]);
    expect(h.entries.find(entry => entry.event === 'grace-start')?.data?.reason).toBe('next-deploy');
    expect(h.provider.revoked).toEqual([]);
    // Even early human finish may not bypass the signed next-deploy maximum.
    await finishRotation(h.input(), h.deps, { ...options, early: true });
    expect(h.provider.revoked).toEqual([]);
    h.clock.ms += 2 * 3_600_000;
    const finished = await finishRotation(h.input(), h.deps, options);
    if (revokeAfterMax) {
      expect(finished.status).toBe('complete');
      expect(h.provider.revoked).toEqual([h.old[0]!.ref]);
    } else {
      expect(finished.status).toBe('partial');
      expect(finished.steps[0]!.warnings.join(' ')).toMatch(/next deploy.*not.*confirmed|did not authorize/i);
      expect(h.provider.revoked).toEqual([]);
    }
  });

  it('finish rechecks application health before any grace revocation', async () => {
    const h = await fixture();
    h.deps.grace = async () => 'defer';
    h.deps.healthCheck = async () => ({ ok: true, detail: 'Health check passed.' });
    const options = { ...h.opts, graceMs: 1_000, holdRevocationOnAnyFailure: true };
    await executePlan(h.plan, h.inventory, h.deps, options);
    h.clock.ms += 1_001;
    let checks = 0;
    h.deps.healthCheck = async () => ({ ok: ++checks !== 2, detail: 'Health check failed (HTTP 500).' });
    const finished = await finishRotation(h.input(), h.deps, options);
    expect(finished.status).toBe('partial');
    expect(h.provider.revoked).toEqual([]);
    expect(finished.steps.flatMap(item => item.warnings)).toContain('Health check failed (HTTP 500).');
  });

  it('an explicit grace callback defers even when graceMs is zero', async () => {
    const h = await fixture();
    let called = 0;
    h.deps.grace = async () => { called++; return 'defer'; };
    const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, graceMs: 0 });
    expect(called).toBe(1);
    expect(report.status).toBe('grace-pending');
    expect(h.provider.revoked).toEqual([]);
  });

  it('finish verifies every replacement before revoking any old key when wave holds are enabled', async () => {
    const h = await fixture();
    h.deps.grace = async () => 'defer';
    const options = { ...h.opts, graceMs: 1_000, holdRevocationOnAnyFailure: true };
    const started = await executePlan(h.plan, h.inventory, h.deps, options);
    h.clock.ms += 1_001;
    const second = h.provider.keys.get(started.steps[1]!.newKeyRef!)!;
    second.active = false;
    const finished = await finishRotation(h.input(), h.deps, options);
    expect(finished.status).toBe('partial');
    expect(h.provider.revoked).toEqual([]);
    expect(finished.pendingRevocations).toHaveLength(3);
  });

  it('a failed finish revocation stops every later revocation when wave holds are enabled', async () => {
    const h = await fixture();
    h.deps.grace = async () => 'defer';
    const options = { ...h.opts, graceMs: 1_000, holdRevocationOnAnyFailure: true };
    await executePlan(h.plan, h.inventory, h.deps, options);
    h.clock.ms += 1_001;
    let attempts = 0;
    const revoke = h.provider.revoke.bind(h.provider);
    h.provider.revoke = async (ref, ctx) => {
      if (++attempts === 1) throw new Error('upstream secret response');
      await revoke(ref, ctx);
    };
    const report = await finishRotation(h.input(), h.deps, options);
    expect(attempts).toBe(1);
    expect(h.provider.revoked).toEqual([]);
    expect(report.status).toBe('partial');
    expect(report.pendingRevocations).toHaveLength(3);
    expect(report.steps.filter(step => step.status === 'failed')).toHaveLength(1);
    expect(h.entries.some(entry => entry.event === 'failed' && entry.data?.phase === 'finish-revocation')).toBe(true);
    expect(JSON.stringify(report)).not.toContain('upstream secret response');
  });

  it('next-deploy consent cannot be widened by passing different options to finish', async () => {
    const h = await fixture('vercel', true);
    h.host.redeploy = async () => null;
    const options = { ...h.opts, nextDeployAcceptance: [{ host: 'vercel' as const, maxHours: 1, revokeAfterMax: false }] };
    await executePlan(h.plan, h.inventory, h.deps, options);
    h.clock.ms += 3_600_000;
    await finishRotation(h.input(), h.deps, { ...options, nextDeployAcceptance: [{ host: 'vercel', maxHours: 1, revokeAfterMax: true }] });
    expect(h.provider.revoked).toEqual([]);
  });

  it('a late failure during grace keeps successful clusters pending for a human finish', async () => {
    const h = await fixture();
    const sleep = h.deps.sleep!;
    h.deps.sleep = async ms => {
      await sleep(ms);
      const value = h.host.peek(h.services[1]!.serviceId, 'OPENAI_API_KEY')!;
      h.provider.keys.get(h.provider.refOf(value)!)!.active = false;
    };
    const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, graceMs: 1_000, holdRevocationOnAnyFailure: true });
    expect(report.status).toBe('partial');
    expect(report.pendingRevocations).toHaveLength(2);
    expect(h.provider.revoked).toEqual([]);
  });

  it('application health is checked again after waiting through grace', async () => {
    const h = await fixture();
    let waitingFinished = false;
    const sleep = h.deps.sleep!;
    h.deps.sleep = async ms => { await sleep(ms); waitingFinished = true; };
    h.deps.healthCheck = async () => ({ ok: !waitingFinished, detail: 'Health check failed (HTTP 500).' });
    const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, graceMs: 1_000, holdRevocationOnAnyFailure: true });
    expect(report.status).toBe('partial');
    expect(h.provider.revoked).toEqual([]);
  });

  it('resume reruns the health check before revocation after a deployment result crash', async () => {
    const h = await fixture();
    const error = new Error('simulated process exit');
    h.deps.crashHook = point => { if (point === 'after-deploy-result') throw error; };
    await expect(executePlan(h.plan, h.inventory, h.deps, h.opts)).rejects.toBe(error);
    delete h.deps.crashHook;
    h.deps.healthCheck = async () => ({ ok: false, detail: 'Health check failed (HTTP 503).' });
    const report = await resumeRotation(h.input(), h.deps, { ...h.opts, deployConcurrency: 1, stopOnFirstFailure: true, holdRevocationOnAnyFailure: true });
    expect(report.status).toBe('partial');
    expect(h.provider.revoked).toEqual([]);
  });

  it('resume preserves a stopped wave when the last durable entry is a failed deployment result', async () => {
    const h = await fixture();
    h.host.failDeploysFor.add(h.services[0]!.serviceId);
    const options = { ...h.opts, deployConcurrency: 1, stopOnFirstFailure: true, holdRevocationOnAnyFailure: true };
    const append = h.deps.journal.append.bind(h.deps.journal);
    h.deps.journal.append = async entry => {
      await append(entry);
      if (entry.event === 'deploy-result' && entry.data?.state === 'failed') throw new Error('journal interrupted after durable append');
    };
    await expect(executePlan(h.plan, h.inventory, h.deps, options)).rejects.toThrow();
    expect(h.entries.at(-1)?.event).toBe('deploy-result');
    expect(h.entries.at(-1)?.data?.state).toBe('failed');
    h.deps.journal.append = append;
    h.host.failDeploysFor.clear();
    const deploymentsBeforeResume = h.host.redeploys.length;
    await resumeRotation(h.input(), h.deps, options);
    expect(h.host.redeploys).toHaveLength(deploymentsBeforeResume);
    expect(h.provider.revoked).toEqual([]);
  });

  it('a normal-run revocation failure holds every subsequent old-key revocation', async () => {
    const h = await fixture();
    let attempts = 0;
    const revoke = h.provider.revoke.bind(h.provider);
    h.provider.revoke = async (ref, ctx) => {
      if (++attempts === 1) throw new Error('provider rejected revoke');
      await revoke(ref, ctx);
    };
    const report = await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, holdRevocationOnAnyFailure: true });
    expect(attempts).toBe(1);
    expect(h.provider.revoked).toEqual([]);
    expect(report.status).toBe('partial');
    expect(report.pendingRevocations).toHaveLength(2);
  });

  it('a known deployment failure stops other workers before its result finishes persisting', async () => {
    const h = await fixture();
    h.host.failDeploysFor.add(h.services[0]!.serviceId);
    let failureStarted!: () => void;
    const failurePersisting = new Promise<void>(resolve => { failureStarted = resolve; });
    let releaseFailure!: () => void;
    const persistenceReleased = new Promise<void>(resolve => { releaseFailure = resolve; });
    const append = h.deps.journal.append.bind(h.deps.journal);
    h.deps.journal.append = async entry => {
      if (entry.event === 'deploy-result' && entry.data?.state === 'failed') {
        failureStarted();
        await persistenceReleased;
      }
      await append(entry);
    };
    const status = h.host.deploymentStatus.bind(h.host);
    h.host.deploymentStatus = async (service, id) => {
      if (service.serviceId === h.services[1]!.serviceId) await failurePersisting;
      return status(service, id);
    };
    const execution = executePlan(h.plan, h.inventory, h.deps, {
      ...h.opts, deployConcurrency: 2, stopOnFirstFailure: true, holdRevocationOnAnyFailure: true,
    });
    await failurePersisting;
    await new Promise<void>(resolve => setImmediate(resolve));
    releaseFailure();
    await execution;
    expect(h.host.redeploys).toEqual([h.services[0]!.serviceId, h.services[1]!.serviceId]);
    expect(h.provider.revoked).toEqual([]);
  });

  it.each([false, true])('finish checks current consumers before revocation (hold=%s)', async hold => {
    const h = await fixture();
    h.deps.grace = async () => 'defer';
    const options = { ...h.opts, graceMs: 1_000, holdRevocationOnAnyFailure: hold };
    await executePlan(h.plan, h.inventory, h.deps, options);
    await h.host.writeVariables(h.services[1]!, { OPENAI_API_KEY: h.old[1]!.value }, { skipDeploy: true });
    h.clock.ms += 1_001;
    // Deliberately retain the original inventory: current host state is authoritative.
    const report = await finishRotation(h.input(), h.deps, options);
    expect(h.provider.keys.get(h.old[1]!.ref)?.active).toBe(true);
    expect(report.status).toBe('partial');
    expect(report.steps.some(step => step.status === 'failed' && step.warnings.some(warning => /consumer.*changed/i.test(warning)))).toBe(true);
    if (hold) expect(h.provider.revoked).toEqual([]);
  });

  it('undo refuses to overwrite a newer manual value at any consumer', async () => {
    const h = await fixture('railway', true);
    h.deps.grace = async () => 'defer';
    await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, graceMs: 1_000 });
    const newer = h.provider.issue('manual newer key');
    await h.host.writeVariables(h.services[1]!, { OPENAI_API_KEY: newer.value }, { skipDeploy: true });
    h.host.writes.length = 0;
    const report = await undoRotation(h.input(), h.deps, h.opts);
    expect(h.host.peek(h.services[1]!.serviceId, 'OPENAI_API_KEY')).toBe(newer.value);
    expect(h.host.writes).toEqual([]);
    expect(report.restored).toEqual([]);
    // M4 identifies the service whose newer value keysentry must preserve.
    expect(report.unavailable[0]!.reason).toMatch(/newer value.*keysentry won't overwrite/i);
    expect(h.provider.revoked).toEqual([]);
  });

  it('undo accepts an already restored old value when recovering an interrupted restore', async () => {
    const h = await fixture('railway', true);
    h.deps.grace = async () => 'defer';
    await executePlan(h.plan, h.inventory, h.deps, { ...h.opts, graceMs: 1_000 });
    // Previously any old value authorized another write; an interrupted undo has durable direction intent.
    h.entries.push({ at: h.deps.now!().toISOString(), planId: h.plan.id, event: 'resume',
      clusterId: h.plan.steps[0]!.clusterId, data: { undo: true, phase: 'start' } });
    await h.host.writeVariables(h.services[1]!, { OPENAI_API_KEY: h.old[0]!.value }, { skipDeploy: true });
    h.host.writes.length = 0;
    const report = await undoRotation(h.input(), h.deps, h.opts);
    expect(report.unavailable).toEqual([]);
    expect(report.restored).toHaveLength(1);
    expect(h.host.peek(h.services[1]!.serviceId, 'OPENAI_API_KEY')).toBe(h.old[0]!.value);
    expect(h.host.writes.some(write => write.serviceId === h.services[1]!.serviceId)).toBe(false);
  });

  it.each([false, true])('a storage failure cleans or records the created replacement (cleanup fails=%s)', async cleanupFails => {
    const h = await fixture('railway', true);
    h.inflight.put = async () => { throw new Error('temporary storage unavailable'); };
    if (cleanupFails) h.provider.revoke = async () => { throw new Error('cleanup upstream response'); };
    const report = await executePlan(h.plan, h.inventory, h.deps, h.opts);
    const created = [...h.provider.keys.values()].find(key => key.name.startsWith('rotated'))!;
    expect(report.steps[0]!.newKeyRef).toBe(created.ref);
    expect(h.entries.some(entry => entry.clusterId === h.plan.steps[0]!.clusterId && entry.data?.newKeyRef === created.ref)).toBe(true);
    expect(created.active).toBe(cleanupFails);
    expect(h.host.writes).toEqual([]);
    expect(h.provider.keys.get(h.old[0]!.ref)?.active).toBe(true);
    const output = JSON.stringify({ report, entries: h.entries });
    expect(output).not.toContain(created.value);
    expect(output).not.toContain('cleanup upstream response');
  });
});
