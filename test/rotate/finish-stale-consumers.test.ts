import { expect, test } from 'vitest';
import { buildInventory, buildPlan, createLogger, createRedactor, fingerprint, serviceKey } from '../../src/core/index.js';
import type { EngineDeps, RotateOptions } from '../../src/rotate/engine.js';
import { finishRotation } from '../../src/rotate/grace.js';
import type { JournalEntry } from '../../src/types.js';
import { FakeHttp } from '../helpers/fake-http.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

// The review probe's deferred-rotation scenario, with a reference consumer variant.
async function deferredRotation(reference = false) {
  let millis = Date.parse('2026-10-27T12:00:00.000Z');
  const now = () => new Date(millis);
  const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
  provider.now = now;
  const old = provider.issue();
  const host = new FakeHost('railway');
  host.pendingPolls = 0;
  const services = [host.addService('api', { OPENAI_API_KEY: old.value }),
    host.addService('worker', { OPENAI_API_KEY: reference ? '${{api.OPENAI_API_KEY}}' : old.value })];
  const fingerprintKey = Buffer.alloc(32, 0x46);
  const scan = async () => buildInventory([{ host: host.id, services: await Promise.all((await host.listServices()).map(async service => ({
    service, vars: await host.readVariables(service),
  }))) }], fingerprintKey, now());
  const inventory = await scan();
  const plan = buildPlan(inventory);
  const clusterId = plan.steps[0]!.clusterId;
  const entries: JournalEntry[] = [];
  const inflight = createFakeInFlight();
  const redactor = createRedactor();
  const log = createLogger({ redactor, sink: () => {} });
  const deps: EngineDeps = {
    hosts: { railway: host }, providers: () => provider, providerCtx: { http: new FakeHttp(), credentials: {}, log },
    journal: { async append(e) { entries.push(structuredClone(e)); }, async read() { return [...entries]; } },
    prompt: async () => null, fingerprintKey, redactor, log, inflight, now, sleep: async ms => { millis += ms; },
  };
  const opts: RotateOptions = { dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 10,
    revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 0, graceMs: 1_000 };
  const event = (event: JournalEntry['event'], extra: Partial<JournalEntry> = {}) =>
    entries.push({ at: now().toISOString(), planId: plan.id, event, ...extra });
  event('plan-start');
  const replacement = await provider.rotate(old.value, deps.providerCtx);
  await inflight.put(plan.id, `old:${clusterId}`, old.value);
  await inflight.put(plan.id, `new:${clusterId}`, replacement.newValue);
  const data = { newKeyRef: replacement.newKeyRef, oldKeyRef: replacement.oldKeyRef, oldRevoked: false,
    newFingerprint: fingerprint(replacement.newValue, fingerprintKey) };
  event('value-stored', { clusterId, data }); event('created', { clusterId, data }); event('verified', { clusterId, data });
  for (const service of services) {
    if (!reference || service.serviceId === 'api') {
      await host.writeVariables(service, { OPENAI_API_KEY: replacement.newValue }, { skipDeploy: true });
      event('written', { clusterId, serviceKey: serviceKey(service) });
    }
    const deploymentId = await host.redeploy(service);
    event('redeploy', { serviceKey: serviceKey(service), data: { deploymentId } });
    event('deploy-result', { serviceKey: serviceKey(service), data: { deploymentId, state: 'success' } });
  }
  event('grace-start', { clusterId, data: { deadline: new Date(millis + 1_000).toISOString() } });
  event('plan-end', { data: { status: 'grace-pending', pending: true } });
  return { provider, old, replacement, host, services, plan, entries, deps, opts, scan, inflight,
    input: async () => ({ plan, inventory: await scan(), entries: [...entries] }),
    advance: (ms: number) => { millis += ms; } };
}

test('finish keeps the old key while a known consumer still uses it', async () => {
  const h = await deferredRotation();
  await h.host.writeVariables(h.services[1]!, { OPENAI_API_KEY: h.old.value }, { skipDeploy: true });
  const input = await h.input();
  expect(input.inventory.clusters.some(cluster => cluster.consumers.some(consumer => consumer.service.serviceId === 'worker'))).toBe(true);
  h.advance(5_000);

  const report = await finishRotation(input, h.deps, h.opts);

  expect(h.provider.revoked).not.toContain(h.old.ref);
  expect(report.status).toBe('partial');
  expect(report.steps[0]!.warnings.join(' ')).toContain(serviceKey(h.services[1]!));
  expect(report.steps[0]!.warnings.join(' ')).toMatch(/worker.*still uses the old key/);
  expect(h.entries).toContainEqual(expect.objectContaining({ event: 'grace-end', clusterId: h.plan.steps[0]!.clusterId,
    data: expect.objectContaining({ kept: true, reason: expect.stringContaining(serviceKey(h.services[1]!)) }) }));
  expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
  expect(JSON.stringify({ report, entries: h.entries })).not.toContain(h.old.value);
});

test('finish checks latest inventory findings outside the plan before revoking', async () => {
  const h = await deferredRotation();
  const extra = h.host.addService('late-consumer', { OPENAI_API_KEY: h.old.value });
  const input = await h.input();
  // Findings alone must be sufficient; a caller need not have rebuilt its clusters.
  input.inventory.clusters = [];
  h.advance(5_000);

  const report = await finishRotation(input, h.deps, { ...h.opts, acceptUnplannedSealed: true });

  expect(h.provider.revoked).not.toContain(h.old.ref);
  expect(report.steps[0]!.warnings.join(' ')).toContain(serviceKey(extra));
  expect(h.entries).toContainEqual(expect.objectContaining({ event: 'grace-end',
    data: expect.objectContaining({ kept: true, reason: expect.stringContaining(serviceKey(extra)) }) }));
  expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
});

test('finish rereads a reference consumer that was replaced by a literal old key', async () => {
  const h = await deferredRotation(true);
  expect(h.plan.steps[0]!.consumers.some(consumer => consumer.reference)).toBe(true);
  await h.host.writeVariables(h.services[1]!, { OPENAI_API_KEY: h.old.value }, { skipDeploy: true });
  h.advance(5_000);

  const report = await finishRotation(await h.input(), h.deps, h.opts);

  expect(h.provider.revoked).not.toContain(h.old.ref);
  expect(report.status).toBe('partial');
  expect(report.steps[0]!.warnings.join(' ')).toContain(serviceKey(h.services[1]!));
});

test('finish keeps the old key if a reference was redirected to an old key outside the plan', async () => {
  const h = await deferredRotation(true);
  h.host.addService('outside', { OPENAI_API_KEY: h.old.value });
  await h.host.writeVariables(h.services[1]!, { OPENAI_API_KEY: '${{outside.OPENAI_API_KEY}}' }, { skipDeploy: true });
  // Keep the pre-redirect inventory: the current host read must still catch this.
  const input = { plan: h.plan, inventory: await h.scan(), entries: [...h.entries] };
  input.inventory.findings = input.inventory.findings.filter(finding => finding.service.serviceId !== 'outside');
  input.inventory.clusters = [];
  h.advance(5_000);

  const report = await finishRotation(input, h.deps, h.opts);

  expect(h.provider.revoked).not.toContain(h.old.ref);
  expect(report.steps[0]!.warnings.join(' ')).toContain(serviceKey(h.services[1]!));
});

test('finish settles an unchanged reference after checking its current replacement source', async () => {
  const h = await deferredRotation(true);
  h.advance(5_000);

  const report = await finishRotation(await h.input(), h.deps, h.opts);

  expect(report.status).toBe('complete');
  expect(h.provider.revoked).toEqual([h.old.ref]);
  expect(h.host.peek('worker', 'OPENAI_API_KEY')).toBe('${{api.OPENAI_API_KEY}}');
  expect(h.entries).toContainEqual(expect.objectContaining({ event: 'grace-end', data: expect.objectContaining({ kept: false }) }));
});

test.each(['renamed', 'ambiguous'])('finish retains the old key when a reference source is now %s', async mode => {
  const h = await deferredRotation(true);
  const input = await h.input();
  const outside = h.host.addService('outside', { OPENAI_API_KEY: h.old.value });
  const namespace = await h.host.listServices();
  h.host.listServices = async () => namespace.map(service => ({ ...service,
    serviceName: service.serviceId === outside.serviceId ? 'api'
      : service.serviceId === 'api' && mode === 'renamed' ? 'renamed-api' : service.serviceName,
  }));
  h.advance(5_000);

  const report = await finishRotation(input, h.deps, h.opts);

  expect(h.provider.revoked).not.toContain(h.old.ref);
  expect(report.status).toBe('partial');
  expect(report.steps[0]!.warnings.join(' ')).toContain(serviceKey(h.services[1]!));
});
