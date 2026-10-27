import { buildInventory, buildPlan, createLogger, createRedactor, fingerprint, serviceKey } from '../../src/core/index.js';
import type { EngineDeps, RotateOptions } from '../../src/rotate/engine.js';
import type { Journal, JournalEntry, ProviderAdapter, ProviderId } from '../../src/types.js';
import { FakeHttp } from '../helpers/fake-http.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

/** Two independent secrets share two services, so batching and revoke-last are observable together. */
export async function recoveryFixture() {
  const clock = { ms: Date.parse('2026-10-26T08:00:00.000Z') };
  const now = () => new Date(clock.ms);
  const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
  const generate = new FakeProvider('app-secret', 'generate', 'Az1By2Cx3Dw4Ev5Fu6Gt7Hs8Ir9Jq0-');
  provider.now = now;
  generate.now = now;
  const old = provider.issue();
  const oldGenerated = generate.issue();
  clock.ms = Date.parse('2026-10-27T08:00:00.000Z');
  const host = new FakeHost('railway');
  const services = [
    host.addService('api', { OPENAI_API_KEY: old.value, SESSION_SECRET: oldGenerated.value, NODE_ENV: 'production' }),
    host.addService('worker', { OPENAI_API_KEY: old.value, SESSION_SECRET: oldGenerated.value, NODE_ENV: 'production' }),
  ];
  const fingerprintKey = Buffer.alloc(32, 0x68);
  const inventory = buildInventory([{ host: host.id, services: await Promise.all(services.map(async service => ({
    service, vars: await host.readVariables(service),
  }))) }], fingerprintKey, now());
  const plan = buildPlan(inventory);
  const trace: string[] = [];
  const storedValues: string[] = [];
  const entries: JournalEntry[] = [];
  const journal: Journal & { entries: JournalEntry[] } = {
    entries,
    async append(entry) { trace.push(`journal:${entry.event}`); entries.push(structuredClone(entry)); },
    async read(planId) { trace.push('journal:read'); return entries.filter(entry => planId === undefined || entry.planId === planId); },
  };
  const inflight = createFakeInFlight();
  const put = inflight.put.bind(inflight);
  inflight.put = async (planId, slot, value) => {
    trace.push(`put:${slot}`);
    storedValues.push(value);
    await put(planId, slot, value);
  };
  const get = inflight.get.bind(inflight);
  inflight.get = async (planId, slot) => { trace.push(`get:${slot}`); return get(planId, slot); };
  const shred = inflight.shred.bind(inflight);
  inflight.shred = async planId => { trace.push('shred'); await shred(planId); };
  const deployed = new Set<string>();
  const revocations: { provider: ProviderId; keyRef: string; deployed: string[]; current: string[] }[] = [];
  const read = host.readVariables.bind(host);
  host.readVariables = async service => { trace.push(`read:${service.serviceId}`); return read(service); };
  const write = host.writeVariables.bind(host);
  host.writeVariables = async (service, vars, options) => {
    trace.push(`write:${service.serviceId}`);
    await write(service, vars, options);
    deployed.delete(service.serviceId);
  };
  const redeploy = host.redeploy.bind(host);
  host.redeploy = async service => { trace.push(`redeploy:${service.serviceId}`); return redeploy(service); };
  const poll = host.deploymentStatus.bind(host);
  host.deploymentStatus = async (service, id) => {
    trace.push(`poll:${service.serviceId}:${id}`);
    const state = await poll(service, id);
    if (state === 'success') deployed.add(service.serviceId);
    return state;
  };
  for (const current of [provider, generate]) {
    const rotate = current.rotate.bind(current);
    current.rotate = async (value, ctx) => {
      trace.push(`rotate:${current.id}`);
      const result = await rotate(value, ctx);
      trace.push(`rotated:${current.id}`);
      return result;
    };
    const verify = current.verify.bind(current);
    current.verify = async (value, ctx) => { trace.push(`verify:${current.id}`); return verify(value, ctx); };
    const resolve = current.resolveKeyRef.bind(current);
    current.resolveKeyRef = async (value, ctx) => { trace.push(`resolve:${current.id}`); return resolve(value, ctx); };
    const list = current.listKeys.bind(current);
    current.listKeys = async ctx => { trace.push(`list:${current.id}`); return list(ctx); };
    const revoke = current.revoke.bind(current);
    current.revoke = async (keyRef, ctx) => {
      trace.push(`revoke:${current.id}:${keyRef}`);
      const name = current.id === 'openai' ? 'OPENAI_API_KEY' : 'SESSION_SECRET';
      revocations.push({ provider: current.id, keyRef, deployed: [...deployed], current: services.map(service => host.peek(service.serviceId, name)!) });
      await revoke(keyRef, ctx);
    };
  }
  const redactor = createRedactor();
  const lines: string[] = [];
  const log = createLogger({ redactor, level: 'debug', json: true, sink: line => { trace.push('log'); lines.push(line); } });
  const byId = new Map<ProviderId, ProviderAdapter>([[provider.id, provider], [generate.id, generate]]);
  const deps: EngineDeps = {
    hosts: { railway: host }, providers(id) { const adapter = byId.get(id); if (!adapter) throw new Error(`Missing provider ${id}`); return adapter; },
    providerCtx: { http: new FakeHttp(), credentials: {}, log },
    journal, inflight, prompt: async () => null, fingerprintKey, redactor, log, now,
    sleep: async ms => { trace.push(`sleep:${ms}`); clock.ms += ms; }, reveal: async () => true,
  };
  const opts: RotateOptions = {
    dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 1,
    revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 0,
    graceMs: 0,
  };
  return {
    host, provider, generate, inventory, inv: inventory, plan, deps, opts, journal, inflight,
    old, oldGenerated, services, trace, storedValues, lines, clock, revocations,
    clusterId: fingerprint(old.value, fingerprintKey), generatedClusterId: fingerprint(oldGenerated.value, fingerprintKey),
    serviceKeys: services.map(serviceKey),
  };
}
