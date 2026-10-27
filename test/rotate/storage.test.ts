import { expect, test, vi } from 'vitest';
import { buildInventory, buildPlan, createRedactor } from '../../src/core/index.js';
import { executePlan, type EngineDeps, type RotateOptions } from '../../src/rotate/engine.js';
import type { JournalEntry } from '../../src/types.js';
import { FakeHttp } from '../helpers/fake-http.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';

test('stores each replacement before journalling it and shreds a completed plan', async () => {
  const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
  const old = provider.issue();
  const host = new FakeHost('railway');
  const service = host.addService('api', { OPENAI_API_KEY: old.value });
  const key = Buffer.alloc(32, 9);
  const inv = buildInventory([{ host: host.id, services: [{ service, vars: await host.readVariables(service) }] }], key);
  const plan = buildPlan(inv);
  const inflight = createFakeInFlight();
  const entries: JournalEntry[] = [];
  const log = { info() {}, warn() {}, error() {}, debug() {} };
  const trace: string[] = [];
  const rotate = provider.rotate.bind(provider);
  vi.spyOn(provider, 'rotate').mockImplementation(async (...args) => { const result = await rotate(...args); trace.push('rotate'); return result; });
  const put = inflight.put.bind(inflight);
  vi.spyOn(inflight, 'put').mockImplementation(async (...args) => { trace.push(`put:${args[1]}`); await put(...args); });
  const deps: EngineDeps = {
    hosts: { railway: host }, providers: () => provider, providerCtx: { http: new FakeHttp(), credentials: {}, log },
    journal: { async append(e) { trace.push(`journal:${e.event}`); entries.push(e); }, async read() { return entries; } },
    prompt: async () => null, fingerprintKey: key, redactor: createRedactor(), log, inflight, sleep: async () => {},
  };
  const opts: RotateOptions = { dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 1,
    revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 0 };
  const report = await executePlan(plan, inv, deps, opts);
  expect(trace[trace.indexOf('rotate') + 1]).toBe(`put:new:${plan.steps[0]!.clusterId}`);
  expect(entries.some(e => e.event === 'value-stored')).toBe(true);
  expect(report.status).toBe('complete');
  expect(inflight.shredded.has(plan.id)).toBe(true);
  expect(entries.at(-1)?.event).toBe('plan-end');
});
