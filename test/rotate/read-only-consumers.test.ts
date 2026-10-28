// fix-verify M-b: Kubernetes Secrets that a controller manages are read-only consumers. A rotation sees the copies
// they hold, never writes them, and keeps (never rolls or revokes) a key also held there.
import { describe, expect, it } from 'vitest';
import { buildInventory, buildPlan, createLogger, createRedactor } from '../../src/core/index.js';
import { executePlan, type EngineDeps, type RotateOptions } from '../../src/rotate/engine.js';
import { createKubernetesHost } from '../../src/hosts/kubernetes.js';
import type { HostAdapter, JournalEntry, ProviderAdapter } from '../../src/types.js';
import { FakeHttp, json, silentLogger } from '../helpers/fake-http.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

const key = Buffer.alloc(32, 0x4b);
const b64 = (value: string) => Buffer.from(value, 'utf8').toString('base64');
const options: RotateOptions = {
  dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 1,
  revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 0,
};

/** A Kubernetes cluster with one Secret `apps/api-env` that External Secrets owns. */
function cluster(data: Record<string, string>) {
  const secret = {
    apiVersion: 'v1', kind: 'Secret', type: 'Opaque',
    metadata: { name: 'api-env', namespace: 'apps', resourceVersion: '9', uid: 's-1',
      ownerReferences: [{ apiVersion: 'external-secrets.io/v1beta1', kind: 'ExternalSecret', name: 'api-env', uid: 'u-1', controller: true }] },
    data: Object.fromEntries(Object.entries(data).map(([name, value]) => [name, b64(value)])),
  };
  const http = new FakeHttp()
    .on('GET', /\/api\/v1\/namespaces\/apps\/secrets\?/, () => json(200, { metadata: {}, items: [secret] }))
    .on('GET', /\/api\/v1\/namespaces\/apps\/secrets\/api-env$/, () => json(200, secret))
    .on('PUT', /\/api\/v1\/namespaces\/apps\/secrets\/api-env$/, () => json(200, secret));
  return { http, host: createKubernetesHost({ server: 'https://k8s.example.test', token: 'kube-token', namespaces: ['apps'], http, log: silentLogger }) };
}

async function run(hosts: HostAdapter[], provider: ProviderAdapter) {
  const inv = buildInventory(await Promise.all(hosts.map(async host => ({ host: host.id, services: await Promise.all((await host.listServices())
    .map(async service => ({ service, vars: await host.readVariables(service) }))) }))), key);
  const entries: JournalEntry[] = [];
  const redactor = createRedactor();
  const log = createLogger({ redactor, level: 'debug', json: true, sink: () => undefined });
  const deps: EngineDeps = {
    hosts: Object.fromEntries(hosts.map(host => [host.id, host])), providers: () => provider,
    providerCtx: { http: new FakeHttp(), credentials: {}, log },
    journal: { async append(entry) { entries.push(structuredClone(entry)); }, async read() { return entries; } },
    prompt: async () => null, reveal: async () => true, fingerprintKey: key, redactor, log, sleep: async () => undefined,
  };
  const report = await executePlan(buildPlan(inv), inv, deps, options);
  return { inv, report, warnings: report.steps.flatMap(step => step.warnings).join(' ') };
}

describe('read-only consumers (managed Kubernetes Secrets)', () => {
  it('delivers the replacement elsewhere, never writes the managed Secret and keeps the old key', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const railway = new FakeHost('railway');
    railway.pendingPolls = 0;
    railway.addService('api', { OPENAI_API_KEY: old.value });
    const k8s = cluster({ OPENAI_API_KEY: old.value });

    const { inv, report, warnings } = await run([railway, k8s.host], provider);

    expect(inv.clusters).toHaveLength(1);
    expect(inv.clusters[0]!.consumers.map(consumer => consumer.service.host).sort()).toEqual(['kubernetes', 'railway']);
    expect(railway.peek('api', 'OPENAI_API_KEY')).not.toBe(old.value);
    expect(k8s.http.callsTo('PUT', /./)).toHaveLength(0);
    expect(provider.revoked).toEqual([]);
    expect(provider.keys.get(old.ref)!.active).toBe(true);
    expect(warnings).toMatch(/Old key kept: kubernetes\/apps\/api-env:OPENAI_API_KEY \(a Kubernetes Secret managed by External Secrets, which restores its value from its own source\) also holds this key/);
    expect(warnings).toMatch(/Update the key in that controller's source \(the store it syncs from\).*revoke the old key yourself/);
    expect(report.diff.join('\n')).toMatch(/OPENAI_API_KEY: kept \(keysentry does not write it; the old key is not revoked\)/);
    expect(report.status).toBe('partial');
    expect(JSON.stringify(report)).not.toContain(old.value);
  });

  it('does not roll a key that a managed Secret also holds (a roll would end it at once)', async () => {
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'cf-token-');
    let rolls = 0;
    provider.rotate = async () => { rolls += 1; throw new Error('must not roll'); };
    const token = 'Zx8Kq2Lm9Pw4Rt7Ys1Vb6Nc3Hd5Jf0Ga';
    const railway = new FakeHost('railway');
    railway.pendingPolls = 0;
    railway.addService('api', { CLOUDFLARE_API_TOKEN: token });
    const k8s = cluster({ CLOUDFLARE_API_TOKEN: token });

    const { report, warnings } = await run([railway, k8s.host], provider);

    expect(rolls).toBe(0);
    expect(railway.writes).toEqual([]);
    expect(report.steps[0]!.status).toBe('skipped');
    expect(warnings).toMatch(/Not rolled: a roll ends the old key at once, but kubernetes\/apps\/api-env:CLOUDFLARE_API_TOKEN .* also holds it/);
  });

  it('does not rotate a key held only in managed Secrets', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const k8s = cluster({ OPENAI_API_KEY: old.value });

    const { report, warnings } = await run([k8s.host], provider);

    expect(provider.keys.size).toBe(1);
    expect(report.steps[0]!.status).toBe('skipped');
    expect(warnings).toMatch(/Not rotated: every copy of this key is in a place keysentry reads but does not write: kubernetes\/apps\/api-env:OPENAI_API_KEY/);
    expect(k8s.http.callsTo('PUT', /./)).toHaveLength(0);
  });
});
