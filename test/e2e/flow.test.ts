import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createRuntime } from '../../src/cli/runtime.js';
import { runCli } from '../../src/cli/index.js';
import { serviceKey } from '../../src/core/index.js';
import { defaultPolicy } from '../../src/monitor/index.js';
import { getProvider } from '../../src/providers/index.js';
import { createDotenvHost } from '../../src/hosts/index.js';
import type { RotationReport } from '../../src/types.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { FakeHttp, json, silentLogger } from '../helpers/fake-http.js';

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(directories.splice(0).map(directory => rm(directory, { recursive: true, force: true })));
});

async function filesUnder(directory: string): Promise<string[]> {
  const files: string[] = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await filesUnder(path));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}

describe('breach-night CLI and monitoring flow', () => {
  it('rotates every copy, batches each service, responds to a canary, and persists no plaintext', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'keysentry-e2e-'));
    directories.push(cwd);
    const http = new FakeHttp();
    const railway = new FakeHost('railway');
    const vercel = new FakeHost('vercel');
    railway.pendingPolls = 0;
    vercel.pendingPolls = 0;
    const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-0123456789abcdef');
    const duplicated = provider.issue('shared-production-key');
    const unrelated = provider.issue('web-only-key');
    const sessionSecret = 'd596c84fc421981033f781cf184d73de9ab9423fe96c310a762d04518feb862a';
    const api = railway.addService('api', { OPENROUTER_API_KEY: duplicated.value, SESSION_SECRET: sessionSecret, NODE_ENV: 'production' });
    vercel.addService('web', {
      OPENROUTER_API_KEY: duplicated.value,
      OPENROUTER_SECONDARY_KEY: unrelated.value,
      PORT: '3000',
    });
    const credential = 'local-management-credential-for-e2e-only';
    const runtime = await createRuntime({
      cwd,
      env: { OPENROUTER_PROVISIONING_KEY: credential },
      hosts: [railway, vercel],
      providers: id => id === 'openrouter' ? provider : getProvider(id),
      http,
      policy: { ...defaultPolicy(), autoExecute: true },
      feeds: [],
      log: silentLogger,
      sleep: async () => {},
    });
    const output: string[] = [];
    const errors: string[] = [];
    const io = { runtime, output: (line: string) => output.push(line), error: (line: string) => errors.push(line) };

    expect(await runCli(['scan', '--json'], io)).toBe(0);
    const inventory = await runtime.inventory();
    expect(inventory.hosts.sort()).toEqual(['railway', 'vercel']);
    expect(inventory.clusters).toHaveLength(3);
    const session = inventory.clusters.find(cluster => cluster.provider === 'app-secret');
    expect(session?.method).toBe('generate');
    const shared = inventory.clusters.find(cluster => cluster.consumers.length === 2);
    expect(shared).toBeDefined();
    expect(shared?.provider).toBe('openrouter');
    expect(new Set(shared?.consumers.map(consumer => consumer.service.host))).toEqual(new Set(['railway', 'vercel']));

    const plan = await runtime.plan({ tiers: ['ai'] });
    expect(plan.steps).toHaveLength(2);
    expect(plan.services).toHaveLength(2);
    const beforeDryRun = provider.keys.size;
    const dryRun = await runtime.rotate(plan, {});
    expect(dryRun.dryRun).toBe(true);
    expect(dryRun.diff.length).toBeGreaterThan(0);
    expect(provider.keys.size).toBe(beforeDryRun);
    expect(provider.revoked).toEqual([]);
    expect(railway.writes).toEqual([]);
    expect(vercel.writes).toEqual([]);
    expect(railway.redeploys).toEqual([]);
    expect(vercel.redeploys).toEqual([]);

    const rotation = await runtime.rotate(plan, { execute: true });
    expect(rotation.dryRun).toBe(false);
    expect(rotation.steps.every(step => step.status === 'revoked')).toBe(true);
    expect(railway.writes).toHaveLength(1);
    expect(vercel.writes).toHaveLength(1);
    expect(Object.keys(vercel.writes[0]!.vars).sort()).toEqual(['OPENROUTER_API_KEY', 'OPENROUTER_SECONDARY_KEY']);
    expect(railway.writes[0]!.skipDeploy).toBe(true);
    expect(vercel.writes[0]!.skipDeploy).toBe(true);
    expect(railway.redeploys).toEqual(['api']);
    expect(vercel.redeploys).toEqual(['web']);
    expect(provider.revoked.sort()).toEqual([duplicated.ref, unrelated.ref].sort());
    expect(railway.peek('api', 'OPENROUTER_API_KEY') === vercel.peek('web', 'OPENROUTER_API_KEY')).toBe(true);
    expect(railway.peek('api', 'OPENROUTER_API_KEY') === duplicated.value).toBe(false);
    expect(railway.peek('api', 'NODE_ENV')).toBe('production');
    expect(railway.peek('api', 'SESSION_SECRET') === sessionSecret).toBe(true);
    expect(vercel.peek('web', 'PORT')).toBe('3000');

    const sharedBeforeMonitor = railway.peek('api', 'OPENROUTER_API_KEY')!;
    const sharedRefBeforeMonitor = provider.refOf(sharedBeforeMonitor)!;
    const unrelatedBeforeMonitor = vercel.peek('web', 'OPENROUTER_SECONDARY_KEY')!;
    const unrelatedRefBeforeMonitor = provider.refOf(unrelatedBeforeMonitor)!;
    http.on('POST', /^https:\/\/openrouter\.ai\/api\/v1\/keys$/, request => {
      const body = JSON.parse(request.body!) as { name: string; limit: number };
      expect(body.limit).toBe(0.01);
      const decoy = provider.issue(body.name, body.limit);
      return json(200, { key: decoy.value, data: { hash: decoy.ref } });
    });
    const canary = await runtime.createCanary({ host: 'railway', service: serviceKey(api), execute: true });
    expect(canary).not.toBeNull();
    expect(canary?.service.serviceId).toBe('api');
    expect(railway.writes).toHaveLength(2);
    expect(railway.redeploys).toHaveLength(1);
    provider.spend(canary!.keyRef, 0.001, 1);

    expect(await runCli(['monitor', '--once', '--json'], io)).toBe(0);
    const monitor = JSON.parse(output.at(-1)!) as { decisions: { action: string; reason?: string; clusterIds: string[] }[] };
    expect(monitor.decisions.some(decision => decision.action === 'alert' && decision.reason === 'generate-disabled'
      && decision.clusterIds.includes(session!.id))).toBe(true);
    expect(railway.writes).toHaveLength(3);
    expect(vercel.writes).toHaveLength(2);
    expect(railway.redeploys).toEqual(['api', 'api']);
    expect(vercel.redeploys).toEqual(['web', 'web']);
    expect(provider.revoked.includes(sharedRefBeforeMonitor)).toBe(true);
    expect(provider.revoked.includes(unrelatedRefBeforeMonitor)).toBe(false);
    expect(provider.revoked.includes(canary!.keyRef)).toBe(false);
    expect(vercel.peek('web', 'OPENROUTER_SECONDARY_KEY') === unrelatedBeforeMonitor, 'unrelated provider key retained').toBe(true);
    expect(railway.peek('api', 'OPENROUTER_API_KEY') === sharedBeforeMonitor, 'shared provider key replaced').toBe(false);
    expect(railway.peek('api', 'OPENROUTER_API_KEY') === vercel.peek('web', 'OPENROUTER_API_KEY'), 'shared consumers agree').toBe(true);
    expect(railway.peek('api', 'SESSION_SECRET') === sessionSecret, 'monitor never generates session secret').toBe(true);
    expect(Object.keys(railway.writes[2]!.vars)).toEqual(['OPENROUTER_API_KEY']);
    const state = JSON.parse(await readFile(join(cwd, '.keysentry', 'monitor.json'), 'utf8')) as {
      canaries: { id: string; triggeredAt?: string }[];
      pendingActions: { action: string; status: string; clusterIds: string[] }[];
    };
    expect(state.canaries.find(candidate => candidate.id === canary!.id)?.triggeredAt).toBeDefined();
    expect(state.pendingActions.some(action => action.action === 'rotate' && action.status === 'executed')).toBe(true);
    expect(errors).toEqual([]);

    const report = await runtime.report();
    const files = await filesUnder(join(cwd, '.keysentry'));
    expect(files.length).toBeGreaterThanOrEqual(4);
    const fileContents = await Promise.all(files.map(path => readFile(path)));
    const allText = [report, JSON.stringify(rotation), JSON.stringify(dryRun), ...output, ...errors];
    const secrets = [credential, sessionSecret, ...[...provider.keys.values()].map(key => key.value)];
    for (const secret of secrets) {
      // Boolean assertions prevent a failed safety check from printing the fixture secret.
      expect(allText.some(text => text.includes(secret))).toBe(false);
      expect(fileContents.some(contents => contents.includes(Buffer.from(secret)))).toBe(false);
    }
  });

  it.each([false, true])('keeps dotenv activation unconfirmed and applies explicit revoke override: %s', async revokeUnconfirmed => {
    const cwd = await mkdtemp(join(tmpdir(), 'keysentry-dotenv-e2e-'));
    directories.push(cwd);
    const dotenvPath = join(cwd, '.env');
    const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-0123456789abcdef');
    const original = provider.issue('dotenv-key');
    const source = `# Application restart remains manual\nOPENROUTER_API_KEY=${original.value}\nPORT=3000\n`;
    await writeFile(dotenvPath, source, { mode: 0o600 });
    const dotenv = createDotenvHost({ roots: [cwd], log: silentLogger });
    const runtime = await createRuntime({
      cwd, env: {}, hosts: [dotenv], providers: id => id === 'openrouter' ? provider : getProvider(id),
      http: new FakeHttp(), feeds: [], log: silentLogger, sleep: async () => {},
    });
    const output: string[] = [];
    const errors: string[] = [];
    const io = { runtime, output: (line: string) => output.push(line), error: (line: string) => errors.push(line) };

    expect(await runCli(['scan', '--json'], io)).toBe(0);
    const plan = await runtime.plan();
    expect(plan.steps).toHaveLength(1);
    expect(await runCli(['rotate', '--plan', plan.id, '--json'], io)).toBe(0);
    const dryRun = JSON.parse(output.at(-1)!) as { report: RotationReport };
    expect(dryRun.report.dryRun).toBe(true);
    expect(await readFile(dotenvPath, 'utf8') === source).toBe(true);
    expect(provider.keys.size).toBe(1);
    expect(provider.revoked).toEqual([]);

    const args = ['rotate', '--plan', plan.id, '--execute', '--yes', '--json'];
    if (revokeUnconfirmed) args.push('--revoke-unconfirmed');
    expect(await runCli(args, io)).toBe(0);
    const execution = JSON.parse(output.at(-1)!) as { report: RotationReport };
    expect(execution.report.dryRun).toBe(false);
    expect(execution.report.deployments).toHaveLength(1);
    expect(execution.report.deployments[0]!.state).toBe('unconfirmed');
    expect(execution.report.steps[0]!.warnings.length).toBeGreaterThan(0);
    expect(provider.revoked).toEqual(revokeUnconfirmed ? [original.ref] : []);
    expect(provider.keys.get(original.ref)?.active).toBe(!revokeUnconfirmed);
    const [service] = await dotenv.listServices();
    const variables = await dotenv.readVariables(service!);
    const replacement = variables.find(variable => variable.name === 'OPENROUTER_API_KEY')?.value;
    expect(replacement === original.value).toBe(false);
    expect(replacement !== undefined && provider.refOf(replacement) !== null).toBe(true);
    expect(variables.find(variable => variable.name === 'PORT')?.value).toBe('3000');
    expect((await readFile(dotenvPath, 'utf8')).startsWith('# Application restart remains manual\n')).toBe(true);
    const metadata = await Promise.all((await filesUnder(join(cwd, '.keysentry'))).map(path => readFile(path)));
    for (const secret of [...provider.keys.values()].map(key => key.value)) {
      expect([...output, ...errors].some(text => text.includes(secret))).toBe(false);
      expect(metadata.some(contents => contents.includes(Buffer.from(secret)))).toBe(false);
    }
  });

  it('revokes a high-confidence canary leak on dotenv despite unconfirmed activation', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'keysentry-dotenv-monitor-e2e-'));
    directories.push(cwd);
    const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-0123456789abcdef');
    const original = provider.issue('dotenv-compromised-key');
    await writeFile(join(cwd, '.env'), `OPENROUTER_API_KEY=${original.value}\n`, { mode: 0o600 });
    const dotenv = createDotenvHost({ roots: [cwd], log: silentLogger });
    const http = new FakeHttp();
    http.on('POST', /^https:\/\/openrouter\.ai\/api\/v1\/keys$/, request => {
      const body = JSON.parse(request.body!) as { name: string; limit: number };
      expect(body.limit).toBe(0.01);
      const decoy = provider.issue(body.name, body.limit);
      return json(200, { key: decoy.value, data: { hash: decoy.ref } });
    });
    const runtime = await createRuntime({
      cwd, env: { OPENROUTER_PROVISIONING_KEY: 'dotenv-monitor-management-credential-e2e-only' },
      hosts: [dotenv], providers: id => id === 'openrouter' ? provider : getProvider(id), http,
      policy: { ...defaultPolicy(), autoExecute: true }, feeds: [], log: silentLogger, sleep: async () => {},
    });
    const output: string[] = [];
    const errors: string[] = [];
    const io = { runtime, output: (line: string) => output.push(line), error: (line: string) => errors.push(line) };
    expect(await runCli(['scan', '--json'], io)).toBe(0);
    const [service] = (await runtime.inventory()).services;
    const canary = await runtime.createCanary({ host: 'dotenv', service: serviceKey(service!), execute: true });
    provider.spend(canary!.keyRef, 0.001, 1);

    expect(await runCli(['monitor', '--once', '--json'], io)).toBe(0);
    const report = JSON.parse(await readFile(join(cwd, '.keysentry', 'rotation-report.json'), 'utf8')) as RotationReport;
    expect(report.dryRun).toBe(false);
    expect(report.deployments[0]!.state).toBe('unconfirmed');
    expect(provider.revoked).toEqual([original.ref]);
    expect(provider.keys.get(original.ref)?.active).toBe(false);
    expect(provider.keys.get(canary!.keyRef)?.active).toBe(true);
    expect(report.steps[0]!.warnings.length).toBeGreaterThan(0);
    expect(errors.every(line => !line.includes(original.value))).toBe(true);
  });
});
