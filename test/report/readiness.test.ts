import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { Cluster, HostId, RotationMethod } from '../../src/types.js';
import { readinessScore, type ReadinessInput } from '../../src/report/readiness.js';
import { scanHosts } from '../../src/core/inventory.js';
import { createRuntime } from '../../src/cli/runtime.js';
import { getProvider } from '../../src/providers/index.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { FakeHost, FakeProvider, svc } from '../helpers/fakes.js';

const directories: string[] = [];
afterEach(async () => {
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
});

function cluster(method: RotationMethod = 'auto', sealed = false): Cluster {
  const service = svc('railway', 'one');
  return {
    id: 'key-one', fingerprint: sealed ? null : 'fingerprint', provider: 'openrouter', tier: 'ai', method,
    hint: null,
    consumers: [{ service, varName: 'OPENROUTER_API_KEY', fingerprint: sealed ? null : 'fingerprint', hint: null, sealed }],
  };
}

function input(): ReadinessInput {
  const key = cluster();
  return {
    inventory: { clusters: [key], services: [key.consumers[0]!.service] },
    configuredCredentials: ['OPENROUTER_PROVISIONING_KEY'], redeploy: { railway: true }, canaries: 0,
  };
}

describe('readinessScore', () => {
  it.each([
    { guided: false, want: 80 },
    { guided: true, want: 40 },
  ])('matches the CLI drill fixture for guided=$guided without mutations', async ({ guided, want }) => {
    // This is the shared-key, two-Railway-service fixture used by test/cli/commands.test.ts.
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    const provider = new FakeProvider(guided ? 'stripe' : 'openrouter', guided ? 'guided' : 'auto',
      guided ? 'sk_live_0123456789abcdef' : 'sk-or-v1-0123456789abcdef');
    const key = provider.issue();
    host.addService('one', { [guided ? 'STRIPE_SECRET_KEY' : 'OPENROUTER_API_KEY']: key.value });
    host.addService('two', { [guided ? 'STRIPE_SECRET_KEY' : 'OPENROUTER_API_KEY']: key.value });
    const inventory = await scanHosts([host], Buffer.alloc(32, 1), silentLogger);
    const cwd = await mkdtemp(join(tmpdir(), 'keysentry-report-readiness-'));
    directories.push(cwd);
    const runtime = await createRuntime({
      cwd, vault: createFakeVault(), inflight: createFakeInFlight(), userDir: join(cwd, '.user'),
      env: { OPENROUTER_PROVISIONING_KEY: 'test-management-credential' }, hosts: [host],
      providers: id => id === provider.id ? provider : getProvider(id),
      http: new FakeHttp(), log: silentLogger, feeds: [], sleep: async () => {},
      stdinIsTTY: true, stdoutIsTTY: true,
    });
    const result = readinessScore({ inventory, configuredCredentials: ['OPENROUTER_PROVISIONING_KEY'],
      redeploy: { railway: true }, canaries: 0 });
    expect(result).toEqual({ score: want, reasons: [
      `${guided ? 0 : 1}/1 clusters are currently auto-rotatable: automatic, atomic-roll, or generated (40 points).`,
      '0/1 clusters are sealed (15 points).',
      '1/1 clusters have duplicate consumers (15 points).',
      '0/1 clusters lack configured admin credentials (15 points).',
      '0/2 services require manual activation or have no redeploy support (10 points).',
      '0 canaries configured (5 points).',
    ] });
    const previous = await runtime.drill();
    expect(result).toEqual({ score: previous.score, reasons: previous.reasons });
    expect(host.writes).toEqual([]);
    expect(host.redeploys).toEqual([]);
    expect(provider.keys.size).toBe(1);
    expect(JSON.stringify(result)).not.toContain(key.value);
    expect(JSON.stringify(result)).not.toContain('test-management-credential');
  });

  it('returns zero for an empty inventory even with canaries', () => {
    expect(readinessScore({ inventory: { clusters: [], services: [] }, configuredCredentials: [], redeploy: {}, canaries: 2 }))
      .toEqual({ score: 0, reasons: [
        '0/0 clusters are currently auto-rotatable: automatic, atomic-roll, or generated (40 points).',
        '0/0 clusters are sealed (15 points).',
        '0/0 clusters have duplicate consumers (15 points).',
        '0/0 clusters lack configured admin credentials (15 points).',
        '0/0 services require manual activation or have no redeploy support (10 points).',
        '2 canaries configured (5 points).',
      ] });
  });

  it.each([
    { method: 'auto' as const, sealed: false, want: 95 },
    { method: 'atomic-roll' as const, sealed: false, want: 95 },
    { method: 'guided' as const, sealed: false, want: 55 },
    { method: 'auto' as const, sealed: true, want: 40 },
    { method: 'atomic-roll' as const, sealed: true, want: 40 },
    { method: 'generate' as const, sealed: true, want: 80 },
  ])('preserves $method scoring with sealed=$sealed', ({ method, sealed, want }) => {
    const data = input();
    const key = cluster(method, sealed);
    if (method === 'generate') key.provider = 'app-secret';
    data.inventory.clusters = [key];
    expect(readinessScore(data).score).toBe(want);
  });

  it('deducts missing credentials from both automation and credential factors', () => {
    const data = input();
    data.configuredCredentials = ['OPENAI_ADMIN_KEY'];
    const result = readinessScore(data);
    expect(result.score).toBe(40);
    expect(result.reasons[0]).toMatch(/^0\/1 /);
    expect(result.reasons[3]).toBe('1/1 clusters lack configured admin credentials (15 points).');
  });

  it('deducts duplicate consumer points once per key', () => {
    const data = input();
    data.inventory.clusters[0]!.consumers.push(data.inventory.clusters[0]!.consumers[0]!);
    expect(readinessScore(data).score).toBe(80);
  });

  it.each([
    { host: 'railway', service: 'one', environment: 'production', redeploy: true, want: 95 },
    { host: 'railway', service: '', environment: 'production', redeploy: true, want: 85 },
    { host: 'fly', service: 'one', environment: 'production', redeploy: true, want: 85 },
    { host: 'vercel', service: 'one', environment: 'preview', redeploy: true, want: 85 },
    { host: 'vercel', service: 'one', environment: 'development', redeploy: true, want: 85 },
    { host: 'vercel', service: 'one', environment: 'production', redeploy: true, want: 95 },
    { host: 'render', service: 'one', environment: 'production', redeploy: false, want: 85 },
    { host: 'dotenv', service: 'one', environment: '', redeploy: undefined, want: 85 },
  ])('preserves manual activation scoring for $host/$service/$environment', ({ host, service, environment, redeploy, want }) => {
    const data = input();
    data.inventory.services = [svc(host as HostId, service, environment)];
    data.redeploy = { [host]: redeploy };
    expect(readinessScore(data).score).toBe(want);
  });

  it('awards five points for any nonzero canary count', () => {
    const data = input();
    data.canaries = 3;
    expect(readinessScore(data)).toEqual({ score: 100, reasons: [
      '1/1 clusters are currently auto-rotatable: automatic, atomic-roll, or generated (40 points).',
      '0/1 clusters are sealed (15 points).',
      '0/1 clusters have duplicate consumers (15 points).',
      '0/1 clusters lack configured admin credentials (15 points).',
      '0/1 services require manual activation or have no redeploy support (10 points).',
      '3 canaries configured (5 points).',
    ] });
  });

  it('rounds fractional weighted scores only after combining all factors', () => {
    const data = input();
    data.inventory.clusters.push({ ...cluster('guided'), id: 'two' }, { ...cluster('guided'), id: 'three' });
    // One automatic key of three: 40/3 + 15 + 15 + 15 + 10 = 68.333...
    expect(readinessScore(data).score).toBe(68);
  });

  it('does not mutate frozen input data', () => {
    const data = input();
    Object.freeze(data.inventory.clusters[0]!.consumers);
    Object.freeze(data.inventory.clusters[0]);
    Object.freeze(data.inventory.clusters);
    Object.freeze(data.inventory.services);
    Object.freeze(data.inventory);
    Object.freeze(data.configuredCredentials);
    Object.freeze(data.redeploy);
    Object.freeze(data);
    expect(readinessScore(data).score).toBe(95);
  });
});
