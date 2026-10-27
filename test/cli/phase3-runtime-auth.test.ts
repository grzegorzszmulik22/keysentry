import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, test } from 'vitest';
import { createRuntime } from '../../src/cli/runtime.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { getProvider } from '../../src/providers/index.js';
import { readinessScore } from '../../src/report/index.js';
import { createHygieneStateStore } from '../../src/hygiene/index.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
async function fixture(env: NodeJS.ProcessEnv = {}, tty = false) {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-phase3-auth-')); dirs.push(cwd);
  const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-0123456789abcdef');
  const key = provider.issue(); const host = new FakeHost('railway'); host.pendingPolls = 0;
  host.addService('app', { OPENROUTER_API_KEY: key.value });
  const runtime = await createRuntime({ cwd, userDir: join(cwd, 'user'), vault: createFakeVault(),
    inflight: createFakeInFlight(), env, http: new FakeHttp(), hosts: [host], log: silentLogger,
    providers: id => id === 'openrouter' ? provider : getProvider(id),
    stdinIsTTY: tty, stdoutIsTTY: tty, now: () => new Date('2026-10-27T12:00:00Z'), sleep: async () => {} });
  return { runtime, provider, host };
}

test('dashboard authorization permits a verified mutation without a terminal and stays scoped', async () => {
  const { runtime } = await fixture();
  await expect(runtime.vaultSet('GITHUB_TOKEN', 'local-value', 'read')).rejects.toThrow(/interactive terminal/);
  await runtime.dashboardAction(() => runtime.vaultSet('GITHUB_TOKEN', 'local-value', 'read'));
  expect((await runtime.vault.get('cred/GITHUB_TOKEN@read'))?.toString()).toBe('local-value');
  await expect(runtime.vaultRemove('GITHUB_TOKEN', 'read')).rejects.toThrow(/interactive terminal/);
});

test('dashboard authorization cannot bypass an agent marker', async () => {
  const { runtime } = await fixture({ AI_AGENT: 'test' });
  await expect(runtime.dashboardAction(() => runtime.vaultSet('GITHUB_TOKEN', 'local-value', 'read'))).rejects.toThrow(/AI coding agent/);
  expect(await runtime.vault.get('cred/GITHUB_TOKEN@read')).toBeNull();
});

test('dashboard disarm works under an agent marker without authorizing any mutation', async () => {
  const { runtime } = await fixture({ AI_AGENT: 'test' });
  await runtime.dashboardDisarm();
  expect((await runtime.autopilotManager().loadState()).disarmed).toBe(true);
  await expect(runtime.vaultSet('GITHUB_TOKEN', 'local-value')).rejects.toThrow(/AI coding agent/);
});

test('dashboard rotation defers grace even when its launching terminal is interactive', async () => {
  const { runtime, provider, host } = await fixture({}, true);
  await runtime.scan(); const plan = await runtime.plan();
  runtime.config.rotation.graceMs = 60_000;
  const report = await runtime.dashboardAction(() => runtime.rotate(plan, { execute: true }));
  expect(report.status).toBe('grace-pending');
  expect(host.writes).toHaveLength(1);
  expect(provider.revoked).toHaveLength(0);
});

test('scan records first seen without replacing it on later scans', async () => {
  const { runtime } = await fixture(); const inv = await runtime.scan();
  const store = createHygieneStateStore(runtime.store);
  const state = await store.load();
  expect(state.firstSeen[inv.clusters[0]!.fingerprint!]).toBe('2026-10-27T12:00:00.000Z');
  state.firstSeen[inv.clusters[0]!.fingerprint!] = '2026-10-01T00:00:00.000Z'; await store.save(state);
  await runtime.scan();
  expect((await store.load()).firstSeen).toEqual(state.firstSeen);
});

test('drill uses the shared report readiness score', async () => {
  const { runtime } = await fixture();
  const result = await runtime.drill(); const inventory = await runtime.inventory();
  expect({ score: result.score, reasons: result.reasons }).toEqual(readinessScore({ inventory,
    configuredCredentials: [], redeploy: { railway: true }, canaries: 0 }));
});

test('autopilot arming guard cancels before committing its signed plan', async () => {
  const { runtime } = await fixture({}, true); await runtime.drill();
  const manager = runtime.autopilotManager({ assertActive: () => { throw new Error('Arming cancelled.'); } });
  await expect(manager.arm()).rejects.toThrow('Arming cancelled.');
  expect(await manager.loadPlan()).toBeNull();
});

test('connecting a platform enables it on the next scan without restarting the dashboard', async () => {
  const { runtime } = await fixture();
  // Exercise a production adapter refresh without making a network call: an empty
  // explicit Railway project list means discovery is requested only on scan.
  await runtime.dashboardAction(() => runtime.vaultSet('RAILWAY_TOKEN', 'new-platform-token', 'read'));
  await runtime.refreshConnections();
  expect((await runtime.credentials.get('RAILWAY_TOKEN', 'read'))?.source).toBe('vault');
});

test('removing a credential clears the cached read context immediately', async () => {
  const { runtime } = await fixture({}, true);
  await runtime.vaultSet('OPENROUTER_PROVISIONING_KEY', 'local-provisioning-value', 'read');
  await runtime.providerContext('read');
  expect(runtime.config.providerCtx.credentials.OPENROUTER_PROVISIONING_KEY).toBe('local-provisioning-value');
  await runtime.vaultRemove('OPENROUTER_PROVISIONING_KEY', 'read');
  expect(runtime.config.providerCtx.credentials.OPENROUTER_PROVISIONING_KEY).toBeUndefined();
});

test('saved dashboard grace applies to a fresh CLI runtime before its first facade read', async () => {
  const { runtime } = await fixture({}, true);
  await runtime.store.writeJson('monitor', join(runtime.paths.dir, 'dashboard-settings.json'), {
    graceMinutes: 7, rotateEveryDays: 90, spendCapsUsd: {}, digestDay: 'off', showHints: false,
  });
  const reopened = await createRuntime({ cwd: runtime.config.cwd, userDir: runtime.userDir, vault: runtime.vault,
    inflight: createFakeInFlight(), env: {}, http: new FakeHttp(), hosts: [], log: silentLogger });
  expect(reopened.config.rotation.graceMs).toBe(7 * 60000);
});

test('disarm wins when it arrives during an armed-state write', async () => {
  const { runtime } = await fixture({}, true); await runtime.drill();
  const original = runtime.store.writeJson.bind(runtime.store);
  let release!: () => void; let entered!: () => void;
  const ready = new Promise<void>(resolve => { entered = resolve; });
  const blocked = new Promise<void>(resolve => { release = resolve; });
  let first = true;
  runtime.store.writeJson = async (...args: Parameters<typeof original>) => {
    if (first && args[1].endsWith('autopilot.json') && (args[2] as { disarmed?: boolean }).disarmed === false) {
      first = false; entered(); await blocked;
    }
    return original(...args);
  };
  const arming = runtime.autopilotManager().arm();
  await ready;
  // The disarm audit proves its state write has completed in the old code. A
  // serialized implementation instead keeps it pending until the arm releases.
  let disarmed = false;
  const disarming = runtime.dashboardDisarm().then(() => { disarmed = true; });
  await new Promise<void>(resolve => setTimeout(resolve, 40));
  const completedBeforeRelease = disarmed;
  release();
  await Promise.allSettled([arming, disarming]);
  expect((await runtime.autopilotManager().loadState()).disarmed).toBe(true);
  expect(completedBeforeRelease).toBe(false);
});
