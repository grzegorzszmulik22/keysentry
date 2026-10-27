import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { afterEach, expect, test, vi } from 'vitest';
import { createRuntime, type RuntimeOptions } from '../../src/cli/runtime.js';
import { runCli } from '../../src/cli/index.js';
import * as release from '../../src/release/index.js';
import { createMonitorState } from '../../src/monitor/state.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';

const dirs: string[] = [];
afterEach(async () => { vi.restoreAllMocks(); for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
async function fixture(cwd?: string, extra: Partial<RuntimeOptions> = {}) {
  cwd ??= await mkdtemp(join(tmpdir(), 'keysentry-review-')); if (!dirs.includes(cwd)) dirs.push(cwd);
  return createRuntime({ cwd, userDir: join(cwd, 'user'), vault: createFakeVault(), inflight: createFakeInFlight(),
    fingerprintKey: Buffer.alloc(32, 7), env: {}, http: new FakeHttp(), hosts: [], log: silentLogger,
    stdinIsTTY: true, stdoutIsTTY: true, ...extra });
}

async function loseStateKey(runtime: Awaited<ReturnType<typeof createRuntime>>) {
  const vault = createFakeVault(Object.fromEntries((runtime.vault as ReturnType<typeof createFakeVault>).dump()));
  for (const name of await vault.list()) if (name.endsWith('/key/state')) await vault.delete(name);
  return vault;
}

test('key loss allows a confirmed scan to rebuild inventory and monitor, preserving recovery files', async () => {
  const first = await fixture(); await first.scan();
  await first.store.writeJson('monitor', first.paths.monitor, createMonitorState());
  const plan = await first.plan();
  await first.store.journal().append({ at: new Date().toISOString(), planId: plan.id, event: 'plan-start' });
  const planPath = join(first.paths.plans, `${plan.id}.json`);
  const [journal, savedPlan] = await Promise.all([readFile(first.paths.journal), readFile(planPath)]);
  let confirmations = 0;
  // The state key is lost; the independent audit keys and project binding remain.
  const secondVault = await loseStateKey(first);
  const second = await fixture(first.config.cwd, { vault: secondVault, confirmInventoryReplacement: async () => { confirmations++; return true; } });
  await second.scan();
  expect(confirmations).toBe(1);
  expect(await second.store.loadInventory()).toMatchObject({ version: 1 });
  expect(await second.store.readJson('monitor', second.paths.monitor)).toEqual(createMonitorState());
  expect(await readFile(first.paths.journal)).toEqual(journal);
  expect(await readFile(planPath)).toEqual(savedPlan);
});

test.each([{ noninteractive: false }, { noninteractive: true }])('key loss keeps saved bytes when scan replacement is declined or noninteractive ($noninteractive)', async ({ noninteractive }) => {
  const first = await fixture(); await first.scan();
  const before = await readFile(first.paths.inventory); let confirmations = 0;
  const second = await fixture(first.config.cwd, { vault: await loseStateKey(first), stdinIsTTY: !noninteractive, stdoutIsTTY: !noninteractive,
    confirmInventoryReplacement: async () => { confirmations++; return false; } });
  await expect(second.scan()).rejects.toThrow(noninteractive ? /keysentry state reset/ : /cancelled/i);
  expect(confirmations).toBe(noninteractive ? 0 : 1);
  expect(await readFile(first.paths.inventory)).toEqual(before);
});

test('complete vault loss refuses scan before replacing state that the old audit key cannot authenticate', async () => {
  const first = await fixture(); await first.scan();
  const before = await readFile(first.paths.inventory);
  const second = await fixture(first.config.cwd, { confirmInventoryReplacement: async () => true });
  await expect(second.scan()).rejects.toThrow(/audit.*key|vault.*audit/i);
  expect(await readFile(first.paths.inventory)).toEqual(before);
});

// Same pending-action scenario as the reviewer's agent-dismiss probe.
test('a coding agent cannot dismiss a pending breach action through runtime or CLI', async () => {
  const runtime = await fixture(undefined, { env: { CLAUDE_CODE_CHILD_SESSION: '1' } });
  const state = createMonitorState();
  state.pendingActions.push({ id: 'a1', createdAt: '2026-10-27T12:00:00.000Z', signalId: 'canary-1', action: 'rotate', clusterIds: ['c1'], status: 'pending', highConfidence: true });
  await runtime.store.writeJson('monitor', runtime.paths.monitor, state);
  await expect(runtime.dismiss('a1')).rejects.toThrow(/AI coding agent/);
  expect(await runCli(['dismiss', 'a1'], { runtime, output: () => {}, error: () => {} })).toBe(1);
  expect((await runtime.pendingActions())[0]?.status).toBe('pending');
});

test('vault set --stdin accepts a human terminal pipe with non-TTY stdin', async () => {
  const runtime = await fixture(undefined, { stdinIsTTY: false, stdoutIsTTY: true });
  const input = new PassThrough(); input.end('opaque-piped-credential\n');
  expect(await runCli(['vault', 'set', 'GITHUB_TOKEN', '--stdin'], { runtime,
    promptIO: { input: input as unknown as NodeJS.ReadStream }, output: () => {}, error: () => {} })).toBe(0);
  expect((await runtime.vault.get('cred/GITHUB_TOKEN'))?.toString()).toBe('opaque-piped-credential');
});

test('memory-only rotation warns once before the confirmation callback', async () => {
  const runtime = await fixture(); const events: string[] = [];
  const plan = await runtime.plan();
  // An empty plan avoids provider side effects; confirmation ordering still uses an actual dry run.
  plan.steps.push({ clusterId: 'sealed:test', provider: 'unknown', tier: 'unknown', method: 'guided', hint: null, consumers: [] });
  runtime.loadPlan = async () => plan;
  expect(await runCli(['rotate', '--plan', plan.id, '--execute'], { runtime, output: () => {}, error: text => events.push(text),
    confirm: async () => { events.push('confirm'); return false; } })).toBe(0);
  const warnings = events.filter(text => text.includes('Your vault keeps rotation values in memory only;'));
  expect(warnings).toHaveLength(1);
  expect(events.indexOf(warnings[0]!)).toBeLessThan(events.indexOf('confirm'));
});

test('missing manifest requires explicit approval even with --yes and blocks direct runtime execution', async () => {
  vi.spyOn(release, 'checkLocalIntegrity').mockResolvedValue({ status: 'missing-manifest' });
  let confirmations = 0;
  const runtime = await fixture(undefined, { confirmMissingManifest: async () => { confirmations++; return false; } });
  const plan = await runtime.plan();
  const errors: string[] = [];
  expect(await runCli(['rotate', '--execute', '--yes'], { runtime, output: () => {}, error: text => errors.push(text) })).toBe(1);
  expect(confirmations).toBe(1);
  expect(errors.join('\n')).toMatch(/manifest/i);
  await expect(runtime.rotate(plan, { execute: true })).rejects.toThrow(/manifest/i);
});

test.each([{ command: 'create' }, { command: 'remove' }])('canary $command --execute requires missing-manifest approval', async ({ command }) => {
  vi.spyOn(release, 'checkLocalIntegrity').mockResolvedValue({ status: 'missing-manifest' });
  const runtime = await fixture(undefined, { confirmMissingManifest: async () => false });
  const operation = command === 'create'
    ? runtime.createCanary({ host: 'dotenv', service: 'app', execute: true })
    : runtime.removeCanary('canary-id', true);
  await expect(operation).rejects.toThrow(/manifest/i);
});
