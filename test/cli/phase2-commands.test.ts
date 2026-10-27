import { afterEach, expect, test } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRuntime, runCli } from '../../src/cli/index.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';
import { configureApprovalRelay } from '../../src/cli/phase2.js';
import { loadConfigMetadata } from '../../src/cli/config.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
async function context() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-phase2-commands-')); dirs.push(cwd);
  const runtime = await createRuntime({ cwd, userDir: join(cwd, 'user'), vault: createFakeVault(), hosts: [], env: {}, http: new FakeHttp(), log: silentLogger, stdinIsTTY: true, stdoutIsTTY: true });
  const output: string[] = []; const errors: string[] = [];
  return { runtime, output, errors, options: { runtime, env: {}, stdinIsTTY: true, stdoutIsTTY: true, output: (line: string) => output.push(line), error: (line: string) => errors.push(line) } };
}

test('new command groups are exposed in top-level help', async () => {
  const c = await context();
  expect(await runCli(['--help'], c.options)).toBe(0);
  for (const name of ['arm', 'disarm', 'autopilot', 'watch', 'watcher', 'notify', 'passkey']) expect(c.output.join('\n')).toContain(name);
});

test('arm reaches the recent drill gate and refuses remote policy widening', async () => {
  const c = await context();
  expect(await runCli(['arm'], c.options)).toBe(1);
  expect(c.errors.join('\n')).toMatch(/drill.*24 hours/);
  c.errors.length = 0;
  expect(await runCli(['arm', '--relay'], c.options)).toBe(1);
  expect(c.errors.join('\n')).toMatch(/local/);
});

test('disarm and status use the same encrypted local state', async () => {
  const c = await context();
  expect(await runCli(['disarm'], c.options)).toBe(0);
  expect(c.output.join('\n')).toMatch(/disarmed/i);
  c.output.length = 0;
  expect(await runCli(['autopilot', 'status', '--json'], c.options)).toBe(0);
  expect(JSON.parse(c.output.join('\n')).disarmed).toBe(true);
});

test('new local-only mutations refuse coding-agent environments before work', async () => {
  const c = await context();
  for (const args of [['arm'], ['disarm'], ['notify', 'add', 'console'], ['notify', 'remove', 'one'], ['passkey', 'register'], ['passkey', 'remove', 'one'], ['watcher', 'setup']]) {
    c.errors.length = 0;
    expect(await runCli(args, { ...c.options, env: { CODEX_THREAD_ID: 'present' } })).toBe(1);
    expect(c.errors.join('\n')).toMatch(/agent|human|terminal/i);
  }
});

test('local watcher setup creates its relay topic privately and saves only the server in YAML', async () => {
  const c = await context();
  await configureApprovalRelay(c.runtime, 'https://relay.example.test');
  const topic = await c.runtime.vault.get('notify/relay/topic');
  expect(topic?.toString()).toMatch(/^[A-Z2-7]{32}$/);
  expect((await loadConfigMetadata({ cwd: c.runtime.config.cwd, env: {} })).settings.notify.relay).toEqual({ server: 'https://relay.example.test' });
  const before = topic?.toString();
  await configureApprovalRelay(c.runtime, 'https://relay.example.test');
  expect((await c.runtime.vault.get('notify/relay/topic'))?.toString()).toBe(before);
});

test('watcher setup JSON refusal cannot export deploy secrets or change relay settings', async () => {
  const c = await context();
  expect(await runCli(['watcher', 'setup', '--relay-server', 'https://relay.example.test', '--json'], c.options)).toBe(1);
  expect(c.output).toEqual([]);
  expect(await c.runtime.vault.get('notify/relay/topic')).toBeNull();
});

test('public-origin passkey registration explains the dashboard limit and notify list has metadata only', async () => {
  const c = await context();
  expect(await runCli(['passkey', 'register', '--origin', 'https://watcher.example.test', '--json'], c.options)).toBe(0);
  expect(c.output.join('\n')).toContain('phase 3');
  c.output.length = 0;
  expect(await runCli(['notify', 'list', '--json'], c.options)).toBe(0);
  expect(JSON.parse(c.output.join('\n'))).toEqual([]);
});
