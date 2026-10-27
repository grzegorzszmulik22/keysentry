import { afterEach, expect, test, vi } from 'vitest';
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCli } from '../../src/cli/index.js';
import { createRuntime } from '../../src/cli/runtime.js';
import type { GitRunner } from '../../src/firstrun/index.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';
import { openDashboardBrowser } from '../../src/cli/phase3.js';
import type { DashboardOptions } from '../../src/dashboard/server/index.js';

const dashboard = vi.hoisted(() => ({ options: [] as DashboardOptions[] }));
const browser = vi.hoisted(() => ({ calls: [] as { command: string; args: string[]; options: { env: NodeJS.ProcessEnv; shell: boolean } }[] }));
vi.mock('../../src/dashboard/server/index.js', () => ({
  startDashboard: async (options: DashboardOptions) => {
    dashboard.options.push(options);
    return { url: `http://localhost:34567/?t=${'a'.repeat(43)}`, port: 34567, async close() {} };
  },
}));
vi.mock('node:child_process', async importOriginal => ({
  ...await importOriginal<typeof import('node:child_process')>(),
  execFile: (command: string, args: string[], options: { env: NodeJS.ProcessEnv; shell: boolean }, callback: (error: Error | null) => void) => {
    browser.calls.push({ command, args, options }); callback(null);
  },
}));

const dirs: string[] = [];
afterEach(async () => {
  vi.useRealTimers(); vi.unstubAllEnvs();
  dashboard.options.length = 0; browser.calls.length = 0;
  for (const cwd of dirs.splice(0)) await rm(cwd, { recursive: true, force: true });
});
async function directory() { const cwd = await mkdtemp(join(tmpdir(), 'keysentry-phase3-commands-')); dirs.push(cwd); return cwd; }
const noHistory: GitRunner = async () => ({ code: 0 });
function capture() {
  const output: string[] = [], errors: string[] = [];
  return { output, errors, options: { output: (line: string) => output.push(line), error: (line: string) => errors.push(line), env: {}, firstRunGit: noHistory, guardGit: noHistory } };
}
async function fixture() {
  const cwd = await directory(), io = capture();
  const runtime = await createRuntime({ cwd, userDir: join(cwd, 'user'), vault: createFakeVault(), hosts: [], env: {}, http: new FakeHttp(), log: silentLogger, stdinIsTTY: true, stdoutIsTTY: true });
  return { cwd, runtime, ...io, options: { ...io.options, runtime, stdinIsTTY: true, stdoutIsTTY: true } };
}

test('phase 3 command groups are listed in help', async () => {
  const c = capture();
  expect(await runCli(['--help'], c.options)).toBe(0);
  for (const command of ['ui', 'guard', 'digest', 'card', 'timeline', 'hygiene', 'spend-limits']) expect(c.output.join('\n')).toContain(command);
});

test('no-command --no-save scans without a vault, state or network', async () => {
  const cwd = await directory(), c = capture();
  const value = `sk-or-v1-${'a'.repeat(64)}`;
  await writeFile(join(cwd, '.env'), `OPENROUTER_API_KEY=${value}\n`);
  expect(await runCli(['--cwd', cwd, '--no-save', '--json'], c.options)).toBe(0);
  expect(JSON.parse(c.output.join('\n')).findings).toHaveLength(1);
  expect(c.output.join('\n')).not.toContain(value);
  expect(await readdir(cwd)).toEqual(['.env']);
  expect(c.errors).toEqual([]);
});

test('first run never prompts to save in a noninteractive terminal', async () => {
  const cwd = await directory(), c = capture();
  expect(await runCli(['--cwd', cwd], { ...c.options, stdinIsTTY: false, stdoutIsTTY: false })).toBe(0);
  expect(c.output.join('\n')).toContain('Scanned');
  expect(await readdir(cwd)).toEqual([]);
});

test('bare invocation scans the supplied project rather than showing help', async () => {
  const cwd = await directory(), c = capture();
  expect(await runCli([], { ...c.options, cwd, stdinIsTTY: false, stdoutIsTTY: false })).toBe(0);
  expect(c.output.join('\n')).toContain('Scanned');
  expect(c.output.join('\n')).not.toContain('Usage:');
});

test('interactive first run shows its summary before saving and offers the dashboard afterward', async () => {
  const c = await fixture();
  let consent = false, offered = false;
  expect(await runCli([], { ...c.options,
    confirmFirstRunSave: async () => { expect(c.output.join('\n')).toContain('Scanned'); consent = true; return true; },
    confirmDashboard: async () => { expect(consent).toBe(true); offered = true; return true; },
    openBrowser: async () => {},
  })).toBe(0);
  expect(consent).toBe(true);
  expect(offered).toBe(true);
  expect(c.output.filter(line => line.includes('Scanned'))).toHaveLength(1);
  expect(dashboard.options).toHaveLength(1);
});

test('no-save skips both save and dashboard offers even in an interactive terminal', async () => {
  const cwd = await directory(), c = capture();
  const confirm = vi.fn(async () => true);
  expect(await runCli(['--no-save'], { ...c.options, cwd, stdinIsTTY: true, stdoutIsTTY: true,
    confirmFirstRunSave: confirm, confirmDashboard: confirm })).toBe(0);
  expect(confirm).not.toHaveBeenCalled();
  expect(dashboard.options).toEqual([]);
  expect(await readdir(cwd)).toEqual([]);
});

test('guard --staged prints the guard formatter and its blocked exit status', async () => {
  const cwd = await directory(), c = capture();
  const value = `sk-or-v1-${'b'.repeat(64)}`;
  const guardGit: GitRunner = async (_args, opts) => {
    for (const line of ['diff --git a/.env b/.env', '--- a/.env', '+++ b/.env', '@@ -0,0 +1 @@', `+OPENROUTER_API_KEY=${value}`]) opts.onLine(line);
    return { code: 0 };
  };
  expect(await runCli(['--cwd', cwd, 'guard', '--staged'], { ...c.options, guardGit })).toBe(1);
  expect(c.output.join('\n')).toContain('Commit stopped: 1 secret would be committed.');
  expect(c.output.join('\n')).toContain('.env:1');
  expect(c.output.join('\n')).not.toContain(value);
});

test('clean staged guard returns zero without output', async () => {
  const cwd = await directory(), c = capture();
  expect(await runCli(['--cwd', cwd, 'guard', '--staged'], c.options)).toBe(0);
  expect(c.output).toEqual([]);
  expect(await readdir(cwd)).toEqual([]);
});

test('plain guard skips history while --history includes it', async () => {
  const cwd = await directory(), c = capture();
  const git = vi.fn(noHistory);
  expect(await runCli(['--cwd', cwd, 'guard'], { ...c.options, firstRunGit: git })).toBe(0);
  expect(git).not.toHaveBeenCalled();
  expect(c.output.join('\n')).toContain('working tree');
  expect(await runCli(['--cwd', cwd, 'guard', '--history'], { ...c.options, firstRunGit: git })).toBe(0);
  expect(git).toHaveBeenCalled();
});

test('hook installation warns when keysentry cannot be found on PATH', async () => {
  const c = await fixture();
  vi.stubEnv('PATH', '');
  const guardGit: GitRunner = async (args, opts) => {
    if (args[0] === 'config') return { code: 1 };
    opts.onLine('.git'); return { code: 0 };
  };
  expect(await runCli(['guard', 'install-hook'], { ...c.options, guardGit })).toBe(0);
  expect(c.errors).toContain('The hook calls keysentry from your PATH; install it with npm install -g keysentry so commits are checked.');
  expect(await readFile(join(c.cwd, '.git', 'hooks', 'pre-commit'), 'utf8')).toContain('guard --staged');
});

test('new mutations refuse an agent before changing state or writing files', async () => {
  const cwd = await directory(), c = capture();
  for (const args of [['guard', 'install-hook'], ['guard', 'uninstall-hook'], ['digest', '--send'], ['spend-limits', '--apply'], ['card', '--out', 'card.svg'], ['timeline', 'plan-one', '--out', 'timeline.md']]) {
    c.errors.length = 0;
    expect(await runCli(['--cwd', cwd, ...args], { ...c.options, env: { CODEX_THREAD_ID: 'present' } })).toBe(1);
    expect(c.errors.join('\n')).toMatch(/coding agent/);
  }
  expect(await readdir(cwd)).toEqual([]);
});

test('hygiene and spend preview call the shared phase 3 runtime without changes', async () => {
  const c = await fixture();
  expect(await runCli(['hygiene', '--json'], c.options)).toBe(0);
  expect(JSON.parse(c.output.at(-1)!)).toEqual([]);
  c.output.length = 0;
  expect(await runCli(['spend-limits', '--json'], c.options)).toBe(0);
  expect(c.errors).toEqual([]);
});

test('a CLI rotation preview writes only its previewed action to the audit', async () => {
  const c = await fixture(); await c.runtime.scan();
  const before = (await readFile(c.runtime.paths.audit, 'utf8')).trim().split('\n').length;
  expect(await runCli(['rotate'], c.options)).toBe(0);
  const events = (await readFile(c.runtime.paths.audit, 'utf8')).trim().split('\n').slice(before).map(line => JSON.parse(line));
  expect(events.filter(event => event.kind !== 'checkpoint').map(event => event.kind)).toEqual(['previewed']);
});

test('card output is a standalone SVG and writing refuses an existing file', async () => {
  const c = await fixture();
  expect(await runCli(['card', '--out', 'readiness.svg'], c.options)).toBe(0);
  const original = await readFile(join(c.cwd, 'readiness.svg'), 'utf8');
  expect(original).toContain('<svg');
  expect(original).not.toMatch(/script|foreignObject/);
  expect(await runCli(['card', '--out', 'readiness.svg'], c.options)).toBe(1);
  expect(await readFile(join(c.cwd, 'readiness.svg'), 'utf8')).toBe(original);
});

test('digest prints a calm message in the terminal rather than a data record', async () => {
  const c = await fixture();
  expect(await runCli(['digest'], c.options)).toBe(0);
  expect(c.output.join('\n')).toContain('Nothing needed your attention this week.');
  expect(c.output.join('\n')).not.toMatch(/^\s*\{/);
});

test('timeline creates the same Markdown returned by the shared runtime', async () => {
  const c = await fixture(), id = 'plan-20261027120000-abcd';
  await c.runtime.store.journal().append({ at: '2026-10-27T12:00:00Z', planId: id, event: 'plan-start' });
  await c.runtime.checkpoint();
  expect(await runCli(['timeline', id, '--out', 'timeline.md'], c.options)).toBe(0);
  expect(await readFile(join(c.cwd, 'timeline.md'), 'utf8')).toContain('# Incident timeline');
});

test.each([{}, { CODEX_THREAD_ID: 'present' }])('ui uses persistent passkeys and automatically browses read-only for agent markers: %j', async env => {
  const c = await fixture(), opened: string[] = [];
  expect(await runCli(['ui'], { ...c.options, env, openBrowser: async url => { opened.push(url); } })).toBe(0);
  expect(dashboard.options).toHaveLength(1);
  expect(dashboard.options[0]!.readOnly).toBe(!!env.CODEX_THREAD_ID);
  expect(dashboard.options[0]!.passkeys).toBeDefined();
  expect(opened).toHaveLength(1);
  const html = await readFile(opened[0]!, 'utf8');
  expect(html).toContain(`http://localhost:34567/?t=${'a'.repeat(43)}`);
  expect(html).toContain('http-equiv="refresh"');
  expect(html).toContain('<a href=');
  expect(c.output.join('\n')).not.toContain('a'.repeat(43));
  expect(c.output.join('\n')).toContain(opened[0]);
  if (process.platform !== 'win32') expect((await stat(opened[0]!)).mode & 0o777).toBe(0o600);
});

test('ui removes the launcher after token use and logs only the failure class', async () => {
  const c = await fixture(); let path = '';
  expect(await runCli(['ui'], { ...c.options, openBrowser: async value => { path = value; } })).toBe(0);
  const options = dashboard.options[0] as DashboardOptions & { onTokenUsed(): Promise<void>; onError(errorClass: string): void };
  options.onError('TypeError');
  expect(c.errors).toContain('Dashboard request failed: TypeError');
  await options.onTokenUsed();
  await expect(stat(path)).rejects.toMatchObject({ code: 'ENOENT' });
});

test('ui expires the private launcher after two minutes and keeps its token out of JSON and argv', async () => {
  const c = await fixture();
  vi.useFakeTimers();
  expect(await runCli(['ui', '--json'], c.options)).toBe(0);
  const output = JSON.parse(c.output.at(-1)!) as { path: string; port: number };
  expect(output.path).toContain('dashboard-');
  expect(await readFile(output.path, 'utf8')).toContain('a'.repeat(43));
  expect(c.output.join('\n') + JSON.stringify(browser.calls)).not.toContain('a'.repeat(43));
  await vi.advanceTimersByTimeAsync(120_000);
  vi.useRealTimers();
  await vi.waitFor(async () => { await expect(stat(output.path)).rejects.toMatchObject({ code: 'ENOENT' }); });
});

test('ui prints a URL only when explicitly requested at an interactive terminal', async () => {
  const c = await fixture();
  expect(await runCli(['ui', '--print-url'], { ...c.options, openBrowser: async () => {} })).toBe(0);
  expect(c.output.join('\n')).toContain('a'.repeat(43));
  c.output.length = 0;
  expect(await runCli(['ui', '--print-url'], { ...c.options, stdinIsTTY: false, stdoutIsTTY: false })).toBe(1);
  expect(c.output.join('\n')).not.toContain('a'.repeat(43));
});

test('ui --read-only keeps the explicit choice in a normal terminal', async () => {
  const c = await fixture();
  expect(await runCli(['ui', '--read-only'], { ...c.options, openBrowser: async () => {} })).toBe(0);
  expect(dashboard.options[0]!.readOnly).toBe(true);
});

test('dashboard browser opener rejects foreign or altered addresses before starting a child', async () => {
  for (const url of ['https://example.test/', `http://localhost:34567/?t=${'a'.repeat(43)}&extra=1`, `http://localhost:34567/path?t=${'a'.repeat(43)}`]) {
    expect(await openDashboardBrowser(url, {})).toBe(false);
  }
  expect(browser.calls).toEqual([]);
});

test('dashboard browser opener uses a fixed executable, no shell and no credential environment', async () => {
  const path = join(await directory(), 'dashboard.html');
  await writeFile(path, '<!doctype html>');
  expect(await openDashboardBrowser(path, { OPENAI_API_KEY: 'never-a-child-secret', PATH: 'untrusted', BROWSER: 'untrusted', SystemRoot: 'C:\\Windows', HOME: '/home/example' })).toBe(true);
  expect(browser.calls).toHaveLength(1);
  expect(browser.calls[0]!.options.shell).toBe(false);
  expect(browser.calls[0]!.args).toContain(path);
  expect(JSON.stringify(browser.calls)).not.toMatch(/never-a-child-secret|untrusted/);
});

