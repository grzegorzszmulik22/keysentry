import { afterEach, expect, test, vi } from 'vitest';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { runCli } from '../../src/cli/index.js';
import type { GitRunner } from '../../src/firstrun/index.js';

const roots: string[] = [];
afterEach(async () => { vi.restoreAllMocks(); for (const cwd of roots.splice(0)) await rm(cwd, { recursive: true, force: true }); });

async function snapshot(directory: string, base = directory): Promise<Record<string, string>> {
  const result: Record<string, string> = {};
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) Object.assign(result, await snapshot(path, base));
    else result[relative(base, path)] = (await readFile(path)).toString('base64');
  }
  return result;
}

// No Git executable is invoked by this suite. Recorded Git output exercises the actual history parser.
async function fixture() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-first-run-e2e-')); roots.push(cwd);
  const live = 'sk-proj-LiveKey0123456789abcdefghijklmnop';
  const removed = 're_HistoryOnly0123456789abcdefghijklmnop';
  await mkdir(join(cwd, '.git'));
  await writeFile(join(cwd, '.git', 'HEAD'), `ref: refs/heads/main\n`);
  await writeFile(join(cwd, '.env'), `OPENAI_API_KEY=${live}\nPORT=3000\n`);
  await writeFile(join(cwd, 'fly.toml'), 'app = "sample"\n');
  const log = [`\x00${'a'.repeat(40)}\x002026-10-20T12:00:00Z`,
    'diff --git a/.env b/.env', '+++ b/.env', '@@ -0,0 +1,2 @@',
    `+OPENAI_API_KEY=${live}`, `+RESEND_API_KEY=${removed}`].join('\n');
  await writeFile(join(cwd, '.git', 'recorded-history.patch'), log);
  const git: GitRunner = async (_args, { cwd: root, onLine }) => {
    for (const line of (await readFile(join(root, '.git', 'recorded-history.patch'), 'utf8')).split('\n')) onLine(line);
    return { code: 0 };
  };
  return { cwd, live, removed, git };
}

test('CLI no-save first run scans local and recorded committed keys under a minute without network or writes', async () => {
  const { cwd, live, removed, git } = await fixture();
  const before = await snapshot(cwd);
  const output: string[] = []; const errors: string[] = [];
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(() => { throw new Error('Unexpected network access.'); });
  const started = performance.now();
  const code = await runCli(['--no-save'], { cwd, firstRunGit: git, env: {}, stdinIsTTY: false, stdoutIsTTY: false,
    output: line => output.push(line), error: line => errors.push(line) });
  expect(code).toBe(0);
  expect(performance.now() - started).toBeLessThan(60_000);
  expect(output.join('\n')).toContain('2 keys');
  expect(output.join('\n')).toContain('git history');
  expect(output.join('\n')).toContain('Fly.io');
  expect(output.join('\n')).not.toContain(live);
  expect(output.join('\n')).not.toContain(removed);
  expect(errors).toEqual([]);
  expect(fetch).not.toHaveBeenCalled();
  expect(await snapshot(cwd)).toEqual(before);
});

test('default first run needs no credentials and preserves history-only findings in JSON', async () => {
  const { cwd, live, removed, git } = await fixture();
  const before = await snapshot(cwd);
  const output: string[] = [];
  expect(await runCli(['--json'], { cwd, firstRunGit: git, env: {}, stdinIsTTY: false, stdoutIsTTY: false,
    output: line => output.push(line), error: () => {} })).toBe(0);
  const result = JSON.parse(output.join('')) as { findings: { provider: string; inGitHistory: boolean; locations: { stillPresent: boolean }[] }[] };
  expect(result.findings).toHaveLength(2);
  const historic = result.findings.find(finding => finding.provider === 'resend')!;
  expect(historic.inGitHistory).toBe(true);
  expect(historic.locations.every(location => !location.stillPresent)).toBe(true);
  expect(output.join('')).not.toContain(live);
  expect(output.join('')).not.toContain(removed);
  expect(await snapshot(cwd)).toEqual(before);
});
