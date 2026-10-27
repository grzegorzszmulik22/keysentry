import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import { installHook } from '../../src/guard/hook.js';

// Opt in only outside the sandbox. No child process is started while skipped.
describe.skipIf(process.env.KEYSENTRY_TEST_REAL_GIT !== '1')('real Git pre-commit integration', () => {
  it('blocks commit -a, explicit paths and --include using the actual hook index, even for binary attributes', async (ctx) => {
    const env: NodeJS.ProcessEnv = { GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' };
    for (const name of ['PATH', 'SystemRoot', 'HOME', 'USERPROFILE']) {
      const entry = Object.entries(process.env).find(([key]) => key.toLowerCase() === name.toLowerCase());
      if (entry) env[name] = entry[1];
    }
    let cwd = resolve('.');
    const git = (args: string[]) => new Promise<{ code: number; stdout: string; stderr: string }>((fulfil, reject) => {
      execFile('git', ['-c', 'user.name=keysentry regression', '-c', 'user.email=test@example.invalid',
        '-c', 'commit.gpgsign=false', ...args], { cwd, env, windowsHide: true, timeout: 20_000 }, (error, stdout, stderr) => {
        if (error && typeof error.code !== 'number') reject(error);
        else fulfil({ code: error?.code ?? 0, stdout, stderr });
      });
    });
    try {
      expect((await git(['version'])).code).toBe(0);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') { ctx.skip(); return; }
      throw error;
    }
    const repo = cwd;
    cwd = await mkdtemp(join(tmpdir(), 'keysentry-real-index-'));
    try {
      env.GIT_CONFIG_GLOBAL = join(cwd, 'empty-gitconfig');
      await writeFile(env.GIT_CONFIG_GLOBAL, '');
      expect((await git(['init', '--quiet'])).code).toBe(0);
      expect((await git(['config', 'core.hooksPath', '.git/hooks'])).code).toBe(0);
      await writeFile(join(cwd, 'tracked.env'), 'PORT=3000\n');
      await writeFile(join(cwd, '.gitattributes'), 'tracked.env binary\n');
      expect((await git(['add', '--', 'tracked.env', '.gitattributes'])).code).toBe(0);
      expect((await git(['-c', 'core.hooksPath=/dev/null', 'commit', '--quiet', '-m', 'base'])).code).toBe(0);
      const head = (await git(['rev-parse', 'HEAD'])).stdout.trim();

      const bin = join(cwd, 'bin');
      await mkdir(bin);
      const runner = join(bin, 'check.mjs');
      await writeFile(runner, `import { guardStaged } from ${JSON.stringify(pathToFileURL(join(repo, 'src/guard/guard.ts')).href)};
try {
  const result = await guardStaged(process.cwd());
  if (result.blocked.length) { console.error('Staged key needs review.'); process.exitCode = 1; }
} catch { console.error('The staged check could not finish.'); process.exitCode = 2; }
`);
      const quote = (value: string) => "'" + value.replaceAll('\\', '/').replaceAll("'", "'\\''") + "'";
      const loader = pathToFileURL(join(repo, 'node_modules/tsx/dist/loader.mjs')).href;
      await writeFile(join(bin, 'keysentry'), `#!/bin/sh\nexec ${quote(process.execPath)} --import ${quote(loader)} ${quote(runner)} "$@"\n`, { mode: 0o755 });
      env.PATH = bin + delimiter + (env.PATH ?? '');
      await installHook(cwd, { binPath: 'keysentry', git: async (args, opts) => {
        const result = await git(args);
        for (const line of result.stdout.trimEnd().split('\n')) if (line) opts.onLine(line.replace(/\r$/, ''));
        return { code: result.code };
      } });
      const key = 'sk-proj-RealGitRegression0123456789abcdef';
      await writeFile(join(cwd, 'tracked.env'), `OPENAI_API_KEY=${key}\n`);
      for (const args of [
        ['commit', '-am', 'must stop'],
        ['commit', '-m', 'must stop', '--', 'tracked.env'],
        ['commit', '--include', '-m', 'must stop', '--', 'tracked.env'],
      ]) {
        // A failed --include attempt can leave index changes behind. Start each
        // case with a clean real index and keep the secret only in the worktree.
        expect((await git(['reset', '--mixed', '--quiet', 'HEAD'])).code).toBe(0);
        expect((await git(['diff', '--cached', '--quiet'])).code).toBe(0);
        const result = await git(args);
        expect(result.code).toBe(1);
        expect(result.stderr).toContain('Staged key needs review.');
        expect(result.stdout + result.stderr).not.toContain(key);
        expect((await git(['rev-parse', 'HEAD'])).stdout.trim()).toBe(head);
      }
    } finally { await rm(cwd, { recursive: true, force: true }); }
  });
});
