import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { installHook, uninstallHook } from '../../src/guard/hook.js';
import type { GitRunner } from '../../src/guard/guard.js';

const SCRIPT = `#!/bin/sh
# keysentry pre-commit hook. Remove with: keysentry guard uninstall-hook
if command -v keysentry >/dev/null 2>&1; then
  exec keysentry guard --staged
else
  printf '%s\\n' 'keysentry is not installed; this commit was not checked.' >&2
  exit 0
fi
`;

function fakeGit(commonDir = '.git', hooksPath?: string): GitRunner {
  return async (args, opts) => {
    expect(opts.signal).toBeInstanceOf(AbortSignal);
    if (args.join(' ') === 'rev-parse --git-common-dir') {
      opts.onLine(commonDir);
      return { code: 0 };
    }
    if (args.join(' ') === 'config --path --get core.hooksPath') {
      if (hooksPath === undefined) return { code: 1 };
      opts.onLine(hooksPath);
      return { code: 0 };
    }
    throw new Error('Unexpected Git query');
  };
}

describe('pre-commit hook installation', () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'keysentry-hook-'));
    vi.stubEnv('PATH', root);
  });
  afterEach(async () => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
    await rm(root, { recursive: true, force: true });
  });

  it('installs fixed readable hook text without interpolating binPath', async () => {
    const result = await installHook(root, { binPath: '/private/user/$(touch bad); keysentry', git: fakeGit() });
    expect(result).toEqual({ path: join(root, '.git', 'hooks', 'pre-commit'), replaced: false, onPath: false });
    expect(await readFile(result.path, 'utf8')).toBe(SCRIPT);
    if (process.platform !== 'win32') {
      expect((await stat(result.path)).mode & 0o777).toBe(0o755);
      expect((await stat(dirname(result.path))).mode & 0o777).toBe(0o755);
    }
  });

  it('respects a relative core.hooksPath', async () => {
    const result = await installHook(root, { binPath: 'keysentry', git: fakeGit('.git', '.custom/hooks') });
    expect(result.path).toBe(join(root, '.custom', 'hooks', 'pre-commit'));
    expect(await readFile(result.path, 'utf8')).toBe(SCRIPT);
    await expect(lstat(join(root, '.git'))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('respects an absolute core.hooksPath', async () => {
    const configured = join(root, 'shared hooks');
    const result = await installHook(root, { binPath: 'keysentry', git: fakeGit('.git', configured) });
    expect(result.path).toBe(join(configured, 'pre-commit'));
  });

  it('uses the common Git directory for a linked worktree', async () => {
    const common = join(root, 'main', '.git');
    const worktree = join(root, 'linked');
    await mkdir(worktree);
    const result = await installHook(worktree, { binPath: 'keysentry', git: fakeGit('../main/.git') });
    expect(result.path).toBe(join(common, 'hooks', 'pre-commit'));
  });

  it('does not overwrite a foreign hook without force', async () => {
    const hook = join(root, '.git', 'hooks', 'pre-commit');
    await mkdir(dirname(hook), { recursive: true });
    await writeFile(hook, '#!/bin/sh\necho existing\n');
    await expect(installHook(root, { binPath: 'keysentry', git: fakeGit() })).rejects.toThrow(/existing.*hook|hook.*exists/i);
    expect(await readFile(hook, 'utf8')).toBe('#!/bin/sh\necho existing\n');
    await expect(lstat(`${hook}.keysentry-backup`)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('preserves a foreign hook on force and explains how to chain it', async () => {
    const hook = join(root, '.git', 'hooks', 'pre-commit');
    await mkdir(dirname(hook), { recursive: true });
    await writeFile(hook, '#!/bin/sh\necho existing\n', { mode: 0o751 });
    const warning = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const result = await installHook(root, { force: true, binPath: 'keysentry', git: fakeGit() });
    expect(result).toEqual({ path: hook, replaced: true, onPath: false });
    expect(await readFile(`${hook}.keysentry-backup`, 'utf8')).toBe('#!/bin/sh\necho existing\n');
    expect(await readFile(hook, 'utf8')).toBe(SCRIPT);
    expect(warning).toHaveBeenCalledWith(expect.stringMatching(/pre-commit\.keysentry-backup.*before.*keysentry|before.*keysentry.*pre-commit\.keysentry-backup/i));
  });

  it('never clobbers an earlier backup when forced', async () => {
    const hook = join(root, '.git', 'hooks', 'pre-commit');
    await mkdir(dirname(hook), { recursive: true });
    await writeFile(hook, 'current hook');
    await writeFile(`${hook}.keysentry-backup`, 'earlier hook');
    await expect(installHook(root, { force: true, binPath: 'keysentry', git: fakeGit() })).rejects.toThrow(/backup/i);
    expect(await readFile(hook, 'utf8')).toBe('current hook');
    expect(await readFile(`${hook}.keysentry-backup`, 'utf8')).toBe('earlier hook');
  });

  it('installs its own exact hook idempotently even with a preserved backup', async () => {
    const opts = { binPath: 'keysentry', git: fakeGit() };
    const first = await installHook(root, opts);
    await writeFile(`${first.path}.keysentry-backup`, 'preserved');
    expect(await installHook(root, opts)).toEqual({ path: first.path, replaced: false, onPath: false });
    expect(await readFile(`${first.path}.keysentry-backup`, 'utf8')).toBe('preserved');
  });

  it('refuses an existing hook symlink even with force', async () => {
    const hook = join(root, '.git', 'hooks', 'pre-commit');
    const target = join(root, 'target');
    await mkdir(dirname(hook), { recursive: true });
    await mkdir(target);
    await writeFile(join(target, 'kept'), 'unchanged');
    await symlink(resolve(target), hook, 'junction');
    await expect(installHook(root, { force: true, binPath: 'keysentry', git: fakeGit() })).rejects.toThrow(/symbolic link|symlink/i);
    expect((await lstat(hook)).isSymbolicLink()).toBe(true);
    expect(await readFile(join(target, 'kept'), 'utf8')).toBe('unchanged');
  });

  it('reports when keysentry can be resolved on PATH, including an idempotent install', async () => {
    const executable = join(root, process.platform === 'win32' ? 'keysentry.exe' : 'keysentry');
    await writeFile(executable, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    const opts = { binPath: 'an-unrelated-binary', git: fakeGit() };
    expect(await installHook(root, opts)).toMatchObject({ onPath: true });
    await rm(executable);
    expect(await installHook(root, opts)).toMatchObject({ onPath: false });
  });

  it('does not mistake a cmd-only wrapper for the command used by the POSIX hook', async () => {
    await writeFile(join(root, 'keysentry.cmd'), '@echo off\r\nexit /b 0\r\n');
    vi.stubEnv('PATHEXT', '.COM;.EXE;.BAT;.CMD');
    expect(await installHook(root, { binPath: 'keysentry', git: fakeGit() })).toMatchObject({ onPath: false });
  });

  it('does not treat a directory or a non-executable file as a PATH command', async () => {
    await mkdir(join(root, 'keysentry'));
    const opts = { binPath: 'keysentry', git: fakeGit() };
    expect(await installHook(root, opts)).toMatchObject({ onPath: false });
    if (process.platform !== 'win32') {
      await rm(join(root, 'keysentry'), { recursive: true });
      await writeFile(join(root, 'keysentry'), '#!/bin/sh\nexit 0\n', { mode: 0o600 });
      expect(await installHook(root, opts)).toMatchObject({ onPath: false });
    }
  });

  it.skipIf(process.platform === 'win32')('preserves existing hooks-directory modes for new, repeated and forced installs', async () => {
    const configured = join(root, 'shared-hooks');
    await mkdir(configured);
    await chmod(configured, 0o700);
    const opts = { binPath: 'keysentry', git: fakeGit('.git', configured) };
    const first = await installHook(root, opts);
    expect((await stat(configured)).mode & 0o777).toBe(0o700);
    await installHook(root, opts);
    expect((await stat(configured)).mode & 0o777).toBe(0o700);
    await writeFile(first.path, '#!/bin/sh\nexit 0\n');
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    await installHook(root, { ...opts, force: true });
    expect((await stat(configured)).mode & 0o777).toBe(0o700);
  });

  it('refuses an existing backup symlink without changing the hook', async () => {
    const hook = join(root, '.git', 'hooks', 'pre-commit');
    const target = join(root, 'target');
    await mkdir(dirname(hook), { recursive: true });
    await mkdir(target);
    await writeFile(hook, 'existing');
    await symlink(resolve(target), `${hook}.keysentry-backup`, 'junction');
    await expect(installHook(root, { force: true, binPath: 'keysentry', git: fakeGit() })).rejects.toThrow(/backup/i);
    expect(await readFile(hook, 'utf8')).toBe('existing');
    expect((await lstat(`${hook}.keysentry-backup`)).isSymbolicLink()).toBe(true);
  });

  it('fails without writing when Git cannot identify a repository', async () => {
    const git: GitRunner = async () => ({ code: 128 });
    await expect(installHook(root, { binPath: 'keysentry', git })).rejects.toThrow(/Git|repository/i);
    await expect(lstat(join(root, '.git'))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('does not fall back to the default directory on a config query error', async () => {
    const git: GitRunner = async (args, opts) => {
      if (args[0] === 'rev-parse') {
        opts.onLine('.git');
        return { code: 0 };
      }
      return { code: 128 };
    };
    await expect(installHook(root, { binPath: 'keysentry', git })).rejects.toThrow(/Git|configuration/i);
    await expect(lstat(join(root, '.git'))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('uninstalls only its exact script and keeps the backup', async () => {
    const git = fakeGit('.git', '.custom');
    const result = await installHook(root, { binPath: 'keysentry', git });
    await writeFile(`${result.path}.keysentry-backup`, 'preserved');
    await uninstallHook(root, git);
    await expect(lstat(result.path)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(await readFile(`${result.path}.keysentry-backup`, 'utf8')).toBe('preserved');
    await uninstallHook(root, git);
  });

  it('leaves foreign and modified keysentry hooks alone on uninstall', async () => {
    const hook = join(root, '.git', 'hooks', 'pre-commit');
    await mkdir(dirname(hook), { recursive: true });
    for (const script of ['#!/bin/sh\necho foreign\n', `${SCRIPT}echo custom\n`]) {
      await writeFile(hook, script);
      await uninstallHook(root, fakeGit());
      expect(await readFile(hook, 'utf8')).toBe(script);
    }
  });

  it('leaves a hook symlink alone on uninstall', async () => {
    const hook = join(root, '.git', 'hooks', 'pre-commit');
    const target = join(root, 'target');
    await mkdir(dirname(hook), { recursive: true });
    await mkdir(target);
    await symlink(resolve(target), hook, 'junction');
    await uninstallHook(root, fakeGit());
    expect((await lstat(hook)).isSymbolicLink()).toBe(true);
  });
});
