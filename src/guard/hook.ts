import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { access, chmod, link, lstat, mkdir, open, readFile, stat, unlink } from 'node:fs/promises';
import { delimiter, dirname, join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import type { GitRunner } from './guard.js';

// Deliberately independent of binPath: no user-controlled text is shell code.
const HOOK = `#!/bin/sh
# keysentry pre-commit hook. Remove with: keysentry guard uninstall-hook
if command -v keysentry >/dev/null 2>&1; then
  exec keysentry guard --staged
else
  printf '%s\\n' 'keysentry is not installed; this commit was not checked.' >&2
  exit 0
fi
`;

/**
 * Configuration queries must see the real core.hooksPath. The staged-diff runner
 * disables hooks using a command-line override, so it cannot be reused here.
 */
const queryGit: GitRunner = async (args, opts) => {
  const env: NodeJS.ProcessEnv = {
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_TERMINAL_PROMPT: '0',
    GIT_PAGER: 'cat',
    GIT_OPTIONAL_LOCKS: '0',
    LC_ALL: 'C',
  };
  for (const name of ['PATH', 'SystemRoot', 'HOME', 'USERPROFILE']) {
    const entry = Object.entries(process.env).find(([key]) => key.toLowerCase() === name.toLowerCase());
    if (entry) env[name] = entry[1];
  }
  return new Promise((resolveResult, reject) => {
    const child = spawn('git', ['-c', 'diff.external=', '-c', 'core.fsmonitor=false', ...args], {
      cwd: opts.cwd,
      env,
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'ignore'],
      signal: opts.signal,
    });
    let bytes = 0;
    let oversized = false;
    let failed = false;
    const fail = () => {
      if (failed) return;
      failed = true;
      child.kill();
      reject(new Error('Git configuration could not be read.'));
    };
    child.stdout.once('error', fail);
    child.stdout.on('data', (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > 32_768) {
        oversized = true;
        child.kill();
      }
    });
    const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
    lines.once('error', fail);
    lines.on('line', (line) => {
      if (!oversized) opts.onLine(line);
    });
    child.once('error', fail);
    child.once('close', (code) => {
      lines.close();
      if (oversized) reject(new Error('Git configuration output was too large.'));
      else if (code === null) reject(new Error('Git configuration query did not complete.'));
      else resolveResult({ code });
    });
  });
};

async function query(root: string, git: GitRunner, args: string[]): Promise<{ code: number; value: string }> {
  const lines: string[] = [];
  let invalid = false;
  let result: { code: number };
  try {
    result = await git(args, {
      cwd: root,
      signal: AbortSignal.timeout(5_000),
      onLine(line) {
        if (lines.length > 0 || line.length > 32_768 || /[\r\n\0]/.test(line)) invalid = true;
        else lines.push(line);
      },
    });
  } catch {
    throw new Error('Git configuration could not be read.');
  }
  if (invalid) throw new Error('Git returned an unsupported hooks path.');
  return { code: result.code, value: lines[0] ?? '' };
}

async function hookPath(root: string, git: GitRunner): Promise<string> {
  const cwd = resolve(root);
  const common = await query(cwd, git, ['rev-parse', '--git-common-dir']);
  if (common.code !== 0 || !common.value) throw new Error('Git could not identify the repository directory.');
  const configured = await query(cwd, git, ['config', '--path', '--get', 'core.hooksPath']);
  if (configured.code === 0) {
    if (!configured.value) throw new Error('Git returned an empty hooks path.');
    return join(resolve(cwd, configured.value), 'pre-commit');
  }
  if (configured.code !== 1) throw new Error('Git hooks configuration could not be read.');
  return join(resolve(cwd, common.value), 'hooks', 'pre-commit');
}

async function existing(path: string) {
  try {
    return await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
}

async function isOwnHook(path: string, size: number): Promise<boolean> {
  return size === Buffer.byteLength(HOOK) && await readFile(path, 'utf8') === HOOK;
}

/** Check the executable lookup without running a command or shell. */
// null: the Node permission model kept keysentry from looking outside its grants, so the answer is unknown.
async function keysentryOnPath(root: string): Promise<boolean | null> {
  const pathEntry = Object.entries(process.env).find(([name]) => name.toLowerCase() === 'path');
  if (pathEntry?.[1] === undefined) return false;
  // The fixed hook uses POSIX sh, including Git for Windows. Its lookup does
  // not use cmd.exe's PATHEXT expansion for .cmd/.bat wrappers.
  const extensions = process.platform === 'win32' ? ['', '.exe'] : [''];
  let unknown = false;
  for (const entry of pathEntry[1].split(delimiter)) {
    const directory = process.platform === 'win32' ? entry.replace(/^"(.*)"$/, '$1') : entry;
    for (const extension of extensions) {
      const candidate = resolve(root, directory, `keysentry${extension}`);
      try {
        if (!(await stat(candidate)).isFile()) continue;
        await access(candidate, constants.X_OK);
        return true;
      } catch (error) {
        // Missing or non-executable entries do not resolve the command.
        if ((error as NodeJS.ErrnoException).code === 'ERR_ACCESS_DENIED') unknown = true;
      }
    }
  }
  return unknown ? null : false;
}

export async function installHook(
  root: string,
  opts: { force?: boolean; binPath: string; git?: GitRunner },
): Promise<{ path: string; replaced: boolean; onPath: boolean | null }> {
  const path = await hookPath(root, opts.git ?? queryGit);
  const current = await existing(path);
  const backup = `${path}.keysentry-backup`;
  let replaced = false;
  if (current) {
    if (current.isSymbolicLink()) throw new Error('The existing pre-commit hook is a symbolic link; it was left unchanged.');
    if (!current.isFile()) throw new Error('The existing pre-commit hook is not a regular file; it was left unchanged.');
    if (await isOwnHook(path, current.size)) {
      if (process.platform !== 'win32') {
        await chmod(path, 0o755);
      }
      return { path, replaced: false, onPath: await keysentryOnPath(resolve(root)) };
    }
    if (!opts.force) throw new Error('An existing pre-commit hook was left unchanged. Use --force to preserve and replace it.');
    if (await existing(backup)) throw new Error('A pre-commit.keysentry-backup already exists; the existing hook was left unchanged.');
    // link is exclusive, including when a backup appears after the check. It
    // preserves the original file's bytes and mode without overwriting a link.
    await link(path, backup);
    await unlink(path);
    replaced = true;
  }

  await mkdir(dirname(path), { recursive: true, mode: 0o755 });
  try {
    const file = await open(path, 'wx', 0o755);
    try {
      await file.writeFile(HOOK, 'utf8');
    } finally {
      await file.close();
    }
    // Path-based chmod (umask may have narrowed the creation mode); FileHandle.chmod is disabled under the Node
    // permission model.
    if (process.platform !== 'win32') await chmod(path, 0o755);
  } catch (error) {
    if (replaced) {
      // Restore the original only if nobody has installed another hook meanwhile.
      await link(backup, path).catch(() => {});
    }
    throw error;
  }
  if (replaced) {
    console.warn('The previous hook is preserved as pre-commit.keysentry-backup. To run both checks, call that backup from a custom pre-commit hook before keysentry guard --staged.');
  }
  return { path, replaced, onPath: await keysentryOnPath(resolve(root)) };
}

export async function uninstallHook(root: string, git: GitRunner = queryGit): Promise<void> {
  const path = await hookPath(root, git);
  const current = await existing(path);
  if (!current?.isFile() || current.isSymbolicLink()) return;
  if (await isOwnHook(path, current.size)) await unlink(path);
}
