import { afterEach, expect, test, vi } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import type { GitRunner } from '../../src/guard/guard.js';

// Inside the Node permission model, the PATH directories are outside keysentry's read grants, so the check
// cannot see the command. Found by the sandboxed container smoke test: it warned with keysentry on PATH.
vi.mock('node:fs/promises', async importOriginal => {
  const actual = await importOriginal<typeof import('node:fs/promises')>();
  return { ...actual, stat: async (path: Parameters<typeof actual.stat>[0]) => {
    if (/^keysentry(?:\.exe)?$/.test(basename(String(path)))) throw Object.assign(new Error('denied'), { code: 'ERR_ACCESS_DENIED' });
    return actual.stat(path);
  } };
});

const dirs: string[] = [];
afterEach(async () => { vi.unstubAllEnvs(); for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });

const git: GitRunner = async (args, opts) => {
  if (args.join(' ') === 'rev-parse --git-common-dir') { opts.onLine('.git'); return { code: 0 }; }
  return { code: 1 };
};

test('a PATH check the sandbox refuses reports unknown instead of missing', async () => {
  const { installHook } = await import('../../src/guard/hook.js');
  const root = await mkdtemp(join(tmpdir(), 'keysentry-hook-sandbox-')); dirs.push(root);
  vi.stubEnv('PATH', root);
  expect(await installHook(root, { binPath: 'keysentry', git })).toMatchObject({ onPath: null });
});
