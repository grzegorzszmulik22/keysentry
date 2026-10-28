import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';

// On Windows a lock file another process has just deleted stays "delete pending" until every handle closes; opening,
// linking or statting it then fails with EPERM. Found by running the lock tests in parallel: that is contention, so the
// lock waits and retries instead of failing with "Unable to check the saved state lock."
const contention = vi.hoisted(() => ({ link: 0, open: 0 }));
vi.mock('node:fs/promises', async importOriginal => {
  const actual = await importOriginal<typeof import('node:fs/promises')>();
  const eperm = () => Object.assign(new Error('operation not permitted'), { code: 'EPERM' });
  return {
    ...actual,
    link: async (...args: Parameters<typeof actual.link>) => { if (contention.link > 0) { contention.link--; throw eperm(); } return actual.link(...args); },
    open: async (...args: Parameters<typeof actual.open>) => {
      if (contention.open > 0 && String(args[0]).endsWith('.state.lock') && args[1] === 'r') { contention.open--; throw eperm(); }
      return actual.open(...args);
    },
  };
});

const dirs: string[] = [];
afterEach(async () => {
  vi.unstubAllGlobals();
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

it('waits through Windows delete-pending errors on the state lock instead of failing', async () => {
  const platform = Object.getOwnPropertyDescriptor(process, 'platform')!;
  Object.defineProperty(process, 'platform', { value: 'win32' });
  try {
    const { createStateCipher, createStateStore } = await import('../../src/core/store.js');
    const cwd = await mkdtemp(join(tmpdir(), 'keysentry-lock-win-')); dirs.push(cwd);
    const store = createStateStore({ cwd, cipher: createStateCipher(randomBytes(32)) });
    contention.link = 2;
    await store.writeJson('plan', join(store.paths.dir, 'one.json'), { ok: 1 });
    expect(await store.readJson('plan', join(store.paths.dir, 'one.json'))).toEqual({ ok: 1 });
    expect(contention.link).toBe(0);
  } finally { Object.defineProperty(process, 'platform', platform); }
});
