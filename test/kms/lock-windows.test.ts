// fix-verify L-d: the KMS first-start lock uses the saved state lock's mechanism, so on Windows a lock file that its
// previous holder has just deleted ("delete pending": link, open and stat fail with EPERM, EACCES or EBUSY) is
// contention to wait through, not a broken lock.
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';

const contention = vi.hoisted(() => ({ link: 0, open: 0, codes: ['EPERM', 'EACCES', 'EBUSY'] }));
vi.mock('node:fs/promises', async importOriginal => {
  const actual = await importOriginal<typeof import('node:fs/promises')>();
  const busy = () => Object.assign(new Error('operation not permitted'), { code: contention.codes[(contention.link + contention.open) % 3] });
  return {
    ...actual,
    link: async (...args: Parameters<typeof actual.link>) => {
      if (contention.link > 0 && String(args[1]).endsWith('state-key.lock')) { contention.link--; throw busy(); }
      return actual.link(...args);
    },
    open: async (...args: Parameters<typeof actual.open>) => {
      if (contention.open > 0 && String(args[0]).endsWith('state-key.lock') && args[1] === 'r') { contention.open--; throw busy(); }
      return actual.open(...args);
    },
  };
});

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });

async function withPlatform<T>(platform: NodeJS.Platform, run: () => Promise<T>): Promise<T> {
  const descriptor = Object.getOwnPropertyDescriptor(process, 'platform')!;
  Object.defineProperty(process, 'platform', { value: platform });
  try { return await run(); } finally { Object.defineProperty(process, 'platform', descriptor); }
}

it('waits through delete-pending errors while publishing and checking the lock on Windows', async () => {
  const { withStateKeyLock } = await import('../../src/kms/lock.js');
  const dir = await mkdtemp(join(tmpdir(), 'ks-kms-lock-win-')); dirs.push(dir);
  const outcome = await withPlatform('win32', async () => {
    contention.link = 3;
    contention.open = 2;
    return withStateKeyLock({ key: 'win', lockPath: join(dir, 'state-key.lock'), waitMs: 5_000 }, async () => 'ran');
  });
  expect(outcome).toBe('ran');
  expect(contention).toMatchObject({ link: 0 });
});

it('treats the same errors as a lock that cannot be used on other systems', async () => {
  const { withStateKeyLock } = await import('../../src/kms/lock.js');
  const { KmsError } = await import('../../src/kms/errors.js');
  const dir = await mkdtemp(join(tmpdir(), 'ks-kms-lock-posix-')); dirs.push(dir);
  const error = await withPlatform('linux', async () => {
    contention.link = 1;
    contention.open = 0;
    return withStateKeyLock({ key: 'posix', lockPath: join(dir, 'state-key.lock'), waitMs: 1_000 }, async () => 'ran').then(() => null, (caught: unknown) => caught);
  });
  contention.link = 0;
  expect(error).toBeInstanceOf(KmsError);
  expect(error).toMatchObject({ code: 'config', message: 'The state key lock in the .keysentry directory could not be used. Check that the directory is writable.' });
});
