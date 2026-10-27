import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, symlink, unlink, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createStateCipher, createStateStore } from '../../src/core/store.js';
import { getProjectId } from '../../src/vault/keys.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import type { JournalEntry } from '../../src/types.js';

const directories: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  vi.resetModules();
  for (const path of directories.splice(0)) await rm(path, { recursive: true, force: true });
});

async function fixture() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-state-lock-'));
  directories.push(cwd);
  const cipher = createStateCipher(randomBytes(32));
  const store = createStateStore({ cwd, cipher });
  return { cwd, cipher, store, lockPath: join(store.paths.dir, '.state.lock') };
}

async function independentModules() {
  vi.resetModules();
  const first = await import('../../src/core/store.js');
  vi.resetModules();
  const second = await import('../../src/core/store.js');
  return [first, second] as const;
}

describe('state operations across independent module instances', () => {
  it.each([false, true])('keeps one authenticated journal chain through independent queues (path alias: %s)', async alias => {
    const { cwd, cipher } = await fixture();
    const [left, right] = await independentModules();
    let otherCwd = cwd;
    if (alias) {
      const aliasRoot = await mkdtemp(join(tmpdir(), 'keysentry-state-alias-'));
      directories.push(aliasRoot);
      otherCwd = join(aliasRoot, 'project');
      await symlink(cwd, otherCwd, process.platform === 'win32' ? 'junction' : 'dir');
    }
    const first = left.createStateStore({ cwd, cipher });
    const second = right.createStateStore({ cwd: otherCwd, cipher });
    const entries: JournalEntry[] = Array.from({ length: 12 }, (_, index) => ({
      at: '2026-10-27T12:00:00.000Z', planId: `plan-${index}`, event: 'plan-start',
    }));

    await Promise.all(entries.map((entry, index) => (index % 2 ? first : second).journal().append(entry)));

    const saved = await first.journal().read();
    expect(saved).toHaveLength(entries.length);
    expect(saved.map(entry => entry.planId).sort()).toEqual(entries.map(entry => entry.planId).sort());
    expect(await second.journal().read()).toEqual(saved);
  });

  it('holds the filesystem lock before project binding starts', async () => {
    const { cwd, cipher, lockPath } = await fixture();
    const [left, right] = await independentModules();
    const projectId = await getProjectId(join(cwd, '.keysentry'));
    const vault = createFakeVault();
    const get = vault.get.bind(vault);
    let release!: () => void;
    const held = new Promise<void>(done => { release = done; });
    let entered!: () => void;
    const started = new Promise<void>(done => { entered = done; });
    let bindingReads = 0;
    vault.get = async name => {
      if (name.startsWith('projects/by-path/')) {
        bindingReads++;
        if (bindingReads === 1) { entered(); await held; }
      }
      return get(name);
    };
    const first = left.createStateStore({ cwd, cipher, vault, projectId }).loadInventory();
    await started;
    const second = right.createStateStore({ cwd, cipher, vault, projectId }).loadInventory();
    try {
      await new Promise<void>(done => setTimeout(done, 50));
      expect(bindingReads).toBe(1);
      expect(JSON.parse(await readFile(lockPath, 'utf8')).pid).toBe(process.pid);
    } finally { release(); await Promise.all([first, second]); }
    await expect(readFile(lockPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('keeps a dead owner lock and explains manual recovery without racing another recoverer', async () => {
    const { store, lockPath } = await fixture();
    await mkdir(store.paths.dir);
    const content = JSON.stringify({ pid: 2_147_483_647, token: 'crashed-owner' });
    await writeFile(lockPath, content);
    // Automatic stale unlink cannot atomically check that a new owner has not replaced the lock.
    await expect(store.loadInventory()).rejects.toThrow(/confirm.*no keysentry command.*remove.*\.keysentry[/\\]\.state\.lock/i);
    expect(await readFile(lockPath, 'utf8')).toBe(content);
    await unlink(lockPath);
    expect(await store.loadInventory()).toBeNull();
  });

  it('keeps malformed owner metadata regardless of its age and explains manual recovery', async () => {
    const { store, lockPath } = await fixture();
    await mkdir(store.paths.dir);
    await writeFile(lockPath, '{"pid":');
    await utimes(lockPath, new Date(0), new Date(0));
    await expect(store.loadInventory()).rejects.toThrow(/confirm.*no keysentry command.*remove.*\.keysentry[/\\]\.state\.lock/i);
    expect(await readFile(lockPath, 'utf8')).toBe('{"pid":');
  });

  it('reports busy within its deadline and never expires an old lock with a live owner', async () => {
    const { store, lockPath } = await fixture();
    await mkdir(store.paths.dir);
    const content = JSON.stringify({ pid: process.pid, token: 'still-working' });
    await writeFile(lockPath, content);
    await utimes(lockPath, new Date(0), new Date(0));
    const start = Date.now();
    let elapsed = 0;
    vi.spyOn(Date, 'now').mockImplementation(() => start + (elapsed += 2_000));
    await expect(store.loadInventory()).rejects.toThrow(/saved state is busy.*other operation finishes/i);
    expect(await readFile(lockPath, 'utf8')).toBe(content);
  });

  it('releases its lock after a failed state operation', async () => {
    const { store, lockPath } = await fixture();
    await mkdir(store.paths.dir);
    await writeFile(store.paths.inventory, '{"unexpected":"plaintext"}');
    await expect(store.loadInventory()).rejects.toThrow(/unencrypted/);
    await expect(readFile(lockPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await unlink(store.paths.inventory);
    expect(await store.loadInventory()).toBeNull();
  });
});
