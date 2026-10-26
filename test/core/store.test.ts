import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import type { Inventory, JournalEntry } from '../../src/types.js';
import { appendAudit, createFileJournal, loadInventory, readJson, saveInventory, statePaths, writeJsonAtomic } from '../../src/core/store.js';

const dirs: string[] = [];
async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'keysentry-store-'));
  dirs.push(dir);
  return dir;
}
afterEach(async () => { await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true }))); });
const inventory: Inventory = {
  version: 1, scannedAt: '2026-10-26T00:00:00.000Z', hosts: [], services: [], findings: [], clusters: [], errors: [],
};

describe('state paths and inventory', () => {
  it('resolves every state path from the working directory', () => {
    const paths = statePaths('relative');
    expect(paths).toEqual({
      dir: resolve('relative', '.keysentry'),
      inventory: resolve('relative', '.keysentry/inventory.json'),
      journal: resolve('relative', '.keysentry/journal.jsonl'),
      audit: resolve('relative', '.keysentry/audit.jsonl'),
      monitor: resolve('relative', '.keysentry/monitor.json'),
      plans: resolve('relative', '.keysentry/plans'),
    });
    expect(Object.values(paths).every(isAbsolute)).toBe(true);
    expect(statePaths().dir).toBe(join(process.cwd(), '.keysentry'));
  });

  it('returns null for an absent inventory and persists a sanitized inventory', async () => {
    const cwd = await tempDir();
    const paths = statePaths(cwd);
    expect(await loadInventory(cwd)).toBeNull();
    expect(await readFile(join(paths.dir, '.gitignore'), 'utf8')).toContain('*');
    await saveInventory(inventory, cwd);
    expect(await loadInventory(cwd)).toEqual(inventory);
    if (process.platform !== 'win32') expect((await stat(paths.inventory)).mode & 0o777).toBe(0o600);
  });
});

describe('atomic JSON state', () => {
  it('never exposes partial writes and removes every temporary file', async () => {
    const path = statePaths(await tempDir()).monitor;
    await writeJsonAtomic(path, { id: -1, payload: 'a'.repeat(64000) });
    let finished = false;
    const observations: number[] = [];
    const reader = (async () => {
      while (!finished) {
        const current = JSON.parse(await readFile(path, 'utf8')) as { id: number; payload: string };
        expect(current).not.toBeNull();
        expect(current!.payload).toBe('a'.repeat(64000));
        observations.push(current!.id);
      }
    })();
    try {
      await Promise.all(Array.from({ length: 20 }, (_, id) => writeJsonAtomic(path, { id, payload: 'a'.repeat(64000) })));
    } finally {
      finished = true;
      await reader;
    }
    expect(observations.length).toBeGreaterThan(0);
    expect((await readdir(statePaths(dirs[dirs.length - 1]!).dir)).sort()).toEqual(['.gitignore', 'monitor.json']);
  });

  it('leaves the previous document intact when serialization fails without exposing input', async () => {
    const cwd = await tempDir();
    const path = statePaths(cwd).monitor;
    await writeJsonAtomic(path, { safe: true });
    const unsafe = { toJSON() { throw new Error('raw-value-must-not-appear'); } };
    await expect(writeJsonAtomic(path, unsafe)).rejects.toThrow(/write|serializ/i);
    try { await writeJsonAtomic(path, unsafe); } catch (error) { expect(String(error)).not.toContain('raw-value-must-not-appear'); }
    expect(await readJson(path)).toEqual({ safe: true });
    expect((await readdir(statePaths(cwd).dir)).sort()).toEqual(['.gitignore', 'monitor.json']);
  });

  it('returns null for missing generic files and rejects malformed JSON safely', async () => {
    const path = statePaths(await tempDir()).monitor;
    expect(await readJson(path)).toBeNull();
    await writeFile(path, '{"value":"raw-value-must-not-appear"');
    await expect(readJson(path)).rejects.toThrow(/JSON/i);
    try { await readJson(path); } catch (error) { expect(String(error)).not.toContain('raw-value-must-not-appear'); }
  });

  it('cleans its temporary file when the target cannot be replaced', async () => {
    const paths = statePaths(await tempDir());
    const target = join(paths.dir, 'occupied');
    await mkdir(target, { recursive: true });
    await expect(writeJsonAtomic(target, { safe: true })).rejects.toThrow(/write/i);
    expect((await stat(target)).isDirectory()).toBe(true);
    expect((await readdir(paths.dir)).sort()).toEqual(['.gitignore', 'occupied']);
  });

  it('preserves another operation’s temporary file on an exclusive-create collision', async () => {
    const paths = statePaths(await tempDir());
    await writeJsonAtomic(paths.monitor, { safe: true });
    const collision = join(paths.dir, `.monitor.json-${'42'.repeat(16)}.tmp`);
    const sentinel = Buffer.from('owned-by-another-operation');
    await writeFile(collision, sentinel);
    vi.doMock('node:crypto', async () => ({
      ...await vi.importActual<typeof import('node:crypto')>('node:crypto'),
      randomBytes: (size: number) => Buffer.alloc(size, 0x42),
    }));
    vi.resetModules();
    try {
      const module = await import('../../src/core/store.js');
      await expect(module.writeJsonAtomic(paths.monitor, { safe: false })).rejects.toThrow(/write/i);
      const remaining = await readFile(collision).catch(() => null);
      expect(remaining?.equals(sentinel) ?? false).toBe(true);
      expect(await readJson(paths.monitor)).toEqual({ safe: true });
    } finally {
      vi.doUnmock('node:crypto');
      vi.resetModules();
    }
  });

  it('repairs the state gitignore on read and nested write entry points', async () => {
    const cwd = await tempDir();
    const paths = statePaths(cwd);
    await readJson(paths.monitor);
    await rm(join(paths.dir, '.gitignore'));
    await writeJsonAtomic(join(paths.plans, 'plan.json'), { id: 'plan' });
    expect(await readFile(join(paths.dir, '.gitignore'), 'utf8')).toContain('*');
    await rm(join(paths.dir, '.gitignore'));
    await readJson(paths.monitor);
    expect(await readFile(join(paths.dir, '.gitignore'), 'utf8')).toContain('*');
    await writeFile(join(paths.dir, '.gitignore'), '!monitor.json\n');
    await readJson(paths.monitor);
    expect(await readFile(join(paths.dir, '.gitignore'), 'utf8')).toBe('!monitor.json\n*\n');
  });
});

describe('append-only state', () => {
  it('returns no entries for a missing journal and restores gitignore on reads', async () => {
    const paths = statePaths(await tempDir());
    const journal = createFileJournal(paths.journal);
    expect(await journal.read()).toEqual([]);
    await rm(join(paths.dir, '.gitignore'));
    expect(await journal.read('unknown')).toEqual([]);
    expect(await readFile(join(paths.dir, '.gitignore'), 'utf8')).toContain('*');
  });

  it('preserves every concurrent entry across journal instances and filters by plan', async () => {
    const paths = statePaths(await tempDir());
    const journals = [createFileJournal(paths.journal), createFileJournal(paths.journal)];
    const entries: JournalEntry[] = Array.from({ length: 80 }, (_, index) => ({
      at: '2026-10-26T00:00:00.000Z', planId: index % 2 ? 'second' : 'first', event: 'written', data: { index },
    }));
    await Promise.all(entries.map((entry, index) => journals[index % 2]!.append(entry)));
    expect(await journals[0]!.read()).toEqual(entries);
    expect(await journals[1]!.read('first')).toEqual(entries.filter((entry) => entry.planId === 'first'));
    const content = await readFile(paths.journal, 'utf8');
    expect(content.endsWith('\n')).toBe(true);
    expect(content.trim().split('\n')).toHaveLength(80);
    if (process.platform !== 'win32') expect((await stat(paths.journal)).mode & 0o777).toBe(0o600);
  });

  it('fails closed on corrupt journal rows without revealing them', async () => {
    const paths = statePaths(await tempDir());
    const journal = createFileJournal(paths.journal);
    await journal.append({ at: 'now', planId: 'first', event: 'plan-start' });
    await writeFile(paths.journal, '{"value":"raw-value-must-not-appear"\n');
    await expect(journal.read()).rejects.toThrow(/journal|JSON/i);
    try { await journal.read(); } catch (error) { expect(String(error)).not.toContain('raw-value-must-not-appear'); }
  });

  it('continues appending after an earlier entry cannot be serialized', async () => {
    const paths = statePaths(await tempDir());
    const journal = createFileJournal(paths.journal);
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    const invalid = journal.append({ at: 'now', planId: 'first', event: 'created', data: circular });
    const valid: JournalEntry = { at: 'now', planId: 'first', event: 'plan-end' };
    const appended = journal.append(valid);
    await expect(invalid).rejects.toThrow(/append/i);
    await appended;
    expect(await journal.read()).toEqual([valid]);
  });

  it('appends audit JSONL and repairs ignore protection on every append', async () => {
    const paths = statePaths(await tempDir());
    await appendAudit(paths.audit, { event: 'first', fingerprint: 'a'.repeat(32) });
    await rm(join(paths.dir, '.gitignore'));
    await appendAudit(paths.audit, { event: 'second', count: 2 });
    expect((await readFile(paths.audit, 'utf8')).trim().split('\n').map((line) => JSON.parse(line))).toEqual([
      { event: 'first', fingerprint: 'a'.repeat(32) }, { event: 'second', count: 2 },
    ]);
    expect(await readFile(join(paths.dir, '.gitignore'), 'utf8')).toContain('*');
    if (process.platform !== 'win32') expect((await stat(paths.audit)).mode & 0o777).toBe(0o600);
  });
});
