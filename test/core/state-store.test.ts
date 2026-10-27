import { randomBytes } from 'node:crypto';
import { appendFile, mkdir, mkdtemp, open, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createStateCipher, createStateStore, StateCorruptError, StateLockedError } from '../../src/core/store.js';
import { DecryptError, openBytes } from '../../src/security/index.js';
import type { Inventory, JournalEntry } from '../../src/types.js';

const header = 'keysentry-encrypted:v1';
const directories: string[] = [];
async function fixture() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-state-'));
  directories.push(cwd);
  const key = randomBytes(32);
  const cipher = createStateCipher(key);
  return { cwd, key, cipher, store: createStateStore({ cwd, cipher }) };
}
afterEach(async () => {
  for (const path of directories.splice(0)) await rm(path, { recursive: true, force: true });
});
const inventory: Inventory = {
  version: 1, scannedAt: '2026-10-27T12:00:00.000Z', hosts: ['railway'],
  services: [{ host: 'railway', projectId: 'project', projectName: 'private-project', serviceId: 'api',
    serviceName: 'private-service', environmentId: 'prod', environmentName: 'production' }],
  findings: [], clusters: [{ id: 'fingerprint-unchanged', fingerprint: 'fingerprint-unchanged', provider: 'openai',
    tier: 'ai', method: 'auto', hint: 'partial-hint', consumers: [] }], errors: [],
};
const first: JournalEntry = { at: '2026-10-27T12:00:00.000Z', planId: 'plan-one', event: 'plan-start' };
const second: JournalEntry = { ...first, planId: 'plan-two', event: 'created', data: { hint: 'private-hint' } };

describe('encrypted state store', () => {
  it('state round-trips and the file on disk contains no service names or hints', async () => {
    const { store, key } = await fixture();
    await store.saveInventory(inventory);
    expect(await store.loadInventory()).toEqual(inventory);
    const disk = await readFile(store.paths.inventory, 'utf8');
    expect(disk.split('\n')[0]).toBe(header);
    expect(disk).not.toContain('private-service');
    expect(disk).not.toContain('partial-hint');
    expect(JSON.parse(openBytes(key, Buffer.from(disk.split('\n')[1]!, 'base64'), 'keysentry-state:inventory').toString())).toEqual(inventory);
    expect(await readFile(join(store.paths.dir, '.gitignore'), 'utf8')).toBe('*\n');
    if (process.platform !== 'win32') expect((await stat(store.paths.inventory)).mode & 0o777).toBe(0o600);
  });

  it('binds ciphertext to its state kind and validates key length', async () => {
    const { cipher } = await fixture();
    expect(() => createStateCipher(Buffer.alloc(31))).toThrow(TypeError);
    const sealed = cipher.seal('plan', Buffer.from('{}'));
    expect(() => cipher.open('monitor', sealed)).toThrow(DecryptError);
  });

  it('undecryptable state raises StateLockedError and is never overwritten implicitly', async () => {
    const { store, cwd } = await fixture();
    await store.saveInventory(inventory);
    const before = await readFile(store.paths.inventory);
    const other = createStateStore({ cwd, cipher: createStateCipher(randomBytes(32)) });
    await expect(other.loadInventory()).rejects.toMatchObject({ code: 'STATE_LOCKED' });
    await expect(other.saveInventory(inventory)).rejects.toThrow(StateLockedError);
    expect(await readFile(store.paths.inventory)).toEqual(before);
    await other.writeJson('inventory', store.paths.inventory, { rebuilt: true }, { replaceUndecryptable: true });
    expect(await other.loadInventory()).toEqual({ rebuilt: true });
  });

  it('rejects invalid base64 as locked without revealing file content', async () => {
    const { store } = await fixture();
    await mkdir(store.paths.dir);
    await writeFile(store.paths.inventory, `${header}\nprivate-sensitive-input!\n`);
    await expect(store.loadInventory()).rejects.toThrow(StateLockedError);
    await expect(store.loadInventory()).rejects.not.toThrow('private-sensitive-input');
  });

  it('rejects reads and writes outside .keysentry before creating paths', async () => {
    const { store, cwd } = await fixture();
    for (const path of [join(cwd, 'outside', 'state.json'), join(store.paths.dir, '..', 'state.json')]) {
      await expect(store.writeJson('plan', path, {})).rejects.toThrow(TypeError);
      await expect(store.readJson('plan', path)).rejects.toThrow(TypeError);
    }
    expect(await readdir(cwd)).toEqual([]);
  });

  it('rejects junction and symlink paths that resolve outside the state directory', async () => {
    const { store, cwd } = await fixture();
    const outside = join(cwd, 'outside');
    await mkdir(outside); await mkdir(store.paths.dir);
    await writeFile(join(outside, 'state.json'), '{"untouched":true}');
    await symlink(outside, join(store.paths.dir, 'linked'), process.platform === 'win32' ? 'junction' : 'dir');
    await expect(store.readJson('plan', join(store.paths.dir, 'linked', 'state.json'))).rejects.toThrow(TypeError);
    await expect(store.writeJson('plan', join(store.paths.dir, 'linked', 'nested', 'state.json'), {})).rejects.toThrow(TypeError);
    expect(await readdir(outside)).toEqual(['state.json']);
    expect(await readFile(join(outside, 'state.json'), 'utf8')).toBe('{"untouched":true}');
  });

  it('reads missing and legacy plaintext files while hiding JSON parser input', async () => {
    const { store } = await fixture();
    expect(await store.loadInventory()).toBeNull();
    await writeFile(store.paths.inventory, JSON.stringify(inventory));
    expect(await store.loadInventory()).toEqual(inventory);
    await writeFile(store.paths.inventory, '{"private-sensitive-input":');
    await expect(store.loadInventory()).rejects.toThrow(/JSON/);
    await expect(store.loadInventory()).rejects.not.toThrow('private-sensitive-input');
  });

  it('keeps plaintext mode compatible but never overwrites encrypted files without permission', async () => {
    const { store, cwd } = await fixture();
    const plain = createStateStore({ cwd, cipher: null });
    await plain.writeJson('monitor', plain.paths.monitor, { version: 1 });
    expect(JSON.parse(await readFile(plain.paths.monitor, 'utf8'))).toEqual({ version: 1 });
    expect(await plain.migratePlaintext()).toEqual({ migrated: [] });
    await store.saveInventory(inventory);
    await expect(plain.loadInventory()).rejects.toThrow(StateLockedError);
    await expect(plain.saveInventory(inventory)).rejects.toThrow(StateLockedError);
  });

  it('serializes concurrent writes across store instances and preserves the last good file on serialization failure', async () => {
    const { store, cwd, cipher } = await fixture();
    const other = createStateStore({ cwd, cipher });
    await Promise.all(Array.from({ length: 20 }, (_, id) => (id % 2 ? store : other).writeJson('monitor', store.paths.monitor, { id })));
    expect(await store.readJson('monitor', store.paths.monitor)).toEqual({ id: 19 });
    const bytes = await readFile(store.paths.monitor);
    const circular: Record<string, unknown> = { secret: 'private-sensitive-input' }; circular.self = circular;
    await expect(store.writeJson('monitor', store.paths.monitor, circular)).rejects.not.toThrow('private-sensitive-input');
    expect(await readFile(store.paths.monitor)).toEqual(bytes);
    expect((await readdir(store.paths.dir)).sort()).toEqual(['.gitignore', 'monitor.json']);
  });

  it.skipIf(process.platform !== 'win32')('keeps a complete temporary file through a sustained Windows sharing violation', async () => {
    const { store, cwd, cipher } = await fixture();
    await store.writeJson('monitor', store.paths.monitor, { before: true });
    let denied = 0;
    vi.doMock('node:fs/promises', async () => {
      const actual = await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises');
      return { ...actual, async rename(source: string, target: string) {
        if (target === store.paths.monitor && denied++ < 9) throw Object.assign(new Error('Sharing violation.'), { code: 'EPERM' });
        return actual.rename(source, target);
      } };
    });
    vi.resetModules();
    try {
      const module = await import('../../src/core/store.js');
      const retried = module.createStateStore({ cwd, cipher });
      await retried.writeJson('monitor', store.paths.monitor, { after: true });
      expect(await retried.readJson('monitor', store.paths.monitor)).toEqual({ after: true });
      expect((await readdir(store.paths.dir)).sort()).toEqual(['.gitignore', 'monitor.json']);
    } finally { vi.doUnmock('node:fs/promises'); vi.resetModules(); }
  });

  it('plaintext 0.1 state is migrated and deleted with identical inventory fingerprints', async () => {
    const { store } = await fixture();
    await mkdir(store.paths.plans, { recursive: true });
    const files = [
      ['inventory.json', 'inventory', inventory], ['monitor.json', 'monitor', { version: 1 }],
      ['plans/plan-old.json', 'plan', { id: 'plan-old' }], ['rotation-report.json', 'report', { planId: 'plan-old' }],
      ['pending.json', 'pending', [{ id: 'action' }]], ['pending-actions.json', 'pending', []],
      ['canary.json', 'canary', { id: 'decoy' }], ['canaries.json', 'canary', []],
    ] as const;
    for (const [path, , value] of files) await writeFile(join(store.paths.dir, path), JSON.stringify(value));
    const result = await store.migratePlaintext();
    expect(result.migrated.sort()).toEqual(files.map(([path]) => path).sort());
    for (const [path, kind, value] of files) {
      const target = join(store.paths.dir, path);
      expect(await store.readJson(kind, target)).toEqual(value);
      expect((await readFile(target, 'utf8')).startsWith(`${header}\n`)).toBe(true);
    }
    expect((await store.loadInventory())!.clusters[0]!.fingerprint).toBe('fingerprint-unchanged');
    expect(await store.migratePlaintext()).toEqual({ migrated: [] });
  });

  it('migrates the 0.1 audit into encrypted legacy state before removing its plaintext file', async () => {
    const { store } = await fixture();
    await mkdir(store.paths.dir);
    const lines = [{ kind: 'scan', at: 'yesterday' }, { kind: 'rotate', hint: 'private-hint' }];
    await writeFile(store.paths.audit, lines.map(line => JSON.stringify(line)).join('\n') + '\n');
    expect(await store.migratePlaintext()).toEqual({ migrated: ['audit.jsonl'] });
    expect(await store.readJson('legacy', join(store.paths.dir, 'audit-0.1.enc'))).toEqual(lines);
    await expect(readFile(store.paths.audit)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(await store.migratePlaintext()).toEqual({ migrated: [] });
  });

  it('encrypts an equal plaintext legacy archive before deleting the old audit file', async () => {
    const { store } = await fixture();
    await mkdir(store.paths.dir);
    const entries = [{ kind: 'scan', hint: 'private-hint' }];
    const archive = join(store.paths.dir, 'audit-0.1.enc');
    await writeFile(store.paths.audit, JSON.stringify(entries[0]) + '\n');
    await writeFile(archive, JSON.stringify(entries));
    expect(await store.migratePlaintext()).toEqual({ migrated: ['audit.jsonl'] });
    expect((await readFile(archive, 'utf8')).startsWith(`${header}\n`)).toBe(true);
    expect(await store.readJson('legacy', archive)).toEqual(entries);
    await expect(readFile(store.paths.audit)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('leaves the new hash-chained audit and unrelated project metadata unchanged during migration', async () => {
    const { store } = await fixture();
    await mkdir(store.paths.dir);
    const audit = '{"hash":"aabb","kind":"scan"}\n';
    await writeFile(store.paths.audit, audit);
    await writeFile(join(store.paths.dir, 'project.json'), '{"id":"stable"}');
    expect(await store.migratePlaintext()).toEqual({ migrated: [] });
    expect(await readFile(store.paths.audit, 'utf8')).toBe(audit);
    expect(await readFile(join(store.paths.dir, 'project.json'), 'utf8')).toBe('{"id":"stable"}');
  });

  it('verifies encrypted migration output before replacing plaintext', async () => {
    const { store, cwd, cipher } = await fixture();
    await mkdir(store.paths.dir);
    const plaintext = JSON.stringify(inventory);
    await writeFile(store.paths.inventory, plaintext);
    const broken = createStateStore({ cwd, cipher: { seal: cipher.seal, open: () => Buffer.from('{}') } });
    await expect(broken.migratePlaintext()).rejects.toThrow(/verif|migrat/i);
    expect(await readFile(store.paths.inventory, 'utf8')).toBe(plaintext);
    expect((await readdir(store.paths.dir)).sort()).toEqual(['.gitignore', 'inventory.json']);
  });
});

describe('encrypted journal', () => {
  it('durably appends even a large event with one write followed by one fsync', async () => {
    const { store, cwd } = await fixture();
    const probe = await open(join(cwd, 'probe'), 'w');
    const prototype = Object.getPrototypeOf(probe) as typeof probe;
    await probe.close();
    const write = vi.spyOn(prototype, 'write');
    const sync = vi.spyOn(prototype, 'sync');
    try {
      const entry = { ...first, data: { metadata: 'large-event-'.repeat(100_000) } };
      await store.journal().append(entry);
      expect(write).toHaveBeenCalledTimes(1);
      expect(sync).toHaveBeenCalledTimes(1);
      expect(write.mock.invocationCallOrder[0]!).toBeLessThan(sync.mock.invocationCallOrder[0]!);
      expect(await store.journal().read()).toEqual([entry]);
    } finally { write.mockRestore(); sync.mockRestore(); }
  });

  it('appends encrypted records, preserves concurrent order, and filters by plan', async () => {
    const { store, cwd, cipher } = await fixture();
    const journal = store.journal();
    expect(await journal.read()).toEqual([]);
    const other = createStateStore({ cwd, cipher }).journal();
    await Promise.all([journal.append(first), other.append(second), journal.append({ ...first, event: 'plan-end' })]);
    expect(await journal.read()).toEqual([first, second, { ...first, event: 'plan-end' }]);
    expect(await journal.read('plan-two')).toEqual([second]);
    const disk = await readFile(store.paths.journal, 'utf8');
    expect(disk.split('\n')).toHaveLength(5);
    expect(disk.split('\n')[0]).toBe(header);
    expect(disk).not.toContain('private-hint');
    expect(disk).not.toContain('plan-one');
  });

  it('reports a tampered line with a content-free StateCorruptError and physical line number', async () => {
    const { store } = await fixture();
    const journal = store.journal();
    await journal.append(first); await journal.append(second);
    const lines = (await readFile(store.paths.journal, 'utf8')).split('\n');
    const bytes = Buffer.from(lines[2]!, 'base64'); bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
    lines[2] = bytes.toString('base64');
    await writeFile(store.paths.journal, lines.join('\n'));
    await expect(journal.read()).rejects.toBeInstanceOf(StateCorruptError);
    await expect(journal.read()).rejects.toMatchObject({ code: 'STATE_CORRUPT', line: 3 });
    await expect(journal.read()).rejects.toThrow(/line 3.*changed or damaged/i);
    await expect(journal.read()).rejects.not.toThrow('private-hint');
  });

  it('rejects a journal encrypted with another key and preserves it on append', async () => {
    const { store, cwd } = await fixture();
    await store.journal().append(first);
    const bytes = await readFile(store.paths.journal);
    const other = createStateStore({ cwd, cipher: createStateCipher(randomBytes(32)) }).journal();
    await expect(other.read()).rejects.toThrow(StateLockedError);
    await expect(other.append(second)).rejects.toThrow(StateLockedError);
    expect(await readFile(store.paths.journal)).toEqual(bytes);
  });

  it('a plaintext-mode store cannot append plaintext to an encrypted journal', async () => {
    const { store, cwd } = await fixture();
    await store.journal().append(first);
    const bytes = await readFile(store.paths.journal);
    const plain = createStateStore({ cwd, cipher: null }).journal();
    await expect(plain.read()).rejects.toThrow(StateLockedError);
    await expect(plain.append(second)).rejects.toThrow(StateLockedError);
    expect(await readFile(store.paths.journal)).toEqual(bytes);
  });

  it('skips a torn final line and permits a later durable append', async () => {
    const { store } = await fixture();
    const journal = store.journal(); await journal.append(first);
    await appendFile(store.paths.journal, 'torn!private-sensitive-input');
    expect(await journal.read()).toEqual([first]);
    await journal.append(second);
    expect(await journal.read()).toEqual([first, second]);
  });

  it('skips a first torn record even when its truncated envelope is valid base64', async () => {
    const { store, cipher } = await fixture();
    await mkdir(store.paths.dir);
    const partial = cipher.seal('journal', Buffer.from(JSON.stringify(first))).subarray(0, 36).toString('base64');
    await writeFile(store.paths.journal, `${header}\n${partial}`);
    expect(await store.journal().read()).toEqual([]);
    await store.journal().append(second);
    expect(await store.journal().read()).toEqual([second]);
  });

  it('rejects malformed complete lines, including blank records, rather than silently dropping them', async () => {
    const { store } = await fixture();
    await store.journal().append(first);
    await appendFile(store.paths.journal, '\n');
    await expect(store.journal().read()).rejects.toMatchObject({ code: 'STATE_CORRUPT', line: 3 });
  });

  it('migrates plaintext journal records in their original order', async () => {
    const { store } = await fixture();
    await mkdir(store.paths.dir);
    await writeFile(store.paths.journal, [first, second].map(entry => JSON.stringify(entry)).join('\n') + '\n');
    expect(await store.journal().read()).toEqual([first, second]);
    expect(await store.migratePlaintext()).toEqual({ migrated: ['journal.jsonl'] });
    expect(await store.journal().read()).toEqual([first, second]);
    expect((await readFile(store.paths.journal, 'utf8')).split('\n')[0]).toBe(header);
  });
});
