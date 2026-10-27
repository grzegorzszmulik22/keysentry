import { afterEach, describe, expect, it } from 'vitest';
import { access, copyFile, mkdir, mkdtemp, open, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createInFlightStore, InFlightClosedError } from '../../src/core/inflight.js';
import { DecryptError, openBytes } from '../../src/security/index.js';
import { createFakeVault } from '../helpers/fake-vault.js';

const temporary: string[] = [];
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'keysentry-inflight-'));
  temporary.push(root);
  const dir = join(root, 'inflight');
  const vault = createFakeVault();
  return { root, dir, vault, store: createInFlightStore({ dir, vault, projectId: 'project1' }) };
}
afterEach(async () => { await Promise.all(temporary.splice(0).map(path => rm(path, { recursive: true, force: true }))); });

describe('encrypted in-flight values', () => {
  it('put/get/slots round-trip and the file never contains the value', async () => {
    const { dir, vault, store } = await fixture();
    await store.put('plan1', 'new:cluster1', 'one-time-secret-value');
    await store.put('plan1', 'old:cluster1', 'old-secret-value');
    expect(await store.get('plan1', 'new:cluster1')).toBe('one-time-secret-value');
    expect(await store.get('plan1', 'missing')).toBeNull();
    expect(await store.slots('plan1')).toEqual(['new:cluster1', 'old:cluster1']);
    expect(await vault.list()).toEqual(['project/project1/inflight/plan1']);
    const contents = await readFile(join(dir, 'plan1.jsonl'), 'utf8');
    expect(contents).not.toContain('one-time-secret-value');
    expect(contents).not.toContain(Buffer.from('one-time-secret-value').toString('base64'));
    expect(contents).not.toContain('new:cluster1');
    expect(contents.trimEnd().split('\n')).toHaveLength(2);
    if (process.platform !== 'win32') {
      expect((await stat(dir)).mode & 0o777).toBe(0o700);
      expect((await stat(join(dir, 'plan1.jsonl'))).mode & 0o777).toBe(0o600);
    }
  });

  it('stores the value under its plan and slot authentication label', async () => {
    const { dir, vault, store } = await fixture();
    await store.put('plan1', 'new:cluster1', 'one-time-secret-value');
    const key = (await vault.get('project/project1/inflight/plan1'))!;
    const sealed = Buffer.from((await readFile(join(dir, 'plan1.jsonl'), 'utf8')).trim(), 'base64');
    const record = JSON.parse(openBytes(key, sealed, 'keysentry-inflight:plan1').toString('utf8'));
    expect(record.slot).toBe('new:cluster1');
    expect(JSON.parse(openBytes(key, Buffer.from(record.sealed, 'base64'), 'keysentry-inflight:plan1:new:cluster1').toString('utf8')))
      .toEqual({ slot: 'new:cluster1', value: 'one-time-secret-value' });
    expect(() => openBytes(key, Buffer.from(record.sealed, 'base64'), 'keysentry-inflight:plan1:old:cluster1')).toThrow(DecryptError);
  });

  it('the last put to a slot wins after reopening', async () => {
    const { dir, vault, store } = await fixture();
    await store.put('plan1', 'new:cluster1', 'first-secret');
    await store.put('plan1', 'new:cluster1', 'replacement-secret');
    const reopened = createInFlightStore({ dir, vault, projectId: 'project1' });
    expect(await reopened.get('plan1', 'new:cluster1')).toBe('replacement-secret');
    expect(await reopened.slots('plan1')).toEqual(['new:cluster1']);
  });

  it('keeps every concurrent append across instances', async () => {
    const { dir, vault, store } = await fixture();
    const second = createInFlightStore({ dir, vault, projectId: 'project1' });
    await Promise.all(Array.from({ length: 20 }, (_, index) =>
      (index % 2 ? second : store).put('plan1', `new:cluster${index}`, `value-${index}`)));
    expect(await store.slots('plan1')).toHaveLength(20);
    expect(await second.get('plan1', 'new:cluster19')).toBe('value-19');
    expect((await readFile(join(dir, 'plan1.jsonl'), 'utf8')).trimEnd().split('\n')).toHaveLength(20);
  });

  it('returns null and no slots when either the key or file is missing', async () => {
    const { dir, vault, store } = await fixture();
    expect(await store.get('unknown', 'new:cluster1')).toBeNull();
    expect(await store.slots('unknown')).toEqual([]);
    await vault.set('project/project1/inflight/plan1', Buffer.alloc(32, 7));
    expect(await store.get('plan1', 'new:cluster1')).toBeNull();
    expect(await store.slots('plan1')).toEqual([]);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, 'no-key.jsonl'), 'invalid ciphertext\n');
    expect(await store.get('no-key', 'new:cluster1')).toBeNull();
    expect(await store.slots('no-key')).toEqual([]);
  });

  it('fails closed on damaged ciphertext without exposing contents', async () => {
    const { dir, store } = await fixture();
    await store.put('plan1', 'new:cluster1', 'sensitive-value');
    await writeFile(join(dir, 'plan1.jsonl'), 'sensitive-value\n');
    await expect(store.get('plan1', 'new:cluster1')).rejects.toThrow(DecryptError);
    try { await store.slots('plan1'); } catch (error) { expect(String(error)).not.toContain('sensitive-value'); }
  });

  it('does not read another plan file under a copied key', async () => {
    const { dir, vault, store } = await fixture();
    await store.put('plan1', 'new:cluster1', 'sensitive-value');
    await vault.set('project/project1/inflight/plan2', (await vault.get('project/project1/inflight/plan1'))!);
    await copyFile(join(dir, 'plan1.jsonl'), join(dir, 'plan2.jsonl'));
    await expect(store.get('plan2', 'new:cluster1')).rejects.toThrow(DecryptError);
  });

  it('shred removes the vault key first and then the file and closes the instance', async () => {
    const { dir, vault } = await fixture();
    let fileExistedOnDelete = false;
    const deletingVault = {
      ...vault,
      async delete(name: string) {
        fileExistedOnDelete = (await readFile(join(dir, 'plan1.jsonl'))).length > 0;
        return vault.delete(name);
      },
    };
    const store = createInFlightStore({ dir, vault: deletingVault, projectId: 'project1' });
    await store.put('plan1', 'new:cluster1', 'sensitive-value');
    await store.shred('plan1');
    expect(fileExistedOnDelete).toBe(true);
    expect(await vault.get('project/project1/inflight/plan1')).toBeNull();
    await expect(access(join(dir, 'plan1.jsonl'))).rejects.toMatchObject({ code: 'ENOENT' });
    expect(await store.get('plan1', 'new:cluster1')).toBeNull();
    expect(await store.slots('plan1')).toEqual([]);
    await expect(store.put('plan1', 'new:cluster1', 'later-value')).rejects.toThrow(InFlightClosedError);
  });

  it('restoring ciphertext after shred cannot restore a secret even in a new instance', async () => {
    const { root, dir, vault, store } = await fixture();
    await store.put('plan1', 'new:cluster1', 'sensitive-value');
    const copy = join(root, 'encrypted-copy');
    await copyFile(join(dir, 'plan1.jsonl'), copy);
    await store.shred('plan1');
    await copyFile(copy, join(dir, 'plan1.jsonl'));
    const reopened = createInFlightStore({ dir, vault, projectId: 'project1' });
    expect(await reopened.get('plan1', 'new:cluster1')).toBeNull();
    expect(await reopened.slots('plan1')).toEqual([]);
  });

  it('overwrites the entire file with zeros before removing it', async () => {
    const { dir, store } = await fixture();
    await store.put('plan1', 'new:cluster1', 'sensitive-value');
    const path = join(dir, 'plan1.jsonl');
    const originalLength = (await stat(path)).size;
    const handle = await open(path, 'r');
    try {
      await store.shred('plan1');
      expect(await handle.readFile()).toEqual(Buffer.alloc(originalLength));
    } finally { await handle.close(); }
  });

  it('keeps ciphertext intact and the plan open when vault key deletion fails', async () => {
    const { dir, vault } = await fixture();
    const store = createInFlightStore({ dir, projectId: 'project1', vault: {
      ...vault, async delete() { throw new Error('Vault is unavailable.'); },
    } });
    await store.put('plan1', 'new:cluster1', 'first-value');
    const before = await readFile(join(dir, 'plan1.jsonl'));
    await expect(store.shred('plan1')).rejects.toThrow('Vault is unavailable.');
    expect(await readFile(join(dir, 'plan1.jsonl'))).toEqual(before);
    expect(await store.get('plan1', 'new:cluster1')).toBe('first-value');
    await store.put('plan1', 'new:cluster1', 'later-value');
    expect(await store.get('plan1', 'new:cluster1')).toBe('later-value');
  });

  it('serializes shred after queued puts and rejects a put queued behind it', async () => {
    const { dir, vault, store } = await fixture();
    const first = store.put('plan1', 'new:cluster1', 'first-value');
    const shred = store.shred('plan1');
    const later = store.put('plan1', 'new:cluster1', 'later-value');
    const rejected = expect(later).rejects.toThrow(InFlightClosedError);
    await Promise.all([first, shred, rejected]);
    expect(await vault.list()).toEqual([]);
    await expect(access(join(dir, 'plan1.jsonl'))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('shred of an unknown plan is a no-op and does not close it', async () => {
    const { store } = await fixture();
    await store.shred('unknown');
    await store.put('unknown', 'new:cluster1', 'later-value');
    expect(await store.get('unknown', 'new:cluster1')).toBe('later-value');
  });

  it('accepts colon identifiers without colliding with ordinary plans', async () => {
    const { dir, vault, store } = await fixture();
    await store.put('plan:1', 'new:cluster.1_-', 'colon-value');
    await store.put('plan_1', 'new:cluster.1_-', 'ordinary-value');
    expect(await store.get('plan:1', 'new:cluster.1_-')).toBe('colon-value');
    expect(await store.get('plan_1', 'new:cluster.1_-')).toBe('ordinary-value');
    expect((await vault.list()).length).toBe(2);
    expect(await readFile(join(dir, 'plan%3A1.jsonl'), 'utf8')).not.toContain('colon-value');
    await store.shred('plan:1');
    expect(await store.get('plan_1', 'new:cluster.1_-')).toBe('ordinary-value');
  });

  it.each(['', '../outside', 'a/b', 'a\\b', 'with space', 'line\nbreak', 'x'.repeat(129)])('rejects invalid plan identifier %j', async id => {
    const { store } = await fixture();
    await expect(store.put(id, 'slot', 'value')).rejects.toThrow(TypeError);
    await expect(store.get(id, 'slot')).rejects.toThrow(TypeError);
    await expect(store.slots(id)).rejects.toThrow(TypeError);
    await expect(store.shred(id)).rejects.toThrow(TypeError);
  });

  it.each(['', '../outside', 'a/b', 'a\\b', 'with space', 'line\nbreak', 'x'.repeat(129)])('rejects invalid slot identifier %j', async slot => {
    const { store } = await fixture();
    await expect(store.put('plan1', slot, 'value')).rejects.toThrow(TypeError);
    await expect(store.get('plan1', slot)).rejects.toThrow(TypeError);
  });
});
