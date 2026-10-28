import { mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createFileStorage, createMemoryStorage } from '../src/storage.js';

const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map(dir => rm(dir, {recursive:true,force:true}))); });
async function directory() { const dir = await mkdtemp(join(tmpdir(),'ks-control-')); dirs.push(dir); return dir; }

describe('control-plane storage', () => {
  for (const backend of ['memory','file']) {
    it(`${backend} isolates copies, lists prefixes and deletes records`, async () => {
      const store = backend === 'memory' ? createMemoryStorage() : createFileStorage(await directory());
      const value = {boxes:['first']};
      await store.put('accounts/one',value);
      value.boxes.push('outside');
      const saved = await store.get<typeof value>('accounts/one');
      saved!.boxes.push('reader');
      expect(await store.get('accounts/one')).toEqual({boxes:['first']});
      await store.put('other/two',{ok:true});
      expect(await store.list('accounts/')).toEqual(['accounts/one']);
      await store.delete('accounts/one');
      expect(await store.get('accounts/one')).toBeNull();
    });
    it(`${backend} refuses path escape keys without altering storage`, async () => {
      const store = backend === 'memory' ? createMemoryStorage() : createFileStorage(await directory());
      for (const key of ['../outside','/absolute','a\\b','a//b','a/../b','a\u0000b']) {
        await expect(store.put(key,{ok:true})).rejects.toThrow('Invalid storage key');
      }
      expect(await store.list('')).toEqual([]);
    });
  }
  it('file writes survive reopening and leave only complete records', async () => {
    const dir = await directory();
    const store = createFileStorage(dir);
    await store.put('relay/box',{message:'first'});
    await store.put('relay/box',{message:'second'});
    expect(await createFileStorage(dir).get('relay/box')).toEqual({message:'second'});
    const files = await readdir(dir);
    expect(files).toHaveLength(1);
    expect(JSON.parse(await readFile(join(dir,files[0]!), 'utf8'))).toEqual({message:'second'});
  });
  it('rejects malformed or oversized saved JSON with a value-free error', async () => {
    const dir = await directory();
    const store = createFileStorage(dir,{maxRecordBytes:64});
    await store.put('valid',{ok:true});
    const file = (await readdir(dir))[0]!;
    await writeFile(join(dir,file),'planted-plaintext');
    await expect(store.get('valid')).rejects.toThrow('Unable to read storage');
    await expect(store.put('large',{data:'x'.repeat(100)})).rejects.toThrow('Storage record is too large');
  });
  it.skipIf(process.platform === 'win32')('refuses symlink records', async () => {
    const dir = await directory();
    const store = createFileStorage(dir);
    await store.put('valid',{ok:true});
    const file = join(dir,(await readdir(dir))[0]!);
    await rm(file);
    const target = join(await directory(),'target');
    await writeFile(target,'{"private":true}');
    await symlink(target,file);
    await expect(store.get('valid')).rejects.toThrow('Unable to read storage');
    await expect(store.put('valid',{overwrite:true})).rejects.toThrow('Unable to write storage');
    expect(await readFile(target,'utf8')).toBe('{"private":true}');
  });
});
