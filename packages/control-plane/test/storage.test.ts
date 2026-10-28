import { mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { json, text } from '../../../test/helpers/fake-http.js';
import type { HttpClient, HttpRequest } from '../../../src/types.js';
import { createFileStorage, createGcsStorage, createMemoryStorage, metadataAccessToken } from '../src/storage.js';

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
  it('L1: a file read allocates the file size, not the record limit', async () => {
    const store = createFileStorage(await directory());
    await store.put('box-owners/small',{accountId:'a'});
    const alloc = vi.spyOn(Buffer,'alloc');
    try {
      expect(await store.get('box-owners/small')).toEqual({accountId:'a'});
      expect(Math.max(0,...alloc.mock.calls.map(args=>Number(args[0])))).toBeLessThan(64);
    } finally { alloc.mockRestore(); }
  });
  it('L2: keys that differ only in case never share a file, even on a case-folding file system', async () => {
    const dir = await directory();
    const store = createFileStorage(dir);
    await store.put('box-owners/GAA',{accountId:'first'});
    await store.put('box-owners/aAA',{accountId:'second'});
    expect(await store.get('box-owners/GAA')).toEqual({accountId:'first'});
    expect(await store.get('box-owners/aAA')).toEqual({accountId:'second'});
    for (const file of await readdir(dir)) expect(file).toMatch(/^[a-z2-7]+\.json$/);
    expect(await store.list('box-owners/')).toEqual(['box-owners/GAA','box-owners/aAA']);
  });
  it('lists by prefix exactly and round-trips the longest key', async () => {
    const store = createFileStorage(await directory());
    const long = `stripe-subscriptions/${'s'.repeat(129)}`;
    expect(long).toHaveLength(150);
    for (const key of ['a','ab','abc/d','b/a',long]) await store.put(key,{key});
    expect(await store.list('ab')).toEqual(['ab','abc/d']);
    expect(await store.list('stripe-subscriptions/')).toEqual([long]);
    expect(await store.get(long)).toEqual({key:long});
    await expect(store.put(`${long}x`,{})).rejects.toThrow('Invalid storage key');
  });
});

/** The Cloud Storage JSON API surface the backend uses, in memory, with every request recorded. */
function fakeGcs(bucket = 'ks-control-state') {
  const objects = new Map<string,string>();
  const calls: HttpRequest[] = [];
  const failures: number[] = [];
  const http: HttpClient = {
    async request(req) {
      calls.push(req);
      if (req.headers?.authorization !== 'Bearer ya29.test-access-token') return json(401,{error:{message:'planted-upstream-detail'}});
      const failure = failures.shift();
      if (failure) return json(failure,{error:{message:'planted-upstream-detail'}});
      const url = new URL(req.url);
      if (url.origin !== 'https://storage.googleapis.com') return json(599,{});
      if (req.method === 'POST' && url.pathname === `/upload/storage/v1/b/${bucket}/o` && url.searchParams.get('uploadType') === 'media') {
        objects.set(url.searchParams.get('name')!,req.body!); return json(200,{name:url.searchParams.get('name')});
      }
      const object = /^\/storage\/v1\/b\/([^/]+)\/o\/([^/]+)$/.exec(url.pathname);
      if (object && object[1] === bucket) {
        const name = decodeURIComponent(object[2]!);
        if (req.method === 'GET' && url.searchParams.get('alt') === 'media') return objects.has(name) ? text(200,objects.get(name)!) : json(404,{});
        if (req.method === 'DELETE') return objects.delete(name) ? text(204,'') : json(404,{});
      }
      if (req.method === 'GET' && url.pathname === `/storage/v1/b/${bucket}/o`) {
        const names = [...objects.keys()].filter(name=>name.startsWith(url.searchParams.get('prefix') ?? '')).sort();
        const start = Number(url.searchParams.get('pageToken') ?? 0);
        const page = names.slice(start,start+2);
        return json(200,{...(page.length?{items:page.map(name=>({name}))}:{}),...(start+2<names.length?{nextPageToken:String(start+2)}:{})});
      }
      return json(599,{});
    },
  };
  return { http, objects, calls, failures };
}

describe('Cloud Storage backend', () => {
  const token = async () => 'ya29.test-access-token';
  it('stores one object per key under the prefix and survives a new instance', async () => {
    const gcs = fakeGcs();
    const store = createGcsStorage({http:gcs.http,bucket:'ks-control-state',accessToken:token,objectPrefix:'control/'});
    await store.put('accounts/one',{plan:'free'});
    await store.put('accounts/two',{plan:'paid'});
    await store.put('other/three',{ok:true});
    expect([...gcs.objects.keys()].sort()).toEqual(['control/accounts/one','control/accounts/two','control/other/three']);
    const again = createGcsStorage({http:gcs.http,bucket:'ks-control-state',accessToken:token,objectPrefix:'control/'});
    expect(await again.get('accounts/two')).toEqual({plan:'paid'});
    expect(await again.get('accounts/missing')).toBeNull();
    expect(await again.list('accounts/')).toEqual(['accounts/one','accounts/two']);
    await again.delete('accounts/one'); await again.delete('accounts/one');
    expect(await again.list('')).toEqual(['accounts/two','other/three']);
    expect(gcs.calls.every(call=>call.url.startsWith('https://storage.googleapis.com/'))).toBe(true);
    expect(gcs.calls.some(call=>call.url.includes('control%2Faccounts%2Fone'))).toBe(true);
  });
  it('retries 429 and 5xx a bounded number of times, then fails with fixed text', async () => {
    const gcs = fakeGcs();
    const store = createGcsStorage({http:gcs.http,bucket:'ks-control-state',accessToken:token,sleep:async()=>undefined});
    gcs.failures.push(429,503);
    await store.put('accounts/one',{plan:'free'});
    expect(await store.get('accounts/one')).toEqual({plan:'free'});
    gcs.failures.push(500,500,500,500);
    const error = await store.get('accounts/one').catch(e=>e as Error);
    expect((error as Error).message).toBe('Unable to read storage.');
    gcs.failures.push(403);
    const denied = await store.put('accounts/one',{plan:'paid'}).catch(e=>e as Error);
    expect((denied as Error).message).toBe('Unable to write storage.');
    expect(JSON.stringify([(error as Error).message,(denied as Error).message,(error as Error).stack])).not.toMatch(/planted-upstream-detail|ya29/);
  });
  it('refuses invalid configuration, keys and oversized objects', async () => {
    const gcs = fakeGcs();
    expect(() => createGcsStorage({http:gcs.http,bucket:'../evil',accessToken:token})).toThrow('Invalid storage configuration');
    expect(() => createGcsStorage({http:gcs.http,bucket:'ok-bucket',accessToken:token,objectPrefix:'../'})).toThrow('Invalid storage configuration');
    const store = createGcsStorage({http:gcs.http,bucket:'ks-control-state',accessToken:token,maxRecordBytes:64});
    await expect(store.put('../x',{})).rejects.toThrow('Invalid storage key');
    await expect(store.put('big',{data:'x'.repeat(100)})).rejects.toThrow('Storage record is too large');
    gcs.objects.set('big','{"data":"'+'x'.repeat(100)+'"}');
    await expect(store.get('big')).rejects.toThrow('Unable to read storage');
    expect(gcs.calls.filter(call=>call.method==='POST')).toEqual([]);
  });
  it('gets its access token from the metadata server, cached until a minute before expiry', async () => {
    let clock = 1_000_000, served = 0;
    const http: HttpClient = { async request(req) {
      expect(req.url).toBe('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token');
      expect(req.headers).toEqual({'Metadata-Flavor':'Google'});
      served++;
      return json(200,{access_token:`ya29.token-${served}`,expires_in:120,token_type:'Bearer'},{'metadata-flavor':'Google'});
    } };
    const access = metadataAccessToken(http,()=>clock);
    expect(await Promise.all([access(),access()])).toEqual(['ya29.token-1','ya29.token-1']);
    clock += 59_000; expect(await access()).toBe('ya29.token-1');
    clock += 2_000; expect(await access()).toBe('ya29.token-2');
    const spoofed = metadataAccessToken({ async request() { return json(200,{access_token:'ya29.x',expires_in:60}); } });
    await expect(spoofed()).rejects.toThrow(/^Storage credentials are unavailable\.$/);
  });
});
