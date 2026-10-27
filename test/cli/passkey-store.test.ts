import { afterEach, expect, test, vi } from 'vitest';
import { mkdtemp, mkdir, readFile, readdir, rm, unlink, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createStateCipher, createStateStore } from '../../src/core/store.js';
import { listPasskeys } from '../../src/cli/passkeys.js';
import { createPasskeyStore } from '../../src/cli/passkey-store.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import type { PasskeyCredential } from '../../src/types.js';

const dirs: string[] = [];
afterEach(async () => { vi.restoreAllMocks(); await Promise.all(dirs.splice(0).map(dir => rm(dir, { recursive: true, force: true }))); });
async function setup() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-passkey-store-')); dirs.push(cwd);
  const store = createStateStore({ cwd, cipher: createStateCipher(Buffer.alloc(32, 3)) });
  return { cwd, store, path: join(store.paths.dir, 'passkeys.json') };
}
function credential(id = Buffer.from('credential').toString('base64url')): PasskeyCredential {
  return { id, publicKeyCose: Buffer.from('public-key').toString('base64url'), alg: -8, signCount: 0,
    backupEligible: false, rpId: 'localhost', origins: ['http://localhost'], label: 'My laptop', createdAt: '2026-10-27T00:00:00.000Z' };
}

test('legacy plaintext passkeys migrate once and later plaintext is refused', async () => {
  const { store, path } = await setup();
  await mkdir(store.paths.dir, { recursive: true });
  await writeFile(path, JSON.stringify({ v: 1, credentials: [credential()] }));
  await store.migratePlaintext();
  expect(await listPasskeys(store)).toEqual([credential()]);
  expect(await readFile(path, 'utf8')).toMatch(/^keysentry-encrypted:v1/);
  await writeFile(path, JSON.stringify({ v: 1, credentials: [credential()] }));
  await store.migratePlaintext();
  await expect(listPasskeys(store)).rejects.toThrow(/unencrypted|plaintext|encrypted/i);
});

test('dashboard vault passkeys migrate into the CLI encrypted store before their vault entries are deleted', async () => {
  const { store, path } = await setup();
  const saved = credential();
  const vault = createFakeVault({ [`passkey/${saved.id}`]: Buffer.from(JSON.stringify(saved)) });
  expect(await listPasskeys(store, vault)).toEqual([saved]);
  expect(await vault.list('passkey/')).toEqual([]);
  expect(await readFile(path, 'utf8')).not.toContain(saved.label);
  expect(await listPasskeys(store)).toEqual([saved]);
});

test('the shared encrypted array accepts a 1023-byte credential id and persists counter updates', async () => {
  const { store, path } = await setup();
  const saved = credential(Buffer.alloc(1023, 7).toString('base64url'));
  const cli = createPasskeyStore(store);
  const dashboard = createPasskeyStore(store);
  await cli.add(saved);
  expect(await store.readJson('passkeys', path)).toEqual([saved]);
  expect(await dashboard.list()).toEqual([saved]);
  await dashboard.update({ ...saved, signCount: 5 });
  expect((await listPasskeys(store))[0]!.signCount).toBe(5);
  await expect(cli.update(saved)).rejects.toThrow('This passkey cannot be saved.');
  expect(await cli.remove(saved.id)).toBe(true);
  expect(await dashboard.list()).toEqual([]);
});

test('the old encrypted CLI wrapper is authenticated and migrated into the shared array', async () => {
  const { store, path } = await setup();
  await store.writeJson('pending', path, { v: 1, credentials: [credential()] });
  expect(await listPasskeys(store)).toEqual([credential()]);
  expect(await store.readJson('passkeys', path)).toEqual([credential()]);
});

test('legacy CLI registration remains available across random localhost dashboard ports', async () => {
  const { store, path } = await setup();
  const old = { ...credential(), origins: ['http://localhost:38493'] };
  await store.writeJson('pending', path, { v: 1, credentials: [old] });
  expect((await listPasskeys(store))[0]!.origins).toEqual(['http://localhost:38493', 'http://localhost']);
});

test('migrating a public-origin CLI credential does not grant localhost access', async () => {
  const { store, path } = await setup();
  const old = { ...credential(), rpId: 'approvals.example.org', origins: ['https://approvals.example.org'] };
  await store.writeJson('pending', path, { v: 1, credentials: [old] });
  expect((await listPasskeys(store))[0]!.origins).toEqual(old.origins);
});

test('vault migration keeps its source when the encrypted write fails', async () => {
  const { store } = await setup();
  const saved = credential();
  const name = `passkey/${saved.id}`;
  const vault = createFakeVault({ [name]: Buffer.from(JSON.stringify(saved)) });
  const failing = { ...store, writeJson: async () => { throw new Error('Write failed'); } };
  await expect(createPasskeyStore(failing, vault).list()).rejects.toThrow('Write failed');
  expect(await vault.list('passkey/')).toEqual([name]);
  expect(await createPasskeyStore(store, vault).list()).toEqual([saved]);
});

test('a migrated vault duplicate never decreases the saved counter or replaces the public key', async () => {
  const { store } = await setup();
  const saved = credential();
  const shared = createPasskeyStore(store);
  await shared.add({ ...saved, signCount: 8 });
  const vault = createFakeVault({ [`passkey/${saved.id}`]: Buffer.from(JSON.stringify(saved)) });
  expect((await createPasskeyStore(store, vault).list())[0]!.signCount).toBe(8);
  await vault.set(`passkey/${saved.id}`, Buffer.from(JSON.stringify({ ...saved, publicKeyCose: 'YW5vdGhlcg' })));
  await expect(createPasskeyStore(store, vault).list()).rejects.toThrow('Saved passkeys could not be read.');
  expect(await vault.list('passkey/')).toEqual([`passkey/${saved.id}`]);
  expect(await shared.list()).toEqual([{ ...saved, signCount: 8 }]);
});

test('stores sharing a state path serialize concurrent credential additions', async () => {
  const { store } = await setup();
  const first = createPasskeyStore(store);
  const second = createPasskeyStore(store);
  const a = credential('YWJj'); const b = credential('ZGVm');
  await Promise.all([first.add(a), second.add(b)]);
  expect(await first.list()).toEqual([a, b]);
});

test('independent store modules serialize removal against an in-flight dashboard counter update', async () => {
  const { store } = await setup();
  const saved = credential();
  await createPasskeyStore(store).add(saved);
  let loaded!: () => void; let release!: () => void;
  const reached = new Promise<void>(resolve => { loaded = resolve; });
  const gate = new Promise<void>(resolve => { release = resolve; });
  const delayed = { ...store, async readJson<T>(...args: Parameters<typeof store.readJson>): Promise<T | null> {
    const result = await store.readJson<T>(...args);
    loaded(); await gate;
    return result;
  } };
  const dashboard = createPasskeyStore(delayed);
  vi.resetModules();
  const { createPasskeyStore: createIndependentStore } = await import('../../src/cli/passkey-store.js');
  const cli = createIndependentStore(store);
  const update = dashboard.update({ ...saved, signCount: 1 });
  await reached;
  let removedBeforeUpdate = false;
  const remove = cli.remove(saved.id).then(result => { removedBeforeUpdate = true; return result; });
  await Promise.race([remove, new Promise(resolve => setTimeout(resolve, 60))]);
  const raced = removedBeforeUpdate;
  release();
  await Promise.all([update, remove]);
  expect(raced).toBe(false);
  expect(await createPasskeyStore(store).list()).toEqual([]);
});

test('a live owner is never expired and waiting is bounded even for an old lock', async () => {
  const { store } = await setup();
  await mkdir(store.paths.dir, { recursive: true });
  const lock = join(store.paths.dir, '.passkeys.lock');
  const original = JSON.stringify({ pid: process.pid, token: 'live-owner' });
  await writeFile(lock, original);
  await utimes(lock, new Date(0), new Date(0));
  let clock = 1_000_000;
  vi.spyOn(Date, 'now').mockImplementation(() => { clock += 5_000; return clock; });
  await expect(createPasskeyStore(store).list()).rejects.toThrow('Saved passkeys are busy.');
  expect(await readFile(lock, 'utf8')).toBe(original);
  expect((await readdir(store.paths.dir)).filter(name => name.startsWith('.passkey-lock-'))).toEqual([]);
});

test('a dead or malformed lock requires explicit recovery and is never automatically removed', async () => {
  const { store } = await setup();
  await mkdir(store.paths.dir, { recursive: true });
  const lock = join(store.paths.dir, '.passkeys.lock');
  vi.spyOn(process, 'kill').mockImplementation(() => { throw Object.assign(new Error(), { code: 'ESRCH' }); });
  for (const original of [JSON.stringify({ pid: 123456, token: 'dead-owner' }), '{}']) {
    await writeFile(lock, original);
    await expect(createPasskeyStore(store).list()).rejects.toThrow('The passkey lock needs attention.');
    expect(await readFile(lock, 'utf8')).toBe(original);
  }
});

test('a changed lock aborts before saving and cleanup leaves the replacement lock intact', async () => {
  const { store } = await setup();
  const saved = credential();
  await createPasskeyStore(store).add(saved);
  let loaded!: () => void; let release!: () => void;
  const reached = new Promise<void>(resolve => { loaded = resolve; });
  const gate = new Promise<void>(resolve => { release = resolve; });
  const delayed = { ...store, async readJson<T>(...args: Parameters<typeof store.readJson>): Promise<T | null> {
    const result = await store.readJson<T>(...args); loaded(); await gate; return result;
  } };
  const update = createPasskeyStore(delayed).update({ ...saved, signCount: 1 });
  await reached;
  const lock = join(store.paths.dir, '.passkeys.lock');
  await unlink(lock);
  const replacement = JSON.stringify({ pid: process.pid, token: 'replacement' });
  await writeFile(lock, replacement);
  release();
  await expect(update).rejects.toThrow('The passkey lock changed.');
  expect(await readFile(lock, 'utf8')).toBe(replacement);
  await unlink(lock);
  expect(await createPasskeyStore(store).list()).toEqual([saved]);
});
