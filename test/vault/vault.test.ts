import { afterEach, expect, test, vi } from 'vitest';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createEncryptedFileVault, createEnvVault, createMemoryVault,
  validateVaultName, VaultLockedError, VaultReadOnlyError,
} from '../../src/vault/index.js';

const dirs: string[] = [];
afterEach(async () => { vi.restoreAllMocks(); await Promise.all(dirs.splice(0).map(d => rm(d, { recursive: true, force: true }))); });
async function file() { const dir = await mkdtemp(join(tmpdir(), 'keysentry-vault-')); dirs.push(dir); return join(dir, 'vault.enc'); }
const scrypt = { N: 1024, r: 8, p: 1 };

test('memory vault round-trips and lists by prefix without sharing caller buffers', async () => {
  const vault = createMemoryVault();
  const input = Buffer.from('credential-value');
  await vault.set('cred/B', input);
  input.fill(0);
  await vault.set('cred/A', Buffer.from('a'));
  await vault.set('key/state', Buffer.from('b'));
  expect(await vault.list('cred/')).toEqual(['cred/A', 'cred/B']);
  const value = (await vault.get('cred/B'))!;
  expect(value.toString()).toBe('credential-value');
  value.fill(0);
  expect((await vault.get('cred/B'))!.toString()).toBe('credential-value');
  expect(await vault.delete('cred/B')).toBe(true);
  expect(await vault.delete('cred/B')).toBe(false);
  expect(await vault.get('absent')).toBeNull();
});

test.each(['', 'with space', 'quote"', "quote'", 'line\n', 'é', 'x'.repeat(201)])('vault names reject invalid input %j', name => {
  expect(() => validateVaultName(name)).toThrow(TypeError);
});
test('vault names accept all contract characters', () => {
  expect(() => validateVaultName('A-z/0_.@#-')).not.toThrow();
});

test('env vault maps names and refuses writes', async () => {
  const key = Buffer.alloc(32, 7);
  const vault = createEnvVault({
    RAILWAY_TOKEN: 'write-token', RAILWAY_TOKEN_READ: 'read-token',
    KEYSENTRY_STATE_KEY: key.toString('base64'), KEYSENTRY_FINGERPRINT_KEY: key.toString('base64'),
    KEYSENTRY_DEVICE_KEY: key.toString('base64'), KEYSENTRY_VAULT_CUSTOM_NAME: 'custom',
  });
  expect((await vault.get('cred/RAILWAY_TOKEN'))!.toString()).toBe('write-token');
  expect((await vault.get('cred/RAILWAY_TOKEN@read'))!.toString()).toBe('read-token');
  for (const name of ['key/state', 'project/p/key/state', 'project/p/key/fingerprint', 'key/device-ed25519']) {
    expect(await vault.get(name)).toEqual(key);
  }
  expect((await vault.get('custom/name'))!.toString()).toBe('custom');
  expect(await vault.get('missing')).toBeNull();
  expect(vault.weakness).toBe('Keys come from environment variables, which other programs started by the same user can read.');
  await expect(vault.set('cred/A', key)).rejects.toBeInstanceOf(VaultReadOnlyError);
  await expect(vault.delete('cred/A')).rejects.toMatchObject({ code: 'VAULT_READ_ONLY' });
  expect(await vault.list('cred/')).toContain('cred/RAILWAY_TOKEN');
});

test('env vault in-flight names work in process memory', async () => {
  const vault = createEnvVault({});
  const name = 'project/p/inflight/plan-1';
  await vault.set(name, Buffer.alloc(32, 4));
  expect(await vault.get(name)).toEqual(Buffer.alloc(32, 4));
  expect(await vault.list('project/p/inflight/')).toEqual([name]);
  expect(await vault.delete(name)).toBe(true);
  expect(await vault.delete(name)).toBe(false);
  expect(await vault.get(name)).toBeNull();
  expect(await createEnvVault({}).get(name)).toBeNull();
});

test('env list does not invent aliases for unrelated process environment variables', async () => {
  const vault = createEnvVault({ PATH: 'bin', RAILWAY_TOKEN: 'token', RAILWAY_TOKEN_READ: 'read' });
  expect(await vault.list('cred/')).toEqual(['cred/RAILWAY_TOKEN', 'cred/RAILWAY_TOKEN@read']);
});

test('encrypted-file vault round-trips and never contains the plaintext or its base64', async () => {
  const path = await file();
  const passphrase = vi.fn(async () => Buffer.from('a passphrase'));
  const vault = createEncryptedFileVault({ path, passphrase, scrypt });
  const value = Buffer.from('a-long-private-credential-value');
  await vault.set('cred/TEST', value);
  await vault.set('key/state', Buffer.alloc(32, 4));
  expect(await vault.get('cred/TEST')).toEqual(value);
  expect(await vault.list('cred/')).toEqual(['cred/TEST']);
  const raw = await readFile(path, 'utf8');
  expect(raw).not.toContain(value.toString());
  expect(raw).not.toContain(value.toString('base64'));
  const data = JSON.parse(raw);
  expect(data.v).toBe(1);
  expect(Buffer.from(data.salt, 'base64')).toHaveLength(16);
  expect(data.params).toEqual(scrypt);
  expect(typeof data.check).toBe('string');
  expect(passphrase).toHaveBeenCalledTimes(1);
  if (process.platform !== 'win32') expect((await stat(path)).mode & 0o777).toBe(0o600);
  const reopened = createEncryptedFileVault({ path, passphrase: async () => Buffer.from('a passphrase') });
  expect(await reopened.get('cred/TEST')).toEqual(value);
  expect(await reopened.delete('cred/TEST')).toBe(true);
  expect(await reopened.delete('cred/TEST')).toBe(false);
  expect(await reopened.get('cred/TEST')).toBeNull();
});

test('encrypted-file vault rejects a wrong passphrase with VaultLockedError before touching entries', async () => {
  const path = await file();
  const vault = createEncryptedFileVault({ path, passphrase: async () => Buffer.from('right'), scrypt });
  await vault.set('cred/TEST', Buffer.from('private-value'));
  const before = await readFile(path);
  const wrong = createEncryptedFileVault({ path, passphrase: async () => Buffer.from('wrong') });
  await expect(wrong.list()).rejects.toBeInstanceOf(VaultLockedError);
  await expect(wrong.set('cred/NEW', Buffer.from('value'))).rejects.toMatchObject({ code: 'VAULT_LOCKED' });
  expect(await readFile(path)).toEqual(before);
});

test('encrypted-file empty vault still checks its passphrase', async () => {
  const path = await file();
  const vault = createEncryptedFileVault({ path, passphrase: async () => Buffer.from('right'), scrypt });
  await vault.set('item', Buffer.from('v'));
  await vault.delete('item');
  const wrong = createEncryptedFileVault({ path, passphrase: async () => Buffer.from('wrong') });
  await expect(wrong.get('missing')).rejects.toBeInstanceOf(VaultLockedError);
});

test('encrypted-file serializes concurrent writes', async () => {
  const path = await file();
  const vault = createEncryptedFileVault({ path, passphrase: async () => Buffer.from('right'), scrypt });
  await Promise.all(Array.from({ length: 12 }, (_, i) => vault.set(`item/${i}`, Buffer.from(String(i)))));
  expect(await vault.list()).toHaveLength(12);
  const next = createEncryptedFileVault({ path, passphrase: async () => Buffer.from('right') });
  expect(await next.list()).toHaveLength(12);
});

test('separate encrypted-file instances preserve writes and cannot resurrect deleted in-flight keys', async () => {
  const path = await file();
  const passphrase = vi.fn(async () => Buffer.from('right'));
  const first = createEncryptedFileVault({ path, passphrase, scrypt });
  const second = createEncryptedFileVault({ path, passphrase, scrypt });
  const name = 'project/p/inflight/plan';
  await first.set(name, Buffer.alloc(32, 8));
  expect(await second.get(name)).toEqual(Buffer.alloc(32, 8));
  await second.set('second', Buffer.from('value'));
  await first.set('first', Buffer.from('value'));
  expect(await first.get('second')).toEqual(Buffer.from('value'));
  await second.delete(name);
  await first.set('another', Buffer.from('value'));
  expect(await first.get(name)).toBeNull();
  expect(await second.get(name)).toBeNull();
  expect(passphrase).toHaveBeenCalledTimes(2);
});

test('separate encrypted-file instances serialize simultaneous writes', async () => {
  const path = await file();
  const create = () => createEncryptedFileVault({ path, passphrase: async () => Buffer.from('right'), scrypt });
  const instances = Array.from({ length: 6 }, create);
  await Promise.all(instances.map((vault, i) => vault.set(`item/${i}`, Buffer.from(String(i)))));
  expect(await create().list()).toHaveLength(6);
});

test('an abandoned encrypted-file lock fails closed and explains manual recovery', async () => {
  const path = await file();
  const lockPath = `${path}.lock`;
  await writeFile(lockPath, JSON.stringify({ pid: 123456 }));
  vi.spyOn(process, 'kill').mockImplementation(() => { throw Object.assign(new Error('gone'), { code: 'ESRCH' }); });
  const vault = createEncryptedFileVault({ path, passphrase: async () => Buffer.from('right'), scrypt });
  await expect(vault.get('item')).rejects.toThrow('remove');
  await expect(vault.get('item')).rejects.toThrow(lockPath);
  expect(await readFile(lockPath, 'utf8')).toBe('{"pid":123456}');
});

test('encrypted-file rejects a modified entry without exposing plaintext', async () => {
  const path = await file();
  await createEncryptedFileVault({ path, passphrase: async () => Buffer.from('right'), scrypt }).set('item', Buffer.from('private-value'));
  const data = JSON.parse(await readFile(path, 'utf8'));
  const entry = Buffer.from(data.entries.item, 'base64');
  entry[entry.length - 1] ^= 1;
  data.entries.item = entry.toString('base64');
  await writeFile(path, JSON.stringify(data));
  const vault = createEncryptedFileVault({ path, passphrase: async () => Buffer.from('right') });
  await expect(vault.get('item')).rejects.toMatchObject({ code: 'VAULT_LOCKED' });
});
