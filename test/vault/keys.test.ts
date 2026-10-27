import { afterEach, expect, test } from 'vitest';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createEnvVault, deleteInflightKey, deviceKey, fingerprintKey, getOrCreateKey, getProjectId, inflightKey, stateKey, VaultReadOnlyError } from '../../src/vault/index.js';
import { signDetached, verifyDetached } from '../../src/security/index.js';

const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map(d => rm(d, { recursive: true, force: true }))); });
async function dir() { const d = await mkdtemp(join(tmpdir(), 'keysentry-keys-')); dirs.push(d); return d; }

test('project id is persistent and sixteen random hex characters', async () => {
  const root = await dir();
  const ids = await Promise.all(Array.from({ length: 8 }, () => getProjectId(root)));
  expect(new Set(ids).size).toBe(1);
  expect(ids[0]).toMatch(/^[a-f0-9]{16}$/);
  expect(JSON.parse(await readFile(join(root, 'project.json'), 'utf8'))).toEqual({ id: ids[0] });
  expect(await readdir(root)).toEqual(['project.json']);
});

test('malformed project metadata is left untouched rather than assigning a different identity', async () => {
  const root = await dir();
  await writeFile(join(root, 'project.json'), '{incomplete');
  await expect(getProjectId(root)).rejects.toThrow('project identifier file is invalid');
  expect(await readFile(join(root, 'project.json'), 'utf8')).toBe('{incomplete');
});
test('getOrCreateKey and stateKey reuse keys and isolate projects', async () => {
  const vault = createFakeVault();
  const values = await Promise.all(Array.from({ length: 8 }, () => stateKey(vault, 'a')));
  expect(values.every(value => value.equals(values[0]!))).toBe(true);
  expect(values[0]).toHaveLength(32);
  expect(await stateKey(vault, 'b')).not.toEqual(values[0]);
  expect(await getOrCreateKey(vault, 'short', 16)).toHaveLength(16);
});
test.each([
  ['project/a/key/state', 'KEYSENTRY_STATE_KEY'],
  ['project/a/key/fingerprint', 'KEYSENTRY_FINGERPRINT_KEY'],
  ['key/custom', 'KEYSENTRY_VAULT_KEY_CUSTOM'],
])('missing read-only key %s explains which environment variable to set', async (name, variable) => {
  const result = getOrCreateKey(createEnvVault({}), name);
  await expect(result).rejects.toBeInstanceOf(VaultReadOnlyError);
  await expect(result).rejects.toThrow(variable);
  await expect(result).rejects.toThrow(`node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`);
});
test('legacy fingerprint.key is imported byte-for-byte and the file removed', async () => {
  const legacyFile = join(await dir(), 'fingerprint.key');
  const legacy = Buffer.alloc(32, 19);
  await writeFile(legacyFile, legacy);
  const vault = createFakeVault();
  expect(await fingerprintKey(vault, 'first', legacyFile)).toEqual(legacy);
  expect(await vault.get('key/fingerprint-legacy')).toEqual(legacy);
  expect(await vault.get('project/first/key/fingerprint')).toEqual(legacy);
  await expect(readFile(legacyFile)).rejects.toMatchObject({ code: 'ENOENT' });
  expect(await fingerprintKey(vault, 'second', legacyFile)).toEqual(legacy);
});
test('legacy fingerprint file stays until both copies are read back correctly', async () => {
  const legacyFile = join(await dir(), 'fingerprint.key');
  const legacy = Buffer.alloc(32, 12);
  await writeFile(legacyFile, legacy);
  const vault = createFakeVault();
  vault.get = async () => null;
  await expect(fingerprintKey(vault, 'p', legacyFile)).rejects.toThrow();
  expect(await readFile(legacyFile)).toEqual(legacy);
});
test('an existing fingerprint project key wins over the legacy key', async () => {
  const project = Buffer.alloc(32, 1);
  const vault = createFakeVault({ 'project/p/key/fingerprint': project, 'key/fingerprint-legacy': Buffer.alloc(32, 2) });
  expect(await fingerprintKey(vault, 'p')).toEqual(project);
});
test('invalid legacy key is not removed', async () => {
  const legacyFile = join(await dir(), 'fingerprint.key');
  await writeFile(legacyFile, Buffer.alloc(31));
  await expect(fingerprintKey(createFakeVault(), 'p', legacyFile)).rejects.toThrow();
  expect(await readFile(legacyFile)).toHaveLength(31);
});
test('device key is persistent and signs with its derived public key', async () => {
  const vault = createFakeVault();
  const first = await deviceKey(vault);
  const second = await deviceKey(vault);
  expect(second).toEqual(first);
  const msg = Buffer.from('message');
  expect(verifyDetached(second.publicKeyDer, msg, signDetached(first.privateKeyDer, msg))).toBe(true);
});
test('in-flight key is per project and plan and delete returns whether it existed', async () => {
  const vault = createFakeVault();
  expect(await inflightKey(vault, 'p', 'plan', false)).toBeNull();
  const key = await inflightKey(vault, 'p', 'plan', true);
  expect(key).toHaveLength(32);
  expect(await vault.get('project/p/inflight/plan')).toEqual(key);
  expect(await inflightKey(vault, 'p', 'plan', false)).toEqual(key);
  expect(await deleteInflightKey(vault, 'p', 'plan')).toBe(true);
  expect(await deleteInflightKey(vault, 'p', 'plan')).toBe(false);
});

test('read-only env backend can provide and delete in-flight keys', async () => {
  const vault = createEnvVault({});
  const key = await inflightKey(vault, 'p', 'plan', true);
  expect(key).toHaveLength(32);
  expect(await inflightKey(vault, 'p', 'plan', false)).toEqual(key);
  expect(await deleteInflightKey(vault, 'p', 'plan')).toBe(true);
});
