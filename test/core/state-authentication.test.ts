import { createHash, randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createStateCipher, createStateStore, StateCorruptError, StateLockedError } from '../../src/core/store.js';
import { openBytes, sealBytes } from '../../src/security/index.js';
import { getProjectId } from '../../src/vault/keys.js';
import { createEnvVault } from '../../src/vault/backends/env.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import type { JournalEntry } from '../../src/types.js';

const directories: string[] = [];
afterEach(async () => {
  for (const path of directories.splice(0)) await rm(path, { recursive: true, force: true });
});

async function fixture() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-state-auth-'));
  directories.push(cwd);
  const vault = createFakeVault();
  const projectId = await getProjectId(join(cwd, '.keysentry'));
  const key = randomBytes(32);
  const cipher = createStateCipher(key);
  const options = { cwd, cipher, vault, projectId };
  return { cwd, vault, projectId, key, cipher, options, store: createStateStore(options) };
}

const first: JournalEntry = { at: '2026-10-27T12:00:00.000Z', planId: 'plan-one', event: 'plan-start' };
const second: JournalEntry = { ...first, event: 'value-stored', clusterId: 'c1', data: { oldKeyRef: 'key_live_production' } };
const third: JournalEntry = { ...first, event: 'grace-start', clusterId: 'c1', data: { deadline: '2026-10-27T12:01:00.000Z' } };

describe('authenticated saved state (M3)', () => {
  // Adapted from tools/probes/phase1/plaintext-state-downgrade.test.ts.
  it('rejects a plaintext plan written over an encrypted one and preserves the replacement', async () => {
    const { store } = await fixture();
    const path = join(store.paths.plans, 'plan-20261027120000-abcd.json');
    await store.writeJson('plan', path, { id: 'plan-20261027120000-abcd', steps: [] });
    const forged = JSON.stringify({ id: 'plan-20261027120000-abcd', steps: [{ forged: true }] });
    await writeFile(path, forged);
    await expect(store.readJson('plan', path)).rejects.toBeInstanceOf(StateLockedError);
    await expect(store.readJson('plan', path)).rejects.toThrow("An unencrypted file appeared in keysentry's saved state: plans/plan-20261027120000-abcd.json.");
    await expect(store.writeJson('plan', path, {}, { replaceUndecryptable: true })).rejects.toBeInstanceOf(StateLockedError);
    await store.migratePlaintext();
    expect(await readFile(path, 'utf8')).toBe(forged);
  });

  // Adapted from tools/probes/phase1/plaintext-state-downgrade.test.ts.
  it('rejects a forged plaintext journal without reading, appending or re-encrypting it', async () => {
    const { store } = await fixture();
    await store.journal().append(first);
    const forged = [first, second, third].map(entry => JSON.stringify(entry)).join('\n') + '\n';
    await writeFile(store.paths.journal, forged);
    await expect(store.journal().read(first.planId)).rejects.toBeInstanceOf(StateLockedError);
    await expect(store.journal().append(third)).rejects.toBeInstanceOf(StateLockedError);
    expect(await store.migratePlaintext()).toEqual({ migrated: [] });
    expect(await readFile(store.paths.journal, 'utf8')).toBe(forged);
  });

  it('accepts legacy plaintext only through explicit migration before the vault marker exists', async () => {
    const { store, vault, projectId, options } = await fixture();
    await writeFile(store.paths.inventory, '{"legacy":true}');
    await expect(store.loadInventory()).rejects.toBeInstanceOf(StateLockedError);
    expect(await vault.get(`project/${projectId}/state-initialized`)).toBeNull();
    expect(await store.migratePlaintext()).toEqual({ migrated: ['inventory.json'] });
    expect(await store.loadInventory()).toEqual({ legacy: true });
    expect(await vault.get(`project/${projectId}/state-initialized`)).not.toBeNull();
    await writeFile(store.paths.monitor, '{"forged":true}');
    const reopened = createStateStore(options);
    expect(await reopened.migratePlaintext()).toEqual({ migrated: [] });
    await expect(reopened.readJson('monitor', store.paths.monitor)).rejects.toBeInstanceOf(StateLockedError);
    expect(await readFile(store.paths.monitor, 'utf8')).toBe('{"forged":true}');
  });

  it('keeps the initialized marker after all encrypted files have been removed', async () => {
    const { store, options, vault, projectId } = await fixture();
    await store.writeJson('inventory', store.paths.inventory, {});
    expect(await vault.get(`project/${projectId}/state-initialized`)).not.toBeNull();
    await rm(store.paths.inventory);
    await writeFile(store.paths.monitor, '{"forged":true}');
    const reopened = createStateStore(options);
    expect(await reopened.migratePlaintext()).toEqual({ migrated: [] });
    await expect(reopened.readJson('monitor', store.paths.monitor)).rejects.toThrow(/not written by keysentry.*state reset/i);
  });

  it('retries persisting the marker after a temporary vault write failure', async () => {
    const { store, vault, projectId } = await fixture();
    const set = vault.set.bind(vault);
    let fail = true;
    vault.set = async (name, value) => {
      if (name === `project/${projectId}/state-initialized` && fail) {
        fail = false;
        throw new Error('The vault is temporarily unavailable.');
      }
      return set(name, value);
    };
    await expect(store.writeJson('inventory', store.paths.inventory, {})).rejects.toThrow(/vault/);
    expect(await vault.get(`project/${projectId}/state-initialized`)).toBeNull();
    await expect(readFile(store.paths.inventory)).rejects.toMatchObject({ code: 'ENOENT' });
    await store.writeJson('inventory', store.paths.inventory, { retried: true });
    expect(await vault.get(`project/${projectId}/state-initialized`)).not.toBeNull();
    expect(await store.loadInventory()).toEqual({ retried: true });
  });

  it('does not initialize migration when its verified temporary output fails', async () => {
    const { store, options, cipher, vault, projectId } = await fixture();
    const legacy = '{"legacy":true}';
    await writeFile(store.paths.inventory, legacy);
    const broken = createStateStore({ ...options, cipher: { seal: cipher.seal, open: () => Buffer.from('{}') } });
    await expect(broken.migratePlaintext()).rejects.toThrow(/verif|migrat/i);
    expect(await vault.get(`project/${projectId}/state-initialized`)).toBeNull();
    expect(await readFile(store.paths.inventory, 'utf8')).toBe(legacy);
    expect(await store.migratePlaintext()).toEqual({ migrated: ['inventory.json'] });
  });

  it('closes migration after its first committed file even if a later legacy file fails', async () => {
    const { store, options, vault, projectId } = await fixture();
    await writeFile(store.paths.inventory, '{"legacy":true}');
    await writeFile(store.paths.journal, 'incomplete legacy record\n');
    await expect(store.migratePlaintext()).rejects.toBeInstanceOf(StateCorruptError);
    expect(await readFile(store.paths.inventory, 'utf8')).toMatch(/^keysentry-encrypted:v1\n/);
    expect(await vault.get(`project/${projectId}/state-initialized`)).not.toBeNull();
    await writeFile(store.paths.journal, JSON.stringify({ ...first, event: 'revoked' }) + '\n');
    const reopened = createStateStore(options);
    expect(await reopened.migratePlaintext()).toEqual({ migrated: [] });
    await expect(reopened.journal().read()).rejects.toBeInstanceOf(StateLockedError);
  });

  it('allows project metadata to remain plaintext and rejects arbitrary new plaintext state paths', async () => {
    const { store, projectId } = await fixture();
    await store.writeJson('inventory', store.paths.inventory, {});
    expect(await store.readJson('legacy', join(store.paths.dir, 'project.json'))).toEqual({ id: projectId });
    const path = join(store.paths.dir, 'nested', 'unexpected.json');
    await mkdir(join(store.paths.dir, 'nested'));
    await writeFile(path, '{"forged":true}');
    await expect(store.readJson('legacy', path)).rejects.toThrow(/nested\/unexpected\.json/);
  });

  it('binds a project directory to its first project id without changing that binding on mismatch', async () => {
    const { store, options, cwd, vault, projectId } = await fixture();
    await store.loadInventory();
    const name = `projects/by-path/${createHash('sha256').update(resolve(cwd)).digest('hex').slice(0, 32)}`;
    expect((await vault.get(name))?.toString()).toBe(projectId);
    const changedId = '0123456789abcdef';
    await writeFile(join(store.paths.dir, 'project.json'), JSON.stringify({ id: changedId }));
    const copied = createStateStore({ ...options, projectId: changedId });
    await expect(copied.loadInventory()).rejects.toThrow(/project\.json.*changed or copied from another project/i);
    await expect(copied.migratePlaintext()).rejects.toThrow(/project\.json/);
    expect((await vault.get(name))?.toString()).toBe(projectId);
    expect(await readFile(join(store.paths.dir, 'project.json'), 'utf8')).toBe(JSON.stringify({ id: changedId }));
  });

  it('rejects a changed project.json even if the caller retains the previous project id', async () => {
    const { store, options } = await fixture();
    await store.loadInventory();
    await writeFile(join(store.paths.dir, 'project.json'), '{"id":"0123456789abcdef"}');
    await expect(createStateStore(options).loadInventory()).rejects.toThrow(/project\.json.*changed or copied/i);
  });

  it.skipIf(process.platform !== 'win32')('does not let Windows path casing create a new project binding', async () => {
    const { store, options, cwd } = await fixture();
    await store.loadInventory();
    const changedId = '0123456789abcdef';
    await writeFile(join(store.paths.dir, 'project.json'), JSON.stringify({ id: changedId }));
    await writeFile(store.paths.inventory, '{"forged":true}');
    const alias = createStateStore({ ...options, cwd: cwd.toUpperCase(), projectId: changedId });
    await expect(alias.migratePlaintext()).rejects.toThrow(/project\.json.*changed or copied/i);
    expect(await readFile(store.paths.inventory, 'utf8')).toBe('{"forged":true}');
  });

  it('does not let a symlink or junction create a new binding for an existing project', async () => {
    const { store, options, cwd } = await fixture();
    await store.loadInventory();
    const aliasRoot = await mkdtemp(join(tmpdir(), 'keysentry-project-alias-'));
    directories.push(aliasRoot);
    const aliasPath = join(aliasRoot, 'project');
    await symlink(cwd, aliasPath, process.platform === 'win32' ? 'junction' : 'dir');
    const changedId = '0123456789abcdef';
    await writeFile(join(store.paths.dir, 'project.json'), JSON.stringify({ id: changedId }));
    await writeFile(store.paths.inventory, '{"forged":true}');
    const alias = createStateStore({ ...options, cwd: aliasPath, projectId: changedId });
    await expect(alias.migratePlaintext()).rejects.toThrow(/project\.json.*changed or copied/i);
    expect(await readFile(store.paths.inventory, 'utf8')).toBe('{"forged":true}');
  });

  it('uses preconfigured binding and marker metadata without writing to a read-only environment vault', async () => {
    const { cwd, projectId, cipher } = await fixture();
    const pathHash = createHash('sha256').update(resolve(cwd)).digest('hex').slice(0, 32).toUpperCase();
    const vault = createEnvVault({
      [`KEYSENTRY_VAULT_PROJECTS_BY_PATH_${pathHash}`]: projectId,
      [`KEYSENTRY_VAULT_PROJECT_${projectId.toUpperCase()}_STATE_INITIALIZED`]: '1',
    });
    const store = createStateStore({ cwd, cipher, vault, projectId });
    await store.writeJson('inventory', store.paths.inventory, { scanned: true });
    expect(await store.loadInventory()).toEqual({ scanned: true });
    await store.journal().append(first);
    expect(await store.journal().read()).toEqual([first]);
  });

  it('authenticates the kind and forward-slash relative path with the v2 AAD', async () => {
    const { store, key } = await fixture();
    const path = join(store.paths.plans, 'plan-a.json');
    await store.writeJson('plan', path, { id: 'plan-a' });
    const content = await readFile(path, 'utf8');
    const sealed = Buffer.from(content.split('\n')[1]!, 'base64');
    expect(JSON.parse(openBytes(key, sealed, 'keysentry-state:v2:plan:plans/plan-a.json').toString())).toEqual({ id: 'plan-a' });
    const other = join(store.paths.plans, 'plan-b.json');
    await writeFile(other, content);
    await expect(store.readJson('plan', other)).rejects.toBeInstanceOf(StateLockedError);
    await expect(store.readJson('monitor', path)).rejects.toBeInstanceOf(StateLockedError);
    await expect(store.writeJson('plan', other, {})).rejects.toBeInstanceOf(StateLockedError);
    expect(await readFile(other, 'utf8')).toBe(content);
  });

  it('does not fall back to the unreleased v1 AAD', async () => {
    const { store, key } = await fixture();
    const old = sealBytes(key, Buffer.from('{"legacy":true}'), 'keysentry-state:inventory').toString('base64');
    await writeFile(store.paths.inventory, `keysentry-encrypted:v1\n${old}\n`);
    await expect(store.loadInventory()).rejects.toBeInstanceOf(StateLockedError);
  });
});

describe('authenticated journal chain (M3)', () => {
  it('seals each record number and the previous sealed line hash', async () => {
    const { store, key } = await fixture();
    await store.journal().append(first);
    await store.journal().append(second);
    const lines = (await readFile(store.paths.journal, 'utf8')).split('\n');
    const records = lines.slice(1, 3).map(line => JSON.parse(openBytes(key, Buffer.from(line, 'base64'), 'keysentry-state:v2:journal:journal.jsonl').toString()));
    expect(records[0]).toMatchObject({ n: 1, prev: '0'.repeat(64) });
    expect(records[1]).toMatchObject({ n: 2, prev: createHash('sha256').update(lines[1]!).digest('hex') });
    expect(await store.journal().read()).toEqual([first, second]);
  });

  it.each(['reorder', 'delete', 'swap'] as const)('rejects %s of authenticated records with the first affected physical line', async action => {
    const { store } = await fixture();
    for (const entry of [first, second, third]) await store.journal().append(entry);
    const lines = (await readFile(store.paths.journal, 'utf8')).split('\n');
    if (action === 'reorder') [lines[2], lines[3]] = [lines[3]!, lines[2]!];
    else if (action === 'delete') lines.splice(2, 1);
    else lines[2] = lines[1]!;
    const modified = lines.join('\n');
    await writeFile(store.paths.journal, modified);
    await expect(store.journal().read()).rejects.toBeInstanceOf(StateCorruptError);
    await expect(store.journal().read(first.planId)).rejects.toMatchObject({ line: 3, code: 'STATE_CORRUPT' });
    await expect(store.journal().append(first)).rejects.toMatchObject({ line: 3 });
    expect(await readFile(store.paths.journal, 'utf8')).toBe(modified);
  });

  it('rejects a same-number record from a different valid journal history', async () => {
    const { store } = await fixture();
    for (const entry of [first, second, third]) await store.journal().append(entry);
    const original = (await readFile(store.paths.journal, 'utf8')).split('\n');
    await rm(store.paths.journal);
    for (const entry of [second, first, third]) await store.journal().append(entry);
    const foreign = (await readFile(store.paths.journal, 'utf8')).split('\n');
    original[2] = foreign[2]!;
    await writeFile(store.paths.journal, original.join('\n'));
    await expect(store.journal().read()).rejects.toMatchObject({ line: 3, code: 'STATE_CORRUPT' });
  });
});
