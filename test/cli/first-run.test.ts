import { afterEach, expect, test, vi } from 'vitest';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runFirstRun, formatFirstRun } from '../../src/cli/first-run.js';
import { createStateCipher, createStateStore } from '../../src/core/store.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createEncryptedFileVault } from '../../src/vault/index.js';
import type { GitRunner } from '../../src/firstrun/index.js';

const roots: string[] = [];
const planted = 'sk-proj-FirstRun0123456789abcdef0123456789';
const git: GitRunner = async () => ({ code: 0 });
async function project() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-cli-first-run-')); roots.push(cwd);
  await writeFile(join(cwd, '.env'), `OPENAI_API_KEY=${planted}\nPORT=3000\n`);
  return cwd;
}
afterEach(async () => { vi.restoreAllMocks(); for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true }); });

test('no-save scans without asking consent, network access, vault or state writes', async () => {
  const cwd = await project();
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(() => { throw new Error('Network is not part of first run.'); });
  const confirmSave = vi.fn(async () => true);
  const { result, saved } = await runFirstRun({ cwd, noSave: true, confirmSave, git });
  expect(result).toMatchObject({ scannedFiles: 1, scannedCommits: 0, historyComplete: true });
  expect(result.findings).toHaveLength(1);
  expect(saved).toBe(false);
  expect(await readdir(cwd)).toEqual(['.env']);
  expect(fetch).not.toHaveBeenCalled();
  expect(confirmSave).not.toHaveBeenCalled();
  expect(JSON.stringify(result)).not.toContain(planted);
});

test('saving requires affirmative consent before the state directory exists', async () => {
  const cwd = await project();
  let checked = false;
  const run = await runFirstRun({ cwd, git, confirmSave: async result => {
    expect(result.findings).toHaveLength(1);
    expect(await readdir(cwd)).toEqual(['.env']); checked = true; return false;
  } });
  expect(checked).toBe(true);
  expect(run.saved).toBe(false);
  expect(await readdir(cwd)).toEqual(['.env']);
});

test('existing project reads its fingerprint key from the injected vault without writing state', async () => {
  const cwd = await project();
  await mkdir(join(cwd, '.keysentry'));
  await writeFile(join(cwd, '.keysentry', 'project.json'), '{"id":"abcdef0123456789"}\n');
  const vault = createFakeVault();
  await vault.set('project/abcdef0123456789/key/fingerprint', Buffer.alloc(32, 13));
  const before = await readFile(join(cwd, '.keysentry', 'project.json'), 'utf8');
  const first = await runFirstRun({ cwd, git, vault, noSave: true });
  const expected = await runFirstRun({ cwd, git, noSave: true, fingerprintKey: Buffer.alloc(32, 13) });
  expect(first.result.findings[0]!.id).toBe(expected.result.findings[0]!.id);
  expect(await readdir(join(cwd, '.keysentry'))).toEqual(['project.json']);
  expect(await readFile(join(cwd, '.keysentry', 'project.json'), 'utf8')).toBe(before);
});

test('existing project can read an environment fingerprint key without opening or probing a vault', async () => {
  const cwd = await project();
  await mkdir(join(cwd, '.keysentry'));
  await writeFile(join(cwd, '.keysentry', 'project.json'), '{"id":"abcdef0123456789"}\n');
  const first = await runFirstRun({ cwd, git, noSave: true, env: { KEYSENTRY_VAULT: 'env', KEYSENTRY_FINGERPRINT_KEY: Buffer.alloc(32, 11).toString('base64') } });
  const expected = await runFirstRun({ cwd, git, noSave: true, fingerprintKey: Buffer.alloc(32, 11) });
  expect(first.result.findings[0]!.id).toBe(expected.result.findings[0]!.id);
  expect(await readdir(join(cwd, '.keysentry'))).toEqual(['project.json']);
});

test('missing existing project key fails without creating one', async () => {
  const cwd = await project();
  await mkdir(join(cwd, '.keysentry'));
  await writeFile(join(cwd, '.keysentry', 'project.json'), '{"id":"abcdef0123456789"}\n');
  const vault = createFakeVault();
  await expect(runFirstRun({ cwd, git, noSave: true, vault })).rejects.toThrow(/fingerprint key/);
  expect(await vault.list()).toEqual([]);
  expect(await readdir(join(cwd, '.keysentry'))).toEqual(['project.json']);
});

test('remembered encrypted vault is read without creating locks or rewriting vault and state', async () => {
  const cwd = await project();
  const userDir = join(cwd, 'user');
  await mkdir(join(cwd, '.keysentry'));
  await mkdir(userDir);
  await writeFile(join(cwd, '.keysentry', 'project.json'), '{"id":"abcdef0123456789"}\n');
  await writeFile(join(userDir, 'vault-backend.json'), '{"backend":"encrypted-file"}\n');
  const path = join(userDir, 'vault.enc');
  const vault = createEncryptedFileVault({ path, passphrase: async () => Buffer.from('test-passphrase'), scrypt: { N: 1024, r: 8, p: 1 } });
  await vault.set('project/abcdef0123456789/key/fingerprint', Buffer.alloc(32, 15));
  const before = await readFile(path, 'utf8');
  const result = await runFirstRun({ cwd, git, noSave: true, userDir, env: {}, passphrase: async () => Buffer.from('test-passphrase') });
  const expected = await runFirstRun({ cwd, git, noSave: true, fingerprintKey: Buffer.alloc(32, 15) });
  expect(result.result.findings[0]!.id).toBe(expected.result.findings[0]!.id);
  expect((await readdir(userDir)).sort()).toEqual(['vault-backend.json', 'vault.enc']);
  expect(await readFile(path, 'utf8')).toBe(before);
  expect(await readdir(join(cwd, '.keysentry'))).toEqual(['project.json']);
});

test('an existing encrypted-vault selection never initializes a missing vault', async () => {
  const cwd = await project();
  const userDir = join(cwd, 'absent-user');
  await mkdir(join(cwd, '.keysentry'));
  await writeFile(join(cwd, '.keysentry', 'project.json'), '{"id":"abcdef0123456789"}\n');
  await expect(runFirstRun({ cwd, git, noSave: true, userDir, env: { KEYSENTRY_VAULT: 'encrypted-file' }, passphrase: async () => Buffer.from('test-passphrase') })).rejects.toThrow(/fingerprint key/);
  expect((await readdir(cwd)).sort()).toEqual(['.env', '.keysentry']);
});

test('wrong encrypted-vault passphrase fails calmly and preserves the vault', async () => {
  const cwd = await project(); const userDir = join(cwd, 'user');
  await mkdir(join(cwd, '.keysentry')); await mkdir(userDir);
  await writeFile(join(cwd, '.keysentry', 'project.json'), '{"id":"abcdef0123456789"}\n');
  const path = join(userDir, 'vault.enc');
  const vault = createEncryptedFileVault({ path, passphrase: async () => Buffer.from('correct'), scrypt: { N: 1024, r: 8, p: 1 } });
  await vault.set('project/abcdef0123456789/key/fingerprint', Buffer.alloc(32, 15));
  const before = await readFile(path, 'utf8');
  await expect(runFirstRun({ cwd, git, noSave: true, userDir, env: { KEYSENTRY_VAULT: 'encrypted-file' }, passphrase: async () => Buffer.from('incorrect') })).rejects.toThrow(/fingerprint key/);
  expect(await readFile(path, 'utf8')).toBe(before);
  expect(await readdir(userDir)).toEqual(['vault.enc']);
});

test('a malformed project identifier fails without generating replacement state', async () => {
  const cwd = await project();
  await mkdir(join(cwd, '.keysentry'));
  await writeFile(join(cwd, '.keysentry', 'project.json'), '{"id":"wrong"}\n');
  await expect(runFirstRun({ cwd, git, noSave: true, vault: createFakeVault() })).rejects.toThrow(/fingerprint key/);
  expect(await readFile(join(cwd, '.keysentry', 'project.json'), 'utf8')).toBe('{"id":"wrong"}\n');
});

test('without a consent callback first run remains unsaved', async () => {
  const cwd = await project();
  expect((await runFirstRun({ cwd, git })).saved).toBe(false);
  expect(await readdir(cwd)).toEqual(['.env']);
});

test('custom persistence runs only after affirmative consent and receives the secret-free result', async () => {
  const cwd = await project();
  const calls: string[] = [];
  let persisted: unknown;
  const saved = await runFirstRun({ cwd, git, confirmSave: async result => {
    calls.push('consent'); expect(result.findings).toHaveLength(1); return true;
  }, saveResult: async result => { calls.push('save'); persisted = result; } });
  expect(calls).toEqual(['consent', 'save']);
  expect(persisted).toEqual(saved.result);
  expect(JSON.stringify(persisted)).not.toContain(planted);
  expect(saved.saved).toBe(true);
  expect(await readdir(cwd)).toEqual(['.env']);
});

test.each([true, false])('custom persistence is bypassed when no-save or consent refusal applies (no-save=%s)', async noSave => {
  const cwd = await project();
  let saved = false;
  const result = await runFirstRun({ cwd, git, noSave, confirmSave: async () => false,
    saveResult: async () => { saved = true; } });
  expect(result.saved).toBe(false);
  expect(saved).toBe(false);
  expect(await readdir(cwd)).toEqual(['.env']);
});

test('consented first run saves only secret-free summary and ignores all local state in git', async () => {
  const cwd = await project();
  const run = await runFirstRun({ cwd, git, confirmSave: async () => true });
  expect(run.saved).toBe(true);
  const state = join(cwd, '.keysentry');
  expect((await readdir(state)).sort()).toEqual(['.gitignore', 'first-run.json']);
  expect(await readFile(join(state, '.gitignore'), 'utf8')).toBe('*\n');
  const content = await readFile(join(state, 'first-run.json'), 'utf8');
  expect(JSON.parse(content)).toEqual(run.result);
  expect(content).not.toContain(planted);
});

test('per-run fingerprints change unless a key is supplied', async () => {
  const cwd = await project();
  const first = await runFirstRun({ cwd, git, noSave: true });
  const second = await runFirstRun({ cwd, git, noSave: true });
  expect(first.result.findings[0]!.id).not.toBe(second.result.findings[0]!.id);
  const key = Buffer.alloc(32, 7);
  const third = await runFirstRun({ cwd, git, noSave: true, fingerprintKey: key });
  const fourth = await runFirstRun({ cwd, git, noSave: true, fingerprintKey: key });
  expect(third.result.findings[0]!.id).toBe(fourth.result.findings[0]!.id);
  expect(key).toEqual(Buffer.alloc(32, 7));
});

test('existing runtime reuses its project fingerprint key and saves through encrypted storage', async () => {
  const cwd = await project();
  const store = createStateStore({ cwd, cipher: createStateCipher(Buffer.alloc(32, 3)) });
  const fingerprintKey = Buffer.alloc(32, 9);
  const runtime = { store, fingerprintKey };
  const saved = await runFirstRun({ cwd, runtime, git, confirmSave: async () => true });
  const unsaved = await runFirstRun({ cwd, runtime, git, noSave: true });
  expect(saved.result.findings[0]!.id).toBe(unsaved.result.findings[0]!.id);
  const path = join(cwd, '.keysentry', 'first-run.json');
  expect(await readFile(path, 'utf8')).toMatch(/^keysentry-encrypted:v1\n/);
  expect(await store.readJson('report', path)).toEqual(saved.result);
});

test('first-run summary explains bounded history and possible deployment without printing values', async () => {
  const cwd = await project();
  await writeFile(join(cwd, 'railway.json'), '{}');
  const history: GitRunner = async (_args, { onLine }) => {
    onLine(`\x00${'a'.repeat(40)}\x002026-10-20T12:00:00Z`);
    onLine('+++ b/.env'); onLine('@@ -0,0 +1 @@'); onLine(`+OPENAI_API_KEY=${planted}`);
    return { code: 1 };
  };
  const { result } = await runFirstRun({ cwd, git: history, noSave: true });
  const output = formatFirstRun(result);
  expect(output).toContain('1 key');
  expect(output).toContain('git history');
  expect(output).toContain('1 commit');
  expect(output).toContain('Railway');
  expect(output).not.toContain(planted);
});

test('does not overwrite an existing consented summary without encrypted runtime storage', async () => {
  const cwd = await project();
  await mkdir(join(cwd, '.keysentry'));
  await writeFile(join(cwd, '.keysentry', 'first-run.json'), 'saved before\n');
  await expect(runFirstRun({ cwd, git, confirmSave: async () => true })).rejects.toThrow();
  expect(await readFile(join(cwd, '.keysentry', 'first-run.json'), 'utf8')).toBe('saved before\n');
});
