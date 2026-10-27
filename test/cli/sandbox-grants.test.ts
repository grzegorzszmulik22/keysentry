import { afterEach, expect, test, vi } from 'vitest';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { permissionOptionsForBin } from '../../src/cli/sandbox-grants.js';
import type { Inventory, ServiceRef } from '../../src/types.js';
import { createStateCipher, createStateStore } from '../../src/core/store.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { environmentVariableForName } from '../../src/vault/backends/env.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
const directory = (path: string) => `${path}${sep}`;

async function fixture(config = '') {
  const cwd = await mkdtemp(join(tmpdir(), 'ks-command-grants-')); dirs.push(cwd);
  if (config) await writeFile(join(cwd, 'keysentry.yaml'), config);
  const userDir = join(cwd, 'user');
  const bundle = join(cwd, 'installed', 'keysentry.mjs');
  const argv = (...args: string[]) => ['node', join(cwd, 'bin', 'keysentry'), '--cwd', cwd, ...args];
  return { cwd, userDir, bundle, argv };
}

function inventory(cwd: string, paths: string[], unrelated: string[] = []): Inventory {
  const service = (path: string): ServiceRef => ({ host: 'dotenv', projectId: cwd, projectName: 'project',
    serviceId: path, serviceName: path, environmentId: '', environmentName: '' });
  return { version: 1, scannedAt: '2026-10-27T12:00:00.000Z', hosts: ['dotenv'],
    services: [...paths, ...unrelated].map(service), findings: [], errors: [], clusters: paths.map((path, index) => ({
      id: `cluster-${index}`, fingerprint: null, provider: 'app-secret', tier: 'app', method: 'generate', hint: null,
      consumers: [{ service: service(path), varName: 'SESSION_SECRET', fingerprint: null, hint: null, sealed: false }],
    })) };
}

test('init grants only its chosen config file in addition to private state', async () => {
  const f = await fixture();
  const result = await permissionOptionsForBin(f.argv('init'), { KEYSENTRY_VAULT: 'memory' }, f.bundle, { userDir: f.userDir });
  expect(result.writePaths).toEqual([directory(join(f.cwd, '.keysentry')), directory(f.userDir), join(f.cwd, 'keysentry.yaml')]);
  expect(result.readPaths).toContain(f.bundle);
  expect(result.readPaths).toContain(join(f.cwd, 'installed', 'release-manifest.json'));
  expect(result.readPaths).not.toContain(join(f.cwd, 'bin', 'keysentry'));
  expect(result.allowChildProcess).toBe(false);
});

test('notification mutations can write the exact selected config and watcher setup its selected directory', async () => {
  const f = await fixture();
  const notify = await permissionOptionsForBin(f.argv('notify', 'add', 'console'), { KEYSENTRY_VAULT: 'memory' }, f.bundle, { userDir: f.userDir });
  expect(notify.writePaths).toContain(join(f.cwd, 'keysentry.yaml'));
  const destination = join(f.cwd, 'deployment');
  const watcher = await permissionOptionsForBin(f.argv('watcher', 'setup', '--output', destination), { KEYSENTRY_VAULT: 'memory' }, f.bundle, { userDir: f.userDir });
  expect(watcher.writePaths).toContain(directory(destination));
});

test('sealed watch grants its explicitly configured private state directory', async () => {
  const f = await fixture(); const state = join(f.cwd, 'watcher-state');
  const result = await permissionOptionsForBin(f.argv('watch', '--once'), { KEYSENTRY_VAULT: 'encrypted-file', KEYSENTRY_STATE_DIR: state, KEYSENTRY_WATCHER_KEY: 'present' }, f.bundle, { userDir: f.userDir });
  expect(result.writePaths).toContain(directory(state));
  expect(result.readPaths).toContain(directory(state));
});

test('plan output grants the exact -o or --output file, including an external path', async () => {
  const f = await fixture(); const output = resolve(f.cwd, '..', 'keysentry-runbook.md');
  for (const args of [['plan', '-o', output], ['plan', `--output=${output}`]]) {
    const result = await permissionOptionsForBin(f.argv(...args), { KEYSENTRY_VAULT: 'memory' }, f.bundle, { userDir: f.userDir });
    expect(result.writePaths).toContain(output);
    expect(result.writePaths).not.toContain(directory(resolve(output, '..')));
  }
});

test('an external configuration grants its exact file without its containing directory', async () => {
  const f = await fixture();
  const configDir = await mkdtemp(join(tmpdir(), 'ks-external-config-')); dirs.push(configDir);
  const configPath = join(configDir, 'keysentry.yaml');
  await writeFile(configPath, 'hosts:\n  dotenv:\n    enabled: false\n');
  const result = await permissionOptionsForBin(f.argv('--config', configPath, 'scan'), { KEYSENTRY_VAULT: 'memory' }, f.bundle, { userDir: f.userDir });
  expect(result.readPaths).toContain(configPath);
  expect(result.readPaths).not.toContain(configDir);
  expect(result.readPaths).not.toContain(directory(configDir));
});

test.each(['approve', 'resume', 'finish', 'undo'])('%s grants only configured dotenv consumer files', async command => {
  const f = await fixture('hosts:\n  dotenv:\n    roots: [app]\n');
  const consumer = join(f.cwd, 'app', '.env');
  const outside = join(f.cwd, 'outside', '.env');
  const unused = join(f.cwd, 'app', '.env.unused');
  const result = await permissionOptionsForBin(f.argv(command, 'plan-1'), { KEYSENTRY_VAULT: 'memory' }, f.bundle,
    { userDir: f.userDir, loadInventory: async () => inventory(f.cwd, [consumer, outside], [unused]) });
  expect(result.writePaths).toContain(consumer);
  expect(result.writePaths).toContain(`${consumer}.keysentry-*`);
  expect(result.writePaths).not.toContain(outside);
  expect(result.writePaths).not.toContain(unused);
  expect(result.writePaths).not.toContain(directory(join(f.cwd, 'app')));
  expect(result.writePaths).not.toContain(`${join(f.cwd, 'app')}*`);
});

test('only executing rotate reads inventory and receives dotenv write grants', async () => {
  const f = await fixture(); const loadInventory = vi.fn(async () => inventory(f.cwd, [join(f.cwd, '.env')]));
  const deps = { userDir: f.userDir, loadInventory };
  const dry = await permissionOptionsForBin(f.argv('rotate'), {}, f.bundle, deps);
  expect(loadInventory).not.toHaveBeenCalled();
  expect(dry.writePaths).toEqual([directory(join(f.cwd, '.keysentry')), directory(f.userDir)]);
  const execute = await permissionOptionsForBin(f.argv('rotate', '--execute'), {}, f.bundle, deps);
  expect(execute.writePaths).toContain(join(f.cwd, '.env'));
});

test.each(['autoExecute', 'autoContain'])('monitor grants dotenv writes only with %s enabled', async flag => {
  const f = await fixture(`monitor:\n  ${flag}: true\n`);
  const result = await permissionOptionsForBin(f.argv('monitor', '--once'), {}, f.bundle,
    { userDir: f.userDir, loadInventory: async () => null });
  expect(result.writePaths).toContain(directory(f.cwd));
  const readOnly = await permissionOptionsForBin(f.argv('monitor'), { KEYSENTRY_AUTO_EXECUTE: 'false', KEYSENTRY_AUTO_CONTAIN: 'false' }, f.bundle,
    { userDir: f.userDir, loadInventory: async () => { throw new Error('must not load'); } });
  expect(readOnly.writePaths).not.toContain(directory(f.cwd));
});

test('unreadable inventory falls back to configured dotenv roots and does not create state', async () => {
  const f = await fixture('hosts:\n  dotenv:\n    roots: [app, ../shared]\n');
  const before = await readdir(f.cwd);
  const result = await permissionOptionsForBin(f.argv('rotate', '--execute'), { KEYSENTRY_VAULT: 'memory' }, f.bundle, { userDir: f.userDir });
  expect(result.writePaths).toContain(directory(join(f.cwd, 'app')));
  expect(result.writePaths).toContain(directory(resolve(f.cwd, '..', 'shared')));
  expect(await readdir(f.cwd)).toEqual(before);
  expect(await readFile(join(f.cwd, 'keysentry.yaml'), 'utf8')).toContain('roots: [app, ../shared]');
});

test('a readable empty inventory grants no dotenv roots', async () => {
  const f = await fixture();
  const result = await permissionOptionsForBin(f.argv('rotate', '--execute'), {}, f.bundle,
    { userDir: f.userDir, loadInventory: async () => inventory(f.cwd, []) });
  expect(result.writePaths).not.toContain(directory(f.cwd));
});

test('disabled dotenv host grants no write roots even when inventory is unavailable', async () => {
  const f = await fixture('hosts:\n  dotenv:\n    enabled: false\n');
  const result = await permissionOptionsForBin(f.argv('rotate', '--execute'), {}, f.bundle,
    { userDir: f.userDir, loadInventory: async () => null });
  expect(result.writePaths).not.toContain(directory(f.cwd));
});

test('an existing encrypted inventory is read with its existing vault key and binding', async () => {
  const f = await fixture(); const projectId = '0123456789abcdef'; const key = Buffer.alloc(32, 5);
  await mkdir(join(f.cwd, '.keysentry'));
  await writeFile(join(f.cwd, '.keysentry', 'project.json'), JSON.stringify({ id: projectId }));
  const vault = createFakeVault({ [`project/${projectId}/key/state`]: key });
  const store = createStateStore({ cwd: f.cwd, cipher: createStateCipher(key), vault, projectId });
  const consumer = join(f.cwd, '.env.production');
  await store.saveInventory(inventory(f.cwd, [consumer]));
  const saved = await readFile(store.paths.inventory, 'utf8');
  const env: NodeJS.ProcessEnv = { KEYSENTRY_VAULT: 'env', KEYSENTRY_STATE_KEY: key.toString('base64') };
  for (const [name, value] of vault.dump()) if (!name.endsWith('key/state')) env[environmentVariableForName(name)] = value.toString('utf8');
  const result = await permissionOptionsForBin(f.argv('rotate', '--execute'), env, f.bundle, { userDir: f.userDir });
  expect(result.writePaths).toContain(consumer);
  expect(result.writePaths).not.toContain(directory(f.cwd));
  expect(await readFile(store.paths.inventory, 'utf8')).toBe(saved);
});

test.each(['install-hook', 'uninstall-hook'])('guard %s grants its resolved hooks directory only', async action => {
  const f = await fixture();
  const hooks = resolve(f.cwd, '..', 'shared-private-hooks');
  const resolveHooksDirectory = vi.fn(async () => hooks);
  const result = await permissionOptionsForBin(f.argv('guard', action), { KEYSENTRY_VAULT: 'encrypted-file' }, f.bundle,
    { userDir: f.userDir, resolveHooksDirectory });
  expect(resolveHooksDirectory).toHaveBeenCalledWith(f.cwd, { KEYSENTRY_VAULT: 'encrypted-file' });
  expect(result.writePaths).toContain(directory(hooks));
  expect(result.readPaths).toContain(directory(hooks));
  expect(result.writePaths).not.toContain(directory(resolve(hooks, '..')));
  expect(result.allowChildProcess).toBe(true);
});

test.each([[], ['--no-save'], ['guard'], ['guard', '--staged'], ['guard', '--history'], ['ui'], ['watch', '--once']].map(args => ({ args })))(
  'git-reading command $args may create child processes with a file vault', async ({ args }) => {
    const f = await fixture();
    const result = await permissionOptionsForBin(f.argv(...args), { KEYSENTRY_VAULT: 'encrypted-file' }, f.bundle,
      { userDir: f.userDir });
    expect(result.allowChildProcess).toBe(true);
  },
);

test.each([['card'], ['timeline', 'plan-1']])('%s output grants only its selected --out file', async (...command) => {
  const f = await fixture();
  const output = resolve(f.cwd, '..', 'shared-output.svg');
  for (const args of [[...command, '--out', output], [...command, `--out=${output}`]]) {
    const result = await permissionOptionsForBin(f.argv(...args), { KEYSENTRY_VAULT: 'encrypted-file' }, f.bundle,
      { userDir: f.userDir });
    expect(result.writePaths).toContain(output);
    expect(result.writePaths).not.toContain(directory(resolve(output, '..')));
    expect(result.allowChildProcess).toBe(false);
  }
});

test('ordinary guard scans neither resolve hooks nor grant writes to them', async () => {
  const f = await fixture(); const resolveHooksDirectory = vi.fn(async () => join(f.cwd, '.git', 'hooks'));
  const result = await permissionOptionsForBin(f.argv('guard'), { KEYSENTRY_VAULT: 'env' }, f.bundle,
    { userDir: f.userDir, resolveHooksDirectory });
  expect(resolveHooksDirectory).not.toHaveBeenCalled();
  expect(result.writePaths).not.toContain(directory(join(f.cwd, '.git', 'hooks')));
});

test('repeated output options grant only the final path Commander will use', async () => {
  const f = await fixture();
  for (const args of [['--out', 'first.svg', '--out', 'final.svg'],
    ['--out=first.svg', '--out', 'final.svg'], ['--out', 'first.svg', '--out=final.svg']]) {
    const result = await permissionOptionsForBin(f.argv('card', ...args), { KEYSENTRY_VAULT: 'encrypted-file' }, f.bundle,
      { userDir: f.userDir });
    expect(result.writePaths).toContain(join(f.cwd, 'final.svg'));
    expect(result.writePaths).not.toContain(join(f.cwd, 'first.svg'));
  }
});

test('watcher grants place the user directory under its configured state directory', async () => {
  const f = await fixture(); const stateDir = resolve(f.cwd, '..', 'watch-state');
  const env = { KEYSENTRY_STATE_DIR: stateDir, KEYSENTRY_VAULT: 'encrypted-file' };
  const result = await permissionOptionsForBin(f.argv('watch', '--once'), env, f.bundle);
  expect(result.writePaths).toContain(directory(join(stateDir, 'user')));
  const explicit = await permissionOptionsForBin(f.argv('watch', '--once'),
    { ...env, KEYSENTRY_USER_DIR: f.userDir }, f.bundle);
  expect(explicit.writePaths).toContain(directory(f.userDir));
});
