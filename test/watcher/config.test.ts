import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, expect, test } from 'vitest';
import { generateDeviceKey } from '../../src/security/index.js';
import { signArmedPlan } from '../../src/autopilot/armed-plan.js';
import { loadWatcherConfigFromEnv, parseWatcherConfig, type WatcherConfig } from '../../src/watcher/config.js';
import { sealWatcherConfig } from '../../src/watcher/seal.js';

function config(): WatcherConfig {
  return { v: 1, projectId: 'project-test', armed: null, trustedKeyIds: [], devicePublicKeys: [], passkeys: [],
    notify: { channels: [{ kind: 'console', settings: {} }] }, sources: { disabled: [], extra: [] },
    approvals: { publicOrigin: null, relay: null }, intervalSeconds: 600 };
}
const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map(dir => rm(dir, { recursive: true, force: true }))); });

test('strict config rejects unknown nested fields, invalid intervals and unsafe URLs without reflecting input', () => {
  const invalid = [
    { ...config(), intervalSeconds: -1 }, { ...config(), v: 2 },
    { ...config(), notify: { channels: [{ kind: 'unknown', settings: {} }] } },
    { ...config(), notify: { channels: [{ kind: 'console', settings: {}, privateToken: 'secret-sentinel' }] } },
    { ...config(), sources: { disabled: [], extra: [{ id: 'x', kind: 'official', url: 'http://example.com/secret-sentinel', hosts: ['railway'], outlet: 'o', owner: 'o' }] } },
    { ...config(), approvals: { publicOrigin: 'https://example.com/path', relay: null } },
    { ...config(), approvals: { publicOrigin: null, relay: { server: 'https://example.com', topic: 'bad/topic' } } },
  ];
  for (const input of invalid) {
    expect(() => parseWatcherConfig(input)).toThrow(/watcher config/i);
    try { parseWatcherConfig(input); } catch (error) { expect(String(error)).not.toContain('secret-sentinel'); }
  }
});

test('an expired but authentic armed plan loads so the runtime can continue in alert-only mode', () => {
  const key = generateDeviceKey();
  const armed = signArmedPlan({ v: 1, id: 'arm-20260101-1234abcd', projectId: 'project-test',
    createdAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-01-02T00:00:00.000Z', hosts: ['railway'], clusters: [],
    maxServicesPerWave: 10, graceSeconds: 900, healthChecks: [], nextDeployAcceptance: [], quiet: {} }, key);
  const input = { ...config(), armed, trustedKeyIds: [key.keyId], devicePublicKeys: [{ keyId: key.keyId, publicKeyDer: key.publicKeyDer.toString('base64') }] };
  expect(parseWatcherConfig(input).armed?.id).toBe('arm-20260101-1234abcd');
  expect(() => parseWatcherConfig({ ...input, armed: { ...armed, graceSeconds: 0 } })).toThrow();
});

test('device key ids must bind to Ed25519 public keys and public key arrays cannot repeat ids', () => {
  const key = generateDeviceKey();
  const entry = { keyId: key.keyId, publicKeyDer: key.publicKeyDer.toString('base64') };
  expect(() => parseWatcherConfig({ ...config(), devicePublicKeys: [{ ...entry, keyId: '1234567890abcdef' }] })).toThrow();
  expect(() => parseWatcherConfig({ ...config(), devicePublicKeys: [entry, entry] })).toThrow();
});

test('loader reads sealed env config and creates the local state directory with private permissions', async () => {
  const key = randomBytes(32);
  const created: { path: string; options: unknown }[] = [];
  const loaded = await loadWatcherConfigFromEnv({ KEYSENTRY_WATCHER_KEY: key.toString('base64'), KEYSENTRY_WATCHER_CONFIG: sealWatcherConfig(config(), key) }, {
    cwd: '/workspace', platform: 'linux',
    mkdir: async (path, options) => { created.push({ path, options }); },
    stat: async () => ({ mode: 0o40700, isDirectory: () => true }),
  });
  expect(loaded.config.projectId).toBe('project-test');
  expect(loaded.deployKey).toEqual(key);
  expect(loaded.stateDir).toBe(resolve('/workspace', '.keysentry'));
  expect(created).toEqual([{ path: resolve('/workspace', '.keysentry'), options: { recursive: true, mode: 0o700 } }]);
});

test('loader reads a sealed file and honors KEYSENTRY_STATE_DIR', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-watcher-')); dirs.push(cwd);
  const key = randomBytes(32);
  const file = join(cwd, 'watcher.sealed');
  await writeFile(file, `${sealWatcherConfig(config(), key)}\n`);
  const stateDir = join(cwd, 'state');
  const loaded = await loadWatcherConfigFromEnv({ KEYSENTRY_WATCHER_KEY: key.toString('base64'), KEYSENTRY_WATCHER_CONFIG_FILE: file, KEYSENTRY_STATE_DIR: stateDir }, { cwd });
  expect(loaded.config).toEqual(config());
  expect(loaded.stateDir).toBe(stateDir);
  expect(await readFile(file, 'utf8')).not.toContain('project-test');
});

test('missing pieces name their environment variable without exposing supplied content', async () => {
  const key = randomBytes(32);
  await expect(loadWatcherConfigFromEnv({})).rejects.toThrow(/KEYSENTRY_WATCHER_KEY/);
  await expect(loadWatcherConfigFromEnv({ KEYSENTRY_WATCHER_KEY: 'secret-sentinel' })).rejects.toThrow(/KEYSENTRY_WATCHER_KEY/);
  await expect(loadWatcherConfigFromEnv({ KEYSENTRY_WATCHER_KEY: key.toString('base64') })).rejects.toThrow(/KEYSENTRY_WATCHER_CONFIG.*KEYSENTRY_WATCHER_CONFIG_FILE/);
  await expect(loadWatcherConfigFromEnv({ KEYSENTRY_WATCHER_KEY: key.toString('base64'), KEYSENTRY_WATCHER_CONFIG_FILE: 'secret-sentinel' }, { readFile: async () => { throw new Error('secret-sentinel'); }, stat: async () => ({ size: 10, mode: 0o100600, isDirectory: () => false }) })).rejects.toThrow(/^Could not read KEYSENTRY_WATCHER_CONFIG_FILE\.$/);
});

test.each([0o40750, 0o40740, 0o40720, 0o40710, 0o40704, 0o40702, 0o40701])('POSIX startup refuses shared directory mode %i with a chmod fix', async mode => {
  const key = randomBytes(32);
  await expect(loadWatcherConfigFromEnv({ KEYSENTRY_WATCHER_KEY: key.toString('base64'), KEYSENTRY_WATCHER_CONFIG: sealWatcherConfig(config(), key) }, {
    platform: 'linux', mkdir: async () => {}, stat: async () => ({ mode, isDirectory: () => true }),
  })).rejects.toThrow(/KEYSENTRY_STATE_DIR.*chmod 700/);
});

test('Windows ignores POSIX mode bits but a state path that is not a directory still fails', async () => {
  const key = randomBytes(32);
  const env = { KEYSENTRY_WATCHER_KEY: key.toString('base64'), KEYSENTRY_WATCHER_CONFIG: sealWatcherConfig(config(), key) };
  await expect(loadWatcherConfigFromEnv(env, { platform: 'win32', mkdir: async () => {}, stat: async () => ({ mode: 0o40777, isDirectory: () => true }) })).resolves.toHaveProperty('config');
  await expect(loadWatcherConfigFromEnv(env, { platform: 'win32', mkdir: async () => {}, stat: async () => ({ mode: 0o100600, isDirectory: () => false }) })).rejects.toThrow(/KEYSENTRY_STATE_DIR/);
});

test('state-directory failures never echo a pathname or filesystem exception', async () => {
  const key = randomBytes(32);
  const env = { KEYSENTRY_WATCHER_KEY: key.toString('base64'), KEYSENTRY_WATCHER_CONFIG: sealWatcherConfig(config(), key), KEYSENTRY_STATE_DIR: 'secret-sentinel' };
  for (const overrides of [
    { mkdir: async () => { throw new Error('secret-sentinel'); }, stat: async () => ({ mode: 0o40700, isDirectory: () => true }) },
    { mkdir: async () => {}, stat: async () => { throw new Error('secret-sentinel'); } },
    { mkdir: async () => {}, stat: async () => ({ mode: 0o40777, isDirectory: () => true }) },
  ]) {
    let message = '';
    try { await loadWatcherConfigFromEnv(env, { platform: 'linux', ...overrides }); }
    catch (error) { message = String(error); }
    expect(message).toContain('KEYSENTRY_STATE_DIR');
    expect(message).not.toContain('secret-sentinel');
  }
});

test('oversized sealed files are rejected from metadata before reading their contents', async () => {
  const key = randomBytes(32);
  let reads = 0;
  await expect(loadWatcherConfigFromEnv({ KEYSENTRY_WATCHER_KEY: key.toString('base64'), KEYSENTRY_WATCHER_CONFIG_FILE: 'config.sealed' }, {
    stat: async () => ({ size: 4 * 1024 * 1024 + 1, mode: 0o100600, isDirectory: () => false }),
    readFile: async () => { reads++; return Buffer.from('content'); },
  })).rejects.toThrow('Could not read KEYSENTRY_WATCHER_CONFIG_FILE.');
  expect(reads).toBe(0);
});

test('an invalid explicit env config never falls back to the file path', async () => {
  const key = randomBytes(32);
  let reads = 0;
  await expect(loadWatcherConfigFromEnv({ KEYSENTRY_WATCHER_KEY: key.toString('base64'), KEYSENTRY_WATCHER_CONFIG: 'ksw1.invalid', KEYSENTRY_WATCHER_CONFIG_FILE: 'config.sealed' }, {
    readFile: async () => { reads++; return Buffer.from(sealWatcherConfig(config(), key)); },
  })).rejects.toThrow(/watcher config/);
  expect(reads).toBe(0);
});
