import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, test } from 'vitest';
import { bootstrapWatcher, prepareWatcherDeployment } from '../../src/cli/watcher-bootstrap.js';
import { configSchema } from '../../src/cli/config.js';
import { generateDeviceKey } from '../../src/security/index.js';
import { createEncryptedFileVault } from '../../src/vault/index.js';
import { sealWatcherConfig, type WatcherConfig } from '../../src/watcher/index.js';
import { createFakeVault } from '../helpers/fake-vault.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
const fastVault: typeof createEncryptedFileVault = options => createEncryptedFileVault({ ...options, scrypt: { N: 1024, r: 8, p: 1 } });
async function fixture() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-container-user-')); dirs.push(cwd);
  const watcher = generateDeviceKey(), device = generateDeviceKey(), stateKey = randomBytes(32), deployKey = randomBytes(32);
  const config: WatcherConfig = { v: 1, projectId: '1234567890abcdef', armed: null, trustedKeyIds: [device.keyId],
    devicePublicKeys: [{ keyId: device.keyId, publicKeyDer: device.publicKeyDer.toString('base64') }], passkeys: [],
    notify: { channels: [] }, sources: { disabled: [], extra: [] }, approvals: { publicOrigin: null, relay: null }, intervalSeconds: 300 };
  const sourceVault = createFakeVault({ [`project/${config.projectId}/key/fingerprint`]: randomBytes(32) });
  const prepared = await prepareWatcherDeployment({ sourceVault, settings: configSchema.parse({}), outputDir: join(cwd, 'deploy'), openVault: fastVault },
    { config, watcherKey: watcher, stateKey, vaultPassphrase: Buffer.from('private-test-passphrase') });
  const env = { KEYSENTRY_WATCHER_KEY: deployKey.toString('base64'), KEYSENTRY_STATE_KEY: stateKey.toString('base64'),
    KEYSENTRY_VAULT_PASSPHRASE: 'private-test-passphrase', KEYSENTRY_WATCHER_CONFIG: sealWatcherConfig(config, deployKey),
    KEYSENTRY_WATCHER_VAULT: prepared.vaultBlob, KEYSENTRY_STATE_DIR: join(cwd, 'state') };
  return { cwd, env };
}

test('bootstrap uses state/user for runtime metadata and preserves the existing durable vault', async () => {
  const { cwd, env } = await fixture();
  const opened = await bootstrapWatcher(env, { cwd, openVault: fastVault });
  try {
    expect(opened.options.userDir).toBe(join(env.KEYSENTRY_STATE_DIR, 'user'));
    await opened.options.vault!.set('test/recovery-marker', Buffer.from('retained-update'));
  } finally { opened.dispose(); }
  const again = await bootstrapWatcher(env, { cwd, openVault: fastVault });
  try {
    expect(await again.options.vault!.get('test/recovery-marker')).toEqual(Buffer.from('retained-update'));
    expect(await readFile(join(env.KEYSENTRY_STATE_DIR, 'vault', 'vault.enc'), 'utf8')).not.toContain('retained-update');
  } finally { again.dispose(); }
});

test('bootstrap honors an explicit user directory resolved against its working directory', async () => {
  const { cwd, env } = await fixture();
  const opened = await bootstrapWatcher({ ...env, KEYSENTRY_USER_DIR: 'user-data' }, { cwd, openVault: fastVault });
  try { expect(opened.options.userDir).toBe(join(cwd, 'user-data')); }
  finally { opened.dispose(); }
});

test('bootstrap directory failures identify the path and variable to set', async () => {
  const { cwd, env } = await fixture();
  const invalid = join(cwd, 'blocked-user'); await writeFile(invalid, 'occupied');
  await expect(bootstrapWatcher({ ...env, KEYSENTRY_USER_DIR: invalid }, { cwd, openVault: fastVault }))
    .rejects.toThrow(`Could not prepare the directory ${invalid}. Set KEYSENTRY_USER_DIR to a writable directory.`);
});

test('bootstrap reports a blocked project-state directory with its state setting', async () => {
  const { cwd, env } = await fixture();
  await mkdir(env.KEYSENTRY_STATE_DIR, { mode: 0o700 });
  const invalid = join(env.KEYSENTRY_STATE_DIR, '.keysentry'); await writeFile(invalid, 'occupied');
  await expect(bootstrapWatcher(env, { cwd, openVault: fastVault }))
    .rejects.toThrow(`Could not prepare the directory ${invalid}. Set KEYSENTRY_STATE_DIR to a writable directory.`);
});
