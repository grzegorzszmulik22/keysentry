import { afterEach, expect, test } from 'vitest';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { bootstrapWatcher, prepareWatcherDeployment } from '../../src/cli/watcher-bootstrap.js';
import { configSchema } from '../../src/cli/config.js';
import { createRuntime } from '../../src/cli/runtime.js';
import { generateDeviceKey } from '../../src/security/index.js';
import { signArmedPlan } from '../../src/autopilot/index.js';
import { createEncryptedFileVault } from '../../src/vault/index.js';
import { sealWatcherConfig, type WatcherConfig } from '../../src/watcher/index.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
const fastVault: typeof createEncryptedFileVault = options => createEncryptedFileVault({ ...options, scrypt: { N: 1024, r: 8, p: 1 } });

async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), 'keysentry-watcher-bootstrap-')); dirs.push(dir);
  const key = generateDeviceKey(), device = generateDeviceKey();
  const config: WatcherConfig = {
    v: 1, projectId: '1234567890abcdef', armed: null,
    trustedKeyIds: [device.keyId], devicePublicKeys: [{ keyId: device.keyId, publicKeyDer: device.publicKeyDer.toString('base64') }],
    passkeys: [], notify: { channels: [] }, sources: { disabled: [], extra: [] },
    approvals: { publicOrigin: null, relay: null }, intervalSeconds: 300,
  };
  const fp = randomBytes(32), state = randomBytes(32), deploy = randomBytes(32);
  const sourceVault = createFakeVault({
    [`project/${config.projectId}/key/state`]: randomBytes(32),
    [`project/${config.projectId}/key/fingerprint`]: fp,
    'key/device-ed25519': device.privateKeyDer,
    'cred/RAILWAY_TOKEN': Buffer.from('planted-host-management-token'),
    'cred/RAILWAY_TOKEN@read': Buffer.from('planted-read-management-token'),
    'notify/phone/topic': Buffer.from('planted-private-topic'),
  });
  const settings = configSchema.parse({ hosts: { railway: { enabled: true, projectIds: ['project-one'] }, dotenv: { enabled: true, roots: ['local-app'] } } });
  const prepared = await prepareWatcherDeployment({ sourceVault, settings, outputDir: join(dir, 'deploy'), openVault: fastVault }, {
    config, watcherKey: key, stateKey: state, vaultPassphrase: Buffer.from('planted-vault-passphrase'),
  });
  const env = {
    KEYSENTRY_WATCHER_KEY: deploy.toString('base64'), KEYSENTRY_STATE_KEY: state.toString('base64'),
    KEYSENTRY_VAULT_PASSPHRASE: 'planted-vault-passphrase', KEYSENTRY_WATCHER_CONFIG: sealWatcherConfig(config, deploy),
    KEYSENTRY_WATCHER_VAULT: prepared.vaultBlob, KEYSENTRY_STATE_DIR: join(dir, 'state'),
  };
  return { dir, config, key, device, fp, state, deploy, prepared, env };
}

test('deployment vault encrypts credentials and carries watcher signing key without copying local device or state keys', async () => {
  const f = await fixture();
  const raw = await readFile(f.prepared.vaultPath, 'utf8');
  expect(raw).not.toContain('planted-host-management-token');
  expect(raw).not.toContain('planted-private-topic');
  expect(raw).not.toContain('planted-vault-passphrase');
  expect(JSON.parse(raw).entries).not.toHaveProperty(`project/${f.config.projectId}/key/state`);
  const opened = await bootstrapWatcher(f.env, { platform: process.platform, openVault: fastVault });
  try {
    expect(await opened.options.vault!.get('key/device-ed25519')).toEqual(f.key.privateKeyDer);
    expect(await opened.options.vault!.get('key/device-ed25519')).not.toEqual(f.device.privateKeyDer);
    expect(await opened.options.vault!.get(`project/${f.config.projectId}/key/fingerprint`)).toEqual(f.fp);
    expect(await opened.options.vault!.get(`project/${f.config.projectId}/key/state`)).toEqual(f.state);
  } finally { opened.dispose(); }
});

test('bootstrap binds sealed identity and keeps runtime paths inside the private state directory', async () => {
  const f = await fixture();
  const opened = await bootstrapWatcher(f.env, { platform: process.platform, openVault: fastVault });
  try {
    expect(opened.options.cwd).toBe(f.env.KEYSENTRY_STATE_DIR);
    expect(opened.options.userDir).toBe(join(f.env.KEYSENTRY_STATE_DIR, 'vault'));
    expect(opened.options.settings?.hosts.railway.projectIds).toEqual(['project-one']);
    expect(JSON.parse(await readFile(join(f.env.KEYSENTRY_STATE_DIR, '.keysentry', 'project.json'), 'utf8'))).toEqual({ id: f.config.projectId });
    await opened.options.vault!.set('project/1234567890abcdef/inflight/plan-one', Buffer.alloc(32, 7));
  } finally { opened.dispose(); }
  const again = await bootstrapWatcher(f.env, { platform: process.platform, openVault: fastVault });
  try { expect(await again.options.vault!.get('project/1234567890abcdef/inflight/plan-one')).toEqual(Buffer.alloc(32, 7)); }
  finally { again.dispose(); }
});

test('bootstrap refuses existing project identity mismatch without replacing it', async () => {
  const f = await fixture();
  const opened = await bootstrapWatcher(f.env, { platform: process.platform, openVault: fastVault }); opened.dispose();
  const path = join(f.env.KEYSENTRY_STATE_DIR, '.keysentry', 'project.json');
  await writeFile(path, JSON.stringify({ id: 'abcdef1234567890' }));
  await expect(bootstrapWatcher(f.env, { platform: process.platform, openVault: fastVault })).rejects.toThrow(/project identity/);
  expect(JSON.parse(await readFile(path, 'utf8'))).toEqual({ id: 'abcdef1234567890' });
});

test.each(['', 'not-base64', Buffer.alloc(31).toString('base64')])('bootstrap rejects missing or invalid external state key without echoing it', async value => {
  const f = await fixture();
  const attempt = bootstrapWatcher({ ...f.env, KEYSENTRY_STATE_KEY: value }, { platform: process.platform, openVault: fastVault });
  await expect(attempt).rejects.toThrow(/KEYSENTRY_STATE_KEY/);
  if (value) await expect(attempt).rejects.not.toThrow(value);
});

test('bootstrap requires vault passphrase and portable vault for a new deployment', async () => {
  const f = await fixture();
  await expect(bootstrapWatcher({ ...f.env, KEYSENTRY_VAULT_PASSPHRASE: '' }, { platform: process.platform, openVault: fastVault })).rejects.toThrow(/KEYSENTRY_VAULT_PASSPHRASE/);
  await expect(bootstrapWatcher({ ...f.env, KEYSENTRY_WATCHER_VAULT: '' }, { platform: process.platform, openVault: fastVault })).rejects.toThrow(/KEYSENTRY_WATCHER_VAULT/);
});

test('bootstrapped runtime saves durable encrypted state without persisting its external state key', async () => {
  const f = await fixture();
  const opened = await bootstrapWatcher(f.env, { platform: process.platform, openVault: fastVault });
  try {
    const runtime = await createRuntime({ ...opened.options, hosts: [], http: new FakeHttp(), log: silentLogger });
    await runtime.scan();
    expect(await readFile(runtime.paths.inventory, 'utf8')).toMatch(/^keysentry-encrypted:v1\n/);
    const rawVault = JSON.parse(await readFile(join(opened.options.userDir!, 'vault.enc'), 'utf8'));
    expect(rawVault.entries).not.toHaveProperty(`project/${f.config.projectId}/key/state`);
    await expect(runtime.vault.set(`project/${f.config.projectId}/key/state`, Buffer.alloc(32))).rejects.toThrow(/KEYSENTRY_STATE_KEY/);
    expect((await runtime.audit.verify()).ok).toBe(true);
  } finally { opened.dispose(); }
});

test('bootstrap refuses altered portable vault bytes without echoing the supplied blob', async () => {
  const f = await fixture();
  const invalid = Buffer.from('{"private":"planted-secret-config"}').toString('base64');
  const attempt = bootstrapWatcher({ ...f.env, KEYSENTRY_WATCHER_VAULT: invalid }, { platform: process.platform, openVault: fastVault });
  await expect(attempt).rejects.toThrow(/KEYSENTRY_WATCHER_VAULT/);
  await expect(attempt).rejects.not.toThrow(invalid);
});

test('bootstrap refuses a wrong vault passphrase without revealing it', async () => {
  const f = await fixture();
  const attempt = bootstrapWatcher({ ...f.env, KEYSENTRY_VAULT_PASSPHRASE: 'wrong-planted-passphrase' }, { platform: process.platform, openVault: fastVault });
  await expect(attempt).rejects.toThrow();
  await expect(attempt).rejects.not.toThrow('wrong-planted-passphrase');
});

test('bootstrap takes trust and health rules from the sealed plan without rewriting saved settings', async () => {
  const f = await fixture();
  f.config.armed = signArmedPlan({
    v: 1, id: 'arm-20261027-12345678', projectId: f.config.projectId,
    createdAt: '2026-10-27T12:00:00.000Z', expiresAt: '2027-01-25T12:00:00.000Z',
    hosts: ['railway'], clusters: [], maxServicesPerWave: 10, graceSeconds: 900,
    healthChecks: [{ serviceKey: 'railway:p/e/s', url: 'https://health.example.test/ready' }],
    nextDeployAcceptance: [], quiet: {},
  }, f.device);
  f.config.sources.extra = [{ id: 'custom-official', kind: 'official', hosts: ['railway'], outlet: 'Custom', owner: 'Custom', url: 'https://custom-feed.example.test/rss' }];
  f.env.KEYSENTRY_WATCHER_CONFIG = sealWatcherConfig(f.config, f.deploy);
  const opened = await bootstrapWatcher(f.env, { platform: process.platform, openVault: fastVault });
  try {
    expect(opened.options.trustedPlanKeyIds).toEqual([f.device.keyId]);
    expect(opened.options.settings?.autopilot.healthChecks).toEqual(f.config.armed.healthChecks);
    expect(opened.options.settings?.monitor.feeds).toContainEqual({ url: 'https://custom-feed.example.test/rss', host: 'railway' });
    expect(opened.options.settings?.hosts.dotenv.enabled).toBe(false);
    const stored = await opened.options.vault!.get('watcher/runtime-settings');
    try {
      expect(JSON.parse(stored!.toString()).settings.autopilot.healthChecks).toEqual([]);
      expect(JSON.parse(stored!.toString()).settings.hosts.dotenv.enabled).toBe(true);
    } finally { stored?.fill(0); }
  } finally { opened.dispose(); }
});

