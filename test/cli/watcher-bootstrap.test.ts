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
import { createCredentialSource, createEncryptedFileVault, createEnvVault } from '../../src/vault/index.js';
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
  return { dir, config, key, device, fp, state, deploy, prepared, env, sourceVault, settings };
}

test('deployment exports only enabled host credentials and credentials for armed providers', async () => {
  const f = await fixture();
  for (const name of ['CLOUDFLARE_ADMIN_TOKEN', 'VERCEL_TOKEN', 'GITHUB_TOKEN', 'FLY_API_TOKEN', 'OPENAI_ADMIN_KEY', 'ANTHROPIC_ADMIN_KEY']) {
    await f.sourceVault.set(`cred/${name}`, Buffer.from(`planted-${name}`));
  }
  f.settings.hosts.vercel.enabled = false;
  f.config.armed = signArmedPlan({ v: 1, id: 'arm-20261027-12345678', projectId: f.config.projectId,
    createdAt: '2026-10-27T12:00:00.000Z', expiresAt: '2027-01-25T12:00:00.000Z', hosts: ['railway'],
    clusters: [{ clusterId: 'openai-key', provider: 'openai', method: 'auto', consumers: [{ serviceKey: 'railway:p/e/s', varName: 'OPENAI_API_KEY', fingerprint: 'openai-fingerprint' }] }],
    maxServicesPerWave: 10, graceSeconds: 900, healthChecks: [], nextDeployAcceptance: [], quiet: {} }, f.device);
  const result = await prepareWatcherDeployment({ sourceVault: f.sourceVault, settings: f.settings,
    outputDir: join(f.dir, 'scoped'), openVault: fastVault }, { config: f.config, watcherKey: f.key,
    stateKey: f.state, vaultPassphrase: Buffer.from('planted-vault-passphrase') });
  const names = Object.keys(JSON.parse(await readFile(result.vaultPath, 'utf8')).entries);
  expect(names).toEqual(expect.arrayContaining(['cred/RAILWAY_TOKEN', 'cred/RAILWAY_TOKEN@read', 'cred/OPENAI_ADMIN_KEY']));
  for (const name of ['CLOUDFLARE_ADMIN_TOKEN', 'VERCEL_TOKEN', 'GITHUB_TOKEN', 'FLY_API_TOKEN', 'ANTHROPIC_ADMIN_KEY']) expect(names).not.toContain(`cred/${name}`);
  expect(result.exportedCredentialNames).toEqual(['OPENAI_ADMIN_KEY', 'RAILWAY_TOKEN', 'RAILWAY_TOKEN@read']);
});

test('deployment does not silently export environment fallback credentials', async () => {
  const f = await fixture();
  await f.sourceVault.delete('cred/RAILWAY_TOKEN'); await f.sourceVault.delete('cred/RAILWAY_TOKEN@read');
  const credentials = createCredentialSource(f.sourceVault, { RAILWAY_TOKEN: 'planted-shell-token', GITHUB_TOKEN: 'planted-personal-token' });
  const result = await prepareWatcherDeployment({ sourceVault: f.sourceVault, credentials, settings: f.settings,
    outputDir: join(f.dir, 'no-env-consent'), openVault: fastVault }, { config: f.config, watcherKey: f.key,
    stateKey: f.state, vaultPassphrase: Buffer.from('planted-vault-passphrase') });
  const names = Object.keys(JSON.parse(await readFile(result.vaultPath, 'utf8')).entries);
  expect(names).not.toContain('cred/RAILWAY_TOKEN'); expect(names).not.toContain('cred/GITHUB_TOKEN');
  expect(result.exportedCredentialNames).toEqual([]);
});

test('deployment asks once per required environment name and exports only accepted names', async () => {
  const f = await fixture();
  await f.sourceVault.delete('cred/RAILWAY_TOKEN'); await f.sourceVault.delete('cred/RAILWAY_TOKEN@read');
  f.settings.hosts.vercel.enabled = true;
  const credentials = createCredentialSource(f.sourceVault, { RAILWAY_TOKEN: 'planted-shell-token', VERCEL_TOKEN: 'planted-vercel-token', GITHUB_TOKEN: 'planted-personal-token' });
  const asked: string[] = [];
  const result = await prepareWatcherDeployment({ sourceVault: f.sourceVault, credentials, settings: f.settings,
    confirmEnvironmentCredential: async name => { asked.push(name); return name === 'RAILWAY_TOKEN'; },
    outputDir: join(f.dir, 'consented-env'), openVault: fastVault }, { config: f.config, watcherKey: f.key,
    stateKey: f.state, vaultPassphrase: Buffer.from('planted-vault-passphrase') });
  const names = Object.keys(JSON.parse(await readFile(result.vaultPath, 'utf8')).entries);
  expect(asked).toEqual(['RAILWAY_TOKEN', 'VERCEL_TOKEN']);
  expect(names).toContain('cred/RAILWAY_TOKEN'); expect(names).not.toContain('cred/VERCEL_TOKEN'); expect(names).not.toContain('cred/GITHUB_TOKEN');
  expect(result.exportedCredentialNames).toEqual(['RAILWAY_TOKEN']);
});

test('deployment asks for actual read-role environment variable names in an environment vault', async () => {
  const f = await fixture();
  const sourceVault = createEnvVault({ KEYSENTRY_FINGERPRINT_KEY: f.fp.toString('base64'), RAILWAY_TOKEN_READ: 'planted-read-token', RAILWAY_TOKEN: 'planted-write-token' });
  const asked: string[] = [];
  const result = await prepareWatcherDeployment({ sourceVault, credentials: createCredentialSource(sourceVault, {}), settings: f.settings,
    confirmEnvironmentCredential: async name => { asked.push(name); return name === 'RAILWAY_TOKEN_READ'; },
    outputDir: join(f.dir, 'env-vault'), openVault: fastVault }, { config: f.config, watcherKey: f.key,
    stateKey: f.state, vaultPassphrase: Buffer.from('planted-vault-passphrase') });
  expect(asked.sort()).toEqual(['RAILWAY_TOKEN', 'RAILWAY_TOKEN_READ']);
  const names = Object.keys(JSON.parse(await readFile(result.vaultPath, 'utf8')).entries);
  expect(names).toContain('cred/RAILWAY_TOKEN@read'); expect(names).not.toContain('cred/RAILWAY_TOKEN');
});

test('deployment keeps the configured Railway token type and separate read role', async () => {
  const f = await fixture();
  f.settings.hosts.railway.tokenType = 'project';
  await f.sourceVault.set('cred/RAILWAY_PROJECT_TOKEN', Buffer.from('planted-project-token'));
  await f.sourceVault.set('cred/RAILWAY_PROJECT_TOKEN@read', Buffer.from('planted-project-read-token'));
  const result = await prepareWatcherDeployment({ sourceVault: f.sourceVault, settings: f.settings,
    outputDir: join(f.dir, 'project-token'), openVault: fastVault }, { config: f.config, watcherKey: f.key,
    stateKey: f.state, vaultPassphrase: Buffer.from('planted-vault-passphrase') });
  const names = Object.keys(JSON.parse(await readFile(result.vaultPath, 'utf8')).entries);
  expect(names).toEqual(expect.arrayContaining(['cred/RAILWAY_PROJECT_TOKEN', 'cred/RAILWAY_PROJECT_TOKEN@read']));
  expect(names).not.toContain('cred/RAILWAY_TOKEN'); expect(names).not.toContain('cred/RAILWAY_TOKEN@read');
  expect(result.exportedCredentialNames).toEqual(['RAILWAY_PROJECT_TOKEN', 'RAILWAY_PROJECT_TOKEN@read']);
});

test('deployment copies only active notification secrets and removes console from portable settings', async () => {
  const f = await fixture();
  f.settings.notify.channels = [{ id: 'terminal', kind: 'console' }, { id: 'phone', kind: 'ntfy' }];
  f.config.notify.channels = [{ kind: 'ntfy', settings: { id: 'phone', server: 'https://ntfy.sh', topic: 'planted-private-topic' } }];
  await f.sourceVault.set('notify/unused/token', Buffer.from('planted-unused-token'));
  await f.sourceVault.set('notify/terminal/token', Buffer.from('planted-terminal-token'));
  const result = await prepareWatcherDeployment({ sourceVault: f.sourceVault, settings: f.settings,
    outputDir: join(f.dir, 'notification-scope'), openVault: fastVault }, { config: f.config, watcherKey: f.key,
    stateKey: f.state, vaultPassphrase: Buffer.from('planted-vault-passphrase') });
  const vault = fastVault({ path: result.vaultPath, passphrase: async () => Buffer.from('planted-vault-passphrase') });
  expect(await vault.get('notify/phone/topic')).toEqual(Buffer.from('planted-private-topic'));
  expect(await vault.get('notify/unused/token')).toBeNull(); expect(await vault.get('notify/terminal/token')).toBeNull();
  const raw = await vault.get('watcher/runtime-settings');
  try { expect(JSON.parse(raw!.toString()).settings.notify.channels.map((channel: { kind: string }) => channel.kind)).toEqual(['ntfy']); }
  finally { raw?.fill(0); }
});

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
    expect(opened.options.userDir).toBe(join(f.env.KEYSENTRY_STATE_DIR, 'user'));
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
    const rawVault = JSON.parse(await readFile(join(f.env.KEYSENTRY_STATE_DIR, 'vault', 'vault.enc'), 'utf8'));
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


test('deployment copies phase 5/6 host credentials only for scoped hosts, and audit export secrets only for configured targets', async () => {
  const f = await fixture();
  for (const name of ['NETLIFY_TOKEN', 'KUBERNETES_TOKEN', 'VAULT_TOKEN', 'COOLIFY_TOKEN']) await f.sourceVault.set(`cred/${name}`, Buffer.from(`planted-${name}`));
  await f.sourceVault.set('audit-export/otel/bearer', Buffer.from('planted-otlp-bearer'));
  await f.sourceVault.set('audit-export/removed-target/bearer', Buffer.from('planted-stale-bearer'));
  const settings = configSchema.parse({ ...f.settings, hosts: { ...f.settings.hosts,
    kubernetes: { server: 'https://k8s.example.test:6443', namespaces: ['apps'] }, vault: { enabled: false, address: 'https://vault.example.test' } },
    audit: { export: [{ kind: 'otlp', id: 'otel', url: 'https://otel.example.test' }] } });
  const result = await prepareWatcherDeployment({ sourceVault: f.sourceVault, settings, outputDir: join(f.dir, 'phase6'), openVault: fastVault },
    { config: f.config, watcherKey: f.key, stateKey: f.state, vaultPassphrase: Buffer.from('planted-vault-passphrase') });
  const names = Object.keys(JSON.parse(await readFile(result.vaultPath, 'utf8')).entries);
  expect(names).toEqual(expect.arrayContaining(['cred/NETLIFY_TOKEN', 'cred/KUBERNETES_TOKEN', 'audit-export/otel/bearer']));
  // Vault is disabled and Coolify has no base URL; the removed export target's secret stays home.
  for (const name of ['cred/VAULT_TOKEN', 'cred/COOLIFY_TOKEN', 'audit-export/removed-target/bearer']) expect(names).not.toContain(name);
  // The sealed runtime settings carry the export targets.
  expect(settings.audit.export).toHaveLength(1);
});
