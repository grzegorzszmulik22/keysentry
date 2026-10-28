// Review phase 5 part A, H1: a deployed watcher must be able to use the network settings it was set up with.
import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, test } from 'vitest';
import { configSchema, type ConfigSettings } from '../../src/cli/config.js';
import { DEPLOYMENT_CA_VAULT_NAME, setupNetwork } from '../../src/cli/network-setup.js';
import { bootstrapWatcher, prepareWatcherDeployment } from '../../src/cli/watcher-bootstrap.js';
import { PROXY_AUTH_VAULT_NAME } from '../../src/net/transport.js';
import { generateDeviceKey } from '../../src/security/index.js';
import { createEncryptedFileVault } from '../../src/vault/index.js';
import { sealWatcherConfig, type WatcherConfig } from '../../src/watcher/index.js';
import { createFakeVault } from '../helpers/fake-vault.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
const fastVault: typeof createEncryptedFileVault = options => createEncryptedFileVault({ ...options, scrypt: { N: 1024, r: 8, p: 1 } });
const CERT = new URL('../fixtures/tls/cert.pem', import.meta.url);

async function project(settingsInput: Record<string, unknown>, seed: Record<string, Buffer> = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'keysentry-watcher-network-')); dirs.push(dir);
  const cwd = join(dir, 'project');
  await mkdir(join(cwd, 'certs'), { recursive: true });
  await writeFile(join(cwd, 'certs', 'corp-root.pem'), `# Corp root\n${await readFile(CERT, 'utf8')}`);
  const device = generateDeviceKey();
  const config: WatcherConfig = {
    v: 1, projectId: '1234567890abcdef', armed: null, trustedKeyIds: [device.keyId],
    devicePublicKeys: [{ keyId: device.keyId, publicKeyDer: device.publicKeyDer.toString('base64') }],
    passkeys: [], notify: { channels: [] }, sources: { disabled: [], extra: [] },
    approvals: { publicOrigin: null, relay: null }, intervalSeconds: 300,
  };
  const sourceVault = createFakeVault({ [`project/${config.projectId}/key/fingerprint`]: randomBytes(32), 'key/device-ed25519': device.privateKeyDer, ...seed });
  const settings: ConfigSettings = configSchema.parse(settingsInput);
  return { dir, cwd, config, sourceVault, settings };
}

async function prepare(p: Awaited<ReturnType<typeof project>>, extra: Partial<Parameters<typeof prepareWatcherDeployment>[0]> = {}, name = 'deploy') {
  const state = randomBytes(32), deploy = randomBytes(32);
  const prepared = await prepareWatcherDeployment({ sourceVault: p.sourceVault, settings: p.settings, outputDir: join(p.dir, name),
    openVault: fastVault, cwd: p.cwd, ...extra }, { config: p.config, watcherKey: generateDeviceKey(), stateKey: state,
    vaultPassphrase: Buffer.from('planted-vault-passphrase') });
  const env = {
    KEYSENTRY_WATCHER_KEY: deploy.toString('base64'), KEYSENTRY_STATE_KEY: state.toString('base64'),
    KEYSENTRY_VAULT_PASSPHRASE: 'planted-vault-passphrase', KEYSENTRY_WATCHER_CONFIG: sealWatcherConfig(p.config, deploy),
    KEYSENTRY_WATCHER_VAULT: prepared.vaultBlob, KEYSENTRY_STATE_DIR: join(p.dir, `${name}-state`),
  };
  const vault = fastVault({ path: prepared.vaultPath, passphrase: async () => Buffer.from('planted-vault-passphrase') });
  return { prepared, env, vault };
}

test('the CA bundle travels as certificates in the encrypted deployment and the deployed transport uses it', async () => {
  const p = await project({ network: { caFile: 'certs/corp-root.pem' } });
  const { prepared, env, vault } = await prepare(p);
  const carried = (await vault.get(DEPLOYMENT_CA_VAULT_NAME))!.toString('utf8');
  expect(carried).toContain('-----BEGIN CERTIFICATE-----');
  expect(carried).not.toContain('# Corp root');
  expect(prepared.notes.join(' ')).toContain('certificate from network.caFile, carried in its encrypted vault');
  const opened = await bootstrapWatcher(env, { platform: process.platform, openVault: fastVault });
  try {
    // The watcher's state directory has no certs/ folder; the certificates come from its vault.
    const network = await setupNetwork({ settings: opened.options.settings!.network, cwd: opened.options.cwd!, env: opened.options.env!,
      vault: opened.options.vault!, policy: null });
    expect(network.problem).toBeNull();
    expect(network.ca).toHaveLength(1);
    expect(network.summary.ca).toMatchObject({ path: 'certs/corp-root.pem', certificates: [expect.anything()] });
  } finally { opened.dispose(); }
});

test('setup refuses a CA file it cannot carry, and needs the project directory to find it', async () => {
  const p = await project({ network: { caFile: 'certs/missing.pem' } });
  await expect(prepare(p)).rejects.toThrow('The watcher cannot be given the certificates in network.caFile, so nothing was deployed: network.caFile could not be read.');
  p.settings.network.caFile = 'certs/corp-root.pem';
  await expect(prepare(p, { cwd: undefined }, 'no-cwd')).rejects.toThrow('Watcher setup needs the project directory');
});

test('a deployment made before the CA was carried refuses to start with a clear message', async () => {
  const p = await project({ network: { caFile: 'certs/corp-root.pem' } });
  const { env, vault } = await prepare(p);
  await vault.delete(DEPLOYMENT_CA_VAULT_NAME);
  const env2 = { ...env, KEYSENTRY_WATCHER_VAULT: (await readFile(join(p.dir, 'deploy', 'watcher-vault.enc'))).toString('base64') };
  await expect(bootstrapWatcher(env2, { platform: process.platform, openVault: fastVault }))
    .rejects.toThrow('This watcher deployment does not carry the certificates from network.caFile');
});

test('the vault proxy credential travels with network.proxy; nothing is carried without a proxy', async () => {
  const p = await project({ network: { proxy: 'http://proxy.corp.example:3128' } }, { [PROXY_AUTH_VAULT_NAME]: Buffer.from('svc-watch:planted-proxy-pass') });
  const { prepared, vault } = await prepare(p);
  expect((await vault.get(PROXY_AUTH_VAULT_NAME))!.toString()).toBe('svc-watch:planted-proxy-pass');
  expect(prepared.exportedCredentialNames).toContain('KEYSENTRY_PROXY_AUTH');
  expect(prepared.notes.join(' ')).toContain('through the proxy at http://proxy.corp.example:3128');
  expect(prepared.notes.join(' ')).not.toContain('planted-proxy-pass');

  const none = await project({}, { [PROXY_AUTH_VAULT_NAME]: Buffer.from('svc-watch:planted-proxy-pass') });
  const withoutProxy = await prepare(none, { env: { HTTPS_PROXY: 'http://u:planted-env-pass@proxy.corp.example:3128' } });
  expect(await withoutProxy.vault.get(PROXY_AUTH_VAULT_NAME)).toBeNull();
  expect(withoutProxy.prepared.notes.join(' ')).toContain('HTTPS_PROXY from this terminal is not carried');
  expect(withoutProxy.prepared.notes.join(' ')).not.toContain('planted-env-pass');
});

test('a proxy credential from HTTPS_PROXY is copied only with consent for that variable', async () => {
  const p = await project({ network: { proxy: 'http://proxy.corp.example:3128' } });
  const env = { HTTPS_PROXY: 'http://svc:planted-env-pass@proxy.corp.example:3128' };
  const asked: string[] = [];
  const declined = await prepare(p, { env, confirmEnvironmentCredential: async name => { asked.push(name); return false; } }, 'declined');
  expect(asked).toEqual(['HTTPS_PROXY']);
  expect(await declined.vault.get(PROXY_AUTH_VAULT_NAME)).toBeNull();
  expect(declined.prepared.notes.join(' ')).toContain('The proxy credential was not copied');
  const accepted = await prepare(p, { env, confirmEnvironmentCredential: async () => true }, 'accepted');
  expect((await accepted.vault.get(PROXY_AUTH_VAULT_NAME))!.toString()).toBe('svc:planted-env-pass');
});

test('setup refuses a proxy setting the watcher could not use', async () => {
  // keysentry.yaml's schema refuses bad proxy URLs; a stored credential the proxy could not be sent is caught here.
  const p = await project({ network: { proxy: 'http://proxy.corp.example:3128' } }, { [PROXY_AUTH_VAULT_NAME]: Buffer.from('svc:planted\u0001pass') });
  const error = await prepare(p).then(() => null, (failure: Error) => failure);
  expect(error?.message).toContain('The watcher cannot use network.proxy, so nothing was deployed: KEYSENTRY_PROXY_AUTH has proxy credentials keysentry cannot send.');
  expect(error?.message).not.toContain('planted');
});

test('a carried CA bundle that cannot be read stops the watcher with a clear message', async () => {
  const p = await project({ network: { caFile: 'certs/corp-root.pem' } });
  const { env, vault } = await prepare(p);
  await vault.set(DEPLOYMENT_CA_VAULT_NAME, Buffer.from('not a certificate'));
  const blob = (await readFile(join(p.dir, 'deploy', 'watcher-vault.enc'))).toString('base64');
  await expect(bootstrapWatcher({ ...env, KEYSENTRY_WATCHER_VAULT: blob }, { platform: process.platform, openVault: fastVault }))
    .rejects.toThrow('The certificates carried for network.caFile cannot be used');
});

test('with a wrapped state key, a refusing network names the setting instead of "could not reach" the KMS', async () => {
  const p = await project({ kms: { provider: 'vault-transit', address: 'https://vault.corp.example', keyName: 'state' } });
  const { env } = await prepare(p);
  const { KEYSENTRY_STATE_KEY: _plain, ...rest } = env;
  const wrapped = { ...rest, KEYSENTRY_STATE_KEY_WRAPPED: Buffer.from('{}').toString('base64'), HTTPS_PROXY: 'socks5://proxy.corp.example:1080' };
  const error = await bootstrapWatcher(wrapped, { platform: process.platform, openVault: fastVault }).then(() => null, (failure: Error) => failure);
  expect(error?.message).toContain("The watcher's network settings cannot be used, so the KMS key was not contacted: HTTPS_PROXY uses an unsupported proxy type.");
  expect(error?.message).not.toContain('Could not reach');
});

test('NODE_TLS_REJECT_UNAUTHORIZED=0 does not reach keysentry: its own transport, which pins certificate checks, is used (review L7)', async () => {
  const settings = configSchema.parse({}).network;
  const network = await setupNetwork({ settings, cwd: '.', env: { NODE_TLS_REJECT_UNAUTHORIZED: '0' }, policy: null });
  expect(network.summary.nodeTrust?.tlsChecksOff).toBe(true);
  // Node's fetch would try to connect; keysentry's transport refuses plain HTTP before opening any socket.
  await expect(network.transport.request({ method: 'GET', url: 'http://127.0.0.1:9/' })).rejects.toMatchObject({ code: 'PLAIN_HTTP_REFUSED' });
});
