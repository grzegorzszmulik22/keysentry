import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import type { CredentialSource, TokenRole, Vault } from '../types.js';
import { credentialVaultName, createEncryptedFileVault } from '../vault/index.js';
import { PROVIDER_CREDENTIALS } from '../providers/index.js';
import { deviceKeyFromPrivate } from '../security/index.js';
import { loadWatcherConfigFromEnv, type WatcherConfig } from '../watcher/index.js';
import { configSchema, type ConfigSettings } from './config.js';
import { CliError } from './errors.js';
import type { RuntimeOptions } from './runtime.js';
import type { WatcherDeploymentSecrets } from './watcher-setup.js';

const MAX_VAULT_BYTES = 8 * 1024 * 1024;
type VaultFactory = typeof createEncryptedFileVault;

export interface WatcherDeploymentOptions {
  sourceVault: Vault;
  credentials?: CredentialSource;
  settings: ConfigSettings;
  outputDir: string;
  /** A shell credential may leave this computer only after consent for its exact variable name. */
  confirmEnvironmentCredential?: (name: string) => Promise<boolean>;
  /** Vault factory injection keeps native stores and expensive KDF parameters out of unit tests. */
  openVault?: VaultFactory;
}

/** Build the encrypted, portable vault without exporting the local device or state key. */
export async function prepareWatcherDeployment(options: WatcherDeploymentOptions, input: WatcherDeploymentSecrets): Promise<{
  vaultPath: string; vaultBlob: string; exportedCredentialNames: string[];
}> {
  const dir = resolve(options.outputDir);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const vaultPath = join(dir, 'watcher-vault.enc');
  try { await readFile(vaultPath); throw new CliError('A deployment vault already exists. Choose a new output directory.'); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  const vault = (options.openVault ?? createEncryptedFileVault)({ path: vaultPath, passphrase: async () => Buffer.from(input.vaultPassphrase) });
  const settings = configSchema.parse(options.settings);
  settings.notify.channels = settings.notify.channels.filter(channel => channel.kind !== 'console');
  const projectId = input.config.projectId;
  if (!/^[a-f0-9]{16}$/.test(projectId)) throw new CliError('The watcher project identity is invalid.');
  const fp = await options.sourceVault.get(`project/${projectId}/key/fingerprint`);
  if (!fp || fp.length !== 32) { fp?.fill(0); throw new CliError('The project fingerprint key is unavailable. Scan the project before watcher setup.'); }
  try {
    await vault.set(`project/${projectId}/key/fingerprint`, fp);
    await vault.set(`project/${projectId}/state-initialized`, Buffer.from('1'));
    // The watcher uses its own signer for audit and notification messages. The
    // registered local device's private key is deliberately absent from this vault.
    await vault.set('key/device-ed25519', input.watcherKey.privateKeyDer);
    await vault.set('watcher/signing/private', input.watcherKey.privateKeyDer);
    await vault.set('watcher/signing/public', input.watcherKey.publicKeyDer);
    await vault.set('watcher/runtime-settings', Buffer.from(JSON.stringify({ projectId, settings })));
    const exported = new Set<string>();
    const environmentConsent = new Map<string, boolean>();
    async function consent(name: string): Promise<boolean> {
      if (!environmentConsent.has(name)) environmentConsent.set(name, await options.confirmEnvironmentCredential?.(name) ?? false);
      return environmentConsent.get(name)!;
    }
    async function exportRole(name: string, role: TokenRole): Promise<boolean> {
      // Preserve exact vault roles. A read may reuse the write entry, so it does
      // not create a second copy of the same token under a different role.
      const candidates = role === 'read' ? [credentialVaultName(name, 'read'), credentialVaultName(name, 'write')] : [credentialVaultName(name, 'write')];
      for (const entry of candidates) {
        const value = await options.sourceVault.get(entry);
        if (value === null) continue;
        try {
          const environmentName = entry.endsWith('@read') ? `${name}_READ` : name;
          if (options.sourceVault.backend === 'env' && !await consent(environmentName)) return false;
          await vault.set(entry, value); exported.add(entry.slice('cred/'.length)); return true;
        } finally { value.fill(0); }
      }
      const credential = await options.credentials?.get(name, role);
      if (!credential) return false;
      // CredentialSource's environment fallback is the ordinary variable; a
      // dedicated NAME_READ value is handled by an environment vault above.
      if (credential.source === 'env' && !await consent(name)) return false;
      const entry = credentialVaultName(name, credential.source === 'env' ? 'write' : role);
      const value = Buffer.from(credential.value);
      try { await vault.set(entry, value); exported.add(entry.slice('cred/'.length)); return true; }
      finally { value.fill(0); }
    }
    async function exportCredential(name: string): Promise<void> {
      for (const role of ['read', 'write'] as const) await exportRole(name, role);
    }
    if (settings.hosts.railway.enabled !== false) {
      const names = settings.hosts.railway.tokenType === 'project' ? ['RAILWAY_PROJECT_TOKEN']
        : settings.hosts.railway.tokenType === 'account' ? ['RAILWAY_TOKEN'] : ['RAILWAY_TOKEN', 'RAILWAY_PROJECT_TOKEN'];
      for (const role of ['read', 'write'] as const) for (const name of names) if (await exportRole(name, role)) break;
    }
    if (settings.hosts.vercel.enabled !== false) await exportCredential('VERCEL_TOKEN');
    if (settings.hosts.render.enabled !== false) await exportCredential('RENDER_API_KEY');
    if (settings.hosts.fly.enabled !== false && (settings.hosts.fly.org || settings.hosts.fly.apps?.length)) await exportCredential('FLY_API_TOKEN');
    if (settings.hosts.github.enabled !== false && settings.hosts.github.repos.length) await exportCredential('GITHUB_TOKEN');
    for (const name of new Set(input.config.armed?.clusters.flatMap(cluster => PROVIDER_CREDENTIALS[cluster.provider]) ?? [])) await exportCredential(name);
    const channelIds = new Set(input.config.notify.channels.filter(channel => channel.kind !== 'console').map(channel => channel.settings.id));
    const notificationNames = (await options.sourceVault.list('notify/')).filter(name => {
      const id = name.split('/')[1];
      return id === 'relay' ? input.config.approvals.relay !== null : channelIds.has(id);
    });
    for (const name of notificationNames) {
      const value = await options.sourceVault.get(name);
      if (value === null) continue;
      try {
        if (options.sourceVault.backend === 'env' && !await consent(`KEYSENTRY_VAULT_${name.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`)) continue;
        await vault.set(name, value); exported.add(name);
      } finally { value.fill(0); }
    }
    const encrypted = await readFile(vaultPath);
    try {
      if (encrypted.length > MAX_VAULT_BYTES) throw new CliError('The encrypted deployment vault is too large.');
      return { vaultPath, vaultBlob: encrypted.toString('base64'), exportedCredentialNames: [...exported].sort() };
    } finally { encrypted.fill(0); }
  } finally { fp.fill(0); }
}

export interface WatcherBootstrapOptions { cwd?: string; platform?: NodeJS.Platform; openVault?: VaultFactory }

/** A deployment state key is supplied externally and is never written to its vault. */
function externalStateVault(vault: Vault, projectId: string, externalKey: Buffer): Vault {
  const name = `project/${projectId}/key/state`;
  return {
    backend: vault.backend, weakness: vault.weakness,
    async get(item) { return item === name ? Buffer.from(externalKey) : vault.get(item); },
    async set(item, value) {
      if (item === name) throw new CliError('The watcher state key is supplied through KEYSENTRY_STATE_KEY.');
      await vault.set(item, value);
    },
    async delete(item) {
      if (item === name) throw new CliError('The watcher state key is supplied through KEYSENTRY_STATE_KEY.');
      return vault.delete(item);
    },
    list: prefix => vault.list(prefix),
  };
}

/** Reuse an existing updated vault; deployment input is imported only on first start. */
async function importDeploymentVault(path: string, encoded: string | undefined): Promise<void> {
  try { await readFile(path); return; }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  if (!encoded) throw new CliError('Set KEYSENTRY_WATCHER_VAULT to the encrypted deployment vault from watcher setup.');
  if (encoded.length > Math.ceil(MAX_VAULT_BYTES / 3) * 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
    throw new CliError('KEYSENTRY_WATCHER_VAULT is not a valid encrypted deployment vault.');
  }
  const bytes = Buffer.from(encoded, 'base64');
  try {
    if (bytes.length > MAX_VAULT_BYTES || bytes.toString('base64') !== encoded) throw new Error();
    const data: unknown = JSON.parse(bytes.toString());
    if (!data || typeof data !== 'object' || !('v' in data) || data.v !== 1 || !('entries' in data)) throw new Error();
    try { await writeFile(path, bytes, { flag: 'wx', mode: 0o600 }); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
  } catch { throw new CliError('KEYSENTRY_WATCHER_VAULT is not a valid encrypted deployment vault.'); }
  finally { bytes.fill(0); }
}

async function bindIdentity(stateDir: string, projectId: string): Promise<void> {
  const dir = join(stateDir, '.keysentry');
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const path = join(dir, 'project.json');
  try { await writeFile(path, JSON.stringify({ id: projectId }), { flag: 'wx', mode: 0o600 }); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
  try {
    const saved: unknown = JSON.parse(await readFile(path, 'utf8'));
    if (!saved || typeof saved !== 'object' || !('id' in saved) || saved.id !== projectId) throw new Error();
  } catch { throw new CliError('The watcher project identity does not match this state directory. Restore the matching deployment before continuing.'); }
}

export async function bootstrapWatcher(env: NodeJS.ProcessEnv, options: WatcherBootstrapOptions = {}): Promise<{
  options: RuntimeOptions; config: WatcherConfig; dispose(): void;
}> {
  const encoded = env.KEYSENTRY_STATE_KEY;
  const stateKey = Buffer.from(encoded ?? '', 'base64');
  if (!encoded || stateKey.length !== 32 || stateKey.toString('base64') !== encoded) {
    stateKey.fill(0);
    throw new CliError('KEYSENTRY_STATE_KEY must be base64 encoding of exactly 32 bytes.');
  }
  if (!env.KEYSENTRY_VAULT_PASSPHRASE) { stateKey.fill(0); throw new CliError('Set KEYSENTRY_VAULT_PASSPHRASE to the value from watcher setup.'); }
  let deployKey: Buffer | undefined;
  try {
    const loaded = await loadWatcherConfigFromEnv(env, { cwd: options.cwd, platform: options.platform });
    deployKey = loaded.deployKey;
    const userDir = join(loaded.stateDir, 'vault');
    await mkdir(userDir, { recursive: true, mode: 0o700 });
    const path = join(userDir, 'vault.enc');
    await importDeploymentVault(path, env.KEYSENTRY_WATCHER_VAULT);
    const vault = (options.openVault ?? createEncryptedFileVault)({ path,
      passphrase: async () => Buffer.from(env.KEYSENTRY_VAULT_PASSPHRASE!),
    });
    let settings: ConfigSettings;
    const raw = await vault.get('watcher/runtime-settings');
    try {
      if (!raw) throw new Error();
      const value: unknown = JSON.parse(raw.toString());
      if (!value || typeof value !== 'object' || !('projectId' in value) || value.projectId !== loaded.config.projectId || !('settings' in value)) throw new Error();
      settings = configSchema.parse(value.settings);
    } catch { throw new CliError('The encrypted deployment vault does not match the watcher configuration. Run watcher setup again.'); }
    finally { raw?.fill(0); }
    // Deployment-time authorization and custom feeds come from the authenticated
    // sealed config. These in-memory overlays must be present before the runtime
    // constructs its HTTP guard; the portable settings record stays unchanged.
    settings.autopilot.healthChecks = loaded.config.armed?.healthChecks.map(check => ({ ...check })) ?? settings.autopilot.healthChecks;
    const feeds = settings.monitor.feeds ?? [];
    const feedKeys = new Set(feeds.map(feed => `${feed.url}\0${feed.host ?? ''}`));
    for (const source of loaded.config.sources.extra) for (const host of source.hosts) {
      const identity = `${source.url}\0${host}`;
      if (feedKeys.has(identity)) continue;
      feeds.push({ url: source.url, host });
      feedKeys.add(identity);
    }
    if (feeds.length) settings.monitor.feeds = feeds;
    // A copied desktop path does not identify a filesystem in the deployed
    // watcher. Missing dotenv consumers therefore ask rather than being changed.
    settings.hosts.dotenv.enabled = false;
    const signer = await vault.get('key/device-ed25519');
    try { if (!signer) throw new Error(); const key = deviceKeyFromPrivate(signer); key.privateKeyDer.fill(0); }
    catch { throw new CliError('The watcher signing key could not be opened. Restore its encrypted deployment vault.'); }
    finally { signer?.fill(0); }
    await bindIdentity(loaded.stateDir, loaded.config.projectId);
    const wrapped = externalStateVault(vault, loaded.config.projectId, stateKey);
    return {
      config: loaded.config,
      options: { cwd: loaded.stateDir, userDir, vault: wrapped, settings,
        trustedPlanKeyIds: [...loaded.config.trustedKeyIds],
        env: { ...env, KEYSENTRY_VAULT: 'encrypted-file' }, stdinIsTTY: false, stdoutIsTTY: false,
      },
      dispose: () => stateKey.fill(0),
    };
  } catch (error) { stateKey.fill(0); throw error; }
  finally { deployKey?.fill(0); }
}
