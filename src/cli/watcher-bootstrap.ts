import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import type { CredentialSource, HostId, HttpClient, TokenRole, Vault } from '../types.js';
import { HOST_CREDENTIALS } from '../hosts/credentials.js';
import { DEPLOYMENT_CA_VAULT_NAME, setupNetwork } from './network-setup.js';
import {
  CaBundleError, PROXY_AUTH_CREDENTIAL, PROXY_AUTH_VAULT_NAME, TransportConfigError, loadCaBundle, parseCaBundle, resolveProxySettings,
  type ResolvedProxy,
} from '../net/transport.js';
import { credentialVaultName, createCredentialSource, createEncryptedFileVault } from '../vault/index.js';
import { createFetchHttp } from '../http.js';
import { unwrapDeploymentStateKey } from '../kms/index.js';
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
  /**
   * The project directory `network.caFile` is relative to. Required when the settings name a CA file: the watcher
   * receives the certificates themselves, because the path names a file on this computer (review H1).
   */
  cwd?: string;
  /** This terminal's environment: proxy credentials in HTTPS_PROXY for the configured network.proxy (with consent). */
  env?: NodeJS.ProcessEnv;
}

/** Build the encrypted, portable vault without exporting the local device or state key. */
export async function prepareWatcherDeployment(options: WatcherDeploymentOptions, input: WatcherDeploymentSecrets): Promise<{
  vaultPath: string; vaultBlob: string; exportedCredentialNames: string[];
  /** Plain lines for the person running setup: what the watcher's network settings will be. */
  notes: string[];
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
    const notes = await carryNetworkSettings({ settings, sourceVault: options.sourceVault, vault, consent, exported,
      ...(options.cwd ? { cwd: options.cwd } : {}), env: options.env ?? {} });
    if (settings.hosts.railway.enabled !== false) {
      const names = settings.hosts.railway.tokenType === 'project' ? ['RAILWAY_PROJECT_TOKEN']
        : settings.hosts.railway.tokenType === 'account' ? ['RAILWAY_TOKEN'] : ['RAILWAY_TOKEN', 'RAILWAY_PROJECT_TOKEN'];
      for (const role of ['read', 'write'] as const) for (const name of names) if (await exportRole(name, role)) break;
    }
    if (settings.hosts.vercel.enabled !== false) await exportCredential('VERCEL_TOKEN');
    if (settings.hosts.render.enabled !== false) await exportCredential('RENDER_API_KEY');
    if (settings.hosts.fly.enabled !== false && (settings.hosts.fly.org || settings.hosts.fly.apps?.length)) await exportCredential('FLY_API_TOKEN');
    if (settings.hosts.github.enabled !== false && settings.hosts.github.repos.length) await exportCredential('GITHUB_TOKEN');
    // Phase 5 and 6 hosts: exported when enabled and scoped like their loadConfig wiring (src/cli/config.ts).
    const h = settings.hosts;
    const phaseHosts: [HostId, boolean | undefined, boolean][] = [
      ['netlify', h.netlify.enabled, true], ['heroku', h.heroku.enabled, true], ['digitalocean', h.digitalocean.enabled, true],
      ['cloudflare-workers', h.cloudflare.enabled, !!h.cloudflare.accountId], ['supabase-functions', h.supabase.enabled, true],
      ['coolify', h.coolify.enabled, !!h.coolify.baseUrl], ['zeabur', h.zeabur.enabled, true],
      ['kubernetes', h.kubernetes.enabled, !!h.kubernetes.server && h.kubernetes.namespaces.length > 0],
      ['aws-secrets-manager', h.awsSecretsManager.enabled, !!h.awsSecretsManager.region], ['vault-kv', h.vault.enabled, !!h.vault.address],
      ['doppler', h.doppler.enabled, !!(h.doppler.configs?.length || h.doppler.projects?.length || h.doppler.enabled)],
      ['infisical', h.infisical.enabled, h.infisical.projects.length > 0],
    ];
    for (const [host, enabled, scoped] of phaseHosts) {
      if (enabled !== false && scoped) for (const name of HOST_CREDENTIALS[host]) await exportCredential(name);
    }
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
    // Audit export credentials (notes/audit-export.md): only the configured targets' entries.
    const exportIds = new Set(settings.audit.export.map(target => target.id));
    const exportNames = (await options.sourceVault.list('audit-export/')).filter(name => exportIds.has(name.split('/')[1] ?? ''));
    for (const name of exportNames) {
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
      return { vaultPath, vaultBlob: encrypted.toString('base64'), exportedCredentialNames: [...exported].sort(), notes };
    } finally { encrypted.fill(0); }
  } finally { fp.fill(0); }
}

/**
 * The deployment's network settings must work where the watcher runs (review H1). The CA bundle travels as PEM text in
 * the encrypted deployment vault, and the proxy credential the configured proxy needs travels there too (an
 * environment value only with consent for its exact variable name). Settings that cannot be carried stop setup.
 */
async function carryNetworkSettings(input: {
  settings: ConfigSettings; sourceVault: Vault; vault: Vault; consent: (name: string) => Promise<boolean>; exported: Set<string>;
  cwd?: string; env: NodeJS.ProcessEnv;
}): Promise<string[]> {
  const { network } = input.settings;
  const notes: string[] = [];
  if (network.caFile) {
    if (!input.cwd) throw new CliError('Watcher setup needs the project directory to carry the certificates in network.caFile.');
    let pems: string[];
    try { pems = (await loadCaBundle(network.caFile, { cwd: input.cwd })).pems; }
    catch (error) {
      if (error instanceof CaBundleError) throw new CliError(`The watcher cannot be given the certificates in network.caFile, so nothing was deployed: ${error.message}`);
      throw error;
    }
    await input.vault.set(DEPLOYMENT_CA_VAULT_NAME, Buffer.from(pems.join('\n'), 'utf8'));
    notes.push(`The watcher trusts the ${pems.length === 1 ? 'certificate' : `${pems.length} certificates`} from network.caFile, carried in its encrypted vault.`);
  }
  if (network.proxy) {
    let resolved: ResolvedProxy;
    try {
      resolved = await resolveProxySettings({ configProxy: network.proxy, configNoProxy: network.noProxy, env: input.env, vault: input.sourceVault });
    } catch (error) {
      if (error instanceof TransportConfigError) throw new CliError(`The watcher cannot use network.proxy, so nothing was deployed: ${error.message}`);
      throw error;
    }
    const credentials = resolved.settings?.credentials;
    if (credentials) {
      // The proxy credential follows the proxy: from the vault as stored, from an environment source only with consent.
      const fromEnvironment = resolved.credentialSource === 'env' ? 'HTTPS_PROXY' : input.sourceVault.backend === 'env' ? PROXY_AUTH_CREDENTIAL : null;
      if (fromEnvironment === null || await input.consent(fromEnvironment)) {
        const value = Buffer.from(`${credentials.username}:${credentials.password}`, 'utf8');
        try { await input.vault.set(PROXY_AUTH_VAULT_NAME, value); input.exported.add(PROXY_AUTH_CREDENTIAL); } finally { value.fill(0); }
      } else {
        notes.push(`The proxy credential was not copied, so the proxy may refuse the watcher. Store it in the watcher with ${PROXY_AUTH_CREDENTIAL} or run setup again.`);
      }
    }
    notes.push(`The watcher sends its requests through the proxy at ${resolved.settings!.url} (network.proxy), so it must be able to reach that proxy where it runs. For a hosted platform outside your network, remove network.proxy before watcher setup.`);
  } else if (input.env.HTTPS_PROXY?.trim() || input.env.https_proxy?.trim()) {
    notes.push('HTTPS_PROXY from this terminal is not carried. Set it in the watcher\'s environment if the watcher needs a proxy.');
  }
  return notes;
}

export interface WatcherBootstrapOptions {
  cwd?: string; platform?: NodeJS.Platform; openVault?: VaultFactory;
  /** Raw transport for unwrapping KEYSENTRY_STATE_KEY_WRAPPED with the deployment's KMS (tests inject a fake). */
  http?: HttpClient; now?: () => Date;
}

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
  try { await mkdir(dir, { recursive: true, mode: 0o700 }); }
  catch { throw new CliError(`Could not prepare the directory ${dir}. Set KEYSENTRY_STATE_DIR to a writable directory.`); }
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
  // KEYSENTRY_STATE_KEY_WRAPPED is the alternative: it is unwrapped with the deployment's kms settings once its vault is open.
  const wrappedState = env.KEYSENTRY_STATE_KEY_WRAPPED;
  if (wrappedState && env.KEYSENTRY_STATE_KEY) throw new CliError('Set KEYSENTRY_STATE_KEY or KEYSENTRY_STATE_KEY_WRAPPED, not both.');
  const encoded = env.KEYSENTRY_STATE_KEY;
  let stateKey: Buffer = Buffer.from(encoded ?? '', 'base64');
  if (!wrappedState && (!encoded || stateKey.length !== 32 || stateKey.toString('base64') !== encoded)) {
    stateKey.fill(0);
    throw new CliError('KEYSENTRY_STATE_KEY must be base64 encoding of exactly 32 bytes.');
  }
  if (!env.KEYSENTRY_VAULT_PASSPHRASE) { stateKey.fill(0); throw new CliError('Set KEYSENTRY_VAULT_PASSPHRASE to the value from watcher setup.'); }
  let deployKey: Buffer | undefined;
  try {
    const loaded = await loadWatcherConfigFromEnv(env, { cwd: options.cwd, platform: options.platform });
    deployKey = loaded.deployKey;
    const userDir = resolve(options.cwd ?? process.cwd(), env.KEYSENTRY_USER_DIR ?? join(loaded.stateDir, 'user'));
    // Keep the existing durable vault location across upgrades. Runtime metadata
    // belongs in user/, while changing the vault path would lose later updates.
    const vaultDir = join(loaded.stateDir, 'vault');
    for (const [directory, variable] of [[userDir, 'KEYSENTRY_USER_DIR'], [vaultDir, 'KEYSENTRY_STATE_DIR']] as const) {
      try { await mkdir(directory, { recursive: true, mode: 0o700 }); }
      catch { throw new CliError(`Could not prepare the directory ${directory}. Set ${variable} to a writable directory.`); }
    }
    const path = join(vaultDir, 'vault.enc');
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
    // network.caFile names a file on the computer that ran setup; the deployment carries the certificates themselves
    // (review H1), and setupNetwork reads them from this vault. A deployment made before that cannot verify servers.
    if (settings.network.caFile) {
      const carried = await vault.get(DEPLOYMENT_CA_VAULT_NAME);
      if (!carried) throw new CliError('This watcher deployment does not carry the certificates from network.caFile, so it could not verify any server. Run watcher setup again with this version of keysentry.');
      try { parseCaBundle(carried, settings.network.caFile); }
      catch (error) {
        if (error instanceof CaBundleError) throw new CliError(`The certificates carried for network.caFile cannot be used: ${error.message} Run watcher setup again.`);
        throw error;
      } finally { carried.fill(0); }
    }
    await bindIdentity(loaded.stateDir, loaded.config.projectId);
    if (wrappedState) {
      let transport = options.http;
      if (!transport) {
        // The deployment's proxy and CA settings apply to the KMS call too, with the sealed team policy's network rules.
        const network = await setupNetwork({ settings: settings.network, cwd: loaded.stateDir, env, vault,
          policy: loaded.config.team?.policy?.policy ?? null });
        if (network.problem) throw new CliError(`The watcher's network settings cannot be used, so the KMS key was not contacted: ${network.problem.message}`);
        transport = network.transport;
      }
      stateKey = await unwrapDeploymentStateKey({ encoded: wrappedState, kms: settings.kms, projectId: loaded.config.projectId,
        credentials: createCredentialSource(vault, env), transport,
        receiptPath: join(loaded.stateDir, '.keysentry', 'network.jsonl'), ...(options.now ? { now: options.now } : {}) });
    }
    // The state key now comes from the environment in either form, so the runtime does not unwrap it again.
    delete settings.kms;
    const wrapped = externalStateVault(vault, loaded.config.projectId, stateKey);
    return {
      config: loaded.config,
      options: { cwd: loaded.stateDir, userDir, vault: wrapped, settings,
        // The sealed roster and policy (authenticated by the deploy key) are this watcher's team governance.
        teamBundle: loaded.config.team ?? null,
        trustedPlanKeyIds: [...loaded.config.trustedKeyIds],
        env: { ...env, KEYSENTRY_VAULT: 'encrypted-file' }, stdinIsTTY: false, stdoutIsTTY: false,
      },
      dispose: () => stateKey.fill(0),
    };
  } catch (error) { stateKey.fill(0); throw error; }
  finally { deployKey?.fill(0); }
}
