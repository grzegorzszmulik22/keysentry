import { randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { TOKEN_CAPABILITIES } from '../doctor/index.js';
import { generateDeviceKey, type DeviceKey } from '../security/index.js';
import type { AuditLog, HostId, HttpClient, Vault } from '../types.js';
import { sealWatcherConfig, type WatcherConfig } from '../watcher/index.js';
import { CliError } from './errors.js';

export type WatcherPlatform = 'compose' | 'railway' | 'fly' | 'render' | 'github-actions';
export interface WatcherSetupOptions { platform?: WatcherPlatform; remote?: boolean; relay?: boolean }
export interface WatcherDeploymentSecrets {
  stateKey: Buffer;
  vaultPassphrase: Buffer;
  watcherKey: DeviceKey;
  config: WatcherConfig;
}
export interface WatcherSetupDependencies {
  assertHuman(action: string): void;
  interactive: boolean;
  json?: boolean;
  vault: Vault;
  audit: AuditLog;
  config: WatcherConfig;
  outputDir: string;
  protectedHosts?: HostId[];
  /** Dedicated terminal sink: never a logger, JSON writer, or captured command result. */
  writeTerminal(text: string): void;
  /** Initialize the portable encrypted vault/state before any deploy secrets are shown. */
  prepareDeployment(input: WatcherDeploymentSecrets): Promise<void | { vaultBlob: string; exportedCredentialNames?: string[] }>;
}

const TEMPLATES: Record<WatcherPlatform, string> = {
  compose: 'deploy/compose/docker-compose.yml', railway: 'deploy/railway/.railway/railway.ts',
  fly: 'deploy/fly/fly.toml', render: 'deploy/render/render.yaml',
  'github-actions': 'deploy/github-actions/keysentry-watch.yml',
};

/** Create deployment artifacts locally. Secret output is intentionally outside the returned result. */
export async function setupWatcher(deps: WatcherSetupDependencies, options: WatcherSetupOptions = {}): Promise<{
  sealedConfigPath: string; template: string; watcherKeyId: string;
}> {
  deps.assertHuman('set up a watcher');
  if (options.remote || options.relay) throw new CliError('Watcher setup is a local change. Run it on your own computer.');
  if (!deps.interactive || deps.json) throw new CliError('Watcher setup needs an interactive terminal and cannot print secrets in JSON.');
  const platform = options.platform ?? 'compose';
  if (!Object.hasOwn(TEMPLATES, platform)) throw new CliError('Choose compose, railway, fly, render, or github-actions for the watcher.');
  const config: WatcherConfig = { ...deps.config, notify: { channels: deps.config.notify.channels.filter(channel => channel.kind !== 'console') } };
  const protectedHosts = deps.protectedHosts ?? deps.config.armed?.hosts ?? [];
  const deployKey = randomBytes(32), stateKey = randomBytes(32), vaultPassphrase = randomBytes(32);
  const watcherKey = generateDeviceKey();
  // Printable random bytes have full entropy and avoid quoting or newline ambiguities in platform settings.
  const printablePassphrase = Buffer.from(vaultPassphrase.toString('base64url'));
  vaultPassphrase.fill(0);
  try {
    const sealed = sealWatcherConfig(config, deployKey);
    const outputDir = resolve(deps.outputDir), sealedConfigPath = join(outputDir, 'watcher-config.sealed');
    await mkdir(outputDir, { recursive: true, mode: 0o700 });
    await writeFile(sealedConfigPath, `${sealed}\n`, { mode: 0o600, flag: 'wx' });
    const deployment = await deps.prepareDeployment({ stateKey, vaultPassphrase: printablePassphrase, watcherKey, config });
    await deps.vault.set('watcher/signing/private', watcherKey.privateKeyDer);
    await deps.vault.set('watcher/signing/public', watcherKey.publicKeyDer);
    await deps.audit.append({ kind: 'watcher:setup', summary: 'Watcher deployment prepared.', data: { platform, watcherKeyId: watcherKey.keyId } });
    const write = deps.writeTerminal;
    write(deployment?.exportedCredentialNames?.length ? `Exported credential names: ${deployment.exportedCredentialNames.join(', ')}.` : 'Exported credential names: none.');
    write('Store the following values in the platform\'s secret settings only. They are shown once. Keep a separate secure backup.');
    write(`KEYSENTRY_WATCHER_KEY=${deployKey.toString('base64')}`);
    write(`KEYSENTRY_STATE_KEY=${stateKey.toString('base64')}`);
    write(`KEYSENTRY_VAULT_PASSPHRASE=${printablePassphrase.toString()}`);
    write(`KEYSENTRY_WATCHER_CONFIG=${sealed}`);
    if (deployment) {
      write(`KEYSENTRY_WATCHER_VAULT=${deployment.vaultBlob}`);
      write('The encrypted vault bootstrap initializes the encrypted vault on first start. The watcher keeps its updated encrypted vault and state on the private persistent state volume. Keep deployment keys and the passphrase outside that volume.');
    } else {
      write('Copy the encrypted deployment vault and state to the private persistent state volume before starting the watcher. Keep these four variables outside that volume.');
    }
    write('A 30-second token guide: read-role tokens inspect your services; write-role tokens change selected variables and deploy. Use a separate token per protected project or app where the platform supports it. keysentry cannot prove the scope of an opaque token.');
    const capabilityIds = [...new Set([...protectedHosts, ...deps.config.armed?.clusters.map(cluster => cluster.provider) ?? []])];
    for (const id of capabilityIds) {
      const capability = TOKEN_CAPABILITIES[id];
      if (!capability) continue;
      const token = capability.tokens.find(item => item.recommended && item.canWrite);
      if (!token) continue;
      write(`${capability.platform}: ${token.name}. ${token.scope} ${token.howToCreate}`);
    }
    // Deployment tokens are a separate concern from tokens for protected hosts.
    if (!capabilityIds.includes(platform as HostId)) {
      const capability = TOKEN_CAPABILITIES[platform];
      const token = capability?.tokens.find(item => item.recommended && item.canWrite);
      if (capability && token) write(`${capability.platform}: ${token.name}. ${token.scope} ${token.howToCreate}`);
    }
    if (protectedHosts.includes(platform as HostId)) write('This watcher runs on a platform it protects. An incident there requires you to rotate the watcher\'s own tokens by hand and run watcher setup again.');
    write(`Use ${TEMPLATES[platform]}. Follow the ${platform} steps in deploy/README.md for secret settings, private persistent storage, and stopping the watcher.`);
    return { sealedConfigPath, template: TEMPLATES[platform], watcherKeyId: watcherKey.keyId };
  } catch (error) {
    if (error instanceof CliError) throw error;
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new CliError('A watcher config already exists in the output directory. Choose a new directory for this setup.');
    throw new CliError('Watcher setup could not finish. No deployment was started.');
  } finally {
    deployKey.fill(0); stateKey.fill(0); printablePassphrase.fill(0); watcherKey.privateKeyDer.fill(0);
  }
}

/** The supplied client must be the runtime's guarded client, including a user rule for this origin. */
export async function watcherStatus(http: HttpClient, value: string, localVersion: string): Promise<{
  healthy: true; version: string; localVersion: string; versionMatches: boolean;
}> {
  let url: URL;
  try {
    url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/' || url.port) throw new Error();
  } catch { throw new CliError('Use an HTTPS watcher origin without credentials.'); }
  try {
    const response = await http.request({ method: 'GET', url: `${url.origin}/healthz` });
    if (response.status !== 200 || response.text.length > 4096) throw new Error();
    const body = response.json<{ ok?: unknown; version?: unknown }>();
    if (body?.ok !== true || typeof body.version !== 'string' || !/^[A-Za-z0-9.+-]{1,80}$/.test(body.version)) throw new Error();
    return { healthy: true, version: body.version, localVersion, versionMatches: body.version === localVersion };
  } catch { throw new CliError('The watcher health check did not succeed.'); }
}
