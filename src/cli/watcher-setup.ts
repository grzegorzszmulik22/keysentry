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
  prepareDeployment(input: WatcherDeploymentSecrets): Promise<void | { vaultBlob: string; exportedCredentialNames?: string[]; notes?: string[] }>;
  /**
   * With a kms section (notes/kms.md): wrap the new deployment state key with the configured KMS key. The watcher then
   * receives KEYSENTRY_STATE_KEY_WRAPPED instead of the plain KEYSENTRY_STATE_KEY.
   */
  wrapStateKey?: (stateKey: Buffer, projectId: string) => Promise<string>;
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
  const protectedHosts = deps.protectedHosts ?? deps.config.armed?.hosts ?? [];
  try {
    const prepared = await createWatcherDeployment(deps, platform);
    const { values, deployment } = prepared;
    const write = deps.writeTerminal;
    write(deployment?.exportedCredentialNames?.length ? `Exported credential names: ${deployment.exportedCredentialNames.join(', ')}.` : 'Exported credential names: none.');
    // What the watcher's network settings will be (proxy, carried certificates): fixed text, no values.
    for (const note of deployment?.notes ?? []) write(note);
    write('Store the following values in the platform\'s secret settings only. They are shown once. Keep a separate secure backup.');
    write(`KEYSENTRY_WATCHER_KEY=${values.KEYSENTRY_WATCHER_KEY}`);
    if (values.KEYSENTRY_STATE_KEY_WRAPPED) write(`KEYSENTRY_STATE_KEY_WRAPPED=${values.KEYSENTRY_STATE_KEY_WRAPPED}`);
    else write(`KEYSENTRY_STATE_KEY=${values.KEYSENTRY_STATE_KEY}`);
    write(`KEYSENTRY_VAULT_PASSPHRASE=${values.KEYSENTRY_VAULT_PASSPHRASE}`);
    write(`KEYSENTRY_WATCHER_CONFIG=${values.KEYSENTRY_WATCHER_CONFIG}`);
    if (deployment) {
      write(`KEYSENTRY_WATCHER_VAULT=${deployment.vaultBlob}`);
      write('The encrypted vault bootstrap initializes the encrypted vault on first start. The watcher keeps its updated encrypted vault and state on the private persistent state volume. Keep deployment keys and the passphrase outside that volume.');
    } else {
      write('Copy the encrypted deployment vault and state to the private persistent state volume before starting the watcher. Keep these four variables outside that volume.');
    }
    if (values.KEYSENTRY_STATE_KEY_WRAPPED) write('The state key is wrapped by your KMS key. The watcher also needs the KMS credentials (for example VAULT_TOKEN, or the AWS, Google or Azure credentials the kms section uses) in its secret settings, and the KMS host must be reachable from it.');
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
    return { sealedConfigPath: prepared.sealedConfigPath, template: TEMPLATES[platform], watcherKeyId: prepared.watcherKeyId };
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError('Watcher setup could not finish. No deployment was started.');
  }
}

export interface WatcherDeploymentValues {
  /** The deployment variables, as the hosted platform or the cloud box receives them. */
  values: { KEYSENTRY_WATCHER_KEY: string; KEYSENTRY_STATE_KEY: string; KEYSENTRY_VAULT_PASSPHRASE: string; KEYSENTRY_WATCHER_CONFIG: string;
    /** Present when the setup wrapped the state key with the configured KMS; the plain KEYSENTRY_STATE_KEY is then not shown. */
    KEYSENTRY_STATE_KEY_WRAPPED?: string };
  deployment: { vaultBlob: string; exportedCredentialNames?: string[]; notes?: string[] } | undefined;
  sealedConfigPath: string;
  watcherKeyId: string;
  /** The new watcher's public key, for callers that record it themselves once the deployment is confirmed. */
  watcherPublicKeyDer: Buffer;
}

/** New deploy, state and watcher keys, the sealed config and the portable vault. Shared by watcher setup and the cloud box. */
export async function createWatcherDeployment(deps: Pick<WatcherSetupDependencies, 'vault' | 'audit' | 'config' | 'outputDir' | 'prepareDeployment' | 'wrapStateKey'>,
  platform: WatcherPlatform | 'cloud-box', options: { persistSigningKey?: boolean } = {}): Promise<WatcherDeploymentValues> {
  const config: WatcherConfig = { ...deps.config, notify: { channels: deps.config.notify.channels.filter(channel => channel.kind !== 'console') } };
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
    // A KMS failure stops setup before any secret is shown; nothing is deployed.
    const wrappedState = deps.wrapStateKey ? await deps.wrapStateKey(stateKey, config.projectId) : undefined;
    // A cloud box records its watcher key only after the box confirms it sealed the deployment, and never in the
    // self-hosted watcher's slot, which would stop this computer trusting a watcher that is still running.
    if (options.persistSigningKey !== false) {
      await deps.vault.set('watcher/signing/private', watcherKey.privateKeyDer);
      await deps.vault.set('watcher/signing/public', watcherKey.publicKeyDer);
      await deps.audit.append({ kind: 'watcher:setup', summary: 'Watcher deployment prepared.', data: { platform, watcherKeyId: watcherKey.keyId } });
    }
    return { sealedConfigPath, watcherKeyId: watcherKey.keyId, deployment: deployment ?? undefined, watcherPublicKeyDer: Buffer.from(watcherKey.publicKeyDer),
      values: { KEYSENTRY_WATCHER_KEY: deployKey.toString('base64'), KEYSENTRY_STATE_KEY: stateKey.toString('base64'),
        KEYSENTRY_VAULT_PASSPHRASE: printablePassphrase.toString(), KEYSENTRY_WATCHER_CONFIG: sealed,
        ...(wrappedState ? { KEYSENTRY_STATE_KEY_WRAPPED: wrappedState } : {}) } };
  } catch (error) {
    if (error instanceof CliError) throw error;
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new CliError('A watcher config already exists in the output directory. Choose a new directory for this setup.');
    throw new CliError('Watcher setup could not finish. No deployment was started.');
  } finally {
    deployKey.fill(0); stateKey.fill(0); printablePassphrase.fill(0); watcherKey.privateKeyDer.fill(0);
  }
}

/** The fixed reason a watcher's /healthz gives when its network transport refuses every request (review H1). */
export const WATCHER_NETWORK_PROBLEM = 'The watcher\'s proxy or certificate settings cannot be used, so it refuses every outbound request.';

/** The fixed reason a watcher's /healthz gives after repeated failed connections to its proxy (review EA H1). */
export const WATCHER_PROXY_UNREACHABLE = 'The watcher cannot reach its proxy: its last connection attempts to the proxy all failed, so no outbound request can be made.';

/** The deployed watcher's /healthz problem: a transport that refuses every request, or a proxy it keeps failing to reach. */
export function watcherNetworkHealth(network: { problem: string | null; proxyUnreachable?: () => boolean }): { code: 'network'; reason: string } | null {
  if (network.problem) return { code: 'network', reason: WATCHER_NETWORK_PROBLEM };
  if (network.proxyUnreachable?.()) return { code: 'network', reason: WATCHER_PROXY_UNREACHABLE };
  return null;
}

/** The supplied client must be the runtime's guarded client, including a user rule for this origin. */
export async function watcherStatus(http: HttpClient, value: string, localVersion: string): Promise<{
  healthy: true; version: string; localVersion: string; versionMatches: boolean;
  /** Offline mode in the watcher: breach feeds and security news are not polled (review L9). */
  feeds: 'polled' | 'offline';
}> {
  let url: URL;
  try {
    url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/' || url.port) throw new Error();
  } catch { throw new CliError('Use an HTTPS watcher origin without credentials.'); }
  let unhealthy = false;
  try {
    const response = await http.request({ method: 'GET', url: `${url.origin}/healthz` });
    if (response.text.length > 4096) throw new Error();
    const body = response.json<{ ok?: unknown; version?: unknown; problem?: unknown; feeds?: unknown }>();
    // Only the known problem code is read; the remote reason text is never printed.
    if (response.status === 503 && body?.ok === false && body.problem === 'network') { unhealthy = true; throw new Error(); }
    if (response.status !== 200) throw new Error();
    if (body?.ok !== true || typeof body.version !== 'string' || !/^[A-Za-z0-9.+-]{1,80}$/.test(body.version)) throw new Error();
    return { healthy: true, version: body.version, localVersion, versionMatches: body.version === localVersion,
      feeds: body.feeds === 'offline' ? 'offline' : 'polled' };
  } catch {
    if (unhealthy) {
      throw new CliError(`The watcher is running but unhealthy. ${WATCHER_NETWORK_PROBLEM} Check network.proxy and network.caFile, then run watcher setup again.`);
    }
    throw new CliError('The watcher health check did not succeed.');
  }
}
