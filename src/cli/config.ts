import { CliError } from './errors.js';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { isIP } from 'node:net';
import { parseDocument, stringify } from 'yaml';
import { z } from 'zod';
import { createLogger, createRedactor } from '../core/index.js';
import { createFetchHttp } from '../http.js';
import {
  createRailwayHost, createVercelHost, createRenderHost, createFlyHost,
  createGithubActionsHost, createDotenvHost, createNetlifyHost, createHerokuHost, createDigitalOceanHost,
  createCloudflareWorkersHost, createSupabaseFunctionsHost, createCoolifyHost, coolifyApiRoot, createZeaburHost,
  createKubernetesHost, createAwsSecretsManagerHost, createVaultKvHost, createDopplerHost, createInfisicalHost,
  type InfisicalAuth,
} from '../hosts/index.js';
import { NON_SECRET_CREDENTIALS, PROVIDER_CREDENTIALS } from '../providers/index.js';
import { HOST_CREDENTIALS } from '../hosts/credentials.js';
import { rulesForUserUrls } from '../net/allowlist.js';
import { CREDENTIAL_NAMES, createCredentialSource, createEnvVault } from '../vault/index.js';
import {
  combineNotifiers, createConsoleNotifier, createWebhookNotifier, defaultPolicy,
  type BreachFeed, type GithubOptions, type UsageOptions,
} from '../monitor/index.js';
import type { RotateOptions } from '../rotate/index.js';
import type { EgressRule, HostAdapter, HostId, HttpClient, Logger, Notifier, Policy, ProviderContext, Redactor, TokenRole, Vault } from '../types.js';
import { HOST_IDS } from '../types.js';

const nonempty = z.string().trim().min(1);
const list = z.array(nonempty);
const positive = z.number().finite().positive();
const hostId = z.enum(HOST_IDS);
const exactHostname = z.string().trim().toLowerCase().refine(value => {
  if (value.length > 253 || !value.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return false;
  try {
    // URL normalization also catches alternate IPv4 forms such as 127.1 or a decimal integer.
    const normalized = new URL(`https://${value}`).hostname;
    return normalized === value && isIP(normalized) === 0;
  } catch { return false; }
});
const rule = z.object({
  action: z.enum(['alert', 'cap', 'rotate', 'breach-mode']).optional(),
  scope: z.enum(['cluster', 'service', 'host']).optional(),
  minConfidence: z.enum(['high', 'medium', 'low']).optional(),
}).strict();
const safeUrl = z.string().url().refine(value => {
  const url = new URL(value);
  return (url.protocol === 'https:' || url.protocol === 'http:') && !url.username && !url.password;
});
const guardedUrl = safeUrl.refine(value => {
  const url = new URL(value);
  return url.protocol === 'https:' && !url.port && !url.hash && !isIP(url.hostname.replace(/^\[|\]$/g, ''))
    && !/^[a-z]+:\/\/[^/]*@/i.test(value);
});
/**
 * A self-hosted server's https origin (optionally followed by the documented API prefix). It must be a DNS name: the
 * egress guard refuses IP literals. An explicit port is allowed; egress then allows exactly that port.
 */
const selfHostedOrigin = (apiPrefix?: string) => z.string().trim().refine(value => {
  try {
    const url = new URL(value);
    const path = url.pathname.replace(/\/+$/, '');
    return url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash
      && !/[?#\\]/.test(value) && (path === '' || path === apiPrefix) && isIP(url.hostname.replace(/^\[|\]$/g, '')) === 0;
  } catch { return false; }
});
const k8sLabel = z.string().regex(/^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$/);
const zeaburId = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);
/** Secret stores: `immediate` only when every consumer reads the store at use time (see the README). */
const storeActivation = z.enum(['manual', 'immediate']).optional();
const channelId = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);
const channelSettings = z.object({
  id: channelId,
  kind: z.enum(['telegram', 'discord', 'slack', 'ntfy', 'webhook', 'resend', 'smtp', 'console']),
  server: guardedUrl.optional(), from: nonempty.optional(), to: z.array(nonempty).optional(),
  host: exactHostname.optional(), port: z.union([z.literal(465), z.literal(587)]).optional(),
}).strict();
const repository = nonempty.refine(value => {
  const parts = value.split('/');
  return parts.length === 2 && /^[A-Za-z0-9-]+$/.test(parts[0]!)
    && /^[A-Za-z0-9_.-]+$/.test(parts[1]!) && parts[1] !== '.' && parts[1] !== '..';
});

/** Configuration intentionally has no fields for host or provider secrets. */
export const configSchema = z.object({
  hosts: z.object({
    railway: z.object({ enabled: z.boolean().optional(), projectIds: list.optional(), tokenType: z.enum(['account', 'project']).optional() }).strict().prefault({}),
    vercel: z.object({ enabled: z.boolean().optional(), teamId: nonempty.optional(), targets: z.array(z.enum(['production', 'preview', 'development'])).min(1).optional() }).strict().prefault({}),
    render: z.object({ enabled: z.boolean().optional() }).strict().prefault({}),
    fly: z.object({ enabled: z.boolean().optional(), org: nonempty.optional(), apps: list.optional() }).strict().prefault({}),
    github: z.object({ enabled: z.boolean().optional(), repos: z.array(repository).default([]) }).strict().prefault({}),
    dotenv: z.object({ enabled: z.boolean().optional(), roots: list.default(['.']), includeTemplates: z.boolean().default(false) }).strict().prefault({}),
    // Phase 6 deploy platforms (notes/hosts-a.md, notes/hosts-b.md).
    netlify: z.object({
      enabled: z.boolean().optional(), accountSlug: nonempty.optional(), siteIds: list.optional(),
      contexts: z.array(z.enum(['production', 'deploy-preview', 'branch-deploy', 'dev'])).min(1).optional(),
      shared: z.boolean().optional(),
    }).strict().prefault({}),
    heroku: z.object({ enabled: z.boolean().optional(), apps: list.optional(), team: nonempty.optional() }).strict().prefault({}),
    digitalocean: z.object({ enabled: z.boolean().optional(), apps: list.optional() }).strict().prefault({}),
    cloudflare: z.object({
      enabled: z.boolean().optional(),
      accountId: z.string().regex(/^[A-Za-z0-9]{1,32}$/).optional(),
      products: z.array(z.enum(['workers', 'pages'])).min(1).optional(),
      scripts: list.optional(),
      pagesProjects: list.optional(),
      pagesEnvironments: z.array(z.enum(['production', 'preview'])).min(1).optional(),
    }).strict().prefault({}),
    supabase: z.object({
      enabled: z.boolean().optional(),
      projectRefs: z.array(z.string().regex(/^[a-z]{20}$/)).min(1).optional(),
    }).strict().prefault({}),
    coolify: z.object({
      enabled: z.boolean().optional(),
      baseUrl: nonempty.refine(value => { try { coolifyApiRoot(value); return true; } catch { return false; } }).optional(),
      include: z.array(z.enum(['applications', 'services'])).min(1).optional(),
      applications: list.optional(),
      services: list.optional(),
      redeploy: z.enum(['restart', 'deploy']).optional(),
    }).strict().prefault({}),
    zeabur: z.object({ enabled: z.boolean().optional(), ownerId: zeaburId.optional(), projectIds: z.array(zeaburId).min(1).optional() }).strict().prefault({}),
    // Phase 5 secret stores (notes/secret-stores.md).
    kubernetes: z.object({
      enabled: z.boolean().optional(),
      server: selfHostedOrigin().optional(),
      namespaces: z.array(k8sLabel).default([]),
      labelSelector: nonempty.optional(),
      cluster: nonempty.optional(),
      excludeTypes: z.array(nonempty).optional(),
      restartDeployments: z.record(z.string().regex(/^[a-z0-9-]{1,63}\/[a-z0-9.-]{1,253}$/), z.array(nonempty).min(1)).optional(),
    }).strict().prefault({}),
    awsSecretsManager: z.object({
      enabled: z.boolean().optional(),
      region: z.string().regex(/^(?:[a-z]+-)+\d+$/).optional(),
      secretIds: list.optional(),
      namePrefixes: z.array(z.string().regex(/^[a-zA-Z0-9 :_@/+=.-]{1,512}$/)).max(10).optional(),
      activation: storeActivation,
    }).strict().prefault({}),
    vault: z.object({
      enabled: z.boolean().optional(),
      address: selfHostedOrigin('/v1').optional(),
      namespace: nonempty.optional(),
      mount: nonempty.optional(),
      paths: list.optional(),
      activation: storeActivation,
    }).strict().prefault({}),
    doppler: z.object({
      enabled: z.boolean().optional(),
      configs: z.array(z.object({ project: nonempty, config: nonempty }).strict()).optional(),
      projects: list.optional(),
      includeBranchConfigs: z.boolean().default(false),
      activation: storeActivation,
    }).strict().prefault({}),
    infisical: z.object({
      enabled: z.boolean().optional(),
      siteUrl: selfHostedOrigin('/api').optional(),
      organizationSlug: nonempty.optional(),
      projects: z.array(z.object({ projectId: nonempty, environments: z.array(nonempty).min(1), secretPath: nonempty.optional() }).strict()).default([]),
      activation: storeActivation,
    }).strict().prefault({}),
  }).strict().prefault({}),
  rotation: z.object({
    graceSeconds: z.number().finite().nonnegative().default(120),
    revoke: z.enum(['after-deploy', 'immediately', 'never']).default('after-deploy'),
    redeploy: z.boolean().default(true),
    revokeUnconfirmed: z.boolean().default(false),
    acceptUnplannedSealed: z.boolean().default(false),
    allowGenerate: z.boolean().default(true),
    verifyRetries: z.number().int().nonnegative().default(4),
    deployTimeoutMs: positive.int().default(600_000),
    pollIntervalMs: positive.int().default(5_000),
  }).strict().prefault({}),
  network: z.object({
    allowHosts: z.array(exactHostname).default([]),
    /** Phase 5: an HTTP(S) proxy for every outbound request (HTTPS_PROXY is also honoured), hosts that bypass it, and
     * a PEM bundle trusted in addition to Node's default roots. */
    proxy: safeUrl.refine(value => { const url = new URL(value); return !url.pathname.replace(/^\/$/, '') && !url.search && !url.hash; }).optional(),
    noProxy: z.array(exactHostname).default([]),
    caFile: nonempty.optional(),
    /** No breach feeds or news: only the hosts and providers you configured are contacted. */
    offline: z.boolean().default(false),
  }).strict().prefault({}),
  /** Phase 5: team mode keeps a signed roster in encrypted state; the policy file narrows what this project may do. */
  team: z.object({ enabled: z.boolean().default(false), policyFile: nonempty.optional() }).strict().prefault({}),
  audit: z.object({
    export: z.array(z.discriminatedUnion('kind', [
      // Syslog over TLS (RFC 5425), host:port only.
      z.object({ kind: z.literal('syslog'), id: channelId, host: exactHostname, port: z.number().int().min(1).max(65535).default(6514),
        appName: z.string().regex(/^[!-~]{1,48}$/).default('keysentry') }).strict(),
      // OpenTelemetry logs over OTLP/HTTP JSON; an optional bearer or header secret lives in the vault.
      z.object({ kind: z.literal('otlp'), id: channelId, url: guardedUrl }).strict(),
      // S3-compatible object storage with SigV4; credentials live in the vault.
      z.object({ kind: z.literal('s3'), id: channelId, endpoint: guardedUrl, bucket: z.string().regex(/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/),
        region: z.string().regex(/^[a-z0-9-]{1,32}$/), prefix: z.string().regex(/^[A-Za-z0-9!_.*'()/-]{0,512}$/).default('keysentry-audit/') }).strict(),
      // Signed webhook: Ed25519 signature by the watcher key, or HMAC with a secret in the vault.
      z.object({ kind: z.literal('webhook'), id: channelId, url: guardedUrl, signing: z.enum(['ed25519', 'hmac-sha256']).default('ed25519') }).strict(),
    ])).max(10).refine(items => new Set(items.map(item => item.id)).size === items.length).default([]),
  }).strict().prefault({}),
  /** Phase 5: wrap the project's state key with your own KMS key; the unwrapped key exists only in memory. */
  kms: z.discriminatedUnion('provider', [
    z.object({ provider: z.literal('aws-kms'), keyId: z.string().regex(/^arn:aws[a-z-]*:kms:[a-z0-9-]+:\d{12}:(?:key|alias)\/[A-Za-z0-9/_-]{1,256}$/),
      region: z.string().regex(/^[a-z0-9-]{1,32}$/) }).strict(),
    z.object({ provider: z.literal('gcp-kms'),
      keyName: z.string().regex(/^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/locations\/[a-z0-9-]+\/keyRings\/[A-Za-z0-9_-]{1,63}\/cryptoKeys\/[A-Za-z0-9_-]{1,63}$/) }).strict(),
    z.object({ provider: z.literal('azure-key-vault'), vaultUrl: guardedUrl, keyName: z.string().regex(/^[A-Za-z0-9-]{1,127}$/),
      keyVersion: z.string().regex(/^[A-Za-z0-9]{32}$/).optional() }).strict(),
    z.object({ provider: z.literal('vault-transit'), address: guardedUrl, mount: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/).default('transit'),
      keyName: z.string().regex(/^[A-Za-z0-9_.-]{1,128}$/), namespace: z.string().regex(/^[A-Za-z0-9_/-]{1,256}$/).optional() }).strict(),
  ]).optional(),
  autopilot: z.object({
    graceMinutes: z.number().finite().nonnegative().default(15),
    maxServices: z.number().int().positive().default(10), showHints: z.boolean().default(false),
    healthChecks: z.array(z.object({ serviceKey: nonempty, url: guardedUrl,
      expectStatus: z.number().int().min(100).max(599).optional(),
    }).strict()).max(50).default([]),
  }).strict().prefault({}),
  notify: z.object({
    channels: z.array(channelSettings).max(50).refine(items => new Set(items.map(item => item.id)).size === items.length).default([]),
    relay: z.object({ server: guardedUrl }).strict().optional(),
  }).strict().prefault({}),
  monitor: z.object({
    interval: positive.default(300),
    autoExecute: z.boolean().default(false),
    autoContain: z.boolean().default(false),
    containCooldownMinutes: z.number().finite().nonnegative().default(60),
    revokeUnconfirmedOnHighConfidence: z.boolean().default(true),
    cooldownMinutes: z.number().finite().nonnegative().default(60),
    maxAutoRotationsPerDay: z.number().int().nonnegative().default(10),
    rules: z.object({
      canary_triggered: rule.optional(), usage_anomaly: rule.optional(), leak_detected: rule.optional(),
      revoked_upstream: rule.optional(), host_breach_advisory: rule.optional(),
    }).strict().prefault({}),
    feeds: z.array(z.object({ url: safeUrl, host: hostId.optional() }).strict()).optional(),
    github: z.object({ repos: z.array(repository).default([]) }).strict().optional(),
    usage: z.object({ floorUsd: z.number().finite().nonnegative().optional(), hourlyBudgets: z.record(z.string(), z.number().finite().nonnegative()).optional() }).strict().optional(),
    webhooks: z.array(safeUrl).default([]),
  }).strict().prefault({}),
}).strict();

export type ConfigSettings = z.infer<typeof configSchema>;
export interface ConfigMetadata {
  cwd: string;
  configPath: string;
  feedUrls: string[];
  webhooks: string[];
  dotenvRoots: string[];
  userHostRules: EgressRule[];
  settings: ConfigSettings;
}
export interface RuntimeConfig extends ConfigMetadata {
  hosts: HostAdapter[];
  disabledHosts: { host: HostId; reason: string }[];
  providerCtx: ProviderContext;
  rotation: RotateOptions;
  monitor: {
    policy: Policy;
    intervalMs: number;
    notifier: Notifier;
    feeds?: BreachFeed[];
    github?: GithubOptions;
    usageOptions?: UsageOptions;
  };
  /** Scope, policy, and timing only; never serialize RuntimeConfig itself. */
  settings: ConfigSettings;
}
export interface LoadConfigOptions {
  cwd?: string;
  config?: string;
  env?: NodeJS.ProcessEnv;
  http?: HttpClient;
  log?: Logger;
  redactor?: Redactor;
  vault?: Vault;
  role?: TokenRole;
  /** Sealed watcher bootstrap supplies validated non-secret settings in memory. */
  settings?: ConfigSettings;
}

function validate(input: unknown): ConfigSettings {
  const result = configSchema.safeParse(input);
  if (result.success) return result.data;
  // Zod/YAML diagnostics can echo user data. Only fixed schema field names and
  // generic failure categories are exposed, never invalid values or source text.
  const fields = [...new Set(result.error.issues.map(issue => issue.path.slice(0, 2).join('.') || 'configuration'))];
  throw new CliError(`Invalid configuration: check ${fields.join(', ')} (wrong type, unknown field, or invalid value).`);
}

function envValue(env: NodeJS.ProcessEnv, name: string): string | undefined {
  return env[name]?.trim() || undefined;
}
function envList(env: NodeJS.ProcessEnv, name: string): string[] | undefined {
  const value = envValue(env, name);
  return value === undefined ? undefined : value.split(',').map(part => part.trim()).filter(Boolean);
}
function envBoolean(env: NodeJS.ProcessEnv, name: string): boolean | undefined {
  const value = envValue(env, name);
  if (value === undefined) return undefined;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new CliError(`${name} must be true or false.`);
}

async function readSettings(path: string, explicit: boolean): Promise<unknown> {
  let source: string;
  try { source = await readFile(path, 'utf8'); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      if (explicit) throw new CliError('Configuration file was not found. Check --config.');
      return {};
    }
    throw new CliError('Unable to read configuration file.');
  }
  let document;
  try { document = parseDocument(source, { prettyErrors: false }); }
  catch { throw new CliError('Invalid YAML configuration. Check the file syntax.'); }
  if (document.errors.length) {
    const offset = document.errors[0]?.pos[0] ?? 0;
    const line = source.slice(0, offset).split('\n').length;
    throw new CliError(`Invalid YAML configuration at line ${line}. Check the file syntax.`);
  }
  try { return document.toJS({ maxAliasCount: 100 }) ?? {}; }
  catch { throw new CliError('Invalid YAML configuration: too many aliases or invalid structure.'); }
}

/** Read scope and network configuration without opening a vault or building adapters. */
export async function loadConfigMetadata(options: Pick<LoadConfigOptions, 'cwd' | 'config' | 'env' | 'settings'> = {}): Promise<ConfigMetadata> {
  const cwd = resolve(options.cwd ?? process.cwd());
  const configPath = resolve(cwd, options.config ?? 'keysentry.yaml');
  const env = options.env ?? process.env;
  const settings = validate(options.settings ?? await readSettings(configPath, options.config !== undefined));
  const railway = settings.hosts.railway;
  const vercel = settings.hosts.vercel;
  const fly = settings.hosts.fly;
  const github = settings.hosts.github;
  const dotenv = settings.hosts.dotenv;
  railway.projectIds = envList(env, 'RAILWAY_PROJECT_IDS') ?? railway.projectIds;
  vercel.teamId = envValue(env, 'VERCEL_TEAM_ID') ?? vercel.teamId;
  const targets = envList(env, 'VERCEL_TARGETS');
  if (targets) {
    const parsed = z.array(z.enum(['production', 'preview', 'development'])).min(1).safeParse(targets);
    if (!parsed.success) throw new CliError('VERCEL_TARGETS must contain production, preview, or development.');
    vercel.targets = parsed.data;
  }
  fly.org = envValue(env, 'FLY_ORG') ?? fly.org;
  fly.apps = envList(env, 'FLY_APPS') ?? fly.apps;
  // Phase 6 hosts: identifiers only, never secrets.
  const { netlify, heroku, digitalocean, cloudflare, supabase, coolify, zeabur } = settings.hosts;
  netlify.accountSlug = envValue(env, 'NETLIFY_ACCOUNT_SLUG') ?? netlify.accountSlug;
  netlify.siteIds = envList(env, 'NETLIFY_SITE_IDS') ?? netlify.siteIds;
  heroku.apps = envList(env, 'HEROKU_APPS') ?? heroku.apps;
  heroku.team = envValue(env, 'HEROKU_TEAM') ?? heroku.team;
  digitalocean.apps = envList(env, 'DIGITALOCEAN_APPS') ?? digitalocean.apps;
  cloudflare.accountId = envValue(env, 'CLOUDFLARE_ACCOUNT_ID') ?? cloudflare.accountId;
  cloudflare.scripts = envList(env, 'CLOUDFLARE_WORKERS_SCRIPTS') ?? cloudflare.scripts;
  cloudflare.pagesProjects = envList(env, 'CLOUDFLARE_PAGES_PROJECTS') ?? cloudflare.pagesProjects;
  supabase.projectRefs = envList(env, 'SUPABASE_PROJECT_REFS') ?? supabase.projectRefs;
  coolify.baseUrl = envValue(env, 'COOLIFY_URL') ?? coolify.baseUrl;
  zeabur.ownerId = envValue(env, 'ZEABUR_OWNER_ID') ?? zeabur.ownerId;
  zeabur.projectIds = envList(env, 'ZEABUR_PROJECT_IDS') ?? zeabur.projectIds;
  github.repos = envList(env, 'GITHUB_REPOS') ?? github.repos;
  dotenv.roots = envList(env, 'KEYSENTRY_DOTENV_ROOTS') ?? dotenv.roots;
  dotenv.roots = dotenv.roots.map(root => resolve(cwd, root));
  settings.monitor.autoExecute = envBoolean(env, 'KEYSENTRY_AUTO_EXECUTE') ?? settings.monitor.autoExecute;
  settings.monitor.autoContain = envBoolean(env, 'KEYSENTRY_AUTO_CONTAIN') ?? settings.monitor.autoContain;
  settings.monitor.revokeUnconfirmedOnHighConfidence = envBoolean(env, 'KEYSENTRY_REVOKE_UNCONFIRMED_ON_HIGH_CONFIDENCE') ?? settings.monitor.revokeUnconfirmedOnHighConfidence;
  const webhook = envValue(env, 'KEYSENTRY_WEBHOOK_URL');
  if (webhook) settings.monitor.webhooks = [webhook];
  // Validate again after environment overrides (notably repository names/URLs).
  validate(settings);

  return {
    cwd, configPath, settings,
    feedUrls: settings.monitor.feeds?.map(feed => feed.url) ?? [],
    webhooks: [...settings.monitor.webhooks], dotenvRoots: [...dotenv.roots],
    userHostRules: [
      ...[...new Set(settings.network.allowHosts)].map(host => ({ host, owner: 'user', purpose: 'host you added in keysentry.yaml' })),
      ...settings.autopilot.healthChecks.map(check => ({ host: new URL(check.url).hostname, owner: 'user', purpose: 'health check you configured' })),
      ...selfHostedRules(settings),
    ],
  };
}

/**
 * Egress for servers you configured: exactly their host, and their explicit port if they name one (decision 2 in
 * notes/integration-phase6.md), only while that host is enabled. Coolify Cloud and Infisical Cloud have built-in rules.
 */
function selfHostedRules(settings: ConfigSettings): EgressRule[] {
  const { coolify, kubernetes, awsSecretsManager, vault, infisical } = settings.hosts;
  const rules: EgressRule[] = [];
  const add = (enabled: boolean | undefined, url: string | undefined, purpose: string) => {
    if (enabled !== false && url) rules.push(...rulesForUserUrls([url], purpose, 'config', { allowPort: true }));
  };
  if (coolify.baseUrl && !/^https:\/\/app\.coolify\.io\/?$/i.test(coolify.baseUrl)) add(coolify.enabled, coolify.baseUrl, 'Coolify instance you configured');
  add(kubernetes.enabled, kubernetes.server, 'Kubernetes API server you configured');
  add(vault.enabled, vault.address, 'Vault server you configured');
  if (infisical.siteUrl && !/^https:\/\/(?:app|eu)\.infisical\.com(?:\/api)?\/?$/i.test(infisical.siteUrl)) {
    add(infisical.enabled, infisical.siteUrl, 'Infisical server you configured');
  }
  // The AWS endpoint is fixed except for the validated region: one exact rule for the configured region.
  if (awsSecretsManager.enabled !== false && awsSecretsManager.region) {
    rules.push({ host: `secretsmanager.${awsSecretsManager.region}.amazonaws.com`, owner: 'aws-secrets-manager', purpose: 'AWS Secrets Manager in the region you configured' });
  }
  return rules;
}

/** Persist only the non-secret notification metadata; secrets live in the vault. */
export async function saveNotificationSettings(path: string, channels: ConfigSettings['notify']['channels']): Promise<void> {
  const previous = await readSettings(path, false) as Record<string, unknown>;
  const notify = previous.notify && typeof previous.notify === 'object' ? previous.notify as Record<string, unknown> : {};
  const next = { ...previous, notify: { ...notify, channels } };
  validate(next);
  await writeFile(path, stringify(next), { mode: 0o600 });
}

export async function saveNotificationRelay(path: string, server: string): Promise<void> {
  const previous = await readSettings(path, false) as Record<string, unknown>;
  const notify = previous.notify && typeof previous.notify === 'object' ? previous.notify as Record<string, unknown> : {};
  const next = { ...previous, notify: { ...notify, relay: { server } } };
  validate(next);
  await writeFile(path, stringify(next), { mode: 0o600 });
}

/**
 * A secret store's consumers decide when a new value takes effect. `activation: immediate` in keysentry.yaml says
 * every consumer reads the store at use time, so a successful write confirms activation; the default stays manual.
 */
function withStoreActivation(host: HostAdapter, activation: 'manual' | 'immediate' | undefined): HostAdapter {
  if (activation !== 'immediate') return host;
  return {
    id: host.id, capabilities: { ...host.capabilities, activation },
    listServices: () => host.listServices(), readVariables: service => host.readVariables(service),
    writeVariables: (service, vars, opts) => host.writeVariables(service, vars, opts),
    redeploy: service => host.redeploy(service), deploymentStatus: (service, id) => host.deploymentStatus(service, id),
  };
}

/** Vault credentials take precedence; environment remains the last fallback. */
export async function loadConfig(options: LoadConfigOptions = {}): Promise<RuntimeConfig> {
  const metadata = await loadConfigMetadata(options);
  const { settings } = metadata;
  const env = options.env ?? process.env;
  const { railway, vercel, fly, github, dotenv } = settings.hosts;

  const redactor = options.redactor ?? createRedactor();
  const log = options.log ?? createLogger({ redactor });
  const http = options.http ?? createFetchHttp();
  const source = createCredentialSource(options.vault ?? createEnvVault(env), env);
  const tokens: Record<string, string | undefined> = Object.create(null);
  for (const name of CREDENTIAL_NAMES) {
    const credential = await source.get(name, options.role ?? 'read');
    if (credential?.value) { tokens[name] = credential.value; if (!NON_SECRET_CREDENTIALS.includes(name)) redactor.register(credential.value); }
  }
  const credentials: ProviderContext['credentials'] = Object.create(null);
  for (const name of new Set(Object.values(PROVIDER_CREDENTIALS).flat())) {
    if (tokens[name]) credentials[name] = tokens[name];
  }
  for (const url of settings.monitor.webhooks) redactor.register(url);

  const hosts: HostAdapter[] = [];
  const disabledHosts: RuntimeConfig['disabledHosts'] = [];
  /** `reportMissing: false` keeps a host you neither configured nor gave a token out of scan, doctor and status lists. */
  function enable(host: HostId, enabled: boolean | undefined, token: string | undefined, missing: string, factory: (value: string) => HostAdapter,
    reportMissing = true) {
    if (enabled === false) disabledHosts.push({ host, reason: 'Disabled in configuration.' });
    else if (!token) { if (reportMissing) disabledHosts.push({ host, reason: missing }); }
    else hosts.push(factory(token));
  }
  /** Phase 5 and 6 hosts are opt-in: listed as disabled only once a setting or one of their credentials exists. */
  const optedIn = (host: HostId, section: Record<string, unknown>): boolean =>
    HOST_CREDENTIALS[host].some(name => tokens[name]) || Object.entries(section).some(([field, value]) =>
      field === 'enabled' ? value === true : value !== undefined && value !== false && !(Array.isArray(value) && value.length === 0));
  const accountToken = tokens.RAILWAY_TOKEN;
  const projectToken = tokens.RAILWAY_PROJECT_TOKEN;
  const railwayType = railway.tokenType ?? (accountToken ? 'account' : 'project');
  enable('railway', railway.enabled, railwayType === 'account' ? accountToken : projectToken, 'Set RAILWAY_TOKEN or RAILWAY_PROJECT_TOKEN.', token => createRailwayHost({ ...railway, token, tokenType: railwayType, http, log }));
  enable('vercel', vercel.enabled, tokens.VERCEL_TOKEN, 'Set VERCEL_TOKEN.', token => createVercelHost({ ...vercel, token, http, log }));
  enable('render', settings.hosts.render.enabled, tokens.RENDER_API_KEY, 'Set RENDER_API_KEY.', apiKey => createRenderHost({ apiKey, http, log }));
  const flyToken = tokens.FLY_API_TOKEN;
  const flyScoped = Boolean(fly.org || fly.apps?.length);
  enable('fly', fly.enabled, flyScoped ? flyToken : undefined,
    flyToken && !flyScoped ? 'Fly disabled: set FLY_ORG or FLY_APPS when FLY_API_TOKEN is configured.' : 'Set FLY_API_TOKEN.',
    token => createFlyHost({ ...fly, token, http, log }));
  enable('github-actions', github.enabled, github.repos.length ? tokens.GITHUB_TOKEN : undefined,
    github.repos.length ? 'Set GITHUB_TOKEN.' : 'Configure hosts.github.repos or GITHUB_REPOS.', token => createGithubActionsHost({ token, repos: github.repos, http, log }));
  if (dotenv.enabled === false) disabledHosts.push({ host: 'dotenv', reason: 'Disabled in configuration.' });
  else hosts.push(createDotenvHost({ roots: dotenv.roots, includeTemplates: dotenv.includeTemplates, log }));

  // Phase 6 deploy platforms (notes/hosts-a.md, notes/hosts-b.md).
  const { netlify, heroku, digitalocean, cloudflare, supabase, coolify, zeabur } = settings.hosts;
  enable('netlify', netlify.enabled, tokens.NETLIFY_TOKEN, 'Set NETLIFY_TOKEN.', token => createNetlifyHost({
    token, accountSlug: netlify.accountSlug, siteIds: netlify.siteIds, contexts: netlify.contexts, shared: netlify.shared, http, log }),
    optedIn('netlify', netlify));
  enable('heroku', heroku.enabled, tokens.HEROKU_API_KEY, 'Set HEROKU_API_KEY.', token => createHerokuHost({
    token, apps: heroku.apps, team: heroku.team, http, log }), optedIn('heroku', heroku));
  enable('digitalocean', digitalocean.enabled, tokens.DIGITALOCEAN_TOKEN, 'Set DIGITALOCEAN_TOKEN.', token => createDigitalOceanHost({
    token, apps: digitalocean.apps, http, log }), optedIn('digitalocean', digitalocean));
  enable('cloudflare-workers', cloudflare.enabled, cloudflare.accountId ? tokens.CLOUDFLARE_WORKERS_TOKEN : undefined,
    cloudflare.accountId ? 'Set CLOUDFLARE_WORKERS_TOKEN.' : 'Configure hosts.cloudflare.accountId or CLOUDFLARE_ACCOUNT_ID.',
    token => createCloudflareWorkersHost({ accountId: cloudflare.accountId!, products: cloudflare.products, scripts: cloudflare.scripts,
      pagesProjects: cloudflare.pagesProjects, pagesEnvironments: cloudflare.pagesEnvironments, token, http, log }),
    optedIn('cloudflare-workers', cloudflare));
  enable('supabase-functions', supabase.enabled, tokens.SUPABASE_FUNCTIONS_TOKEN, 'Set SUPABASE_FUNCTIONS_TOKEN.',
    token => createSupabaseFunctionsHost({ projectRefs: supabase.projectRefs, token, http, log }), optedIn('supabase-functions', supabase));
  enable('coolify', coolify.enabled, coolify.baseUrl ? tokens.COOLIFY_TOKEN : undefined,
    coolify.baseUrl ? 'Set COOLIFY_TOKEN.' : 'Configure hosts.coolify.baseUrl or COOLIFY_URL.',
    token => createCoolifyHost({ baseUrl: coolify.baseUrl!, include: coolify.include, applications: coolify.applications,
      services: coolify.services, redeploy: coolify.redeploy, token, http, log }), optedIn('coolify', coolify));
  enable('zeabur', zeabur.enabled, tokens.ZEABUR_TOKEN, 'Set ZEABUR_TOKEN.',
    token => createZeaburHost({ ownerId: zeabur.ownerId, projectIds: zeabur.projectIds, token, http, log }), optedIn('zeabur', zeabur));

  // Phase 5 secret stores (notes/secret-stores.md).
  const { kubernetes, awsSecretsManager, vault: vaultKv, doppler, infisical } = settings.hosts;
  const k8sReady = Boolean(kubernetes.server && kubernetes.namespaces.length);
  enable('kubernetes', kubernetes.enabled, k8sReady ? tokens.KUBERNETES_TOKEN : undefined,
    k8sReady ? 'Set KUBERNETES_TOKEN.' : 'Configure hosts.kubernetes.server and hosts.kubernetes.namespaces.',
    token => createKubernetesHost({ server: kubernetes.server!, namespaces: kubernetes.namespaces, labelSelector: kubernetes.labelSelector,
      cluster: kubernetes.cluster, excludeTypes: kubernetes.excludeTypes, restartDeployments: kubernetes.restartDeployments, token, http, log }),
    optedIn('kubernetes', kubernetes));
  const awsId = tokens.AWS_SECRETS_MANAGER_ACCESS_KEY_ID;
  const awsSession = tokens.AWS_SECRETS_MANAGER_SESSION_TOKEN;
  enable('aws-secrets-manager', awsSecretsManager.enabled, awsSecretsManager.region && awsId ? tokens.AWS_SECRETS_MANAGER_SECRET_ACCESS_KEY : undefined,
    awsSecretsManager.region ? 'Set AWS_SECRETS_MANAGER_ACCESS_KEY_ID and AWS_SECRETS_MANAGER_SECRET_ACCESS_KEY.' : 'Configure hosts.awsSecretsManager.region.',
    secretAccessKey => withStoreActivation(createAwsSecretsManagerHost({
      region: awsSecretsManager.region!, secretIds: awsSecretsManager.secretIds, namePrefixes: awsSecretsManager.namePrefixes, http, log,
      credentials: { accessKeyId: awsId!, secretAccessKey, ...(awsSession ? { sessionToken: awsSession } : {}) },
    }), awsSecretsManager.activation), optedIn('aws-secrets-manager', awsSecretsManager));
  enable('vault-kv', vaultKv.enabled, vaultKv.address ? tokens.VAULT_TOKEN : undefined,
    vaultKv.address ? 'Set VAULT_TOKEN.' : 'Configure hosts.vault.address.',
    token => withStoreActivation(createVaultKvHost({ address: vaultKv.address!, namespace: vaultKv.namespace, mount: vaultKv.mount,
      paths: vaultKv.paths, token, http, log }), vaultKv.activation), optedIn('vault-kv', vaultKv));
  // An explicit enabled: true is consent to list every project the token can see.
  const dopplerScoped = Boolean(doppler.configs?.length || doppler.projects?.length || doppler.enabled);
  enable('doppler', doppler.enabled, dopplerScoped ? tokens.DOPPLER_TOKEN : undefined,
    dopplerScoped ? 'Set DOPPLER_TOKEN.' : 'Configure hosts.doppler.configs or hosts.doppler.projects.',
    token => withStoreActivation(createDopplerHost({ configs: doppler.configs, projects: doppler.projects,
      includeBranchConfigs: doppler.includeBranchConfigs, token, http, log }), doppler.activation), optedIn('doppler', doppler));
  const infisicalAuth: InfisicalAuth | undefined = tokens.INFISICAL_TOKEN ? { accessToken: tokens.INFISICAL_TOKEN }
    : tokens.INFISICAL_CLIENT_ID && tokens.INFISICAL_CLIENT_SECRET
      ? { clientId: tokens.INFISICAL_CLIENT_ID, clientSecret: tokens.INFISICAL_CLIENT_SECRET,
        ...(infisical.organizationSlug ? { organizationSlug: infisical.organizationSlug } : {}) }
      : undefined;
  enable('infisical', infisical.enabled, infisical.projects.length && infisicalAuth ? 'configured' : undefined,
    infisical.projects.length ? 'Set INFISICAL_TOKEN, or INFISICAL_CLIENT_ID and INFISICAL_CLIENT_SECRET.' : 'Configure hosts.infisical.projects.',
    () => withStoreActivation(createInfisicalHost({ siteUrl: infisical.siteUrl, projects: infisical.projects, auth: infisicalAuth!, http, log }),
      infisical.activation), optedIn('infisical', infisical));

  const policy = defaultPolicy();
  policy.autoExecute = settings.monitor.autoExecute;
  policy.autoContain = settings.monitor.autoContain;
  policy.containCooldownMinutes = settings.monitor.containCooldownMinutes;
  policy.revokeUnconfirmedOnHighConfidence = settings.monitor.revokeUnconfirmedOnHighConfidence;
  policy.cooldownMinutes = settings.monitor.cooldownMinutes;
  policy.maxAutoRotationsPerDay = settings.monitor.maxAutoRotationsPerDay;
  for (const kind of Object.keys(policy.rules) as (keyof Policy['rules'])[]) {
    policy.rules[kind] = { ...policy.rules[kind], ...settings.monitor.rules[kind] };
  }
  const notifier = combineNotifiers(createConsoleNotifier(log), ...settings.monitor.webhooks.map(url => createWebhookNotifier(url, http)));
  const monitorGithub = settings.monitor.github;
  const { graceSeconds, ...rotation } = settings.rotation;
  return {
    ...metadata, hosts, disabledHosts,
    providerCtx: { http, credentials, log },
    rotation: { dryRun: true, ...rotation, graceMs: graceSeconds * 1000 },
    monitor: {
      policy, intervalMs: settings.monitor.interval * 1000, notifier,
      ...(settings.monitor.feeds === undefined ? {} : { feeds: settings.monitor.feeds }),
      ...(monitorGithub ? { github: { repos: monitorGithub.repos, token: tokens.GITHUB_TOKEN } } : {}),
      ...(settings.monitor.usage ? { usageOptions: settings.monitor.usage } : {}),
    },
  };
}
