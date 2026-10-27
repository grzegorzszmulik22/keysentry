import { CliError } from './errors.js';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { isIP } from 'node:net';
import { parseDocument } from 'yaml';
import { z } from 'zod';
import { createLogger, createRedactor } from '../core/index.js';
import { createFetchHttp } from '../http.js';
import {
  createRailwayHost, createVercelHost, createRenderHost, createFlyHost,
  createGithubActionsHost, createDotenvHost,
} from '../hosts/index.js';
import { PROVIDER_CREDENTIALS } from '../providers/index.js';
import { CREDENTIAL_NAMES, createCredentialSource, createEnvVault } from '../vault/index.js';
import {
  combineNotifiers, createConsoleNotifier, createWebhookNotifier, defaultPolicy,
  type BreachFeed, type GithubOptions, type UsageOptions,
} from '../monitor/index.js';
import type { RotateOptions } from '../rotate/index.js';
import type { EgressRule, HostAdapter, HostId, HttpClient, Logger, Notifier, Policy, ProviderContext, Redactor, TokenRole, Vault } from '../types.js';

const nonempty = z.string().trim().min(1);
const list = z.array(nonempty);
const positive = z.number().finite().positive();
const hostId = z.enum(['railway', 'vercel', 'render', 'fly', 'github-actions', 'dotenv']);
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
  network: z.object({ allowHosts: z.array(exactHostname).default([]) }).strict().prefault({}),
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
export async function loadConfigMetadata(options: Pick<LoadConfigOptions, 'cwd' | 'config' | 'env'> = {}): Promise<ConfigMetadata> {
  const cwd = resolve(options.cwd ?? process.cwd());
  const configPath = resolve(cwd, options.config ?? 'keysentry.yaml');
  const env = options.env ?? process.env;
  const settings = validate(await readSettings(configPath, options.config !== undefined));
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
    userHostRules: [...new Set(settings.network.allowHosts)].map(host => ({ host, owner: 'user', purpose: 'host you added in keysentry.yaml' })),
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
    if (credential?.value) { tokens[name] = credential.value; redactor.register(credential.value); }
  }
  const credentials: ProviderContext['credentials'] = Object.create(null);
  for (const name of new Set(Object.values(PROVIDER_CREDENTIALS).flat())) {
    if (tokens[name]) credentials[name] = tokens[name];
  }
  for (const url of settings.monitor.webhooks) redactor.register(url);

  const hosts: HostAdapter[] = [];
  const disabledHosts: RuntimeConfig['disabledHosts'] = [];
  function enable(host: HostId, enabled: boolean | undefined, token: string | undefined, missing: string, factory: (value: string) => HostAdapter) {
    if (enabled === false) disabledHosts.push({ host, reason: 'Disabled in configuration.' });
    else if (!token) disabledHosts.push({ host, reason: missing });
    else hosts.push(factory(token));
  }
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
