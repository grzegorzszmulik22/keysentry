import { CliError } from './errors.js';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parseDocument } from 'yaml';
import { z } from 'zod';
import { createLogger, createRedactor } from '../core/index.js';
import { createFetchHttp } from '../http.js';
import {
  createRailwayHost, createVercelHost, createRenderHost, createFlyHost,
  createGithubActionsHost, createDotenvHost,
} from '../hosts/index.js';
import { PROVIDER_CREDENTIALS } from '../providers/index.js';
import {
  combineNotifiers, createConsoleNotifier, createWebhookNotifier, defaultPolicy,
  type BreachFeed, type GithubOptions, type UsageOptions,
} from '../monitor/index.js';
import type { RotateOptions } from '../rotate/index.js';
import type { HostAdapter, HostId, HttpClient, Logger, Notifier, Policy, ProviderContext, Redactor } from '../types.js';

const nonempty = z.string().trim().min(1);
const list = z.array(nonempty);
const positive = z.number().finite().positive();
const hostId = z.enum(['railway', 'vercel', 'render', 'fly', 'github-actions', 'dotenv']);
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
    railway: z.object({ enabled: z.boolean().optional(), projectIds: list.optional(), tokenType: z.enum(['account', 'project']).optional() }).strict().default({}),
    vercel: z.object({ enabled: z.boolean().optional(), teamId: nonempty.optional(), targets: z.array(z.enum(['production', 'preview', 'development'])).min(1).optional() }).strict().default({}),
    render: z.object({ enabled: z.boolean().optional() }).strict().default({}),
    fly: z.object({ enabled: z.boolean().optional(), org: nonempty.optional(), apps: list.optional() }).strict().default({}),
    github: z.object({ enabled: z.boolean().optional(), repos: z.array(repository).default([]) }).strict().default({}),
    dotenv: z.object({ enabled: z.boolean().optional(), roots: list.default(['.']), includeTemplates: z.boolean().default(false) }).strict().default({}),
  }).strict().default({}),
  rotation: z.object({
    revoke: z.enum(['after-deploy', 'immediately', 'never']).default('after-deploy'),
    redeploy: z.boolean().default(true),
    deployTimeoutMs: positive.int().default(600_000),
    pollIntervalMs: positive.int().default(5_000),
  }).strict().default({}),
  monitor: z.object({
    interval: positive.default(300),
    autoExecute: z.boolean().default(false),
    cooldownMinutes: z.number().finite().nonnegative().default(60),
    maxAutoRotationsPerDay: z.number().int().nonnegative().default(10),
    rules: z.object({
      canary_triggered: rule.optional(), usage_anomaly: rule.optional(), leak_detected: rule.optional(),
      revoked_upstream: rule.optional(), host_breach_advisory: rule.optional(),
    }).strict().default({}),
    feeds: z.array(z.object({ url: safeUrl, host: hostId.optional() }).strict()).optional(),
    github: z.object({ repos: z.array(repository).default([]) }).strict().optional(),
    usage: z.object({ floorUsd: z.number().finite().nonnegative().optional(), hourlyBudgets: z.record(z.number().finite().nonnegative()).optional() }).strict().optional(),
    webhooks: z.array(safeUrl).default([]),
  }).strict().default({}),
}).strict();

export type ConfigSettings = z.infer<typeof configSchema>;
export interface RuntimeConfig {
  cwd: string;
  configPath: string;
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

/** Environment wins for credentials and documented environment scope overrides. */
export async function loadConfig(options: LoadConfigOptions = {}): Promise<RuntimeConfig> {
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
  const webhook = envValue(env, 'KEYSENTRY_WEBHOOK_URL');
  if (webhook) settings.monitor.webhooks = [webhook];
  // Validate again after environment overrides (notably repository names/URLs).
  validate(settings);

  const redactor = options.redactor ?? createRedactor();
  const log = options.log ?? createLogger({ redactor });
  const http = options.http ?? createFetchHttp();
  const credentials: ProviderContext['credentials'] = Object.create(null);
  for (const name of new Set(Object.values(PROVIDER_CREDENTIALS).flat())) {
    const value = envValue(env, name);
    if (value) { credentials[name] = value; redactor.register(value); }
  }
  const tokenNames = ['RAILWAY_TOKEN', 'RAILWAY_PROJECT_TOKEN', 'VERCEL_TOKEN', 'RENDER_API_KEY', 'FLY_API_TOKEN', 'GITHUB_TOKEN'];
  for (const name of tokenNames) {
    const value = envValue(env, name);
    if (value) redactor.register(value);
  }
  for (const url of settings.monitor.webhooks) redactor.register(url);

  const hosts: HostAdapter[] = [];
  const disabledHosts: RuntimeConfig['disabledHosts'] = [];
  function enable(host: HostId, enabled: boolean | undefined, token: string | undefined, missing: string, factory: (value: string) => HostAdapter) {
    if (enabled === false) disabledHosts.push({ host, reason: 'Disabled in configuration.' });
    else if (!token) disabledHosts.push({ host, reason: missing });
    else hosts.push(factory(token));
  }
  const accountToken = envValue(env, 'RAILWAY_TOKEN');
  const projectToken = envValue(env, 'RAILWAY_PROJECT_TOKEN');
  const railwayType = railway.tokenType ?? (accountToken ? 'account' : 'project');
  enable('railway', railway.enabled, railwayType === 'account' ? accountToken : projectToken, 'Set RAILWAY_TOKEN or RAILWAY_PROJECT_TOKEN.', token => createRailwayHost({ ...railway, token, tokenType: railwayType, http, log }));
  enable('vercel', vercel.enabled, envValue(env, 'VERCEL_TOKEN'), 'Set VERCEL_TOKEN.', token => createVercelHost({ ...vercel, token, http, log }));
  enable('render', settings.hosts.render.enabled, envValue(env, 'RENDER_API_KEY'), 'Set RENDER_API_KEY.', apiKey => createRenderHost({ apiKey, http, log }));
  enable('fly', fly.enabled, envValue(env, 'FLY_API_TOKEN'), 'Set FLY_API_TOKEN.', token => createFlyHost({ ...fly, token, http, log }));
  enable('github-actions', github.enabled, github.repos.length ? envValue(env, 'GITHUB_TOKEN') : undefined,
    github.repos.length ? 'Set GITHUB_TOKEN.' : 'Configure hosts.github.repos or GITHUB_REPOS.', token => createGithubActionsHost({ token, repos: github.repos, http, log }));
  if (dotenv.enabled === false) disabledHosts.push({ host: 'dotenv', reason: 'Disabled in configuration.' });
  else hosts.push(createDotenvHost({ roots: dotenv.roots, includeTemplates: dotenv.includeTemplates, log }));

  const policy = defaultPolicy();
  policy.autoExecute = settings.monitor.autoExecute;
  policy.cooldownMinutes = settings.monitor.cooldownMinutes;
  policy.maxAutoRotationsPerDay = settings.monitor.maxAutoRotationsPerDay;
  for (const kind of Object.keys(policy.rules) as (keyof Policy['rules'])[]) {
    policy.rules[kind] = { ...policy.rules[kind], ...settings.monitor.rules[kind] };
  }
  const notifier = combineNotifiers(createConsoleNotifier(log), ...settings.monitor.webhooks.map(url => createWebhookNotifier(url, http)));
  const monitorGithub = settings.monitor.github;
  return {
    cwd, configPath, hosts, disabledHosts, settings,
    providerCtx: { http, credentials, log },
    rotation: { dryRun: true, ...settings.rotation },
    monitor: {
      policy, intervalMs: settings.monitor.interval * 1000, notifier,
      ...(settings.monitor.feeds === undefined ? {} : { feeds: settings.monitor.feeds }),
      ...(monitorGithub ? { github: { repos: monitorGithub.repos, token: envValue(env, 'GITHUB_TOKEN') } } : {}),
      ...(settings.monitor.usage ? { usageOptions: settings.monitor.usage } : {}),
    },
  };
}
