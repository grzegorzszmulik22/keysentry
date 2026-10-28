import type { DeployState, HostAdapter, HttpClient, HttpRequest, HttpResponse, Logger, RawVariable, ServiceRef } from '../types.js';

/**
 * Netlify API v1 (sources: notes/hosts-a.md).
 *
 * One ServiceRef per site × deploy context (`production`, `deploy-preview`, `branch-deploy`, optionally `dev`), plus
 * `branch:<name>` for branch-specific values found on the site. Team-level shared variables appear as a pseudo-service
 * per team and context (serviceId '', serviceName 'shared'). projectId is the team (account) id the env API needs.
 *
 * A context reads its own value, otherwise the variable's `all` value. Secret variables are write-only except for
 * their `dev` value. Writes are per-key PATCHes of one context value (or of the inherited `all` value) and never
 * start a build. Variable changes need a new deploy; only production is redeployed here, by rebuilding the published
 * commit. Other contexts and shared variables apply on their next deploy.
 */
export type NetlifyContext = 'production' | 'deploy-preview' | 'branch-deploy' | 'dev';

export interface NetlifyHostOptions {
  token: string;
  /** Team slug. When set (and `siteIds` is not), only that team's sites are listed. */
  accountSlug?: string;
  /** Site ids. When set, only these sites are listed. */
  siteIds?: string[];
  /** Deploy contexts scanned for every site. Default: production, deploy-preview, branch-deploy. */
  contexts?: NetlifyContext[];
  /** Also scan team-level shared variables (readable by Team Owners only). Default true. */
  shared?: boolean;
  http: HttpClient;
  log: Logger;
}

const BASE_URL = 'https://api.netlify.com/api/v1';
const PER_PAGE = 100;
const CONTEXTS: readonly NetlifyContext[] = ['production', 'deploy-preview', 'branch-deploy', 'dev'];
const DEFAULT_CONTEXTS: readonly NetlifyContext[] = ['production', 'deploy-preview', 'branch-deploy'];
const FAILED_STATES = new Set(['error', 'rejected']);

interface EnvValue { context: string; contextParameter?: string; value?: string }
interface EnvVar { key: string; isSecret: boolean; values: EnvValue[] }
type Target = { context: NetlifyContext } | { context: 'branch'; branch: string };
interface Site { id: string; name: string; accountId: string; accountName: string }

function invalidResponse(): never {
  // Variable values and site payloads (hook tokens) can be secret; never include them in errors.
  throw new Error('Netlify returned an invalid response');
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return invalidResponse();
  return value as Record<string, unknown>;
}

function optionalRecord(value: unknown): Record<string, unknown> | undefined {
  return value === undefined || value === null ? undefined : record(value);
}

function nonemptyString(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) return invalidResponse();
  return value;
}

function optionalString(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string') return invalidResponse();
  return value;
}

function segment(value: string): string {
  if (value.length === 0 || value === '.' || value === '..') throw new Error('Netlify identifier is invalid');
  return encodeURIComponent(value);
}

function header(headers: Record<string, string>, name: string): string | undefined {
  return Object.entries(headers).find(([key]) => key.toLowerCase() === name)?.[1];
}

function envVar(value: unknown): EnvVar {
  const entry = record(value);
  if (entry.is_secret !== undefined && entry.is_secret !== null && typeof entry.is_secret !== 'boolean') return invalidResponse();
  if (entry.values !== undefined && entry.values !== null && !Array.isArray(entry.values)) return invalidResponse();
  const values = (Array.isArray(entry.values) ? entry.values : []).map((item): EnvValue => {
    const raw = record(item);
    const contextParameter = optionalString(raw.context_parameter);
    const text = optionalString(raw.value);
    return {
      context: nonemptyString(raw.context),
      ...(contextParameter === undefined ? {} : { contextParameter }),
      ...(text === undefined ? {} : { value: text }),
    };
  });
  return { key: nonemptyString(entry.key), isSecret: entry.is_secret === true, values };
}

function targetOf(service: ServiceRef): Target {
  const id = service.environmentId;
  if (id.startsWith('branch:')) {
    const branch = id.slice('branch:'.length);
    if (branch.length === 0) throw new Error('Netlify deploy context is invalid');
    return { context: 'branch', branch };
  }
  if (!(CONTEXTS as readonly string[]).includes(id)) throw new Error('Netlify deploy context is invalid');
  return { context: id as NetlifyContext };
}

/** Values that define this context: an exact context (or branch) value, otherwise the shared `all` value. */
function applicable(entry: EnvVar, target: Target): EnvValue[] {
  if (target.context === 'branch') {
    return entry.values.filter((value) => value.context === 'branch' && value.contextParameter === target.branch);
  }
  const exact = entry.values.filter((value) => value.context === target.context);
  return exact.length > 0 ? exact : entry.values.filter((value) => value.context === 'all');
}

function branchesOf(entries: EnvVar[]): string[] {
  const branches = new Set<string>();
  for (const entry of entries) {
    for (const value of entry.values) {
      if (value.context === 'branch' && value.contextParameter !== undefined && value.contextParameter.length > 0) {
        branches.add(value.contextParameter);
      }
    }
  }
  return [...branches].sort();
}

function contextValue(target: Target, value: string): Record<string, string> {
  return target.context === 'branch'
    ? { context: 'branch', context_parameter: target.branch, value }
    : { context: target.context, value };
}

export function createNetlifyHost(options: NetlifyHostOptions): HostAdapter {
  const { token, http, log } = options;
  const contexts = [...new Set(options.contexts ?? DEFAULT_CONTEXTS)];
  for (const context of contexts) {
    if (!CONTEXTS.includes(context)) throw new Error('Netlify deploy context is invalid');
  }

  async function call(method: HttpRequest['method'], path: string, body?: unknown): Promise<{ headers: Record<string, string>; data: unknown }> {
    const headers: Record<string, string> = { Authorization: `Bearer ${token}` };
    const req: HttpRequest = { method, url: `${BASE_URL}${path}`, headers };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      req.body = JSON.stringify(body);
    }
    let response: HttpResponse;
    try {
      response = await http.request(req);
    } catch {
      throw new Error('Netlify request failed');
    }
    if (response.status < 200 || response.status >= 300) throw new Error(`Netlify request failed (HTTP ${response.status})`);
    let data: unknown;
    if (response.text.trim()) {
      try {
        data = response.json();
      } catch {
        throw new Error('Netlify returned invalid JSON');
      }
    }
    return { headers: response.headers ?? {}, data };
  }

  async function data(method: HttpRequest['method'], path: string, body?: unknown): Promise<unknown> {
    return (await call(method, path, body)).data;
  }

  /** Page-number pagination; follows the Link header's rel="next", or full pages when no Link header is sent. */
  async function pages(path: string, query: string): Promise<Record<string, unknown>[]> {
    const items: Record<string, unknown>[] = [];
    const seen = new Set<string>();
    for (let page = 1; ; page++) {
      const response = await call('GET', `${path}?${query}${query ? '&' : ''}page=${page}&per_page=${PER_PAGE}`);
      if (!Array.isArray(response.data)) return invalidResponse();
      let added = 0;
      for (const item of response.data) {
        const site = record(item);
        const id = nonemptyString(site.id);
        if (seen.has(id)) continue; // Page numbers can shift while sites change; keep the first copy.
        seen.add(id);
        items.push(site);
        added++;
      }
      const link = header(response.headers, 'link');
      const hasNext = link === undefined ? response.data.length >= PER_PAGE : /;\s*rel="?next"?/i.test(link);
      if (!hasNext) return items;
      if (added === 0) throw new Error('Netlify pagination did not advance');
    }
  }

  function siteOf(value: unknown): Site {
    const site = record(value);
    const accountId = nonemptyString(site.account_id);
    return {
      id: nonemptyString(site.id),
      name: nonemptyString(site.name),
      accountId,
      accountName: optionalString(site.account_slug) || optionalString(site.account_name) || accountId,
    };
  }

  const isShared = (service: ServiceRef) => service.serviceId === '';

  function envPath(service: ServiceRef, key?: string): string {
    const path = `/accounts/${segment(service.projectId)}/env${key === undefined ? '' : `/${encodeURIComponent(key)}`}`;
    return isShared(service) ? path : `${path}?site_id=${encodeURIComponent(service.serviceId)}`;
  }

  async function readEnv(service: ServiceRef): Promise<EnvVar[]> {
    const body = await data('GET', envPath(service));
    if (!Array.isArray(body)) return invalidResponse();
    return body.map(envVar);
  }

  function servicesFor(base: Omit<ServiceRef, 'environmentId' | 'environmentName'>, branches: string[]): ServiceRef[] {
    return [...contexts, ...branches.map((branch) => `branch:${branch}`)]
      .map((environmentId) => ({ ...base, environmentId, environmentName: environmentId }));
  }

  return {
    id: 'netlify',
    capabilities: { readValues: true, batchWrite: false, redeploy: true },
    // Only a site's production context is rebuilt; other contexts, branch values and shared team variables apply on
    // their next deploy.
    activationFor: service => service.environmentId === 'production' && service.serviceId !== '' ? 'redeploy' : 'manual',

    async listServices() {
      let rawSites: unknown[];
      if (options.siteIds !== undefined && options.siteIds.length > 0) {
        rawSites = [];
        for (const id of new Set(options.siteIds)) rawSites.push(await data('GET', `/sites/${segment(id)}`));
      } else if (options.accountSlug !== undefined) {
        rawSites = await pages(`/${segment(options.accountSlug)}/sites`, '');
      } else {
        rawSites = await pages('/sites', 'filter=all');
      }
      const sites = rawSites.map(siteOf);
      const services: ServiceRef[] = [];
      for (const site of sites) {
        const base = { host: 'netlify' as const, projectId: site.accountId, projectName: site.accountName, serviceId: site.id, serviceName: site.name };
        let branches: string[] = [];
        try {
          branches = branchesOf(await readEnv({ ...base, environmentId: '', environmentName: '' }));
        } catch {
          log.warn('Netlify could not read this site\'s variables to find branch values', { site: site.name });
        }
        services.push(...servicesFor(base, branches));
      }
      if (options.shared !== false) {
        const accounts = new Map(sites.map((site) => [site.accountId, site.accountName]));
        for (const [accountId, accountName] of accounts) {
          const base = { host: 'netlify' as const, projectId: accountId, projectName: accountName, serviceId: '', serviceName: 'shared' };
          let entries: EnvVar[];
          try {
            entries = await readEnv({ ...base, environmentId: '', environmentName: '' });
          } catch {
            log.warn('Netlify shared team variables are not readable with this token (Team Owners only); skipping them', { team: accountName });
            continue;
          }
          if (entries.length > 0) services.push(...servicesFor(base, branchesOf(entries)));
        }
      }
      return services;
    },

    async readVariables(service): Promise<RawVariable[]> {
      const target = targetOf(service);
      const entries = await readEnv(service);
      const keyCounts = new Map<string, number>();
      for (const entry of entries) keyCounts.set(entry.key, (keyCounts.get(entry.key) ?? 0) + 1);
      const variables: RawVariable[] = [];
      const ambiguous: string[] = [];
      const emitted = new Set<string>();
      for (const entry of entries) {
        if (emitted.has(entry.key)) continue;
        const values = applicable(entry, target);
        if (values.length === 0 && (keyCounts.get(entry.key) ?? 0) === 1) continue;
        emitted.add(entry.key);
        if (values.length !== 1 || (keyCounts.get(entry.key) ?? 0) > 1) {
          ambiguous.push(entry.key);
          variables.push({ name: entry.key, sealed: true });
          continue;
        }
        const [selected] = values as [EnvValue];
        // Secret values are masked everywhere except their explicit dev value.
        const readable = !entry.isSecret || (target.context === 'dev' && selected.context === 'dev');
        if (!readable || selected.value === undefined) variables.push({ name: entry.key, sealed: true });
        else variables.push({ name: entry.key, value: selected.value, sealed: false });
      }
      if (ambiguous.length > 0) {
        log.warn('Netlify has several values for these variables in one context; they are reported as sealed', {
          site: service.serviceName, context: service.environmentId, keys: ambiguous,
        });
      }
      return variables;
    },

    async writeVariables(service, vars, _opts) {
      const updates = Object.entries(vars);
      if (updates.some(([name]) => name === '' || name === '.' || name === '..')) throw new Error('Netlify variable name is invalid');
      const target = targetOf(service);
      if (updates.length === 0) return;
      const entries = await readEnv(service);
      const patches: { key: string; body: Record<string, string> }[] = [];
      const creates: { key: string; values: Record<string, string>[] }[] = [];
      // Plan every key before changing anything.
      for (const [key, value] of updates) {
        const matches = entries.filter((entry) => entry.key === key);
        if (matches.length > 1) throw new Error('Netlify has duplicate variables with this name; fix them in Netlify first');
        const existing = matches[0];
        if (existing === undefined) {
          // A new team-wide variable would reach every site; create those in the team settings instead.
          if (isShared(service)) throw new Error('Netlify shared variable does not exist; create it in the team settings first');
          creates.push({ key, values: [contextValue(target, value)] });
          continue;
        }
        if (target.context === 'branch') {
          if (applicable(existing, target).length > 1) throw new Error('Netlify has several values for this variable in one context');
          patches.push({ key, body: contextValue(target, value) });
          continue;
        }
        const exact = existing.values.filter((item) => item.context === target.context);
        const inherited = existing.values.filter((item) => item.context === 'all');
        if (exact.length > 1 || (exact.length === 0 && inherited.length > 1)) {
          throw new Error('Netlify has several values for this variable in one context');
        }
        // A context that inherits the `all` value shares that secret with every other inheriting context, so the
        // `all` value is updated (like a Vercel entry that covers several targets).
        const context = exact.length === 0 && inherited.length === 1 && !existing.isSecret ? 'all' : target.context;
        patches.push({ key, body: { context, value } });
      }
      for (const patch of patches) await call('PATCH', envPath(service, patch.key), patch.body);
      if (creates.length > 0) await call('POST', envPath(service), creates);
      // Netlify variable writes never deploy, regardless of skipDeploy.
    },

    async redeploy(service) {
      if (isShared(service)) {
        log.warn('Netlify shared variables reach each site on its next deploy; activation unconfirmed.', { team: service.projectName });
        return null;
      }
      // Only production is rebuilt; previews and branch deploys pick up the values on their next deploy.
      if (service.environmentId !== 'production') return null;
      const site = record(await data('GET', `/sites/${segment(service.serviceId)}`));
      const build = optionalRecord(site.build_settings);
      if (build === undefined || !optionalString(build.repo_url) || build.stop_builds === true) {
        log.warn('Netlify site does not build from a linked repository; deploy it yourself. Activation unconfirmed.', { site: service.serviceName });
        return null;
      }
      const published = optionalRecord(site.published_deploy);
      if (published?.locked === true) {
        log.warn('Netlify production publishing is locked to a deploy; activation unconfirmed.', { site: service.serviceName });
        return null;
      }
      const commit = optionalString(published?.commit_ref);
      if (!commit) {
        log.warn('Netlify has no published commit to rebuild; building the latest production branch commit.', { site: service.serviceName });
      }
      // Rebuild the live commit so rotating a secret does not publish newer code.
      const query = commit ? `?commit_sha=${encodeURIComponent(commit)}` : '';
      const created = record(await data('POST', `/sites/${segment(service.serviceId)}/builds${query}`));
      return nonemptyString(created.deploy_id);
    },

    async deploymentStatus(service, deploymentId): Promise<DeployState> {
      const deploy = record(await data('GET', `/deploys/${segment(deploymentId)}`));
      const state = nonemptyString(deploy.state);
      if (FAILED_STATES.has(state) || deploy.skipped === true) return 'failed';
      if (state !== 'ready') return 'pending';
      // A ready deploy is live only if it is the published one; anything else (locked, replaced) fails closed.
      const site = record(await data('GET', `/sites/${segment(service.serviceId)}`));
      return optionalRecord(site.published_deploy)?.id === deploymentId ? 'success' : 'failed';
    },
  };
}
