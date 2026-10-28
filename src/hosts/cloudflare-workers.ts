import type { DeployState, HostAdapter, HttpClient, HttpRequest, Logger, RawVariable, ServiceRef } from '../types.js';
import { requestJson } from './http.js';

export type CloudflareProduct = 'workers' | 'pages';
export type CloudflarePagesEnvironment = 'production' | 'preview';

export interface CloudflareWorkersHostOptions {
  /** API token sent as `Authorization: Bearer`; the legacy global API key scheme is not supported. */
  token: string;
  /** Cloudflare account id (not a secret). Every ServiceRef carries it as `projectId`. */
  accountId: string;
  /** Which products to scan; default both. */
  products?: CloudflareProduct[];
  /** Limit Workers to these script names (no listing call when set). */
  scripts?: string[];
  /** Limit Pages to these project names. */
  pagesProjects?: string[];
  /** Pages deployment environments to scan; default both. */
  pagesEnvironments?: CloudflarePagesEnvironment[];
  http: HttpClient;
  log: Logger;
}

type Data = Record<string, unknown>;

const API = 'https://api.cloudflare.com/client/v4';
const WORKER_PREFIX = 'worker:';
const PAGES_PREFIX = 'pages:';
const PAGES_ENVIRONMENTS: readonly CloudflarePagesEnvironment[] = ['production', 'preview'];
const MAX_PAGES = 1000;

type Target =
  | { kind: 'worker'; script: string }
  | { kind: 'pages'; project: string; environment: CloudflarePagesEnvironment };

interface Binding { name: string; type: string; text?: string }
interface PagesVar { type: string; value?: string }

interface ServingState {
  deploymentId: string;
  /** The newest version serves 100% of traffic. */
  latestServesAll: boolean;
  /** The newest version serves at least part of the traffic. */
  latestServesSome: boolean;
}

function invalidResponse(): never {
  // Upstream payloads can contain plaintext values; never echo them.
  throw new Error('Cloudflare returned an invalid response');
}

function record(value: unknown): Data {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return invalidResponse();
  return value as Data;
}

function list(value: unknown): unknown[] {
  if (!Array.isArray(value)) return invalidResponse();
  return value;
}

function nonempty(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) return invalidResponse();
  return value;
}

/** Script and project names become path segments; reject anything that could normalize to another endpoint. */
function safeName(value: string, what: string): string {
  if (typeof value !== 'string' || value.length === 0 || value === '.' || value === '..'
    || /[/\\?#%\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(`Cloudflare ${what} is invalid`);
  }
  return value;
}

function validateNames(names: string[]): void {
  if (names.some((name) => name.length === 0 || /[\u0000-\u001f\u007f]/u.test(name))) {
    throw new Error('Cloudflare variable name is invalid');
  }
}

export function createCloudflareWorkersHost(opts: CloudflareWorkersHostOptions): HostAdapter {
  const { http, log } = opts;
  if (typeof opts.accountId !== 'string' || !/^[A-Za-z0-9]{1,32}$/.test(opts.accountId)) {
    throw new Error('Cloudflare account id is invalid');
  }
  const accountId = opts.accountId;
  const products = new Set<CloudflareProduct>(opts.products ?? ['workers', 'pages']);
  if ([...products].some((product) => product !== 'workers' && product !== 'pages')) {
    throw new Error('Cloudflare product is invalid');
  }
  const pagesEnvironments = [...new Set(opts.pagesEnvironments ?? PAGES_ENVIRONMENTS)];
  if (pagesEnvironments.some((environment) => !PAGES_ENVIRONMENTS.includes(environment))) {
    throw new Error('Cloudflare Pages environment is invalid');
  }
  const scripts = opts.scripts === undefined ? undefined : [...new Set(opts.scripts.map((name) => safeName(name, 'script name')))];
  const pagesProjects = opts.pagesProjects === undefined
    ? undefined
    : [...new Set(opts.pagesProjects.map((name) => safeName(name, 'Pages project name')))];
  const accountPath = `/accounts/${encodeURIComponent(accountId)}`;

  async function request(method: HttpRequest['method'], path: string, body?: unknown): Promise<Data> {
    const headers: Record<string, string> = { Authorization: `Bearer ${opts.token}` };
    const req: HttpRequest = { method, url: `${API}${accountPath}${path}`, headers };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      req.body = JSON.stringify(body);
    }
    const envelope = record(await requestJson<unknown>(http, 'Cloudflare', req));
    // Cloudflare's v4 envelope reports failure in `success` even when a proxy returns 2xx.
    if (envelope.success !== true) throw new Error('Cloudflare request failed');
    return envelope;
  }

  function target(service: ServiceRef): Target {
    if (service.host !== 'cloudflare-workers' || service.projectId !== accountId) {
      throw new Error('Cloudflare service does not belong to the configured account');
    }
    if (service.serviceId.startsWith(WORKER_PREFIX)) {
      if (service.environmentId !== '') throw new Error('Cloudflare service reference is invalid');
      return { kind: 'worker', script: safeName(service.serviceId.slice(WORKER_PREFIX.length), 'script name') };
    }
    if (service.serviceId.startsWith(PAGES_PREFIX)) {
      const environment = service.environmentId as CloudflarePagesEnvironment;
      if (!PAGES_ENVIRONMENTS.includes(environment)) throw new Error('Cloudflare service reference is invalid');
      return { kind: 'pages', project: safeName(service.serviceId.slice(PAGES_PREFIX.length), 'Pages project name'), environment };
    }
    throw new Error('Cloudflare service reference is invalid');
  }

  // ------------------------------------------------------------------ Workers
  const scriptPath = (script: string) => `/workers/scripts/${encodeURIComponent(script)}`;

  async function listScripts(): Promise<string[]> {
    // Documented without pagination: GET /accounts/{account_id}/workers/scripts returns every script.
    const envelope = await request('GET', '/workers/scripts');
    return list(envelope.result).map((item) => safeNameOrInvalid(nonempty(record(item).id)));
  }

  async function bindings(script: string): Promise<Binding[]> {
    const envelope = await request('GET', `${scriptPath(script)}/settings`);
    const raw = record(envelope.result).bindings;
    if (raw === undefined || raw === null) return [];
    const seen = new Set<string>();
    return list(raw).map((item) => {
      const binding = record(item);
      const name = nonempty(binding.name);
      const type = nonempty(binding.type);
      if (seen.has(name)) return invalidResponse();
      seen.add(name);
      if (type === 'plain_text') {
        if (typeof binding.text !== 'string') return invalidResponse();
        return { name, type, text: binding.text };
      }
      // Secret text is never read back, whatever the response schema allows.
      return { name, type };
    });
  }

  async function servingState(script: string): Promise<ServingState | null> {
    // "The first deployment in the list is the latest deployment actively serving traffic."
    const deployments = list(record((await request('GET', `${scriptPath(script)}/deployments`)).result).deployments);
    if (deployments.length === 0) return null;
    const active = record(deployments[0]);
    const deploymentId = nonempty(active.id);
    const versions = list(active.versions).map((item) => {
      const version = record(item);
      if (typeof version.percentage !== 'number' || !Number.isFinite(version.percentage)) return invalidResponse();
      return { id: nonempty(version.version_id), percentage: version.percentage };
    });
    if (versions.length === 0) return invalidResponse();
    // "The first version in the list is the latest version."
    const items = list(record((await request('GET', `${scriptPath(script)}/versions`)).result).items);
    if (items.length === 0) return invalidResponse();
    const latestId = nonempty(record(items[0]).id);
    const latestServesSome = versions.some((version) => version.id === latestId && version.percentage > 0);
    const latestServesAll = versions.length === 1 && versions[0]!.id === latestId && versions[0]!.percentage === 100;
    return { deploymentId, latestServesAll, latestServesSome };
  }

  async function readWorker(script: string): Promise<RawVariable[]> {
    const variables: RawVariable[] = [];
    for (const binding of await bindings(script)) {
      if (binding.type === 'plain_text') variables.push({ name: binding.name, value: binding.text, sealed: false });
      else if (binding.type === 'secret_text') variables.push({ name: binding.name, sealed: true });
    }
    return variables;
  }

  async function writeWorker(script: string, changes: [string, string][]): Promise<void> {
    const existing = new Map((await bindings(script)).map((binding) => [binding.name, binding.type]));
    if (changes.some(([name]) => existing.has(name) && existing.get(name) !== 'secret_text')) {
      // The secrets endpoint cannot convert a plain-text or resource binding, and the settings PATCH replace
      // semantics for bindings are undocumented. Refuse before any write.
      throw new Error('Cloudflare Workers can only update secret bindings; change this variable in Cloudflare');
    }
    // A secret write creates a new version from the latest one and deploys it. Refuse when the latest version is
    // not the one serving all traffic, so a rotation never ships undeployed code or ends a gradual rollout.
    const state = await servingState(script);
    if (state === null || !state.latestServesAll) {
      throw new Error('Cloudflare Workers script has an undeployed or partially deployed version; finish that deployment first');
    }
    for (const [name, value] of changes) {
      await request('PUT', `${scriptPath(script)}/secrets`, { name, text: value, type: 'secret_text' });
    }
  }

  // ------------------------------------------------------------------ Pages
  const projectPath = (project: string) => `/pages/projects/${encodeURIComponent(project)}`;

  async function listPagesProjects(): Promise<string[]> {
    const names: string[] = [];
    const seen = new Set<string>();
    for (let page = 1; page <= MAX_PAGES; page++) {
      const envelope = await request('GET', `/pages/projects?page=${page}`);
      const items = list(envelope.result);
      if (items.length === 0) return names;
      let added = 0;
      for (const item of items) {
        const name = safeNameOrInvalid(nonempty(record(item).name));
        if (seen.has(name)) continue;
        seen.add(name);
        names.push(name);
        added += 1;
      }
      // A page that adds nothing new means the page cursor did not advance: stop instead of looping.
      if (added === 0) return names;
      const info = envelope.result_info;
      if (info !== undefined && info !== null) {
        const totalPages = record(info).total_pages;
        if (typeof totalPages === 'number' && Number.isFinite(totalPages) && page >= totalPages) return names;
      }
    }
    throw new Error('Cloudflare pagination did not finish');
  }

  async function getProject(project: string): Promise<Data> {
    return record((await request('GET', projectPath(project))).result);
  }

  function pagesVars(project: Data, environment: CloudflarePagesEnvironment): Map<string, PagesVar> {
    const configs = project.deployment_configs;
    if (configs === undefined || configs === null) return new Map();
    const config = record(configs)[environment];
    if (config === undefined || config === null) return new Map();
    const envVars = record(config).env_vars;
    if (envVars === undefined || envVars === null) return new Map();
    const result = new Map<string, PagesVar>();
    for (const [name, raw] of Object.entries(record(envVars))) {
      if (raw === null) continue; // a deleted entry
      const entry = record(raw);
      const type = nonempty(entry.type);
      if (type === 'plain_text') {
        if (typeof entry.value !== 'string') return invalidResponse();
        result.set(name, { type, value: entry.value });
      } else {
        // secret_text (and any type we do not know) is never read back.
        result.set(name, { type });
      }
    }
    return result;
  }

  async function writePages(project: string, environment: CloudflarePagesEnvironment, vars: Record<string, string>): Promise<void> {
    const before = await getProject(project);
    const current = pagesVars(before, environment);
    const envVars: Record<string, { type: string; value: string }> = {};
    for (const [name, value] of Object.entries(vars)) {
      const existing = current.get(name);
      if (existing !== undefined && existing.type !== 'plain_text' && existing.type !== 'secret_text') {
        throw new Error('Cloudflare Pages variable has an unsupported type; change it in Cloudflare');
      }
      // Keep the existing type; new variables are encrypted.
      envVars[name] = { type: existing?.type === 'plain_text' ? 'plain_text' : 'secret_text', value };
    }
    // Only the named keys are sent. The API deletes a key only when it is sent as null, so omitted keys stay.
    await request('PATCH', projectPath(project), { deployment_configs: { [environment]: { env_vars: envVars } } });
    // Verify the documented merge behavior instead of trusting it: every other variable must survive unchanged.
    const after = await getProject(project);
    // So must every other deployment setting (bindings, compatibility date and flags, usage model, ...).
    for (const checked of PAGES_ENVIRONMENTS) {
      if (pagesSettings(before, checked) !== pagesSettings(after, checked)) {
        throw new Error('Cloudflare Pages settings changed beyond this update; check the project settings (bindings, compatibility) in Cloudflare');
      }
    }
    for (const checked of PAGES_ENVIRONMENTS) {
      const was = pagesVars(before, checked);
      const now = pagesVars(after, checked);
      const written: Record<string, PagesVar> = checked === environment ? envVars : {};
      for (const name of new Set([...was.keys(), ...now.keys(), ...Object.keys(written)])) {
        const expected = Object.hasOwn(written, name) ? written[name] : was.get(name);
        if (!samePagesVar(expected, now.get(name))) {
          throw new Error('Cloudflare Pages variables changed beyond this update; check the project settings in Cloudflare');
        }
      }
    }
  }

  // ------------------------------------------------------------------ adapter
  return {
    id: 'cloudflare-workers',
    // readValues: plain-text Workers vars and Pages plain_text vars. redeploy: Workers activation is confirmed
    // from the deployment list (the secret write itself deploys); Pages needs a new deployment that keysentry
    // does not start (redeploy returns null).
    capabilities: { readValues: true, batchWrite: false, redeploy: true },
    // Each Worker secret write deploys a new version; Pages values apply on the next Pages deployment.
    activationFor: service => service.serviceId.startsWith('worker:') ? 'on-write' : 'manual',

    async listServices() {
      const services: ServiceRef[] = [];
      if (products.has('workers')) {
        for (const script of scripts ?? await listScripts()) {
          services.push({
            host: 'cloudflare-workers', projectId: accountId, projectName: accountId,
            serviceId: `${WORKER_PREFIX}${script}`, serviceName: script, environmentId: '', environmentName: '',
          });
        }
      }
      if (products.has('pages')) {
        const projects: string[] = [];
        if (pagesProjects === undefined) projects.push(...await listPagesProjects());
        else for (const name of pagesProjects) projects.push(safeNameOrInvalid(nonempty((await getProject(name)).name)));
        for (const project of projects) {
          for (const environment of pagesEnvironments) {
            services.push({
              host: 'cloudflare-workers', projectId: accountId, projectName: accountId,
              serviceId: `${PAGES_PREFIX}${project}`, serviceName: project, environmentId: environment, environmentName: environment,
            });
          }
        }
      }
      return services;
    },

    async readVariables(service) {
      const where = target(service);
      if (where.kind === 'worker') return readWorker(where.script);
      return [...pagesVars(await getProject(where.project), where.environment)].map(([name, entry]): RawVariable =>
        entry.type === 'plain_text' ? { name, value: entry.value, sealed: false } : { name, sealed: true });
    },

    async writeVariables(service, vars, _writeOptions) {
      const where = target(service);
      const changes = Object.entries(vars);
      if (changes.length === 0) return;
      validateNames(changes.map(([name]) => name));
      // Workers: Cloudflare deploys each secret write at once, so there is no deployment that skipDeploy could
      // suppress, and keysentry never starts another one. Pages: writes never deploy.
      if (where.kind === 'worker') await writeWorker(where.script, changes);
      else await writePages(where.project, where.environment, vars);
    },

    async redeploy(service) {
      const where = target(service);
      if (where.kind === 'pages') {
        log.warn('Cloudflare Pages applies variable changes to new deployments only; start a new Pages deployment to activate them', {
          project: where.project, environment: where.environment,
        });
        return null;
      }
      // No deployment is started: the secret write already created and deployed a new version. Return the id of
      // the deployment serving traffic only when the newest version serves all of it.
      const state = await servingState(where.script);
      if (state === null || !state.latestServesAll) {
        log.warn('Cloudflare Workers newest version is not serving all traffic; activation unconfirmed', { script: where.script });
        return null;
      }
      return state.deploymentId;
    },

    async deploymentStatus(service, deploymentId): Promise<DeployState> {
      const where = target(service);
      if (where.kind === 'pages') throw new Error('Cloudflare Pages deployments are not tracked by keysentry');
      nonemptyId(deploymentId);
      const state = await servingState(where.script);
      if (state === null) return 'failed';
      if (state.latestServesAll) return 'success';
      // A gradual rollout of the newest version may still complete; anything else rolled the secret back.
      return state.latestServesSome ? 'pending' : 'failed';
    },
  };
}

/** One environment's deployment settings other than env_vars, in a canonical form for comparison only. */
function pagesSettings(project: Data, environment: CloudflarePagesEnvironment): string {
  const configs = project.deployment_configs;
  const config = configs === undefined || configs === null ? undefined : (record(configs) as Data)[environment];
  if (config === undefined || config === null) return 'null';
  const { env_vars: _vars, ...rest } = record(config) as Data;
  const canonical = (value: unknown): unknown => Array.isArray(value) ? value.map(canonical)
    : value !== null && typeof value === 'object'
      ? Object.fromEntries(Object.keys(value as Data).sort().map(key => [key, canonical((value as Data)[key])]))
      : value;
  return JSON.stringify(canonical(rest));
}

/** Secret values are never compared: they are not returned. Plain-text values must match exactly. */
function samePagesVar(expected: PagesVar | undefined, actual: PagesVar | undefined): boolean {
  if (expected === undefined || actual === undefined) return expected === actual;
  if (expected.type !== actual.type) return false;
  return expected.type !== 'plain_text' || expected.value === actual.value;
}

function nonemptyId(value: string): void {
  if (typeof value !== 'string' || value.length === 0) throw new Error('Cloudflare deployment id is invalid');
}

function safeNameOrInvalid(value: string): string {
  try {
    return safeName(value, 'name');
  } catch {
    return invalidResponse();
  }
}
