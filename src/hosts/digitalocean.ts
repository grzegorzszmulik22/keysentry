import type { DeployState, HostAdapter, HttpClient, HttpRequest, Logger, RawVariable, ServiceRef } from '../types.js';
import { requestJson } from './http.js';

/**
 * DigitalOcean App Platform API (sources: notes/hosts-a.md).
 *
 * Variables live inside the app spec: app-level `envs` (serviceId '') and each component's `envs`
 * (serviceId `<kind>/<name>`, for example `services/api`). The only write is `PUT /v2/apps/{id}` with a complete spec,
 * so writes are read-modify-write and every other spec field, component and variable is sent back unchanged (SECRET
 * values come back as `EV[...]` ciphertext and must be resubmitted as is). Updating the spec always creates a
 * deployment (`pending_deployment`); `skipDeploy` cannot prevent it. `redeploy` never starts another deployment: it
 * reports the one the latest update created.
 */
export interface DigitalOceanHostOptions {
  token: string;
  /** App ids to scan. When set, only these apps are listed. */
  apps?: string[];
  http: HttpClient;
  log: Logger;
}

const BASE_URL = 'https://api.digitalocean.com/v2';
const COMPONENT_KINDS = ['services', 'workers', 'jobs', 'static_sites', 'functions'] as const;
type ComponentKind = typeof COMPONENT_KINDS[number];
// Documented key pattern for app variables.
const ENV_KEY = /^[_A-Za-z][_A-Za-z0-9]*$/;
// SECRET values are returned encrypted, e.g. EV[1:...:...].
const CIPHERTEXT = /^EV\[[^\]]*\]$/;
// Bindable variables such as ${db.PASSWORD} or ${APP_URL} are resolved by App Platform.
const BINDABLE = /\$\{[^{}]+\}/;
const FAILED_PHASES = new Set(['ERROR', 'CANCELED', 'SUPERSEDED']);
const DEFAULT_SCOPE = 'RUN_AND_BUILD_TIME';

interface EnvEntry {
  entry: Record<string, unknown>;
  key: string;
  value: string | undefined;
  sealed: boolean;
}

// Credentials kept in the spec outside `envs`: log destination keys (Datadog api_key, Better Stack/Logtail token,
// OpenSearch basic_auth password) and image registry_credentials.
const SPEC_SECRET_FIELDS = new Set(['api_key', 'token', 'password', 'registry_credentials']);

/**
 * The whole spec is sent back on every write, so a credential outside `envs` must round-trip exactly. App Platform
 * returns encrypted values as `EV[...]` ciphertext, which it accepts back unchanged. A value in any other form (plain,
 * empty or masked) might be a placeholder that would overwrite the real credential, so the write is refused. Whether
 * these fields always come back as ciphertext is not documented (notes/fix-phase6.md).
 */
function specCredentialsRoundTrip(value: unknown, key = ''): boolean {
  if (key === 'envs') return true;
  if (Array.isArray(value)) return value.every((item) => specCredentialsRoundTrip(item));
  if (value !== null && typeof value === 'object') {
    return Object.entries(value as Record<string, unknown>).every(([name, item]) => specCredentialsRoundTrip(item, name));
  }
  if (!SPEC_SECRET_FIELDS.has(key)) return true;
  return value === undefined || value === null || (typeof value === 'string' && CIPHERTEXT.test(value));
}

function invalidResponse(): never {
  // App specs hold secrets (variables, log destination keys); never include them in errors.
  throw new Error('DigitalOcean returned an invalid response');
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return invalidResponse();
  return value as Record<string, unknown>;
}

function nonemptyString(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) return invalidResponse();
  return value;
}

function optionalRecord(value: unknown): Record<string, unknown> | undefined {
  return value === undefined || value === null ? undefined : record(value);
}

function segment(value: string): string {
  if (value.length === 0 || value === '.' || value === '..') throw new Error('DigitalOcean identifier is invalid');
  return encodeURIComponent(value);
}

function componentRef(serviceId: string): { kind: ComponentKind; name: string } | null {
  if (serviceId === '') return null;
  const slash = serviceId.indexOf('/');
  const kind = serviceId.slice(0, slash) as ComponentKind;
  const name = serviceId.slice(slash + 1);
  if (slash < 0 || !COMPONENT_KINDS.includes(kind) || name.length === 0) {
    throw new Error('DigitalOcean component reference is invalid');
  }
  return { kind, name };
}

function envEntry(value: unknown): EnvEntry {
  const entry = record(value);
  const key = nonemptyString(entry.key);
  if (entry.value !== undefined && entry.value !== null && typeof entry.value !== 'string') return invalidResponse();
  if (entry.type !== undefined && entry.type !== null && typeof entry.type !== 'string') return invalidResponse();
  const text = typeof entry.value === 'string' ? entry.value : undefined;
  const sealed = entry.type === 'SECRET' || (text !== undefined && CIPHERTEXT.test(text));
  return { entry, key, value: text, sealed };
}

function deploymentId(value: unknown): string | undefined {
  const deployment = optionalRecord(value);
  if (deployment === undefined) return undefined;
  return nonemptyString(deployment.id);
}

export function createDigitalOceanHost({ token, apps, http, log }: DigitalOceanHostOptions): HostAdapter {
  /** Deployments created by this adapter's spec updates, oldest first, per app id. In memory only. */
  const created = new Map<string, string[]>();

  function request(method: HttpRequest['method'], path: string, body?: unknown): Promise<unknown> {
    const headers: Record<string, string> = { Authorization: `Bearer ${token}` };
    const req: HttpRequest = { method, url: `${BASE_URL}${path}`, headers };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      req.body = JSON.stringify(body);
    }
    return requestJson<unknown>(http, 'DigitalOcean', req);
  }

  const appPath = (service: ServiceRef) => `/apps/${segment(service.projectId)}`;

  async function getApp(path: string): Promise<Record<string, unknown>> {
    return record(record(await request('GET', path)).app);
  }

  function servicesFor(app: Record<string, unknown>): ServiceRef[] {
    const id = nonemptyString(app.id);
    const spec = record(app.spec);
    const name = nonemptyString(spec.name);
    const base = { host: 'digitalocean' as const, projectId: id, projectName: name, environmentId: '', environmentName: '' };
    const services: ServiceRef[] = [{ ...base, serviceId: '', serviceName: 'app' }];
    const seen = new Set<string>();
    for (const kind of COMPONENT_KINDS) {
      const components = spec[kind];
      if (components === undefined || components === null) continue;
      if (!Array.isArray(components)) return invalidResponse();
      for (const component of components) {
        const componentName = nonemptyString(record(component).name);
        const serviceId = `${kind}/${componentName}`;
        if (seen.has(serviceId)) return invalidResponse();
        seen.add(serviceId);
        services.push({ ...base, serviceId, serviceName: componentName });
      }
    }
    return services;
  }

  /** The `envs` holder (spec or one component) for a ServiceRef. */
  function holderFor(spec: Record<string, unknown>, service: ServiceRef): Record<string, unknown> {
    const ref = componentRef(service.serviceId);
    if (ref === null) return spec;
    const components = spec[ref.kind];
    if (components !== undefined && components !== null && !Array.isArray(components)) return invalidResponse();
    const matches = (Array.isArray(components) ? components : []).map(record).filter((component) => component.name === ref.name);
    if (matches.length > 1) return invalidResponse();
    if (matches.length === 0) throw new Error('DigitalOcean component was not found in the app spec');
    return matches[0]!;
  }

  function entriesOf(holder: Record<string, unknown>): EnvEntry[] {
    if (holder.envs === undefined || holder.envs === null) return [];
    if (!Array.isArray(holder.envs)) return invalidResponse();
    return holder.envs.map(envEntry);
  }

  async function listAllApps(): Promise<Record<string, unknown>[]> {
    const result: Record<string, unknown>[] = [];
    const seen = new Set<string>();
    for (let page = 1; ; page++) {
      const body = record(await request('GET', `/apps?page=${page}&per_page=200`));
      let items: unknown[];
      if (body.apps === undefined || body.apps === null) {
        // The collection key can be omitted for an empty account.
        if (optionalRecord(body.meta)?.total !== 0) return invalidResponse();
        items = [];
      } else if (Array.isArray(body.apps)) {
        items = body.apps;
      } else {
        return invalidResponse();
      }
      let added = 0;
      for (const item of items) {
        const app = record(item);
        const id = nonemptyString(app.id);
        if (seen.has(id)) continue;
        seen.add(id);
        result.push(app);
        added++;
      }
      const pages = optionalRecord(optionalRecord(body.links)?.pages);
      const next = pages?.next;
      if (next !== undefined && next !== null && typeof next !== 'string') return invalidResponse();
      if (typeof next !== 'string' || next.length === 0) return result;
      if (added === 0) throw new Error('DigitalOcean pagination did not advance');
    }
  }

  async function phase(service: ServiceRef, id: string): Promise<string> {
    const body = record(await request('GET', `${appPath(service)}/deployments/${segment(id)}`));
    return nonemptyString(record(body.deployment).phase);
  }

  return {
    id: 'digitalocean',
    // redeploy: the spec update itself deploys; redeploy() reports that deployment so activation can be confirmed.
    // Every app spec update creates a deployment; redeploy() reports the deployment the write created.
    capabilities: { readValues: true, batchWrite: true, redeploy: true, activation: 'on-write' },

    async listServices() {
      let found: Record<string, unknown>[];
      if (apps !== undefined && apps.length > 0) {
        found = [];
        for (const id of new Set(apps)) found.push(await getApp(`/apps/${segment(id)}`));
      } else {
        found = await listAllApps();
      }
      return found.flatMap(servicesFor);
    },

    async readVariables(service): Promise<RawVariable[]> {
      const app = await getApp(appPath(service));
      const entries = entriesOf(holderFor(record(app.spec), service));
      const counts = new Map<string, number>();
      for (const { key } of entries) counts.set(key, (counts.get(key) ?? 0) + 1);
      const duplicates = [...counts].filter(([, count]) => count > 1).map(([key]) => key);
      if (duplicates.length > 0) {
        log.warn('DigitalOcean app spec repeats variable names; they are reported as sealed', { app: service.projectName, keys: duplicates });
      }
      const variables: RawVariable[] = [];
      const emitted = new Set<string>();
      for (const entry of entries) {
        if (emitted.has(entry.key)) continue;
        emitted.add(entry.key);
        if (entry.sealed || (counts.get(entry.key) ?? 0) > 1) variables.push({ name: entry.key, sealed: true });
        else variables.push({ name: entry.key, value: entry.value ?? '', sealed: false });
      }
      return variables;
    },

    async writeVariables(service, vars, opts) {
      const updates = Object.entries(vars);
      if (updates.some(([name]) => !ENV_KEY.test(name))) throw new Error('DigitalOcean variable name is invalid');
      if (updates.length === 0) return;
      componentRef(service.serviceId);
      const app = await getApp(appPath(service));
      if (optionalRecord(app.pinned_deployment) !== undefined) {
        throw new Error('DigitalOcean app is pinned to a rollback; commit or revert the rollback first');
      }
      const spec = record(app.spec);
      if (!specCredentialsRoundTrip(spec)) {
        throw new Error('DigitalOcean app spec holds a log destination or registry credential that is not encrypted, so a full spec update could overwrite it; update this variable in the DigitalOcean control panel instead');
      }
      const holder = holderFor(spec, service);
      const entries = entriesOf(holder);
      // Validate every key before changing anything.
      const targets = updates.map(([name, value]) => {
        const matches = entries.filter((entry) => entry.key === name);
        if (matches.length > 1) throw new Error('DigitalOcean app spec repeats a variable name; fix it in the app spec first');
        const existing = matches[0];
        if (existing !== undefined && !existing.sealed && existing.value !== undefined && BINDABLE.test(existing.value)) {
          throw new Error('DigitalOcean variable is a bindable reference; update the referenced resource instead');
        }
        return { name, value, existing };
      });
      let envs = holder.envs as unknown[] | undefined | null;
      for (const { name, value, existing } of targets) {
        // SECRET values are encrypted by App Platform on submission; type, scope and other fields stay as they were.
        if (existing !== undefined) existing.entry.value = value;
        else {
          if (envs === undefined || envs === null) {
            envs = [];
            holder.envs = envs;
          }
          envs.push({ key: name, value, scope: DEFAULT_SCOPE, type: 'SECRET' });
        }
      }
      if (opts.skipDeploy) {
        log.info('DigitalOcean deploys every app spec update; it cannot stage variable changes.', { app: service.projectName });
      }
      // Source versions stay pinned, so the update deploys the current code with the new variables.
      const response = record(await request('PUT', appPath(service), { spec, update_all_source_versions: false }));
      let createdId: string | undefined;
      try {
        createdId = deploymentId(record(response.app).pending_deployment);
      } catch {
        createdId = undefined;
      }
      if (createdId === undefined) {
        log.warn('DigitalOcean did not report the deployment for this update; status will use the app\'s pending deployment.', { app: service.projectName });
        created.delete(service.projectId);
        return;
      }
      created.set(service.projectId, [...(created.get(service.projectId) ?? []), createdId]);
    },

    async redeploy(service) {
      const chain = created.get(service.projectId);
      // Every service of one app shares the deployment created by the latest spec update.
      if (chain !== undefined && chain.length > 0) return chain[chain.length - 1]!;
      const app = await getApp(appPath(service));
      const pending = deploymentId(app.pending_deployment) ?? deploymentId(app.in_progress_deployment);
      if (pending !== undefined) return pending;
      // The active deployment may predate the update, so it cannot confirm activation.
      log.warn('DigitalOcean has no pending deployment for this app; activation unconfirmed.', { app: service.projectName });
      return null;
    },

    async deploymentStatus(service, id): Promise<DeployState> {
      const current = await phase(service, id);
      if (current === 'ACTIVE') return 'success';
      if (!FAILED_PHASES.has(current)) return 'pending';
      // A later spec update by this adapter replaces earlier deployments and carries their variables forward.
      const chain = created.get(service.projectId) ?? [];
      const latest = chain[chain.length - 1];
      if (!chain.includes(id) || latest === undefined || latest === id) return 'failed';
      const replacement = await phase(service, latest);
      if (replacement === 'ACTIVE') return 'success';
      return FAILED_PHASES.has(replacement) ? 'failed' : 'pending';
    },
  };
}
