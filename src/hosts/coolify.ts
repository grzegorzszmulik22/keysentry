import { isIP } from 'node:net';
import type { DeployState, HostAdapter, HttpClient, HttpRequest, Logger, RawVariable, ServiceRef } from '../types.js';
import { requestJson } from './http.js';

export type CoolifyResourceKind = 'application' | 'service';

export interface CoolifyHostOptions {
  /** API token (Keys & Tokens > API tokens), sent as `Authorization: Bearer`. */
  token: string;
  /** Instance origin with an optional port (a self-hosted DNS name, or Coolify Cloud: `https://app.coolify.io`). */
  baseUrl: string;
  /** Resource kinds to scan; default both. */
  include?: ('applications' | 'services')[];
  /** Limit to these application UUIDs. */
  applications?: string[];
  /** Limit to these service (Docker Compose / one-click) UUIDs. */
  services?: string[];
  /**
   * restart (default): recreate the containers with the current values, without building new code.
   * deploy: start a new deployment, which builds the configured branch and may include newer commits.
   */
  redeploy?: 'restart' | 'deploy';
  http: HttpClient;
  log: Logger;
}

interface EnvEntry {
  key: string;
  value?: string;
  preview: boolean;
  literal?: boolean;
  multiline?: boolean;
  shownOnce?: boolean;
  buildtime?: boolean;
  shared?: boolean;
}

type Data = Record<string, unknown>;

const UUID = /^[A-Za-z0-9_-]+$/;
/** Documented shared-variable reference syntax, e.g. `{{environment.DATABASE_URL}}`. */
const SHARED_REFERENCE = /\{\{\s*(?:team|project|environment|server)\.[^}]*\}\}/u;
const FAILED_STATES = new Set(['failed', 'cancelled-by-user', 'cancelled', 'error', 'killed']);

/**
 * Validate a self-hosted Coolify base URL and return the API root (`<origin>/api/v1`). Only an https origin on
 * the default port with a DNS hostname is accepted: no credentials, path, query, fragment or IP literal, so the
 * hostname can be added to `network.allowHosts` as an exact rule.
 */
export function coolifyApiRoot(baseUrl: string): string {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new Error('Coolify base URL is invalid');
  }
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const canonical = url.origin.toLowerCase();
  const given = baseUrl.toLowerCase();
  // An explicit port is allowed (self-hosted Coolify often listens on 8000); egress then allows exactly that port.
  if (url.protocol !== 'https:' || url.username !== '' || url.password !== ''
    || host.length === 0 || isIP(host) !== 0 || (given !== canonical && given !== `${canonical}/`)) {
    throw new Error('Coolify base URL must be the https address of your Coolify instance (a DNS name, optionally with a port), without a path or credentials');
  }
  return `${url.origin}/api/v1`;
}

function invalidResponse(): never {
  // Upstream payloads can contain plaintext values; never echo them.
  throw new Error('Coolify returned an invalid response');
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

function optionalFlag(value: unknown): boolean | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'boolean') return invalidResponse();
  return value;
}

function uuid(value: string): string {
  if (typeof value !== 'string' || !UUID.test(value)) throw new Error('Coolify resource id is invalid');
  return value;
}

function envEntry(value: unknown): EnvEntry {
  const entry = record(value);
  const key = nonempty(entry.key);
  if (entry.value !== undefined && entry.value !== null && typeof entry.value !== 'string') return invalidResponse();
  return {
    key,
    ...(typeof entry.value === 'string' ? { value: entry.value } : {}),
    preview: optionalFlag(entry.is_preview) ?? false,
    literal: optionalFlag(entry.is_literal),
    multiline: optionalFlag(entry.is_multiline),
    shownOnce: optionalFlag(entry.is_shown_once),
    buildtime: optionalFlag(entry.is_buildtime),
    shared: optionalFlag(entry.is_shared),
  };
}

function isReference(entry: EnvEntry): boolean {
  return entry.shared === true || (entry.value !== undefined && SHARED_REFERENCE.test(entry.value));
}

/** Readable only when the value is present and not marked "shown once" (locked). */
function readable(entry: EnvEntry): entry is EnvEntry & { value: string } {
  return entry.value !== undefined && entry.shownOnce !== true;
}

export function createCoolifyHost(opts: CoolifyHostOptions): HostAdapter {
  const { http, log } = opts;
  const root = coolifyApiRoot(opts.baseUrl);
  const include = new Set(opts.include ?? ['applications', 'services']);
  if ([...include].some((kind) => kind !== 'applications' && kind !== 'services')) throw new Error('Coolify resource kind is invalid');
  const applications = opts.applications === undefined ? undefined : new Set(opts.applications.map(uuid));
  const services = opts.services === undefined ? undefined : new Set(opts.services.map(uuid));
  const mode = opts.redeploy ?? 'restart';
  if (mode !== 'restart' && mode !== 'deploy') throw new Error('Coolify redeploy mode is invalid');

  async function request(method: HttpRequest['method'], path: string, body?: unknown): Promise<unknown> {
    const headers: Record<string, string> = { Authorization: `Bearer ${opts.token}` };
    const req: HttpRequest = { method, url: `${root}${path}`, headers };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      req.body = JSON.stringify(body);
    }
    return requestJson<unknown>(http, 'Coolify', req);
  }

  function resource(service: ServiceRef): { kind: CoolifyResourceKind; uuid: string; path: string } {
    if (service.host !== 'coolify' || service.environmentId !== '') throw new Error('Coolify service reference is invalid');
    const separator = service.serviceId.indexOf(':');
    const kind = service.serviceId.slice(0, separator);
    const id = service.serviceId.slice(separator + 1);
    if (separator < 0 || (kind !== 'application' && kind !== 'service') || !UUID.test(id) || service.projectId !== id) {
      throw new Error('Coolify service reference is invalid');
    }
    return { kind, uuid: id, path: `/${kind}s/${encodeURIComponent(id)}` };
  }

  async function listKind(kind: CoolifyResourceKind, only: Set<string> | undefined): Promise<ServiceRef[]> {
    // GET /applications and GET /services are documented as plain arrays without pagination.
    const found = list(await request('GET', `/${kind}s`)).map((item) => {
      const value = record(item);
      const id = nonempty(value.uuid);
      if (!UUID.test(id)) return invalidResponse();
      return { id, name: nonempty(value.name) };
    });
    if (only !== undefined && [...only].some((id) => !found.some((item) => item.id === id))) {
      throw new Error('Coolify configured resource was not found or is not visible to this token');
    }
    return found
      .filter((item) => only === undefined || only.has(item.id))
      .map((item) => ({
        host: 'coolify', projectId: item.id, projectName: item.name, serviceId: `${kind}:${item.id}`, serviceName: item.name,
        environmentId: '', environmentName: '',
      }));
  }

  async function envs(path: string): Promise<EnvEntry[]> {
    // Production values only: preview-deployment values (is_preview) are a separate set keysentry does not manage.
    return list(await request('GET', `${path}/envs`)).map(envEntry).filter((entry) => !entry.preview);
  }

  function byKey(entries: EnvEntry[]): Map<string, EnvEntry[]> {
    const map = new Map<string, EnvEntry[]>();
    for (const entry of entries) map.set(entry.key, [...map.get(entry.key) ?? [], entry]);
    return map;
  }

  /** All entries, preview included, keyed for the post-write comparison. */
  async function snapshot(path: string): Promise<Map<string, EnvEntry>> {
    const result = new Map<string, EnvEntry>();
    for (const entry of list(await request('GET', `${path}/envs`)).map(envEntry)) {
      const id = `${entry.preview ? 'preview' : 'production'}\u0000${entry.key}`;
      if (result.has(id)) return invalidResponse();
      result.set(id, entry);
    }
    return result;
  }

  return {
    id: 'coolify',
    // Values are readable with a read:sensitive token; per-key writes; restart/deploy is a separate step.
    capabilities: { readValues: true, batchWrite: false, redeploy: true },
    // Application restarts and deployments return a deployment id; service restarts do not.
    activationFor: service => service.serviceId.startsWith('application:') ? 'redeploy' : 'manual',

    async listServices() {
      const refs: ServiceRef[] = [];
      if (include.has('applications')) refs.push(...await listKind('application', applications));
      if (include.has('services')) refs.push(...await listKind('service', services));
      return refs;
    },

    async readVariables(service): Promise<RawVariable[]> {
      const { path } = resource(service);
      const grouped = byKey(await envs(path));
      const ambiguous = [...grouped].filter(([, entries]) => entries.length > 1).map(([key]) => key);
      if (ambiguous.length > 0) log.warn('Coolify has duplicate variables; they are reported as sealed', { keys: ambiguous });
      return [...grouped].map(([name, entries]): RawVariable => {
        const entry = entries[0]!;
        if (entries.length > 1 || !readable(entry)) return { name, sealed: true };
        // Shared-variable references are returned as written (`{{environment.X}}`), never resolved.
        return { name, value: entry.value, sealed: false };
      });
    },

    async writeVariables(service, vars, _writeOptions) {
      const { path } = resource(service);
      const changes = Object.entries(vars);
      if (changes.length === 0) return;
      if (changes.some(([name]) => name.length === 0 || /[\s=]/u.test(name))) throw new Error('Coolify variable name is invalid');
      const before = await snapshot(path);
      const current = byKey([...before.values()].filter((entry) => !entry.preview));
      for (const [name] of changes) {
        const existing = current.get(name) ?? [];
        if (existing.length > 1) throw new Error('Coolify has duplicate variables with this name; fix them in Coolify first');
        // Overwriting a shared-variable reference would replace the reference with a copy of the secret.
        if (existing.length === 1 && isReference(existing[0]!)) {
          throw new Error('Coolify variable references a shared variable; rotate the shared variable instead');
        }
      }
      let buildtime = false;
      for (const [key, value] of changes) {
        const existing = current.get(key)?.[0];
        const multiline = value.includes('\n');
        if (existing === undefined) {
          // New variables are literal so Coolify never interpolates `$` sequences inside a secret.
          await request('POST', `${path}/envs`, { key, value, is_preview: false, is_literal: true, is_multiline: multiline });
          buildtime = true; // Coolify's default for new variables is "available during build".
          continue;
        }
        // PATCH by key; resend the existing flags so the update changes only the value.
        await request('PATCH', `${path}/envs`, {
          key, value, is_preview: false,
          ...(existing.literal === undefined ? {} : { is_literal: existing.literal }),
          ...(existing.multiline === undefined && !multiline ? {} : { is_multiline: existing.multiline === true || multiline }),
          ...(existing.shownOnce === undefined ? {} : { is_shown_once: existing.shownOnce }),
        });
        if (existing.buildtime !== false) buildtime = true;
      }
      // Coolify updates by key; make sure no preview value or other variable was touched.
      const after = await snapshot(path);
      for (const [id, was] of before) {
        const now = after.get(id);
        if (now === undefined) throw drift();
        if (!was.preview && Object.hasOwn(vars, was.key)) continue;
        if (now.value !== was.value) throw drift();
      }
      for (const [id, now] of after) {
        if (!before.has(id) && (now.preview || !Object.hasOwn(vars, now.key))) throw drift();
      }
      for (const [key, value] of changes) {
        const now = after.get(`production\u0000${key}`);
        if (now === undefined || (readable(now) && now.value !== value)) throw drift();
      }
      // Coolify writes never deploy, regardless of skipDeploy.
      if (buildtime && mode === 'restart') {
        log.warn('Coolify restart applies new runtime values but does not rebuild; values used during the build need a new deployment', {
          resource: service.serviceName,
        });
      }
    },

    async redeploy(service) {
      const { kind, path } = resource(service);
      if (kind === 'service') {
        // The documented service restart response has no deployment id.
        await request('POST', `${path}/restart`);
        log.warn('Coolify service restart has no deployment id; activation unconfirmed', { resource: service.serviceName });
        return null;
      }
      const response = record(await request('POST', `${path}/${mode === 'deploy' ? 'start' : 'restart'}`));
      return nonempty(response.deployment_uuid);
    },

    async deploymentStatus(service, deploymentId): Promise<DeployState> {
      resource(service);
      const deployment = record(await request('GET', `/deployments/${encodeURIComponent(uuid(deploymentId))}`));
      const status = nonempty(deployment.status);
      if (status === 'finished') return 'success';
      return FAILED_STATES.has(status) ? 'failed' : 'pending';
    },
  };
}

function drift(): Error {
  return new Error('Coolify variables changed beyond this update; check the resource in Coolify');
}
