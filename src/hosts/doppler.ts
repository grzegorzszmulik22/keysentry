import type { HostAdapter, HttpClient, HttpRequest, HttpResponse, Logger, RawVariable, ServiceRef } from '../types.js';

/**
 * Doppler as a keysentry host (notes/secret-stores.md).
 *
 * One project + config is one ServiceRef; each secret is a variable. keysentry reads the `raw` value (a reference
 * such as `${OTHER}` stays a reference) because writing a computed value would replace the reference with a copy.
 * Restricted values are not returned to user-bound tokens and are reported as write-only.
 *
 * Writes use `change_requests` for exactly the given names. For readable secrets each request carries
 * `originalValue`, which Doppler documents as a precondition, so a concurrent change is not overwritten. Doppler does
 * not deploy; Doppler integrations and syncs that the user configured may still push the change elsewhere.
 */
export interface DopplerHostOptions {
  token: string;
  /** Exact configs to scan. Needed for service tokens, which are bound to one config and cannot list projects. */
  configs?: { project: string; config: string }[];
  /** Projects to scan when `configs` is not set; every visible project when omitted. */
  projects?: string[];
  /** Also scan branch configs (default: root configs only, so inherited values are not written as overrides). */
  includeBranchConfigs?: boolean;
  http: HttpClient;
  log: Logger;
}

const BASE_URL = 'https://api.doppler.com';
const PER_PAGE = 20;
const MAX_PAGES = 500;
const IDENTIFIER = /^[A-Za-z0-9_.-]{1,128}$/;

function invalidResponse(): never {
  throw new Error('Doppler returned an invalid response');
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalidResponse();
  return value as Record<string, unknown>;
}

function nonempty(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) invalidResponse();
  return value;
}

function identifier(value: string, what: string): string {
  if (!IDENTIFIER.test(value)) throw new Error(`Doppler ${what} is invalid`);
  return value;
}

interface DopplerSecret {
  raw?: string;
  readable: boolean;
  /** The secret's current visibility and value type, sent back with every change so an update never resets them. */
  visibility?: 'masked' | 'unmasked' | 'restricted';
  valueType?: string;
}

const VISIBILITIES = new Set(['masked', 'unmasked', 'restricted']);
const VALUE_TYPE = /^[a-z0-9]{1,32}$/;

function secretEntry(value: unknown): DopplerSecret {
  const entry = object(value);
  const visibility = entry.rawVisibility === undefined || entry.rawVisibility === null ? {} : object(entry.rawVisibility);
  const restricted = visibility.type === 'restricted';
  const kept: Pick<DopplerSecret, 'visibility' | 'valueType'> = {};
  if (typeof visibility.type === 'string' && VISIBILITIES.has(visibility.type)) kept.visibility = visibility.type as DopplerSecret['visibility'];
  const valueType = entry.rawValueType ?? entry.valueType;
  if (valueType !== undefined && valueType !== null) {
    const type = object(valueType).type;
    if (typeof type === 'string' && VALUE_TYPE.test(type)) kept.valueType = type;
  }
  if (entry.raw === undefined || entry.raw === null) return { readable: false, ...kept };
  if (typeof entry.raw !== 'string') invalidResponse();
  // Older behaviour returned an empty string for a restricted value hidden from a user-bound token.
  if (restricted && entry.raw === '') return { readable: false, ...kept };
  return { raw: entry.raw, readable: true, ...kept };
}

/**
 * Doppler documents no default `visibility` for a change request, so an update without one might reset a restricted
 * secret to masked. Send the current visibility (and value type, when the listing shows it) back unchanged.
 */
function keepSettings(existing: DopplerSecret): Record<string, unknown> {
  return {
    ...(existing.visibility ? { visibility: existing.visibility } : {}),
    ...(existing.valueType ? { valueType: { type: existing.valueType } } : {}),
  };
}

export function createDopplerHost(opts: DopplerHostOptions): HostAdapter {
  if (!opts.token) throw new Error('Doppler token is missing');
  const configs = opts.configs?.map(({ project, config }) => ({ project: identifier(project, 'project'), config: identifier(config, 'config') }));
  const projects = opts.projects?.map((project) => identifier(project, 'project'));

  async function send(method: HttpRequest['method'], path: string, query: Record<string, string>, body?: unknown): Promise<HttpResponse> {
    const headers: Record<string, string> = { Authorization: `Bearer ${opts.token}`, Accept: 'application/json' };
    const search = new URLSearchParams(query).toString();
    const req: HttpRequest = { method, url: `${BASE_URL}${path}${search ? `?${search}` : ''}`, headers };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      req.body = JSON.stringify(body);
    }
    try {
      return await opts.http.request(req);
    } catch {
      throw new Error('Doppler request failed');
    }
  }

  async function request(method: HttpRequest['method'], path: string, query: Record<string, string>, body?: unknown): Promise<Record<string, unknown>> {
    const response = await send(method, path, query, body);
    if (response.status < 200 || response.status >= 300) throw new Error(`Doppler request failed (HTTP ${response.status})`);
    try { return object(response.json<unknown>()); } catch (error) {
      if (error instanceof Error && error.message.startsWith('Doppler')) throw error;
      throw new Error('Doppler returned invalid JSON');
    }
  }

  /** Page-number pagination: stop on a short page; a repeated page means the server is not advancing. */
  async function pages(path: string, field: string, query: Record<string, string>, key: (item: Record<string, unknown>) => string): Promise<Record<string, unknown>[]> {
    const items: Record<string, unknown>[] = [];
    let previous = '';
    for (let page = 1; page <= MAX_PAGES; page += 1) {
      const body = await request('GET', path, { ...query, page: String(page), per_page: String(PER_PAGE) });
      const list = body[field];
      if (!Array.isArray(list)) invalidResponse();
      const pageItems = list.map(object);
      const signature = pageItems.map(key).join('\n');
      if (pageItems.length > 0 && signature === previous) throw new Error('Doppler pagination did not advance');
      previous = signature;
      items.push(...pageItems);
      if (pageItems.length < PER_PAGE) return items;
    }
    throw new Error('Doppler pagination did not advance');
  }

  async function readSecrets(service: ServiceRef): Promise<Map<string, DopplerSecret>> {
    const body = await request('GET', '/v3/configs/config/secrets', {
      project: service.projectId, config: service.serviceId,
      include_dynamic_secrets: 'false', include_managed_secrets: 'false',
    });
    const secrets = object(body.secrets);
    return new Map(Object.entries(secrets).map(([name, value]) => [name, secretEntry(value)]));
  }

  function ref(project: string, projectName: string, config: string, environment: string): ServiceRef {
    return {
      host: 'doppler', projectId: project, projectName, serviceId: config, serviceName: config,
      // Doppler config names are unique within a project; the environment is descriptive only.
      environmentId: '', environmentName: environment,
    };
  }

  return {
    id: 'doppler',
    // A secret store does not deploy (activation manual); whether consumers read at use time is the application's choice.
    capabilities: { readValues: true, batchWrite: true, redeploy: false },

    async listServices() {
      if (configs) return configs.map(({ project, config }) => ref(project, project, config, ''));
      const targets: { slug: string; name: string }[] = projects
        ? projects.map((slug) => ({ slug, name: slug }))
        : (await pages('/v3/projects', 'projects', {}, (item) => nonempty(item.id))).map((item) => {
          const slug = nonempty(item.slug);
          return { slug: identifier(slug, 'project'), name: typeof item.name === 'string' && item.name ? item.name : slug };
        });
      const refs: ServiceRef[] = [];
      for (const project of targets) {
        const list = await pages('/v3/configs', 'configs', { project: project.slug }, (item) => nonempty(item.name));
        for (const item of list) {
          const name = identifier(nonempty(item.name), 'config');
          if (item.root !== true && !opts.includeBranchConfigs) continue;
          refs.push(ref(project.slug, project.name, name, typeof item.environment === 'string' ? item.environment : ''));
        }
      }
      return refs;
    },

    async readVariables(service): Promise<RawVariable[]> {
      const secrets = await readSecrets(service);
      return [...secrets].map(([name, secret]) => (secret.readable
        ? { name, value: secret.raw!, sealed: false }
        : { name, sealed: true }));
    },

    async writeVariables(service, vars, _writeOptions) {
      const entries = Object.entries(vars);
      if (entries.length === 0) return;
      if (entries.some(([name]) => name === '')) throw new Error('Doppler secret name is empty');
      const current = await readSecrets(service);
      const changes: Record<string, unknown>[] = [];
      for (const [name, value] of entries) {
        const existing = current.get(name);
        if (!existing) {
          changes.push({ name, originalName: null, value });
        } else if (!existing.readable) {
          // A write-only value cannot be compared; Doppler gets no precondition for it.
          changes.push({ name, originalName: name, value, ...keepSettings(existing) });
        } else if (existing.raw !== value) {
          changes.push({ name, originalName: name, value, originalValue: existing.raw, ...keepSettings(existing) });
        }
      }
      if (changes.length === 0) return;
      const response = await send('POST', '/v3/configs/config/secrets', {}, {
        project: service.projectId, config: service.serviceId, change_requests: changes,
      });
      if (response.status < 200 || response.status >= 300) {
        throw new Error(`Doppler did not apply the update (HTTP ${response.status}); a secret may have changed since keysentry read it`);
      }
      try { object(object(response.json<unknown>()).secrets); } catch { throw new Error('Doppler returned an invalid response'); }
    },

    async redeploy() { return null; },
    async deploymentStatus() { throw new Error('Doppler does not create deployments'); },
  };
}
