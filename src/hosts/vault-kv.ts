import type { HostAdapter, HttpClient, HttpRequest, HttpResponse, Logger, RawVariable, ServiceRef } from '../types.js';

/**
 * HashiCorp Vault KV version 2 as a keysentry host (notes/secret-stores.md).
 *
 * One KV path is one ServiceRef; each string-valued key in its data map is a variable. Other JSON values are kept and
 * are not variables. Writes read the current version and send a JSON merge patch with only the given keys and
 * `options.cas` set to that version, so other keys, custom metadata and version settings are untouched and a
 * concurrent write fails. When the token lacks the `patch` capability (HTTP 403/405), the adapter falls back to a
 * full-map POST with the same `cas`, but only when every existing value is a string so the rewrite is exact.
 */
export interface VaultKvHostOptions {
  /** Vault origin (https, a DNS name, optionally a port such as 8200). The adapter adds /v1. */
  address: string;
  token: string;
  /** Enterprise / HCP namespace, sent as X-Vault-Namespace. */
  namespace?: string;
  /** KV v2 mount path. Default `secret`. */
  mount?: string;
  /** Folders to scan recursively, relative to the mount. Default: the whole mount. */
  paths?: string[];
  http: HttpClient;
  log: Logger;
}

const SEGMENT = /^[^/]+$/;
const MOUNT_SEGMENT = /^[A-Za-z0-9_.-]+$/;
const NAMESPACE = /^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/;
const MAX_SECRETS = 10_000;
const MAX_DEPTH = 32;

function invalidResponse(): never {
  throw new Error('Vault returned an invalid response');
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalidResponse();
  return value as Record<string, unknown>;
}

export function vaultOrigin(address: string): string {
  let url: URL;
  try { url = new URL(address); } catch { throw new Error('Vault address is invalid'); }
  const path = url.pathname.replace(/\/+$/, '');
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || /[?#]/.test(address)
    || (path !== '' && path !== '/v1')) {
    throw new Error('Vault address must be an https origin without credentials, path or query');
  }
  return url.origin;
}

function segments(path: string, what: string): string[] {
  const parts = path.split('/').filter((part) => part !== '');
  if (parts.some((part) => part === '.' || part === '..' || !SEGMENT.test(part))) throw new Error(`Vault ${what} is invalid`);
  return parts;
}

function encodePath(parts: string[]): string {
  return parts.map(encodeURIComponent).join('/');
}

function cas(value: unknown): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) invalidResponse();
  return value;
}

function errorMentionsCas(response: HttpResponse): boolean {
  try {
    const errors = (response.json<Record<string, unknown>>() ?? {}).errors;
    return Array.isArray(errors) && errors.some((message) => typeof message === 'string' && /check-and-set/i.test(message));
  } catch {
    return false;
  }
}

export function createVaultKvHost(opts: VaultKvHostOptions): HostAdapter {
  const origin = vaultOrigin(opts.address);
  if (!opts.token) throw new Error('Vault token is missing');
  if (opts.namespace !== undefined && !NAMESPACE.test(opts.namespace)) throw new Error('Vault namespace is invalid');
  const mountParts = (opts.mount ?? 'secret').split('/').filter((part) => part !== '');
  if (mountParts.length === 0 || mountParts.some((part) => !MOUNT_SEGMENT.test(part) || part === '.' || part === '..')) {
    throw new Error('Vault mount path is invalid');
  }
  const mount = mountParts.join('/');
  const roots = (opts.paths ?? ['']).map((path) => segments(path, 'path'));
  const environment = opts.namespace ?? '';

  async function send(method: HttpRequest['method'], path: string, body?: unknown, contentType = 'application/json'): Promise<HttpResponse> {
    const headers: Record<string, string> = { 'X-Vault-Token': opts.token };
    if (opts.namespace !== undefined) headers['X-Vault-Namespace'] = opts.namespace;
    const req: HttpRequest = { method, url: `${origin}/v1/${mount}/${path}`, headers };
    if (body !== undefined) {
      headers['Content-Type'] = contentType;
      req.body = JSON.stringify(body);
    }
    try {
      return await opts.http.request(req);
    } catch {
      throw new Error('Vault request failed');
    }
  }

  function parse(response: HttpResponse): Record<string, unknown> {
    if (response.status < 200 || response.status >= 300) throw new Error(`Vault request failed (HTTP ${response.status})`);
    if (!response.text.trim()) return {};
    try { return object(response.json<unknown>()); } catch (error) {
      if (error instanceof Error && error.message.startsWith('Vault')) throw error;
      throw new Error('Vault returned invalid JSON');
    }
  }

  function ref(parts: string[]): ServiceRef {
    const path = parts.join('/');
    return {
      host: 'vault-kv', projectId: mount, projectName: opts.namespace ? `${opts.namespace}/${mount}` : mount,
      serviceId: path, serviceName: path, environmentId: environment, environmentName: environment,
    };
  }

  /** Current data and version of a path; null when the latest version is deleted or destroyed. */
  async function readCurrent(service: ServiceRef): Promise<{ data: Record<string, unknown>; version: number } | null> {
    const response = await send('GET', `data/${encodePath(segments(service.serviceId, 'secret path'))}`);
    if (response.status === 404) return null;
    const body = object(parse(response).data);
    const metadata = object(body.metadata);
    // A future deletion_time (delete_version_after) still returns data; only missing data means deleted.
    if (metadata.destroyed === true || body.data === null || body.data === undefined) return null;
    return { data: object(body.data), version: cas(metadata.version) };
  }

  return {
    id: 'vault-kv',
    // A secret store does not deploy (activation manual); whether consumers read at use time is the application's choice.
    capabilities: { readValues: true, batchWrite: true, redeploy: false },

    async listServices() {
      const refs: ServiceRef[] = [];
      const seen = new Set<string>();
      const queue = roots.map((parts) => parts);
      while (queue.length > 0) {
        const folder = queue.shift()!;
        if (folder.length > MAX_DEPTH) throw new Error('Vault folders are nested too deeply');
        const prefix = folder.length ? `${encodePath(folder)}/` : '';
        const response = await send('GET', `metadata/${prefix}?list=true`);
        if (response.status === 404) continue;
        const keys = object(parse(response).data).keys;
        if (!Array.isArray(keys)) invalidResponse();
        for (const key of keys) {
          if (typeof key !== 'string' || key === '' || key === '/') invalidResponse();
          const isFolder = key.endsWith('/');
          const name = isFolder ? key.slice(0, -1) : key;
          if (name === '.' || name === '..' || !SEGMENT.test(name)) invalidResponse();
          const parts = [...folder, name];
          const id = `${isFolder ? 'd' : 's'}:${parts.join('/')}`;
          if (seen.has(id)) continue;
          seen.add(id);
          if (isFolder) queue.push(parts);
          else {
            refs.push(ref(parts));
            if (refs.length > MAX_SECRETS) throw new Error('Vault mount has more secrets than keysentry scans; narrow hosts.vault.paths');
          }
        }
      }
      return refs;
    },

    async readVariables(service): Promise<RawVariable[]> {
      const current = await readCurrent(service);
      if (!current) return [];
      return Object.entries(current.data)
        .filter((entry): entry is [string, string] => typeof entry[1] === 'string')
        .map(([name, value]) => ({ name, value, sealed: false }));
    },

    async writeVariables(service, vars, _writeOptions) {
      const entries = Object.entries(vars);
      if (entries.length === 0) return;
      if (entries.some(([name]) => name === '')) throw new Error('Vault key name is empty');
      const current = await readCurrent(service);
      if (!current) throw new Error('Vault secret is deleted or missing; restore it before writing');
      for (const [name] of entries) {
        if (Object.hasOwn(current.data, name) && typeof current.data[name] !== 'string') {
          throw new Error('Vault key holds a non-string value; keysentry only replaces string values');
        }
      }
      if (entries.every(([name, value]) => current.data[name] === value && Object.hasOwn(current.data, name))) return;
      const path = `data/${encodePath(segments(service.serviceId, 'secret path'))}`;
      const conflict = () => new Error('Vault secret changed while keysentry was writing it; nothing was written. Scan again and retry.');

      const patch = await send('PATCH', path, { options: { cas: current.version }, data: Object.fromEntries(entries) }, 'application/merge-patch+json');
      if (patch.status >= 200 && patch.status < 300) return;
      if (patch.status === 400 && errorMentionsCas(patch)) throw conflict();
      if (patch.status !== 403 && patch.status !== 405) throw new Error(`Vault request failed (HTTP ${patch.status})`);

      // No patch capability or an older server: a full write is exact only when every existing value is a string.
      if (!Object.values(current.data).every((value) => typeof value === 'string')) {
        throw new Error('Vault token needs the patch capability to update a secret with non-string values');
      }
      opts.log.debug('Vault patch was refused; writing the full secret with check-and-set', { path: service.serviceId });
      const post = await send('POST', path, { options: { cas: current.version }, data: Object.fromEntries([...Object.entries(current.data), ...entries]) });
      if (post.status === 400 && errorMentionsCas(post)) throw conflict();
      parse(post);
    },

    async redeploy() { return null; },
    async deploymentStatus() { throw new Error('Vault does not create deployments'); },
  };
}
