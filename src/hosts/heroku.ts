import type { DeployState, HostAdapter, HttpClient, HttpRequest, HttpResponse, Logger, RawVariable, ServiceRef } from '../types.js';

/**
 * Heroku Platform API v3 (sources: notes/hosts-a.md).
 *
 * A config var change always creates a release and restarts the app's dynos; the API has no way to stage a change.
 * `skipDeploy` therefore cannot prevent activation. Writes send every requested var in one PATCH, so each write call
 * produces exactly one release. `redeploy` never restarts anything: it returns the release that write created so the
 * caller can confirm activation.
 */
export interface HerokuHostOptions {
  token: string;
  /** App names or ids to scan. When set, only these apps are listed. */
  apps?: string[];
  /** Team name or id. When set (and `apps` is not), only that team's apps are listed. */
  team?: string;
  http: HttpClient;
  log: Logger;
}

const BASE_URL = 'https://api.heroku.com';
const ACCEPT = 'application/vnd.heroku+json; version=3';
// Documented maximum page size is 1000; the default sort key for app lists is `id`.
const FIRST_RANGE = 'id ..; max=1000;';
const NEWEST_RELEASE_RANGE = 'version ..; order=desc,max=1;';
// The schema's patternProperties for config vars.
const CONFIG_KEY = /^\w+$/;

interface Release { id: string }

function invalidResponse(): never {
  // Upstream payloads (config vars, release metadata) can contain secrets; never include them.
  throw new Error('Heroku returned an invalid response');
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return invalidResponse();
  return value as Record<string, unknown>;
}

function nonemptyString(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) return invalidResponse();
  return value;
}

function segment(value: string): string {
  if (value.length === 0 || value === '.' || value === '..') throw new Error('Heroku identifier is invalid');
  return encodeURIComponent(value);
}

function header(headers: Record<string, string>, name: string): string | undefined {
  return Object.entries(headers).find(([key]) => key.toLowerCase() === name)?.[1];
}

export function createHerokuHost({ token, apps, team, http, log }: HerokuHostOptions): HostAdapter {
  /** Release created by the latest successful write, per app id. In memory only. */
  const writtenReleases = new Map<string, string>();

  async function call(method: HttpRequest['method'], path: string, opts: { range?: string; body?: unknown } = {}):
  Promise<{ status: number; headers: Record<string, string>; data: unknown }> {
    const headers: Record<string, string> = { Authorization: `Bearer ${token}`, Accept: ACCEPT };
    if (opts.range !== undefined) headers.Range = opts.range;
    const req: HttpRequest = { method, url: `${BASE_URL}${path}`, headers };
    if (opts.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      req.body = JSON.stringify(opts.body);
    }
    let response: HttpResponse;
    try {
      response = await http.request(req);
    } catch {
      throw new Error('Heroku request failed');
    }
    if (response.status < 200 || response.status >= 300) throw new Error(`Heroku request failed (HTTP ${response.status})`);
    let data: unknown;
    if (response.text.trim()) {
      try {
        data = response.json();
      } catch {
        throw new Error('Heroku returned invalid JSON');
      }
    }
    return { status: response.status, headers: response.headers ?? {}, data };
  }

  /** Follows Heroku's Range pagination: 206 Partial Content plus Next-Range until a complete (200) response. */
  async function listRange(path: string): Promise<Record<string, unknown>[]> {
    const items: Record<string, unknown>[] = [];
    const seen = new Set<string>([FIRST_RANGE]);
    let range = FIRST_RANGE;
    for (;;) {
      const page = await call('GET', path, { range });
      if (!Array.isArray(page.data)) return invalidResponse();
      items.push(...page.data.map(record));
      if (page.status !== 206) return items;
      const next = header(page.headers, 'next-range');
      if (next === undefined || next.trim() === '') return invalidResponse();
      if (seen.has(next)) throw new Error('Heroku pagination did not advance');
      seen.add(next);
      range = next;
    }
  }

  function serviceFor(value: unknown): ServiceRef {
    const app = record(value);
    const id = nonemptyString(app.id);
    const name = nonemptyString(app.name);
    return { host: 'heroku', projectId: id, projectName: name, serviceId: id, serviceName: name, environmentId: '', environmentName: '' };
  }

  const appPath = (service: ServiceRef) => `/apps/${segment(service.serviceId)}`;

  async function newestRelease(service: ServiceRef): Promise<Release | null> {
    const page = await call('GET', `${appPath(service)}/releases`, { range: NEWEST_RELEASE_RANGE });
    if (!Array.isArray(page.data)) return invalidResponse();
    if (page.data.length === 0) return null;
    return { id: nonemptyString(record(page.data[0]).id) };
  }

  async function addonConfigVars(service: ServiceRef): Promise<Set<string>> {
    const names = new Set<string>();
    for (const addon of await listRange(`${appPath(service)}/addons`)) {
      if (addon.config_vars === undefined || addon.config_vars === null) continue;
      if (!Array.isArray(addon.config_vars)) return invalidResponse();
      for (const name of addon.config_vars) names.add(nonemptyString(name));
    }
    return names;
  }

  return {
    id: 'heroku',
    // redeploy: the write itself releases; redeploy() reports that release so activation can be confirmed.
    // Every config var change creates a release; redeploy() reports the release the write created.
    capabilities: { readValues: true, batchWrite: true, redeploy: true, activation: 'on-write' },

    async listServices() {
      let services: ServiceRef[];
      if (apps !== undefined && apps.length > 0) {
        const paths = [...new Set(apps)].map((name) => `/apps/${segment(name)}`);
        services = [];
        for (const path of paths) services.push(serviceFor((await call('GET', path)).data));
      } else {
        const path = team === undefined ? '/apps' : `/teams/${segment(team)}/apps`;
        services = (await listRange(path)).map(serviceFor);
      }
      const seen = new Set<string>();
      return services.filter((service) => !seen.has(service.serviceId) && Boolean(seen.add(service.serviceId)));
    },

    async readVariables(service): Promise<RawVariable[]> {
      const vars = record((await call('GET', `${appPath(service)}/config-vars`)).data);
      return Object.entries(vars).map(([name, value]) => {
        if (typeof value !== 'string') return invalidResponse();
        return { name, value, sealed: false };
      });
    },

    async writeVariables(service, vars, opts) {
      const updates = Object.entries(vars);
      if (updates.some(([name]) => !CONFIG_KEY.test(name))) throw new Error('Heroku config var name is invalid');
      if (updates.length === 0) return;
      // Add-on providers own their config vars and may replace them at any time; rotate those through the add-on.
      const managed = await addonConfigVars(service);
      if (updates.some(([name]) => managed.has(name))) {
        throw new Error('Heroku add-on config vars are managed by the add-on; rotate them through the add-on');
      }
      if (opts.skipDeploy) {
        log.info('Heroku applies config var changes with a new release and a dyno restart; it cannot stage them.', { app: service.serviceName });
      }
      // One PATCH upserts only these keys; keys not in the body are untouched, and null (delete) is never sent.
      await call('PATCH', `${appPath(service)}/config-vars`, { body: Object.fromEntries(updates) });
      writtenReleases.delete(service.serviceId);
      try {
        const created = await newestRelease(service);
        if (created !== null) writtenReleases.set(service.serviceId, created.id);
      } catch {
        // The config change is already applied; redeploy() falls back to the newest release.
        log.warn('Heroku release lookup failed after the config update; status will use the newest release.', { app: service.serviceName });
      }
    },

    async redeploy(service) {
      const written = writtenReleases.get(service.serviceId);
      if (written !== undefined) {
        writtenReleases.delete(service.serviceId);
        return written;
      }
      // No write by this adapter instance (for example after a restart): the newest release carries the current config.
      const newest = await newestRelease(service);
      if (newest === null) {
        log.warn('Heroku app has no releases; activation unconfirmed.', { app: service.serviceName });
        return null;
      }
      return newest.id;
    },

    async deploymentStatus(service, deploymentId): Promise<DeployState> {
      const release = record((await call('GET', `${appPath(service)}/releases/${segment(deploymentId)}`)).data);
      const status = nonemptyString(release.status);
      // A succeeded release that is no longer current was replaced (possibly by a rollback); fail closed.
      if (status === 'succeeded') return release.current === true ? 'success' : 'failed';
      if (status === 'failed' || status === 'expired') return 'failed';
      return 'pending';
    },
  };
}
