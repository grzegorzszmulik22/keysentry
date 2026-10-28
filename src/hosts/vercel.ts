import type { HostAdapter, HttpClient, HttpRequest, Logger, RawVariable, ServiceRef } from '../types.js';
import { requestJson } from './http.js';

export interface VercelHostOptions {
  token: string;
  teamId?: string;
  targets?: ('production' | 'preview' | 'development')[];
  http: HttpClient;
  log: Logger;
}

interface EnvironmentEntry {
  id: string;
  key: string;
  type: string;
  visibility?: string;
  target: string[];
}

function invalidResponse(): never {
  // Upstream payloads can contain plaintext secrets; never include them in diagnostics.
  throw new Error('Vercel returned an invalid response');
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return invalidResponse();
  return value as Record<string, unknown>;
}

function identifier(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) return invalidResponse();
  return value;
}

function nextCursor(page: Record<string, unknown>): string | undefined {
  if (page.pagination == null) return undefined;
  const next = object(page.pagination).next;
  if (next == null) return undefined;
  if (typeof next === 'string' && next.length > 0) return next;
  if (typeof next === 'number' && Number.isFinite(next)) return String(next);
  return invalidResponse();
}

function environment(value: unknown): EnvironmentEntry {
  const entry = object(value);
  if (!Array.isArray(entry.target) || !entry.target.every((target) => typeof target === 'string')) return invalidResponse();
  if (entry.visibility !== undefined && typeof entry.visibility !== 'string') return invalidResponse();
  return {
    id: identifier(entry.id),
    key: identifier(entry.key),
    type: identifier(entry.type),
    visibility: entry.visibility as string | undefined,
    target: entry.target as string[],
  };
}

function ambiguousKeys(entries: EnvironmentEntry[]): Set<string> {
  const keys = new Set<string>();
  const ambiguous = new Set<string>();
  for (const entry of entries) {
    // Branch-specific duplicates cannot be represented by the shared ServiceRef contract.
    if (keys.has(entry.key)) ambiguous.add(entry.key);
    keys.add(entry.key);
  }
  return ambiguous;
}

export function createVercelHost(opts: VercelHostOptions): HostAdapter {
  const targets = [...new Set(opts.targets ?? ['production', 'preview'])];

  async function request(method: HttpRequest['method'], path: string, query: Record<string, string> = {}, body?: unknown): Promise<unknown> {
    const url = new URL(path, 'https://api.vercel.com');
    for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
    if (opts.teamId !== undefined) url.searchParams.set('teamId', opts.teamId);
    return requestJson<unknown>(opts.http, 'Vercel', {
      method,
      url: url.toString(),
      headers: {
        Authorization: `Bearer ${opts.token}`,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  }

  async function pages(path: string, field: string, query: Record<string, string> = {}): Promise<unknown[]> {
    const entries: unknown[] = [];
    const visited = new Set<string>();
    let until: string | undefined;
    do {
      const page = object(await request('GET', path, { ...query, ...(until === undefined ? {} : { until }) }));
      const items = page[field];
      if (!Array.isArray(items)) return invalidResponse();
      entries.push(...items);
      until = nextCursor(page);
      if (until !== undefined) {
        if (visited.has(until)) throw new Error('Vercel returned repeated pagination cursor');
        visited.add(until);
      }
    } while (until !== undefined);
    return entries;
  }

  async function environments(service: ServiceRef): Promise<EnvironmentEntry[]> {
    const entries = await pages(`/v10/projects/${encodeURIComponent(service.projectId)}/env`, 'envs');
    return entries.map(environment);
  }

  function pinnedProduction(service: ServiceRef): null {
    opts.log.warn('Vercel production is pinned by an Instant Rollback; activation unconfirmed', {
      projectId: service.projectId,
    });
    return null;
  }

  return {
    id: 'vercel',
    capabilities: { readValues: true, batchWrite: false, redeploy: true },
    // Only production is redeployed; preview and development values apply on their next deployment.
    activationFor: service => service.environmentId === 'production' ? 'redeploy' : 'manual',

    async listServices() {
      const projects = await pages('/v10/projects', 'projects', { limit: '100' });
      return projects.flatMap((value): ServiceRef[] => {
        const project = object(value);
        const id = identifier(project.id);
        const name = identifier(project.name);
        return targets.map((target) => ({
          host: 'vercel',
          projectId: id,
          projectName: name,
          serviceId: id,
          serviceName: name,
          environmentId: target,
          environmentName: target,
        }));
      });
    },

    async readVariables(service) {
      const entries = (await environments(service)).filter((entry) => entry.type !== 'system' && entry.target.includes(service.environmentId));
      const ambiguous = ambiguousKeys(entries);
      if (ambiguous.size > 0) {
        opts.log.warn('Vercel sealed ambiguous variables for this target; update branch overrides in Vercel', {
          projectId: service.projectId, target: service.environmentId, keys: [...ambiguous],
        });
      }
      const variables: RawVariable[] = [];
      const emittedAmbiguous = new Set<string>();
      for (const entry of entries) {
        if (ambiguous.has(entry.key)) {
          if (!emittedAmbiguous.has(entry.key)) variables.push({ name: entry.key, sealed: true });
          emittedAmbiguous.add(entry.key);
          continue;
        }
        if (entry.type === 'sensitive' || entry.type === 'secret' || entry.visibility === 'secret') {
          variables.push({ name: entry.key, sealed: true });
          continue;
        }
        const detail = object(await request('GET', `/v1/projects/${encodeURIComponent(service.projectId)}/env/${encodeURIComponent(entry.id)}`));
        if (!Object.hasOwn(detail, 'value')) {
          variables.push({ name: entry.key, sealed: true });
          continue;
        }
        if (typeof detail.value !== 'string') return invalidResponse();
        variables.push({ name: entry.key, value: detail.value, sealed: false });
      }
      return variables;
    },

    async writeVariables(service, vars, _writeOptions) {
      const changes = Object.entries(vars);
      if (changes.length === 0) return;
      const requestedKeys = new Set(changes.map(([key]) => key));
      const allEntries = await environments(service);
      if (allEntries.some((entry) => entry.type === 'system' && requestedKeys.has(entry.key))) {
        throw new Error('Vercel system variables are managed and cannot be changed');
      }
      const entries = allEntries.filter((entry) => requestedKeys.has(entry.key) && entry.target.includes(service.environmentId));
      const ambiguous = ambiguousKeys(entries);
      if (ambiguous.size > 0) {
        throw new Error(`Vercel cannot write ambiguous variable ${[...ambiguous][0]} for target ${service.environmentId}; update branch overrides in Vercel`);
      }
      for (const [key, value] of changes) {
        const existing = entries.find((entry) => entry.key === key);
        if (existing !== undefined) {
          // A shared entry can cover several targets; the contract permits updating that same secret in all of them.
          await request('PATCH', `/v9/projects/${encodeURIComponent(service.projectId)}/env/${encodeURIComponent(existing.id)}`, {}, { value });
        } else {
          await request('POST', `/v10/projects/${encodeURIComponent(service.projectId)}/env`, { upsert: 'true' }, {
            key, value, type: 'encrypted', target: [service.environmentId],
          });
        }
      }
      // Vercel environment writes never deploy, regardless of skipDeploy.
    },

    async redeploy(service) {
      if (service.environmentId !== 'production') return null;
      const project = object(await request('GET', `/v9/projects/${encodeURIComponent(service.projectId)}`));
      const production = project.targets == null ? undefined : object(project.targets).production;
      const servingId = production == null ? undefined : object(production).id;
      const previousId = servingId == null ? undefined : identifier(servingId);
      // These project fields are treated conservatively as rollback markers. A
      // redeployment reaching READY does not prove pinned domains switched to it.
      if (project.rollbackDescription || project.lastRollbackTarget) return pinnedProduction(service);
      const response = object(await request('GET', '/v6/deployments', {
        projectId: service.projectId, target: 'production', state: 'READY', limit: '1',
      }));
      if (!Array.isArray(response.deployments)) return invalidResponse();
      if (response.deployments.length === 0) throw new Error('Vercel has no ready production deployment to redeploy');
      const latestId = identifier(object(response.deployments[0]).uid);
      // The list is newest-first. A different serving target may be an Instant
      // Rollback; fail closed even if the response does not supply its metadata.
      if (previousId !== undefined && previousId !== latestId) return pinnedProduction(service);
      if (previousId === undefined) {
        opts.log.warn('Vercel serving production deployment is unavailable; falling back to the latest READY production deployment, which may undo a rollback', {
          projectId: service.projectId,
        });
      }
      const deployment = object(await request('POST', '/v13/deployments', { forceNew: '1' }, {
        name: service.projectName, deploymentId: previousId ?? latestId, target: 'production',
      }));
      return identifier(deployment.id);
    },

    async deploymentStatus(_service, deploymentId) {
      const deployment = object(await request('GET', `/v13/deployments/${encodeURIComponent(deploymentId)}`));
      const state = identifier(deployment.readyState);
      if (state === 'READY') return 'success';
      if (state === 'ERROR' || state === 'CANCELED') return 'failed';
      return 'pending';
    },
  };
}
