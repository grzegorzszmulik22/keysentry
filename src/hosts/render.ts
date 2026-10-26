import type { DeployState, HostAdapter, HttpClient, HttpRequest, Logger, RawVariable, ServiceRef } from '../types.js';
import { requestJson } from './http.js';

export interface RenderHostOptions {
  apiKey: string;
  http: HttpClient;
  log: Logger;
}

const BASE_URL = 'https://api.render.com/v1';
const FAILED_DEPLOY_STATES = new Set([
  'build_failed', 'update_failed', 'canceled', 'pre_deploy_failed', 'deactivated',
]);

function invalidResponse(): never {
  throw new Error('Render returned an invalid response');
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalidResponse();
  return value as Record<string, unknown>;
}

function nonemptyString(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) invalidResponse();
  return value;
}

export function createRenderHost({ apiKey, http, log }: RenderHostOptions): HostAdapter {
  async function request(method: HttpRequest['method'], path: string, body?: Record<string, unknown>): Promise<unknown> {
    const headers: Record<string, string> = { Authorization: `Bearer ${apiKey}` };
    const req: HttpRequest = { method, url: `${BASE_URL}${path}`, headers };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      req.body = JSON.stringify(body);
    }
    return requestJson<unknown>(http, 'Render', req);
  }

  async function readPages<T>(path: string, parseItem: (item: Record<string, unknown>) => T): Promise<T[]> {
    const result: T[] = [];
    const seenCursors = new Set<string>();
    let cursor: string | undefined;
    for (;;) {
      const query = `?limit=100${cursor === undefined ? '' : `&cursor=${encodeURIComponent(cursor)}`}`;
      const page = await request('GET', `${path}${query}`);
      if (!Array.isArray(page)) invalidResponse();
      if (page.length === 0) return result;
      const items = page.map(record);
      result.push(...items.map(parseItem));
      cursor = nonemptyString(items[items.length - 1]?.cursor);
      if (seenCursors.has(cursor)) throw new Error('Render pagination did not advance');
      seenCursors.add(cursor);
    }
  }

  const servicePath = (service: ServiceRef) => `/services/${encodeURIComponent(service.serviceId)}`;

  return {
    id: 'render',
    capabilities: { readValues: true, batchWrite: false, redeploy: true },

    listServices(): Promise<ServiceRef[]> {
      return readPages('/services', (item) => {
        const service = record(item.service);
        const id = nonemptyString(service.id);
        const name = nonemptyString(service.name);
        return {
          host: 'render', projectId: id, projectName: name, serviceId: id, serviceName: name,
          environmentId: '', environmentName: '',
        };
      });
    },

    readVariables(service): Promise<RawVariable[]> {
      return readPages(`${servicePath(service)}/env-vars`, (item) => {
        const envVar = record(item.envVar);
        const name = nonemptyString(envVar.key);
        if (typeof envVar.value !== 'string') invalidResponse();
        return { name, value: envVar.value, sealed: false };
      });
    },

    async writeVariables(service, vars, _opts): Promise<void> {
      // Render's per-key updates do not deploy, regardless of skipDeploy. Never use the full-set PUT.
      const updates = Object.entries(vars);
      // Empty or dot segments can normalize to a different endpoint, including the full-set endpoint.
      if (updates.some(([name]) => name === '' || name === '.' || name === '..')) {
        throw new Error('Render variable name is invalid');
      }
      for (const [name, value] of updates) {
        await request('PUT', `${servicePath(service)}/env-vars/${encodeURIComponent(name)}`, { value });
      }
    },

    async redeploy(service): Promise<string> {
      const path = `${servicePath(service)}/deploys`;
      const liveDeployments = await request('GET', `${path}?limit=1&status=live`);
      if (!Array.isArray(liveDeployments)) invalidResponse();
      const body: Record<string, unknown> = { clearCache: 'do_not_clear' };
      if (liveDeployments.length > 0) {
        const liveDeployment = record(record(liveDeployments[0]).deploy);
        if (liveDeployment.commit === undefined || liveDeployment.commit === null) {
          // Image-backed live deployments have no commit; use Render's plain deploy request.
          // Still require a deployment identity so a malformed empty envelope fails closed.
          nonemptyString(liveDeployment.id);
        } else {
          // Reuse live Git code so rotating a secret cannot publish newer branch commits.
          body.commitId = nonemptyString(record(liveDeployment.commit).id);
        }
      } else {
        log.warn('Render has no live deployment; starting an unpinned deployment of the latest branch commit.');
      }
      const deployment = record(await request('POST', path, body));
      return nonemptyString(deployment.id);
    },

    async deploymentStatus(service, deploymentId): Promise<DeployState> {
      const deployment = record(await request('GET', `${servicePath(service)}/deploys/${encodeURIComponent(deploymentId)}`));
      const status = nonemptyString(deployment.status);
      if (status === 'live') return 'success';
      return FAILED_DEPLOY_STATES.has(status) ? 'failed' : 'pending';
    },
  };
}
