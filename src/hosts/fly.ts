import type { DeployState, HostAdapter, HttpClient, HttpRequest, HttpResponse, Logger, ServiceRef } from '../types.js';
import { requestJson } from './http.js';

export interface FlyHostOptions {
  token: string;
  org?: string;
  apps?: string[];
  http: HttpClient;
  log: Logger;
}

const GRAPHQL_URL = 'https://api.fly.io/graphql';
const MACHINES_URL = 'https://api.machines.dev/v1/apps';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

interface Machine {
  id: string;
  version: string;
  state: string;
  config: Record<string, unknown>;
}

interface DeployedMachine {
  id: string;
  version: string;
  wasRunning: boolean;
}

// Like requestJson's errors, retain only local text and the HTTP status, never
// response bodies, transport diagnostics, request headers, or exception causes.
class FlyApiError extends Error {
  constructor(readonly status?: number, readonly timedOut = false) {
    super(status === undefined ? 'Fly request failed' : `Fly request failed (HTTP ${status})`);
    this.name = 'FlyApiError';
  }
}

function nonempty(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function pathSegment(value: string): string {
  if (!nonempty(value) || value === '.' || value === '..') throw new Error('Fly identifier is invalid');
  return encodeURIComponent(value);
}

function parseResponse(response: HttpResponse): unknown {
  if (!response.text.trim()) return undefined;
  try { return response.json<unknown>(); }
  catch { throw new Error('Fly returned invalid JSON'); }
}

function decodeDeployment(id: string, app: string): DeployedMachine[] {
  let value: unknown;
  try {
    if (id.length > 1024 * 1024 || !/^[A-Za-z0-9_-]+$/.test(id)) throw new Error();
    value = JSON.parse(Buffer.from(id, 'base64url').toString('utf8'));
  } catch { throw new Error('Fly deployment id is invalid'); }
  if (!isRecord(value) || value.app !== app || !Array.isArray(value.machines) || value.machines.length === 0) {
    throw new Error('Fly deployment id does not match the requested app');
  }
  const seen = new Set<string>();
  return value.machines.map((machine: unknown) => {
    if (!isRecord(machine) || !nonempty(machine.id) || !nonempty(machine.version)
      || typeof machine.wasRunning !== 'boolean' || seen.has(machine.id)) {
      throw new Error('Fly deployment id is invalid');
    }
    pathSegment(machine.id);
    seen.add(machine.id);
    return { id: machine.id, version: machine.version, wasRunning: machine.wasRunning };
  });
}

function appService(name: string): ServiceRef {
  return {
    host: 'fly',
    // Both the Machines paths and GraphQL name lookup use the app name.
    projectId: name,
    projectName: name,
    serviceId: name,
    serviceName: name,
    environmentId: '',
    environmentName: '',
  };
}

export function createFlyHost(options: FlyHostOptions): HostAdapter {
  const { token, http } = options;
  const headers = { Authorization: token.startsWith('FlyV1 ') ? token : `Bearer ${token}`, 'Content-Type': 'application/json' };
  const secretVersions = new Map<string, number>();

  async function machinesRequest(method: HttpRequest['method'], path: string, body?: unknown, nonce?: string): Promise<HttpResponse> {
    let response: HttpResponse;
    try {
      response = await http.request({
        method, url: `${MACHINES_URL}/${path}`,
        headers: nonce === undefined ? headers : { ...headers, 'fly-machine-lease-nonce': nonce },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
    } catch (error) {
      const timedOut = error instanceof Error && (error.name === 'TimeoutError' || error.name === 'AbortError')
        || isRecord(error) && error.code === 'ETIMEDOUT';
      throw new FlyApiError(undefined, timedOut);
    }
    if (response.status < 200 || response.status >= 300) throw new FlyApiError(response.status);
    return response;
  }

  async function listMachines(app: string): Promise<Machine[]> {
    const machines: Machine[] = [];
    const ids = new Set<string>();
    const cursors = new Set<string>();
    let cursor: string | undefined;
    do {
      const path = `${pathSegment(app)}/machines${cursor === undefined ? '' : `?cursor=${encodeURIComponent(cursor)}`}`;
      // summary=true omits the config that must be preserved during updates.
      const response = await machinesRequest('GET', path);
      const page = parseResponse(response);
      if (!Array.isArray(page)) throw new Error('Fly returned an invalid machine list');
      for (const machine of page) {
        if (!isRecord(machine) || !nonempty(machine.id) || !nonempty(machine.version)
          || !nonempty(machine.state) || !isRecord(machine.config) || ids.has(machine.id)) {
          throw new Error('Fly returned an invalid machine list');
        }
        pathSegment(machine.id);
        if (machine.state === 'failed' || machine.state === 'destroyed') throw new Error('Fly machine is unavailable for update');
        ids.add(machine.id);
        machines.push({ id: machine.id, version: machine.version, state: machine.state, config: machine.config });
      }
      cursor = Object.entries(response.headers).find(([name]) => name.toLowerCase() === 'fly-next-cursor')?.[1];
      if (cursor === '') cursor = undefined;
      if (cursor !== undefined) {
        if (cursors.has(cursor)) throw new Error('Fly returned a repeated machine cursor');
        cursors.add(cursor);
      }
    } while (cursor !== undefined);
    return machines.sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  }

  async function machineStatus(app: string, machine: DeployedMachine): Promise<DeployState> {
    const path = `${pathSegment(app)}/machines/${pathSegment(machine.id)}`;
    let response: HttpResponse;
    try {
      response = await machinesRequest('GET', machine.wasRunning
        // Fly blocks for at most the given seconds; stay under the HTTP client's 30 s timeout.
        ? `${path}/wait?state=started&version=${encodeURIComponent(machine.version)}&timeout=25`
        : path);
    } catch (error) {
      if (error instanceof FlyApiError) {
        if (error.status === 409) return 'failed';
        if (error.timedOut || error.status === 408 || error.status === 504) return 'pending';
      }
      throw error;
    }
    const status = parseResponse(response);
    if (!isRecord(status)) throw new Error('Fly returned an invalid machine status');
    if (status.state === 'failed' || status.state === 'destroyed') return 'failed';
    if (!nonempty(status.state) || status.version !== machine.version) return 'pending';
    if (machine.wasRunning) return status.ok === true && status.state === 'started' ? 'success' : 'pending';
    return status.id === machine.id ? 'success' : 'pending';
  }

  async function graphql(query: string, variables: Record<string, unknown>): Promise<Record<string, unknown>> {
    const response = await requestJson<unknown>(http, 'Fly', {
      method: 'POST',
      url: GRAPHQL_URL,
      headers,
      body: JSON.stringify({ query, variables }),
    });
    if (!isRecord(response)) throw new Error('Fly returned an invalid GraphQL response');
    if (response.errors !== undefined && (!Array.isArray(response.errors) || response.errors.length > 0)) {
      // Upstream messages can echo request variables, including secret values.
      throw new Error('Fly GraphQL request failed');
    }
    if (!isRecord(response.data)) throw new Error('Fly returned an incomplete GraphQL response');
    return response.data;
  }

  return {
    id: 'fly',
    capabilities: { readValues: false, batchWrite: true, redeploy: true },

    async listServices() {
      if (options.apps !== undefined) {
        if (options.apps.some((name) => !name.trim())) throw new Error('Fly configured apps must have names');
        return [...new Set(options.apps)].map(appService);
      }
      // The Machines listing requires an organization. Avoid silently scanning
      // an arbitrary organization when neither selector was configured.
      if (!options.org?.trim()) throw new Error('Fly requires an organization or configured apps for discovery');
      const url = new URL(MACHINES_URL);
      url.searchParams.set('org_slug', options.org);
      const response = await requestJson<unknown>(http, 'Fly', { method: 'GET', url: url.toString(), headers });
      if (!isRecord(response) || !Array.isArray(response.apps)) throw new Error('Fly returned an invalid app list');
      const names: string[] = [];
      for (const app of response.apps) {
        if (!isRecord(app) || typeof app.name !== 'string' || !app.name.trim()) {
          throw new Error('Fly returned an invalid app list');
        }
        names.push(app.name);
      }
      return [...new Set(names)].map(appService);
    },

    async readVariables(service) {
      const data = await graphql(
        'query($name:String!){ app(name:$name){ secrets { name digest createdAt } } }',
        { name: service.serviceId },
      );
      if (!isRecord(data.app) || !Array.isArray(data.app.secrets)) {
        throw new Error('Fly returned an incomplete secret list');
      }
      return data.app.secrets.map((secret) => {
        if (!isRecord(secret) || typeof secret.name !== 'string' || !secret.name) {
          throw new Error('Fly returned an invalid secret list');
        }
        return { name: secret.name, sealed: true };
      });
    },

    async writeVariables(service, vars, _opts) {
      if (Object.keys(vars).length === 0) return;
      const app = service.serviceId;
      const data = parseResponse(await machinesRequest('POST', `${pathSegment(app)}/secrets`, { values: vars }));
      if (data !== undefined && !isRecord(data)) throw new Error('Fly returned an invalid secrets response');
      if (data?.version === undefined) {
        // Do not reuse a stale version after a later successful write omitted it.
        // Fly looks up the current app secrets version when the update omits it.
        secretVersions.delete(app);
      } else {
        if (typeof data.version !== 'number' || !Number.isSafeInteger(data.version) || data.version < 0) {
          throw new Error('Fly returned an invalid secrets version');
        }
        secretVersions.set(app, data.version);
      }
    },

    async redeploy(service) {
      const app = service.serviceId;
      const machines = await listMachines(app);
      if (machines.length === 0) return null;
      const version = secretVersions.get(app);
      const deployed: DeployedMachine[] = [];
      for (const machine of machines) {
        const path = `${pathSegment(app)}/machines/${pathSegment(machine.id)}`;
        const lease = parseResponse(await machinesRequest('POST', `${path}/lease`, {
          ttl: 120, description: 'keysentry secrets update',
        }));
        if (!isRecord(lease) || !nonempty(lease.nonce)) throw new Error('Fly returned an invalid machine lease');
        const wasRunning = machine.state !== 'stopped' && machine.state !== 'suspended';
        let updated: DeployedMachine;
        let updateFailed = false;
        try {
          const result = parseResponse(await machinesRequest('POST', path, {
            config: machine.config,
            ...(version === undefined ? {} : { min_secrets_version: version }),
            current_version: machine.version, skip_launch: !wasRunning,
          }, lease.nonce));
          if (!isRecord(result) || result.id !== machine.id || !nonempty(result.version) || result.version === machine.version) {
            throw new Error('Fly returned an invalid machine update');
          }
          updated = { id: machine.id, version: result.version, wasRunning };
        } catch (error) {
          updateFailed = true;
          throw error;
        } finally {
          try { await machinesRequest('DELETE', `${path}/lease`, undefined, lease.nonce); }
          catch (error) { if (!updateFailed) throw error; }
        }
        deployed.push(updated);
        if (wasRunning) {
          const status = await machineStatus(app, updated);
          if (status !== 'success') throw new Error(status === 'failed'
            ? 'Fly machine deployment failed' : 'Fly machine deployment is not confirmed');
        }
      }
      return Buffer.from(JSON.stringify({ app, machines: deployed })).toString('base64url');
    },

    async deploymentStatus(service, deploymentId) {
      const machines = decodeDeployment(deploymentId, service.serviceId);
      let pending = false;
      for (const machine of machines) {
        const status = await machineStatus(service.serviceId, machine);
        if (status === 'failed') return 'failed';
        if (status === 'pending') pending = true;
      }
      return pending ? 'pending' : 'success';
    },
  };
}
