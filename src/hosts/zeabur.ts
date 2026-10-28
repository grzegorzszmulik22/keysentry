import type { DeployState, HostAdapter, HttpClient, Logger, RawVariable, ServiceRef } from '../types.js';
import { requestJson } from './http.js';

export interface ZeaburHostOptions {
  /** Personal API key (Dashboard > Settings > API Keys), sent as `Authorization: Bearer`. */
  token: string;
  /** Team id whose projects to scan; omit for the personal account. Not a secret. */
  ownerId?: string;
  /** Limit the scan to these project ids. */
  projectIds?: string[];
  http: HttpClient;
  log: Logger;
}

type Data = Record<string, unknown>;

const ENDPOINT = 'https://api.zeabur.com/graphql';
const PAGE_SIZE = 100;
const MAX_PAGES = 1000;
/** Zeabur ids are ObjectIDs (24 hex characters); accept any plain token so a format change does not break scans. */
const OBJECT_ID = /^[A-Za-z0-9_-]{1,64}$/;

// Every operation is a constant document; ids and values travel only in `variables`.
const projectsQuery = `query KeysentryProjects($skip: Int!, $limit: Int!) {
  projects(skip: $skip, limit: $limit) { edges { node { _id name } } pageInfo { hasNextPage } }
}`;
const ownerProjectsQuery = `query KeysentryOwnerProjects($ownerID: ObjectID!, $skip: Int!, $limit: Int!) {
  projects(ownerID: $ownerID, skip: $skip, limit: $limit) { edges { node { _id name } } pageInfo { hasNextPage } }
}`;
const projectQuery = `query KeysentryProject($id: ObjectID!) {
  project(_id: $id) { _id name }
}`;
const environmentsQuery = `query KeysentryEnvironments($projectID: ObjectID!) {
  environments(projectID: $projectID) { _id name }
}`;
const servicesQuery = `query KeysentryServices($projectID: ObjectID!, $skip: Int!, $limit: Int!) {
  services(projectID: $projectID, skip: $skip, limit: $limit) { edges { node { _id name } } pageInfo { hasNextPage } }
}`;
const variablesQuery = `query KeysentryVariables($serviceID: ObjectID!, $environmentID: ObjectID!) {
  service(_id: $serviceID) { variables(environmentID: $environmentID, exposed: true) { key value serviceID } }
}`;
const updateVariablesMutation = `mutation KeysentryUpdateVariables($serviceID: ObjectID!, $environmentID: ObjectID!, $data: Map!) {
  updateEnvironmentVariable(serviceID: $serviceID, environmentID: $environmentID, data: $data)
}`;
const restartMutation = `mutation KeysentryRestart($serviceID: ObjectID!, $environmentID: ObjectID!) {
  restartService(serviceID: $serviceID, environmentID: $environmentID)
}`;

interface Named { id: string; name: string }

function invalidResponse(): never {
  // Upstream payloads can contain plaintext values; never echo them.
  throw new Error('Zeabur returned an invalid response');
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

function named(value: unknown): Named {
  const item = record(value);
  const id = nonempty(item._id);
  if (!OBJECT_ID.test(id)) return invalidResponse();
  return { id, name: nonempty(item.name) };
}

function objectId(value: string, what: string): string {
  if (typeof value !== 'string' || !OBJECT_ID.test(value)) throw new Error(`Zeabur ${what} is invalid`);
  return value;
}

export function createZeaburHost(opts: ZeaburHostOptions): HostAdapter {
  const { http, log } = opts;
  const ownerId = opts.ownerId === undefined ? undefined : objectId(opts.ownerId, 'owner id');
  const projectIds = opts.projectIds === undefined ? undefined : [...new Set(opts.projectIds.map((id) => objectId(id, 'project id')))];
  const headers = { Authorization: `Bearer ${opts.token}`, 'Content-Type': 'application/json' };

  async function graphql(query: string, variables: Data): Promise<Data> {
    const payload = record(await requestJson<unknown>(http, 'Zeabur', {
      method: 'POST', url: ENDPOINT, headers, body: JSON.stringify({ query, variables }),
    }));
    // GraphQL messages can echo submitted variables; partial data with errors is rejected too.
    if ('errors' in payload && (!Array.isArray(payload.errors) || payload.errors.length > 0)) {
      throw new Error('Zeabur GraphQL request failed');
    }
    return record(payload.data);
  }

  /** skip/limit pagination; stops when hasNextPage is false or a page adds nothing new. */
  async function connection(query: string, variables: Data, field: string): Promise<Named[]> {
    const items: Named[] = [];
    const seen = new Set<string>();
    for (let page = 0; page < MAX_PAGES; page++) {
      const result = record((await graphql(query, { ...variables, skip: page * PAGE_SIZE, limit: PAGE_SIZE }))[field]);
      let added = 0;
      for (const edge of list(result.edges)) {
        const node = named(record(edge).node);
        if (seen.has(node.id)) continue;
        seen.add(node.id);
        items.push(node);
        added += 1;
      }
      const hasNextPage = record(result.pageInfo).hasNextPage;
      if (typeof hasNextPage !== 'boolean') return invalidResponse();
      if (!hasNextPage || added === 0) return items;
    }
    throw new Error('Zeabur pagination did not finish');
  }

  function parts(service: ServiceRef): { serviceID: string; environmentID: string } {
    if (service.host !== 'zeabur' || !OBJECT_ID.test(service.serviceId) || !OBJECT_ID.test(service.environmentId)) {
      throw new Error('Zeabur service reference is invalid');
    }
    return { serviceID: service.serviceId, environmentID: service.environmentId };
  }

  /** The service's own variables. Variables exposed by other services are returned too and are excluded here. */
  async function ownVariables(service: ServiceRef): Promise<Map<string, string>> {
    const { serviceID, environmentID } = parts(service);
    const data = await graphql(variablesQuery, { serviceID, environmentID });
    const own = new Map<string, string>();
    for (const item of list(record(data.service).variables)) {
      const variable = record(item);
      const key = nonempty(variable.key);
      if (typeof variable.value !== 'string') return invalidResponse();
      if (nonempty(variable.serviceID) !== serviceID) continue;
      if (own.has(key)) return invalidResponse();
      own.set(key, variable.value);
    }
    return own;
  }

  async function projects(): Promise<Named[]> {
    if (projectIds !== undefined) {
      const found: Named[] = [];
      for (const id of projectIds) found.push(named((await graphql(projectQuery, { id })).project));
      return found;
    }
    return ownerId === undefined
      ? connection(projectsQuery, {}, 'projects')
      : connection(ownerProjectsQuery, { ownerID: ownerId }, 'projects');
  }

  return {
    id: 'zeabur',
    // updateEnvironmentVariable replaces the whole set in one call (read-modify-write here). Values need a
    // restart to apply; restartService returns no deployment id, so activation stays unconfirmed (null).
    // restartService returns no deployment id, so activation cannot be confirmed.
    capabilities: { readValues: true, batchWrite: true, redeploy: true, activation: 'manual' },

    async listServices() {
      const refs: ServiceRef[] = [];
      for (const project of await projects()) {
        const environments = list((await graphql(environmentsQuery, { projectID: project.id })).environments).map(named);
        const services = await connection(servicesQuery, { projectID: project.id }, 'services');
        for (const environment of environments) {
          for (const service of services) {
            refs.push({
              host: 'zeabur', projectId: project.id, projectName: project.name, serviceId: service.id, serviceName: service.name,
              environmentId: environment.id, environmentName: environment.name,
            });
          }
        }
      }
      return refs;
    },

    async readVariables(service): Promise<RawVariable[]> {
      return [...await ownVariables(service)].map(([name, value]) => ({ name, value, sealed: false }));
    },

    async writeVariables(service, vars, _writeOptions) {
      const { serviceID, environmentID } = parts(service);
      const changes = Object.entries(vars);
      if (changes.length === 0) return;
      if (changes.some(([name]) => name.length === 0)) throw new Error('Zeabur variable name is invalid');
      // The mutation replaces the service's whole variable set: send every current variable unchanged plus the
      // requested ones. Reference values such as ${PASSWORD} are sent back exactly as read.
      const before = await ownVariables(service);
      const data = Object.fromEntries(before);
      for (const [name, value] of changes) data[name] = value;
      const result = await graphql(updateVariablesMutation, { serviceID, environmentID, data });
      if (result.updateEnvironmentVariable !== true) throw new Error('Zeabur did not apply the variable update');
      // Read back: a concurrent edit between the read and the replace would otherwise go unnoticed.
      const after = await ownVariables(service);
      const expected = Object.entries(data);
      if (after.size !== expected.length || expected.some(([name, value]) => after.get(name) !== value)) {
        throw new Error('Zeabur variables changed beyond this update; check the service in Zeabur');
      }
      // Zeabur variable updates never deploy or restart, regardless of skipDeploy.
    },

    async redeploy(service) {
      const { serviceID, environmentID } = parts(service);
      const result = await graphql(restartMutation, { serviceID, environmentID });
      if (result.restartService !== true) throw new Error('Zeabur did not restart the service');
      log.warn('Zeabur restarted the service but reports no deployment id; activation unconfirmed', { service: service.serviceName });
      return null;
    },

    async deploymentStatus(service, _deploymentId): Promise<DeployState> {
      parts(service);
      throw new Error('Zeabur restarts have no deployment to track');
    },
  };
}
