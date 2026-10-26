import type { HostAdapter, HttpClient, Logger, RawVariable, ServiceRef } from '../types.js';
import { requestJson } from './http.js';

export interface RailwayHostOptions {
  token: string;
  tokenType?: 'account' | 'project';
  projectIds?: string[];
  http: HttpClient;
  log: Logger;
}

const endpoint = 'https://backboard.railway.com/graphql/v2';

const projectsQuery = `query KeysentryProjects($after: String) {
  projects(first: 100, after: $after) {
    edges { node { id name } }
    pageInfo { hasNextPage endCursor }
  }
}`;
const projectQuery = `query KeysentryProject($projectId: String!) {
  project(id: $projectId) { id name }
}`;
const environmentsQuery = `query KeysentryEnvironments($projectId: String!, $after: String) {
  project(id: $projectId) {
    environments(first: 100, after: $after) {
      edges { node { id name } }
      pageInfo { hasNextPage endCursor }
    }
  }
}`;
const servicesQuery = `query KeysentryServices($projectId: String!, $after: String) {
  project(id: $projectId) {
    services(first: 100, after: $after) {
      edges { node { id name } }
      pageInfo { hasNextPage endCursor }
    }
  }
}`;
const variablesQuery = `query KeysentryVariables($projectId: String!, $environmentId: String!, $serviceId: String) {
  variables(projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId, unrendered: true)
}`;
const upsertMutation = `mutation KeysentryVariablesUpsert($input: VariableCollectionUpsertInput!) {
  variableCollectionUpsert(input: $input)
}`;
const deployMutation = `mutation KeysentryDeploy($serviceId: String!, $environmentId: String!) {
  serviceInstanceDeployV2(serviceId: $serviceId, environmentId: $environmentId)
}`;
const deploymentQuery = `query KeysentryDeployment($id: String!) {
  deployment(id: $id) { status }
}`;

type Data = Record<string, unknown>;
interface NamedEntity { id: string; name: string }

function object(value: unknown): Data {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Railway returned an invalid response');
  }
  return value as Data;
}

function nonemptyString(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error('Railway returned an invalid response');
  }
  return value;
}

function namedEntity(value: unknown): NamedEntity {
  const entity = object(value);
  return { id: nonemptyString(entity.id), name: nonemptyString(entity.name) };
}

export function createRailwayHost(options: RailwayHostOptions): HostAdapter {
  const { token, http } = options;
  const configuredProjectIds = options.projectIds === undefined ? undefined : [...new Set(options.projectIds)];
  const headers: Record<string, string> = {
    ...(options.tokenType === 'project' ? { 'Project-Access-Token': token } : { Authorization: `Bearer ${token}` }),
    'Content-Type': 'application/json',
  };

  async function graphql(query: string, variables: Data = {}): Promise<Data> {
    const response = object(await requestJson<unknown>(http, 'Railway', {
      method: 'POST', url: endpoint, headers, body: JSON.stringify({ query, variables }),
    }));
    // An upstream GraphQL message can echo credentials or submitted variable values.
    // Reject partial data too, and never expose the upstream message or extensions.
    if ('errors' in response && (!Array.isArray(response.errors) || response.errors.length > 0)) {
      throw new Error('Railway GraphQL request failed');
    }
    return object(response.data);
  }

  async function listConnection(
    query: string,
    variables: Data,
    select: (data: Data) => unknown,
  ): Promise<NamedEntity[]> {
    const entities = new Map<string, NamedEntity>();
    const cursors = new Set<string>();
    let after: string | null = null;
    for (;;) {
      const page = object(select(await graphql(query, { ...variables, after })));
      if (!Array.isArray(page.edges)) throw new Error('Railway returned an invalid response');
      for (const edge of page.edges) {
        const entity = namedEntity(object(edge).node);
        entities.set(entity.id, entity);
      }
      const pageInfo = object(page.pageInfo);
      if (pageInfo.hasNextPage === false) return [...entities.values()];
      if (pageInfo.hasNextPage !== true) throw new Error('Railway returned invalid pagination data');
      const cursor = nonemptyString(pageInfo.endCursor);
      if (cursors.has(cursor)) throw new Error('Railway returned invalid pagination data');
      cursors.add(cursor);
      after = cursor;
    }
  }

  async function listProjects(): Promise<NamedEntity[]> {
    let ids = configuredProjectIds;
    if (ids === undefined && options.tokenType === 'project') {
      const data = await graphql('query KeysentryProjectToken { projectToken { projectId } }');
      ids = [nonemptyString(object(data.projectToken).projectId)];
    }
    if (ids === undefined) return listConnection(projectsQuery, {}, (data) => data.projects);
    const projects: NamedEntity[] = [];
    for (const projectId of ids) {
      const data = await graphql(projectQuery, { projectId });
      projects.push(namedEntity(data.project));
    }
    return projects;
  }

  function variableScope(service: ServiceRef): Data {
    // Shared variables belong to the environment, without a service UUID.
    return { projectId: service.projectId, environmentId: service.environmentId, serviceId: service.serviceId || null };
  }

  return {
    id: 'railway',
    capabilities: { readValues: true, batchWrite: true, redeploy: true },
    async listServices() {
      const services: ServiceRef[] = [];
      for (const project of await listProjects()) {
        const variables = { projectId: project.id };
        const environments = await listConnection(environmentsQuery, variables, (data) => object(data.project).environments);
        const projectServices = await listConnection(servicesQuery, variables, (data) => object(data.project).services);
        for (const environment of environments) {
          const base = {
            host: 'railway' as const, projectId: project.id, projectName: project.name,
            environmentId: environment.id, environmentName: environment.name,
          };
          services.push({ ...base, serviceId: '', serviceName: 'shared' });
          for (const service of projectServices) {
            services.push({ ...base, serviceId: service.id, serviceName: service.name });
          }
        }
      }
      return services;
    },
    async readVariables(service) {
      const data = await graphql(variablesQuery, variableScope(service));
      const variables: RawVariable[] = [];
      for (const [name, value] of Object.entries(object(data.variables))) {
        if (value === null || value === '') variables.push({ name, sealed: true });
        else if (typeof value === 'string') variables.push({ name, value, sealed: false });
        else throw new Error('Railway returned an invalid variable value');
      }
      return variables;
    },
    async writeVariables(service, vars, opts) {
      const data = await graphql(upsertMutation, { input: {
        ...variableScope(service), variables: vars, replace: false, skipDeploys: opts.skipDeploy,
      } });
      if (data.variableCollectionUpsert !== true) throw new Error('Railway variable update failed');
    },
    async redeploy(service) {
      if (service.serviceId === '') return null;
      const data = await graphql(deployMutation, { serviceId: service.serviceId, environmentId: service.environmentId });
      return nonemptyString(data.serviceInstanceDeployV2);
    },
    async deploymentStatus(_service, deploymentId) {
      const data = await graphql(deploymentQuery, { id: deploymentId });
      const status = nonemptyString(object(data.deployment).status);
      if (status === 'SUCCESS') return 'success';
      if (status === 'FAILED' || status === 'CRASHED' || status === 'REMOVED') return 'failed';
      return 'pending';
    },
  };
}
