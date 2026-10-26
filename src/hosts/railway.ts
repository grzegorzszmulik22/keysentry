import type { HostAdapter, HttpClient, Logger, RawVariable, ServiceRef } from '../types.js';

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
const latestDeploymentQuery = `query KeysentryLatestDeployment($projectId: String!, $serviceId: String!, $environmentId: String!) {
  deployments(first: 1, input: { projectId: $projectId, serviceId: $serviceId, environmentId: $environmentId }) {
    edges { node { id status } }
  }
}`;
const redeployMutation = `mutation KeysentryRedeploy($id: String!) {
  deploymentRedeploy(id: $id) { id status }
}`;
const triggerDeployMutation = `mutation KeysentryTriggerDeploy($environmentId: String!, $projectId: String!, $serviceId: String!) {
  environmentTriggersDeploy(input: { environmentId: $environmentId, projectId: $projectId, serviceId: $serviceId })
}`;
const legacyDeployMutation = `mutation KeysentryDeploy($serviceId: String!, $environmentId: String!) {
  serviceInstanceDeployV2(serviceId: $serviceId, environmentId: $environmentId)
}`;
const deploymentQuery = `query KeysentryDeployment($id: String!) {
  deployment(id: $id) { status }
}`;

type Data = Record<string, unknown>;
interface NamedEntity { id: string; name: string }

// Only a sanitized marker escapes GraphQL parsing; upstream diagnostics may contain secrets.
class RailwaySchemaError extends Error {}

function isSchemaError(value: unknown): boolean {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const { extensions, message } = value as Data;
  if (extensions !== null && typeof extensions === 'object' && !Array.isArray(extensions)) {
    const { code } = extensions as Data;
    if (typeof code === 'string') return code === 'GRAPHQL_VALIDATION_FAILED';
  }
  // Some GraphQL servers omit extensions.code on standard schema validation failures.
  return typeof message === 'string' && (
    /^Cannot query field "[^"]+" on type "[^"]+"\./.test(message)
    || /^Unknown argument "[^"]+" on field "[^"]+"\./.test(message)
    || /^Unknown type "[^"]+"\./.test(message)
    || /^Field "[^"]+" is not defined by type "[^"]+"\./.test(message)
    || /^Variable "\$[^"]+" of type "[^"]+" used in position expecting type "[^"]+"\./.test(message)
    || /^Field "[^"]+" argument "[^"]+" of type "[^"]+" is required, but it was not provided\./.test(message)
    || /^Field "[^"]+" of required type "[^"]+" was not provided\./.test(message)
  );
}

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
    const response = await http.request({
      method: 'POST', url: endpoint, headers, body: JSON.stringify({ query, variables }),
    }).catch(() => { throw new Error('Railway request failed'); });
    const ok = response.status >= 200 && response.status < 300;
    const httpError = () => new Error(`Railway request failed (HTTP ${response.status})`);
    // Validation can use HTTP 400. Inspect that body for schema errors without treating other HTTP failures as retryable.
    if (!ok && response.status !== 400) throw httpError();
    let payload: unknown;
    try {
      payload = response.text.trim() ? response.json<unknown>() : undefined;
    } catch {
      throw ok ? new Error('Railway returned invalid JSON') : httpError();
    }
    const data = object(payload);
    // An upstream GraphQL message can echo credentials or submitted variable values.
    // Reject partial data too, and never expose the upstream message or extensions.
    if ('errors' in data && (!Array.isArray(data.errors) || data.errors.length > 0)) {
      if (Array.isArray(data.errors) && data.errors.length > 0 && data.errors.every(isSchemaError)) {
        throw new RailwaySchemaError('Railway GraphQL request failed');
      }
      if (!ok) throw httpError();
      throw new Error('Railway GraphQL request failed');
    }
    if (!ok) throw httpError();
    return object(data.data);
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
        if (value === null || value === undefined) variables.push({ name, sealed: true });
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
      const scope = { projectId: service.projectId, serviceId: service.serviceId, environmentId: service.environmentId };
      let latest: Data;
      try {
        latest = await graphql(latestDeploymentQuery, scope);
      } catch (error) {
        if (!(error instanceof RailwaySchemaError)) throw error;
        // This compatibility path is limited to a failed read, so a failed deploy can never cause a second deploy.
        const data = await graphql(legacyDeployMutation, { serviceId: service.serviceId, environmentId: service.environmentId });
        return nonemptyString(data.serviceInstanceDeployV2);
      }
      const { edges } = object(latest.deployments);
      if (!Array.isArray(edges)) throw new Error('Railway returned an invalid response');
      if (edges.length > 0) {
        const id = nonemptyString(object(object(edges[0]).node).id);
        const data = await graphql(redeployMutation, { id });
        return nonemptyString(object(data.deploymentRedeploy).id);
      }
      const data = await graphql(triggerDeployMutation, scope);
      if (data.environmentTriggersDeploy !== true) throw new Error('Railway deployment trigger failed');
      options.log.warn('Railway deployment triggered without a deployment ID; status polling is unavailable.');
      return null;
    },
    async deploymentStatus(_service, deploymentId) {
      const data = await graphql(deploymentQuery, { id: deploymentId });
      const status = nonemptyString(object(data.deployment).status);
      if (status === 'SUCCESS' || status === 'SLEEPING') return 'success';
      if (status === 'FAILED' || status === 'CRASHED' || status === 'REMOVED' || status === 'SKIPPED') return 'failed';
      return 'pending';
    },
  };
}
