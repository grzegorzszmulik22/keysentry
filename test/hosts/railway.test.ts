import { describe, expect, it } from 'vitest';
import { createRailwayHost } from '../../src/hosts/railway.js';
import type { HttpRequest, ServiceRef } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const endpoint = 'https://backboard.railway.com/graphql/v2';
const endpointPattern = /^https:\/\/backboard\.railway\.com\/graphql\/v2$/;
const token = 'railway-private-account-token';
const service: ServiceRef = {
  host: 'railway', projectId: 'p1', projectName: 'Project One',
  environmentId: 'e1', environmentName: 'production', serviceId: 's1', serviceName: 'api',
};
const shared: ServiceRef = { ...service, serviceId: '', serviceName: 'shared' };

function body(req: HttpRequest): { query: string; variables: Record<string, unknown> } {
  return JSON.parse(req.body ?? '{}');
}

function connection(nodes: { id: string; name: string }[], hasNextPage = false, endCursor: string | null = null) {
  return { edges: nodes.map((node) => ({ node })), pageInfo: { hasNextPage, endCursor } };
}

function queuedHttp(...responses: unknown[]): FakeHttp {
  const remaining = [...responses];
  return new FakeHttp().on('POST', endpointPattern, () => {
    if (remaining.length === 0) throw new Error('Unexpected extra Railway request');
    return json(200, remaining.shift());
  });
}

describe('Railway host', () => {
  it('paginates projects, environments and services and includes shared variables for every environment', async () => {
    const http = queuedHttp(
      { data: { projects: connection([{ id: 'p1', name: 'Project One' }], true, 'projects-next') } },
      { data: { projects: connection([{ id: 'p2', name: 'Project Two' }]) } },
      { data: { project: { environments: connection([{ id: 'e1', name: 'production' }], true, 'envs-next') } } },
      { data: { project: { environments: connection([{ id: 'e2', name: 'preview' }]) } } },
      { data: { project: { services: connection([{ id: 's1', name: 'api' }], true, 'services-next') } } },
      { data: { project: { services: connection([{ id: 's2', name: 'worker' }]) } } },
      { data: { project: { environments: connection([{ id: 'e3', name: 'production' }]) } } },
      { data: { project: { services: connection([]) } } },
    );
    const host = createRailwayHost({ token, http, log: silentLogger });

    expect(await host.listServices()).toEqual([
      shared,
      service,
      { ...service, serviceId: 's2', serviceName: 'worker' },
      { ...shared, environmentId: 'e2', environmentName: 'preview' },
      { ...service, environmentId: 'e2', environmentName: 'preview' },
      { ...service, environmentId: 'e2', environmentName: 'preview', serviceId: 's2', serviceName: 'worker' },
      { ...shared, projectId: 'p2', projectName: 'Project Two', environmentId: 'e3' },
    ]);
    expect(http.calls).toHaveLength(8);
    for (const req of http.calls) {
      expect(req.method).toBe('POST');
      expect(req.url).toBe(endpoint);
      expect(req.headers).toEqual({ Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' });
      expect(body(req).query).not.toContain(token);
      expect(body(req).query).toContain('first: 100');
      expect(body(req).query).toContain('pageInfo');
    }
    expect(http.calls.map((req) => body(req).variables)).toEqual([
      { after: null }, { after: 'projects-next' },
      { projectId: 'p1', after: null }, { projectId: 'p1', after: 'envs-next' },
      { projectId: 'p1', after: null }, { projectId: 'p1', after: 'services-next' },
      { projectId: 'p2', after: null }, { projectId: 'p2', after: null },
    ]);
  });

  it('limits discovery to unique configured project ids without listing account projects', async () => {
    const http = queuedHttp(
      { data: { project: { id: 'p1', name: 'Project One' } } },
      { data: { project: { environments: connection([{ id: 'e1', name: 'production' }]) } } },
      { data: { project: { services: connection([{ id: 's1', name: 'api' }]) } } },
    );
    const host = createRailwayHost({ token, projectIds: ['p1', 'p1'], http, log: silentLogger });

    expect(await host.listServices()).toEqual([shared, service]);
    expect(http.calls).toHaveLength(3);
    expect(body(http.calls[0]!).variables).toEqual({ projectId: 'p1' });
    expect(http.calls.every((req) => !body(req).query.includes('projects('))).toBe(true);
  });

  it('treats an empty configured project scope as empty without making requests', async () => {
    const http = new FakeHttp();
    const host = createRailwayHost({ token, projectIds: [], http, log: silentLogger });

    expect(await host.listServices()).toEqual([]);
    expect(http.calls).toHaveLength(0);
  });

  it('discovers project-token scope and sends the project token header exclusively', async () => {
    const http = queuedHttp(
      { data: { projectToken: { projectId: 'p1' } } },
      { data: { project: { id: 'p1', name: 'Project One' } } },
      { data: { project: { environments: connection([{ id: 'e1', name: 'production' }]) } } },
      { data: { project: { services: connection([{ id: 's1', name: 'api' }]) } } },
    );
    const host = createRailwayHost({ token, tokenType: 'project', http, log: silentLogger });

    expect(await host.listServices()).toEqual([shared, service]);
    expect(body(http.calls[0]!).query).toContain('projectToken');
    expect(body(http.calls[1]!).variables).toEqual({ projectId: 'p1' });
    for (const req of http.calls) {
      expect(req.headers).toEqual({ 'Project-Access-Token': token, 'Content-Type': 'application/json' });
    }
  });

  it('reads unrendered variables and preserves empty strings as readable values', async () => {
    const http = queuedHttp({ data: { variables: {
      API_KEY: 'private-value-kept-in-memory', DATABASE_URL: '${{Postgres.DATABASE_URL}}', SEALED: null, EMPTY: '',
    } } });
    const host = createRailwayHost({ token, http, log: silentLogger });

    expect(await host.readVariables(service)).toEqual([
      { name: 'API_KEY', value: 'private-value-kept-in-memory', sealed: false },
      { name: 'DATABASE_URL', value: '${{Postgres.DATABASE_URL}}', sealed: false },
      { name: 'SEALED', sealed: true }, { name: 'EMPTY', value: '', sealed: false },
    ]);
    expect(body(http.calls[0]!).query).toContain('unrendered: true');
    expect(body(http.calls[0]!).variables).toEqual({ projectId: 'p1', environmentId: 'e1', serviceId: 's1' });
  });

  it('marks an existing variable with an unavailable value as sealed', async () => {
    const http = new FakeHttp().on('POST', endpointPattern, () => ({
      ...json(200, {}),
      json: <T>() => ({ data: { variables: { UNAVAILABLE: undefined } } }) as T,
    }));
    const host = createRailwayHost({ token, http, log: silentLogger });

    expect(await host.readVariables(service)).toEqual([{ name: 'UNAVAILABLE', sealed: true }]);
  });

  it('uses null service scope for shared variables rather than an empty service id', async () => {
    const http = queuedHttp({ data: { variables: { SHARED_KEY: 'private-shared-value' } } });
    const host = createRailwayHost({ token, http, log: silentLogger });

    expect(await host.readVariables(shared)).toEqual([{ name: 'SHARED_KEY', value: 'private-shared-value', sealed: false }]);
    expect(body(http.calls[0]!).variables).toEqual({ projectId: 'p1', environmentId: 'e1', serviceId: null });
  });

  it.each([true, false])('always merges only the requested variables and forwards skipDeploy=%s', async (skipDeploy) => {
    const http = queuedHttp({ data: { variableCollectionUpsert: true } });
    const host = createRailwayHost({ token, http, log: silentLogger });

    await host.writeVariables(service, { API_KEY: 'replacement-private-value' }, { skipDeploy });

    expect(http.calls).toHaveLength(1);
    const request = body(http.calls[0]!);
    expect(request.query).toContain('variableCollectionUpsert(input: $input)');
    expect(request.query).not.toContain('replacement-private-value');
    expect(request.variables).toEqual({ input: {
      projectId: 'p1', environmentId: 'e1', serviceId: 's1',
      variables: { API_KEY: 'replacement-private-value' }, replace: false, skipDeploys: skipDeploy,
    } });
  });

  it('merges shared variables without deploying the shared pseudo-service', async () => {
    const http = queuedHttp({ data: { variableCollectionUpsert: true } });
    const host = createRailwayHost({ token, http, log: silentLogger });

    await host.writeVariables(shared, { SHARED_KEY: 'replacement-shared-value' }, { skipDeploy: true });
    expect(await host.redeploy(shared)).toBeNull();

    expect(http.calls).toHaveLength(1);
    expect(body(http.calls[0]!).variables).toEqual({ input: {
      projectId: 'p1', environmentId: 'e1', serviceId: null,
      variables: { SHARED_KEY: 'replacement-shared-value' }, replace: false, skipDeploys: true,
    } });
  });

  it('redeploys the latest deployment in the exact service scope and returns the new deployment id', async () => {
    const http = queuedHttp(
      { data: { deployments: { edges: [{ node: { id: 'previous-deployment', status: 'SUCCESS' } }] } } },
      { data: { deploymentRedeploy: { id: 'deployment-1', status: 'QUEUED' } } },
    );
    const host = createRailwayHost({ token, http, log: silentLogger });

    expect(await host.redeploy(service)).toBe('deployment-1');
    expect(http.calls).toHaveLength(2);
    const lookup = body(http.calls[0]!);
    expect(lookup.query.replace(/\s+/g, ' ')).toContain(
      'deployments(first: 1, input: { projectId: $projectId, serviceId: $serviceId, environmentId: $environmentId }) { edges { node { id status } } }',
    );
    expect(lookup.query).toContain('$projectId: String!');
    expect(lookup.query).toContain('$serviceId: String!');
    expect(lookup.query).toContain('$environmentId: String!');
    expect(lookup.variables).toEqual({ projectId: 'p1', serviceId: 's1', environmentId: 'e1' });
    const redeploy = body(http.calls[1]!);
    expect(redeploy.query).toContain('$id: String!');
    expect(redeploy.query.replace(/\s+/g, ' ')).toContain('deploymentRedeploy(id: $id) { id status }');
    expect(redeploy.variables).toEqual({ id: 'previous-deployment' });
  });

  it('triggers an initial service deployment and warns that status polling is unavailable', async () => {
    const http = queuedHttp(
      { data: { deployments: { edges: [] } } },
      { data: { environmentTriggersDeploy: true } },
    );
    const warnings: string[] = [];
    const host = createRailwayHost({ token, http, log: { ...silentLogger, warn: (message) => warnings.push(message) } });

    expect(await host.redeploy(service)).toBeNull();
    expect(http.calls).toHaveLength(2);
    expect(body(http.calls[0]!).query).toContain('deployments(first: 1');
    expect(body(http.calls[0]!).variables).toEqual({ projectId: 'p1', serviceId: 's1', environmentId: 'e1' });
    const trigger = body(http.calls[1]!);
    expect(trigger.query.replace(/\s+/g, ' ')).toContain(
      'environmentTriggersDeploy(input: { environmentId: $environmentId, projectId: $projectId, serviceId: $serviceId })',
    );
    expect(trigger.query).toContain('$environmentId: String!');
    expect(trigger.query).toContain('$projectId: String!');
    expect(trigger.query).toContain('$serviceId: String!');
    expect(trigger.variables).toEqual({ projectId: 'p1', serviceId: 's1', environmentId: 'e1' });
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/status polling is unavailable/i);
  });

  it.each([
    { message: `Schema rejected ${token}`, extensions: { code: 'GRAPHQL_VALIDATION_FAILED' } },
    { message: 'Cannot query field "deployments" on type "Query".' },
    { message: 'Unknown argument "input" on field "Query.deployments".' },
    { message: 'Unknown type "DeploymentListInput".' },
    { message: 'Field "projectId" is not defined by type "DeploymentListInput".' },
    { message: 'Variable "$projectId" of type "String!" used in position expecting type "ID!".' },
    { message: 'Field "deployments" argument "workspaceId" of type "String!" is required, but it was not provided.' },
    { message: 'Field "DeploymentListInput.workspaceId" of required type "String!" was not provided.' },
  ])('uses the legacy mutation only after a lookup schema error: %j', async (schemaError) => {
    const http = queuedHttp(
      { errors: [schemaError] },
      { data: { serviceInstanceDeployV2: 'legacy-deployment' } },
    );
    const warnings: string[] = [];
    const host = createRailwayHost({ token, http, log: { ...silentLogger, warn: (message) => warnings.push(message) } });

    expect(await host.redeploy(service)).toBe('legacy-deployment');
    expect(http.calls).toHaveLength(2);
    expect(body(http.calls[0]!).query).toContain('deployments(first: 1');
    expect(body(http.calls[0]!).variables).toEqual({ projectId: 'p1', serviceId: 's1', environmentId: 'e1' });
    const fallback = body(http.calls[1]!);
    expect(fallback.query).toContain('$serviceId: String!');
    expect(fallback.query).toContain('$environmentId: String!');
    expect(fallback.query.replace(/\s+/g, ' ')).toContain(
      'serviceInstanceDeployV2(serviceId: $serviceId, environmentId: $environmentId)',
    );
    expect(fallback.variables).toEqual({ serviceId: 's1', environmentId: 'e1' });
    expect(warnings.join(' ')).not.toContain(token);
  });

  it('recognizes a lookup schema error returned with HTTP 400', async () => {
    let request = 0;
    const http = new FakeHttp().on('POST', endpointPattern, () => ++request === 1
      ? json(400, { errors: [{ message: 'Cannot query field "deployments" on type "Query".' }] })
      : json(200, { data: { serviceInstanceDeployV2: 'legacy-deployment' } }));
    const host = createRailwayHost({ token, http, log: silentLogger });

    expect(await host.redeploy(service)).toBe('legacy-deployment');
    expect(http.calls).toHaveLength(2);
    expect(body(http.calls[0]!).query).toContain('deployments(first: 1');
    expect(body(http.calls[1]!).query).toContain('serviceInstanceDeployV2');
    expect(body(http.calls[1]!).variables).toEqual({ serviceId: 's1', environmentId: 'e1' });
  });

  it.each([
    [{ message: 'Access denied', extensions: { code: 'FORBIDDEN' } }],
    [{ message: 'Cannot query field "deployments" on type "Query".', extensions: { code: 'FORBIDDEN' } }],
    [{ message: 'Deployment lookup failed', extensions: { code: 'INTERNAL_SERVER_ERROR' } }],
    [
      { message: 'Cannot query field "deployments" on type "Query".' },
      { message: 'Access denied', extensions: { code: 'FORBIDDEN' } },
    ],
  ])('does not deploy after a non-schema lookup error: %j', async (...errors) => {
    const http = queuedHttp({ errors });
    const host = createRailwayHost({ token, http, log: silentLogger });

    await expect(host.redeploy(service)).rejects.toThrow('Railway');
    expect(http.calls).toHaveLength(1);
    expect(body(http.calls[0]!).query).toContain('deployments(first: 1');
  });

  it.each([401, 403, 500])('does not treat a schema-shaped HTTP %s failure as a compatibility issue', async (status) => {
    const http = new FakeHttp().on('POST', endpointPattern, () => json(status, {
      errors: [{ message: 'Cannot query field "deployments" on type "Query".' }],
    }));
    const host = createRailwayHost({ token, http, log: silentLogger });

    await expect(host.redeploy(service)).rejects.toThrow(`HTTP ${status}`);
    expect(http.calls).toHaveLength(1);
    expect(body(http.calls[0]!).query).toContain('deployments(first: 1');
  });

  it.each(['http', 'invalid-json', 'transport'] as const)('does not deploy after a %s lookup failure', async (failure) => {
    const http = new FakeHttp().on('POST', endpointPattern, () => {
      if (failure === 'transport') throw new Error(token);
      return failure === 'http' ? text(401, token) : text(200, token);
    });
    const host = createRailwayHost({ token, http, log: silentLogger });

    const error = await host.redeploy(service).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).not.toContain(token);
    expect(http.calls).toHaveLength(1);
    expect(body(http.calls[0]!).query).toContain('deployments(first: 1');
  });

  it.each([null, {}, { edges: null }, { edges: [{ node: null }] }, { edges: [{ node: { id: '' } }] }])(
    'rejects a malformed deployment lookup without triggering a deploy: %j', async (deployments) => {
      const http = queuedHttp({ data: { deployments } });
      const host = createRailwayHost({ token, http, log: silentLogger });

      await expect(host.redeploy(service)).rejects.toThrow('Railway');
      expect(http.calls).toHaveLength(1);
      expect(body(http.calls[0]!).query).toContain('deployments(first: 1');
    },
  );

  it.each(['redeploy', 'trigger', 'legacy'] as const)('never retries a %s mutation schema error through another mutation', async (path) => {
    const http = queuedHttp(
      path === 'legacy' ? { errors: [{ extensions: { code: 'GRAPHQL_VALIDATION_FAILED' } }] }
        : { data: { deployments: { edges: path === 'trigger' ? [] : [{ node: { id: 'previous', status: 'SUCCESS' } }] } } },
      { errors: [{ extensions: { code: 'GRAPHQL_VALIDATION_FAILED' }, message: token }] },
    );
    const host = createRailwayHost({ token, http, log: silentLogger });

    const error = await host.redeploy(service).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).not.toContain(token);
    expect(http.calls).toHaveLength(2);
    expect(body(http.calls[1]!).query).toContain(path === 'redeploy' ? 'deploymentRedeploy'
      : path === 'trigger' ? 'environmentTriggersDeploy' : 'serviceInstanceDeployV2');
  });

  it.each([
    ['redeploy', { deploymentRedeploy: { id: '' } }],
    ['trigger', { environmentTriggersDeploy: false }],
    ['legacy', { serviceInstanceDeployV2: null }],
  ] as const)('rejects an unsuccessful %s mutation result', async (path, data) => {
    const http = queuedHttp(
      path === 'legacy' ? { errors: [{ extensions: { code: 'GRAPHQL_VALIDATION_FAILED' } }] }
        : { data: { deployments: { edges: path === 'trigger' ? [] : [{ node: { id: 'previous', status: 'SUCCESS' } }] } } },
      { data },
    );
    const host = createRailwayHost({ token, http, log: silentLogger });

    await expect(host.redeploy(service)).rejects.toThrow('Railway');
    expect(http.calls).toHaveLength(2);
  });

  it.each([
    ['SUCCESS', 'success'], ['SKIPPED', 'failed'], ['FAILED', 'failed'], ['CRASHED', 'failed'], ['REMOVED', 'failed'],
    ['BUILDING', 'pending'], ['DEPLOYING', 'pending'], ['QUEUED', 'pending'],
    ['SLEEPING', 'success'], ['WAITING', 'pending'], ['UNKNOWN_FUTURE_STATUS', 'pending'],
  ])('maps deployment status %s to %s', async (status, expected) => {
    const http = queuedHttp({ data: { deployment: { status } } });
    const host = createRailwayHost({ token, http, log: silentLogger });

    expect(await host.deploymentStatus(service, 'deployment-1')).toBe(expected);
    expect(body(http.calls[0]!).query).toContain('deployment(id: $id) { status }');
    expect(body(http.calls[0]!).variables).toEqual({ id: 'deployment-1' });
  });

  it.each(['read', 'write', 'redeploy', 'status', 'list'] as const)(
    'rejects partial GraphQL errors in %s without echoing remote secrets', async (operation) => {
      const remoteSecret = 'private-value-echoed-from-server';
      const http = queuedHttp({
        data: { variables: { API_KEY: remoteSecret }, variableCollectionUpsert: true, serviceInstanceDeployV2: 'd1',
          deployment: { status: 'SUCCESS' }, projects: connection([]) },
        errors: [{ message: `Rejected ${token} ${remoteSecret} request body`, extensions: { echoed: remoteSecret } }],
      });
      const host = createRailwayHost({ token, http, log: silentLogger });
      const result = operation === 'read' ? host.readVariables(service)
        : operation === 'write' ? host.writeVariables(service, { API_KEY: remoteSecret }, { skipDeploy: true })
        : operation === 'redeploy' ? host.redeploy(service)
        : operation === 'status' ? host.deploymentStatus(service, 'd1') : host.listServices();

      const error = await result.catch((caught: unknown) => caught);
      expect(http.calls).toHaveLength(1);
      expect(error).toBeInstanceOf(Error);
      expect(String(error)).toContain('Railway');
      expect(String(error)).not.toContain(remoteSecret);
      expect(String(error)).not.toContain(token);
      expect(String(error)).not.toContain('request body');
    },
  );

  it('rejects failed upserts instead of treating a false result as success', async () => {
    const http = queuedHttp({ data: { variableCollectionUpsert: false } });
    const host = createRailwayHost({ token, http, log: silentLogger });

    await expect(host.writeVariables(service, { API_KEY: 'new-value' }, { skipDeploy: true })).rejects.toThrow('Railway');
    expect(http.calls).toHaveLength(1);
  });

  it.each([42, false, { nested: 'secret-inside-object' }])('rejects malformed variable values safely: %j', async (value) => {
    const http = queuedHttp({ data: { variables: { MALFORMED: value } } });
    const host = createRailwayHost({ token, http, log: silentLogger });

    await expect(host.readVariables(service)).rejects.toThrow('Railway');
    expect(http.calls).toHaveLength(1);
  });

  it('rejects repeated pagination cursors rather than looping or silently truncating', async () => {
    const http = queuedHttp(
      { data: { projects: connection([{ id: 'p1', name: 'Project One' }], true, 'same-cursor') } },
      { data: { projects: connection([{ id: 'p2', name: 'Project Two' }], true, 'same-cursor') } },
    );
    const host = createRailwayHost({ token, http, log: silentLogger });

    await expect(host.listServices()).rejects.toThrow('Railway');
    expect(http.calls).toHaveLength(2);
  });

  it.each(['http', 'invalid-json', 'transport'] as const)('sanitizes %s failures', async (failure) => {
    const leak = `private-server-secret ${token}`;
    const http = new FakeHttp().on('POST', endpointPattern, () => {
      if (failure === 'transport') throw new Error(leak);
      return failure === 'http' ? text(401, leak) : text(200, leak);
    });
    const host = createRailwayHost({ token, http, log: silentLogger });

    const error = await host.readVariables(service).catch((caught: unknown) => caught);
    expect(http.calls).toHaveLength(1);
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).toContain('Railway');
    expect(String(error)).not.toContain('private-server-secret');
    expect(String(error)).not.toContain(token);
  });
});
