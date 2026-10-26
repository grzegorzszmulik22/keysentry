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

  it('reads unrendered variables and marks null or empty values as sealed', async () => {
    const http = queuedHttp({ data: { variables: {
      API_KEY: 'private-value-kept-in-memory', DATABASE_URL: '${{Postgres.DATABASE_URL}}', SEALED: null, EMPTY: '',
    } } });
    const host = createRailwayHost({ token, http, log: silentLogger });

    expect(await host.readVariables(service)).toEqual([
      { name: 'API_KEY', value: 'private-value-kept-in-memory', sealed: false },
      { name: 'DATABASE_URL', value: '${{Postgres.DATABASE_URL}}', sealed: false },
      { name: 'SEALED', sealed: true }, { name: 'EMPTY', sealed: true },
    ]);
    expect(body(http.calls[0]!).query).toContain('unrendered: true');
    expect(body(http.calls[0]!).variables).toEqual({ projectId: 'p1', environmentId: 'e1', serviceId: 's1' });
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

  it('starts one service deployment and returns its deployment id', async () => {
    const http = queuedHttp({ data: { serviceInstanceDeployV2: 'deployment-1' } });
    const host = createRailwayHost({ token, http, log: silentLogger });

    expect(await host.redeploy(service)).toBe('deployment-1');
    expect(http.calls).toHaveLength(1);
    expect(body(http.calls[0]!).query).toContain('serviceInstanceDeployV2');
    expect(body(http.calls[0]!).variables).toEqual({ serviceId: 's1', environmentId: 'e1' });
  });

  it.each([
    ['SUCCESS', 'success'], ['FAILED', 'failed'], ['CRASHED', 'failed'], ['REMOVED', 'failed'],
    ['BUILDING', 'pending'], ['DEPLOYING', 'pending'], ['QUEUED', 'pending'],
  ])('maps deployment status %s to %s', async (status, expected) => {
    const http = queuedHttp({ data: { deployment: { status } } });
    const host = createRailwayHost({ token, http, log: silentLogger });

    expect(await host.deploymentStatus(service, 'deployment-1')).toBe(expected);
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
