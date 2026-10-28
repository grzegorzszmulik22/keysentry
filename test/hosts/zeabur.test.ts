import { describe, expect, it } from 'vitest';
import { createZeaburHost } from '../../src/hosts/zeabur.js';
import type { HttpRequest, HttpResponse, ServiceRef } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const token = 'zeabur-test-token';
const endpoint = 'https://api.zeabur.com/graphql';
const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
const P1 = '64f0a0a0a0a0a0a0a0a0a0a1';
const E1 = '64f0b0b0b0b0b0b0b0b0b0b1';
const E2 = '64f0b0b0b0b0b0b0b0b0b0b2';
const S1 = '64f0c0c0c0c0c0c0c0c0c0c1';
const S2 = '64f0c0c0c0c0c0c0c0c0c0c2';
const TEAM = '64f0d0d0d0d0d0d0d0d0d0d1';
const service: ServiceRef = {
  host: 'zeabur', projectId: P1, projectName: 'shop', serviceId: S1, serviceName: 'api', environmentId: E1, environmentName: 'production',
};

interface Gql { operation: string; query: string; variables: Record<string, unknown> }
type GqlHandler = (call: Gql) => HttpResponse;

function parse(req: HttpRequest): Gql {
  const body = JSON.parse(req.body ?? '{}') as { query: string; variables: Record<string, unknown> };
  const operation = /^(?:query|mutation) (\w+)/.exec(body.query)?.[1] ?? '';
  return { operation, query: body.query, variables: body.variables };
}

function graphqlHttp(handlers: Record<string, GqlHandler>): { http: FakeHttp; calls: Gql[] } {
  const calls: Gql[] = [];
  const http = new FakeHttp().on('POST', /^https:\/\/api\.zeabur\.com\/graphql$/, (req) => {
    const call = parse(req);
    calls.push(call);
    const handler = handlers[call.operation];
    return handler ? handler(call) : json(200, { errors: [{ message: `no handler for ${call.operation}` }] });
  });
  return { http, calls };
}

const data = (value: unknown) => json(200, { data: value });
const page = (nodes: { _id: string; name: string }[], hasNextPage = false) => ({ edges: nodes.map((node) => ({ node })), pageInfo: { hasNextPage } });

function hostFor(http: FakeHttp, extra: Partial<Parameters<typeof createZeaburHost>[0]> = {}, warnings: string[] = []) {
  return createZeaburHost({ token, http, log: { ...silentLogger, warn: (message: string) => warnings.push(message) }, ...extra });
}

/** A Zeabur variable store with whole-set replacement semantics, plus one variable exposed by another service. */
function variableStore(initial: Record<string, string>) {
  let own = { ...initial };
  const { http, calls } = graphqlHttp({
    KeysentryVariables: () => data({ service: { variables: [
      ...Object.entries(own).map(([key, value]) => ({ key, value, serviceID: S1 })),
      { key: 'POSTGRES_PASSWORD', value: 'exposed-by-db', serviceID: S2 },
    ] } }),
    KeysentryUpdateVariables: ({ variables }) => {
      own = { ...(variables.data as Record<string, string>) };
      return data({ updateEnvironmentVariable: true });
    },
  });
  return { http, calls, current: () => own };
}

describe('Zeabur host', () => {
  it('reports readable values, one-call writes and a restart step', () => {
    const host = hostFor(new FakeHttp());
    expect(host.id).toBe('zeabur');
    expect(host.capabilities).toEqual({ readValues: true, batchWrite: true, redeploy: true, activation: 'manual' });
  });

  it('sends parameterized GraphQL with bearer authentication and lists environment x service pairs', async () => {
    const { http, calls } = graphqlHttp({
      KeysentryProjects: ({ variables }) => data({ projects: variables.skip === 0 ? page([{ _id: P1, name: 'shop' }], true) : page([]) }),
      KeysentryEnvironments: () => data({ environments: [{ _id: E1, name: 'production' }, { _id: E2, name: 'staging' }] }),
      KeysentryServices: () => data({ services: page([{ _id: S1, name: 'api' }, { _id: S2, name: 'db' }]) }),
    });
    expect(await hostFor(http).listServices()).toEqual([
      service,
      { ...service, serviceId: S2, serviceName: 'db' },
      { ...service, environmentId: E2, environmentName: 'staging' },
      { ...service, serviceId: S2, serviceName: 'db', environmentId: E2, environmentName: 'staging' },
    ]);
    expect(http.calls.every((call) => call.method === 'POST' && call.url === endpoint)).toBe(true);
    expect(http.calls.every((call) => JSON.stringify(call.headers) === JSON.stringify(headers))).toBe(true);
    expect(calls.map((call) => [call.operation, call.variables])).toEqual([
      ['KeysentryProjects', { skip: 0, limit: 100 }],
      ['KeysentryProjects', { skip: 100, limit: 100 }],
      ['KeysentryEnvironments', { projectID: P1 }],
      ['KeysentryServices', { projectID: P1, skip: 0, limit: 100 }],
    ]);
    // No id is ever interpolated into a query document.
    expect(calls.some((call) => call.query.includes(P1))).toBe(false);
  });

  it('scopes to a team owner or to configured project ids', async () => {
    const owner = graphqlHttp({
      KeysentryOwnerProjects: () => data({ projects: page([]) }),
    });
    expect(await hostFor(owner.http, { ownerId: TEAM }).listServices()).toEqual([]);
    expect(owner.calls.map((call) => [call.operation, call.variables])).toEqual([['KeysentryOwnerProjects', { ownerID: TEAM, skip: 0, limit: 100 }]]);

    const configured = graphqlHttp({
      KeysentryProject: () => data({ project: { _id: P1, name: 'shop' } }),
      KeysentryEnvironments: () => data({ environments: [{ _id: E1, name: 'production' }] }),
      KeysentryServices: () => data({ services: page([{ _id: S1, name: 'api' }]) }),
    });
    expect(await hostFor(configured.http, { projectIds: [P1, P1] }).listServices()).toEqual([service]);
    expect(configured.calls.map((call) => call.operation)).toEqual(['KeysentryProject', 'KeysentryEnvironments', 'KeysentryServices']);
  });

  it.each([{ ownerId: 'x y' }, { projectIds: ['../x'] }, { projectIds: [''] }])('rejects invalid scoping %j', (extra) => {
    expect(() => hostFor(new FakeHttp(), extra)).toThrow(/Zeabur/);
  });

  it('stops pagination when a page adds nothing new', async () => {
    const { http, calls } = graphqlHttp({
      KeysentryProjects: () => data({ projects: page([{ _id: P1, name: 'shop' }], true) }),
      KeysentryEnvironments: () => data({ environments: [] }),
      KeysentryServices: () => data({ services: page([]) }),
    });
    expect(await hostFor(http).listServices()).toEqual([]);
    expect(calls.filter((call) => call.operation === 'KeysentryProjects')).toHaveLength(2);
  });

  it('reads only the service own variables, excluding ones exposed by other services', async () => {
    const { http, calls } = variableStore({ OPENAI_API_KEY: 'test-current', EMPTY: '', DB_URL: '${POSTGRES_CONNECTION_STRING}' });
    expect(await hostFor(http).readVariables(service)).toEqual([
      { name: 'OPENAI_API_KEY', value: 'test-current', sealed: false },
      { name: 'EMPTY', value: '', sealed: false },
      { name: 'DB_URL', value: '${POSTGRES_CONNECTION_STRING}', sealed: false },
    ]);
    expect(calls).toEqual([{ operation: 'KeysentryVariables', query: expect.stringContaining('exposed: true'), variables: { serviceID: S1, environmentID: E1 } }]);
  });

  it('replaces the set with every other own variable preserved exactly, then verifies it', async () => {
    const store = variableStore({ OPENAI_API_KEY: 'test-old', KEEP: 'keep-me', DB_URL: '${POSTGRES_CONNECTION_STRING}' });
    await hostFor(store.http).writeVariables(service, { OPENAI_API_KEY: 'test-new', NEW_KEY: 'test-added' }, { skipDeploy: true });
    expect(store.calls.map((call) => call.operation)).toEqual(['KeysentryVariables', 'KeysentryUpdateVariables', 'KeysentryVariables']);
    expect(store.calls[1]?.variables).toEqual({
      serviceID: S1, environmentID: E1,
      data: { OPENAI_API_KEY: 'test-new', KEEP: 'keep-me', DB_URL: '${POSTGRES_CONNECTION_STRING}', NEW_KEY: 'test-added' },
    });
    // The variable exposed by another service is never copied into this service.
    expect(store.current()).not.toHaveProperty('POSTGRES_PASSWORD');
    expect(store.calls.some((call) => call.operation.includes('Restart'))).toBe(false);
  });

  it('fails when the update is not acknowledged', async () => {
    const { http } = graphqlHttp({
      KeysentryVariables: () => data({ service: { variables: [] } }),
      KeysentryUpdateVariables: () => data({ updateEnvironmentVariable: false }),
    });
    await expect(hostFor(http).writeVariables(service, { A: 'test-a' }, { skipDeploy: true })).rejects.toThrow(/Zeabur did not apply/);
  });

  it('fails when the read-back shows other variables changed', async () => {
    let reads = 0;
    const marker = 'test-new-zeabur-secret';
    const { http } = graphqlHttp({
      KeysentryVariables: () => data({ service: { variables: reads++ === 0
        ? [{ key: 'A', value: '1', serviceID: S1 }, { key: 'B', value: '2', serviceID: S1 }]
        : [{ key: 'A', value: marker, serviceID: S1 }] } }),
      KeysentryUpdateVariables: () => data({ updateEnvironmentVariable: true }),
    });
    const error = await hostFor(http).writeVariables(service, { A: marker }, { skipDeploy: true }).catch((caught: unknown) => caught);
    expect(String(error)).toMatch(/Zeabur variables changed/);
    expect(String(error)).not.toContain(marker);
  });

  it('does nothing for an empty update and rejects an empty name before any request', async () => {
    const http = new FakeHttp();
    await hostFor(http).writeVariables(service, {}, { skipDeploy: true });
    await expect(hostFor(http).writeVariables(service, { '': 'test-a' }, { skipDeploy: true })).rejects.toThrow(/Zeabur/);
    expect(http.calls).toEqual([]);
  });

  it('restarts the service and reports activation as unconfirmed', async () => {
    const warnings: string[] = [];
    const { http, calls } = graphqlHttp({ KeysentryRestart: () => data({ restartService: true }) });
    expect(await hostFor(http, {}, warnings).redeploy(service)).toBeNull();
    expect(calls).toEqual([{ operation: 'KeysentryRestart', query: expect.stringContaining('restartService'), variables: { serviceID: S1, environmentID: E1 } }]);
    expect(warnings).toEqual([expect.stringMatching(/unconfirmed/)]);
    await expect(hostFor(http).deploymentStatus(service, 'x')).rejects.toThrow(/Zeabur/);
  });

  it('fails when the restart is not acknowledged', async () => {
    const { http } = graphqlHttp({ KeysentryRestart: () => data({ restartService: false }) });
    await expect(hostFor(http).redeploy(service)).rejects.toThrow(/Zeabur did not restart/);
  });

  it.each([
    { ...service, host: 'railway' as const },
    { ...service, serviceId: '' },
    { ...service, environmentId: '' },
    { ...service, serviceId: 'a"b' },
  ])('rejects malformed service references before any request: %j', async (bad) => {
    const http = new FakeHttp();
    await expect(hostFor(http).readVariables(bad)).rejects.toThrow(/Zeabur/);
    await expect(hostFor(http).writeVariables(bad, { A: 'test-a' }, { skipDeploy: true })).rejects.toThrow(/Zeabur/);
    await expect(hostFor(http).redeploy(bad)).rejects.toThrow(/Zeabur/);
    expect(http.calls).toEqual([]);
  });

  it.each(['http', 'transport', 'json', 'graphql', 'partial', 'malformed'] as const)('sanitizes %s failures', async (failure) => {
    const marker = 'test-private-zeabur-marker';
    const http = new FakeHttp().on('POST', /graphql$/, () => {
      if (failure === 'transport') throw new Error(`${token} ${marker}`);
      if (failure === 'http') return json(401, { errors: [{ message: marker }] });
      if (failure === 'json') return text(200, marker);
      if (failure === 'graphql') return json(200, { errors: [{ message: marker }] });
      if (failure === 'partial') return json(200, { data: { service: { variables: [] } }, errors: [{ message: marker }] });
      return json(200, { data: { service: { variables: [{ key: marker, value: { v: marker }, serviceID: S1 }] } } });
    });
    const error = await hostFor(http).readVariables(service).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).toMatch(/Zeabur/);
    expect(String(error)).not.toContain(marker);
    expect(String(error)).not.toContain(token);
  });

  it('sanitizes a rejected update without echoing submitted values', async () => {
    const marker = 'test-new-zeabur-value';
    const { http } = graphqlHttp({
      KeysentryVariables: () => data({ service: { variables: [] } }),
      KeysentryUpdateVariables: ({ variables }) => json(200, { errors: [{ message: JSON.stringify(variables) }] }),
    });
    const error = await hostFor(http).writeVariables(service, { A: marker }, { skipDeploy: true }).catch((caught: unknown) => caught);
    expect(String(error)).toBe('Error: Zeabur GraphQL request failed');
  });
});
