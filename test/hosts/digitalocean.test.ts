import { describe, expect, it } from 'vitest';
import { createDigitalOceanHost } from '../../src/hosts/digitalocean.js';
import type { ServiceRef } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const base = 'https://api.digitalocean.com/v2';
const token = 'do-test-token';
const readHeaders = { Authorization: `Bearer ${token}` };
const writeHeaders = { ...readHeaders, 'Content-Type': 'application/json' };
const ciphertext = 'EV[1:zqiRIeaaYK/NqctZDYzy6t0pTrtRDez8:wqGpZRrsKN5nPhWQrS479cfBiXT0WQ==]';

const appLevel: ServiceRef = {
  host: 'digitalocean', projectId: 'app-1', projectName: 'web-app',
  serviceId: '', serviceName: 'app', environmentId: '', environmentName: '',
};
const apiService: ServiceRef = { ...appLevel, serviceId: 'services/api', serviceName: 'api' };
const queueWorker: ServiceRef = { ...appLevel, serviceId: 'workers/queue', serviceName: 'queue' };

function spec() {
  return {
    name: 'web-app',
    region: 'nyc',
    features: ['buildpack-stack=ubuntu-22'],
    envs: [
      { key: 'SHARED_SECRET', scope: 'RUN_AND_BUILD_TIME', type: 'SECRET', value: ciphertext },
      { key: 'APP_URL', scope: 'RUN_TIME', value: '${APP_URL}' },
    ],
    services: [{
      name: 'api',
      github: { repo: 'acme/api', branch: 'main', deploy_on_push: true },
      envs: [
        { key: 'OPENAI_API_KEY', scope: 'RUN_TIME', type: 'GENERAL', value: 'test-current-openai' },
        { key: 'STRIPE_KEY', scope: 'RUN_TIME', type: 'SECRET', value: ciphertext },
        { key: 'DB_PASSWORD', scope: 'RUN_TIME', type: 'GENERAL', value: '${db.PASSWORD}' },
      ],
      // App Platform returns spec credentials outside envs as EV[...] ciphertext (fix-phase6 refuses any other form).
      log_destinations: [{ name: 'dd', datadog: { api_key: ciphertext } }],
    }],
    workers: [{ name: 'queue', image: { registry_type: 'DOCR', repository: 'queue', tag: 'stable' } }],
    databases: [{ name: 'db', engine: 'PG' }],
  };
}

function app(overrides: Record<string, unknown> = {}) {
  return { id: 'app-1', spec: spec(), active_deployment: { id: 'dep-active', phase: 'ACTIVE' }, ...overrides };
}

const hostFor = (http: FakeHttp, extra: { apps?: string[]; warn?: (msg: string) => void } = {}) =>
  createDigitalOceanHost({ token, http, apps: extra.apps, log: { ...silentLogger, ...(extra.warn ? { warn: extra.warn } : {}) } });

async function failure(promise: Promise<unknown>): Promise<string> {
  const error = await promise.then(() => undefined, (caught: unknown) => caught);
  expect(error).toBeInstanceOf(Error);
  return String(error);
}

function putBody(http: FakeHttp): { spec: ReturnType<typeof spec>; update_all_source_versions: boolean } {
  const put = http.calls.find((call) => call.method === 'PUT');
  return JSON.parse(put?.body ?? 'null');
}

describe('DigitalOcean App Platform host', () => {
  it('reports readable general values, whole-spec writes and deployment tracking', () => {
    const host = hostFor(new FakeHttp());
    expect(host.id).toBe('digitalocean');
    expect(host.capabilities).toEqual({ readValues: true, batchWrite: true, redeploy: true, activation: 'on-write' });
  });

  it('lists an app-level service and every env-capable component across pages', async () => {
    const second = { id: 'app-2', spec: { name: 'site', static_sites: [{ name: 'docs' }], jobs: [{ name: 'migrate' }], functions: [{ name: 'fns' }] } };
    const http = new FakeHttp().on('GET', /\/apps\?/, (req) => {
      const page = new URL(req.url).searchParams.get('page');
      return page === '1'
        ? json(200, { apps: [app()], links: { pages: { next: 'https://api.digitalocean.com/v2/apps?page=2', last: 'x' } }, meta: { total: 2 } })
        : json(200, { apps: [second], links: { pages: { first: 'x', prev: 'y' } }, meta: { total: 2 } });
    });

    expect(await hostFor(http).listServices()).toEqual([
      appLevel, apiService, queueWorker,
      { ...appLevel, projectId: 'app-2', projectName: 'site' },
      { ...appLevel, projectId: 'app-2', projectName: 'site', serviceId: 'jobs/migrate', serviceName: 'migrate' },
      { ...appLevel, projectId: 'app-2', projectName: 'site', serviceId: 'static_sites/docs', serviceName: 'docs' },
      { ...appLevel, projectId: 'app-2', projectName: 'site', serviceId: 'functions/fns', serviceName: 'fns' },
    ]);
    expect(http.calls).toEqual([
      { method: 'GET', url: `${base}/apps?page=1&per_page=200`, headers: readHeaders },
      { method: 'GET', url: `${base}/apps?page=2&per_page=200`, headers: readHeaders },
    ]);
  });

  it('accepts an empty account without an apps array', async () => {
    const http = new FakeHttp().on('GET', /\/apps\?/, () => json(200, { links: {}, meta: { total: 0 } }));
    expect(await hostFor(http).listServices()).toEqual([]);
  });

  it('stops when a next page adds no new apps', async () => {
    const http = new FakeHttp().on('GET', /\/apps\?/, () => json(200, { apps: [app()], links: { pages: { next: 'again' } }, meta: { total: 9 } }));
    expect(await failure(hostFor(http).listServices())).toMatch(/DigitalOcean pagination/);
    expect(http.calls).toHaveLength(2);
  });

  it('looks up configured app ids only', async () => {
    const http = new FakeHttp().on('GET', /\/apps\/app%2F1$/, () => json(200, { app: { ...app(), id: 'app/1' } }));
    const services = await hostFor(http, { apps: ['app/1', 'app/1'] }).listServices();
    expect(services.map((service) => [service.projectId, service.serviceId])).toEqual([['app/1', ''], ['app/1', 'services/api'], ['app/1', 'workers/queue']]);
    expect(http.calls).toEqual([{ method: 'GET', url: `${base}/apps/app%2F1`, headers: readHeaders }]);
  });

  it('reads app-level variables, sealing SECRET values and keeping bindable references as text', async () => {
    const http = new FakeHttp().on('GET', /\/apps\/app-1$/, () => json(200, { app: app() }));
    expect(await hostFor(http).readVariables(appLevel)).toEqual([
      { name: 'SHARED_SECRET', sealed: true },
      { name: 'APP_URL', value: '${APP_URL}', sealed: false },
    ]);
    expect(http.calls).toEqual([{ method: 'GET', url: `${base}/apps/app-1`, headers: readHeaders }]);
  });

  it('reads only the selected component and never returns ciphertext', async () => {
    const http = new FakeHttp().on('GET', /\/apps\/app-1$/, () => json(200, { app: app() }));
    const vars = await hostFor(http).readVariables(apiService);
    expect(vars).toEqual([
      { name: 'OPENAI_API_KEY', value: 'test-current-openai', sealed: false },
      { name: 'STRIPE_KEY', sealed: true },
      { name: 'DB_PASSWORD', value: '${db.PASSWORD}', sealed: false },
    ]);
    expect(JSON.stringify(vars)).not.toContain('EV[');
    expect(await hostFor(http).readVariables(queueWorker)).toEqual([]);
  });

  it('seals encrypted-looking values without a type and duplicated keys', async () => {
    const warnings: string[] = [];
    const custom = app({ spec: { name: 'web-app', envs: [
      { key: 'UNTYPED', value: ciphertext },
      { key: 'DUP', value: 'test-one' },
      { key: 'DUP', value: 'test-two' },
      { key: 'NO_VALUE' },
    ] } });
    const http = new FakeHttp().on('GET', /\/apps\/app-1$/, () => json(200, { app: custom }));
    expect(await hostFor(http, { warn: (msg) => warnings.push(msg) }).readVariables(appLevel)).toEqual([
      { name: 'UNTYPED', sealed: true },
      { name: 'DUP', sealed: true },
      { name: 'NO_VALUE', value: '', sealed: false },
    ]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).not.toContain('test-one');
  });

  it('read-modify-writes the whole spec, changing only the requested component variables', async () => {
    const http = new FakeHttp()
      .on('GET', /\/apps\/app-1$/, () => json(200, { app: app() }))
      .on('PUT', /\/apps\/app-1$/, () => json(200, { app: { ...app(), pending_deployment: { id: 'dep-new' } } }));
    const host = hostFor(http);

    await host.writeVariables(apiService, { OPENAI_API_KEY: 'test-new-openai', STRIPE_KEY: 'test-new-stripe', NEW_TOKEN: 'test-new-token' }, { skipDeploy: true });

    expect(http.calls.map((call) => [call.method, call.url, call.headers])).toEqual([
      ['GET', `${base}/apps/app-1`, readHeaders],
      ['PUT', `${base}/apps/app-1`, writeHeaders],
    ]);
    const expected = spec();
    expected.services[0]!.envs[0]!.value = 'test-new-openai';
    expected.services[0]!.envs[1]!.value = 'test-new-stripe';
    expected.services[0]!.envs.push({ key: 'NEW_TOKEN', value: 'test-new-token', scope: 'RUN_AND_BUILD_TIME', type: 'SECRET' });
    // Every other field survives, including undocumented ones, other components, and app-level ciphertext.
    expect(putBody(http)).toEqual({ spec: expected, update_all_source_versions: false });
    expect(await host.redeploy(apiService)).toBe('dep-new');
    expect(http.calls).toHaveLength(2);
  });

  it('writes app-level variables and creates an envs list on a component that had none', async () => {
    const http = new FakeHttp()
      .on('GET', /\/apps\/app-1$/, () => json(200, { app: app() }))
      .on('PUT', /\/apps\/app-1$/, () => json(200, { app: { ...app(), pending_deployment: { id: 'dep-new' } } }));
    await hostFor(http).writeVariables(appLevel, { SHARED_SECRET: 'test-new-shared' }, { skipDeploy: true });
    const sent = putBody(http).spec;
    expect(sent.envs[0]).toEqual({ key: 'SHARED_SECRET', scope: 'RUN_AND_BUILD_TIME', type: 'SECRET', value: 'test-new-shared' });
    expect(sent.envs[1]).toEqual(spec().envs[1]);
    expect(sent.services).toEqual(spec().services);

    const second = new FakeHttp()
      .on('GET', /\/apps\/app-1$/, () => json(200, { app: app() }))
      .on('PUT', /\/apps\/app-1$/, () => json(200, { app: { ...app(), pending_deployment: { id: 'dep-new' } } }));
    await hostFor(second).writeVariables(queueWorker, { QUEUE_TOKEN: 'test-new-queue' }, { skipDeploy: false });
    expect(putBody(second).spec.workers).toEqual([{ ...spec().workers[0], envs: [{ key: 'QUEUE_TOKEN', value: 'test-new-queue', scope: 'RUN_AND_BUILD_TIME', type: 'SECRET' }] }]);
  });

  it.each([
    ['a pinned rollback', app({ pinned_deployment: { id: 'dep-old' } }), apiService, { OPENAI_API_KEY: 'test-new' }],
    ['a duplicated key', app({ spec: { name: 'web-app', envs: [{ key: 'K', value: 'a' }, { key: 'K', value: 'b' }] } }), appLevel, { K: 'test-new' }],
    ['a missing component', app(), { ...apiService, serviceId: 'services/gone' }, { K: 'test-new' }],
    ['a bindable reference', app(), apiService, { DB_PASSWORD: 'test-new' }],
    ['a malformed service id', app(), { ...apiService, serviceId: 'databases/db' }, { K: 'test-new' }],
  ])('refuses to write over %s without sending the spec', async (_label, current, target, vars) => {
    const http = new FakeHttp()
      .on('GET', /\/apps\/app-1$/, () => json(200, { app: current }))
      .on('PUT', /\/apps\/app-1$/, () => json(200, { app: current }));
    expect(await failure(hostFor(http).writeVariables(target, vars, { skipDeploy: true }))).toMatch(/DigitalOcean/);
    expect(http.calls.filter((call) => call.method === 'PUT')).toEqual([]);
  });

  it.each(['', '1ABC', 'BAD-NAME', 'has space'])('rejects the invalid variable name %j before any request', async (name) => {
    const http = new FakeHttp();
    await expect(hostFor(http).writeVariables(apiService, { OK: 'test-new', [name]: 'test-new' }, { skipDeploy: true })).rejects.toThrow(/DigitalOcean/);
    expect(http.calls).toEqual([]);
  });

  it('does nothing for an empty update', async () => {
    const http = new FakeHttp();
    await hostFor(http).writeVariables(apiService, {}, { skipDeploy: true });
    expect(http.calls).toEqual([]);
  });

  it('returns the latest update deployment for every service of the same app', async () => {
    let n = 0;
    const http = new FakeHttp()
      .on('GET', /\/apps\/app-1$/, () => json(200, { app: app() }))
      .on('PUT', /\/apps\/app-1$/, () => json(200, { app: { ...app(), pending_deployment: { id: `dep-${++n}` } } }));
    const host = hostFor(http);
    await host.writeVariables(appLevel, { SHARED_SECRET: 'test-a' }, { skipDeploy: true });
    await host.writeVariables(apiService, { OPENAI_API_KEY: 'test-b' }, { skipDeploy: true });
    expect(await host.redeploy(appLevel)).toBe('dep-2');
    expect(await host.redeploy(apiService)).toBe('dep-2');
    // The later spec update replaced the earlier deployment; its status follows the newer one.
    http.on('GET', /\/deployments\/dep-1$/, () => json(200, { deployment: { id: 'dep-1', phase: 'CANCELED' } }))
      .on('GET', /\/deployments\/dep-2$/, () => json(200, { deployment: { id: 'dep-2', phase: 'ACTIVE' } }));
    expect(await host.deploymentStatus(appLevel, 'dep-1')).toBe('success');
    expect(http.calls.filter((call) => call.method === 'POST')).toEqual([]);
  });

  it('keeps a successful write when the response has no deployment, then finds the pending one', async () => {
    const warnings: string[] = [];
    const http = new FakeHttp()
      .on('GET', /\/apps\/app-1$/, () => json(200, { app: app({ in_progress_deployment: { id: 'dep-running' } }) }))
      .on('PUT', /\/apps\/app-1$/, () => json(200, { app: app() }));
    const host = hostFor(http, { warn: (msg) => warnings.push(msg) });
    await host.writeVariables(apiService, { OPENAI_API_KEY: 'test-new' }, { skipDeploy: true });
    expect(warnings).toHaveLength(1);
    expect(await host.redeploy(apiService)).toBe('dep-running');
    expect(http.calls.map((call) => call.method)).toEqual(['GET', 'PUT', 'GET']);
  });

  it('never starts a deployment: a fresh adapter reports the pending one or null', async () => {
    const pending = new FakeHttp().on('GET', /\/apps\/app-1$/, () => json(200, { app: app({ pending_deployment: { id: 'dep-pending' }, in_progress_deployment: { id: 'dep-running' } }) }));
    expect(await hostFor(pending).redeploy(apiService)).toBe('dep-pending');

    const warnings: string[] = [];
    const idle = new FakeHttp().on('GET', /\/apps\/app-1$/, () => json(200, { app: app() }));
    expect(await hostFor(idle, { warn: (msg) => warnings.push(msg) }).redeploy(apiService)).toBeNull();
    expect(warnings).toHaveLength(1);
    expect([...pending.calls, ...idle.calls].every((call) => call.method === 'GET')).toBe(true);
  });

  it.each([
    ['ACTIVE', 'success'],
    ['ERROR', 'failed'],
    ['CANCELED', 'failed'],
    ['SUPERSEDED', 'failed'],
    ['PENDING_BUILD', 'pending'],
    ['BUILDING', 'pending'],
    ['PENDING_DEPLOY', 'pending'],
    ['DEPLOYING', 'pending'],
    ['UNKNOWN', 'pending'],
  ] as const)('maps deployment phase %s to %s', async (phase, expected) => {
    const http = new FakeHttp().on('GET', /\/apps\/app-1\/deployments\/dep%2F1$/, () => json(200, { deployment: { id: 'dep/1', phase } }));
    expect(await hostFor(http).deploymentStatus(apiService, 'dep/1')).toBe(expected);
    expect(http.calls).toEqual([{ method: 'GET', url: `${base}/apps/app-1/deployments/dep%2F1`, headers: readHeaders }]);
  });

  it.each(['http', 'transport', 'json'] as const)('sanitizes %s failures during writes', async (kind) => {
    const marker = 'test-private-error-marker';
    const http = new FakeHttp()
      .on('GET', /\/apps\/app-1$/, () => json(200, { app: app() }))
      .on('PUT', /\/apps\/app-1$/, () => {
        if (kind === 'transport') throw new Error(`${token} ${marker}`);
        return kind === 'http' ? json(422, { message: marker }) : text(200, marker);
      });
    const message = await failure(hostFor(http).writeVariables(apiService, { OPENAI_API_KEY: marker }, { skipDeploy: true }));
    expect(message).toMatch(/DigitalOcean/);
    expect(message).not.toContain(marker);
    expect(message).not.toContain(token);
  });

  it('rejects a malformed spec without echoing it', async () => {
    const http = new FakeHttp().on('GET', /\/apps\/app-1$/, () => json(200, { app: { id: 'app-1', spec: { name: 'web-app', services: 'test-private-response-marker' } } }));
    const message = await failure(hostFor(http).readVariables(apiService));
    expect(message).toMatch(/DigitalOcean/);
    expect(message).not.toContain('test-private-response-marker');
  });
});
