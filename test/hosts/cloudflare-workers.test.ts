import { describe, expect, it } from 'vitest';
import { createCloudflareWorkersHost } from '../../src/hosts/cloudflare-workers.js';
import type { HttpRequest, ServiceRef } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const token = 'cf-test-token';
const accountId = '0123456789abcdef0123456789abcdef';
const base = `https://api.cloudflare.com/client/v4/accounts/${accountId}`;
const auth = { Authorization: `Bearer ${token}` };
const jsonAuth = { ...auth, 'Content-Type': 'application/json' };

const worker: ServiceRef = {
  host: 'cloudflare-workers', projectId: accountId, projectName: accountId,
  serviceId: 'worker:api', serviceName: 'api', environmentId: '', environmentName: '',
};
const pagesProduction: ServiceRef = {
  host: 'cloudflare-workers', projectId: accountId, projectName: accountId,
  serviceId: 'pages:site', serviceName: 'site', environmentId: 'production', environmentName: 'production',
};
const pagesPreview: ServiceRef = { ...pagesProduction, environmentId: 'preview', environmentName: 'preview' };

const ok = (result: unknown, extra: Record<string, unknown> = {}) => json(200, { success: true, errors: [], messages: [], result, ...extra });

function hostFor(http: FakeHttp, extra: Partial<Parameters<typeof createCloudflareWorkersHost>[0]> = {}, warnings: string[] = []) {
  return createCloudflareWorkersHost({
    token, accountId, http, log: { ...silentLogger, warn: (message: string) => warnings.push(message) }, ...extra,
  });
}

/** Latest deployment serving version v2 at 100%, and v2 is the newest version. */
function serving(http: FakeHttp, deployment: unknown = { id: 'dep-2', versions: [{ version_id: 'v2', percentage: 100 }] }, latest = 'v2') {
  return http
    .on('GET', /\/workers\/scripts\/api\/deployments$/, () => ok({ deployments: deployment === null ? [] : [deployment, { id: 'dep-1', versions: [{ version_id: 'v1', percentage: 100 }] }] }))
    .on('GET', /\/workers\/scripts\/api\/versions$/, () => ok({ items: [{ id: latest, number: 2 }, { id: 'v1', number: 1 }] }));
}

function project(production: Record<string, unknown> | null, preview: Record<string, unknown> | null = {}) {
  return {
    id: 'proj-1', name: 'site',
    deployment_configs: {
      production: { compatibility_date: '2026-01-01', env_vars: production },
      preview: { env_vars: preview },
    },
  };
}

describe('Cloudflare Workers and Pages host', () => {
  it('declares readable plain vars, per-key writes and a deployment step', () => {
    const host = hostFor(new FakeHttp());
    expect(host.id).toBe('cloudflare-workers');
    expect(host.capabilities).toEqual({ readValues: true, batchWrite: false, redeploy: true });
  });

  it.each(['', 'a/b', '../x', 'x'.repeat(33)])('rejects invalid account id %j', (bad) => {
    expect(() => createCloudflareWorkersHost({ token, accountId: bad, http: new FakeHttp(), log: silentLogger })).toThrow(/Cloudflare/);
  });

  it('lists Workers scripts and paginated Pages projects for each environment', async () => {
    const http = new FakeHttp()
      .on('GET', /\/workers\/scripts$/, () => ok([{ id: 'api' }, { id: 'cron' }]))
      .on('GET', /\/pages\/projects\?page=1$/, () => ok([{ name: 'site' }], { result_info: { page: 1, total_pages: 2 } }))
      .on('GET', /\/pages\/projects\?page=2$/, () => ok([{ name: 'docs' }], { result_info: { page: 2, total_pages: 2 } }));

    expect(await hostFor(http).listServices()).toEqual([
      worker,
      { ...worker, serviceId: 'worker:cron', serviceName: 'cron' },
      pagesProduction,
      pagesPreview,
      { ...pagesProduction, serviceId: 'pages:docs', serviceName: 'docs' },
      { ...pagesPreview, serviceId: 'pages:docs', serviceName: 'docs' },
    ]);
    expect(http.calls).toEqual([
      { method: 'GET', url: `${base}/workers/scripts`, headers: auth },
      { method: 'GET', url: `${base}/pages/projects?page=1`, headers: auth },
      { method: 'GET', url: `${base}/pages/projects?page=2`, headers: auth },
    ]);
  });

  it('stops Pages pagination at an empty page or a page that adds nothing new', async () => {
    const http = new FakeHttp()
      .on('GET', /\/pages\/projects\?page=1$/, () => ok([{ name: 'site' }]))
      .on('GET', /\/pages\/projects\?page=2$/, () => ok([{ name: 'site' }]));
    expect(await hostFor(http, { products: ['pages'], pagesEnvironments: ['production'] }).listServices()).toEqual([pagesProduction]);
    expect(http.calls).toHaveLength(2);

    const empty = new FakeHttp()
      .on('GET', /\/pages\/projects\?page=1$/, () => ok([{ name: 'site' }]))
      .on('GET', /\/pages\/projects\?page=2$/, () => ok([]));
    expect(await hostFor(empty, { products: ['pages'], pagesEnvironments: ['preview'] }).listServices()).toEqual([pagesPreview]);
    expect(empty.calls).toHaveLength(2);
  });

  it('uses configured scripts without listing and validates configured Pages projects', async () => {
    const http = new FakeHttp().on('GET', /\/pages\/projects\/site$/, () => ok(project({})));
    const host = hostFor(http, { scripts: ['api', 'api'], pagesProjects: ['site'], pagesEnvironments: ['production'] });
    expect(await host.listServices()).toEqual([worker, pagesProduction]);
    expect(http.calls).toEqual([{ method: 'GET', url: `${base}/pages/projects/site`, headers: auth }]);
  });

  it.each(['', '.', '..', 'a/b', 'a?b'])('rejects unsafe configured script name %j', (name) => {
    expect(() => hostFor(new FakeHttp(), { scripts: [name] })).toThrow(/Cloudflare/);
  });

  it('reads Worker plain-text bindings and reports secret bindings as sealed without their text', async () => {
    const marker = 'test-secret-should-not-surface';
    const http = new FakeHttp().on('GET', /\/workers\/scripts\/api\/settings$/, () => ok({
      bindings: [
        { name: 'MODE', type: 'plain_text', text: 'live' },
        { name: 'EMPTY', type: 'plain_text', text: '' },
        { name: 'OPENAI_API_KEY', type: 'secret_text', text: marker },
        { name: 'CACHE', type: 'kv_namespace', namespace_id: 'ns' },
      ],
    }));
    const variables = await hostFor(http).readVariables(worker);
    expect(variables).toEqual([
      { name: 'MODE', value: 'live', sealed: false },
      { name: 'EMPTY', value: '', sealed: false },
      { name: 'OPENAI_API_KEY', sealed: true },
    ]);
    expect(JSON.stringify(variables)).not.toContain(marker);
    expect(http.calls).toEqual([{ method: 'GET', url: `${base}/workers/scripts/api/settings`, headers: auth }]);
  });

  it('reads Pages plain_text values and seals secret_text for the requested environment only', async () => {
    const marker = 'test-pages-secret-marker';
    const http = new FakeHttp().on('GET', /\/pages\/projects\/site$/, () => ok(project(
      { MODE: { type: 'plain_text', value: 'prod' }, API_KEY: { type: 'secret_text', value: marker }, GONE: null },
      { MODE: { type: 'plain_text', value: 'preview' } },
    )));
    const variables = await hostFor(http).readVariables(pagesProduction);
    expect(variables).toEqual([
      { name: 'MODE', value: 'prod', sealed: false },
      { name: 'API_KEY', sealed: true },
    ]);
    expect(JSON.stringify(variables)).not.toContain(marker);
    expect(await hostFor(http).readVariables(pagesPreview)).toEqual([{ name: 'MODE', value: 'preview', sealed: false }]);
  });

  it('treats missing Pages env vars as empty', async () => {
    const http = new FakeHttp().on('GET', /\/pages\/projects\/site$/, () => ok({ name: 'site', deployment_configs: { production: {} } }));
    expect(await hostFor(http).readVariables(pagesProduction)).toEqual([]);
    expect(await hostFor(http).readVariables(pagesPreview)).toEqual([]);
  });

  it('writes Worker secrets one per request after checking the newest version serves all traffic', async () => {
    const http = serving(new FakeHttp()
      .on('GET', /\/workers\/scripts\/api\/settings$/, () => ok({ bindings: [{ name: 'OPENAI_API_KEY', type: 'secret_text' }] }))
      .on('PUT', /\/workers\/scripts\/api\/secrets$/, () => ok({ name: 'x', type: 'secret_text' })));

    await hostFor(http).writeVariables(worker, { OPENAI_API_KEY: 'test-new-value', NEW_SECRET: 'test-other' }, { skipDeploy: true });
    expect(http.calls).toEqual([
      { method: 'GET', url: `${base}/workers/scripts/api/settings`, headers: auth },
      { method: 'GET', url: `${base}/workers/scripts/api/deployments`, headers: auth },
      { method: 'GET', url: `${base}/workers/scripts/api/versions`, headers: auth },
      {
        method: 'PUT', url: `${base}/workers/scripts/api/secrets`, headers: jsonAuth,
        body: JSON.stringify({ name: 'OPENAI_API_KEY', text: 'test-new-value', type: 'secret_text' }),
      },
      {
        method: 'PUT', url: `${base}/workers/scripts/api/secrets`, headers: jsonAuth,
        body: JSON.stringify({ name: 'NEW_SECRET', text: 'test-other', type: 'secret_text' }),
      },
    ]);
  });

  it.each([
    { name: 'plain text', binding: { name: 'API_KEY', type: 'plain_text', text: 'old' } },
    { name: 'resource', binding: { name: 'API_KEY', type: 'kv_namespace', namespace_id: 'ns' } },
  ])('refuses to overwrite a $name Worker binding before any write', async ({ binding }) => {
    const http = serving(new FakeHttp()
      .on('GET', /\/settings$/, () => ok({ bindings: [binding] }))
      .on('PUT', /\/secrets$/, () => ok({})));
    await expect(hostFor(http).writeVariables(worker, { OTHER: 'test-a', API_KEY: 'test-b' }, { skipDeploy: true }))
      .rejects.toThrow(/Cloudflare Workers/);
    expect(http.callsTo('PUT', /./)).toEqual([]);
  });

  it.each([
    { name: 'a gradual rollout', deployment: { id: 'dep-2', versions: [{ version_id: 'v2', percentage: 50 }, { version_id: 'v1', percentage: 50 }] }, latest: 'v2' },
    { name: 'an undeployed newest version', deployment: { id: 'dep-2', versions: [{ version_id: 'v2', percentage: 100 }] }, latest: 'v3' },
    { name: 'no deployment', deployment: null, latest: 'v2' },
  ])('refuses Worker writes during $name', async ({ deployment, latest }) => {
    const http = serving(new FakeHttp()
      .on('GET', /\/settings$/, () => ok({ bindings: [] }))
      .on('PUT', /\/secrets$/, () => ok({})), deployment, latest);
    await expect(hostFor(http).writeVariables(worker, { API_KEY: 'test-new' }, { skipDeploy: true })).rejects.toThrow(/Cloudflare Workers/);
    expect(http.callsTo('PUT', /./)).toEqual([]);
  });

  it('stops writing Worker secrets after the first failure', async () => {
    const http = serving(new FakeHttp()
      .on('GET', /\/settings$/, () => ok({ bindings: [] }))
      .on('PUT', /\/secrets$/, () => json(403, { success: false, errors: [{ code: 10000, message: 'denied' }] })));
    await expect(hostFor(http).writeVariables(worker, { A: 'test-a', B: 'test-b' }, { skipDeploy: true })).rejects.toThrow('Cloudflare request failed (HTTP 403)');
    expect(http.callsTo('PUT', /./)).toHaveLength(1);
  });

  it('does nothing for an empty update', async () => {
    const http = new FakeHttp();
    await hostFor(http).writeVariables(worker, {}, { skipDeploy: true });
    await hostFor(http).writeVariables(pagesProduction, {}, { skipDeploy: true });
    expect(http.calls).toEqual([]);
  });

  it('confirms Worker activation from the deployment list without starting a deployment', async () => {
    const http = serving(new FakeHttp());
    const host = hostFor(http);
    expect(await host.redeploy(worker)).toBe('dep-2');
    expect(await host.deploymentStatus(worker, 'dep-2')).toBe('success');
    expect(http.calls.every((call) => call.method === 'GET')).toBe(true);
  });

  it('returns null with a warning when the newest Worker version is not serving all traffic', async () => {
    const warnings: string[] = [];
    const http = serving(new FakeHttp(), { id: 'dep-2', versions: [{ version_id: 'v2', percentage: 10 }, { version_id: 'v1', percentage: 90 }] });
    expect(await hostFor(http, {}, warnings).redeploy(worker)).toBeNull();
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).not.toContain(token);
  });

  it.each([
    { deployment: { id: 'dep-3', versions: [{ version_id: 'v2', percentage: 100 }] }, latest: 'v2', expected: 'success' },
    { deployment: { id: 'dep-3', versions: [{ version_id: 'v2', percentage: 40 }, { version_id: 'v1', percentage: 60 }] }, latest: 'v2', expected: 'pending' },
    { deployment: { id: 'dep-3', versions: [{ version_id: 'v1', percentage: 100 }] }, latest: 'v2', expected: 'failed' },
    { deployment: null, latest: 'v2', expected: 'failed' },
  ] as const)('maps Worker serving state to $expected', async ({ deployment, latest, expected }) => {
    const http = serving(new FakeHttp(), deployment, latest);
    expect(await hostFor(http).deploymentStatus(worker, 'dep-2')).toBe(expected);
  });

  it('writes Pages variables with a merge PATCH that keeps types and verifies other variables survive', async () => {
    let current = project(
      { MODE: { type: 'plain_text', value: 'prod' }, API_KEY: { type: 'secret_text', value: '' }, CONFIG_KEY: { type: 'plain_text', value: 'old-plain' } },
      { MODE: { type: 'plain_text', value: 'preview' }, API_KEY: { type: 'secret_text' } },
    );
    const http = new FakeHttp()
      .on('GET', /\/pages\/projects\/site$/, () => ok(current))
      .on('PATCH', /\/pages\/projects\/site$/, (req: HttpRequest) => {
        const patch = JSON.parse(req.body ?? '{}').deployment_configs.production.env_vars as Record<string, unknown>;
        current = project(
          { ...current.deployment_configs.production.env_vars, ...Object.fromEntries(Object.entries(patch).map(([k, v]) => [k, (v as { type: string }).type === 'secret_text' ? { type: 'secret_text', value: '' } : v])) },
          current.deployment_configs.preview.env_vars,
        );
        return ok(current);
      });

    await hostFor(http).writeVariables(pagesProduction, { API_KEY: 'test-new-secret', CONFIG_KEY: 'test-new-plain', NEW_KEY: 'test-added' }, { skipDeploy: true });
    expect(http.calls).toEqual([
      { method: 'GET', url: `${base}/pages/projects/site`, headers: auth },
      {
        method: 'PATCH', url: `${base}/pages/projects/site`, headers: jsonAuth,
        body: JSON.stringify({ deployment_configs: { production: { env_vars: {
          API_KEY: { type: 'secret_text', value: 'test-new-secret' },
          CONFIG_KEY: { type: 'plain_text', value: 'test-new-plain' },
          NEW_KEY: { type: 'secret_text', value: 'test-added' },
        } } } }),
      },
      { method: 'GET', url: `${base}/pages/projects/site`, headers: auth },
    ]);
  });

  it.each([
    { name: 'a removed production variable', after: project({ API_KEY: { type: 'secret_text' } }, { MODE: { type: 'plain_text', value: 'preview' } }) },
    { name: 'a removed preview variable', after: project({ MODE: { type: 'plain_text', value: 'prod' }, API_KEY: { type: 'secret_text' } }, {}) },
    { name: 'a changed plain value', after: project({ MODE: { type: 'plain_text', value: 'changed' }, API_KEY: { type: 'secret_text' } }, { MODE: { type: 'plain_text', value: 'preview' } }) },
    { name: 'a write that did not land', after: project({ MODE: { type: 'plain_text', value: 'prod' } }, { MODE: { type: 'plain_text', value: 'preview' } }) },
  ])('fails a Pages write after detecting $name', async ({ after }) => {
    const marker = 'test-pages-new-secret';
    let reads = 0;
    const before = project({ MODE: { type: 'plain_text', value: 'prod' } }, { MODE: { type: 'plain_text', value: 'preview' } });
    const http = new FakeHttp()
      .on('GET', /\/pages\/projects\/site$/, () => ok(reads++ === 0 ? before : after))
      .on('PATCH', /\/pages\/projects\/site$/, () => ok({}));
    const error = await hostFor(http).writeVariables(pagesProduction, { API_KEY: marker }, { skipDeploy: true }).catch((caught: unknown) => caught);
    expect(String(error)).toMatch(/Cloudflare Pages variables changed/);
    expect(String(error)).not.toContain(marker);
  });

  it('refuses a Pages variable of an unknown type before writing', async () => {
    const http = new FakeHttp()
      .on('GET', /\/pages\/projects\/site$/, () => ok(project({ API_KEY: { type: 'future_type' } })))
      .on('PATCH', /./, () => ok({}));
    await expect(hostFor(http).writeVariables(pagesProduction, { API_KEY: 'test-new' }, { skipDeploy: true })).rejects.toThrow(/unsupported type/);
    expect(http.callsTo('PATCH', /./)).toEqual([]);
  });

  it('does not start a Pages deployment and warns that activation waits for the next one', async () => {
    const warnings: string[] = [];
    const http = new FakeHttp();
    expect(await hostFor(http, {}, warnings).redeploy(pagesProduction)).toBeNull();
    expect(http.calls).toEqual([]);
    expect(warnings).toEqual([expect.stringMatching(/new deployments/)]);
    await expect(hostFor(http).deploymentStatus(pagesProduction, 'x')).rejects.toThrow(/Cloudflare Pages/);
  });

  it.each([
    { ...worker, projectId: 'other-account' },
    { ...worker, host: 'vercel' as const },
    { ...worker, serviceId: 'unknown:api' },
    { ...worker, serviceId: 'worker:..' },
    { ...worker, environmentId: 'production' },
    { ...pagesProduction, environmentId: 'staging' },
  ])('rejects foreign or malformed service references before any request: %j', async (service) => {
    const http = new FakeHttp();
    await expect(hostFor(http).readVariables(service)).rejects.toThrow(/Cloudflare/);
    await expect(hostFor(http).writeVariables(service, { A: 'test-a' }, { skipDeploy: true })).rejects.toThrow(/Cloudflare/);
    expect(http.calls).toEqual([]);
  });

  it.each(['http', 'transport', 'json', 'unsuccessful', 'malformed'] as const)('sanitizes %s failures', async (failure) => {
    const marker = 'test-private-cloudflare-marker';
    const http = new FakeHttp().on('GET', /\/settings$/, () => {
      if (failure === 'transport') throw new Error(`${token} ${marker}`);
      if (failure === 'http') return json(500, { errors: [{ message: marker }] });
      if (failure === 'json') return text(200, marker);
      if (failure === 'unsuccessful') return json(200, { success: false, errors: [{ message: marker }] });
      return ok({ bindings: [{ name: marker, type: 'plain_text', text: { value: marker } }] });
    });
    const error = await hostFor(http).readVariables(worker).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).toMatch(/Cloudflare/);
    expect(String(error)).not.toContain(marker);
    expect(String(error)).not.toContain(token);
  });

  it('sanitizes a failed secret write without echoing the value', async () => {
    const marker = 'test-new-secret-marker';
    const http = serving(new FakeHttp()
      .on('GET', /\/settings$/, () => ok({ bindings: [] }))
      .on('PUT', /\/secrets$/, () => json(400, { success: false, errors: [{ message: marker }] })));
    const error = await hostFor(http).writeVariables(worker, { API_KEY: marker }, { skipDeploy: true }).catch((caught: unknown) => caught);
    expect(String(error)).toBe('Error: Cloudflare request failed (HTTP 400)');
  });
});
