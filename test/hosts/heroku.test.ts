import { describe, expect, it } from 'vitest';
import { createHerokuHost } from '../../src/hosts/heroku.js';
import type { HttpRequest, ServiceRef } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const base = 'https://api.heroku.com';
const token = 'heroku-test-token';
const accept = 'application/vnd.heroku+json; version=3';
const readHeaders = { Authorization: `Bearer ${token}`, Accept: accept };
const writeHeaders = { ...readHeaders, 'Content-Type': 'application/json' };
const firstRange = 'id ..; max=1000;';
const newestRange = 'version ..; order=desc,max=1;';
const app: ServiceRef = {
  host: 'heroku',
  projectId: 'app-uuid-1',
  projectName: 'api-prod',
  serviceId: 'app-uuid-1',
  serviceName: 'api-prod',
  environmentId: '',
  environmentName: '',
};

const hostFor = (http: FakeHttp, extra: { apps?: string[]; team?: string; warn?: (msg: string) => void; info?: (msg: string) => void } = {}) =>
  createHerokuHost({
    token, http, apps: extra.apps, team: extra.team,
    log: { ...silentLogger, ...(extra.warn ? { warn: extra.warn } : {}), ...(extra.info ? { info: extra.info } : {}) },
  });

function addons(configVars: string[][] = []) {
  return json(200, configVars.map((names, index) => ({ id: `addon-${index}`, name: `addon-${index}`, config_vars: names })));
}

function release(id: string, version: number, extra: Record<string, unknown> = {}) {
  return { id, version, status: 'succeeded', current: true, description: 'Set config vars', ...extra };
}

async function failure(promise: Promise<unknown>): Promise<string> {
  const error = await promise.then(() => undefined, (caught: unknown) => caught);
  expect(error).toBeInstanceOf(Error);
  return String(error);
}

describe('Heroku host', () => {
  it('reports readable values, single-request writes, and release tracking', () => {
    const host = hostFor(new FakeHttp());
    expect(host.id).toBe('heroku');
    expect(host.capabilities).toEqual({ readValues: true, batchWrite: true, redeploy: true, activation: 'on-write' });
  });

  it('lists every app across Range pages with the versioned Accept header', async () => {
    const http = new FakeHttp().on('GET', /\/apps$/, (req) => {
      if (req.headers?.Range === firstRange) {
        return json(206, [{ id: 'app-uuid-1', name: 'api-prod' }], { 'next-range': 'id ]app-uuid-1..; max=1000;' });
      }
      expect(req.headers?.Range).toBe('id ]app-uuid-1..; max=1000;');
      return json(200, [{ id: 'app-uuid-2', name: 'worker-prod' }]);
    });

    expect(await hostFor(http).listServices()).toEqual([
      app,
      { ...app, projectId: 'app-uuid-2', projectName: 'worker-prod', serviceId: 'app-uuid-2', serviceName: 'worker-prod' },
    ]);
    expect(http.calls).toEqual([
      { method: 'GET', url: `${base}/apps`, headers: { ...readHeaders, Range: firstRange } },
      { method: 'GET', url: `${base}/apps`, headers: { ...readHeaders, Range: 'id ]app-uuid-1..; max=1000;' } },
    ]);
  });

  it('matches the Next-Range header case-insensitively', async () => {
    const http = new FakeHttp().on('GET', /\/apps$/, (req) => req.headers?.Range === firstRange
      ? json(206, [{ id: 'app-uuid-1', name: 'api-prod' }], { 'Next-Range': 'id ]app-uuid-1..;' })
      : json(200, []));
    expect(await hostFor(http).listServices()).toEqual([app]);
    expect(http.calls[1]?.headers?.Range).toBe('id ]app-uuid-1..;');
  });

  it('lists only the configured team apps', async () => {
    const http = new FakeHttp().on('GET', /\/teams\/acme%20team\/apps$/, () => json(200, [{ id: 'app-uuid-1', name: 'api-prod' }]));
    expect(await hostFor(http, { team: 'acme team' }).listServices()).toEqual([app]);
    expect(http.calls).toEqual([
      { method: 'GET', url: `${base}/teams/acme%20team/apps`, headers: { ...readHeaders, Range: firstRange } },
    ]);
  });

  it('looks up configured apps by name or id and removes duplicates', async () => {
    const http = new FakeHttp().on('GET', /\/apps\/(api-prod|app-uuid-1)$/, () => json(200, { id: 'app-uuid-1', name: 'api-prod', owner: { email: 'x' } }));
    expect(await hostFor(http, { apps: ['api-prod', 'app-uuid-1', 'api-prod'] }).listServices()).toEqual([app]);
    expect(http.calls.map((call) => call.url)).toEqual([`${base}/apps/api-prod`, `${base}/apps/app-uuid-1`]);
    expect(http.calls.every((call) => call.headers?.Range === undefined)).toBe(true);
  });

  it.each(['', '.', '..'])('rejects the unsafe configured app identifier %j before any request', async (name) => {
    const http = new FakeHttp();
    await expect(hostFor(http, { apps: [name] }).listServices()).rejects.toThrow(/Heroku/);
    expect(http.calls).toEqual([]);
  });

  it('stops when Next-Range repeats instead of looping', async () => {
    const http = new FakeHttp().on('GET', /\/apps$/, () => json(206, [{ id: 'app-uuid-1', name: 'api-prod' }], { 'next-range': 'id ]stuck..;' }));
    expect(await failure(hostFor(http).listServices())).toMatch(/Heroku pagination/);
    expect(http.calls).toHaveLength(2);
  });

  it('rejects a partial response without a Next-Range header', async () => {
    const http = new FakeHttp().on('GET', /\/apps$/, () => json(206, [{ id: 'app-uuid-1', name: 'api-prod' }]));
    expect(await failure(hostFor(http).listServices())).toMatch(/Heroku/);
    expect(http.calls).toHaveLength(1);
  });

  it('reads every config var as a readable value', async () => {
    const http = new FakeHttp().on('GET', /\/apps\/app-uuid-1\/config-vars$/, () => json(200, {
      OPENAI_API_KEY: 'test-current-value', EMPTY: '',
    }));
    expect(await hostFor(http).readVariables(app)).toEqual([
      { name: 'OPENAI_API_KEY', value: 'test-current-value', sealed: false },
      { name: 'EMPTY', value: '', sealed: false },
    ]);
    expect(http.calls).toEqual([{ method: 'GET', url: `${base}/apps/app-uuid-1/config-vars`, headers: readHeaders }]);
  });

  it.each([
    [null],
    [['list']],
    [{ KEY: { nested: 'test-private-response-marker' } }],
    [{ KEY: null }],
  ])('rejects malformed config vars without echoing them: %j', async (body) => {
    const http = new FakeHttp().on('GET', /\/config-vars$/, () => json(200, body));
    const message = await failure(hostFor(http).readVariables(app));
    expect(message).toMatch(/Heroku/);
    expect(message).not.toContain('test-private-response-marker');
  });

  it('writes exactly the requested vars in one PATCH and records the release it created', async () => {
    const infos: string[] = [];
    const http = new FakeHttp()
      .on('GET', /\/apps\/app-uuid-1\/addons$/, () => addons([['DATABASE_URL']]))
      .on('PATCH', /\/apps\/app-uuid-1\/config-vars$/, () => json(200, { OPENAI_API_KEY: 'test-new-value', OTHER: 'kept' }))
      .on('GET', /\/apps\/app-uuid-1\/releases$/, () => json(206, [release('release-42', 42)]));
    const host = hostFor(http, { info: (msg) => infos.push(msg) });

    await host.writeVariables(app, { OPENAI_API_KEY: 'test-new-value', AWS_ACCESS_KEY_ID: 'AKIA-test' }, { skipDeploy: true });
    expect(http.calls).toEqual([
      { method: 'GET', url: `${base}/apps/app-uuid-1/addons`, headers: { ...readHeaders, Range: firstRange } },
      {
        method: 'PATCH', url: `${base}/apps/app-uuid-1/config-vars`, headers: writeHeaders,
        body: JSON.stringify({ OPENAI_API_KEY: 'test-new-value', AWS_ACCESS_KEY_ID: 'AKIA-test' }),
      },
      { method: 'GET', url: `${base}/apps/app-uuid-1/releases`, headers: { ...readHeaders, Range: newestRange } },
    ]);
    expect(infos.join(' ')).toMatch(/release/i);
    expect(infos.join(' ')).not.toContain('test-new-value');

    // The write already started the release; redeploy only identifies it.
    expect(await host.redeploy(app)).toBe('release-42');
    expect(http.calls).toHaveLength(3);
  });

  it('never sends null (which deletes a var) and makes no extra restart call when skipDeploy is false', async () => {
    const http = new FakeHttp()
      .on('GET', /\/addons$/, () => addons())
      .on('PATCH', /\/config-vars$/, () => json(200, {}))
      .on('GET', /\/releases$/, () => json(200, [release('release-7', 7)]));
    await hostFor(http).writeVariables(app, { EMPTY: '' }, { skipDeploy: false });
    const patch = http.calls.find((call) => call.method === 'PATCH');
    expect(JSON.parse(patch?.body ?? 'null')).toEqual({ EMPTY: '' });
    expect(http.calls.map((call) => call.method)).toEqual(['GET', 'PATCH', 'GET']);
  });

  it('refuses add-on managed config vars before any change', async () => {
    const http = new FakeHttp()
      .on('GET', /\/addons$/, () => addons([['REDIS_URL'], ['DATABASE_URL', 'DATABASE_CREDENTIALS']]))
      .on('PATCH', /\/config-vars$/, () => json(200, {}));
    const message = await failure(hostFor(http).writeVariables(app, { API_KEY: 'test-new-value', DATABASE_URL: 'postgres://u:test-secret@h/db' }, { skipDeploy: true }));
    expect(message).toMatch(/add-on/);
    expect(message).not.toContain('test-secret');
    expect(http.calls.map((call) => call.method)).toEqual(['GET']);
  });

  it.each(['', 'BAD-NAME', 'has space', 'dot.name'])('rejects the invalid config var name %j before any request', async (name) => {
    const http = new FakeHttp();
    await expect(hostFor(http).writeVariables(app, { OK_NAME: 'test-new-value', [name]: 'test-new-value' }, { skipDeploy: true }))
      .rejects.toThrow(/Heroku/);
    expect(http.calls).toEqual([]);
  });

  it('does nothing for an empty update', async () => {
    const http = new FakeHttp();
    await hostFor(http).writeVariables(app, {}, { skipDeploy: true });
    expect(http.calls).toEqual([]);
  });

  it('keeps a successful write when the follow-up release lookup fails, then falls back to the newest release', async () => {
    const warnings: string[] = [];
    let releaseCalls = 0;
    const http = new FakeHttp()
      .on('GET', /\/addons$/, () => addons())
      .on('PATCH', /\/config-vars$/, () => json(200, {}))
      .on('GET', /\/releases$/, () => (++releaseCalls === 1 ? json(503, { id: 'unavailable' }) : json(206, [release('release-9', 9)])));
    const host = hostFor(http, { warn: (msg) => warnings.push(msg) });

    await host.writeVariables(app, { API_KEY: 'test-new-value' }, { skipDeploy: true });
    expect(warnings).toHaveLength(1);
    expect(await host.redeploy(app)).toBe('release-9');
    expect(http.calls.at(-1)).toEqual({ method: 'GET', url: `${base}/apps/app-uuid-1/releases`, headers: { ...readHeaders, Range: newestRange } });
  });

  it('uses the newest release on a fresh adapter and returns null when the app has none', async () => {
    const withRelease = new FakeHttp().on('GET', /\/releases$/, () => json(206, [release('release-3', 3)]));
    expect(await hostFor(withRelease).redeploy(app)).toBe('release-3');
    expect(withRelease.calls).toEqual([{ method: 'GET', url: `${base}/apps/app-uuid-1/releases`, headers: { ...readHeaders, Range: newestRange } }]);

    const warnings: string[] = [];
    const empty = new FakeHttp().on('GET', /\/releases$/, () => json(200, []));
    expect(await hostFor(empty, { warn: (msg) => warnings.push(msg) }).redeploy(app)).toBeNull();
    expect(warnings).toHaveLength(1);
    expect(empty.calls.every((call: HttpRequest) => call.method === 'GET')).toBe(true);
  });

  it.each([
    [{ status: 'succeeded', current: true }, 'success'],
    [{ status: 'succeeded', current: false }, 'failed'],
    [{ status: 'succeeded' }, 'failed'],
    [{ status: 'failed', current: false }, 'failed'],
    [{ status: 'expired', current: false }, 'failed'],
    [{ status: 'pending', current: false }, 'pending'],
  ] as const)('maps release %j to %s', async (fields, expected) => {
    const http = new FakeHttp().on('GET', /\/apps\/app-uuid-1\/releases\/release%2F1$/, () => json(200, { id: 'release/1', version: 1, ...fields }));
    expect(await hostFor(http).deploymentStatus(app, 'release/1')).toBe(expected);
    expect(http.calls).toEqual([{ method: 'GET', url: `${base}/apps/app-uuid-1/releases/release%2F1`, headers: readHeaders }]);
  });

  it.each(['http', 'transport', 'json'] as const)('sanitizes %s failures during writes', async (kind) => {
    const marker = 'test-private-error-marker';
    const http = new FakeHttp()
      .on('GET', /\/addons$/, () => addons())
      .on('PATCH', /\/config-vars$/, () => {
        if (kind === 'transport') throw new Error(`${token} ${marker}`);
        return kind === 'http' ? json(422, { message: marker }) : text(200, marker);
      });
    const message = await failure(hostFor(http).writeVariables(app, { API_KEY: marker }, { skipDeploy: true }));
    expect(message).toMatch(/Heroku/);
    expect(message).not.toContain(marker);
    expect(message).not.toContain(token);
  });

  it('includes only the HTTP status in errors', async () => {
    const http = new FakeHttp().on('GET', /\/config-vars$/, () => json(403, { id: 'forbidden', message: 'test-private-error-marker' }));
    expect(await failure(hostFor(http).readVariables(app))).toBe('Error: Heroku request failed (HTTP 403)');
  });
});
