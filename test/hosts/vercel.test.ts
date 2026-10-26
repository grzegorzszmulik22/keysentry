import { describe, expect, it, vi } from 'vitest';
import { createVercelHost } from '../../src/hosts/vercel.js';
import type { HttpRequest, ServiceRef } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const token = 'vercel-auth-token-for-tests';
const project: ServiceRef = {
  host: 'vercel',
  projectId: 'prj_site',
  projectName: 'site',
  serviceId: 'prj_site',
  serviceName: 'site',
  environmentId: 'production',
  environmentName: 'production',
};

function expectRequest(req: HttpRequest, method: HttpRequest['method'], path: string, query: Record<string, string> = {}) {
  const url = new URL(req.url);
  expect(req.method).toBe(method);
  expect(url.origin).toBe('https://api.vercel.com');
  expect(url.pathname).toBe(path);
  expect(Object.fromEntries(url.searchParams)).toEqual(query);
  expect(req.headers?.Authorization).toBe(`Bearer ${token}`);
  if (req.body !== undefined) expect(req.headers?.['Content-Type']).toBe('application/json');
}

describe('createVercelHost', () => {
  it('discovers one service per project and default production/preview target', async () => {
    const http = new FakeHttp().on('GET', /\/v10\/projects\?/, (req) => {
      expectRequest(req, 'GET', '/v10/projects', { limit: '100' });
      return json(200, { projects: [{ id: 'prj_site', name: 'site' }], pagination: { next: null } });
    });
    const host = createVercelHost({ token, http, log: silentLogger });

    expect(host.id).toBe('vercel');
    expect(host.capabilities).toEqual({ readValues: true, batchWrite: false, redeploy: true });
    await expect(host.listServices()).resolves.toEqual([
      project,
      { ...project, environmentId: 'preview', environmentName: 'preview' },
    ]);
  });

  it('follows next/until project pagination with team scope and explicit targets', async () => {
    const http = new FakeHttp().on('GET', /\/v10\/projects\?/, (req) => {
      const until = new URL(req.url).searchParams.get('until');
      expectRequest(req, 'GET', '/v10/projects', {
        limit: '100', teamId: 'team scope', ...(until === null ? {} : { until }),
      });
      if (until === null) return json(200, { projects: [{ id: 'prj_site', name: 'site' }], pagination: { next: 0 } });
      expect(until).toBe('0');
      return json(200, { projects: [{ id: 'prj_second', name: 'second' }], pagination: { next: null } });
    });
    const host = createVercelHost({ token, teamId: 'team scope', targets: ['development'], http, log: silentLogger });

    await expect(host.listServices()).resolves.toEqual([
      { ...project, environmentId: 'development', environmentName: 'development' },
      { ...project, projectId: 'prj_second', projectName: 'second', serviceId: 'prj_second', serviceName: 'second', environmentId: 'development', environmentName: 'development' },
    ]);
    expect(http.calls).toHaveLength(2);
  });

  it('does not loop forever on a repeated project pagination cursor', async () => {
    const http = new FakeHttp().on('GET', /\/v10\/projects\?/, () => json(200, { projects: [], pagination: { next: 12 } }));
    const host = createVercelHost({ token, http, log: silentLogger });

    await expect(host.listServices()).rejects.toThrow(/pagination/i);
    expect(http.calls).toHaveLength(2);
  });

  it('decrypts only matching readable entries and leaves sensitive/secret values sealed', async () => {
    const http = new FakeHttp()
      .on('GET', /\/v10\/projects\/prj_site\/env\?/, (req) => {
        expectRequest(req, 'GET', '/v10/projects/prj_site/env', { teamId: 'team_one' });
        return json(200, { envs: [
          { id: 'env_other', key: 'OTHER', type: 'encrypted', target: ['preview'] },
          { id: 'env_shared', key: 'API_KEY', type: 'encrypted', target: ['preview', 'production'] },
          { id: 'env_sensitive', key: 'SENSITIVE_KEY', type: 'sensitive', target: ['production'], value: 'must-not-return' },
          { id: 'env_secret', key: 'SECRET_KEY', type: 'secret', target: ['production'], value: 'must-not-return' },
          { id: 'env_empty', key: 'EMPTY', type: 'plain', target: ['production'] },
        ] });
      })
      .on('GET', /\/v1\/projects\/prj_site\/env\/env_shared\?/, (req) => {
        expectRequest(req, 'GET', '/v1/projects/prj_site/env/env_shared', { teamId: 'team_one' });
        return json(200, { value: 'readable-value' });
      })
      .on('GET', /\/v1\/projects\/prj_site\/env\/env_empty\?/, (req) => {
        expectRequest(req, 'GET', '/v1/projects/prj_site/env/env_empty', { teamId: 'team_one' });
        return json(200, { value: '' });
      });
    const host = createVercelHost({ token, teamId: 'team_one', http, log: silentLogger });

    await expect(host.readVariables(project)).resolves.toEqual([
      { name: 'API_KEY', value: 'readable-value', sealed: false },
      { name: 'SENSITIVE_KEY', sealed: true },
      { name: 'SECRET_KEY', sealed: true },
      { name: 'EMPTY', value: '', sealed: false },
    ]);
    expect(http.calls).toHaveLength(3);
  });

  it('reads subsequent environment pages before completing a scan', async () => {
    const http = new FakeHttp()
      .on('GET', /\/v10\/projects\/prj_site\/env/, (req) => {
        const until = new URL(req.url).searchParams.get('until');
        return json(200, { envs: until === null ? [] : [{ id: 'env_last', key: 'LAST', type: 'secret', target: ['production'] }], pagination: { next: until === null ? 'cursor' : null } });
      });
    const host = createVercelHost({ token, http, log: silentLogger });

    await expect(host.readVariables(project)).resolves.toEqual([{ name: 'LAST', sealed: true }]);
    expect(new URL(http.calls[1]!.url).searchParams.get('until')).toBe('cursor');
  });

  it('omits Vercel-managed system variables without decrypting them', async () => {
    const http = new FakeHttp().on('GET', /\/v10\/projects\/prj_site\/env$/, () => json(200, { envs: [
      { id: 'managed', key: 'VERCEL_SYSTEM_KEY', type: 'system', target: ['production'] },
      { id: 'user', key: 'USER_KEY', type: 'sensitive', target: ['production'] },
    ] }));
    const host = createVercelHost({ token, http, log: silentLogger });

    await expect(host.readVariables(project)).resolves.toEqual([{ name: 'USER_KEY', sealed: true }]);
    expect(http.calls).toHaveLength(1);
  });

  it('seals entries with secret visibility without decrypting their values', async () => {
    const http = new FakeHttp().on('GET', /\/v10\/projects\/prj_site\/env$/, () => json(200, { envs: [
      { id: 'hidden', key: 'HIDDEN_KEY', type: 'encrypted', visibility: 'secret', target: ['production'], value: 'must-not-return' },
    ] }));
    const host = createVercelHost({ token, http, log: silentLogger });

    await expect(host.readVariables(project)).resolves.toEqual([{ name: 'HIDDEN_KEY', sealed: true }]);
    expect(http.calls).toHaveLength(1);
  });

  it('reads entries with default visibility normally', async () => {
    const http = new FakeHttp()
      .on('GET', /\/v10\/projects\/prj_site\/env$/, () => json(200, { envs: [
        { id: 'readable', key: 'READABLE_KEY', type: 'encrypted', visibility: 'default', target: ['production'] },
      ] }))
      .on('GET', /\/v1\/projects\/prj_site\/env\/readable$/, () => json(200, { value: 'readable-value' }));
    const host = createVercelHost({ token, http, log: silentLogger });

    await expect(host.readVariables(project)).resolves.toEqual([{ name: 'READABLE_KEY', value: 'readable-value', sealed: false }]);
    expect(http.calls).toHaveLength(2);
  });

  it('seals entries when the decrypted detail omits a value', async () => {
    const http = new FakeHttp()
      .on('GET', /\/v10\/projects\/prj_site\/env$/, () => json(200, { envs: [
        { id: 'hidden', key: 'HIDDEN_KEY', type: 'encrypted', target: ['production'] },
      ] }))
      .on('GET', /\/v1\/projects\/prj_site\/env\/hidden$/, () => json(200, { id: 'hidden' }));
    const host = createVercelHost({ token, http, log: silentLogger });

    await expect(host.readVariables(project)).resolves.toEqual([{ name: 'HIDDEN_KEY', sealed: true }]);
    expect(http.calls).toHaveLength(2);
  });

  it.each([true, false])('patches only the existing key in the requested target, skipDeploy=%s', async (skipDeploy) => {
    const http = new FakeHttp()
      .on('GET', /\/v10\/projects\/prj_site\/env\?/, (req) => {
        expectRequest(req, 'GET', '/v10/projects/prj_site/env', { teamId: 'team_one' });
        return json(200, { envs: [
          { id: 'preview_key', key: 'API_KEY', type: 'encrypted', target: ['preview'] },
          { id: 'production_other', key: 'UNRELATED', type: 'encrypted', target: ['production'] },
          { id: 'production_key', key: 'API_KEY', type: 'encrypted', target: ['preview', 'production'] },
        ] });
      })
      .on('PATCH', /\/v9\/projects\/prj_site\/env\/production_key\?/, (req) => {
        expectRequest(req, 'PATCH', '/v9/projects/prj_site/env/production_key', { teamId: 'team_one' });
        expect(JSON.parse(req.body!)).toEqual({ value: 'new-private-value' });
        expect(req.url).not.toContain('new-private-value');
        return json(200, {});
      });
    const host = createVercelHost({ token, teamId: 'team_one', http, log: silentLogger });

    await host.writeVariables(project, { API_KEY: 'new-private-value' }, { skipDeploy });

    expect(http.calls).toHaveLength(2);
  });

  it('creates an encrypted variable when its key exists only in another target', async () => {
    const http = new FakeHttp()
      .on('GET', /\/v10\/projects\/prj_site\/env\?/, (req) => {
        expectRequest(req, 'GET', '/v10/projects/prj_site/env', { teamId: 'team_one' });
        return json(200, { envs: [{ id: 'preview_key', key: 'API_KEY', type: 'encrypted', target: ['preview'] }] });
      })
      .on('POST', /\/v10\/projects\/prj_site\/env\?/, (req) => {
        expectRequest(req, 'POST', '/v10/projects/prj_site/env', { upsert: 'true', teamId: 'team_one' });
        expect(JSON.parse(req.body!)).toEqual({ key: 'API_KEY', value: 'new-private-value', type: 'encrypted', target: ['production'] });
        expect(req.url).not.toContain('new-private-value');
        return json(200, { id: 'new-env' });
      });
    const host = createVercelHost({ token, teamId: 'team_one', http, log: silentLogger });

    await host.writeVariables(project, { API_KEY: 'new-private-value' }, { skipDeploy: true });

    expect(http.calls).toHaveLength(2);
  });

  it('writes exactly the requested keys without replacing the variable collection', async () => {
    const http = new FakeHttp()
      .on('GET', /\/v10\/projects\/prj_site\/env$/, () => json(200, { envs: [
        { id: 'existing', key: 'EXISTING', type: 'sensitive', target: ['production'] },
        { id: 'unrelated', key: 'UNRELATED', type: 'encrypted', target: ['production'] },
      ] }))
      .on('PATCH', /\/v9\/projects\/prj_site\/env\/existing$/, () => json(200, {}))
      .on('POST', /\/v10\/projects\/prj_site\/env\?upsert=true$/, () => json(200, {}));
    const host = createVercelHost({ token, http, log: silentLogger });

    await host.writeVariables(project, { EXISTING: 'replacement', MISSING: 'new-value' }, { skipDeploy: true });

    expect(http.calls).toHaveLength(3);
    expect(http.calls.filter((req) => req.method !== 'GET').map((req) => JSON.parse(req.body!))).toEqual([
      { value: 'replacement' },
      { key: 'MISSING', value: 'new-value', type: 'encrypted', target: ['production'] },
    ]);
  });

  it('does not request anything for an empty write', async () => {
    const http = new FakeHttp();
    const host = createVercelHost({ token, http, log: silentLogger });

    await host.writeVariables(project, {}, { skipDeploy: true });

    expect(http.calls).toEqual([]);
  });

  it.each(['production', 'preview'])('rejects requested system keys in %s before making any writes', async (target) => {
    const http = new FakeHttp().on('GET', /\/v10\/projects\/prj_site\/env$/, () => json(200, { envs: [
      { id: 'normal', key: 'USER_KEY', type: 'encrypted', target: ['production'] },
      { id: 'managed', key: 'VERCEL_SYSTEM_KEY', type: 'system', target: [target] },
    ] }));
    const host = createVercelHost({ token, http, log: silentLogger });

    await expect(host.writeVariables(project, { USER_KEY: 'new-value', VERCEL_SYSTEM_KEY: 'managed-new-value' }, { skipDeploy: true })).rejects.toThrow(/system|managed/i);
    expect(http.calls).toHaveLength(1);
  });

  it('skips ambiguous same-key/target entries with a warning while scanning other keys', async () => {
    const log = { ...silentLogger, warn: vi.fn() };
    const http = new FakeHttp()
      .on('GET', /\/v10\/projects\/prj_site\/env$/, () => json(200, { envs: [
        { id: 'safe', key: 'SAFE_KEY', type: 'encrypted', target: ['preview'] },
        { id: 'first', key: 'KEY', type: 'encrypted', target: ['preview'], gitBranch: 'branch-one', value: 'private-first-value' },
        { id: 'second', key: 'KEY', type: 'encrypted', target: ['preview'], gitBranch: 'branch-two', value: 'private-second-value' },
      ] }))
      .on('GET', /\/v1\/projects\/prj_site\/env\/safe$/, () => json(200, { value: 'safe-private-value' }));
    const host = createVercelHost({ token, http, log });

    await expect(host.readVariables({ ...project, environmentId: 'preview', environmentName: 'preview' })).resolves.toEqual([
      { name: 'SAFE_KEY', value: 'safe-private-value', sealed: false },
    ]);
    expect(http.calls).toHaveLength(2);
    expect(log.warn).toHaveBeenCalledTimes(1);
    const warning = JSON.stringify(log.warn.mock.calls);
    expect(warning).toMatch(/ambiguous|branch/i);
    expect(warning).toContain('KEY');
    expect(warning).toContain('preview');
    expect(warning).not.toContain('private-first-value');
    expect(warning).not.toContain('private-second-value');
  });

  it('rejects requested ambiguous same-key/target entries before making any writes', async () => {
    const http = new FakeHttp().on('GET', /\/v10\/projects\/prj_site\/env$/, () => json(200, { envs: [
      { id: 'safe', key: 'SAFE', type: 'secret', target: ['production'] },
      { id: 'first', key: 'KEY', type: 'secret', target: ['production'], gitBranch: 'branch-one' },
      { id: 'second', key: 'KEY', type: 'secret', target: ['production'], gitBranch: 'branch-two' },
    ] }));
    const host = createVercelHost({ token, http, log: silentLogger });

    const error = await host.writeVariables(project, { SAFE: 'other-new-value', KEY: 'new-private-value' }, { skipDeploy: true }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(Error);
    expect(String(error)).toMatch(/ambiguous/i);
    expect(String(error)).toContain('KEY');
    expect(String(error)).toContain('production');
    expect(String(error)).not.toContain('new-private-value');
    expect(http.calls).toHaveLength(1);
  });

  it('writes an unrelated key when other entries are ambiguous for the target', async () => {
    const http = new FakeHttp()
      .on('GET', /\/v10\/projects\/prj_site\/env$/, () => json(200, { envs: [
        { id: 'safe', key: 'SAFE', type: 'secret', target: ['production'] },
        { id: 'first', key: 'KEY', type: 'secret', target: ['production'], gitBranch: 'branch-one' },
        { id: 'second', key: 'KEY', type: 'secret', target: ['production'], gitBranch: 'branch-two' },
      ] }))
      .on('PATCH', /\/v9\/projects\/prj_site\/env\/safe$/, (req) => {
        expect(JSON.parse(req.body!)).toEqual({ value: 'other-new-value' });
        return json(200, {});
      });
    const host = createVercelHost({ token, http, log: silentLogger });

    await host.writeVariables(project, { SAFE: 'other-new-value' }, { skipDeploy: true });

    expect(http.calls).toHaveLength(2);
  });

  it('redeploys the currently serving production deployment after a rollback', async () => {
    const http = new FakeHttp()
      .on('GET', /\/v9\/projects\/prj%2Fsite\?/, (req) => {
        expectRequest(req, 'GET', '/v9/projects/prj%2Fsite', { teamId: 'team_one' });
        return json(200, { targets: { production: { id: 'dpl_serving' } } });
      })
      .on('GET', /\/v6\/deployments\?/, () => json(200, { deployments: [{ uid: 'dpl_newer_rolled_back' }] }))
      .on('POST', /\/v13\/deployments\?/, (req) => {
        expectRequest(req, 'POST', '/v13/deployments', { forceNew: '1', teamId: 'team_one' });
        expect(JSON.parse(req.body!)).toEqual({ name: 'site', deploymentId: 'dpl_serving', target: 'production' });
        return json(200, { id: 'dpl_new' });
      });
    const host = createVercelHost({ token, teamId: 'team_one', http, log: silentLogger });

    await expect(host.redeploy({ ...project, projectId: 'prj/site', serviceId: 'prj/site' })).resolves.toBe('dpl_new');
    expect(http.calls).toHaveLength(2);
    expect(http.callsTo('GET', /\/v6\/deployments\?/)).toHaveLength(0);
  });

  it.each([
    {}, { targets: null }, { targets: {} }, { targets: { production: null } },
    { targets: { production: {} } }, { targets: { production: { id: null } } },
  ])('warns and falls back to the latest ready production deployment when the serving ID is absent %#', async (body) => {
    const log = { ...silentLogger, warn: vi.fn() };
    const http = new FakeHttp()
      .on('GET', /\/v9\/projects\/prj_site\?/, (req) => {
        expectRequest(req, 'GET', '/v9/projects/prj_site', { teamId: 'team_one' });
        return json(200, body);
      })
      .on('GET', /\/v6\/deployments\?/, (req) => {
        expectRequest(req, 'GET', '/v6/deployments', { projectId: 'prj_site', target: 'production', state: 'READY', limit: '1', teamId: 'team_one' });
        return json(200, { deployments: [{ uid: 'dpl_previous' }] });
      })
      .on('POST', /\/v13\/deployments\?/, (req) => {
        expectRequest(req, 'POST', '/v13/deployments', { forceNew: '1', teamId: 'team_one' });
        expect(JSON.parse(req.body!)).toEqual({ name: 'site', deploymentId: 'dpl_previous', target: 'production' });
        return json(200, { id: 'dpl_new' });
      });
    const host = createVercelHost({ token, teamId: 'team_one', http, log });

    await expect(host.redeploy(project)).resolves.toBe('dpl_new');
    expect(http.calls).toHaveLength(3);
    expect(log.warn).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(log.warn.mock.calls)).toMatch(/latest ready|fall.?back/i);
  });

  it.each([
    null, { targets: [] }, { targets: { production: 'invalid' } },
    { targets: { production: { id: 42 } } }, { targets: { production: { id: '' } } },
  ])('does not fall back or deploy after a malformed project response %#', async (body) => {
    const http = new FakeHttp()
      .on('GET', /\/v9\/projects\/prj_site$/, () => json(200, body))
      .on('GET', /\/v6\/deployments\?/, () => json(200, { deployments: [{ uid: 'unsafe_latest' }] }))
      .on('POST', /\/v13\/deployments\?/, () => json(200, { id: 'unsafe_new' }));
    const host = createVercelHost({ token, http, log: silentLogger });

    await expect(host.redeploy(project)).rejects.toThrow(/invalid response/i);
    expect(http.calls).toHaveLength(1);
    expectRequest(http.calls[0]!, 'GET', '/v9/projects/prj_site');
  });

  it('does not fall back after a failed project lookup or expose its response', async () => {
    const http = new FakeHttp()
      .on('GET', /\/v9\/projects\/prj_site$/, () => json(403, { error: `Denied ${token}` }))
      .on('GET', /\/v6\/deployments\?/, () => json(200, { deployments: [{ uid: 'unsafe_latest' }] }))
      .on('POST', /\/v13\/deployments\?/, () => json(200, { id: 'unsafe_new' }));
    const host = createVercelHost({ token, http, log: silentLogger });

    const error = await host.redeploy(project).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(Error);
    expect(String(error)).not.toContain(token);
    expect(http.calls).toHaveLength(1);
    expectRequest(http.calls[0]!, 'GET', '/v9/projects/prj_site');
  });

  it('does not fall back or retry when deployment creation fails', async () => {
    const http = new FakeHttp()
      .on('GET', /\/v9\/projects\/prj_site$/, () => json(200, { targets: { production: { id: 'dpl_serving' } } }))
      .on('GET', /\/v6\/deployments\?/, () => json(200, { deployments: [{ uid: 'unsafe_latest' }] }))
      .on('POST', /\/v13\/deployments\?/, () => json(503, { error: `Unavailable ${token}` }));
    const host = createVercelHost({ token, http, log: silentLogger });

    await expect(host.redeploy(project)).rejects.toThrow(/vercel/i);
    expect(http.calls).toHaveLength(2);
    expect(http.callsTo('GET', /\/v6\/deployments\?/)).toHaveLength(0);
    expect(http.callsTo('POST', /\/v13\/deployments\?/)).toHaveLength(1);
  });

  it.each(['preview', 'development'])('does not redeploy %s targets', async (target) => {
    const http = new FakeHttp();
    const host = createVercelHost({ token, http, log: silentLogger });

    await expect(host.redeploy({ ...project, environmentId: target, environmentName: target })).resolves.toBeNull();
    expect(http.calls).toEqual([]);
  });

  it('fails closed when a production project has no ready deployment to redeploy', async () => {
    const http = new FakeHttp()
      .on('GET', /\/v9\/projects\/prj_site$/, () => json(200, {}))
      .on('GET', /\/v6\/deployments\?/, () => json(200, { deployments: [] }));
    const host = createVercelHost({ token, http, log: silentLogger });

    await expect(host.redeploy(project)).rejects.toThrow(/ready production deployment/i);
    expect(http.calls).toHaveLength(2);
  });

  it.each([
    ['READY', 'success'], ['ERROR', 'failed'], ['CANCELED', 'failed'],
    ['QUEUED', 'pending'], ['BUILDING', 'pending'], ['FUTURE_STATE', 'pending'],
  ])('maps deployment readyState %s to %s', async (readyState, expected) => {
    const http = new FakeHttp().on('GET', /\/v13\/deployments\/dpl%2Fnew\?/, (req) => {
      expectRequest(req, 'GET', '/v13/deployments/dpl%2Fnew', { teamId: 'team_one' });
      return json(200, { readyState });
    });
    const host = createVercelHost({ token, teamId: 'team_one', http, log: silentLogger });

    await expect(host.deploymentStatus(project, 'dpl/new')).resolves.toBe(expected);
  });

  it('encodes project and environment IDs in paths', async () => {
    const http = new FakeHttp()
      .on('GET', /\/v10\/projects\/prj%2Fencoded\/env$/, () => json(200, { envs: [{ id: 'env/encoded', key: 'KEY', type: 'encrypted', target: ['production'] }] }))
      .on('GET', /\/v1\/projects\/prj%2Fencoded\/env\/env%2Fencoded$/, () => json(200, { value: 'value' }));
    const host = createVercelHost({ token, http, log: silentLogger });

    await expect(host.readVariables({ ...project, projectId: 'prj/encoded', serviceId: 'prj/encoded' })).resolves.toEqual([{ name: 'KEY', value: 'value', sealed: false }]);
    expect(http.calls).toHaveLength(2);
  });

  it('does not expose secret-bearing HTTP response bodies or request headers', async () => {
    const value = 'private-value-must-not-escape';
    const log = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() };
    const http = new FakeHttp()
      .on('GET', /\/v10\/projects\/prj_site\/env$/, () => json(200, { envs: [] }))
      .on('POST', /\/v10\/projects\/prj_site\/env\?/, () => json(403, { error: `Denied ${value} ${token}` }));
    const host = createVercelHost({ token, http, log });

    const error = await host.writeVariables(project, { KEY: value }, { skipDeploy: true }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(Error);
    expect(http.calls).toHaveLength(2);
    expect(String(error)).not.toContain(value);
    expect(String(error)).not.toContain(token);
    expect(JSON.stringify(log.info.mock.calls.concat(log.warn.mock.calls, log.error.mock.calls, log.debug.mock.calls))).not.toContain(value);
    for (const req of http.calls) {
      expect(req.url).not.toContain(value);
      expect(req.url).not.toContain(token);
    }
  });

  it('does not propagate transport exception text', async () => {
    const http = new FakeHttp().on('GET', /\/v10\/projects\?/, () => { throw new Error(`connection failed ${token}`); });
    const host = createVercelHost({ token, http, log: silentLogger });

    const error = await host.listServices().catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(Error);
    expect(http.calls).toHaveLength(1);
    expect(String(error)).not.toContain(token);
  });

  it('does not propagate invalid JSON text', async () => {
    const http = new FakeHttp().on('GET', /\/v10\/projects\?/, () => text(200, `invalid ${token}`));
    const host = createVercelHost({ token, http, log: silentLogger });

    const error = await host.listServices().catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(Error);
    expect(http.calls).toHaveLength(1);
    expect(String(error)).not.toContain(token);
  });

  it.each([
    {}, { projects: null }, { projects: [{ id: 'prj_site', name: null }] },
    { projects: [], pagination: { next: { private: token } } },
  ])('rejects malformed project response %# without exposing its contents', async (body) => {
    const http = new FakeHttp().on('GET', /\/v10\/projects\?/, () => json(200, body));
    const host = createVercelHost({ token, http, log: silentLogger });

    await expect(host.listServices()).rejects.toThrow(/vercel/i);
    expect(http.calls).toHaveLength(1);
  });

  it('rejects malformed variable entries before making any writes', async () => {
    const http = new FakeHttp().on('GET', /\/v10\/projects\/prj_site\/env$/, () => json(200, { envs: [{ id: 'env_id', key: 'KEY', type: 'encrypted', target: 42 }] }));
    const host = createVercelHost({ token, http, log: silentLogger });

    await expect(host.writeVariables(project, { KEY: 'new-value' }, { skipDeploy: true })).rejects.toThrow(/vercel/i);
    expect(http.calls).toHaveLength(1);
  });

  it('rejects explicitly non-string decrypted values instead of reporting an unsealed variable', async () => {
    const http = new FakeHttp()
      .on('GET', /\/v10\/projects\/prj_site\/env$/, () => json(200, { envs: [{ id: 'env_id', key: 'KEY', type: 'encrypted', target: ['production'] }] }))
      .on('GET', /\/v1\/projects\/prj_site\/env\/env_id$/, () => json(200, { value: null }));
    const host = createVercelHost({ token, http, log: silentLogger });

    await expect(host.readVariables(project)).rejects.toThrow(/vercel/i);
    expect(http.calls).toHaveLength(2);
  });

  it('rejects a created deployment without an ID', async () => {
    const http = new FakeHttp()
      .on('GET', /\/v9\/projects\/prj_site$/, () => json(200, { targets: { production: { id: 'dpl_previous' } } }))
      .on('POST', /\/v13\/deployments\?/, () => json(200, {}));
    const host = createVercelHost({ token, http, log: silentLogger });

    await expect(host.redeploy(project)).rejects.toThrow(/vercel/i);
    expect(http.calls).toHaveLength(2);
  });
});
