import { describe, expect, it } from 'vitest';
import { createInfisicalHost, infisicalApiBase, type InfisicalHostOptions } from '../../src/hosts/infisical.js';
import type { HttpRequest, ServiceRef } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const api = 'https://app.infisical.com/api';
const accessToken = 'test-infisical-access-token-value';
const headers = { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' };
const projectId = 'proj_123';
const service: ServiceRef = {
  host: 'infisical', projectId, projectName: projectId, serviceId: '/backend', serviceName: '/backend',
  environmentId: 'prod', environmentName: 'prod',
};

function hostFor(http: FakeHttp, extra: Partial<InfisicalHostOptions> = {}) {
  return createInfisicalHost({
    auth: { accessToken }, projects: [{ projectId, environments: ['prod'] }], http, log: silentLogger, ...extra,
  });
}

const secret = (secretKey: string, extra: Record<string, unknown> = {}) => ({
  id: `id-${secretKey}`, _id: `id-${secretKey}`, workspace: projectId, environment: 'prod', version: 1, type: 'shared',
  secretKey, secretValue: `test-${secretKey.toLowerCase()}-value`, secretComment: '', secretValueHidden: false,
  secretPath: '/backend', createdAt: '2026-01-01T00:00:00Z', updatedAt: '2026-01-01T00:00:00Z', ...extra,
});

const listUrl = (path: string, recursive: boolean, values: boolean) => `${api}/v4/secrets?projectId=${projectId}&environment=prod`
  + `&secretPath=${encodeURIComponent(path)}&recursive=${recursive}&viewSecretValue=${values}`
  + '&expandSecretReferences=false&includeImports=false&includePersonalOverrides=false';

describe('Infisical host', () => {
  it('reports readable values, batch writes and no deployments', () => {
    const host = hostFor(new FakeHttp());
    expect(host.id).toBe('infisical');
    expect(host.capabilities).toEqual({ readValues: true, batchWrite: true, redeploy: false });
  });

  it('accepts only an https origin, optionally with the documented /api prefix', () => {
    expect(infisicalApiBase('https://eu.infisical.com')).toBe('https://eu.infisical.com/api');
    expect(infisicalApiBase('https://secrets.example.test/api/')).toBe('https://secrets.example.test/api');
    for (const bad of ['http://app.infisical.com', 'https://u:p@app.infisical.com', 'https://app.infisical.com/other', 'https://app.infisical.com/?a=1']) {
      expect(() => infisicalApiBase(bad)).toThrow(/Infisical site URL/);
    }
    expect(() => hostFor(new FakeHttp(), { projects: [{ projectId, environments: [] }] })).toThrow(/environment/);
    expect(() => hostFor(new FakeHttp(), { projects: [{ projectId, environments: ['prod'], secretPath: '/a/../b' }] })).toThrow(/path/);
  });

  it('lists one service per folder path from a recursive, value-free listing', async () => {
    const http = new FakeHttp().on('GET', /\/v4\/secrets\?/, () => json(200, {
      secrets: [
        secret('B', { secretPath: '/backend' }),
        secret('A', { secretPath: '/' }),
        secret('P', { secretPath: '/personal', type: 'personal' }),
        secret('C', { secretPath: '/backend/' }),
      ],
      imports: [],
    }));
    const refs = await hostFor(http).listServices();
    expect(refs).toEqual([{ ...service, serviceId: '/', serviceName: '/' }, service]);
    expect(http.calls).toEqual([{ method: 'GET', url: listUrl('/', true, false), headers }]);
  });

  it('reads shared values in one folder, sealing values the identity cannot see', async () => {
    const http = new FakeHttp().on('GET', /\/v4\/secrets\?/, () => json(200, {
      secrets: [
        secret('API_KEY'),
        secret('HIDDEN', { secretValue: '<hidden-by-infisical>', secretValueHidden: true }),
        secret('MINE', { type: 'personal', secretValue: 'test-personal' }),
        secret('REF', { secretValue: '${prod.shared.TOKEN}' }),
      ],
    }));
    expect(await hostFor(http).readVariables(service)).toEqual([
      { name: 'API_KEY', value: 'test-api_key-value', sealed: false },
      { name: 'HIDDEN', sealed: true },
      { name: 'REF', value: '${prod.shared.TOKEN}', sealed: false },
    ]);
    expect(http.calls).toEqual([{ method: 'GET', url: listUrl('/backend', false, true), headers }]);
  });

  it('updates existing keys and creates missing keys with the bulk endpoints', async () => {
    const http = new FakeHttp()
      .on('GET', /\/v4\/secrets\?/, () => json(200, { secrets: [secret('API_KEY'), secret('UNTOUCHED')] }))
      .on('PATCH', /\/v4\/secrets\/batch$/, () => json(200, { secrets: [secret('API_KEY')] }))
      .on('POST', /\/v4\/secrets\/batch$/, () => json(200, { secrets: [secret('ADDED')] }));
    await hostFor(http).writeVariables(service, { API_KEY: 'test-new-api', ADDED: 'test-added' }, { skipDeploy: true });
    expect(http.calls).toEqual([
      { method: 'GET', url: listUrl('/backend', false, false), headers },
      {
        method: 'PATCH', url: `${api}/v4/secrets/batch`, headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId, environment: 'prod', secretPath: '/backend', mode: 'failOnNotFound',
          secrets: [{ secretKey: 'API_KEY', secretValue: 'test-new-api' }],
        }),
      },
      {
        method: 'POST', url: `${api}/v4/secrets/batch`, headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId, environment: 'prod', secretPath: '/backend', secrets: [{ secretKey: 'ADDED', secretValue: 'test-added' }] }),
      },
    ]);
  });

  it('reports an approval-gated change as not applied, and refuses rotation-managed secrets', async () => {
    const gated = new FakeHttp()
      .on('GET', /\/v4\/secrets\?/, () => json(200, { secrets: [secret('API_KEY')] }))
      .on('PATCH', /\/v4\/secrets\/batch$/, () => json(200, { approval: { id: 'apr-1', policyId: 'pol', status: 'open' } }));
    await expect(hostFor(gated).writeVariables(service, { API_KEY: 'test-new' }, { skipDeploy: true })).rejects.toThrow(/approval/);

    const rotated = new FakeHttp().on('GET', /\/v4\/secrets\?/, () => json(200, { secrets: [secret('DB_PASSWORD', { isRotatedSecret: true })] }));
    await expect(hostFor(rotated).writeVariables(service, { DB_PASSWORD: 'test-new' }, { skipDeploy: true })).rejects.toThrow(/secret rotation/);
    expect(rotated.calls).toHaveLength(1);
  });

  it('logs in with Universal Auth, reuses the token and renews it before expiry', async () => {
    let issued = 0;
    let clock = Date.parse('2026-10-28T10:00:00Z');
    const http = new FakeHttp()
      .on('POST', /\/v1\/auth\/universal-auth\/login$/, () => {
        issued += 1;
        return json(200, { accessToken: `test-issued-token-${issued}`, expiresIn: 600, accessTokenMaxTTL: 2592000, tokenType: 'Bearer' });
      })
      .on('GET', /\/v4\/secrets\?/, () => json(200, { secrets: [] }));
    const host = hostFor(http, {
      auth: { clientId: 'client-id', clientSecret: 'test-client-secret-value', organizationSlug: 'acme' },
      now: () => new Date(clock),
    });
    await host.readVariables(service);
    await host.readVariables(service);
    clock += 541_000;
    await host.readVariables(service);

    expect(http.calls[0]).toEqual({
      method: 'POST', url: `${api}/v1/auth/universal-auth/login`, headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientId: 'client-id', clientSecret: 'test-client-secret-value', organizationSlug: 'acme' }),
    });
    const auths = http.callsTo('GET', /./).map((call: HttpRequest) => call.headers?.Authorization);
    expect(auths).toEqual(['Bearer test-issued-token-1', 'Bearer test-issued-token-1', 'Bearer test-issued-token-2']);
    expect(http.calls.every((call) => !call.url.includes('test-client-secret-value') && !call.url.includes('test-issued-token'))).toBe(true);
  });

  it('sanitizes a failed login', async () => {
    const http = new FakeHttp().on('POST', /login$/, () => json(401, { message: 'planted-login-marker test-client-secret-value' }));
    const error = await hostFor(http, { auth: { clientId: 'c', clientSecret: 'test-client-secret-value' } }).readVariables(service)
      .catch((caught: unknown) => caught);
    expect(String(error)).toBe('Error: Infisical login failed (HTTP 401)');
  });

  it.each(['http', 'transport', 'json'] as const)('sanitizes a %s failure', async (failure) => {
    const marker = 'test-planted-infisical-marker';
    const http = new FakeHttp().on('GET', /./, () => {
      if (failure === 'transport') throw new Error(`${accessToken} ${marker}`);
      return failure === 'http' ? json(403, { message: marker }) : text(200, `{${marker}`);
    });
    const error = await hostFor(http).readVariables(service).catch((caught: unknown) => caught);
    expect(String(error)).toMatch(/Infisical/);
    expect(String(error)).not.toContain(marker);
    expect(String(error)).not.toContain(accessToken);
  });

  it('does not deploy', async () => {
    expect(await hostFor(new FakeHttp()).redeploy(service)).toBeNull();
    await expect(hostFor(new FakeHttp()).deploymentStatus(service, 'x')).rejects.toThrow(/does not create deployments/);
  });
});
