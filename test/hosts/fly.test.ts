import { describe, expect, it } from 'vitest';
import { createFlyHost } from '../../src/hosts/fly.js';
import type { Logger, ServiceRef } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const graphql = /^https:\/\/api\.fly\.io\/graphql$/;
const service: ServiceRef = {
  host: 'fly', projectId: 'demo-app', projectName: 'demo-app',
  serviceId: 'demo-app', serviceName: 'demo-app', environmentId: '', environmentName: '',
};

describe('Fly host', () => {
  it('lists configured apps without making a network request', async () => {
    const http = new FakeHttp();
    const host = createFlyHost({ token: 'fly-token', apps: ['demo-app', 'second-app'], http, log: silentLogger });

    expect(await host.listServices()).toEqual([
      service,
      { ...service, projectId: 'second-app', projectName: 'second-app', serviceId: 'second-app', serviceName: 'second-app' },
    ]);
    expect(http.calls).toHaveLength(0);
    expect(host.id).toBe('fly');
    expect(host.capabilities).toEqual({ readValues: false, batchWrite: true, redeploy: true });
  });

  it('lists organization apps through Machines using app names as GraphQL identifiers', async () => {
    const http = new FakeHttp().on('GET', /^https:\/\/api\.machines\.dev\/v1\/apps\?org_slug=example-org$/, (req) => {
      expect(req.headers?.Authorization).toBe('Bearer fly-token');
      expect(req.body).toBeUndefined();
      return json(200, { total_apps: 1, apps: [{ id: 'machines-opaque-id', name: 'demo-app', status: 'deployed' }] });
    });
    const host = createFlyHost({ token: 'fly-token', org: 'example-org', http, log: silentLogger });

    expect(await host.listServices()).toEqual([service]);
    expect(http.calls).toHaveLength(1);
  });

  it('fails safely when app discovery has no organization or configured app list', async () => {
    const http = new FakeHttp();
    const host = createFlyHost({ token: 'fly-token', http, log: silentLogger });

    await expect(host.listServices()).rejects.toThrow(/organization|org|apps/i);
    expect(http.calls).toHaveLength(0);
  });

  it('reads names as sealed without returning digest or any response values', async () => {
    const http = new FakeHttp().on('POST', graphql, (req) => {
      expect(req.headers?.Authorization).toBe('Bearer fly-token');
      expect(req.headers?.['Content-Type']).toBe('application/json');
      const body = JSON.parse(req.body!);
      expect(body.query).toMatch(/app\(name:\s*\$name\)/);
      expect(body.query).toMatch(/secrets\s*\{\s*name\s+digest\s+createdAt/);
      expect(body.variables).toEqual({ name: 'demo-app' });
      return json(200, { data: { app: { secrets: [
        { name: 'API_KEY', digest: 'hash', createdAt: '2026-01-01', value: 'must-not-return' },
        { name: 'OTHER_KEY', digest: 'other', createdAt: '2026-01-02' },
      ] } } });
    });
    const host = createFlyHost({ token: 'fly-token', apps: ['demo-app'], http, log: silentLogger });

    expect(await host.readVariables(service)).toEqual([
      { name: 'API_KEY', sealed: true }, { name: 'OTHER_KEY', sealed: true },
    ]);
    expect(http.calls).toHaveLength(1);
  });

  it.each([true, false])('batches an additive staged write with skipDeploy=%s', async (skipDeploy) => {
    const http = new FakeHttp().on('POST', graphql, (req) => {
      expect(req.headers?.Authorization).toBe('Bearer fly-token');
      expect(req.headers?.['Content-Type']).toBe('application/json');
      const body = JSON.parse(req.body!);
      expect(body.query).toMatch(/setSecrets\(input:\s*\$input\)/);
      expect(body.variables).toEqual({ input: {
        appId: 'demo-app',
        secrets: [{ key: 'FIRST_KEY', value: 'first-secret-value' }, { key: 'SECOND_KEY', value: 'second-secret-value' }],
        replaceAll: false,
        stage: true,
      } });
      expect(req.url).not.toContain('secret-value');
      return json(200, { data: { setSecrets: { app: { name: 'demo-app' } } } });
    });
    const host = createFlyHost({ token: 'fly-token', http, log: silentLogger });

    await host.writeVariables(service, { FIRST_KEY: 'first-secret-value', SECOND_KEY: 'second-secret-value' }, { skipDeploy });
    expect(http.calls).toHaveLength(1);
  });

  it('does not send an empty secret mutation', async () => {
    const http = new FakeHttp();
    const host = createFlyHost({ token: 'fly-token', http, log: silentLogger });

    await host.writeVariables(service, {}, { skipDeploy: true });
    expect(http.calls).toHaveLength(0);
  });

  it('fails closed without an unstaged fallback when staging is unsupported', async () => {
    const http = new FakeHttp().on('POST', graphql, () => json(200, {
      errors: [{ message: 'stage is unsupported; echoed first-secret-value and fly-token' }],
    }));
    const host = createFlyHost({ token: 'fly-token', http, log: silentLogger });

    const error = await host.writeVariables(service, { API_KEY: 'first-secret-value' }, { skipDeploy: true }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).toMatch(/Fly|fly/);
    expect(String(error)).not.toContain('first-secret-value');
    expect(String(error)).not.toContain('fly-token');
    expect(http.calls).toHaveLength(1);
  });

  it.each([
    { data: { setSecrets: {} } },
    { data: { setSecrets: { app: null } } },
    { data: { setSecrets: { app: { name: 'different-app' } } } },
  ])('rejects a mutation response that does not confirm the requested app', async (body) => {
    const http = new FakeHttp().on('POST', graphql, () => json(200, body));
    const host = createFlyHost({ token: 'fly-token', http, log: silentLogger });

    await expect(host.writeVariables(service, { API_KEY: 'first-secret-value' }, { skipDeploy: true })).rejects.toThrow(/confirm|app/i);
    expect(http.calls).toHaveLength(1);
  });

  it('provides the manual deployment command without starting a deployment', async () => {
    const warnings: string[] = [];
    const log: Logger = { ...silentLogger, warn: (message) => { warnings.push(message); } };
    const http = new FakeHttp();
    const host = createFlyHost({ token: 'fly-token', http, log });

    expect(await host.redeploy(service)).toBeNull();
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('fly secrets deploy -a demo-app');
    expect(http.calls).toHaveLength(0);
    await expect(host.deploymentStatus(service, 'unknown-id')).rejects.toThrow(/status|support|deploy/i);
    expect(http.calls).toHaveLength(0);
  });

  it.each([
    { data: { app: null } },
    { data: { app: { secrets: null } } },
    { data: { app: { secrets: [{ digest: 'hash' }] } } },
    { data: { app: { secrets: [] } }, errors: [{ message: 'echoed-secret' }] },
  ])('rejects incomplete secret reads without copying response text', async (body) => {
    const http = new FakeHttp().on('POST', graphql, () => json(200, body));
    const host = createFlyHost({ token: 'fly-token', http, log: silentLogger });

    const error = await host.readVariables(service).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).not.toContain('echoed-secret');
  });

  it.each([
    { status: 403, body: 'echoed-secret fly-token' },
    { status: 200, body: '{invalid-json echoed-secret fly-token' },
  ])('sanitizes HTTP and JSON failures', async ({ status, body }) => {
    const http = new FakeHttp().on('POST', graphql, () => text(status, body));
    const host = createFlyHost({ token: 'fly-token', http, log: silentLogger });

    const error = await host.readVariables(service).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).not.toContain('echoed-secret');
    expect(String(error)).not.toContain('fly-token');
  });

  it('sanitizes transport errors that may echo credentials', async () => {
    const http = new FakeHttp().on('POST', graphql, () => { throw new Error('echoed-secret fly-token'); });
    const host = createFlyHost({ token: 'fly-token', http, log: silentLogger });

    const error = await host.readVariables(service).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).not.toContain('echoed-secret');
    expect(String(error)).not.toContain('fly-token');
  });
});
