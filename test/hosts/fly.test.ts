import { describe, expect, it } from 'vitest';
import { createFlyHost } from '../../src/hosts/fly.js';
import type { ServiceRef } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const graphql = /^https:\/\/api\.fly\.io\/graphql$/;
const service: ServiceRef = {
  host: 'fly', projectId: 'demo-app', projectName: 'demo-app',
  serviceId: 'demo-app', serviceName: 'demo-app', environmentId: '', environmentName: '',
};
const machinesUrl = 'https://api.machines.dev/v1/apps/demo-app/machines';
const machine = (id: string, state = 'started') => ({
  id, state, version: `old-${id}`,
  config: { image: 'registry.fly.io/demo-app@sha256:123', env: { PORT: '8080' }, services: [{ internal_port: 8080 }] },
});
const deploymentId = (machines: { id: string; version: string; wasRunning: boolean }[], app = 'demo-app') =>
  Buffer.from(JSON.stringify({ app, machines })).toString('base64url');
const hostFor = (http: FakeHttp, token = 'fly-token') => createFlyHost({ token, http, log: silentLogger });

function deploymentRoutes(http: FakeHttp, listed = [machine('a')]): FakeHttp {
  return http
    .on('GET', /\/apps\/[^/]+\/machines$/, () => json(200, listed))
    .on('POST', /\/machines\/([^/]+)\/lease$/, (_req, match) => json(200, { nonce: `lease-${match[1]}` }))
    .on('POST', /\/machines\/([^/]+)$/, (_req, match) => json(200, { id: match[1], version: `new-${match[1]}` }))
    .on('DELETE', /\/machines\/[^/]+\/lease$/, () => text(204, ''))
    .on('GET', /\/machines\/([^/]+)\/wait\?state=started&version=new-[^&]+&timeout=25$/, (_req, match) =>
      json(200, { ok: true, state: 'started', version: `new-${match[1]}` }));
}

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

  // Phase 2 uses the verified Machines secrets endpoint instead of the old
  // GraphQL stage mutation, and activation is a separate Machines update.
  it.each([true, false])('writeVariables posts secrets to the Machines API and records the version with skipDeploy=%s', async (skipDeploy) => {
    const http = deploymentRoutes(new FakeHttp().on('POST', /\/apps\/demo-app\/secrets$/, () =>
      json(200, { version: 42, secrets: [{ name: 'FIRST_KEY', digest: 'hash' }] })));
    const host = hostFor(http);

    await host.writeVariables(service, { FIRST_KEY: 'first-secret-value', SECOND_KEY: 'second-secret-value' }, { skipDeploy });
    expect(http.calls).toEqual([{
      method: 'POST', url: 'https://api.machines.dev/v1/apps/demo-app/secrets',
      headers: { Authorization: 'Bearer fly-token', 'Content-Type': 'application/json' },
      body: JSON.stringify({ values: { FIRST_KEY: 'first-secret-value', SECOND_KEY: 'second-secret-value' } }),
    }]);
    await host.redeploy(service);
    const update = http.callsTo('POST', /\/machines\/a$/)[0]!;
    expect(JSON.parse(update.body!)).toEqual({
      config: { image: 'registry.fly.io/demo-app@sha256:123', env: { PORT: '8080' }, services: [{ internal_port: 8080 }] },
      min_secrets_version: 42, current_version: 'old-a', skip_launch: false,
    });
  });

  it('does not send an empty secret mutation', async () => {
    const http = new FakeHttp();
    const host = createFlyHost({ token: 'fly-token', http, log: silentLogger });

    await host.writeVariables(service, {}, { skipDeploy: true });
    expect(http.calls).toHaveLength(0);
  });

  it('redeploy updates every machine under a lease in global id order, waiting before the next update', async () => {
    const http = deploymentRoutes(new FakeHttp()
      .on('GET', /\/machines$/, () => json(200, [machine('z')], { 'Fly-Next-Cursor': 'next / page' }))
      .on('GET', /\/machines\?cursor=next%20%2F%20page$/, () => json(200, [machine('a')])));
    const id = await hostFor(http).redeploy(service);

    expect(http.calls.map((call) => `${call.method} ${call.url}`)).toEqual([
      `GET ${machinesUrl}`, `GET ${machinesUrl}?cursor=next%20%2F%20page`,
      `POST ${machinesUrl}/a/lease`, `POST ${machinesUrl}/a`, `DELETE ${machinesUrl}/a/lease`,
      `GET ${machinesUrl}/a/wait?state=started&version=new-a&timeout=25`,
      `POST ${machinesUrl}/z/lease`, `POST ${machinesUrl}/z`, `DELETE ${machinesUrl}/z/lease`,
      `GET ${machinesUrl}/z/wait?state=started&version=new-z&timeout=25`,
    ]);
    for (const call of http.callsTo('POST', /\/lease$/)) {
      expect(JSON.parse(call.body!)).toEqual({ ttl: 120, description: 'keysentry secrets update' });
    }
    for (const call of http.calls.filter((call) => /\/machines\/[az](\/lease)?$/.test(call.url) && call.method !== 'GET')) {
      const machineId = /\/machines\/([az])/.exec(call.url)![1];
      if (call.method === 'DELETE' || !call.url.endsWith('/lease')) {
        expect(call.headers?.['fly-machine-lease-nonce']).toBe(`lease-${machineId}`);
      }
    }
    expect(Buffer.from(id!, 'base64url').toString()).toBe(JSON.stringify({
      app: 'demo-app', machines: [
        { id: 'a', version: 'new-a', wasRunning: true }, { id: 'z', version: 'new-z', wasRunning: true },
      ],
    }));
    expect(id).not.toContain('fly-token');
    expect(Buffer.from(id!, 'base64url').toString()).not.toContain('config');
  });

  it('keeps secret versions per app and uses the latest successful write', async () => {
    let version = 3;
    const http = deploymentRoutes(new FakeHttp().on('POST', /\/secrets$/, () => json(200, { version: version++ })));
    const host = hostFor(http);
    const other = { ...service, serviceId: 'other-app' };
    await host.writeVariables(service, { KEY: 'first-secret-value' }, { skipDeploy: true });
    await host.writeVariables(other, { KEY: 'second-secret-value' }, { skipDeploy: true });
    await host.writeVariables(service, { KEY: 'third-secret-value' }, { skipDeploy: true });
    await host.redeploy(other);
    await host.redeploy(service);
    expect(http.callsTo('POST', /\/machines\/a$/).map((call) => JSON.parse(call.body!).min_secrets_version)).toEqual([4, 5]);
  });

  it.each([{}, undefined])('omits min_secrets_version when the secrets response has no version (%j)', async (response) => {
    let writes = 0;
    const http = deploymentRoutes(new FakeHttp().on('POST', /\/secrets$/, () => {
      if (writes++ === 0) return json(200, { version: 7 });
      return response === undefined ? text(204, '') : json(200, response);
    }));
    const host = hostFor(http);
    await host.writeVariables(service, { KEY: 'first-secret-value' }, { skipDeploy: true });
    await host.writeVariables(service, { KEY: 'second-secret-value' }, { skipDeploy: true });
    await host.redeploy(service);
    expect(JSON.parse(http.callsTo('POST', /\/machines\/a$/)[0]!.body!)).not.toHaveProperty('min_secrets_version');
  });

  it('omits min_secrets_version in a fresh adapter without a prior write', async () => {
    const http = deploymentRoutes(new FakeHttp());
    await hostFor(http).redeploy(service);
    expect(JSON.parse(http.callsTo('POST', /\/machines\/a$/)[0]!.body!)).not.toHaveProperty('min_secrets_version');
  });

  it.each(['stopped', 'suspended'])('updates %s machines with skip_launch and does not wait for them to start', async (state) => {
    const http = deploymentRoutes(new FakeHttp(), [machine('a', state)]);
    const id = await hostFor(http).redeploy(service);
    expect(JSON.parse(http.callsTo('POST', /\/machines\/a$/)[0]!.body!)).toEqual({
      config: { image: 'registry.fly.io/demo-app@sha256:123', env: { PORT: '8080' }, services: [{ internal_port: 8080 }] },
      current_version: 'old-a', skip_launch: true,
    });
    expect(http.callsTo('GET', /\/wait\?/)).toHaveLength(0);
    expect(Buffer.from(id!, 'base64url').toString()).toBe(JSON.stringify({
      app: 'demo-app', machines: [{ id: 'a', version: 'new-a', wasRunning: false }],
    }));
  });

  it('a 409 on current_version fails the deployment, releases the lease and does not retry', async () => {
    const http = deploymentRoutes(new FakeHttp().on('POST', /\/machines\/a$/, () =>
      text(409, 'first-secret-value fly-token')), [machine('a'), machine('b')]);
    const error = await hostFor(http).redeploy(service).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).toContain('409');
    expect(String(error)).not.toMatch(/first-secret-value|fly-token/);
    expect(http.callsTo('POST', /\/machines\/a$/)).toHaveLength(1);
    expect(http.callsTo('DELETE', /\/machines\/a\/lease$/)).toHaveLength(1);
    expect(http.callsTo('POST', /\/machines\/b/)).toHaveLength(0);
  });

  it.each([{}, { version: '' }, { version: 'new-a', id: 'different-machine' }])('releases the lease on an invalid update response (%j)', async (body) => {
    const http = deploymentRoutes(new FakeHttp().on('POST', /\/machines\/a$/, () => json(200, body)));
    await expect(hostFor(http).redeploy(service)).rejects.toThrow(/Fly/);
    expect(http.callsTo('DELETE', /\/lease$/)).toHaveLength(1);
    expect(http.callsTo('GET', /\/wait\?/)).toHaveLength(0);
  });

  it('does not confirm a stopped machine update that returned its old version', async () => {
    const http = deploymentRoutes(new FakeHttp().on('POST', /\/machines\/a$/, () =>
      json(200, { id: 'a', version: 'old-a' })), [machine('a', 'stopped')]);
    await expect(hostFor(http).redeploy(service)).rejects.toThrow(/Fly/);
    expect(http.callsTo('DELETE', /\/lease$/)).toHaveLength(1);
    expect(http.callsTo('GET', /\/wait\?/)).toHaveLength(0);
  });

  it('preserves the original sanitized update failure when lease cleanup also fails', async () => {
    const http = deploymentRoutes(new FakeHttp()
      .on('POST', /\/machines\/a$/, () => text(409, 'first-secret-value fly-token'))
      .on('DELETE', /\/lease$/, () => text(500, 'cleanup-secret fly-token')));
    const error = await hostFor(http).redeploy(service).catch((e: unknown) => e);
    expect(String(error)).toContain('409');
    expect(String(error)).not.toMatch(/first-secret-value|cleanup-secret|fly-token/);
  });

  it('stops before the next machine if releasing the lease fails', async () => {
    const http = deploymentRoutes(new FakeHttp().on('DELETE', /\/lease$/, () => text(500, 'fly-token')),
      [machine('a'), machine('b')]);
    await expect(hostFor(http).redeploy(service)).rejects.toThrow(/Fly.*500/);
    expect(http.callsTo('POST', /\/machines\/b/)).toHaveLength(0);
  });

  it.each([
    { status: 200, body: { ok: false, state: 'starting', version: 'new-a' } },
    { status: 200, body: { ok: true, state: 'started', version: 'old-a' } },
    { status: 200, body: { ok: false, state: 'failed', version: 'new-a' } },
    { status: 409, body: {} }, { status: 408, body: {} }, { status: 504, body: {} },
  ])('does not advance the rolling update without readiness (%j)', async ({ status, body }) => {
    const http = deploymentRoutes(new FakeHttp().on('GET', /\/wait\?/, () => json(status, body)),
      [machine('a'), machine('b')]);
    await expect(hostFor(http).redeploy(service)).rejects.toThrow(/Fly/);
    expect(http.callsTo('POST', /\/machines\/b/)).toHaveLength(0);
    expect(http.callsTo('DELETE', /\/machines\/a\/lease$/)).toHaveLength(1);
  });

  it('rejects repeated cursors before modifying any machine', async () => {
    const http = new FakeHttp().on('GET', /\/machines(?:\?cursor=same)?$/, () =>
      json(200, [machine('a')], { 'fly-next-cursor': 'same' }));
    await expect(hostFor(http).redeploy(service)).rejects.toThrow(/Fly/);
    expect(http.calls).toHaveLength(2);
    expect(http.calls.every((call) => call.method === 'GET')).toBe(true);
  });

  it.each([
    [machine('a'), machine('a')], [{ id: 'a', version: 'old-a', state: 'started' }],
    [{ ...machine('a'), version: '' }], [{ ...machine('a'), config: null }],
  ])('validates all machine records before taking a lease (%j)', async (...items) => {
    const http = new FakeHttp().on('GET', /\/machines$/, () => json(200, items));
    await expect(hostFor(http).redeploy(service)).rejects.toThrow(/Fly/);
    expect(http.calls).toHaveLength(1);
  });

  it('does not claim activation when an app has no machines', async () => {
    const http = deploymentRoutes(new FakeHttp(), []);
    expect(await hostFor(http).redeploy(service)).toBeNull();
    expect(http.calls).toHaveLength(1);
  });

  it('deploymentStatus succeeds only when every running machine reports started at the new version', async () => {
    const id = deploymentId([
      { id: 'a', version: 'new-a', wasRunning: true }, { id: 'b', version: 'new-b', wasRunning: true },
    ]);
    let bStarted = false;
    const http = deploymentRoutes(new FakeHttp().on('GET', /\/machines\/b\/wait\?/, () =>
      json(200, { ok: true, state: bStarted ? 'started' : 'starting', version: 'new-b' })));
    const host = hostFor(http);
    expect(await host.deploymentStatus(service, id)).toBe('pending');
    bStarted = true;
    expect(await host.deploymentStatus(service, id)).toBe('success');
  });

  it.each([
    { status: 200, body: { ok: true, state: 'started', version: 'old-a' }, want: 'pending' },
    { status: 200, body: { ok: false, state: 'started', version: 'new-a' }, want: 'pending' },
    { status: 200, body: { ok: false, state: 'failed', version: 'new-a' }, want: 'failed' },
    { status: 200, body: { ok: true, state: 'destroyed', version: 'new-a' }, want: 'failed' },
    { status: 409, body: { message: 'fly-token' }, want: 'failed' },
    { status: 408, body: { message: 'fly-token' }, want: 'pending' },
    { status: 504, body: { message: 'fly-token' }, want: 'pending' },
  ])('maps running machine status conservatively (%j)', async ({ status, body, want }) => {
    const http = new FakeHttp().on('GET', /\/wait\?/, () => json(status, body));
    expect(await hostFor(http).deploymentStatus(service, deploymentId([{ id: 'a', version: 'new-a', wasRunning: true }]))).toBe(want);
  });

  it.each(['TimeoutError', 'AbortError'])('treats %s from the injected HTTP client as pending without diagnostics', async (name) => {
    const http = new FakeHttp().on('GET', /\/wait\?/, () => { throw new DOMException('fly-token first-secret-value', name); });
    expect(await hostFor(http).deploymentStatus(service, deploymentId([{ id: 'a', version: 'new-a', wasRunning: true }]))).toBe('pending');
  });

  it.each([
    { state: 'stopped', version: 'new-a', want: 'success' },
    { state: 'suspended', version: 'new-a', want: 'success' },
    { state: 'stopped', version: 'old-a', want: 'pending' },
    { state: 'failed', version: 'new-a', want: 'failed' },
    { state: 'destroyed', version: 'new-a', want: 'failed' },
  ])('stopped machines need only their new version for success (%j)', async ({ state, version, want }) => {
    const http = new FakeHttp().on('GET', /\/machines\/a$/, () => json(200, { id: 'a', state, version }));
    expect(await hostFor(http).deploymentStatus(service, deploymentId([{ id: 'a', version: 'new-a', wasRunning: false }]))).toBe(want);
    expect(http.callsTo('GET', /\/wait\?/)).toHaveLength(0);
  });

  it('a failed machine wins over another pending machine', async () => {
    const http = new FakeHttp()
      .on('GET', /\/machines\/a\/wait\?/, () => text(504, 'timeout'))
      .on('GET', /\/machines\/b\/wait\?/, () => json(200, { ok: false, state: 'failed', version: 'new-b' }));
    expect(await hostFor(http).deploymentStatus(service, deploymentId([
      { id: 'a', version: 'new-a', wasRunning: true }, { id: 'b', version: 'new-b', wasRunning: true },
    ]))).toBe('failed');
  });

  it.each([
    'invalid-id',
    deploymentId([{ id: 'a', version: 'new-a', wasRunning: true }], 'other-app'),
    deploymentId([]),
    Buffer.from(JSON.stringify({ app: 'demo-app', machines: [{ id: 'a', version: 'new-a' }] })).toString('base64url'),
  ])('rejects an invalid or mismatched deployment id before HTTP (%s)', async (id) => {
    const http = new FakeHttp();
    await expect(hostFor(http).deploymentStatus(service, id)).rejects.toThrow(/Fly/);
    expect(http.calls).toHaveLength(0);
  });

  it('FlyV1 macaroon tokens are sent unchanged on GraphQL and Machines requests', async () => {
    const http = deploymentRoutes(new FakeHttp()
      .on('POST', graphql, () => json(200, { data: { app: { secrets: [] } } }))
      .on('POST', /\/secrets$/, () => json(200, { version: 2 })));
    const host = hostFor(http, 'FlyV1 test-macaroon');
    await host.readVariables(service);
    await host.writeVariables(service, { KEY: 'first-secret-value' }, { skipDeploy: true });
    const id = await host.redeploy(service);
    await host.deploymentStatus(service, id!);
    expect(http.calls.every((call) => call.headers?.Authorization === 'FlyV1 test-macaroon')).toBe(true);
  });

  it.each([
    { status: 403, body: 'echoed-secret fly-token' },
    { status: 200, body: '{invalid-json echoed-secret fly-token' },
  ])('sanitizes secrets update failures without a GraphQL fallback (%j)', async ({ status, body }) => {
    const http = new FakeHttp().on('POST', /\/secrets$/, () => text(status, body));
    const error = await hostFor(http).writeVariables(service, { KEY: 'echoed-secret' }, { skipDeploy: true }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).not.toMatch(/echoed-secret|fly-token/);
    expect(http.calls).toHaveLength(1);
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
