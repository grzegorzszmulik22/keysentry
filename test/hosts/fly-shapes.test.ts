import { describe, expect, it } from 'vitest';
import { createFlyHost } from '../../src/hosts/fly.js';
import type { ServiceRef } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const service: ServiceRef = {
  host: 'fly', projectId: 'demo-app', projectName: 'demo-app',
  serviceId: 'demo-app', serviceName: 'demo-app', environmentId: '', environmentName: '',
};
const machinesUrl = 'https://api.machines.dev/v1/apps/demo-app/machines';
const machine = (id: string, state = 'started') => ({
  id, state, version: `old-${id}`, config: { image: 'registry.fly.io/demo-app@sha256:123' },
});
const hostFor = (http: FakeHttp) => createFlyHost({ token: 'fly-token', http, log: silentLogger });
const deploymentId = (entry: Record<string, unknown>) =>
  Buffer.from(JSON.stringify({ app: 'demo-app', machines: [entry] })).toString('base64url');

function routes(http: FakeHttp, listed = [machine('a')]): FakeHttp {
  return http
    .on('GET', /\/machines$/, () => json(200, listed))
    .on('POST', /\/machines\/([^/]+)\/lease$/, () => json(200, { nonce: 'lease-nonce' }))
    .on('POST', /\/machines\/([^/]+)$/, (_req, match) => json(200, { id: match[1], version: `new-${match[1]}` }))
    .on('DELETE', /\/lease$/, () => text(204, ''))
    .on('GET', /\/machines\/([^/]+)\/wait\?/, (_req, match) =>
      json(200, { ok: true, state: 'started', version: `new-${match[1]}` }));
}

describe('Fly API response shapes (L6)', () => {
  it.each([
    { nonce: 'lease-nonce' },
    { data: { nonce: 'lease-nonce' } },
    { nonce: 'lease-nonce', data: { nonce: 'lease-nonce' } },
  ])('uses either supported lease nonce shape for the update and release (%j)', async (lease) => {
    const http = routes(new FakeHttp().on('POST', /\/lease$/, () => json(200, lease)));

    expect(await hostFor(http).redeploy(service)).toEqual(expect.any(String));
    const update = http.callsTo('POST', /\/machines\/a$/)[0]!;
    const release = http.callsTo('DELETE', /\/lease$/)[0]!;
    expect(update.headers?.['fly-machine-lease-nonce']).toBe('lease-nonce');
    expect(release.headers?.['fly-machine-lease-nonce']).toBe('lease-nonce');
  });

  it.each([
    null, [], {}, { data: null }, { data: [] }, { data: {} }, { data: { nonce: '' } },
    { nonce: 42 }, { nonce: null, data: { nonce: 'lease-nonce' } },
    { nonce: 'lease-nonce', data: { nonce: 'different-nonce' } },
    { nonce: 'lease-nonce', data: { nonce: null } }, { nonce: 'lease-nonce', data: null },
  ].map((lease) => ({ lease })))('refuses malformed or conflicting leases before updating a machine (%j)', async ({ lease }) => {
    const http = routes(new FakeHttp().on('POST', /\/lease$/, () => json(200, lease)));

    await expect(hostFor(http).redeploy(service)).rejects.toThrow(/Fly.*lease/);
    expect(http.callsTo('POST', /\/machines\/a$/)).toHaveLength(0);
    expect(http.callsTo('GET', /\/wait\?/)).toHaveLength(0);
  });

  it('waits on the returned instance and retains it for polling in a fresh adapter', async () => {
    const instanceId = 'instance /?&=a';
    const http = routes(new FakeHttp()
      .on('POST', /\/machines\/a$/, () => json(200, { id: 'a', version: 'new-a', instance_id: instanceId }))
      .on('GET', /\/wait\?/, (req) => {
        const url = new URL(req.url);
        expect(url.searchParams.get('state')).toBe('started');
        expect(url.searchParams.get('instance_id')).toBe(instanceId);
        expect(url.searchParams.has('version')).toBe(false);
        expect(url.searchParams.get('timeout')).toBe('25');
        return json(200, { ok: true, id: 'a', state: 'started', version: 'new-a', instance_id: instanceId });
      }));

    const id = await hostFor(http).redeploy(service);
    expect(JSON.parse(Buffer.from(id!, 'base64url').toString())).toEqual({
      app: 'demo-app', machines: [{ id: 'a', version: 'new-a', wasRunning: true, instanceId }],
    });
    expect(await hostFor(http).deploymentStatus(service, id!)).toBe('success');
    expect(http.callsTo('GET', /\/wait\?/)).toHaveLength(2);
    expect(http.calls.findIndex((call) => call.method === 'DELETE')).toBeLessThan(
      http.calls.findIndex((call) => /\/wait\?/.test(call.url)),
    );
  });

  it('falls back to the returned version and still polls old deployment IDs', async () => {
    const http = routes(new FakeHttp().on('GET', /\/wait\?/, (req) => {
      expect(req.url).toBe(`${machinesUrl}/a/wait?state=started&version=new-a&timeout=25`);
      return json(200, { ok: true, state: 'started', version: 'new-a' });
    }));
    const id = await hostFor(http).redeploy(service);
    expect(id).toBe(deploymentId({ id: 'a', version: 'new-a', wasRunning: true }));
    expect(await hostFor(http).deploymentStatus(service, id!)).toBe('success');
  });

  it.each([null, '', ' ', 42, {}, []].map((instance_id) => ({ instance_id })))('releases the lease and stops after a malformed update instance (%j)', async ({ instance_id }) => {
    const http = routes(new FakeHttp().on('POST', /\/machines\/a$/, () =>
      json(200, { id: 'a', version: 'new-a', instance_id })), [machine('a'), machine('b')]);

    await expect(hostFor(http).redeploy(service)).rejects.toThrow(/Fly.*update/);
    expect(http.callsTo('DELETE', /\/machines\/a\/lease$/)).toHaveLength(1);
    expect(http.callsTo('GET', /\/wait\?/)).toHaveLength(0);
    expect(http.callsTo('POST', /\/machines\/b/)).toHaveLength(0);
  });

  it.each([null, '', ' ', 42, {}, []].map((instanceId) => ({ instanceId })))('rejects malformed persisted instance identity before HTTP (%j)', async ({ instanceId }) => {
    const http = new FakeHttp();
    const id = deploymentId({ id: 'a', version: 'new-a', wasRunning: true, instanceId });

    await expect(hostFor(http).deploymentStatus(service, id)).rejects.toThrow(/Fly.*id/);
    expect(http.calls).toHaveLength(0);
  });

  it.each([
    { id: 'other-machine' }, { id: null }, { id: 42 },
    { instance_id: 'other-instance' }, { instance_id: null }, { instance_id: '' }, { instance_id: 42 },
  ])('refuses explicit wrong or malformed wait response identities (%j)', async (identity) => {
    const http = new FakeHttp().on('GET', /\/wait\?/, () =>
      json(200, { ok: true, state: 'started', version: 'new-a', ...identity }));
    const id = deploymentId({ id: 'a', version: 'new-a', wasRunning: true, instanceId: 'instance-a' });

    await expect(hostFor(http).deploymentStatus(service, id)).rejects.toThrow(/Fly.*status/);
  });

  it.each([
    { ok: true, state: 'started', version: 'new-a', want: 'success' },
    { ok: true, state: 'started', want: 'pending' },
    { ok: true, state: 'started', version: 'old-a', want: 'pending' },
    { ok: false, state: 'started', version: 'new-a', want: 'pending' },
    { ok: true, state: 'starting', version: 'new-a', want: 'pending' },
    { ok: false, state: 'failed', version: 'new-a', want: 'failed' },
  ])('keeps the readiness and version guards for instance waits (%j)', async ({ want, ...body }) => {
    const http = new FakeHttp().on('GET', /\/wait\?state=started&instance_id=instance-a&timeout=25$/, () => json(200, body));
    const id = deploymentId({ id: 'a', version: 'new-a', wasRunning: true, instanceId: 'instance-a' });

    expect(await hostFor(http).deploymentStatus(service, id)).toBe(want);
  });

  it('keeps stopped machines stopped while retaining and checking the updated instance', async () => {
    let instanceId = 'instance-a';
    const http = routes(new FakeHttp()
      .on('POST', /\/machines\/a$/, (req) => {
        expect(JSON.parse(req.body!).skip_launch).toBe(true);
        return json(200, { id: 'a', version: 'new-a', instance_id: 'instance-a' });
      })
      .on('GET', /\/machines\/a$/, () => json(200, { id: 'a', state: 'stopped', version: 'new-a', instance_id: instanceId })),
    [machine('a', 'stopped')]);

    const id = await hostFor(http).redeploy(service);
    expect(await hostFor(http).deploymentStatus(service, id!)).toBe('success');
    instanceId = 'other-instance';
    await expect(hostFor(http).deploymentStatus(service, id!)).rejects.toThrow(/Fly.*status/);
    expect(http.callsTo('GET', /\/wait\?/)).toHaveLength(0);
  });

  it('does not advance the rolling update after an instance readiness failure', async () => {
    const http = routes(new FakeHttp()
      .on('POST', /\/machines\/a$/, () => json(200, { id: 'a', version: 'new-a', instance_id: 'instance-a' }))
      .on('GET', /\/wait\?state=started&instance_id=instance-a&timeout=25$/, () =>
        json(200, { ok: false, state: 'starting', version: 'new-a' })), [machine('a'), machine('b')]);

    await expect(hostFor(http).redeploy(service)).rejects.toThrow(/Fly.*not confirmed/);
    expect(http.callsTo('DELETE', /\/machines\/a\/lease$/)).toHaveLength(1);
    expect(http.callsTo('POST', /\/machines\/b/)).toHaveLength(0);
  });
});
