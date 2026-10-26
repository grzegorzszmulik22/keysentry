import { describe, expect, it } from 'vitest';
import { createRenderHost } from '../../src/hosts/render.js';
import type { ServiceRef } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const base = 'https://api.render.com/v1';
const apiKey = 'render-test-token';
const service: ServiceRef = {
  host: 'render',
  projectId: 'srv-one',
  projectName: 'api',
  serviceId: 'srv-one',
  serviceName: 'api',
  environmentId: '',
  environmentName: '',
};
const hostFor = (http: FakeHttp) => createRenderHost({ apiKey, http, log: silentLogger });

describe('Render host', () => {
  it('reports readable values, individual writes, and a separate deployment step', () => {
    const host = hostFor(new FakeHttp());
    expect(host.id).toBe('render');
    expect(host.capabilities).toEqual({ readValues: true, batchWrite: false, redeploy: true });
  });

  it('lists services across cursor pages with bearer authentication', async () => {
    const http = new FakeHttp()
      .on('GET', /\/services\?limit=100$/, () => json(200, [
        { cursor: 'cursor / one', service: { id: 'srv-one', name: 'api' } },
      ]))
      .on('GET', /\/services\?limit=100&cursor=cursor%20%2F%20one$/, () => json(200, [
        { cursor: 'cursor-two', service: { id: 'srv-two', name: 'worker' } },
      ]))
      .on('GET', /\/services\?limit=100&cursor=cursor-two$/, () => json(200, []));

    expect(await hostFor(http).listServices()).toEqual([
      service,
      { ...service, projectId: 'srv-two', projectName: 'worker', serviceId: 'srv-two', serviceName: 'worker' },
    ]);
    expect(http.calls).toEqual([
      { method: 'GET', url: `${base}/services?limit=100`, headers: { Authorization: `Bearer ${apiKey}` } },
      { method: 'GET', url: `${base}/services?limit=100&cursor=cursor%20%2F%20one`, headers: { Authorization: `Bearer ${apiKey}` } },
      { method: 'GET', url: `${base}/services?limit=100&cursor=cursor-two`, headers: { Authorization: `Bearer ${apiKey}` } },
    ]);
  });

  it('reads values including empty strings across env-var cursor pages', async () => {
    const http = new FakeHttp()
      .on('GET', /\/services\/srv-one\/env-vars\?limit=100$/, () => json(200, [
        { cursor: 'vars-one', envVar: { key: 'API_KEY', value: 'test-current-value' } },
      ]))
      .on('GET', /\/services\/srv-one\/env-vars\?limit=100&cursor=vars-one$/, () => json(200, [
        { cursor: 'vars-two', envVar: { key: 'EMPTY', value: '' } },
      ]))
      .on('GET', /\/services\/srv-one\/env-vars\?limit=100&cursor=vars-two$/, () => json(200, []));

    expect(await hostFor(http).readVariables(service)).toEqual([
      { name: 'API_KEY', value: 'test-current-value', sealed: false },
      { name: 'EMPTY', value: '', sealed: false },
    ]);
    expect(http.calls).toEqual([
      { method: 'GET', url: `${base}/services/srv-one/env-vars?limit=100`, headers: { Authorization: `Bearer ${apiKey}` } },
      { method: 'GET', url: `${base}/services/srv-one/env-vars?limit=100&cursor=vars-one`, headers: { Authorization: `Bearer ${apiKey}` } },
      { method: 'GET', url: `${base}/services/srv-one/env-vars?limit=100&cursor=vars-two`, headers: { Authorization: `Bearer ${apiKey}` } },
    ]);
  });

  it('updates exactly the requested keys with per-key PUTs and does not deploy', async () => {
    const http = new FakeHttp().on('PUT', /\/services\/srv%2Fone\/env-vars\/(API%2FKEY|EMPTY)$/, () => text(204, ''));
    await hostFor(http).writeVariables(
      { ...service, serviceId: 'srv/one' },
      { 'API/KEY': 'test-new-value', EMPTY: '' },
      { skipDeploy: true },
    );
    expect(http.calls).toEqual([
      {
        method: 'PUT', url: `${base}/services/srv%2Fone/env-vars/API%2FKEY`,
        headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: 'test-new-value' }),
      },
      {
        method: 'PUT', url: `${base}/services/srv%2Fone/env-vars/EMPTY`,
        headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: '' }),
      },
    ]);
  });

  it('does not deploy during writes even when skipDeploy is false', async () => {
    const http = new FakeHttp().on('PUT', /\/services\/srv-one\/env-vars\/API_KEY$/, () => json(200, { value: 'test-new-value' }));
    await hostFor(http).writeVariables(service, { API_KEY: 'test-new-value' }, { skipDeploy: false });
    expect(http.calls).toHaveLength(1);
    expect(http.calls[0]).toEqual({
      method: 'PUT', url: `${base}/services/srv-one/env-vars/API_KEY`,
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: 'test-new-value' }),
    });
  });

  it('does nothing for an empty update', async () => {
    const http = new FakeHttp();
    await hostFor(http).writeVariables(service, {}, { skipDeploy: true });
    expect(http.calls).toEqual([]);
  });

  it.each(['', '.', '..'])('rejects unsafe variable name %j before writing any keys', async (name) => {
    const http = new FakeHttp().on('PUT', /\/env-vars\/API_KEY$/, () => text(204, ''));
    await expect(hostFor(http).writeVariables(service, { API_KEY: 'test-new-value', [name]: 'test-invalid-value' }, { skipDeploy: true }))
      .rejects.toThrow(/Render/i);
    expect(http.calls).toEqual([]);
  });

  it('stops writing subsequent keys after a failed per-key update', async () => {
    const http = new FakeHttp().on('PUT', /\/env-vars\/API_KEY$/, () => json(403, { error: 'denied' }));
    await expect(hostFor(http).writeVariables(service, { API_KEY: 'test-new-value', OTHER_KEY: 'test-other-value' }, { skipDeploy: true }))
      .rejects.toThrow(/Render/i);
    expect(http.calls).toHaveLength(1);
    expect(http.calls[0]?.url).toBe(`${base}/services/srv-one/env-vars/API_KEY`);
  });

  it('starts one deployment without clearing the cache', async () => {
    const http = new FakeHttp().on('POST', /\/services\/srv-one\/deploys$/, () => json(201, { id: 'dep-one' }));
    expect(await hostFor(http).redeploy(service)).toBe('dep-one');
    expect(http.calls).toEqual([{
      method: 'POST', url: `${base}/services/srv-one/deploys`,
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ clearCache: 'do_not_clear' }),
    }]);
  });

  it.each([
    ['live', 'success'],
    ['build_failed', 'failed'],
    ['update_failed', 'failed'],
    ['canceled', 'failed'],
    ['pre_deploy_failed', 'failed'],
    ['deactivated', 'failed'],
    ['build_in_progress', 'pending'],
    ['created', 'pending'],
    ['future_render_status', 'pending'],
  ] as const)('maps deployment status %s to %s', async (status, expected) => {
    const http = new FakeHttp().on('GET', /\/services\/srv%2Fone\/deploys\/dep%2Fone$/, () => json(200, { status }));
    expect(await hostFor(http).deploymentStatus({ ...service, serviceId: 'srv/one' }, 'dep/one')).toBe(expected);
    expect(http.calls).toEqual([{
      method: 'GET', url: `${base}/services/srv%2Fone/deploys/dep%2Fone`,
      headers: { Authorization: `Bearer ${apiKey}` },
    }]);
  });

  it('rejects repeated pagination cursors instead of looping', async () => {
    const http = new FakeHttp().on('GET', /\/services\?limit=100(?:&cursor=stuck)?$/, () => json(200, [
      { cursor: 'stuck', service: { id: 'srv-one', name: 'api' } },
    ]));
    await expect(hostFor(http).listServices()).rejects.toThrow(/Render/i);
    expect(http.calls).toHaveLength(2);
  });

  it('rejects malformed env-var values without exposing response contents', async () => {
    const marker = 'test-private-response-marker';
    const http = new FakeHttp().on('GET', /\/env-vars\?limit=100$/, () => json(200, [
      { envVar: { key: marker, value: { unexpected: marker } } },
    ]));
    let message = '';
    try { await hostFor(http).readVariables(service); } catch (error) { message = String(error); }
    expect(message).toMatch(/Render/i);
    expect(message).not.toContain(marker);
  });

  it.each(['http', 'transport', 'json'] as const)('redacts %s failures during writes', async (failure) => {
    const marker = 'test-private-error-marker';
    const http = new FakeHttp().on('PUT', /\/env-vars\/API_KEY$/, () => {
      if (failure === 'transport') throw new Error(`${apiKey} ${marker}`);
      return failure === 'http' ? json(403, { error: marker }) : text(200, marker);
    });
    let message = '';
    try { await hostFor(http).writeVariables(service, { API_KEY: marker }, { skipDeploy: true }); }
    catch (error) { message = String(error); }
    expect(message).toMatch(/Render/i);
    expect(message).not.toContain(marker);
    expect(message).not.toContain(apiKey);
  });
});
