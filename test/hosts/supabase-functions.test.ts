import { describe, expect, it } from 'vitest';
import { createSupabaseFunctionsHost } from '../../src/hosts/supabase-functions.js';
import type { ServiceRef } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const token = 'sbp_test_management_token';
const base = 'https://api.supabase.com/v1';
const ref = 'abcdefghijklmnopqrst';
const other = 'tsrqponmlkjihgfedcba';
const auth = { Authorization: `Bearer ${token}` };
const jsonAuth = { ...auth, 'Content-Type': 'application/json' };
const service: ServiceRef = {
  host: 'supabase-functions', projectId: ref, projectName: 'api', serviceId: ref, serviceName: 'api',
  environmentId: '', environmentName: '',
};

const hostFor = (http: FakeHttp, projectRefs?: string[]) =>
  createSupabaseFunctionsHost({ token, http, log: silentLogger, ...(projectRefs === undefined ? {} : { projectRefs }) });

describe('Supabase Edge Functions host', () => {
  it('reports write-only secrets, batch writes and no deploy step', () => {
    const host = hostFor(new FakeHttp());
    expect(host.id).toBe('supabase-functions');
    expect(host.capabilities).toEqual({ readValues: false, batchWrite: true, redeploy: false, activation: 'immediate' });
  });

  it('lists every project as one project-wide service', async () => {
    const http = new FakeHttp().on('GET', /\/v1\/projects$/, () => json(200, [
      { id: ref, ref, name: 'api', status: 'ACTIVE_HEALTHY' },
      { id: other, ref: other, name: 'jobs', status: 'INACTIVE' },
    ]));
    expect(await hostFor(http).listServices()).toEqual([
      service,
      { ...service, projectId: other, projectName: 'jobs', serviceId: other, serviceName: 'jobs' },
    ]);
    expect(http.calls).toEqual([{ method: 'GET', url: `${base}/projects`, headers: auth }]);
  });

  it('fetches only configured project refs', async () => {
    const http = new FakeHttp().on('GET', /\/v1\/projects\/[a-z]+$/, () => json(200, { ref, name: 'api' }));
    expect(await hostFor(http, [ref, ref]).listServices()).toEqual([service]);
    expect(http.calls).toEqual([{ method: 'GET', url: `${base}/projects/${ref}`, headers: auth }]);
  });

  it.each(['ABCDEFGHIJKLMNOPQRST', 'short', `${ref}/../x`, ''])('rejects invalid configured ref %j', (bad) => {
    expect(() => hostFor(new FakeHttp(), [bad])).toThrow(/Supabase/);
  });

  it.each([{ ref: 'bad/ref', name: 'x' }, { ref, name: '' }, { name: 'x' }, null])('rejects malformed project %j', async (project) => {
    const http = new FakeHttp().on('GET', /\/v1\/projects$/, () => json(200, [project]));
    await expect(hostFor(http).listServices()).rejects.toThrow('Supabase returned an invalid response');
  });

  it('reads secret names as sealed, never their values, and skips Supabase-managed defaults', async () => {
    const marker = 'test-value-or-digest-marker';
    const http = new FakeHttp().on('GET', /\/secrets$/, () => json(200, [
      { name: 'OPENAI_API_KEY', value: marker, updated_at: '2026-10-01T00:00:00Z' },
      { name: 'SUPABASE_SERVICE_ROLE_KEY', value: marker },
      { name: 'STRIPE_KEY', value: marker },
      { name: 'STRIPE_KEY', value: marker },
    ]));
    const variables = await hostFor(http).readVariables(service);
    expect(variables).toEqual([
      { name: 'OPENAI_API_KEY', sealed: true },
      { name: 'STRIPE_KEY', sealed: true },
    ]);
    expect(JSON.stringify(variables)).not.toContain(marker);
    expect(http.calls).toEqual([{ method: 'GET', url: `${base}/projects/${ref}/secrets`, headers: auth }]);
  });

  it('upserts exactly the given secrets in one documented bulk request and never deletes', async () => {
    const http = new FakeHttp().on('POST', /\/secrets$/, () => text(201, ''));
    await hostFor(http).writeVariables(service, { OPENAI_API_KEY: 'test-new', EMPTY: '' }, { skipDeploy: true });
    expect(http.calls).toEqual([{
      method: 'POST', url: `${base}/projects/${ref}/secrets`, headers: jsonAuth,
      body: JSON.stringify([{ name: 'OPENAI_API_KEY', value: 'test-new' }, { name: 'EMPTY', value: '' }]),
    }]);
    expect(http.callsTo('DELETE', /./)).toEqual([]);
  });

  it('splits more than 100 secrets into documented batch sizes', async () => {
    const http = new FakeHttp().on('POST', /\/secrets$/, () => text(201, ''));
    const vars = Object.fromEntries(Array.from({ length: 101 }, (_, index) => [`KEY_${index}`, `test-${index}`]));
    await hostFor(http).writeVariables(service, vars, { skipDeploy: false });
    expect(http.calls.map((call) => (JSON.parse(call.body ?? '[]') as unknown[]).length)).toEqual([100, 1]);
  });

  it.each([
    { name: 'SUPABASE_URL', value: 'test-a' },
    { name: '', value: 'test-a' },
    { name: 'X'.repeat(257), value: 'test-a' },
    { name: 'BIG', value: 'x'.repeat(24_577) },
  ])('rejects an invalid batch before any write: $name', async ({ name, value }) => {
    const http = new FakeHttp().on('POST', /./, () => text(201, ''));
    await expect(hostFor(http).writeVariables(service, { OK_KEY: 'test-ok', [name]: value }, { skipDeploy: true })).rejects.toThrow(/Supabase/);
    expect(http.calls).toEqual([]);
  });

  it('does nothing for an empty update', async () => {
    const http = new FakeHttp();
    await hostFor(http).writeVariables(service, {}, { skipDeploy: true });
    expect(http.calls).toEqual([]);
  });

  it('starts no deployment and has none to track', async () => {
    const http = new FakeHttp();
    const host = hostFor(http);
    expect(await host.redeploy(service)).toBeNull();
    await expect(host.deploymentStatus(service, 'x')).rejects.toThrow(/Supabase/);
    expect(http.calls).toEqual([]);
  });

  it.each([
    { ...service, host: 'vercel' as const },
    { ...service, serviceId: other },
    { ...service, projectId: '../x', serviceId: '../x' },
  ])('rejects a foreign service reference before any request: %j', async (bad) => {
    const http = new FakeHttp();
    await expect(hostFor(http).readVariables(bad)).rejects.toThrow(/Supabase/);
    await expect(hostFor(http).writeVariables(bad, { A: 'test-a' }, { skipDeploy: true })).rejects.toThrow(/Supabase/);
    expect(http.calls).toEqual([]);
  });

  it.each(['http', 'transport', 'json', 'malformed'] as const)('sanitizes %s failures', async (failure) => {
    const marker = 'test-private-supabase-marker';
    const http = new FakeHttp()
      .on('GET', /\/secrets$/, () => {
        if (failure === 'transport') throw new Error(`${token} ${marker}`);
        if (failure === 'http') return json(429, { message: marker });
        if (failure === 'json') return text(200, marker);
        return json(200, { secrets: marker });
      })
      .on('POST', /\/secrets$/, () => json(500, { message: marker }));
    const read = await hostFor(http).readVariables(service).catch((caught: unknown) => caught);
    expect(String(read)).toMatch(/Supabase/);
    expect(String(read)).not.toContain(marker);
    expect(String(read)).not.toContain(token);
    const write = await hostFor(http).writeVariables(service, { KEY: marker }, { skipDeploy: true }).catch((caught: unknown) => caught);
    expect(String(write)).toBe('Error: Supabase request failed (HTTP 500)');
  });
});
