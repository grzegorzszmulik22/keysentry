import { describe, expect, it } from 'vitest';
import { coolifyApiRoot, createCoolifyHost } from '../../src/hosts/coolify.js';
import type { HttpRequest, ServiceRef } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const token = 'coolify-test-token';
const base = 'https://coolify.example.test/api/v1';
const auth = { Authorization: `Bearer ${token}` };
const jsonAuth = { ...auth, 'Content-Type': 'application/json' };
const app: ServiceRef = {
  host: 'coolify', projectId: 'app1', projectName: 'api', serviceId: 'application:app1', serviceName: 'api',
  environmentId: '', environmentName: '',
};
const svc: ServiceRef = { ...app, projectId: 'svc1', projectName: 'n8n', serviceId: 'service:svc1', serviceName: 'n8n' };

function hostFor(http: FakeHttp, extra: Partial<Parameters<typeof createCoolifyHost>[0]> = {}, warnings: string[] = []) {
  return createCoolifyHost({
    token, baseUrl: 'https://coolify.example.test', http, log: { ...silentLogger, warn: (message: string) => warnings.push(message) }, ...extra,
  });
}

interface Env { key: string; value?: string; is_preview?: boolean; is_shown_once?: boolean; is_literal?: boolean; is_multiline?: boolean; is_buildtime?: boolean; is_shared?: boolean }

/** In-memory Coolify env store that applies documented create/update-by-key semantics. */
function store(initial: Env[], path = '/applications/app1') {
  const envs = initial.map((entry) => ({ ...entry }));
  const http = new FakeHttp()
    .on('GET', new RegExp(`${path}/envs$`), () => json(200, envs))
    .on('POST', new RegExp(`${path}/envs$`), (req: HttpRequest) => {
      envs.push(JSON.parse(req.body ?? '{}') as Env);
      return json(201, { uuid: 'new-env' });
    })
    .on('PATCH', new RegExp(`${path}/envs$`), (req: HttpRequest) => {
      const body = JSON.parse(req.body ?? '{}') as Env;
      const target = envs.find((entry) => entry.key === body.key && (entry.is_preview ?? false) === (body.is_preview ?? false));
      if (!target) return json(404, { message: 'Resource not found.' });
      Object.assign(target, body);
      return json(201, target);
    });
  return { http, envs };
}

describe('coolifyApiRoot', () => {
  it.each([
    ['https://coolify.example.test', `${base}`],
    ['https://coolify.example.test/', `${base}`],
    ['https://Coolify.Example.Test', `${base}`],
    ['https://app.coolify.io', 'https://app.coolify.io/api/v1'],
    // Decision 2 (notes/integration-phase6.md): a self-hosted instance may name its port; egress allows exactly that port.
    ['https://coolify.example.test:8000', 'https://coolify.example.test:8000/api/v1'],
  ])('accepts %s', (input, expected) => {
    expect(coolifyApiRoot(input)).toBe(expected);
  });

  it.each([
    'http://coolify.example.test',
    'https://user:pass@coolify.example.test',
    'https://token@coolify.example.test',
    'https://coolify.example.test:443',
    'https://coolify.example.test/api/v1',
    'https://coolify.example.test/../admin',
    'https://coolify.example.test/%2e%2e/',
    'https://coolify.example.test?next=evil',
    'https://coolify.example.test#x',
    'https://10.0.0.5',
    'https://[::1]',
    'https://coolify.example.test\\evil.test',
    'https://coolify.exam\nple.test',
    'coolify.example.test',
    '',
  ])('rejects %j', (input) => {
    expect(() => coolifyApiRoot(input)).toThrow(/Coolify base URL/);
  });
});

describe('Coolify host', () => {
  it('reports readable values, per-key writes and a restart step', () => {
    const host = hostFor(new FakeHttp());
    expect(host.id).toBe('coolify');
    expect(host.capabilities).toEqual({ readValues: true, batchWrite: false, redeploy: true });
  });

  it('rejects an invalid base URL or option at construction', () => {
    expect(() => hostFor(new FakeHttp(), { baseUrl: 'http://coolify.example.test' })).toThrow(/Coolify/);
    expect(() => hostFor(new FakeHttp(), { applications: ['../x'] })).toThrow(/Coolify/);
    expect(() => hostFor(new FakeHttp(), { redeploy: 'rebuild' as 'deploy' })).toThrow(/Coolify/);
  });

  it('lists applications and services with bearer authentication', async () => {
    const http = new FakeHttp()
      .on('GET', /\/applications$/, () => json(200, [{ uuid: 'app1', name: 'api', fqdn: 'https://api.test' }]))
      .on('GET', /\/services$/, () => json(200, [{ uuid: 'svc1', name: 'n8n' }]));
    expect(await hostFor(http).listServices()).toEqual([app, svc]);
    expect(http.calls).toEqual([
      { method: 'GET', url: `${base}/applications`, headers: auth },
      { method: 'GET', url: `${base}/services`, headers: auth },
    ]);
  });

  it('filters configured resources and fails when one is missing', async () => {
    const http = new FakeHttp().on('GET', /\/applications$/, () => json(200, [{ uuid: 'app1', name: 'api' }, { uuid: 'app2', name: 'web' }]));
    expect(await hostFor(http, { include: ['applications'], applications: ['app1'] }).listServices()).toEqual([app]);
    await expect(hostFor(http, { include: ['applications'], applications: ['app9'] }).listServices()).rejects.toThrow(/not found/);
  });

  it('reads production values, seals locked, redacted and duplicate ones, and ignores preview values', async () => {
    const { http } = store([
      { key: 'OPENAI_API_KEY', value: 'test-current', is_preview: false },
      { key: 'OPENAI_API_KEY', value: 'test-preview', is_preview: true },
      { key: 'LOCKED', value: 'test-locked', is_shown_once: true },
      { key: 'REDACTED' },
      { key: 'SHARED', value: '{{environment.DATABASE_URL}}', is_shared: true },
      { key: 'DUP', value: 'a' },
      { key: 'DUP', value: 'b' },
      { key: 'EMPTY', value: '' },
    ]);
    const variables = await hostFor(http).readVariables(app);
    expect(variables).toEqual([
      { name: 'OPENAI_API_KEY', value: 'test-current', sealed: false },
      { name: 'LOCKED', sealed: true },
      { name: 'REDACTED', sealed: true },
      { name: 'SHARED', value: '{{environment.DATABASE_URL}}', sealed: false },
      { name: 'DUP', sealed: true },
      { name: 'EMPTY', value: '', sealed: false },
    ]);
    expect(JSON.stringify(variables)).not.toContain('test-locked');
    expect(JSON.stringify(variables)).not.toContain('test-preview');
    expect(http.calls).toEqual([{ method: 'GET', url: `${base}/applications/app1/envs`, headers: auth }]);
  });

  it('updates existing keys with their flags, creates missing keys, and leaves others and preview values alone', async () => {
    const { http, envs } = store([
      { key: 'OPENAI_API_KEY', value: 'test-old', is_preview: false, is_literal: false, is_multiline: false, is_shown_once: true, is_buildtime: false },
      { key: 'OPENAI_API_KEY', value: 'test-preview', is_preview: true },
      { key: 'OTHER', value: 'keep-me' },
    ]);
    await hostFor(http).writeVariables(app, { OPENAI_API_KEY: 'test-new', NEW_KEY: 'test-added' }, { skipDeploy: true });
    expect(http.calls).toEqual([
      { method: 'GET', url: `${base}/applications/app1/envs`, headers: auth },
      {
        method: 'PATCH', url: `${base}/applications/app1/envs`, headers: jsonAuth,
        body: JSON.stringify({ key: 'OPENAI_API_KEY', value: 'test-new', is_preview: false, is_literal: false, is_multiline: false, is_shown_once: true }),
      },
      {
        method: 'POST', url: `${base}/applications/app1/envs`, headers: jsonAuth,
        body: JSON.stringify({ key: 'NEW_KEY', value: 'test-added', is_preview: false, is_literal: true, is_multiline: false }),
      },
      { method: 'GET', url: `${base}/applications/app1/envs`, headers: auth },
    ]);
    expect(envs.find((entry) => entry.is_preview)?.value).toBe('test-preview');
    expect(envs.find((entry) => entry.key === 'OTHER')?.value).toBe('keep-me');
  });

  it('marks multiline values and omits flags Coolify did not report', async () => {
    const { http } = store([{ key: 'PEM', value: 'old' }]);
    await hostFor(http).writeVariables(app, { PEM: 'line1\nline2' }, { skipDeploy: true });
    expect(JSON.parse(http.callsTo('PATCH', /./)[0]?.body ?? '{}')).toEqual({ key: 'PEM', value: 'line1\nline2', is_preview: false, is_multiline: true });
  });

  it('fails after a write that changed a preview value instead of the production one', async () => {
    const envs: Env[] = [
      { key: 'API_KEY', value: 'test-preview', is_preview: true },
      { key: 'API_KEY', value: 'test-old', is_preview: false },
    ];
    const http = new FakeHttp()
      .on('GET', /\/envs$/, () => json(200, envs))
      .on('PATCH', /\/envs$/, (req: HttpRequest) => {
        envs[0]!.value = (JSON.parse(req.body ?? '{}') as Env).value; // first match by key, ignoring is_preview
        return json(201, envs[0]);
      });
    const marker = 'test-new-secret-marker';
    const error = await hostFor(http).writeVariables(app, { API_KEY: marker }, { skipDeploy: true }).catch((caught: unknown) => caught);
    expect(String(error)).toMatch(/Coolify variables changed/);
    expect(String(error)).not.toContain(marker);
  });

  it('fails after a write when another variable disappeared', async () => {
    let reads = 0;
    const http = new FakeHttp()
      .on('GET', /\/envs$/, () => json(200, reads++ === 0 ? [{ key: 'A', value: '1' }, { key: 'B', value: '2' }] : [{ key: 'A', value: 'test-new' }]))
      .on('PATCH', /\/envs$/, () => json(201, {}));
    await expect(hostFor(http).writeVariables(app, { A: 'test-new' }, { skipDeploy: true })).rejects.toThrow(/Coolify variables changed/);
  });

  it.each([
    { name: 'a shared reference flag', entries: [{ key: 'API_KEY', value: 'x', is_shared: true }] },
    { name: 'a shared reference value', entries: [{ key: 'API_KEY', value: '{{ project.API_KEY }}' }] },
    { name: 'duplicates', entries: [{ key: 'API_KEY', value: 'a' }, { key: 'API_KEY', value: 'b' }] },
  ])('refuses to overwrite $name before any write', async ({ entries }) => {
    const { http } = store(entries);
    await expect(hostFor(http).writeVariables(app, { OTHER: 'test-a', API_KEY: 'test-b' }, { skipDeploy: true })).rejects.toThrow(/Coolify/);
    expect(http.calls.filter((call) => call.method !== 'GET')).toEqual([]);
  });

  it.each(['', 'A B', 'A=B'])('rejects invalid variable name %j before any request', async (name) => {
    const http = new FakeHttp();
    await expect(hostFor(http).writeVariables(app, { [name]: 'test-a' }, { skipDeploy: true })).rejects.toThrow(/Coolify/);
    expect(http.calls).toEqual([]);
  });

  it('warns that restart does not rebuild build-time values', async () => {
    const warnings: string[] = [];
    const { http } = store([{ key: 'API_KEY', value: 'old', is_buildtime: true }]);
    await hostFor(http, {}, warnings).writeVariables(app, { API_KEY: 'test-new' }, { skipDeploy: true });
    expect(warnings).toEqual([expect.stringMatching(/does not rebuild/)]);
    const quiet: string[] = [];
    const runtimeOnly = store([{ key: 'API_KEY', value: 'old', is_buildtime: false }]);
    await hostFor(runtimeOnly.http, {}, quiet).writeVariables(app, { API_KEY: 'test-new' }, { skipDeploy: true });
    expect(quiet).toEqual([]);
  });

  it('writes service variables through the service endpoints', async () => {
    const { http } = store([{ key: 'SERVICE_PASSWORD_DB', value: 'old' }], '/services/svc1');
    await hostFor(http).writeVariables(svc, { SERVICE_PASSWORD_DB: 'test-new' }, { skipDeploy: true });
    expect(http.calls.map((call) => `${call.method} ${call.url}`)).toEqual([
      `GET ${base}/services/svc1/envs`,
      `PATCH ${base}/services/svc1/envs`,
      `GET ${base}/services/svc1/envs`,
    ]);
  });

  it('does nothing for an empty update', async () => {
    const http = new FakeHttp();
    await hostFor(http).writeVariables(app, {}, { skipDeploy: true });
    expect(http.calls).toEqual([]);
  });

  it('restarts an application by default and returns its deployment id', async () => {
    const http = new FakeHttp().on('POST', /\/applications\/app1\/restart$/, () => json(200, { message: 'Restart request queued.', deployment_uuid: 'dep1' }));
    expect(await hostFor(http).redeploy(app)).toBe('dep1');
    expect(http.calls).toEqual([{ method: 'POST', url: `${base}/applications/app1/restart`, headers: auth }]);
  });

  it('starts a deployment in deploy mode', async () => {
    const http = new FakeHttp().on('POST', /\/applications\/app1\/start$/, () => json(200, { message: 'Deployment request queued.', deployment_uuid: 'dep2' }));
    expect(await hostFor(http, { redeploy: 'deploy' }).redeploy(app)).toBe('dep2');
    expect(http.calls).toEqual([{ method: 'POST', url: `${base}/applications/app1/start`, headers: auth }]);
  });

  it('restarts a service and reports activation as unconfirmed', async () => {
    const warnings: string[] = [];
    const http = new FakeHttp().on('POST', /\/services\/svc1\/restart$/, () => json(200, { message: 'Service restaring request queued.' }));
    expect(await hostFor(http, {}, warnings).redeploy(svc)).toBeNull();
    expect(http.calls).toEqual([{ method: 'POST', url: `${base}/services/svc1/restart`, headers: auth }]);
    expect(warnings).toEqual([expect.stringMatching(/unconfirmed/)]);
  });

  it('fails closed when a restart response has no deployment id', async () => {
    const http = new FakeHttp().on('POST', /\/restart$/, () => json(200, { message: 'queued' }));
    await expect(hostFor(http).redeploy(app)).rejects.toThrow('Coolify returned an invalid response');
  });

  it.each([
    ['finished', 'success'],
    ['failed', 'failed'],
    ['cancelled-by-user', 'failed'],
    ['queued', 'pending'],
    ['in_progress', 'pending'],
    ['future_status', 'pending'],
  ] as const)('maps deployment status %s to %s', async (status, expected) => {
    const http = new FakeHttp().on('GET', /\/deployments\/dep1$/, () => json(200, { deployment_uuid: 'dep1', status }));
    expect(await hostFor(http).deploymentStatus(app, 'dep1')).toBe(expected);
    expect(http.calls).toEqual([{ method: 'GET', url: `${base}/deployments/dep1`, headers: auth }]);
  });

  it.each([
    { ...app, host: 'render' as const },
    { ...app, serviceId: 'database:app1' },
    { ...app, serviceId: 'application:../x', projectId: '../x' },
    { ...app, projectId: 'other' },
    { ...app, environmentId: 'preview' },
  ])('rejects malformed service references before any request: %j', async (service) => {
    const http = new FakeHttp();
    await expect(hostFor(http).readVariables(service)).rejects.toThrow(/Coolify/);
    await expect(hostFor(http).redeploy(service)).rejects.toThrow(/Coolify/);
    expect(http.calls).toEqual([]);
  });

  it.each(['http', 'transport', 'json', 'malformed'] as const)('sanitizes %s failures', async (failure) => {
    const marker = 'test-private-coolify-marker';
    const http = new FakeHttp().on('GET', /\/envs$/, () => {
      if (failure === 'transport') throw new Error(`${token} ${marker}`);
      if (failure === 'http') return json(401, { message: marker });
      if (failure === 'json') return text(200, marker);
      return json(200, [{ key: marker, value: { nested: marker } }]);
    });
    const error = await hostFor(http).readVariables(app).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).toMatch(/Coolify/);
    expect(String(error)).not.toContain(marker);
    expect(String(error)).not.toContain(token);
  });

  it('sanitizes a failed update without echoing the new value', async () => {
    const marker = 'test-new-coolify-secret';
    const http = new FakeHttp()
      .on('GET', /\/envs$/, () => json(200, [{ key: 'API_KEY', value: 'old' }]))
      .on('PATCH', /\/envs$/, () => json(422, { message: marker, errors: { value: [marker] } }));
    const error = await hostFor(http).writeVariables(app, { API_KEY: marker }, { skipDeploy: true }).catch((caught: unknown) => caught);
    expect(String(error)).toBe('Error: Coolify request failed (HTTP 422)');
  });
});
