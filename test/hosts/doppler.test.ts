import { describe, expect, it } from 'vitest';
import { createDopplerHost, type DopplerHostOptions } from '../../src/hosts/doppler.js';
import type { ServiceRef } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const base = 'https://api.doppler.com';
const token = 'dp.st.prd.test-doppler-token-value';
const headers = { Authorization: `Bearer ${token}`, Accept: 'application/json' };
const service: ServiceRef = {
  host: 'doppler', projectId: 'backend', projectName: 'backend', serviceId: 'prd', serviceName: 'prd',
  environmentId: '', environmentName: '',
};
const secretsUrl = `${base}/v3/configs/config/secrets?project=backend&config=prd&include_dynamic_secrets=false&include_managed_secrets=false`;

function hostFor(http: FakeHttp, extra: Partial<DopplerHostOptions> = {}) {
  return createDopplerHost({ token, http, log: silentLogger, ...extra });
}

const visible = (raw: string, type = 'masked') => ({ raw, computed: raw, note: '', rawVisibility: { type }, computedVisibility: { type } });

describe('Doppler host', () => {
  it('reports readable values, single-call writes and no deployments', () => {
    const host = hostFor(new FakeHttp());
    expect(host.id).toBe('doppler');
    expect(host.capabilities).toEqual({ readValues: true, batchWrite: true, redeploy: false });
  });

  it('uses configured configs without listing (service tokens cannot list projects)', async () => {
    const http = new FakeHttp();
    expect(await hostFor(http, { configs: [{ project: 'backend', config: 'prd' }] }).listServices()).toEqual([service]);
    expect(http.calls).toEqual([]);
    expect(() => hostFor(http, { configs: [{ project: 'back end', config: 'prd' }] })).toThrow(/project is invalid/);
  });

  it('lists projects and root configs across pages', async () => {
    const firstProjects = Array.from({ length: 20 }, (_, i) => ({ id: `p${i}`, slug: `proj-${i}`, name: `Project ${i}` }));
    const http = new FakeHttp()
      .on('GET', /\/v3\/projects\?page=1&per_page=20$/, () => json(200, { page: 1, projects: firstProjects }))
      .on('GET', /\/v3\/projects\?page=2&per_page=20$/, () => json(200, { page: 2, projects: [{ id: 'p20', slug: 'backend', name: 'Backend' }] }))
      .on('GET', /\/v3\/configs\?project=backend&page=1&per_page=20$/, () => json(200, {
        page: 1,
        configs: [
          { name: 'prd', root: true, environment: 'prd' },
          { name: 'prd_hotfix', root: false, environment: 'prd' },
        ],
      }))
      .on('GET', /\/v3\/configs\?project=proj-\d+&page=1&per_page=20$/, () => json(200, { page: 1, configs: [] }));

    const refs = await hostFor(http).listServices();
    expect(refs).toEqual([{ ...service, projectName: 'Backend', environmentName: 'prd' }]);
    expect(http.calls.slice(0, 2)).toEqual([
      { method: 'GET', url: `${base}/v3/projects?page=1&per_page=20`, headers },
      { method: 'GET', url: `${base}/v3/projects?page=2&per_page=20`, headers },
    ]);
    expect(http.calls).toHaveLength(2 + 21);

    const withBranches = new FakeHttp()
      .on('GET', /\/v3\/configs\?project=backend&page=1&per_page=20$/, () => json(200, {
        configs: [{ name: 'prd', root: true, environment: 'prd' }, { name: 'prd_hotfix', root: false, environment: 'prd' }],
      }));
    expect((await hostFor(withBranches, { projects: ['backend'], includeBranchConfigs: true }).listServices()).map((ref) => ref.serviceId))
      .toEqual(['prd', 'prd_hotfix']);
  });

  it('stops when a page repeats', async () => {
    const page = Array.from({ length: 20 }, (_, i) => ({ id: `p${i}`, slug: `proj-${i}` }));
    const http = new FakeHttp().on('GET', /\/v3\/projects\?/, () => json(200, { projects: page }));
    await expect(hostFor(http).listServices()).rejects.toThrow('Doppler pagination did not advance');
    expect(http.calls).toHaveLength(2);
  });

  it('reads raw values, keeps references unexpanded and seals restricted values it cannot see', async () => {
    const http = new FakeHttp().on('GET', /\/v3\/configs\/config\/secrets\?/, () => json(200, {
      secrets: {
        STRIPE_SECRET_KEY: visible('test-stripe-value'),
        DATABASE_URL: { raw: '${USER}@db.example.test', computed: 'brian@db.example.test', rawVisibility: { type: 'unmasked' } },
        RESTRICTED_NULL: { raw: null, computed: null, rawVisibility: { type: 'restricted' } },
        RESTRICTED_EMPTY: { raw: '', computed: '', rawVisibility: { type: 'restricted' } },
        RESTRICTED_VISIBLE: visible('test-visible-to-service-token', 'restricted'),
        EMPTY: visible(''),
      },
    }));
    expect(await hostFor(http).readVariables(service)).toEqual([
      { name: 'STRIPE_SECRET_KEY', value: 'test-stripe-value', sealed: false },
      { name: 'DATABASE_URL', value: '${USER}@db.example.test', sealed: false },
      { name: 'RESTRICTED_NULL', sealed: true },
      { name: 'RESTRICTED_EMPTY', sealed: true },
      { name: 'RESTRICTED_VISIBLE', value: 'test-visible-to-service-token', sealed: false },
      { name: 'EMPTY', value: '', sealed: false },
    ]);
    expect(http.calls).toEqual([{ method: 'GET', url: secretsUrl, headers }]);
  });

  it('writes change requests for exactly the given names with originalValue preconditions', async () => {
    const http = new FakeHttp()
      .on('GET', /\/v3\/configs\/config\/secrets\?/, () => json(200, {
        secrets: {
          API_KEY: visible('test-old-api'),
          SEALED: { raw: null, rawVisibility: { type: 'restricted' } },
          SAME: visible('test-same'),
          UNTOUCHED: visible('test-untouched'),
        },
      }))
      .on('POST', /\/v3\/configs\/config\/secrets$/, () => json(200, { secrets: { API_KEY: visible('test-new-api') } }));
    await hostFor(http).writeVariables(service, { API_KEY: 'test-new-api', SEALED: 'test-new-sealed', SAME: 'test-same', ADDED: 'test-added' }, { skipDeploy: true });

    expect(http.calls[1]).toEqual({
      method: 'POST', url: `${base}/v3/configs/config/secrets`, headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project: 'backend', config: 'prd',
        change_requests: [
          { name: 'API_KEY', originalName: 'API_KEY', value: 'test-new-api', originalValue: 'test-old-api' },
          { name: 'SEALED', originalName: 'SEALED', value: 'test-new-sealed' },
          { name: 'ADDED', originalName: null, value: 'test-added' },
        ],
      }),
    });
  });

  it('skips the write when nothing changes and fails clearly when Doppler rejects the precondition', async () => {
    const same = new FakeHttp().on('GET', /secrets\?/, () => json(200, { secrets: { A: visible('test-a') } }));
    await hostFor(same).writeVariables(service, { A: 'test-a' }, { skipDeploy: true });
    expect(same.calls).toHaveLength(1);

    const rejected = new FakeHttp()
      .on('GET', /secrets\?/, () => json(200, { secrets: { A: visible('test-a') } }))
      .on('POST', /secrets$/, () => json(400, { messages: ['planted-doppler-marker test-new'] }));
    const error = await hostFor(rejected).writeVariables(service, { A: 'test-new' }, { skipDeploy: true }).catch((caught: unknown) => caught);
    expect(String(error)).toMatch(/Doppler did not apply the update \(HTTP 400\)/);
    expect(String(error)).not.toContain('planted-doppler-marker');
    expect(String(error)).not.toContain('test-new');
  });

  it.each(['http', 'transport', 'json'] as const)('sanitizes a %s failure', async (failure) => {
    const marker = 'test-planted-doppler-marker';
    const http = new FakeHttp().on('GET', /./, () => {
      if (failure === 'transport') throw new Error(`${token} ${marker}`);
      return failure === 'http' ? json(401, { messages: [marker] }) : text(200, `{${marker}`);
    });
    const error = await hostFor(http).readVariables(service).catch((caught: unknown) => caught);
    expect(String(error)).toMatch(/Doppler/);
    expect(String(error)).not.toContain(marker);
    expect(String(error)).not.toContain(token);
  });

  it('rejects malformed secret entries', async () => {
    const http = new FakeHttp().on('GET', /secrets\?/, () => json(200, { secrets: { A: { raw: 42 } } }));
    await expect(hostFor(http).readVariables(service)).rejects.toThrow('Doppler returned an invalid response');
  });

  it('does not deploy', async () => {
    expect(await hostFor(new FakeHttp()).redeploy(service)).toBeNull();
    await expect(hostFor(new FakeHttp()).deploymentStatus(service, 'x')).rejects.toThrow(/does not create deployments/);
  });
});
