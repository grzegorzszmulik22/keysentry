import { describe, expect, it } from 'vitest';
import { createVaultKvHost, type VaultKvHostOptions } from '../../src/hosts/vault-kv.js';
import type { ServiceRef } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const address = 'https://vault.example.test:8200';
const token = 'hvs.test-vault-token-value';
const headers = { 'X-Vault-Token': token, 'X-Vault-Namespace': 'admin/team' };
const service: ServiceRef = {
  host: 'vault-kv', projectId: 'kv', projectName: 'admin/team/kv', serviceId: 'apps/api', serviceName: 'apps/api',
  environmentId: 'admin/team', environmentName: 'admin/team',
};
const dataUrl = `${address}/v1/kv/data/apps/api`;

function hostFor(http: FakeHttp, extra: Partial<VaultKvHostOptions> = {}) {
  return createVaultKvHost({ address, token, namespace: 'admin/team', mount: 'kv', http, log: silentLogger, ...extra });
}

const read = (data: Record<string, unknown> | null, metadata: Record<string, unknown> = {}) => json(200, {
  data: { data, metadata: { version: 3, deletion_time: '', destroyed: false, custom_metadata: { owner: 'pay' }, ...metadata } },
});

describe('Vault KV v2 host', () => {
  it('reports readable values, single-call writes and no deployments', () => {
    const host = hostFor(new FakeHttp());
    expect(host.id).toBe('vault-kv');
    expect(host.capabilities).toEqual({ readValues: true, batchWrite: true, redeploy: false });
  });

  it.each(['http://vault.example.test', 'https://u:p@vault.example.test', 'https://vault.example.test/ui', 'https://vault.example.test/?a=b'])(
    'rejects the address %s', (value) => {
      expect(() => hostFor(new FakeHttp(), { address: value })).toThrow(/Vault address/);
    },
  );

  it('validates mount and namespace', () => {
    expect(() => hostFor(new FakeHttp(), { mount: '../sys' })).toThrow(/mount/);
    expect(() => hostFor(new FakeHttp(), { namespace: 'bad ns' })).toThrow(/namespace/);
    expect(() => hostFor(new FakeHttp(), { address: 'https://vault.example.test/v1' })).not.toThrow();
  });

  it('lists the configured folders recursively with LIST-as-GET and skips empty folders', async () => {
    const listings: Record<string, unknown> = {
      'apps/': { data: { keys: ['api', 'jobs/', 'web'] } },
      'apps/jobs/': { data: { keys: ['nightly'] } },
    };
    const http = new FakeHttp().on('GET', /\/v1\/kv\/metadata\/(.*)\?list=true$/, (_req, match) => {
      const body = listings[match[1]!];
      return body ? json(200, body) : json(404, { errors: [] });
    });
    const refs = await hostFor(http, { paths: ['apps', 'empty/'] }).listServices();
    expect(refs.map((ref) => ref.serviceId)).toEqual(['apps/api', 'apps/web', 'apps/jobs/nightly']);
    expect(refs[0]).toEqual(service);
    expect(http.calls).toEqual([
      { method: 'GET', url: `${address}/v1/kv/metadata/apps/?list=true`, headers },
      { method: 'GET', url: `${address}/v1/kv/metadata/empty/?list=true`, headers },
      { method: 'GET', url: `${address}/v1/kv/metadata/apps/jobs/?list=true`, headers },
    ]);
  });

  it('lists from the mount root by default, without a namespace header when none is set', async () => {
    const http = new FakeHttp().on('GET', /\/v1\/secret\/metadata\/\?list=true$/, () => json(200, { data: { keys: ['top'] } }));
    const refs = await createVaultKvHost({ address, token, http, log: silentLogger }).listServices();
    expect(refs).toEqual([{
      host: 'vault-kv', projectId: 'secret', projectName: 'secret', serviceId: 'top', serviceName: 'top', environmentId: '', environmentName: '',
    }]);
    expect(http.calls).toEqual([{ method: 'GET', url: `${address}/v1/secret/metadata/?list=true`, headers: { 'X-Vault-Token': token } }]);
  });

  it('reads string values only and treats deleted or destroyed versions as empty', async () => {
    const http = new FakeHttp().on('GET', /\/v1\/kv\/data\/apps\/api$/, () => read({ API_KEY: 'test-api-value', PORT: 8080, nested: { a: 'b' }, EMPTY: '' }));
    expect(await hostFor(http).readVariables(service)).toEqual([
      { name: 'API_KEY', value: 'test-api-value', sealed: false },
      { name: 'EMPTY', value: '', sealed: false },
    ]);
    expect(http.calls).toEqual([{ method: 'GET', url: dataUrl, headers }]);

    for (const response of [read(null, { deletion_time: '2026-01-01T00:00:00Z' }), read(null, { destroyed: true }), json(404, { errors: [] })]) {
      const deleted = new FakeHttp().on('GET', /\/data\/apps\/api$/, () => response);
      expect(await hostFor(deleted).readVariables(service)).toEqual([]);
    }
    // delete_version_after sets a future deletion_time while the data stays readable.
    const scheduled = new FakeHttp().on('GET', /\/data\/apps\/api$/, () => read({ A: 'test-a' }, { deletion_time: '2099-01-01T00:00:00Z' }));
    expect(await hostFor(scheduled).readVariables(service)).toEqual([{ name: 'A', value: 'test-a', sealed: false }]);
  });

  it('patches only the given keys with check-and-set on the version it read', async () => {
    const http = new FakeHttp()
      .on('GET', /\/data\/apps\/api$/, () => read({ API_KEY: 'test-old', PORT: 8080 }))
      .on('PATCH', /\/data\/apps\/api$/, () => json(200, { data: { version: 4 } }));
    await hostFor(http).writeVariables(service, { API_KEY: 'test-new', ADDED: 'test-added' }, { skipDeploy: true });
    expect(http.calls).toEqual([
      { method: 'GET', url: dataUrl, headers },
      {
        method: 'PATCH', url: dataUrl, headers: { ...headers, 'Content-Type': 'application/merge-patch+json' },
        body: JSON.stringify({ options: { cas: 3 }, data: { API_KEY: 'test-new', ADDED: 'test-added' } }),
      },
    ]);
  });

  it('fails on a check-and-set mismatch without echoing the response', async () => {
    const http = new FakeHttp()
      .on('GET', /\/data\/apps\/api$/, () => read({ API_KEY: 'test-old' }))
      .on('PATCH', /\/data\/apps\/api$/, () => json(400, { errors: ['check-and-set parameter did not match the current version planted-marker'] }));
    const error = await hostFor(http).writeVariables(service, { API_KEY: 'test-new' }, { skipDeploy: true }).catch((caught: unknown) => caught);
    expect(String(error)).toMatch(/changed while keysentry was writing it/);
    expect(String(error)).not.toContain('planted-marker');
    expect(String(error)).not.toContain('test-new');
  });

  it('falls back to a full check-and-set write when patch is refused and every value is a string', async () => {
    const http = new FakeHttp()
      .on('GET', /\/data\/apps\/api$/, () => read({ API_KEY: 'test-old', OTHER: 'test-other' }))
      .on('PATCH', /\/data\/apps\/api$/, () => json(405, { errors: ['unsupported operation'] }))
      .on('POST', /\/data\/apps\/api$/, () => json(200, { data: { version: 4 } }));
    await hostFor(http).writeVariables(service, { API_KEY: 'test-new' }, { skipDeploy: true });
    expect(http.calls[2]).toEqual({
      method: 'POST', url: dataUrl, headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ options: { cas: 3 }, data: { API_KEY: 'test-new', OTHER: 'test-other' } }),
    });
  });

  it('refuses the fallback when a full write would rewrite non-string values', async () => {
    const http = new FakeHttp()
      .on('GET', /\/data\/apps\/api$/, () => read({ API_KEY: 'test-old', PORT: 8080 }))
      .on('PATCH', /\/data\/apps\/api$/, () => json(403, { errors: ['permission denied'] }));
    await expect(hostFor(http).writeVariables(service, { API_KEY: 'test-new' }, { skipDeploy: true })).rejects.toThrow(/patch capability/);
    expect(http.callsTo('POST', /./)).toHaveLength(0);
  });

  it('refuses non-string targets and deleted secrets, and skips unchanged writes', async () => {
    const typed = new FakeHttp().on('GET', /\/data\/apps\/api$/, () => read({ PORT: 8080 }));
    await expect(hostFor(typed).writeVariables(service, { PORT: '9090' }, { skipDeploy: true })).rejects.toThrow(/non-string/);
    expect(typed.calls).toHaveLength(1);

    const deleted = new FakeHttp().on('GET', /\/data\/apps\/api$/, () => read(null, { deletion_time: '2026-01-01T00:00:00Z' }));
    await expect(hostFor(deleted).writeVariables(service, { A: 'test-new' }, { skipDeploy: true })).rejects.toThrow(/deleted or missing/);
    expect(deleted.calls).toHaveLength(1);

    const same = new FakeHttp().on('GET', /\/data\/apps\/api$/, () => read({ A: 'test-same' }));
    await hostFor(same).writeVariables(service, { A: 'test-same' }, { skipDeploy: true });
    expect(same.calls).toHaveLength(1);
  });

  it('encodes path segments and rejects dot segments', async () => {
    const http = new FakeHttp().on('GET', /\/data\/team%20a\/api%3Fx$/, () => read({ A: 'test-a' }));
    await hostFor(http).readVariables({ ...service, serviceId: 'team a/api?x' });
    expect(http.calls[0]?.url).toBe(`${address}/v1/kv/data/team%20a/api%3Fx`);
    await expect(hostFor(new FakeHttp()).readVariables({ ...service, serviceId: 'apps/../sys' })).rejects.toThrow(/secret path is invalid/);
  });

  it('stops listing on a malformed key', async () => {
    const http = new FakeHttp().on('GET', /\?list=true$/, () => json(200, { data: { keys: ['..'] } }));
    await expect(hostFor(http).listServices()).rejects.toThrow('Vault returned an invalid response');
  });

  it.each(['http', 'transport', 'json'] as const)('sanitizes a %s failure', async (failure) => {
    const marker = 'test-planted-vault-marker';
    const http = new FakeHttp().on('GET', /./, () => {
      if (failure === 'transport') throw new Error(`${token} ${marker}`);
      return failure === 'http' ? json(500, { errors: [marker] }) : text(200, `{${marker}`);
    });
    const error = await hostFor(http).readVariables(service).catch((caught: unknown) => caught);
    expect(String(error)).toMatch(/Vault/);
    expect(String(error)).not.toContain(marker);
    expect(String(error)).not.toContain(token);
  });

  it('does not deploy', async () => {
    expect(await hostFor(new FakeHttp()).redeploy(service)).toBeNull();
    await expect(hostFor(new FakeHttp()).deploymentStatus(service, 'x')).rejects.toThrow(/does not create deployments/);
  });
});
