import { describe, expect, it } from 'vitest';
import { createKubernetesHost, type KubernetesHostOptions } from '../../src/hosts/kubernetes.js';
import type { HttpRequest, ServiceRef } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const server = 'https://k8s.example.test:6443';
const token = 'k8s-test-bearer-token';
const auth = { Authorization: `Bearer ${token}`, Accept: 'application/json' };
const b64 = (value: string) => Buffer.from(value, 'utf8').toString('base64');
const service: ServiceRef = {
  host: 'kubernetes', projectId: 'apps', projectName: 'apps', serviceId: 'api-env', serviceName: 'api-env',
  environmentId: '', environmentName: '',
};
const secretUrl = `${server}/api/v1/namespaces/apps/secrets/api-env`;
const deploymentUrl = (name: string) => `${server}/apis/apps/v1/namespaces/apps/deployments/${name}`;

function hostFor(http: FakeHttp, extra: Partial<KubernetesHostOptions> = {}) {
  return createKubernetesHost({ server, token, namespaces: ['apps'], http, log: silentLogger, ...extra });
}

function secret(overrides: Record<string, unknown> = {}) {
  return {
    apiVersion: 'v1', kind: 'Secret', type: 'Opaque',
    metadata: {
      name: 'api-env', namespace: 'apps', resourceVersion: '4711', uid: 'uid-1',
      labels: { app: 'api' }, annotations: { owner: 'platform' },
    },
    data: { OPENAI_API_KEY: b64('test-current-openai-value'), OTHER: b64('test-other-value') },
    ...overrides,
  };
}

function deployment(overrides: { spec?: Record<string, unknown>; status?: Record<string, unknown>; generation?: number } = {}) {
  return {
    metadata: { name: 'api', namespace: 'apps', generation: overrides.generation ?? 7 },
    spec: {
      replicas: 2,
      template: {
        metadata: { labels: { app: 'api' } },
        spec: { containers: [{ name: 'api', envFrom: [{ secretRef: { name: 'api-env' } }] }] },
      },
      ...overrides.spec,
    },
    status: { observedGeneration: 7, replicas: 2, updatedReplicas: 2, availableReplicas: 2, ...overrides.status },
  };
}

describe('Kubernetes host', () => {
  it('reports readable values, single-call writes and redeploy only when restarts are configured', () => {
    expect(hostFor(new FakeHttp()).capabilities).toEqual({ readValues: true, batchWrite: true, redeploy: false });
    expect(hostFor(new FakeHttp(), { restartDeployments: { 'apps/api-env': ['api'] } }).capabilities)
      .toEqual({ readValues: true, batchWrite: true, redeploy: true });
    expect(hostFor(new FakeHttp()).id).toBe('kubernetes');
  });

  it.each([
    'http://k8s.example.test', 'https://user:pass@k8s.example.test', 'https://k8s.example.test/api',
    'https://k8s.example.test/?x=1', 'not a url',
  ])('rejects the server URL %s', (value) => {
    expect(() => createKubernetesHost({ server: value, token, namespaces: ['apps'], http: new FakeHttp(), log: silentLogger }))
      .toThrow(/Kubernetes server URL/);
  });

  it('requires namespaces and valid restart keys', () => {
    expect(() => hostFor(new FakeHttp(), { namespaces: [] })).toThrow(/namespace/);
    expect(() => hostFor(new FakeHttp(), { namespaces: ['Bad_NS'] })).toThrow(/namespace/);
    expect(() => hostFor(new FakeHttp(), { restartDeployments: { 'api-env': ['api'] } })).toThrow(/restart key/);
  });

  it('lists Secrets across continue pages, skips managed types and sends the selector', async () => {
    const http = new FakeHttp()
      .on('GET', /\/namespaces\/apps\/secrets\?limit=100&labelSelector=team%3Dpay$/, () => json(200, {
        metadata: { continue: 'next/token' },
        items: [
          secret(),
          { ...secret(), type: 'kubernetes.io/service-account-token', metadata: { name: 'sa-token' } },
          { ...secret(), type: 'helm.sh/release.v1', metadata: { name: 'sh.helm.release.v1.api.v3' } },
        ],
      }))
      .on('GET', /\/namespaces\/apps\/secrets\?limit=100&labelSelector=team%3Dpay&continue=next%2Ftoken$/, () => json(200, {
        metadata: { continue: '' },
        // A TLS pair is renewed by its issuer (skipped since fix-phase6); an ordinary Secret on this page is listed.
        items: [{ ...secret(), type: 'kubernetes.io/tls', metadata: { name: 'tls-cert' } }, { ...secret(), metadata: { name: 'billing' } }],
      }))
      .on('GET', /\/namespaces\/jobs\/secrets\?limit=100&labelSelector=team%3Dpay$/, () => json(200, {
        metadata: {}, items: [{ metadata: { name: 'worker' }, data: {} }],
      }));

    const refs = await hostFor(http, { namespaces: ['apps', 'jobs'], labelSelector: 'team=pay', cluster: 'prod-eu' }).listServices();
    expect(refs).toEqual([
      { ...service, environmentId: 'prod-eu', environmentName: 'prod-eu' },
      { ...service, serviceId: 'billing', serviceName: 'billing', environmentId: 'prod-eu', environmentName: 'prod-eu' },
      { ...service, projectId: 'jobs', projectName: 'jobs', serviceId: 'worker', serviceName: 'worker', environmentId: 'prod-eu', environmentName: 'prod-eu' },
    ]);
    expect(http.calls).toEqual([
      { method: 'GET', url: `${server}/api/v1/namespaces/apps/secrets?limit=100&labelSelector=team%3Dpay`, headers: auth },
      { method: 'GET', url: `${server}/api/v1/namespaces/apps/secrets?limit=100&labelSelector=team%3Dpay&continue=next%2Ftoken`, headers: auth },
      { method: 'GET', url: `${server}/api/v1/namespaces/jobs/secrets?limit=100&labelSelector=team%3Dpay`, headers: auth },
    ]);
  });

  it('stops when a continue token repeats and reports an expired list without echoing the body', async () => {
    const repeating = new FakeHttp().on('GET', /\/secrets\?/, () => json(200, { metadata: { continue: 'same' }, items: [] }));
    await expect(hostFor(repeating).listServices()).rejects.toThrow('Kubernetes pagination did not advance');
    expect(repeating.calls).toHaveLength(2);

    const expired = new FakeHttp().on('GET', /\/secrets\?/, () => json(410, { message: 'planted-expired-marker' }));
    const error = await hostFor(expired).listServices().catch((caught: unknown) => caught);
    expect(String(error)).toMatch(/expired/);
    expect(String(error)).not.toContain('planted-expired-marker');
  });

  it('decodes values, reports binary data as write-only and handles a Secret without data', async () => {
    const http = new FakeHttp().on('GET', /\/secrets\/api-env$/, () => json(200, secret({
      data: { TEXT: b64('test-plain-value'), EMPTY: '', BINARY: Buffer.from([0xff, 0xfe, 0x00]).toString('base64') },
    })));
    expect(await hostFor(http).readVariables(service)).toEqual([
      { name: 'TEXT', value: 'test-plain-value', sealed: false },
      { name: 'EMPTY', value: '', sealed: false },
      { name: 'BINARY', sealed: true },
    ]);
    expect(http.calls).toEqual([{ method: 'GET', url: secretUrl, headers: auth }]);

    const empty = new FakeHttp().on('GET', /\/secrets\/api-env$/, () => json(200, secret({ data: undefined })));
    expect(await hostFor(empty).readVariables(service)).toEqual([]);
  });

  it('rejects malformed base64 and mismatched objects without echoing values', async () => {
    const http = new FakeHttp().on('GET', /\/secrets\/api-env$/, () => json(200, secret({ data: { BAD: 'not base64 planted-marker' } })));
    const error = await hostFor(http).readVariables(service).catch((caught: unknown) => caught);
    expect(String(error)).toBe('Error: Kubernetes returned an invalid response');

    const other = new FakeHttp().on('GET', /\/secrets\/api-env$/, () => json(200, secret({ metadata: { name: 'other', resourceVersion: '1' } })));
    await expect(hostFor(other).readVariables(service)).rejects.toThrow('Kubernetes returned an invalid response');
  });

  it('writes with PUT of the object as read, keeping metadata, type and other keys, conditional on resourceVersion', async () => {
    const http = new FakeHttp()
      .on('GET', /\/secrets\/api-env$/, () => json(200, secret()))
      .on('PUT', /\/secrets\/api-env$/, (req) => json(200, JSON.parse(req.body!)));
    await hostFor(http).writeVariables(service, { OPENAI_API_KEY: 'test-new-openai-value', NEW_KEY: 'test-added-value' }, { skipDeploy: true });

    expect(http.calls).toHaveLength(2);
    expect(http.calls[0]).toEqual({ method: 'GET', url: secretUrl, headers: auth });
    const put = http.calls[1]!;
    expect(put).toMatchObject({ method: 'PUT', url: secretUrl, headers: { ...auth, 'Content-Type': 'application/json' } });
    expect(JSON.parse(put.body!)).toEqual({
      ...secret(),
      data: {
        OPENAI_API_KEY: b64('test-new-openai-value'),
        OTHER: b64('test-other-value'),
        NEW_KEY: b64('test-added-value'),
      },
    });
  });

  it('fails on a concurrent change (409) without echoing the response or values', async () => {
    const http = new FakeHttp()
      .on('GET', /\/secrets\/api-env$/, () => json(200, secret()))
      .on('PUT', /\/secrets\/api-env$/, () => json(409, { message: 'planted-conflict-marker test-new-value' }));
    const error = await hostFor(http).writeVariables(service, { OPENAI_API_KEY: 'test-new-value' }, { skipDeploy: true })
      .catch((caught: unknown) => caught);
    expect(String(error)).toMatch(/changed while keysentry was writing it/);
    expect(String(error)).not.toContain('planted-conflict-marker');
    expect(String(error)).not.toContain('test-new-value');
  });

  it('refuses immutable, managed-type Secrets and invalid keys before any write', async () => {
    const immutable = new FakeHttp().on('GET', /\/secrets\/api-env$/, () => json(200, secret({ immutable: true })));
    await expect(hostFor(immutable).writeVariables(service, { A: 'test-value' }, { skipDeploy: true })).rejects.toThrow(/immutable/);
    expect(immutable.callsTo('PUT', /./)).toHaveLength(0);

    const managed = new FakeHttp().on('GET', /\/secrets\/api-env$/, () => json(200, secret({ type: 'kubernetes.io/service-account-token' })));
    await expect(hostFor(managed).writeVariables(service, { token: 'test-value' }, { skipDeploy: true })).rejects.toThrow(/managed/);
    expect(managed.callsTo('PUT', /./)).toHaveLength(0);

    const invalid = new FakeHttp();
    await expect(hostFor(invalid).writeVariables(service, { 'BAD/KEY': 'test-value' }, { skipDeploy: true })).rejects.toThrow(/keys may contain/);
    await expect(hostFor(invalid).writeVariables(service, { '..': 'test-value' }, { skipDeploy: true })).rejects.toThrow(/keys may contain/);
    expect(invalid.calls).toEqual([]);

    const none = new FakeHttp();
    await hostFor(none).writeVariables(service, {}, { skipDeploy: false });
    expect(none.calls).toEqual([]);
  });

  it.each(['http', 'transport', 'json'] as const)('sanitizes a %s read failure', async (failure) => {
    const marker = 'test-planted-secret-marker';
    const http = new FakeHttp().on('GET', /\/secrets\/api-env$/, () => {
      if (failure === 'transport') throw new Error(`${token} ${marker}`);
      return failure === 'http' ? json(500, { message: marker }) : text(200, `{${marker}`);
    });
    const error = await hostFor(http).readVariables(service).catch((caught: unknown) => caught);
    expect(String(error)).toMatch(/Kubernetes/);
    expect(String(error)).not.toContain(marker);
    expect(String(error)).not.toContain(token);
  });

  it('returns null from redeploy without requests when no restart is configured', async () => {
    const http = new FakeHttp();
    expect(await hostFor(http).redeploy(service)).toBeNull();
    expect(http.calls).toEqual([]);
  });

  it('restarts configured Deployments by patching only the pod-template annotation', async () => {
    const http = new FakeHttp()
      .on('GET', /\/deployments\/(api|worker)$/, (_req, match) => json(200, match[1] === 'api' ? deployment() : {
        ...deployment(),
        metadata: { name: 'worker', generation: 3 },
        spec: {
          replicas: 1,
          template: { spec: { containers: [{ name: 'w', env: [{ name: 'K', valueFrom: { secretKeyRef: { name: 'api-env', key: 'OTHER' } } }] }] } },
        },
      }))
      .on('PATCH', /\/deployments\/(api|worker)$/, (_req, match) => json(200, { metadata: { name: match[1], generation: match[1] === 'api' ? 8 : 4 } }));
    const host = hostFor(http, {
      restartDeployments: { 'apps/api-env': ['api', 'worker'] },
      now: () => new Date('2026-10-28T12:34:56.789Z'),
    });

    const id = await host.redeploy(service);
    expect(id).toMatch(/^k8s-restart:v1:/);
    expect(http.calls.map((call) => `${call.method} ${call.url}`)).toEqual([
      `GET ${deploymentUrl('api')}`, `GET ${deploymentUrl('worker')}`,
      `PATCH ${deploymentUrl('api')}`, `PATCH ${deploymentUrl('worker')}`,
    ]);
    for (const patch of http.callsTo('PATCH', /./)) {
      expect(patch.headers).toEqual({ ...auth, 'Content-Type': 'application/merge-patch+json' });
      expect(JSON.parse(patch.body!)).toEqual({
        spec: { template: { metadata: { annotations: { 'kubectl.kubernetes.io/restartedAt': '2026-10-28T12:34:56Z' } } } },
      });
    }
    const decoded = JSON.parse(Buffer.from(id!.slice('k8s-restart:v1:'.length), 'base64url').toString('utf8'));
    expect(decoded).toEqual([{ name: 'api', generation: 8 }, { name: 'worker', generation: 4 }]);
  });

  it('refuses to restart a Deployment that does not reference the Secret or is paused, before any patch', async () => {
    const unrelated = new FakeHttp().on('GET', /\/deployments\/api$/, () => json(200, deployment({
      spec: { template: { spec: { containers: [{ name: 'api', envFrom: [{ secretRef: { name: 'other-secret' } }] }] } } },
    })));
    await expect(hostFor(unrelated, { restartDeployments: { 'apps/api-env': ['api'] } }).redeploy(service))
      .rejects.toThrow(/does not reference this Secret/);
    expect(unrelated.callsTo('PATCH', /./)).toHaveLength(0);

    const paused = new FakeHttp().on('GET', /\/deployments\/api$/, () => json(200, deployment({ spec: { paused: true } })));
    await expect(hostFor(paused, { restartDeployments: { 'apps/api-env': ['api'] } }).redeploy(service)).rejects.toThrow(/paused/);
    expect(paused.callsTo('PATCH', /./)).toHaveLength(0);
  });

  it('accepts volume and projected references when validating restarts', async () => {
    for (const volumes of [
      [{ name: 'v', secret: { secretName: 'api-env' } }],
      [{ name: 'v', projected: { sources: [{ secret: { name: 'api-env' } }] } }],
    ]) {
      const http = new FakeHttp()
        .on('GET', /\/deployments\/api$/, () => json(200, deployment({ spec: { template: { spec: { containers: [{ name: 'c' }], volumes } } } })))
        .on('PATCH', /\/deployments\/api$/, () => json(200, { metadata: { generation: 8 } }));
      await expect(hostFor(http, { restartDeployments: { 'apps/api-env': ['api'] } }).redeploy(service)).resolves.toMatch(/^k8s-restart:v1:/);
    }
  });

  it('reports rollout status from generation, replica counts and the progress deadline', async () => {
    const id = `k8s-restart:v1:${Buffer.from(JSON.stringify([{ name: 'api', generation: 8 }])).toString('base64url')}`;
    const statusFor = async (body: unknown) => {
      const http = new FakeHttp().on('GET', /\/deployments\/api$/, () => json(200, body));
      return hostFor(http, { restartDeployments: { 'apps/api-env': ['api'] } }).deploymentStatus(service, id);
    };
    expect(await statusFor(deployment({ generation: 8, status: { observedGeneration: 7 } }))).toBe('pending');
    expect(await statusFor(deployment({ generation: 8, status: { observedGeneration: 8, updatedReplicas: 1 } }))).toBe('pending');
    expect(await statusFor(deployment({ generation: 8, status: { observedGeneration: 8, replicas: 3 } }))).toBe('pending');
    expect(await statusFor(deployment({ generation: 8, status: { observedGeneration: 8, availableReplicas: 1 } }))).toBe('pending');
    expect(await statusFor(deployment({ generation: 8, status: { observedGeneration: 8 } }))).toBe('success');
    expect(await statusFor(deployment({
      generation: 8,
      status: { observedGeneration: 8, updatedReplicas: 1, conditions: [{ type: 'Progressing', status: 'False', reason: 'ProgressDeadlineExceeded' }] },
    }))).toBe('failed');
    await expect(hostFor(new FakeHttp()).deploymentStatus(service, 'not-an-id')).rejects.toThrow(/deployment id is invalid/);
  });

  it('never puts the token in a URL', async () => {
    const http = new FakeHttp().on('GET', /./, () => json(200, { metadata: {}, items: [] }));
    await hostFor(http).listServices();
    expect(http.calls.every((call: HttpRequest) => !call.url.includes(token))).toBe(true);
  });
});
