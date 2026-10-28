// fix-phase6: host fixes (notes/fix-phase6.md M2, L5).
import { describe, expect, it } from 'vitest';
import { createAwsSecretsManagerHost, replaceJsonStringValues } from '../../src/hosts/aws-secrets-manager.js';
import { createCloudflareWorkersHost } from '../../src/hosts/cloudflare-workers.js';
import { createDigitalOceanHost } from '../../src/hosts/digitalocean.js';
import { createDopplerHost } from '../../src/hosts/doppler.js';
import { createKubernetesHost, kubernetesSecretManager } from '../../src/hosts/kubernetes.js';
import type { HttpRequest, ServiceRef } from '../../src/types.js';
import { FakeHttp, json, silentLogger } from '../helpers/fake-http.js';

async function failure(promise: Promise<unknown>): Promise<string> {
  const error = await promise.then(() => undefined, (caught: unknown) => caught);
  expect(error).toBeInstanceOf(Error);
  return String(error);
}

describe('Kubernetes Secrets managed by a controller (M2)', () => {
  const server = 'https://k8s.example.test:6443';
  const b64 = (value: string) => Buffer.from(value, 'utf8').toString('base64');
  const service: ServiceRef = { host: 'kubernetes', projectId: 'apps', projectName: 'apps', serviceId: 'api-env', serviceName: 'api-env', environmentId: '', environmentName: '' };
  const secret = (metadata: Record<string, unknown>) => ({ apiVersion: 'v1', kind: 'Secret', type: 'Opaque',
    metadata: { name: 'api-env', namespace: 'apps', resourceVersion: '7', ...metadata }, data: { OPENAI_API_KEY: b64('sk-old-value-from-the-source-store') } });
  const managed: [string, Record<string, unknown>, RegExp][] = [
    ['an owner reference of any kind', { ownerReferences: [{ apiVersion: 'example.io/v1', kind: 'Widget', name: 'w', uid: 'u' }] }, /the resource that owns it/],
    ['an ExternalSecret owner', { ownerReferences: [{ apiVersion: 'external-secrets.io/v1beta1', kind: 'ExternalSecret', name: 'api-env', uid: 'u', controller: true }] }, /External Secrets/],
    ['External Secrets labels without an owner (creationPolicy Merge)', { annotations: { 'reconcile.external-secrets.io/data-hash': 'abc' } }, /External Secrets/],
    ['a Sealed Secrets take-over annotation', { annotations: { 'sealedsecrets.bitnami.com/managed': 'true' } }, /Sealed Secrets/],
    ['Vault Secrets Operator labels', { labels: { 'app.kubernetes.io/managed-by': 'hashicorp-vso', 'app.kubernetes.io/component': 'secret-sync' } }, /Vault Secrets Operator/],
    ['a cert-manager certificate', { annotations: { 'cert-manager.io/certificate-name': 'api' } }, /cert-manager/],
    ['a legacy service account token', { annotations: { 'kubernetes.io/service-account.name': 'deployer' } }, /service account token/],
  ];

  it.each(managed)('skips a Secret with %s when listing, reading and writing', async (_label, metadata, manager) => {
    const logs: string[] = [];
    const http = new FakeHttp()
      .on('GET', /\/namespaces\/apps\/secrets\?/, () => json(200, { metadata: {}, items: [secret(metadata), { ...secret({}), metadata: { name: 'plain' } }] }))
      .on('GET', /\/namespaces\/apps\/secrets\/api-env$/, () => json(200, secret(metadata)))
      .on('PUT', /\/namespaces\/apps\/secrets\/api-env$/, (req: HttpRequest) => json(200, JSON.parse(req.body!)));
    const host = createKubernetesHost({ server, token: 'kube-token', namespaces: ['apps'], http,
      log: { ...silentLogger, info: (message: string) => logs.push(message) } });

    expect((await host.listServices()).map(ref => ref.serviceId)).toEqual(['plain']);
    expect(logs.join('\n')).toMatch(manager);
    expect(logs.join('\n')).toMatch(/Rotate the key in its source store/);
    expect(await host.readVariables(service)).toEqual([]);
    const error = await failure(host.writeVariables(service, { OPENAI_API_KEY: 'sk-new-value' }, { skipDeploy: true }));
    expect(error).toMatch(manager);
    expect(error).not.toContain('sk-');
    expect(http.callsTo('PUT', /secrets\/api-env$/)).toHaveLength(0);
  });

  it('leaves ordinary Secrets alone and describes owners only with fixed text', () => {
    expect(kubernetesSecretManager(secret({ labels: { app: 'api' }, annotations: { team: 'pay' } }))).toBeNull();
    expect(kubernetesSecretManager(secret({ ownerReferences: [] }))).toBeNull();
    expect(kubernetesSecretManager(secret({ ownerReferences: [{ kind: 'sk-proj-looks-like-a-key' }] }))).toBe('the resource that owns it');
  });
});

describe('DigitalOcean credentials outside envs (L5)', () => {
  const ciphertext = 'EV[1:zqiRIeaaYK/NqctZDYzy6t0pTrtRDez8:wqGpZRrsKN5nPhWQrS479cfBiXT0WQ==]';
  const apiService: ServiceRef = { host: 'digitalocean', projectId: 'app-1', projectName: 'web-app', serviceId: 'services/api', serviceName: 'api', environmentId: '', environmentName: '' };
  const app = (spec: Record<string, unknown>) => ({ id: 'app-1', spec: { name: 'web-app', services: [{ name: 'api', envs: [{ key: 'OPENAI_API_KEY', type: 'GENERAL', value: 'old' }], ...spec }] } });

  it.each([
    ['a plain Datadog key', { log_destinations: [{ name: 'dd', datadog: { api_key: 'plain-datadog-key' } }] }],
    ['a masked Logtail token', { log_destinations: [{ name: 'lt', logtail: { token: '********' } }] }],
    ['an empty OpenSearch password', { log_destinations: [{ name: 'os', open_search: { basic_auth: { user: 'u', password: '' } } }] }],
    ['plain registry credentials', { image: { registry_type: 'DOCKER_HUB', registry_credentials: 'user:token' } }],
  ])('refuses a whole-spec write when the spec holds %s', async (_label, spec) => {
    const http = new FakeHttp().on('GET', /\/apps\/app-1$/, () => json(200, { app: app(spec) })).on('PUT', /./, () => json(200, {}));
    const error = await failure(createDigitalOceanHost({ token: 't', http, log: silentLogger }).writeVariables(apiService, { OPENAI_API_KEY: 'new' }, { skipDeploy: true }));
    expect(error).toMatch(/not encrypted.*DigitalOcean control panel/);
    expect(http.callsTo('PUT', /./)).toHaveLength(0);
  });

  it('writes when those credentials come back as ciphertext', async () => {
    const http = new FakeHttp()
      .on('GET', /\/apps\/app-1$/, () => json(200, { app: app({ log_destinations: [{ name: 'dd', datadog: { api_key: ciphertext } }],
        image: { registry_type: 'GHCR', registry_credentials: ciphertext } }) }))
      .on('PUT', /\/apps\/app-1$/, () => json(200, { app: { pending_deployment: { id: 'dep-1' } } }));
    await createDigitalOceanHost({ token: 't', http, log: silentLogger }).writeVariables(apiService, { OPENAI_API_KEY: 'new' }, { skipDeploy: true });
    const sent = JSON.parse(http.callsTo('PUT', /./)[0]!.body!) as { spec: { services: { log_destinations: unknown; image: unknown }[] } };
    expect(sent.spec.services[0]!.log_destinations).toEqual([{ name: 'dd', datadog: { api_key: ciphertext } }]);
  });
});

describe('Cloudflare Pages settings beyond env_vars (L5)', () => {
  const accountId = '0123456789abcdef0123456789abcdef';
  const pages: ServiceRef = { host: 'cloudflare-workers', projectId: accountId, projectName: accountId, serviceId: 'pages:site', serviceName: 'site', environmentId: 'production', environmentName: 'production' };
  const ok = (result: unknown) => json(200, { success: true, errors: [], messages: [], result });

  it('reports a write that changed bindings or the compatibility date', async () => {
    let calls = 0;
    const project = (compat: string) => ({ name: 'site', deployment_configs: {
      production: { compatibility_date: compat, kv_namespaces: { CACHE: { namespace_id: 'ns-1' } }, env_vars: { API_KEY: { type: 'secret_text' } } },
      preview: { env_vars: {} } } });
    const http = new FakeHttp()
      .on('GET', /\/pages\/projects\/site$/, () => ok(project(calls++ === 0 ? '2026-01-01' : '2026-10-01')))
      .on('PATCH', /\/pages\/projects\/site$/, () => ok({}));
    const host = createCloudflareWorkersHost({ token: 't', accountId, http, log: silentLogger });
    const error = await failure(host.writeVariables(pages, { API_KEY: 'new-secret' }, { skipDeploy: true }));
    expect(error).toMatch(/Pages settings changed beyond this update/);
    expect(error).not.toContain('new-secret');
  });
});

describe('Doppler change requests keep visibility and value type (L5)', () => {
  it('sends the current visibility and value type with each change', async () => {
    const http = new FakeHttp()
      .on('GET', /\/v3\/configs\/config\/secrets\?/, () => json(200, { secrets: {
        API_KEY: { raw: 'old', computed: 'old', rawVisibility: { type: 'restricted' }, rawValueType: { type: 'string' } },
        CONFIG: { raw: '{"a":1}', computed: '{"a":1}', rawVisibility: { type: 'unmasked' }, rawValueType: { type: 'json' } },
      } }))
      .on('POST', /\/v3\/configs\/config\/secrets$/, () => json(200, { secrets: {} }));
    const host = createDopplerHost({ token: 'dp.st.x', http, log: silentLogger });
    const service: ServiceRef = { host: 'doppler', projectId: 'backend', projectName: 'backend', serviceId: 'prd', serviceName: 'prd', environmentId: '', environmentName: '' };
    await host.writeVariables(service, { API_KEY: 'new', CONFIG: '{"a":2}' }, { skipDeploy: true });
    const changes = (JSON.parse(http.callsTo('POST', /./)[0]!.body!) as { change_requests: Record<string, unknown>[] }).change_requests;
    expect(changes).toEqual([
      { name: 'API_KEY', originalName: 'API_KEY', value: 'new', originalValue: 'old', visibility: 'restricted', valueType: { type: 'string' } },
      { name: 'CONFIG', originalName: 'CONFIG', value: '{"a":2}', originalValue: '{"a":1}', visibility: 'unmasked', valueType: { type: 'json' } },
    ]);
  });
});

describe('AWS Secrets Manager keeps the secret\'s JSON formatting (L5)', () => {
  it('replaces only the changed string values in place', () => {
    const original = '{\r\n    "OPENAI_API_KEY" : "old-openai",\r\n    "PORT": 5432,\r\n    "nested": {"OPENAI_API_KEY": "inner"},\r\n    "esc": "a\\/b"\r\n}\r\n';
    const next = replaceJsonStringValues(original, new Map([['OPENAI_API_KEY', 'new "quoted" value']]));
    expect(next).toBe('{\r\n    "OPENAI_API_KEY" : "new \\"quoted\\" value",\r\n    "PORT": 5432,\r\n    "nested": {"OPENAI_API_KEY": "inner"},\r\n    "esc": "a\\/b"\r\n}\r\n');
    expect(replaceJsonStringValues(original, new Map([['ADDED', 'x']]))).toBeUndefined();
  });

  it('writes the formatted text back when only existing values change', async () => {
    const arn = 'arn:aws:secretsmanager:eu-west-1:123456789012:secret:prod/api-AbCdEf';
    const current = 'a1b2c3d4-0000-4000-8000-000000000001';
    const original = '{\n  "OPENAI_API_KEY": "test-old-openai",\n  "PORT": 5432\n}';
    const bodies: Record<string, unknown>[] = [];
    const http = new FakeHttp().on('POST', /secretsmanager/, (req: HttpRequest) => {
      const target = req.headers?.['x-amz-target']?.replace('secretsmanager.', '');
      bodies.push(JSON.parse(req.body ?? '{}'));
      if (target === 'DescribeSecret') return json(200, { ARN: arn, Name: 'prod/api', VersionIdsToStages: { [current]: ['AWSCURRENT'] } });
      if (target === 'GetSecretValue') return json(200, { ARN: arn, Name: 'prod/api', VersionId: current, SecretString: original });
      if (target === 'PutSecretValue') return json(200, { ARN: arn, Name: 'prod/api', VersionId: 'a1b2c3d4-0000-4000-8000-0000000000ff', VersionStages: ['KEYSENTRY_PENDING'] });
      return json(200, { ARN: arn, Name: 'prod/api' });
    });
    const host = createAwsSecretsManagerHost({ region: 'eu-west-1', credentials: { accessKeyId: 'AKIDEXAMPLESECRETSMGR', secretAccessKey: 'test-secret-access-key' },
      http, log: silentLogger, randomUUID: () => 'a1b2c3d4-0000-4000-8000-0000000000ff' });
    await host.writeVariables({ host: 'aws-secrets-manager', projectId: 'eu-west-1', projectName: 'eu-west-1', serviceId: arn, serviceName: 'prod/api', environmentId: '', environmentName: '' },
      { OPENAI_API_KEY: 'test-new-openai' }, { skipDeploy: true });
    expect(bodies.find(body => typeof body.SecretString === 'string')?.SecretString).toBe('{\n  "OPENAI_API_KEY": "test-new-openai",\n  "PORT": 5432\n}');
  });
});
