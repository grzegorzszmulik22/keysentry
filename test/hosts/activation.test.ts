import { describe, expect, it } from 'vitest';
import {
  activationMode, builtInActivation, canConfirmActivation, createAwsSecretsManagerHost, createCloudflareWorkersHost,
  createCoolifyHost, createDigitalOceanHost, createDopplerHost, createDotenvHost, createFlyHost, createGithubActionsHost,
  createHerokuHost, createInfisicalHost, createKubernetesHost, createNetlifyHost, createRailwayHost, createRenderHost,
  createSupabaseFunctionsHost, createVaultKvHost, createVercelHost, createZeaburHost, needsManualActivation,
} from '../../src/hosts/index.js';
import type { HostAdapter, HostId } from '../../src/types.js';
import { HOST_IDS } from '../../src/types.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';
import { FakeHost, svc } from '../helpers/fakes.js';

const http = new FakeHttp();
const log = silentLogger;
const service = (host: HostId, serviceId: string, environmentId = 'production') => svc(host, serviceId, environmentId);

describe('activation modes (decision 1)', () => {
  it('only redeploy (with redeploys on), on-write and immediate can be confirmed', () => {
    expect(canConfirmActivation('redeploy')).toBe(true);
    expect(canConfirmActivation('redeploy', false)).toBe(false);
    expect(canConfirmActivation('on-write', false)).toBe(true);
    expect(canConfirmActivation('immediate', false)).toBe(true);
    expect(canConfirmActivation('manual')).toBe(false);
  });

  it('keeps every existing host exactly as the old hard-coded lists did', () => {
    // engine cannotConfirmActivation / runtime manualActivation / readiness before phase 6:
    // dotenv, fly and github-actions are manual; Vercel outside production and Railway shared variables are manual.
    const old = (host: HostId, serviceId: string, environmentId: string, redeploy: boolean) => !redeploy
      || ['dotenv', 'fly', 'github-actions'].includes(host)
      || host === 'vercel' && environmentId !== 'production' || host === 'railway' && serviceId === '';
    const cases: [HostId, string, string, boolean][] = [
      ['railway', 'api', 'production', true], ['railway', '', 'production', true], ['vercel', 'web', 'production', true],
      ['vercel', 'web', 'preview', true], ['vercel', 'web', 'development', true], ['render', 'srv', '', true], ['render', 'srv', '', false],
      ['fly', 'app', '', true], ['github-actions', 'acme/repo', '', false], ['dotenv', '/x/.env', '', false],
    ];
    for (const [host, serviceId, environmentId, redeploy] of cases) {
      const fake = new FakeHost(host, { redeploy });
      expect(needsManualActivation(service(host, serviceId, environmentId), fake), `${host}/${serviceId}/${environmentId}`)
        .toBe(old(host, serviceId, environmentId, redeploy));
    }
  });

  it('real adapters declare the same modes as the built-in table', () => {
    const adapters: HostAdapter[] = [
      createRailwayHost({ token: 't', tokenType: 'account', http, log }), createVercelHost({ token: 't', http, log }),
      createRenderHost({ apiKey: 't', http, log }), createFlyHost({ token: 't', apps: ['a'], http, log }),
      createGithubActionsHost({ token: 't', repos: ['acme/repo'], http, log }), createDotenvHost({ roots: [], log }),
      createNetlifyHost({ token: 't', http, log }), createHerokuHost({ token: 't', http, log }), createDigitalOceanHost({ token: 't', http, log }),
      createCloudflareWorkersHost({ token: 't', accountId: 'abc123', http, log }), createSupabaseFunctionsHost({ token: 't', http, log }),
      createCoolifyHost({ token: 't', baseUrl: 'https://coolify.example.test:8000', http, log }), createZeaburHost({ token: 't', http, log }),
      createKubernetesHost({ token: 't', server: 'https://k8s.example.test:6443', namespaces: ['apps'], http, log }),
      createAwsSecretsManagerHost({ region: 'us-east-1', credentials: { accessKeyId: 'AKIAEXAMPLEEXAMPLE00', secretAccessKey: 's' }, http, log }),
      createVaultKvHost({ token: 't', address: 'https://vault.example.test:8200', http, log }), createDopplerHost({ token: 't', http, log }),
      createInfisicalHost({ auth: { accessToken: 't' }, projects: [{ projectId: 'p1', environments: ['prod'] }], http, log }),
    ];
    expect(new Set(adapters.map(adapter => adapter.id))).toEqual(new Set(HOST_IDS));
    const samples: Record<HostId, [string, string][]> = {
      railway: [['api', 'production'], ['', 'production']], vercel: [['web', 'production'], ['web', 'preview']], render: [['srv', '']],
      fly: [['app', '']], 'github-actions': [['acme/repo', '']], dotenv: [['/x/.env', '']],
      netlify: [['site', 'production'], ['site', 'deploy-preview'], ['site', 'branch:feature'], ['', 'production']],
      heroku: [['app', '']], digitalocean: [['', ''], ['services/web', '']],
      'cloudflare-workers': [['worker:api', ''], ['pages:site', 'production']], 'supabase-functions': [['abcdefghijklmnopqrst', '']],
      coolify: [['application:uuid', ''], ['service:uuid', '']], zeabur: [['svc', 'env']],
      kubernetes: [['app-secrets', '']], 'aws-secrets-manager': [['arn', '']], 'vault-kv': [['app/config', '']],
      doppler: [['prd', '']], infisical: [['/', 'prod']],
    };
    for (const adapter of adapters) {
      for (const [serviceId, environmentId] of samples[adapter.id]) {
        const ref = service(adapter.id, serviceId, environmentId);
        expect(activationMode(ref, adapter), `${adapter.id}/${serviceId}/${environmentId}`).toBe(builtInActivation(ref));
      }
    }
  });

  it('maps each phase 5/6 host to its documented mode', () => {
    expect(builtInActivation(service('heroku', 'app'))).toBe('on-write');
    expect(builtInActivation(service('digitalocean', 'services/web'))).toBe('on-write');
    expect(builtInActivation(service('cloudflare-workers', 'worker:api'))).toBe('on-write');
    expect(builtInActivation(service('cloudflare-workers', 'pages:site'))).toBe('manual');
    expect(builtInActivation(service('supabase-functions', 'ref'))).toBe('immediate');
    expect(builtInActivation(service('netlify', 'site', 'production'))).toBe('redeploy');
    expect(builtInActivation(service('netlify', 'site', 'deploy-preview'))).toBe('manual');
    expect(builtInActivation(service('netlify', '', 'production'))).toBe('manual');
    expect(builtInActivation(service('coolify', 'application:x'))).toBe('redeploy');
    expect(builtInActivation(service('coolify', 'service:x'))).toBe('manual');
    expect(builtInActivation(service('zeabur', 'svc'))).toBe('manual');
    for (const store of ['kubernetes', 'aws-secrets-manager', 'vault-kv', 'doppler', 'infisical'] as const) {
      expect(builtInActivation(service(store, 'x'))).toBe('manual');
    }
  });

  it('a Kubernetes Secret confirms activation only when restarts are configured for it', () => {
    const host = createKubernetesHost({ token: 't', server: 'https://k8s.example.test', namespaces: ['apps'],
      restartDeployments: { 'apps/api-secrets': ['api'] }, http, log });
    expect(activationMode({ ...service('kubernetes', 'api-secrets'), projectId: 'apps' }, host)).toBe('redeploy');
    expect(activationMode({ ...service('kubernetes', 'other'), projectId: 'apps' }, host)).toBe('manual');
  });

  it('a declared redeploy without a deploy step cannot confirm', () => {
    const fake = new FakeHost('render', { redeploy: false, activation: 'redeploy' });
    expect(activationMode(service('render', 'srv'), fake)).toBe('manual');
  });
});
