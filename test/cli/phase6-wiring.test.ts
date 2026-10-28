import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/cli/config.js';
import { createRuntime } from '../../src/cli/runtime.js';
import { inspectNetwork } from '../../src/cli/inspection.js';
import { VAULT_ONLY_CREDENTIAL_NAMES, VAULT_SET_NAMES } from '../../src/cli/credential-names.js';
import { createOtlpSink } from '../../src/audit-export/index.js';
import { CREDENTIAL_NAMES } from '../../src/vault/index.js';
import { createRedactor } from '../../src/core/index.js';
import { KMS_CREDENTIAL_NAMES } from '../../src/kms/index.js';
import { EgressBlockedError } from '../../src/net/index.js';
import { FakeHttp, json, silentLogger } from '../helpers/fake-http.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';

const directories: string[] = [];
afterEach(async () => { for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true }); });
async function project(yaml = ''): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-phase6-'));
  directories.push(cwd);
  if (yaml) await writeFile(join(cwd, 'keysentry.yaml'), yaml);
  return cwd;
}
async function runtime(cwd: string, extra: Partial<Parameters<typeof createRuntime>[0]> = {}) {
  return createRuntime({ cwd, vault: createFakeVault(), inflight: createFakeInFlight(), userDir: join(cwd, '.user'), env: {},
    log: silentLogger, feeds: undefined, sleep: async () => {}, stdinIsTTY: true, stdoutIsTTY: true, ...extra });
}

describe('host and credential wiring', () => {
  it('enables phase 5/6 hosts from their credentials and lists only hosts you opted into as disabled', async () => {
    const cwd = await project('hosts:\n  kubernetes: { namespaces: [apps] }\n');
    const config = await loadConfig({ cwd, http: new FakeHttp(), log: silentLogger, env: {
      NETLIFY_TOKEN: 'netlify-token', HEROKU_API_KEY: 'heroku-token', DIGITALOCEAN_TOKEN: 'do-token', ZEABUR_TOKEN: 'zeabur-token',
      SUPABASE_FUNCTIONS_TOKEN: 'supabase-token', COOLIFY_TOKEN: 'coolify-token',
    } });
    expect(config.hosts.map(host => host.id)).toEqual(['dotenv', 'netlify', 'heroku', 'digitalocean', 'supabase-functions', 'zeabur']);
    // Coolify has a token but no base URL; Kubernetes has settings but no server. Hosts you never mentioned stay silent.
    expect(config.disabledHosts.filter(item => !['railway', 'vercel', 'render', 'fly', 'github-actions'].includes(item.host))).toEqual([
      { host: 'coolify', reason: 'Configure hosts.coolify.baseUrl or COOLIFY_URL.' },
      { host: 'kubernetes', reason: 'Configure hosts.kubernetes.server and hosts.kubernetes.namespaces.' },
    ]);
  });

  it('builds the self-hosted and secret-store adapters from settings plus their vault credentials', async () => {
    const cwd = await project([
      'hosts:',
      '  coolify: { baseUrl: "https://coolify.example.test:8000" }',
      '  cloudflare: { accountId: abc123 }',
      '  kubernetes: { server: "https://k8s.example.test:6443", namespaces: [apps] }',
      '  awsSecretsManager: { region: us-east-1, activation: immediate }',
      '  vault: { address: "https://vault.example.test:8200" }',
      '  doppler: { configs: [{ project: app, config: prd }] }',
      '  infisical: { projects: [{ projectId: p1, environments: [prod] }] }',
    ].join('\n'));
    const config = await loadConfig({ cwd, http: new FakeHttp(), log: silentLogger, env: {
      COOLIFY_TOKEN: 'c', CLOUDFLARE_WORKERS_TOKEN: 'w', KUBERNETES_TOKEN: 'k', AWS_SECRETS_MANAGER_ACCESS_KEY_ID: 'AKIAEXAMPLEEXAMPLE00',
      AWS_SECRETS_MANAGER_SECRET_ACCESS_KEY: 'aws-secret', VAULT_TOKEN: 'v', DOPPLER_TOKEN: 'd', INFISICAL_CLIENT_ID: 'id', INFISICAL_CLIENT_SECRET: 'cs',
    } });
    const ids = config.hosts.map(host => host.id);
    for (const id of ['coolify', 'cloudflare-workers', 'kubernetes', 'aws-secrets-manager', 'vault-kv', 'doppler', 'infisical'] as const) expect(ids).toContain(id);
    // Secret stores stay manual unless keysentry.yaml says every consumer reads at use time.
    expect(config.hosts.find(host => host.id === 'aws-secrets-manager')!.capabilities.activation).toBe('immediate');
    expect(config.hosts.find(host => host.id === 'vault-kv')!.capabilities.activation).toBeUndefined();
    expect(config.hosts.find(host => host.id === 'vault-kv')!.capabilities.redeploy).toBe(false);
  });

  it('never registers the Google project id with the redactor', async () => {
    const cwd = await project();
    const redactor = createRedactor();
    await loadConfig({ cwd, http: new FakeHttp(), log: silentLogger, redactor, env: {
      GOOGLE_API_KEYS_PROJECT: '123456789012', GOOGLE_OAUTH_ACCESS_TOKEN: 'ya29.example-access-token-value',
    } });
    expect(redactor.redact('projects/123456789012/locations/global/keys/abc')).toBe('projects/123456789012/locations/global/keys/abc');
    expect(redactor.redact('token ya29.example-access-token-value')).not.toContain('example-access-token-value');
  });

  it('vault set accepts KMS credentials and the OIDC client secret without making them keysentry credentials', async () => {
    expect(VAULT_ONLY_CREDENTIAL_NAMES).toContain('KEYSENTRY_OIDC_CLIENT_SECRET');
    for (const name of KMS_CREDENTIAL_NAMES) expect(VAULT_SET_NAMES).toContain(name);
    for (const name of ['AWS_ACCESS_KEY_ID', 'AZURE_CLIENT_SECRET', 'GOOGLE_SERVICE_ACCOUNT_KEY', 'KEYSENTRY_OIDC_CLIENT_SECRET']) {
      expect(CREDENTIAL_NAMES).not.toContain(name);
    }
    // VAULT_TOKEN is both the Vault KV host token and a Vault Transit KMS credential.
    expect(CREDENTIAL_NAMES).toContain('VAULT_TOKEN');
    expect(CREDENTIAL_NAMES).toContain('KEYSENTRY_PROXY_AUTH');
    const cwd = await project();
    const vault = createFakeVault();
    const rt = await runtime(cwd, { vault, http: new FakeHttp() });
    await rt.vaultSet('KEYSENTRY_OIDC_CLIENT_SECRET', 'oidc-client-secret-value', 'write');
    await rt.vaultSet('AZURE_CLIENT_SECRET', 'azure-client-secret-value', 'read');
    expect((await vault.get('cred/KEYSENTRY_OIDC_CLIENT_SECRET'))?.toString()).toBe('oidc-client-secret-value');
    expect((await vault.get('cred/AZURE_CLIENT_SECRET@read'))?.toString()).toBe('azure-client-secret-value');
    const status = await rt.vaultStatus();
    expect(status.credentials).toEqual(expect.arrayContaining([{ name: 'KEYSENTRY_OIDC_CLIENT_SECRET', role: 'write' }, { name: 'AZURE_CLIENT_SECRET', role: 'read' }]));
    expect(status.supportedNames).toContain('KEYSENTRY_OIDC_CLIENT_SECRET');
    await expect(rt.vaultSet('SOME_APP_SECRET', 'x', 'write')).rejects.toThrow('Unknown credential name');
  });
});

describe('network wiring (notes/network-enterprise.md)', () => {
  it('a configured proxy builds the proxy transport, and doctor reports it', async () => {
    const cwd = await project('network:\n  proxy: "http://127.0.0.1:9"\n');
    const rt = await runtime(cwd);
    expect(rt.network.summary.proxy).toMatchObject({ origin: 'http://127.0.0.1:9', source: 'config' });
    // The node transport connects to the proxy (nothing listens on port 9), never directly to the destination.
    await expect(rt.network.transport.request({ method: 'GET', url: 'https://api.openai.com/v1/models' }))
      .rejects.toMatchObject({ code: 'PROXY_UNREACHABLE' });
    const doctor = await rt.doctor();
    expect(doctor.items).toEqual(expect.arrayContaining([expect.objectContaining({ area: 'network', title: 'Proxy', status: 'ok' })]));
  });

  it('a broken CA file refuses every request instead of silently going direct', async () => {
    const cwd = await project('network:\n  caFile: ca.pem\n');
    await writeFile(join(cwd, 'ca.pem'), 'not a certificate');
    const rt = await runtime(cwd);
    expect(rt.network.summary.ca).toMatchObject({ path: 'ca.pem', error: expect.any(String) });
    await expect(rt.network.transport.request({ method: 'GET', url: 'https://api.openai.com/v1/models' })).rejects.toThrow();
    const doctor = await rt.doctor();
    expect(doctor.items.some(item => item.area === 'network' && item.status === 'fail')).toBe(true);
  });

  it('offline mode removes feed hosts from the runtime, the monitor and keysentry network', async () => {
    const cwd = await project('network:\n  offline: true\nmonitor:\n  feeds: [{ url: "https://feeds.example.test/rss" }]\n');
    const rt = await runtime(cwd, { http: new FakeHttp() });
    expect(rt.network.feedMode).toEqual({ offline: true, source: 'config' });
    expect(rt.rules.some(rule => rule.owner === 'feed')).toBe(false);
    expect(rt.rules.some(rule => rule.host === 'feeds.example.test')).toBe(false);
    expect(rt.rules.some(rule => rule.host === 'api.openai.com')).toBe(true);
    expect(rt.config.monitor.feeds).toEqual([]);
    const network = await inspectNetwork({ cwd, env: {} });
    expect(network.rules.some(rule => rule.owner === 'feed')).toBe(false);
    expect(network.status[0]).toMatch(/^Offline mode is on/);
  });

  it('online, keysentry network still lists feeds and the plain status is empty', async () => {
    const cwd = await project();
    const network = await inspectNetwork({ cwd, env: {} });
    expect(network.rules.some(rule => rule.owner === 'feed')).toBe(true);
    expect(network.status).toEqual([]);
  });
});

describe('KMS and audit export egress', () => {
  it('KMS and audit export hosts appear in keysentry network', async () => {
    const cwd = await project([
      'kms: { provider: vault-transit, address: "https://vault.example.test", keyName: keysentry }',
      'audit:',
      '  export:',
      '    - { kind: otlp, id: otel, url: "https://otel.example.test" }',
      '    - { kind: webhook, id: hook, url: "https://hooks.example.test/audit" }',
    ].join('\n'));
    const network = await inspectNetwork({ cwd, env: {} });
    expect(network.rules).toEqual(expect.arrayContaining([
      expect.objectContaining({ host: 'vault.example.test', purpose: 'Vault Transit key you configured (wraps the state key)' }),
      expect.objectContaining({ host: 'otel.example.test', purpose: 'audit export you configured' }),
      expect.objectContaining({ host: 'hooks.example.test', purpose: 'audit export you configured' }),
    ]));
  });

  it('the runtime lists audit export hosts and gives each target a single-host client that follows no redirect', async () => {
    const cwd = await project('audit:\n  export:\n    - { kind: otlp, id: otel, url: "https://otel.example.test" }\n');
    const http = new FakeHttp()
      .on('POST', /^https:\/\/otel\.example\.test\/v1\/logs$/, () => json(200, {}))
      .on('POST', /^https:\/\/otel\.example\.test\/moved$/, () => ({ status: 307, headers: { location: 'https://other.example.test/v1/logs' }, text: '', json: () => ({}) }));
    const rt = await runtime(cwd, { http });
    expect(rt.rules.some(rule => rule.host === 'otel.example.test')).toBe(true);
    const client = rt.singleHostHttp('https://otel.example.test/v1/logs', 'audit export you configured');
    expect((await client.request({ method: 'POST', url: 'https://otel.example.test/v1/logs', body: '{}' })).status).toBe(200);
    await expect(client.request({ method: 'POST', url: 'https://api.openai.com/v1/models', body: '{}' })).rejects.toBeInstanceOf(EgressBlockedError);
    await expect(client.request({ method: 'POST', url: 'https://otel.example.test/moved', body: '{}' })).rejects.toThrow();
    expect(http.calls.some(call => call.url.startsWith('https://other.example.test'))).toBe(false);
  });

  it('an OTLP target on a single-host client may use any header name; a shared client keeps the credential-name rule', async () => {
    const vault = createFakeVault({ 'audit-export/otel/header': Buffer.from('X-Honeycomb-Team: header-value-1') });
    const target = { kind: 'otlp' as const, id: 'otel', url: 'https://otel.example.test' };
    const record = { seq: 1, at: '2026-10-28T10:00:00.000Z', kind: 'doctor', summary: 'Doctor checks completed.' };
    const single = new FakeHttp().on('POST', /otel\.example\.test/, () => json(200, {}));
    await createOtlpSink(target, { http: single, vault, now: () => new Date('2026-10-28T10:00:00Z'), singleHost: true }).deliver([record as never]);
    expect(single.calls[0]!.headers).toMatchObject({ 'x-honeycomb-team': 'header-value-1' });
    const shared = new FakeHttp().on('POST', /otel\.example\.test/, () => json(200, {}));
    await expect(createOtlpSink(target, { http: shared, vault, now: () => new Date() }).deliver([record as never])).rejects.toThrow(/token, secret, key or auth/);
    expect(shared.calls).toHaveLength(0);
  });
});
