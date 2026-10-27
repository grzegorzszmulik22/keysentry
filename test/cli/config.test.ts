import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { loadConfig, loadConfigMetadata } from '../../src/cli/config.js';
import { createRedactor } from '../../src/core/index.js';
import { FakeHttp, json, silentLogger } from '../helpers/fake-http.js';
import { createFakeVault } from '../helpers/fake-vault.js';

const dirs: string[] = [];
async function directory() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-config-'));
  dirs.push(cwd);
  return cwd;
}
afterEach(async () => {
  for (const path of dirs.splice(0)) await rm(path, { recursive: true, force: true });
});

describe('CLI configuration', () => {
  it('uses read-role credentials for scans and write-role credentials only when requested', async () => {
    const cwd = await directory();
    const vault = createFakeVault({
      'cred/VERCEL_TOKEN@read': Buffer.from('read-vercel-token'),
      'cred/VERCEL_TOKEN': Buffer.from('write-vercel-token'),
      'cred/OPENAI_ADMIN_KEY@read': Buffer.from('read-provider-token'),
      'cred/OPENAI_ADMIN_KEY': Buffer.from('write-provider-token'),
    });
    const http = new FakeHttp().on('GET', /^https:\/\/api.vercel.com\/v10\/projects/, () => json(200, { projects: [] }));
    const redactor = createRedactor();
    const options = { cwd, vault, http, redactor, log: silentLogger, env: { VERCEL_TOKEN: 'env-vercel-token' } };
    const read = await loadConfig(options);
    await read.hosts.find(host => host.id === 'vercel')!.listServices();
    expect(http.calls[0]?.headers?.Authorization).toBe('Bearer read-vercel-token');
    expect(read.providerCtx.credentials.OPENAI_ADMIN_KEY).toBe('read-provider-token');
    const write = await loadConfig({ ...options, role: 'write' });
    await write.hosts.find(host => host.id === 'vercel')!.listServices();
    expect(http.calls[1]?.headers?.Authorization).toBe('Bearer write-vercel-token');
    expect(write.providerCtx.credentials.OPENAI_ADMIN_KEY).toBe('write-provider-token');
    expect(redactor.redact('read-vercel-token write-vercel-token read-provider-token write-provider-token')).not.toContain('token');
  });

  it('loads permission and egress metadata without opening adapters or credentials', async () => {
    const cwd = await directory();
    await writeFile(join(cwd, 'keysentry.yaml'), [
      'network:', '  allowHosts: [API.Example.test, api.example.test]',
      'hosts:', '  dotenv:', '    roots: [services]',
      'monitor:', '  feeds:', '    - url: https://feeds.example.test/advisories?private=hidden',
      '  webhooks: [https://notify.example.test/private-webhook]',
    ].join('\n'));
    const metadata = await loadConfigMetadata({ cwd, env: {} });
    expect(metadata.userHostRules).toEqual([{ host: 'api.example.test', owner: 'user', purpose: 'host you added in keysentry.yaml' }]);
    expect(metadata.feedUrls).toEqual(['https://feeds.example.test/advisories?private=hidden']);
    expect(metadata.webhooks).toEqual(['https://notify.example.test/private-webhook']);
    expect(metadata.dotenvRoots).toEqual([resolve(cwd, 'services')]);
    expect(metadata.settings.rotation.graceSeconds).toBe(120);
  });

  it.each(['*.example.test', '127.0.0.1', '[::1]', '127.1', '2130706433', 'https://example.test', 'example.test/path', 'example.test:443', '-bad.example', 'example..test'])('refuses a non-exact DNS allowHosts entry %s without echoing it', async host => {
    const cwd = await directory();
    await writeFile(join(cwd, 'keysentry.yaml'), `network:\n  allowHosts: [${JSON.stringify(host)}]\n`);
    const attempt = loadConfig({ cwd, env: {}, http: new FakeHttp(), log: silentLogger });
    await expect(attempt).rejects.toThrow(/network.allowHosts/);
    await expect(attempt).rejects.not.toThrow(host);
  });

  it('converts the configured grace seconds into engine milliseconds and allows zero', async () => {
    const cwd = await directory();
    expect((await loadConfig({ cwd, env: {}, http: new FakeHttp(), log: silentLogger })).rotation.graceMs).toBe(120_000);
    await writeFile(join(cwd, 'keysentry.yaml'), 'rotation:\n  graceSeconds: 0\n');
    expect((await loadConfig({ cwd, env: {}, http: new FakeHttp(), log: silentLogger })).rotation.graceMs).toBe(0);
    await writeFile(join(cwd, 'keysentry.yaml'), 'rotation:\n  graceSeconds: -1\n');
    await expect(loadConfig({ cwd, env: {}, http: new FakeHttp(), log: silentLogger })).rejects.toThrow(/rotation.graceSeconds/);
  });

  it('loads env-only configuration with real factories and safe defaults', async () => {
    const cwd = await directory();
    const http = new FakeHttp().on('GET', /^https:\/\/api.vercel.com\/v10\/projects/, () => json(200, { projects: [] }));
    const config = await loadConfig({ cwd, http, log: silentLogger, env: {
      RAILWAY_PROJECT_TOKEN: 'railway-management-token', VERCEL_TOKEN: 'vercel-management-token',
      RENDER_API_KEY: 'render-management-token', FLY_API_TOKEN: 'fly-management-token', FLY_APPS: 'app-one,app-two',
      GITHUB_TOKEN: 'github-management-token', GITHUB_REPOS: 'acme/service',
      OPENAI_ADMIN_KEY: 'openai-management-token', OPENROUTER_PROVISIONING_KEY: 'router-management-token',
    } });
    expect(config.hosts.map(host => host.id)).toEqual(['railway', 'vercel', 'render', 'fly', 'github-actions', 'dotenv']);
    expect(config.disabledHosts).toEqual([]);
    expect(config.providerCtx.credentials).toEqual({ OPENAI_ADMIN_KEY: 'openai-management-token', OPENROUTER_PROVISIONING_KEY: 'router-management-token' });
    // Phase 1 gives rotations a two-minute undo window unless explicitly disabled.
    expect(config.rotation).toEqual({ dryRun: true, revoke: 'after-deploy', redeploy: true, revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 4, deployTimeoutMs: 600_000, pollIntervalMs: 5_000, graceMs: 120_000 });
    expect(config.monitor.policy).toMatchObject({ autoExecute: false, autoContain: false, containCooldownMinutes: 60, revokeUnconfirmedOnHighConfidence: true });
    expect(config.monitor.intervalMs).toBe(300_000);
    expect(config.settings.hosts.dotenv.roots).toEqual([cwd]);
    await config.hosts.find(host => host.id === 'vercel')!.listServices();
    expect(http.calls[0]?.headers?.Authorization).toBe('Bearer vercel-management-token');
  });

  it('merges YAML scope and policy with environment precedence without credentials in settings', async () => {
    const cwd = await directory();
    await writeFile(join(cwd, 'custom.yaml'), [
      'hosts:', '  vercel:', '    teamId: yaml-team', '    targets: [preview]',
      '  github:', '    repos: [yaml/repo]', '  dotenv:', '    roots: [services]',
      'rotation:', '  revoke: never', '  redeploy: false',
      'monitor:', '  interval: 42', '  autoExecute: false', '  cooldownMinutes: 90',
      '  feeds: []', '  rules:', '    usage_anomaly:', '      action: alert',
    ].join('\n'));
    const config = await loadConfig({ cwd, config: 'custom.yaml', http: new FakeHttp(), log: silentLogger, env: {
      VERCEL_TOKEN: 'vercel-management-token', VERCEL_TEAM_ID: 'env-team', GITHUB_TOKEN: 'github-management-token',
      GITHUB_REPOS: 'env/repo', KEYSENTRY_AUTO_EXECUTE: 'true',
    } });
    expect(config.configPath).toBe(join(cwd, 'custom.yaml'));
    expect(config.settings.hosts.vercel).toMatchObject({ teamId: 'env-team', targets: ['preview'] });
    expect(config.settings.hosts.github.repos).toEqual(['env/repo']);
    expect(config.settings.hosts.dotenv.roots).toEqual([resolve(cwd, 'services')]);
    expect(config.rotation).toMatchObject({ dryRun: true, revoke: 'never', redeploy: false });
    expect(config.monitor).toMatchObject({ intervalMs: 42_000, feeds: [], policy: { autoExecute: true, cooldownMinutes: 90, maxAutoRotationsPerDay: 10, rules: { usage_anomaly: { action: 'alert', scope: 'cluster', minConfidence: 'medium' } } } });
    expect(JSON.stringify(config.settings)).not.toContain('management-token');
  });

  it('disables missing-token hosts and requires repositories for GitHub', async () => {
    const config = await loadConfig({ cwd: await directory(), env: { GITHUB_TOKEN: 'github-management-token' }, http: new FakeHttp(), log: silentLogger });
    expect(config.hosts.map(host => host.id)).toEqual(['dotenv']);
    expect(config.disabledHosts).toHaveLength(5);
    expect(config.disabledHosts.find(host => host.host === 'github-actions')?.reason).toMatch(/repos/i);
  });

  it('loads rotation safety settings and explicit containment policy from YAML', async () => {
    const cwd = await directory();
    await writeFile(join(cwd, 'keysentry.yaml'), [
      'rotation:', '  revokeUnconfirmed: true', '  acceptUnplannedSealed: true',
      '  allowGenerate: false', '  verifyRetries: 0',
      'monitor:', '  autoContain: true', '  containCooldownMinutes: 17',
      '  revokeUnconfirmedOnHighConfidence: false',
    ].join('\n'));
    const config = await loadConfig({ cwd, env: {}, http: new FakeHttp(), log: silentLogger });
    expect(config.rotation).toMatchObject({ revokeUnconfirmed: true, acceptUnplannedSealed: true, allowGenerate: false, verifyRetries: 0 });
    expect(config.monitor.policy).toMatchObject({ autoContain: true, containCooldownMinutes: 17, revokeUnconfirmedOnHighConfidence: false });
  });

  it('overrides containment and high-confidence revocation policy from the environment', async () => {
    const cwd = await directory();
    await writeFile(join(cwd, 'keysentry.yaml'), 'monitor:\n  autoContain: false\n  revokeUnconfirmedOnHighConfidence: true\n');
    const config = await loadConfig({ cwd, env: {
      KEYSENTRY_AUTO_CONTAIN: 'true', KEYSENTRY_REVOKE_UNCONFIRMED_ON_HIGH_CONFIDENCE: 'false',
    }, http: new FakeHttp(), log: silentLogger });
    expect(config.monitor.policy).toMatchObject({ autoContain: true, revokeUnconfirmedOnHighConfidence: false });
    expect(config.settings.monitor).toMatchObject({ autoContain: true, revokeUnconfirmedOnHighConfidence: false });
  });

  it('refuses invalid containment environment booleans without echoing the value', async () => {
    const cwd = await directory();
    for (const name of ['KEYSENTRY_AUTO_CONTAIN', 'KEYSENTRY_REVOKE_UNCONFIRMED_ON_HIGH_CONFIDENCE']) {
      const attempt = loadConfig({ cwd, env: { [name]: 'opaque-invalid-value' }, http: new FakeHttp(), log: silentLogger });
      await expect(attempt).rejects.toThrow(`${name} must be true or false.`);
      await expect(attempt).rejects.not.toThrow('opaque-invalid-value');
    }
  });

  it('disables Fly with an explanatory message when its token has no org or apps', async () => {
    const config = await loadConfig({ cwd: await directory(), env: { FLY_API_TOKEN: 'fly-management-token', FLY_APPS: ', ,' }, http: new FakeHttp(), log: silentLogger });
    expect(config.hosts.some(host => host.id === 'fly')).toBe(false);
    expect(config.disabledHosts.find(host => host.host === 'fly')?.reason).toMatch(/FLY_ORG.*FLY_APPS/);
  });

  it('enables Fly when its scope comes from YAML or the environment', async () => {
    const cwd = await directory();
    await writeFile(join(cwd, 'keysentry.yaml'), 'hosts:\n  fly:\n    org: team-from-yaml\n');
    const yaml = await loadConfig({ cwd, env: { FLY_API_TOKEN: 'fly-management-token' }, http: new FakeHttp(), log: silentLogger });
    expect(yaml.hosts.some(host => host.id === 'fly')).toBe(true);
    await writeFile(join(cwd, 'keysentry.yaml'), '{}');
    const environment = await loadConfig({ cwd, env: { FLY_API_TOKEN: 'fly-management-token', FLY_ORG: 'team-from-env' }, http: new FakeHttp(), log: silentLogger });
    expect(environment.hosts.some(host => host.id === 'fly')).toBe(true);
  });

  it('rejects negative retry counts and containment cooldowns', async () => {
    const cwd = await directory();
    await writeFile(join(cwd, 'keysentry.yaml'), 'rotation:\n  verifyRetries: -1\n');
    await expect(loadConfig({ cwd, env: {}, http: new FakeHttp(), log: silentLogger })).rejects.toThrow(/rotation.verifyRetries/);
    await writeFile(join(cwd, 'keysentry.yaml'), 'monitor:\n  containCooldownMinutes: -1\n');
    await expect(loadConfig({ cwd, env: {}, http: new FakeHttp(), log: silentLogger })).rejects.toThrow(/monitor.containCooldownMinutes/);
  });

  it('reports invalid YAML with line location and never echoes input', async () => {
    const cwd = await directory();
    await writeFile(join(cwd, 'keysentry.yaml'), 'hosts: [super-sensitive-value\n');
    await expect(loadConfig({ cwd, env: {}, http: new FakeHttp(), log: silentLogger })).rejects.toThrow(/Invalid YAML.*line/i);
    await expect(loadConfig({ cwd, env: {}, http: new FakeHttp(), log: silentLogger })).rejects.not.toThrow(/super-sensitive-value/);
  });

  it('reports schema errors by field and refuses unsafe boolean coercion', async () => {
    const cwd = await directory();
    await writeFile(join(cwd, 'keysentry.yaml'), 'monitor:\n  interval: -2\n');
    await expect(loadConfig({ cwd, env: {}, http: new FakeHttp(), log: silentLogger })).rejects.toThrow(/monitor.interval/);
    await writeFile(join(cwd, 'keysentry.yaml'), '{}');
    await expect(loadConfig({ cwd, env: { KEYSENTRY_AUTO_EXECUTE: 'maybe-secret' }, http: new FakeHttp(), log: silentLogger })).rejects.toThrow(/KEYSENTRY_AUTO_EXECUTE.*true or false/);
    await expect(loadConfig({ cwd, env: { KEYSENTRY_AUTO_EXECUTE: 'maybe-secret' }, http: new FakeHttp(), log: silentLogger })).rejects.not.toThrow(/maybe-secret/);
  });

  it('registers credentials and webhooks with the supplied redactor', async () => {
    const redactor = createRedactor();
    const config = await loadConfig({ cwd: await directory(), http: new FakeHttp(), log: silentLogger, redactor,
      env: { RAILWAY_TOKEN: 'host-management-token', OPENAI_ADMIN_KEY: 'provider-management-token', KEYSENTRY_WEBHOOK_URL: 'https://example.test/secret-webhook-token' } });
    expect(redactor.redact('host-management-token provider-management-token https://example.test/secret-webhook-token')).not.toContain('management-token');
    expect(redactor.redact('https://example.test/secret-webhook-token')).not.toContain('secret-webhook-token');
    expect(config.monitor.notifier).toBeDefined();
  });

  it('allows explicit host disabling and reports missing explicit files safely', async () => {
    const cwd = await directory();
    await writeFile(join(cwd, 'keysentry.yaml'), 'hosts:\n  dotenv:\n    enabled: false\n  vercel:\n    enabled: false\n');
    const config = await loadConfig({ cwd, env: { VERCEL_TOKEN: 'vercel-management-token' }, http: new FakeHttp(), log: silentLogger });
    expect(config.hosts).toEqual([]);
    expect(config.disabledHosts.find(host => host.host === 'vercel')?.reason).toMatch(/disabled/i);
    await expect(loadConfig({ cwd, config: 'absent.yaml', env: {}, http: new FakeHttp(), log: silentLogger })).rejects.toThrow(/Configuration file was not found/);
  });
});
