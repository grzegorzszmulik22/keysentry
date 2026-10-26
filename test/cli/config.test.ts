import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { loadConfig } from '../../src/cli/config.js';
import { createRedactor } from '../../src/core/index.js';
import { FakeHttp, json, silentLogger } from '../helpers/fake-http.js';

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
    expect(config.rotation).toEqual({ dryRun: true, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 600_000, pollIntervalMs: 5_000 });
    expect(config.monitor.policy.autoExecute).toBe(false);
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
