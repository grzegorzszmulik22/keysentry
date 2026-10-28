import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { EGRESS_RULES, matchRule, ruleAuthority, rulesForUserUrls } from '../../src/net/allowlist.js';
import { createGuardedHttp, EgressBlockedError } from '../../src/net/index.js';
import { loadConfigMetadata } from '../../src/cli/config.js';
import type { EgressRule } from '../../src/types.js';
import { FakeHttp, json } from '../helpers/fake-http.js';

// Decision 2 (notes/integration-phase6.md): ports for self-hosted servers.
const directories: string[] = [];
afterEach(async () => { for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true }); });
async function project(yaml: string): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-ports-'));
  directories.push(cwd);
  await writeFile(join(cwd, 'keysentry.yaml'), yaml);
  return cwd;
}

describe('port-carrying user rules', () => {
  const coolify: EgressRule = { host: 'coolify.example.test', owner: 'user', purpose: 'Coolify instance you configured', port: 8000 };

  it('accept exactly the configured host and port', () => {
    expect(matchRule(new URL('https://coolify.example.test:8000/api/v1/applications'), [coolify])).toBe(coolify);
    expect(matchRule(new URL('https://COOLIFY.example.test.:8000/x'), [coolify])).toBe(coolify);
    for (const url of ['https://coolify.example.test/x', 'https://coolify.example.test:443/x', 'https://coolify.example.test:8001/x',
      'https://other.example.test:8000/x', 'http://coolify.example.test:8000/x', 'https://user:pw@coolify.example.test:8000/x']) {
      expect(matchRule(new URL(url), [coolify]), url).toBeNull();
    }
  });

  it('rules without a port keep accepting only 443, and suffix rules never match another port', () => {
    const plain: EgressRule = { host: 'api.example.test', owner: 'user', purpose: 'x' };
    const suffix: EgressRule = { host: '*.example.test', owner: 'user', purpose: 'y' };
    expect(matchRule(new URL('https://api.example.test/'), [plain])).toBe(plain);
    expect(matchRule(new URL('https://api.example.test:8443/'), [plain, suffix])).toBeNull();
    expect(matchRule(new URL('https://a.example.test:8443/'), [suffix])).toBeNull();
    expect(EGRESS_RULES.every(rule => rule.port === undefined)).toBe(true);
  });

  it('a host with both a 443 rule and a port rule picks the rule for the requested port', () => {
    const base: EgressRule = { host: 'vault.example.test', owner: 'user', purpose: 'base' };
    const ported: EgressRule = { host: 'vault.example.test', owner: 'user', purpose: 'ported', port: 8200 };
    expect(matchRule(new URL('https://vault.example.test:8200/v1/sys'), [base, ported])).toBe(ported);
    expect(matchRule(new URL('https://vault.example.test/v1/sys'), [base, ported])).toBe(base);
  });

  it('IP literals stay refused with or without a port', () => {
    const ip: EgressRule = { host: '10.0.0.5', owner: 'user', purpose: 'x', port: 6443 };
    expect(matchRule(new URL('https://10.0.0.5:6443/api'), [ip])).toBeNull();
    expect(() => rulesForUserUrls(['https://10.0.0.5:6443'], 'x', 'config', { allowPort: true })).toThrow(TypeError);
    expect(() => rulesForUserUrls(['https://[::1]:8200'], 'x', 'config', { allowPort: true })).toThrow(TypeError);
  });

  it('rulesForUserUrls keeps a port only when allowed, and dedupes host:port pairs', () => {
    expect(() => rulesForUserUrls(['https://k8s.example.test:6443'], 'x')).toThrow(TypeError);
    expect(rulesForUserUrls(['https://k8s.example.test:6443/', 'https://K8S.example.test:6443/other', 'https://k8s.example.test/'], 'k8s', 'config', { allowPort: true }))
      .toEqual([
        { host: 'k8s.example.test', owner: 'user', purpose: 'k8s', port: 6443, source: 'config' },
        { host: 'k8s.example.test', owner: 'user', purpose: 'k8s', source: 'config' },
      ]);
    expect(ruleAuthority({ host: 'k8s.example.test', owner: 'user', purpose: 'k8s', port: 6443 })).toBe('k8s.example.test:6443');
    expect(ruleAuthority(EGRESS_RULES[0]!)).toBe(EGRESS_RULES[0]!.host);
  });

  it('the guarded client reaches a configured port and blocks every other port on that host', async () => {
    const inner = new FakeHttp().on('GET', /^https:\/\/vault\.example\.test:8200\//, () => json(200, {}));
    const http = createGuardedHttp(inner, { rules: rulesForUserUrls(['https://vault.example.test:8200'], 'Vault server you configured', 'config', { allowPort: true }) });
    expect((await http.request({ method: 'GET', url: 'https://vault.example.test:8200/v1/sys/health' })).status).toBe(200);
    await expect(http.request({ method: 'GET', url: 'https://vault.example.test:8300/v1/sys/health' })).rejects.toBeInstanceOf(EgressBlockedError);
    await expect(http.request({ method: 'GET', url: 'https://vault.example.test/v1/sys/health' })).rejects.toBeInstanceOf(EgressBlockedError);
  });
});

describe('rules derived from self-hosted settings', () => {
  it('derive exact host:port rules for Coolify, Kubernetes, Vault, self-hosted Infisical and the AWS region', async () => {
    const cwd = await project([
      'hosts:',
      '  coolify: { baseUrl: "https://coolify.example.test:8000" }',
      '  kubernetes: { server: "https://k8s.example.test:6443", namespaces: [apps] }',
      '  vault: { address: "https://vault.example.test:8200/v1" }',
      '  infisical: { siteUrl: "https://secrets.example.test/api", projects: [{ projectId: p1, environments: [prod] }] }',
      '  awsSecretsManager: { region: eu-west-1 }',
    ].join('\n'));
    const metadata = await loadConfigMetadata({ cwd, env: {} });
    const derived = metadata.userHostRules.map(rule => ({ host: rule.host, port: rule.port, owner: rule.owner }));
    expect(derived).toEqual(expect.arrayContaining([
      { host: 'coolify.example.test', port: 8000, owner: 'user' },
      { host: 'k8s.example.test', port: 6443, owner: 'user' },
      { host: 'vault.example.test', port: 8200, owner: 'user' },
      { host: 'secrets.example.test', port: undefined, owner: 'user' },
      { host: 'secretsmanager.eu-west-1.amazonaws.com', port: undefined, owner: 'aws-secrets-manager' },
    ]));
  });

  it('adds nothing for a disabled host or for the built-in cloud endpoints', async () => {
    const cwd = await project([
      'hosts:',
      '  coolify: { enabled: false, baseUrl: "https://coolify.example.test:8000" }',
      '  infisical: { siteUrl: "https://eu.infisical.com", projects: [{ projectId: p1, environments: [prod] }] }',
    ].join('\n'));
    const metadata = await loadConfigMetadata({ cwd, env: {} });
    expect(metadata.userHostRules).toEqual([]);
  });

  it('COOLIFY_URL from the environment derives the same rule', async () => {
    const cwd = await project('hosts: {}\n');
    const metadata = await loadConfigMetadata({ cwd, env: { COOLIFY_URL: 'https://coolify.example.test:8443' } });
    expect(metadata.userHostRules).toEqual([{ host: 'coolify.example.test', owner: 'user', purpose: 'Coolify instance you configured', port: 8443, source: 'config' }]);
  });

  it.each([
    ['kubernetes', 'server', 'https://10.0.0.5:6443'],
    ['vault', 'address', 'https://127.0.0.1:8200'],
    ['vault', 'address', 'http://vault.example.test:8200'],
    ['vault', 'address', 'https://vault.example.test:8200/other'],
    ['infisical', 'siteUrl', 'https://user:pw@secrets.example.test'],
    ['coolify', 'baseUrl', 'https://192.168.1.10:8000'],
  ])('refuses %s.%s %s (a self-hosted server needs an https DNS name)', async (host, field, url) => {
    const cwd = await project(`hosts:\n  ${host}: { ${field}: "${url}" }\n`);
    await expect(loadConfigMetadata({ cwd, env: {} })).rejects.toThrow(/Invalid configuration: check hosts\./);
  });
});
