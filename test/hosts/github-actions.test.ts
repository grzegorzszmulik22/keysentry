import { describe, expect, it } from 'vitest';
import sodium from 'libsodium-wrappers';
import { createGithubActionsHost } from '../../src/hosts/github-actions.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

describe('GitHub Actions host', () => {
  it('lists configured repositories as services without a network request', async () => {
    const http = new FakeHttp();
    const host = createGithubActionsHost({
      token: 'github-test-token',
      repos: ['octocat/hello-world', 'example/api'],
      http,
      log: silentLogger,
    });

    expect(await host.listServices()).toEqual([
      {
        host: 'github-actions',
        projectId: 'octocat',
        projectName: 'octocat',
        serviceId: 'octocat/hello-world',
        serviceName: 'hello-world',
        environmentId: '',
        environmentName: '',
      },
      {
        host: 'github-actions',
        projectId: 'example',
        projectName: 'example',
        serviceId: 'example/api',
        serviceName: 'api',
        environmentId: '',
        environmentName: '',
      },
    ]);
    expect(host.id).toBe('github-actions');
    expect(host.capabilities).toEqual({ readValues: false, batchWrite: false, redeploy: false });
    expect(http.calls).toHaveLength(0);
  });

  it('reads more than 100 secret names as sealed variables with authenticated pagination', async () => {
    const http = new FakeHttp();
    const firstPage = Array.from({ length: 100 }, (_, i) => ({
      name: `SECRET_${i}`,
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
    }));
    http.on('GET', /^https:\/\/api\.github\.com\/repos\/octocat\/hello-world\/actions\/secrets\?per_page=100$/, () =>
      json(200, { total_count: 101, secrets: firstPage }));
    http.on('GET', /^https:\/\/api\.github\.com\/repos\/octocat\/hello-world\/actions\/secrets\?per_page=100&page=2$/, () =>
      json(200, {
        total_count: 101,
        secrets: [{ name: 'LAST_SECRET', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' }],
      }));
    const host = createGithubActionsHost({ token: 'github-test-token', repos: ['octocat/hello-world'], http, log: silentLogger });
    const [service] = await host.listServices();

    const variables = await host.readVariables(service!);

    expect(variables).toHaveLength(101);
    expect(variables[0]).toEqual({ name: 'SECRET_0', sealed: true });
    expect(variables[100]).toEqual({ name: 'LAST_SECRET', sealed: true });
    expect(variables.every((variable) => variable.sealed && variable.value === undefined)).toBe(true);
    expect(http.calls).toEqual([
      {
        method: 'GET',
        url: 'https://api.github.com/repos/octocat/hello-world/actions/secrets?per_page=100',
        headers: {
          Authorization: 'Bearer github-test-token',
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
        },
      },
      {
        method: 'GET',
        url: 'https://api.github.com/repos/octocat/hello-world/actions/secrets?per_page=100&page=2',
        headers: {
          Authorization: 'Bearer github-test-token',
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
        },
      },
    ]);
  });

  it('encrypts each requested value with the repository key before sending an individual upsert', async () => {
    await sodium.ready;
    const pair = sodium.crypto_box_keypair();
    const http = new FakeHttp();
    http.on('GET', /^https:\/\/api\.github\.com\/repos\/octocat\/hello-world\/actions\/secrets\/public-key$/, () =>
      json(200, { key_id: 'repository-key-1', key: sodium.to_base64(pair.publicKey, sodium.base64_variants.ORIGINAL) }));
    http.on('PUT', /^https:\/\/api\.github\.com\/repos\/octocat\/hello-world\/actions\/secrets\/API_TOKEN$/, () =>
      json(201, {}));
    http.on('PUT', /^https:\/\/api\.github\.com\/repos\/octocat\/hello-world\/actions\/secrets\/SECOND_SECRET$/, () =>
      text(204, ''));
    const host = createGithubActionsHost({ token: 'github-test-token', repos: ['octocat/hello-world'], http, log: silentLogger });
    const [service] = await host.listServices();
    const values = { API_TOKEN: 'new-token-value-sensitive', SECOND_SECRET: 'second-value-sensitive-🗝️' };

    await host.writeVariables(service!, values, { skipDeploy: true });

    expect(http.calls.map(({ method, url }) => ({ method, url }))).toEqual([
      { method: 'GET', url: 'https://api.github.com/repos/octocat/hello-world/actions/secrets/public-key' },
      { method: 'PUT', url: 'https://api.github.com/repos/octocat/hello-world/actions/secrets/API_TOKEN' },
      { method: 'PUT', url: 'https://api.github.com/repos/octocat/hello-world/actions/secrets/SECOND_SECRET' },
    ]);
    for (const call of http.calls) {
      expect(call.headers).toMatchObject({
        Authorization: 'Bearer github-test-token',
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      });
      for (const value of Object.values(values)) {
        expect(call.url).not.toContain(value);
        expect(call.body ?? '').not.toContain(value);
      }
    }
    for (const [index, expected] of Object.values(values).entries()) {
      const call = http.calls[index + 1]!;
      expect(call.headers?.['Content-Type']).toBe('application/json');
      const body = JSON.parse(call.body!) as { key_id: string; encrypted_value: string };
      expect(Object.keys(body).sort()).toEqual(['encrypted_value', 'key_id']);
      expect(body.key_id).toBe('repository-key-1');
      const decrypted = sodium.crypto_box_seal_open(
        sodium.from_base64(body.encrypted_value, sodium.base64_variants.ORIGINAL),
        pair.publicKey,
        pair.privateKey,
        'text',
      );
      expect(decrypted).toBe(expected);
    }
  });

  it.each([
    { key_id: 'repository-key-1', key: '!not-base64' },
    { key_id: 'repository-key-1', key: 'AQID' },
    { key_id: '', key: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' },
  ])('rejects an invalid repository public key before writing a secret: %j', async (publicKey) => {
    const http = new FakeHttp().on('GET', /\/actions\/secrets\/public-key$/, () => json(200, publicKey));
    const host = createGithubActionsHost({ token: 'github-test-token', repos: ['octocat/hello-world'], http, log: silentLogger });
    const [service] = await host.listServices();

    await expect(host.writeVariables(service!, { API_TOKEN: 'must-stay-in-memory' }, { skipDeploy: true }))
      .rejects.toThrow('GitHub Actions returned an invalid public key');

    expect(http.calls.map((call) => call.method)).toEqual(['GET']);
  });

  it.each([
    null,
    { total_count: 1, secrets: null },
    { total_count: 1, secrets: [{ name: 42 }] },
    { total_count: -1, secrets: [] },
  ])('fails closed on a malformed secret listing: %j', async (response) => {
    const http = new FakeHttp().on('GET', /\/actions\/secrets\?per_page=100$/, () => json(200, response));
    const host = createGithubActionsHost({ token: 'github-test-token', repos: ['octocat/hello-world'], http, log: silentLogger });
    const [service] = await host.listServices();

    await expect(host.readVariables(service!)).rejects.toThrow('GitHub Actions returned an invalid secret list');
    expect(http.calls).toHaveLength(1);
  });

  it.each(['octocat', 'octocat/', '/repo', './repo', 'octocat/..', 'octocat/repo/extra', 'octocat/repo?query=yes'])
  ('rejects a repository path that is not owner/repo: %s', (repo) => {
    const http = new FakeHttp();

    expect(() => createGithubActionsHost({ token: 'github-test-token', repos: [repo], http, log: silentLogger }))
      .toThrow('GitHub Actions requires repositories in owner/repo format');
    expect(http.calls).toHaveLength(0);
  });

  it('rejects a caller-supplied repository path before making a request', async () => {
    const http = new FakeHttp();
    const host = createGithubActionsHost({ token: 'github-test-token', repos: ['octocat/hello-world'], http, log: silentLogger });
    const [service] = await host.listServices();

    await expect(host.readVariables({ ...service!, serviceId: 'octocat/..' }))
      .rejects.toThrow('GitHub Actions requires repositories in owner/repo format');
    expect(http.calls).toHaveLength(0);
  });

  it.each(['', '.', '..', 'invalid/name', '%2e%2e'])('rejects an invalid secret name before requesting a public key: %s', async (name) => {
    const http = new FakeHttp();
    const host = createGithubActionsHost({ token: 'github-test-token', repos: ['octocat/hello-world'], http, log: silentLogger });
    const [service] = await host.listServices();

    await expect(host.writeVariables(service!, { VALID_NAME: 'first-value-sensitive', [name]: 'second-value-sensitive' }, { skipDeploy: true }))
      .rejects.toThrow('GitHub Actions received an invalid secret name');
    expect(http.calls).toHaveLength(0);
  });

  it('makes no requests for an empty write or redeploy and rejects deployment polling', async () => {
    const http = new FakeHttp();
    const host = createGithubActionsHost({ token: 'github-test-token', repos: ['octocat/hello-world'], http, log: silentLogger });
    const [service] = await host.listServices();

    await host.writeVariables(service!, {}, { skipDeploy: false });
    expect(await host.redeploy(service!)).toBeNull();
    await expect(host.deploymentStatus(service!, 'not-a-deployment'))
      .rejects.toThrow('GitHub Actions does not support deployments');
    expect(http.calls).toHaveLength(0);
  });

  it('stops after a rejected upsert and does not expose echoed secrets in the error', async () => {
    await sodium.ready;
    const pair = sodium.crypto_box_keypair();
    const http = new FakeHttp();
    const values = { FIRST_SECRET: 'first-sensitive-new-value', SECOND_SECRET: 'second-sensitive-new-value' };
    http.on('GET', /\/actions\/secrets\/public-key$/, () => json(200, {
      key_id: 'repository-key-1',
      key: sodium.to_base64(pair.publicKey, sodium.base64_variants.ORIGINAL),
    }));
    http.on('PUT', /\/actions\/secrets\/FIRST_SECRET$/, () =>
      json(403, { message: `Rejected github-test-token ${values.FIRST_SECRET}` }));
    const host = createGithubActionsHost({ token: 'github-test-token', repos: ['octocat/hello-world'], http, log: silentLogger });
    const [service] = await host.listServices();

    const operation = host.writeVariables(service!, values, { skipDeploy: false });

    await expect(operation).rejects.toThrow('HTTP 403');
    await expect(operation).rejects.not.toThrow('github-test-token');
    await expect(operation).rejects.not.toThrow(values.FIRST_SECRET);
    expect(http.calls.map((call) => call.method)).toEqual(['GET', 'PUT']);
    expect(http.calls[1]!.url).toBe('https://api.github.com/repos/octocat/hello-world/actions/secrets/FIRST_SECRET');
  });

  it('does not expose transport diagnostics that include credentials', async () => {
    const http = new FakeHttp().on('GET', /\/actions\/secrets\?per_page=100$/, () => {
      throw new Error('request failed Authorization: Bearer github-test-token');
    });
    const host = createGithubActionsHost({ token: 'github-test-token', repos: ['octocat/hello-world'], http, log: silentLogger });
    const [service] = await host.listServices();

    await expect(host.readVariables(service!)).rejects.toThrow(/^GitHub Actions request failed$/);
  });
});
