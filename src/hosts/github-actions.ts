import sodium from 'libsodium-wrappers';
import type { HostAdapter, HttpClient, Logger, RawVariable, ServiceRef } from '../types.js';
import { requestJson } from './http.js';

export interface GithubActionsHostOptions {
  token: string;
  repos: string[];
  http: HttpClient;
  log: Logger;
}

interface SecretList {
  total_count: number;
  secrets: { name: string }[];
}

interface RepositoryPublicKey {
  key_id: string;
  key: string;
}

function repositoryParts(repo: string): [string, string] {
  const parts = repo.split('/');
  const owner = parts[0];
  const name = parts[1];
  if (parts.length !== 2 || !owner || !/^[A-Za-z0-9-]+$/.test(owner)
    || !name || !/^[A-Za-z0-9_.-]+$/.test(name) || name === '.' || name === '..') {
    throw new Error('GitHub Actions requires repositories in owner/repo format');
  }
  return [owner, name];
}

function repositoryUrl(service: ServiceRef): string {
  const [owner, name] = repositoryParts(service.serviceId);
  return `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`;
}

export function createGithubActionsHost(options: GithubActionsHostOptions): HostAdapter {
  options.repos.forEach(repositoryParts);
  const headers = {
    Authorization: `Bearer ${options.token}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  return {
    id: 'github-actions',
    capabilities: { readValues: false, batchWrite: false, redeploy: false },
    async listServices() {
      return options.repos.map((repo): ServiceRef => {
        const [owner, name] = repositoryParts(repo);
        return {
          host: 'github-actions',
          projectId: owner,
          projectName: owner,
          serviceId: repo,
          serviceName: name,
          environmentId: '',
          environmentName: '',
        };
      });
    },
    async readVariables(service) {
      const variables: RawVariable[] = [];
      let page = 1;
      while (true) {
        const suffix = page === 1 ? '' : `&page=${page}`;
        const result = await requestJson<SecretList>(options.http, 'GitHub Actions', {
          method: 'GET',
          url: `${repositoryUrl(service)}/actions/secrets?per_page=100${suffix}`,
          headers,
        });
        if (!result || !Number.isSafeInteger(result.total_count) || result.total_count < 0
          || !Array.isArray(result.secrets)
          || result.secrets.some((secret) => !secret || typeof secret.name !== 'string' || !secret.name)) {
          throw new Error('GitHub Actions returned an invalid secret list');
        }
        for (const secret of result.secrets) variables.push({ name: secret.name, sealed: true });
        if (result.secrets.length === 0 || variables.length >= result.total_count) break;
        page += 1;
      }
      return variables;
    },
    async writeVariables(service, vars) {
      const entries = Object.entries(vars);
      if (entries.length === 0) return;
      if (entries.some(([name]) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name))) {
        throw new Error('GitHub Actions received an invalid secret name');
      }
      const result = await requestJson<RepositoryPublicKey>(options.http, 'GitHub Actions', {
        method: 'GET',
        url: `${repositoryUrl(service)}/actions/secrets/public-key`,
        headers,
      });
      await sodium.ready;
      let publicKey: Uint8Array;
      try {
        if (!result || typeof result.key_id !== 'string' || !result.key_id || typeof result.key !== 'string') {
          throw new Error();
        }
        publicKey = sodium.from_base64(result.key, sodium.base64_variants.ORIGINAL);
        if (publicKey.length !== sodium.crypto_box_PUBLICKEYBYTES) throw new Error();
      } catch {
        throw new Error('GitHub Actions returned an invalid public key');
      }
      for (const [name, value] of entries) {
        let encryptedValue: string;
        try {
          encryptedValue = sodium.to_base64(sodium.crypto_box_seal(value, publicKey), sodium.base64_variants.ORIGINAL);
        } catch {
          throw new Error('GitHub Actions secret encryption failed');
        }
        await requestJson<void>(options.http, 'GitHub Actions', {
          method: 'PUT',
          url: `${repositoryUrl(service)}/actions/secrets/${encodeURIComponent(name)}`,
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({ encrypted_value: encryptedValue, key_id: result.key_id }),
        });
      }
    },
    async redeploy() { return null; },
    async deploymentStatus() { throw new Error('GitHub Actions does not support deployments'); },
  };
}
