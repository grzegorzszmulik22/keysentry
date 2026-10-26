import type { HostAdapter, HttpClient, Logger, ServiceRef } from '../types.js';
import { requestJson } from './http.js';

export interface FlyHostOptions {
  token: string;
  org?: string;
  apps?: string[];
  http: HttpClient;
  log: Logger;
}

const GRAPHQL_URL = 'https://api.fly.io/graphql';
const MACHINES_URL = 'https://api.machines.dev/v1/apps';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function appService(name: string): ServiceRef {
  return {
    host: 'fly',
    // Fly GraphQL accepts the app name as appId. Machines app IDs are not
    // assumed to be interchangeable with GraphQL node IDs.
    projectId: name,
    projectName: name,
    serviceId: name,
    serviceName: name,
    environmentId: '',
    environmentName: '',
  };
}

export function createFlyHost(options: FlyHostOptions): HostAdapter {
  const { token, http, log } = options;
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  async function graphql(query: string, variables: Record<string, unknown>): Promise<Record<string, unknown>> {
    const response = await requestJson<unknown>(http, 'Fly', {
      method: 'POST',
      url: GRAPHQL_URL,
      headers,
      body: JSON.stringify({ query, variables }),
    });
    if (!isRecord(response)) throw new Error('Fly returned an invalid GraphQL response');
    if (response.errors !== undefined && (!Array.isArray(response.errors) || response.errors.length > 0)) {
      // Upstream messages can echo request variables, including secret values.
      throw new Error('Fly GraphQL request failed');
    }
    if (!isRecord(response.data)) throw new Error('Fly returned an incomplete GraphQL response');
    return response.data;
  }

  return {
    id: 'fly',
    capabilities: { readValues: false, batchWrite: true, redeploy: true },

    async listServices() {
      if (options.apps !== undefined) {
        if (options.apps.some((name) => !name.trim())) throw new Error('Fly configured apps must have names');
        return [...new Set(options.apps)].map(appService);
      }
      // The Machines listing requires an organization. Avoid silently scanning
      // an arbitrary organization when neither selector was configured.
      if (!options.org?.trim()) throw new Error('Fly requires an organization or configured apps for discovery');
      const url = new URL(MACHINES_URL);
      url.searchParams.set('org_slug', options.org);
      const response = await requestJson<unknown>(http, 'Fly', { method: 'GET', url: url.toString(), headers });
      if (!isRecord(response) || !Array.isArray(response.apps)) throw new Error('Fly returned an invalid app list');
      const names: string[] = [];
      for (const app of response.apps) {
        if (!isRecord(app) || typeof app.name !== 'string' || !app.name.trim()) {
          throw new Error('Fly returned an invalid app list');
        }
        names.push(app.name);
      }
      return [...new Set(names)].map(appService);
    },

    async readVariables(service) {
      const data = await graphql(
        'query($name:String!){ app(name:$name){ secrets { name digest createdAt } } }',
        { name: service.serviceId },
      );
      if (!isRecord(data.app) || !Array.isArray(data.app.secrets)) {
        throw new Error('Fly returned an incomplete secret list');
      }
      return data.app.secrets.map((secret) => {
        if (!isRecord(secret) || typeof secret.name !== 'string' || !secret.name) {
          throw new Error('Fly returned an invalid secret list');
        }
        return { name: secret.name, sealed: true };
      });
    },

    async writeVariables(service, vars, _opts) {
      const secrets = Object.entries(vars).map(([key, value]) => ({ key, value }));
      if (secrets.length === 0) return;
      const data = await graphql(
        'mutation($input:SetSecretsInput!){ setSecrets(input:$input){ app { name } } }',
        { input: { appId: service.serviceId, secrets, replaceAll: false, stage: true } },
      );
      // Staging is required even when skipDeploy is false: redeploy is a separate
      // plan step. This assumes Fly's SetSecretsInput supports stage:true. If a
      // deployment lacks that API field, fail closed; never retry without stage
      // or split writes per key, which could start deployments during a plan.
      if (!isRecord(data.setSecrets) || !isRecord(data.setSecrets.app) || data.setSecrets.app.name !== service.serviceId) {
        throw new Error('Fly did not confirm the staged secret update for the requested app');
      }
    },

    async redeploy(service) {
      log.warn(`Fly secrets are staged; run fly secrets deploy -a ${service.serviceId}`);
      return null;
    },

    async deploymentStatus(_service, _deploymentId) {
      throw new Error('Fly deployment status is unavailable for manual secret deployments');
    },
  };
}
