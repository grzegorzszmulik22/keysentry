import type { DeployState, HostAdapter, HttpClient, HttpRequest, Logger, RawVariable, ServiceRef } from '../types.js';
import { requestJson } from './http.js';

export interface SupabaseFunctionsHostOptions {
  /** Management API token (scoped or classic personal access token, or OAuth token), sent as `Authorization: Bearer`. */
  token: string;
  /** Limit the scan to these project refs; default every project the token can see. */
  projectRefs?: string[];
  http: HttpClient;
  log: Logger;
}

const API = 'https://api.supabase.com/v1';
/** Documented project ref schema: `^[a-z]+$`, length 20. */
const PROJECT_REF = /^[a-z]{20}$/;
/** Documented CreateSecretBody limits. */
const MAX_SECRETS_PER_REQUEST = 100;
const MAX_NAME_LENGTH = 256;
const MAX_VALUE_LENGTH = 24_576;
/** Names Supabase reserves for the variables it injects; the Management API rejects them. */
const RESERVED_PREFIX = 'SUPABASE_';

function invalidResponse(): never {
  throw new Error('Supabase returned an invalid response');
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return invalidResponse();
  return value as Record<string, unknown>;
}

function list(value: unknown): unknown[] {
  if (!Array.isArray(value)) return invalidResponse();
  return value;
}

function nonempty(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) return invalidResponse();
  return value;
}

export function createSupabaseFunctionsHost(opts: SupabaseFunctionsHostOptions): HostAdapter {
  const { http, log } = opts;
  const projectRefs = opts.projectRefs === undefined ? undefined : [...new Set(opts.projectRefs)];
  if (projectRefs?.some((ref) => !PROJECT_REF.test(ref))) throw new Error('Supabase project ref is invalid');

  async function request(method: HttpRequest['method'], path: string, body?: unknown): Promise<unknown> {
    const headers: Record<string, string> = { Authorization: `Bearer ${opts.token}` };
    const req: HttpRequest = { method, url: `${API}${path}`, headers };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      req.body = JSON.stringify(body);
    }
    return requestJson<unknown>(http, 'Supabase', req);
  }

  function serviceFor(project: unknown): ServiceRef {
    const item = record(project);
    const ref = nonempty(item.ref);
    if (!PROJECT_REF.test(ref)) return invalidResponse();
    const name = nonempty(item.name);
    // Edge Function secrets are project-wide: one service per project covers every function.
    return {
      host: 'supabase-functions', projectId: ref, projectName: name, serviceId: ref, serviceName: name,
      environmentId: '', environmentName: '',
    };
  }

  function refOf(service: ServiceRef): string {
    if (service.host !== 'supabase-functions' || service.serviceId !== service.projectId || !PROJECT_REF.test(service.serviceId)) {
      throw new Error('Supabase service reference is invalid');
    }
    return service.serviceId;
  }

  return {
    id: 'supabase-functions',
    // Values are write-only (sealed). One POST upserts many secrets. No deploy step: functions read new secrets
    // on their next invocation ("Your functions read a new secret immediately, so you don't need to redeploy").
    // Functions read a new secret on their next invocation; nothing is deployed.
    capabilities: { readValues: false, batchWrite: true, redeploy: false, activation: 'immediate' },

    async listServices() {
      if (projectRefs !== undefined) {
        const services: ServiceRef[] = [];
        for (const ref of projectRefs) services.push(serviceFor(await request('GET', `/projects/${ref}`)));
        return services;
      }
      // Documented as a plain array without pagination parameters.
      return list(await request('GET', '/projects')).map(serviceFor);
    },

    async readVariables(service): Promise<RawVariable[]> {
      const ref = refOf(service);
      const names = new Set<string>();
      for (const item of list(await request('GET', `/projects/${ref}/secrets`))) {
        // The response carries a `value` field; it is never read (write-only by contract, possibly a digest).
        const name = nonempty(record(item).name);
        // Supabase-injected defaults (SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, ...) are platform-managed and
        // cannot be written through this API; they follow the project's own key rotation.
        if (name.startsWith(RESERVED_PREFIX)) continue;
        names.add(name);
      }
      return [...names].map((name) => ({ name, sealed: true }));
    },

    async writeVariables(service, vars, _writeOptions) {
      const ref = refOf(service);
      const secrets = Object.entries(vars).map(([name, value]) => ({ name, value }));
      if (secrets.length === 0) return;
      // Validate the whole batch against the documented schema before the first request.
      if (secrets.some(({ name }) => name.length === 0 || name.length > MAX_NAME_LENGTH || name.startsWith(RESERVED_PREFIX))) {
        throw new Error('Supabase secret name is invalid or reserved');
      }
      if (secrets.some(({ value }) => value.length > MAX_VALUE_LENGTH)) throw new Error('Supabase secret value is too long');
      // POST /v1/projects/{ref}/secrets adds or replaces only the named secrets; it never deletes others.
      // Writes never deploy anything, regardless of skipDeploy.
      for (let start = 0; start < secrets.length; start += MAX_SECRETS_PER_REQUEST) {
        await request('POST', `/projects/${ref}/secrets`, secrets.slice(start, start + MAX_SECRETS_PER_REQUEST));
      }
    },

    async redeploy(service) {
      refOf(service);
      log.info('Supabase Edge Functions read new secrets on their next invocation; no deployment is needed');
      return null;
    },

    async deploymentStatus(service, _deploymentId): Promise<DeployState> {
      refOf(service);
      throw new Error('Supabase Edge Function secrets have no deployment to track');
    },
  };
}
