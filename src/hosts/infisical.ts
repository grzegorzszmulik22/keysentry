import type { HostAdapter, HttpClient, HttpRequest, HttpResponse, Logger, RawVariable, ServiceRef } from '../types.js';

/**
 * Infisical as a keysentry host (notes/secret-stores.md).
 *
 * One project + environment + folder path is one ServiceRef; each shared secret in that folder is a variable.
 * Personal overrides and imported secrets are excluded (imports are scanned where they are defined). References are
 * read unexpanded. Values the identity may not read (`secretValueHidden`) are reported as write-only.
 *
 * Uses the v4 secrets endpoints; the v3 raw endpoints are marked deprecated in Infisical's API reference. Writes
 * update existing keys with the bulk update (mode failOnNotFound) and create missing keys with the bulk create.
 * Infisical documents no version precondition, so a concurrent change between keysentry's read and write cannot be
 * detected. Secrets managed by Infisical secret rotation are never written.
 */
export type InfisicalAuth =
  | { accessToken: string }
  | { clientId: string; clientSecret: string; organizationSlug?: string };

export interface InfisicalHostOptions {
  /** Default https://app.infisical.com (US). EU: https://eu.infisical.com. Self-hosted: your https origin. */
  siteUrl?: string;
  auth: InfisicalAuth;
  projects: { projectId: string; environments: string[]; secretPath?: string }[];
  http: HttpClient;
  log: Logger;
  now?: () => Date;
}

const DEFAULT_SITE = 'https://app.infisical.com';
const IDENTIFIER = /^[A-Za-z0-9_-]{1,128}$/;

function invalidResponse(): never {
  throw new Error('Infisical returned an invalid response');
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalidResponse();
  return value as Record<string, unknown>;
}

function nonempty(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) invalidResponse();
  return value;
}

export function infisicalApiBase(siteUrl: string): string {
  let url: URL;
  try { url = new URL(siteUrl); } catch { throw new Error('Infisical site URL is invalid'); }
  const path = url.pathname.replace(/\/+$/, '');
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || /[?#]/.test(siteUrl)
    || (path !== '' && path !== '/api')) {
    throw new Error('Infisical site URL must be an https origin without credentials, path or query');
  }
  return `${url.origin}/api`;
}

function folderPath(value: string | undefined): string {
  const parts = (value ?? '/').split('/').filter((part) => part !== '');
  if (parts.some((part) => part === '.' || part === '..')) throw new Error('Infisical secret path is invalid');
  return `/${parts.join('/')}`;
}

interface ListedSecret { key: string; path: string; value?: string; hidden: boolean; rotated: boolean }

export function createInfisicalHost(opts: InfisicalHostOptions): HostAdapter {
  const base = infisicalApiBase(opts.siteUrl ?? DEFAULT_SITE);
  const now = opts.now ?? (() => new Date());
  const scopes = opts.projects.map((project) => {
    if (!IDENTIFIER.test(project.projectId)) throw new Error('Infisical project id is invalid');
    const environments = [...new Set(project.environments)];
    if (environments.length === 0 || environments.some((slug) => !IDENTIFIER.test(slug))) {
      throw new Error('Infisical environment slugs are invalid');
    }
    return { projectId: project.projectId, environments, secretPath: folderPath(project.secretPath) };
  });
  if (scopes.length === 0) throw new Error('Infisical host needs at least one project');
  const auth = opts.auth;
  if ('accessToken' in auth ? !auth.accessToken : !auth.clientId || !auth.clientSecret) throw new Error('Infisical credentials are missing');
  let session: { token: string; expiresAt: number } | undefined;

  async function send(req: HttpRequest): Promise<HttpResponse> {
    try {
      return await opts.http.request(req);
    } catch {
      throw new Error('Infisical request failed');
    }
  }

  async function accessToken(): Promise<string> {
    if ('accessToken' in auth) return auth.accessToken;
    if (session && now().getTime() < session.expiresAt) return session.token;
    const response = await send({
      method: 'POST', url: `${base}/v1/auth/universal-auth/login`,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        clientId: auth.clientId, clientSecret: auth.clientSecret,
        ...(auth.organizationSlug ? { organizationSlug: auth.organizationSlug } : {}),
      }),
    });
    if (response.status < 200 || response.status >= 300) throw new Error(`Infisical login failed (HTTP ${response.status})`);
    let body: Record<string, unknown>;
    try { body = object(response.json<unknown>()); } catch { throw new Error('Infisical login returned an invalid response'); }
    const token = body.accessToken;
    const expiresIn = body.expiresIn;
    if (typeof token !== 'string' || !token || body.tokenType !== 'Bearer' || typeof expiresIn !== 'number' || !(expiresIn > 0)) {
      throw new Error('Infisical login returned an invalid response');
    }
    // Renew a minute early (or at half-life for very short tokens) so a request never carries an expired token.
    const margin = Math.min(60, expiresIn / 2) * 1000;
    session = { token, expiresAt: now().getTime() + expiresIn * 1000 - margin };
    return token;
  }

  async function request(method: HttpRequest['method'], path: string, query?: Record<string, string>, body?: unknown): Promise<Record<string, unknown>> {
    const headers: Record<string, string> = { Authorization: `Bearer ${await accessToken()}`, Accept: 'application/json' };
    const search = query ? `?${new URLSearchParams(query).toString()}` : '';
    const req: HttpRequest = { method, url: `${base}${path}${search}`, headers };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      req.body = JSON.stringify(body);
    }
    const response = await send(req);
    if (response.status < 200 || response.status >= 300) throw new Error(`Infisical request failed (HTTP ${response.status})`);
    try { return object(response.json<unknown>()); } catch (error) {
      if (error instanceof Error && error.message.startsWith('Infisical')) throw error;
      throw new Error('Infisical returned invalid JSON');
    }
  }

  async function list(projectId: string, environment: string, secretPath: string, recursive: boolean, values: boolean): Promise<ListedSecret[]> {
    const body = await request('GET', '/v4/secrets', {
      projectId, environment, secretPath,
      recursive: String(recursive), viewSecretValue: String(values),
      expandSecretReferences: 'false', includeImports: 'false', includePersonalOverrides: 'false',
    });
    if (!Array.isArray(body.secrets)) invalidResponse();
    const secrets: ListedSecret[] = [];
    for (const value of body.secrets) {
      const item = object(value);
      if (item.type !== 'shared') continue;
      const key = nonempty(item.secretKey);
      const path = item.secretPath === undefined ? secretPath : folderPath(nonempty(item.secretPath));
      const hidden = item.secretValueHidden === true;
      if (values && !hidden && typeof item.secretValue !== 'string') invalidResponse();
      secrets.push({
        key, path, hidden, rotated: item.isRotatedSecret === true,
        ...(values && !hidden ? { value: item.secretValue as string } : {}),
      });
    }
    return secrets;
  }

  function ref(projectId: string, environment: string, path: string): ServiceRef {
    return {
      host: 'infisical', projectId, projectName: projectId, serviceId: path, serviceName: path,
      environmentId: environment, environmentName: environment,
    };
  }

  function applied(body: Record<string, unknown>): void {
    if (body.approval !== undefined && body.approval !== null) {
      throw new Error('Infisical requires approval for changes here; it opened a change request and has not applied the new value');
    }
    if (!Array.isArray(body.secrets)) invalidResponse();
  }

  return {
    id: 'infisical',
    // A secret store does not deploy (activation manual); whether consumers read at use time is the application's choice.
    capabilities: { readValues: true, batchWrite: true, redeploy: false },

    async listServices() {
      const refs: ServiceRef[] = [];
      for (const scope of scopes) {
        for (const environment of scope.environments) {
          const secrets = await list(scope.projectId, environment, scope.secretPath, true, false);
          const paths = [...new Set(secrets.map((secret) => secret.path))].sort();
          refs.push(...paths.map((path) => ref(scope.projectId, environment, path)));
        }
      }
      return refs;
    },

    async readVariables(service): Promise<RawVariable[]> {
      const path = folderPath(service.serviceId);
      const secrets = await list(service.projectId, service.environmentId, path, false, true);
      return secrets.filter((secret) => secret.path === path).map((secret) => (secret.hidden
        ? { name: secret.key, sealed: true }
        : { name: secret.key, value: secret.value!, sealed: false }));
    },

    async writeVariables(service, vars, _writeOptions) {
      const entries = Object.entries(vars);
      if (entries.length === 0) return;
      if (entries.some(([name]) => name === '')) throw new Error('Infisical secret name is empty');
      const path = folderPath(service.serviceId);
      const existing = new Map((await list(service.projectId, service.environmentId, path, false, false))
        .filter((secret) => secret.path === path).map((secret) => [secret.key, secret]));
      if (entries.some(([name]) => existing.get(name)?.rotated)) {
        throw new Error('Infisical secret is managed by Infisical secret rotation; rotate it there');
      }
      const updates = entries.filter(([name]) => existing.has(name));
      const creates = entries.filter(([name]) => !existing.has(name));
      const scope = { projectId: service.projectId, environment: service.environmentId, secretPath: path };
      if (updates.length > 0) {
        applied(await request('PATCH', '/v4/secrets/batch', undefined, {
          ...scope, mode: 'failOnNotFound',
          secrets: updates.map(([secretKey, secretValue]) => ({ secretKey, secretValue })),
        }));
      }
      if (creates.length > 0) {
        applied(await request('POST', '/v4/secrets/batch', undefined, {
          ...scope, secrets: creates.map(([secretKey, secretValue]) => ({ secretKey, secretValue })),
        }));
      }
      // Infisical does not deploy; integrations and syncs the user configured may still push the change elsewhere.
    },

    async redeploy() { return null; },
    async deploymentStatus() { throw new Error('Infisical does not create deployments'); },
  };
}
