import type { DeployState, HostAdapter, HttpClient, HttpRequest, HttpResponse, Logger, RawVariable, ServiceRef } from '../types.js';

/**
 * Kubernetes Secrets as a keysentry host (notes/secret-stores.md).
 *
 * One Secret (namespace + name) is one ServiceRef; each `data` key is one variable. Values are base64 in the API and
 * are decoded as UTF-8; bytes that are not valid UTF-8 are reported as sealed because a string write would change
 * them. Writes re-read the Secret and send it back with PUT and its unchanged `metadata.resourceVersion`, so labels,
 * annotations, `type`, owner references and every other key are preserved and a concurrent change fails with 409.
 *
 * Writes never restart pods. `redeploy` is opt-in: only Deployments listed in `restartDeployments` for that Secret
 * are restarted, only after checking that their pod template references the Secret, and the only change is the
 * `kubectl.kubernetes.io/restartedAt` pod-template annotation that `kubectl rollout restart` sets.
 */
export interface KubernetesHostOptions {
  /** API server origin (https, a DNS name, optionally a port such as 6443). No credentials, path or query. */
  server: string;
  /** Bearer token (ServiceAccount token or user token). */
  token: string;
  /** Namespaces to scan; at least one. Cluster-wide listing is deliberately not offered. */
  namespaces: string[];
  /** Optional label selector passed to the list call. */
  labelSelector?: string;
  /** Distinguishes several clusters; becomes the ServiceRef environment. Default ''. */
  cluster?: string;
  /** Secret types that are never listed or written. Defaults to DEFAULT_EXCLUDED_SECRET_TYPES. */
  excludeTypes?: string[];
  /** Opt-in rollout restarts: "<namespace>/<secret>" -> Deployment names in the same namespace. */
  restartDeployments?: Record<string, string[]>;
  http: HttpClient;
  log: Logger;
  now?: () => Date;
}

/** Controller-managed or tool-state Secrets: rotating them by editing data would break their owner. */
export const DEFAULT_EXCLUDED_SECRET_TYPES: readonly string[] = [
  'kubernetes.io/service-account-token',
  'bootstrap.kubernetes.io/token',
  'helm.sh/release.v1',
];

const RESTART_ANNOTATION = 'kubectl.kubernetes.io/restartedAt';
const RESTART_ID_PREFIX = 'k8s-restart:v1:';
const DNS_LABEL = /^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$/;
const DNS_SUBDOMAIN = /^(?=.{1,253}$)[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*$/;
const DATA_KEY = /^[-._a-zA-Z0-9]{1,253}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const MAX_PAGES = 1000;

function invalidResponse(): never {
  // Secret objects carry values; never include a response in an error.
  throw new Error('Kubernetes returned an invalid response');
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalidResponse();
  return value as Record<string, unknown>;
}

function optionalObject(value: unknown): Record<string, unknown> {
  return value === undefined || value === null ? {} : object(value);
}

function nonempty(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) invalidResponse();
  return value;
}

function count(value: unknown): number {
  if (value === undefined || value === null) return 0;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) invalidResponse();
  return value;
}

export function kubernetesServerOrigin(server: string): string {
  let url: URL;
  try { url = new URL(server); } catch { throw new Error('Kubernetes server URL is invalid'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash
    || (url.pathname !== '/' && url.pathname !== '') || /[?#]/.test(server)) {
    throw new Error('Kubernetes server URL must be an https origin without credentials, path or query');
  }
  return url.origin;
}

function namespaceName(value: string): string {
  if (!DNS_LABEL.test(value)) throw new Error('Kubernetes namespace name is invalid');
  return value;
}

function objectName(value: string): string {
  if (!DNS_SUBDOMAIN.test(value)) throw new Error('Kubernetes object name is invalid');
  return value;
}

function decode(value: unknown): string | undefined {
  if (typeof value !== 'string' || !BASE64.test(value)) invalidResponse();
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(value, 'base64'));
  } catch {
    return undefined;
  }
}

function references(template: Record<string, unknown>, secretName: string): boolean {
  const spec = optionalObject(template.spec);
  const containers = [spec.containers, spec.initContainers, spec.ephemeralContainers]
    .flatMap((list) => (Array.isArray(list) ? list : []));
  for (const value of containers) {
    const container = optionalObject(value);
    for (const env of Array.isArray(container.env) ? container.env : []) {
      const ref = optionalObject(optionalObject(optionalObject(env).valueFrom).secretKeyRef);
      if (ref.name === secretName) return true;
    }
    for (const source of Array.isArray(container.envFrom) ? container.envFrom : []) {
      if (optionalObject(optionalObject(source).secretRef).name === secretName) return true;
    }
  }
  for (const value of Array.isArray(spec.volumes) ? spec.volumes : []) {
    const volume = optionalObject(value);
    if (optionalObject(volume.secret).secretName === secretName) return true;
    const sources = optionalObject(volume.projected).sources;
    for (const source of Array.isArray(sources) ? sources : []) {
      if (optionalObject(optionalObject(source).secret).name === secretName) return true;
    }
  }
  return false;
}

interface RestartRecord { name: string; generation: number }

function encodeRestartId(records: RestartRecord[]): string {
  return RESTART_ID_PREFIX + Buffer.from(JSON.stringify(records), 'utf8').toString('base64url');
}

function decodeRestartId(id: string): RestartRecord[] {
  const fail = (): never => { throw new Error('Kubernetes deployment id is invalid'); };
  if (!id.startsWith(RESTART_ID_PREFIX)) fail();
  let parsed: unknown;
  try { parsed = JSON.parse(Buffer.from(id.slice(RESTART_ID_PREFIX.length), 'base64url').toString('utf8')); } catch { fail(); }
  if (!Array.isArray(parsed) || parsed.length === 0) fail();
  return (parsed as unknown[]).map((entry) => {
    if (entry === null || typeof entry !== 'object') fail();
    const { name, generation } = entry as Record<string, unknown>;
    if (typeof name !== 'string' || !DNS_SUBDOMAIN.test(name) || typeof generation !== 'number'
      || !Number.isInteger(generation) || generation < 0) fail();
    return { name: name as string, generation: generation as number };
  });
}

export function createKubernetesHost(opts: KubernetesHostOptions): HostAdapter {
  const origin = kubernetesServerOrigin(opts.server);
  if (!opts.token) throw new Error('Kubernetes token is missing');
  const namespaces = [...new Set(opts.namespaces.map(namespaceName))];
  if (namespaces.length === 0) throw new Error('Kubernetes host needs at least one namespace');
  const excluded = new Set(opts.excludeTypes ?? DEFAULT_EXCLUDED_SECRET_TYPES);
  const cluster = opts.cluster ?? '';
  const now = opts.now ?? (() => new Date());
  const restarts = new Map<string, string[]>();
  for (const [key, deployments] of Object.entries(opts.restartDeployments ?? {})) {
    const [namespace, name, extra] = key.split('/');
    if (namespace === undefined || name === undefined || extra !== undefined) throw new Error('Kubernetes restart key must be <namespace>/<secret>');
    namespaceName(namespace);
    objectName(name);
    const names = [...new Set(deployments.map(objectName))];
    if (names.length > 0) restarts.set(key, names);
  }

  async function send(method: HttpRequest['method'], path: string, body?: unknown, contentType = 'application/json'): Promise<HttpResponse> {
    const headers: Record<string, string> = { Authorization: `Bearer ${opts.token}`, Accept: 'application/json' };
    const req: HttpRequest = { method, url: `${origin}${path}`, headers };
    if (body !== undefined) {
      headers['Content-Type'] = contentType;
      req.body = JSON.stringify(body);
    }
    try {
      return await opts.http.request(req);
    } catch {
      throw new Error('Kubernetes request failed');
    }
  }

  function parse(response: HttpResponse): unknown {
    if (response.status < 200 || response.status >= 300) throw new Error(`Kubernetes request failed (HTTP ${response.status})`);
    try { return response.json<unknown>(); } catch { throw new Error('Kubernetes returned invalid JSON'); }
  }

  const secretPath = (namespace: string, name: string) =>
    `/api/v1/namespaces/${encodeURIComponent(namespaceName(namespace))}/secrets/${encodeURIComponent(objectName(name))}`;
  const deploymentPath = (namespace: string, name: string) =>
    `/apis/apps/v1/namespaces/${encodeURIComponent(namespaceName(namespace))}/deployments/${encodeURIComponent(objectName(name))}`;

  function ref(namespace: string, name: string): ServiceRef {
    return {
      host: 'kubernetes', projectId: namespace, projectName: namespace, serviceId: name, serviceName: name,
      environmentId: cluster, environmentName: cluster,
    };
  }

  async function readSecret(service: ServiceRef): Promise<Record<string, unknown>> {
    const secret = object(parse(await send('GET', secretPath(service.projectId, service.serviceId))));
    const metadata = object(secret.metadata);
    if (metadata.name !== service.serviceId || (metadata.namespace !== undefined && metadata.namespace !== service.projectId)) invalidResponse();
    if (secret.type !== undefined && typeof secret.type !== 'string') invalidResponse();
    return secret;
  }

  async function listNamespace(namespace: string): Promise<ServiceRef[]> {
    const refs: ServiceRef[] = [];
    const seen = new Set<string>();
    let token: string | undefined;
    for (let page = 0; page < MAX_PAGES; page += 1) {
      const query = new URLSearchParams({ limit: '100' });
      if (opts.labelSelector) query.set('labelSelector', opts.labelSelector);
      if (token !== undefined) query.set('continue', token);
      const response = await send('GET', `/api/v1/namespaces/${encodeURIComponent(namespace)}/secrets?${query.toString()}`);
      if (response.status === 410) throw new Error('Kubernetes list expired before it finished; scan again');
      const list = object(parse(response));
      if (!Array.isArray(list.items)) invalidResponse();
      for (const value of list.items) {
        const secret = object(value);
        const metadata = object(secret.metadata);
        const name = nonempty(metadata.name);
        const type = secret.type ?? 'Opaque';
        if (typeof type !== 'string') invalidResponse();
        if (excluded.has(type)) continue;
        refs.push(ref(namespace, name));
      }
      const next = optionalObject(list.metadata).continue;
      if (next === undefined || next === null || next === '') return refs;
      if (typeof next !== 'string' || seen.has(next)) throw new Error('Kubernetes pagination did not advance');
      seen.add(next);
      token = next;
    }
    throw new Error('Kubernetes pagination did not advance');
  }

  return {
    id: 'kubernetes',
    capabilities: { readValues: true, batchWrite: true, redeploy: restarts.size > 0 },
    // Only Secrets with configured Deployment restarts can confirm activation.
    activationFor: service => restarts.has(`${service.projectId}/${service.serviceId}`) ? 'redeploy' : 'manual',

    async listServices() {
      const refs: ServiceRef[] = [];
      for (const namespace of namespaces) refs.push(...await listNamespace(namespace));
      return refs;
    },

    async readVariables(service): Promise<RawVariable[]> {
      const secret = await readSecret(service);
      if (excluded.has((secret.type as string | undefined) ?? 'Opaque')) return [];
      const data = optionalObject(secret.data);
      const variables: RawVariable[] = [];
      let binary = 0;
      for (const [name, encoded] of Object.entries(data)) {
        const value = decode(encoded);
        if (value === undefined) {
          binary += 1;
          variables.push({ name, sealed: true });
        } else {
          variables.push({ name, value, sealed: false });
        }
      }
      if (binary > 0) opts.log.debug('Kubernetes Secret has binary values that keysentry reports as write-only', { namespace: service.projectId, secret: service.serviceId, count: binary });
      return variables;
    },

    async writeVariables(service, vars, _writeOptions) {
      const entries = Object.entries(vars);
      if (entries.length === 0) return;
      if (entries.some(([name]) => !DATA_KEY.test(name) || name === '.' || name === '..')) {
        throw new Error('Kubernetes Secret keys may contain only letters, digits, "-", "_" and "."');
      }
      const secret = await readSecret(service);
      if (excluded.has((secret.type as string | undefined) ?? 'Opaque')) throw new Error('Kubernetes Secret type is managed by its owner and is not written by keysentry');
      if (secret.immutable === true) throw new Error('Kubernetes Secret is immutable; create a replacement Secret instead');
      nonempty(object(secret.metadata).resourceVersion);
      const existing = optionalObject(secret.data);
      const data = Object.fromEntries([
        ...Object.entries(existing),
        ...entries.map(([name, value]) => [name, Buffer.from(value, 'utf8').toString('base64')] as const),
      ]);
      // PUT the object as read: only `data` changes, and the unchanged resourceVersion makes the write conditional.
      const response = await send('PUT', secretPath(service.projectId, service.serviceId), { ...secret, data });
      if (response.status === 409) {
        throw new Error('Kubernetes Secret changed while keysentry was writing it; nothing was written. Scan again and retry.');
      }
      parse(response);
      // Pods only see new environment values after a restart; that is redeploy's job, so skipDeploy needs no action.
    },

    async redeploy(service) {
      const deployments = restarts.get(`${service.projectId}/${service.serviceId}`);
      if (!deployments) return null;
      // Validate every Deployment before changing any of them.
      for (const name of deployments) {
        const deployment = object(parse(await send('GET', deploymentPath(service.projectId, name))));
        const spec = object(deployment.spec);
        if (spec.paused === true) throw new Error('Kubernetes Deployment is paused; resume it before keysentry restarts it');
        if (!references(object(spec.template), service.serviceId)) {
          throw new Error('Kubernetes Deployment configured for restart does not reference this Secret');
        }
      }
      const at = now().toISOString().replace(/\.\d{3}Z$/, 'Z');
      const records: RestartRecord[] = [];
      for (const name of deployments) {
        const patched = object(parse(await send('PATCH', deploymentPath(service.projectId, name), {
          spec: { template: { metadata: { annotations: { [RESTART_ANNOTATION]: at } } } },
        }, 'application/merge-patch+json')));
        const generation = count(object(patched.metadata).generation);
        records.push({ name, generation });
      }
      return encodeRestartId(records);
    },

    async deploymentStatus(service, deploymentId): Promise<DeployState> {
      const records = decodeRestartId(deploymentId);
      let pending = false;
      for (const record of records) {
        const deployment = object(parse(await send('GET', deploymentPath(service.projectId, record.name))));
        const metadata = object(deployment.metadata);
        const spec = object(deployment.spec);
        const status = optionalObject(deployment.status);
        const conditions = Array.isArray(status.conditions) ? status.conditions.map(object) : [];
        if (conditions.some((c) => c.type === 'Progressing' && c.status === 'False' && c.reason === 'ProgressDeadlineExceeded')) return 'failed';
        const generation = count(metadata.generation);
        const observed = count(status.observedGeneration);
        const desired = spec.replicas === undefined ? 1 : count(spec.replicas);
        const updated = count(status.updatedReplicas);
        const total = count(status.replicas);
        const available = count(status.availableReplicas);
        const complete = observed >= Math.max(generation, record.generation)
          && updated >= desired && total <= updated && available >= updated;
        if (!complete) pending = true;
      }
      return pending ? 'pending' : 'success';
    },
  };
}
