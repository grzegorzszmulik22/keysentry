import { createCipheriv, createDecipheriv, createPublicKey, randomBytes, sign, verify, type JsonWebKey, type X509Certificate } from 'node:crypto';
import { createServer, request as nodeRequest, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AttestationClaims, HttpClient, HttpRequest, HttpResponse } from '../../../../src/types.js';
import { parseJwt } from '../../../../src/box/attestation/jwt.js';
import { crc32c } from '../../../../src/box/seal/kms.js';
import { createEmulatorPki } from './pki.js';

/** Test-only deviations from a production Confidential Space token. */
export interface EmulatorSwitches {
  debugImage?: boolean;
  otherProject?: boolean;
  otherServiceAccount?: boolean;
  missingStable?: boolean;
  wrongDigest?: boolean;
  staleIat?: boolean;
  replay?: boolean;
}
export interface EmulatorReleasePolicy {
  projectId: string;
  projectNumber: string;
  serviceAccount: string;
  allowedDigests: string[];
  audience: string;
  keyName: string;
}
export interface EmulatorBoxConfig {
  projectId: string;
  zone: string;
  instanceName: string;
  instance: Record<string, unknown>;
}
export interface EmulatorOptions {
  policy?: Partial<EmulatorReleasePolicy>;
  now?: () => number;
  startBox?: (config: EmulatorBoxConfig) => unknown | Promise<unknown>;
}
export interface EmulatorTokenInput {
  audience: string;
  nonces: string[];
  tokenType?: 'OIDC' | 'PKI';
  switches?: EmulatorSwitches;
}
export interface Emulator {
  baseUrl: string;
  computeOrigin: string;
  endpoints: { attestation: string; jwks: string; sts: string; kms: string; compute: string };
  http: HttpClient;
  readonly policy: EmulatorReleasePolicy;
  readonly audience: string;
  readonly keyName: string;
  readonly jwks: JsonWebKey[];
  root: X509Certificate;
  mintToken(input: EmulatorTokenInput): string;
  setSwitches(switches: EmulatorSwitches): void;
  updateReleasePolicy(policy: Partial<EmulatorReleasePolicy>): void;
  close(): Promise<void>;
}

const ISSUER = 'https://confidentialcomputing.googleapis.com';
const MAX_BODY = 512 * 1024;
type Body = Record<string, unknown>;
class RequestError extends Error {
  constructor(readonly status: number) { super('Emulator request was refused.'); }
}
function object(value: unknown): Body {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new RequestError(400);
  return value as Body;
}
function allowedFields(body: Body, names: string[], required = names): void {
  if (Object.keys(body).some(name => !names.includes(name)) || required.some(name => !(name in body))) throw new RequestError(400);
}
function base64(value: unknown, limit: number): Buffer {
  if (typeof value !== 'string' || value.length > Math.ceil(limit * 4 / 3) + 4) throw new RequestError(400);
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length > limit || bytes.toString('base64') !== value) throw new RequestError(400);
  return bytes;
}
function validPolicy(policy: EmulatorReleasePolicy): void {
  if (!/^[a-z][a-z0-9-]{1,62}$/.test(policy.projectId) || !/^\d+$/.test(policy.projectNumber)
    || !/^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.iam\.gserviceaccount\.com$/.test(policy.serviceAccount)
    || !Array.isArray(policy.allowedDigests) || policy.allowedDigests.length === 0
    || policy.allowedDigests.some(digest => !/^sha256:[a-f0-9]{64}$/.test(digest))
    || !/^\/\/iam\.googleapis\.com\/projects\/\d+\/locations\/global\/workloadIdentityPools\/[A-Za-z0-9_-]+\/providers\/[A-Za-z0-9_-]+$/.test(policy.audience)
    || !/^projects\/[A-Za-z0-9_-]+\/locations\/[A-Za-z0-9_-]+\/keyRings\/[A-Za-z0-9_-]+\/cryptoKeys\/[A-Za-z0-9_-]+$/.test(policy.keyName)) throw new TypeError('Invalid emulator release policy.');
}
function send(res: ServerResponse, status: number, data: unknown, raw = false): void {
  res.writeHead(status, { 'content-type': raw ? 'text/html' : 'application/json', 'cache-control': 'no-store',
    'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer' });
  res.end(raw ? data : JSON.stringify(data));
}
async function readBody(req: IncomingMessage): Promise<Body> {
  if ((req.headers['content-type'] ?? '').split(';')[0]?.trim().toLowerCase() !== 'application/json'
    || (req.headers['content-encoding'] && req.headers['content-encoding'] !== 'identity')) throw new RequestError(415);
  const length = req.headers['content-length'];
  if (length && (!/^\d+$/.test(length) || Number(length) > MAX_BODY)) { req.resume(); throw new RequestError(413); }
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY) throw new RequestError(413);
    chunks.push(chunk);
  }
  try { return object(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)))); }
  catch { throw new RequestError(400); }
}

/** Local REST emulator. It never calls Google, launches processes or persists plaintext. */
export async function startEmulator(options: EmulatorOptions = {}): Promise<Emulator> {
  const now = options.now ?? Date.now;
  let release: EmulatorReleasePolicy = {
    projectId: 'keysentry-box', projectNumber: '123456789', serviceAccount: 'keysentry-box@keysentry-box.iam.gserviceaccount.com',
    allowedDigests: [`sha256:${'a'.repeat(64)}`],
    audience: '//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/box-pool/providers/box-provider',
    keyName: 'projects/keysentry-box/locations/global/keyRings/box/cryptoKeys/seal', ...structuredClone(options.policy ?? {}),
  };
  validPolicy(release);
  const identity = structuredClone(release);
  const pki = createEmulatorPki(new Date(now()));
  const signingPublicKey = createPublicKey(pki.privateKey);
  let switches: EmulatorSwitches = {};
  let previousToken: string | undefined;
  const issued = new Map<string, { claims: AttestationClaims; expiresAt: number }>();
  const kmsKeys = new Map<string, Buffer>([[release.keyName, randomBytes(32)]]);
  const instances = new Set<string>();
  let closed = false;

  function mintToken(input: EmulatorTokenInput): string {
    if (typeof input.audience !== 'string' || !input.audience || Buffer.byteLength(input.audience) > 512
      || !Array.isArray(input.nonces) || input.nonces.length > 6
      || input.nonces.some(nonce => typeof nonce !== 'string' || Buffer.byteLength(nonce) < 10 || Buffer.byteLength(nonce) > 74)
      || (input.tokenType !== undefined && input.tokenType !== 'OIDC' && input.tokenType !== 'PKI')) throw new RequestError(400);
    const controls = { ...switches, ...input.switches };
    if (controls.replay && previousToken) return previousToken;
    const seconds = Math.floor(now() / 1000) - (controls.staleIat ? 7200 : 0);
    const projectId = controls.otherProject ? 'other-project' : identity.projectId;
    const digest = controls.wrongDigest ? `sha256:${'b'.repeat(64)}` : identity.allowedDigests[0]!;
    const claims = {
      iss: ISSUER, aud: input.audience, exp: seconds + 3600, iat: seconds, nbf: seconds,
      sub: `https://www.googleapis.com/compute/v1/projects/${projectId}/zones/us-central1-a/instances/emulated-box`,
      jti: randomBytes(16).toString('base64url'), eat_profile: 'https://cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims',
      ...(input.nonces.length ? { eat_nonce: input.nonces.length === 1 ? input.nonces[0] : [...input.nonces] } : {}),
      secboot: true, dbgstat: controls.debugImage ? 'enabled' : 'disabled-since-boot', hwmodel: 'GCP_INTEL_TDX',
      swname: 'CONFIDENTIAL_SPACE', swversion: ['261000'], oemid: 11129, attester_tcb: ['INTEL'],
      google_service_accounts: [controls.otherServiceAccount ? 'box@other-project.iam.gserviceaccount.com' : identity.serviceAccount],
      submods: {
        confidential_space: { support_attributes: controls.debugImage ? [] : controls.missingStable ? ['LATEST'] : ['STABLE', 'LATEST'], monitoring_enabled: { memory: false } },
        container: { image_digest: digest, image_reference: `registry.invalid/keysentry/box@${digest}`, image_id: digest,
          restart_policy: 'Always', env: {}, env_override: {}, cmd_override: [], args: [] },
        gce: { project_id: projectId, project_number: identity.projectNumber, zone: 'us-central1-a', instance_id: '987654321', instance_name: 'emulated-box' },
      },
    };
    const head = { alg: 'RS256', typ: 'JWT', kid: pki.kid, ...(input.tokenType === 'PKI' ? { x5c: pki.chain } : {}) };
    const signingInput = `${Buffer.from(JSON.stringify(head)).toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}`;
    const token = `${signingInput}.${sign('RSA-SHA256', Buffer.from(signingInput), pki.privateKey).toString('base64url')}`;
    previousToken = token;
    return token;
  }
  function permitted(claims: AttestationClaims): boolean {
    const at = Math.floor(now() / 1000);
    return claims.iss === ISSUER && (Array.isArray(claims.aud) ? claims.aud.includes('https://sts.googleapis.com') : claims.aud === 'https://sts.googleapis.com')
      && Number.isSafeInteger(claims.iat) && claims.iat <= at + 60
      && Number.isSafeInteger(claims.exp) && claims.exp > at
      && (claims.nbf === undefined || (Number.isSafeInteger(claims.nbf) && claims.nbf <= at + 60))
      && claims.swname === 'CONFIDENTIAL_SPACE' && claims.dbgstat === 'disabled-since-boot'
      && claims.submods?.confidential_space?.support_attributes?.includes('STABLE') === true
      && claims.submods?.gce?.project_id === release.projectId
      && claims.google_service_accounts?.includes(release.serviceAccount) === true
      && release.allowedDigests.includes(claims.submods?.container?.image_digest ?? '');
  }
  function subjectClaims(token: unknown): AttestationClaims {
    if (typeof token !== 'string') throw new RequestError(403);
    try {
      const parsed = parseJwt(token);
      if (parsed.header.alg !== 'RS256' || parsed.header.typ !== 'JWT' || parsed.header.kid !== pki.kid || parsed.header.x5c !== undefined
        || !verify('RSA-SHA256', parsed.signingInput, signingPublicKey, parsed.signature)) throw new Error();
      const claims = parsed.claims as unknown as AttestationClaims;
      if (!permitted(claims)) throw new Error();
      return claims;
    } catch { throw new RequestError(403); }
  }
  function kms(body: Body, req: IncomingMessage, name: string, operation: string): Body {
    const authorization = req.headers.authorization;
    const credential = authorization?.startsWith('Bearer ') ? issued.get(authorization.slice(7)) : undefined;
    if (!credential || now() >= credential.expiresAt || !permitted(credential.claims)) throw new RequestError(403);
    const key = kmsKeys.get(name);
    if (!key || name !== release.keyName) throw new RequestError(403);
    const field = operation === 'encrypt' ? 'plaintext' : 'ciphertext';
    allowedFields(body, [field, `${field}Crc32c`, 'additionalAuthenticatedData', 'additionalAuthenticatedDataCrc32c']);
    const data = base64(body[field], operation === 'encrypt' ? 65536 : 65564);
    const aad = base64(body.additionalAuthenticatedData, 65536);
    try {
      if (String(body[`${field}Crc32c`]) !== String(crc32c(data)) || String(body.additionalAuthenticatedDataCrc32c) !== String(crc32c(aad))) throw new RequestError(400);
      if (operation === 'encrypt') {
        const nonce = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, nonce);
        cipher.setAAD(aad);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        const wrapped = Buffer.concat([nonce, cipher.getAuthTag(), encrypted]);
        return { name: `${name}/cryptoKeyVersions/1`, ciphertext: wrapped.toString('base64'), ciphertextCrc32c: String(crc32c(wrapped)),
          verifiedPlaintextCrc32c: true, verifiedAdditionalAuthenticatedDataCrc32c: true, protectionLevel: 'SOFTWARE' };
      }
      if (data.length < 28) throw new RequestError(400);
      const decipher = createDecipheriv('aes-256-gcm', key, data.subarray(0, 12));
      decipher.setAAD(aad); decipher.setAuthTag(data.subarray(12, 28));
      const chunks = [decipher.update(data.subarray(28))];
      try {
        chunks.push(decipher.final());
        const plaintext = Buffer.concat(chunks);
        try { return { plaintext: plaintext.toString('base64'), plaintextCrc32c: String(crc32c(plaintext)), protectionLevel: 'SOFTWARE' }; }
        finally { plaintext.fill(0); }
      } finally { chunks.forEach(chunk => chunk.fill(0)); }
    } finally { data.fill(0); aad.fill(0); }
  }
  const server = createServer(async (req, res) => {
    try {
      const path = req.url;
      if (req.method === 'GET' && path === '/health') { send(res, 200, { status: 'ok', emulator: true }); return; }
      if (req.method === 'GET' && path === '/jwks') { send(res, 200, { keys: pki.jwks }); return; }
      if (req.method === 'GET' && path === '/.well-known/confidential_space_root.crt') { send(res, 200, pki.root.toString(), true); return; }
      if (path === '/v1/token' && req.method === 'GET') { send(res, 200, mintToken({ audience: 'https://sts.googleapis.com', nonces: [] }), true); return; }
      if (req.method !== 'POST') throw new RequestError(404);
      const body = await readBody(req);
      if (path === '/v1/token') {
        allowedFields(body, ['audience', 'nonces', 'token_type', 'aws_principal_tag_options'], ['audience', 'token_type']);
        if (body.token_type !== 'OIDC' && body.token_type !== 'PKI') throw new RequestError(400);
        send(res, 200, mintToken({ audience: body.audience as string, nonces: (body.nonces ?? []) as string[], tokenType: body.token_type }), true); return;
      }
      if (path === '/v1/sts/token') {
        allowedFields(body, ['audience', 'grantType', 'requestedTokenType', 'scope', 'subjectToken', 'subjectTokenType']);
        if (req.headers.authorization || body.audience !== release.audience
          || body.grantType !== 'urn:ietf:params:oauth:grant-type:token-exchange'
          || body.requestedTokenType !== 'urn:ietf:params:oauth:token-type:access_token'
          || body.scope !== 'https://www.googleapis.com/auth/cloud-platform'
          || body.subjectTokenType !== 'urn:ietf:params:oauth:token-type:jwt') throw new RequestError(403);
        const claims = subjectClaims(body.subjectToken);
        for (const [token, record] of issued) if (now() >= record.expiresAt) issued.delete(token);
        const accessToken = randomBytes(32).toString('base64url');
        issued.set(accessToken, { claims, expiresAt: Math.min(now() + 3_600_000, claims.exp * 1000) });
        send(res, 200, { access_token: accessToken, token_type: 'Bearer', expires_in: Math.max(1, Math.min(3600, claims.exp - Math.floor(now() / 1000))) }); return;
      }
      const kmsRoute = /^\/v1\/(projects\/[A-Za-z0-9_-]+\/locations\/[A-Za-z0-9_-]+\/keyRings\/[A-Za-z0-9_-]+\/cryptoKeys\/[A-Za-z0-9_-]+):(encrypt|decrypt)$/.exec(path ?? '');
      if (kmsRoute) { send(res, 200, kms(body, req, kmsRoute[1]!, kmsRoute[2]!)); return; }
      const compute = /^\/compute\/v1\/projects\/([A-Za-z0-9_-]+)\/zones\/([A-Za-z0-9_-]+)\/instances$/.exec(path ?? '');
      if (compute) {
        if (compute[1] !== identity.projectId || typeof body.name !== 'string' || !/^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(body.name)) throw new RequestError(400);
        if (body.metadata !== undefined) {
          const metadata = object(body.metadata);
          if (!Array.isArray(metadata.items)) throw new RequestError(400);
          for (const item of metadata.items) {
            const entry = object(item);
            if (entry.key !== 'tee-image-reference' && entry.key !== 'tee-restart-policy') throw new RequestError(400);
            if (typeof entry.value !== 'string' || (entry.key === 'tee-image-reference' && !/@sha256:[a-f0-9]{64}$/.test(entry.value))
              || (entry.key === 'tee-restart-policy' && entry.value !== 'Always')) throw new RequestError(400);
          }
        }
        const instanceKey = `${compute[1]}/${compute[2]}/${body.name}`;
        if (instances.has(instanceKey)) throw new RequestError(409);
        instances.add(instanceKey);
        try {
          await options.startBox?.({ projectId: compute[1]!, zone: compute[2]!, instanceName: body.name, instance: structuredClone(body) });
        } catch { instances.delete(instanceKey); throw new RequestError(400); }
        send(res, 200, { name: `operation-${randomBytes(8).toString('hex')}`, status: 'DONE', targetLink: `projects/${instanceKey}`, operationType: 'insert' }); return;
      }
      throw new RequestError(404);
    } catch (error) { if (!res.headersSent) send(res, error instanceof RequestError ? error.status : 400, { error: 'request_refused' }); else res.end(); }
  });
  server.requestTimeout = 10_000; server.headersTimeout = 10_000; server.maxHeadersCount = 32;
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); }); });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Could not start emulator.');
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const http: HttpClient = {
    request(input: HttpRequest): Promise<HttpResponse> {
      if (closed) return Promise.reject(new Error('Emulator is closed.'));
      let target: URL;
      try {
        target = new URL(input.url);
        if (target.username || target.password || target.search || target.hash) throw new Error();
        if (target.origin !== baseUrl) {
          if (target.origin === 'https://sts.googleapis.com' && target.pathname === '/v1/token') target = new URL('/v1/sts/token', baseUrl);
          else if (target.origin === 'https://cloudkms.googleapis.com' && target.pathname.startsWith('/v1/projects/')) target = new URL(target.pathname, baseUrl);
          else if (target.origin === 'https://compute.googleapis.com' && target.pathname.startsWith('/compute/v1/projects/')) target = new URL(target.pathname, baseUrl);
          else throw new Error();
        }
      } catch { return Promise.reject(new Error('Emulator destination is not supported.')); }
      return new Promise((resolve, reject) => {
        const request = nodeRequest(target, { method: input.method, headers: input.headers, timeout: 10_000 }, response => {
          const chunks: Buffer[] = []; let length = 0;
          response.on('data', (chunk: Buffer) => { length += chunk.length; if (length > 1024 * 1024) response.destroy(new Error('Emulator response is too large.')); else chunks.push(chunk); });
          response.on('error', () => reject(new Error('Emulator request failed.')));
          response.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            const headers: Record<string, string> = {};
            for (const [name, value] of Object.entries(response.headers)) if (value !== undefined) headers[name] = Array.isArray(value) ? value.join(', ') : value;
            resolve({ status: response.statusCode ?? 500, headers, text, json<T>(): T { return JSON.parse(text) as T; } });
          });
        });
        request.on('timeout', () => request.destroy());
        request.on('error', () => reject(new Error('Emulator request failed.')));
        request.end(input.body);
      });
    },
  };
  return {
    baseUrl, computeOrigin: baseUrl,
    endpoints: { attestation: `${baseUrl}/v1/token`, jwks: `${baseUrl}/jwks`, sts: `${baseUrl}/v1/sts/token`, kms: `${baseUrl}/v1`, compute: `${baseUrl}/compute/v1` },
    http, root: pki.root, get jwks() { return structuredClone(pki.jwks); },
    get policy() { return structuredClone(release); }, get audience() { return release.audience; }, get keyName() { return release.keyName; },
    mintToken, setSwitches(value) { switches = { ...value }; },
    updateReleasePolicy(value) { const next = { ...release, ...structuredClone(value) }; validPolicy(next); release = next; },
    async close() {
      if (closed) return; closed = true;
      issued.clear(); kmsKeys.forEach(key => key.fill(0)); kmsKeys.clear();
      await new Promise<void>((resolve, reject) => { server.close(error => error ? reject(error) : resolve()); server.closeAllConnections(); });
    },
  };
}
