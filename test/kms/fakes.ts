// Behavioural fakes of the four KMS APIs on top of FakeHttp. Each one really encrypts with AES-256-GCM (or RSA-OAEP
// for Key Vault) and binds the context the way the real service does, so wrong contexts and tampering fail for real.
import {
  createCipheriv, createDecipheriv, createHash, createPublicKey, generateKeyPairSync, privateDecrypt, publicEncrypt, randomBytes,
  verify, constants, type KeyObject,
} from 'node:crypto';
import { crc32c } from '../../src/box/seal/kms.js';
import type { CredentialSource, HttpRequest, HttpResponse, TokenRole } from '../../src/types.js';
import { FakeHttp, json } from '../helpers/fake-http.js';

export const NOW = new Date('2026-10-28T12:00:00.000Z');
export const now = () => NOW;

export function seal(key: Buffer, plaintext: Buffer, aad: Buffer): Buffer {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]);
}

export function open(key: Buffer, sealed: Buffer, aad: Buffer): Buffer | null {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, sealed.subarray(0, 12));
    decipher.setAAD(aad);
    decipher.setAuthTag(sealed.subarray(12, 28));
    return Buffer.concat([decipher.update(sealed.subarray(28)), decipher.final()]);
  } catch { return null; }
}

const body = (req: HttpRequest) => JSON.parse(req.body ?? '{}') as Record<string, unknown>;
const header = (req: HttpRequest, name: string) => Object.entries(req.headers ?? {}).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1];

// ------------------------------------------------------------------ AWS KMS
export interface FakeAws { http: FakeHttp; state: { disabled: boolean; down: boolean; keyArn: string; plaintextOverride?: Buffer } }
export function fakeAwsKms(options: { region?: string; keyArn?: string; http?: FakeHttp } = {}): FakeAws {
  const region = options.region ?? 'us-east-1';
  const http = options.http ?? new FakeHttp();
  const master = randomBytes(32);
  const state = { disabled: false, down: false, keyArn: options.keyArn ?? `arn:aws:kms:${region}:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab` };
  const host = new RegExp(`^https://kms\\.${region.replace(/-/g, '\\-')}\\.amazonaws\\.com/$`);
  http.on('POST', host, req => {
    if (state.down) throw new Error('connect ECONNREFUSED upstream-secret-detail');
    if (!header(req, 'authorization')?.startsWith('AWS4-HMAC-SHA256 Credential=')) return json(400, { __type: 'MissingAuthenticationTokenException' });
    if (state.disabled) return json(400, { __type: 'com.amazonaws.kms#DisabledException', message: 'upstream-secret-detail' });
    const input = body(req);
    const aad = Buffer.from(JSON.stringify(input.EncryptionContext ?? {}));
    if (header(req, 'x-amz-target') === 'TrentService.Encrypt') {
      const blob = seal(master, Buffer.from(String(input.Plaintext), 'base64'), aad);
      return json(200, { CiphertextBlob: blob.toString('base64'), KeyId: state.keyArn, EncryptionAlgorithm: 'SYMMETRIC_DEFAULT' });
    }
    if (input.KeyId !== undefined && input.KeyId !== state.keyArn) return json(400, { __type: 'IncorrectKeyException', message: 'upstream-secret-detail' });
    const plain = open(master, Buffer.from(String(input.CiphertextBlob), 'base64'), aad);
    if (!plain) return json(400, { __type: 'InvalidCiphertextException', message: 'upstream-secret-detail' });
    return json(200, { KeyId: state.keyArn, Plaintext: (state.plaintextOverride ?? plain).toString('base64'), EncryptionAlgorithm: 'SYMMETRIC_DEFAULT' });
  });
  return { http, state };
}

// ------------------------------------------------------------------ Google Cloud KMS
export const GCP_KEY = 'projects/acme-prod-123/locations/europe-west1/keyRings/keysentry/cryptoKeys/state';
export interface FakeGcp {
  http: FakeHttp; serviceAccountJson: string; publicKey: KeyObject;
  state: { primary: number; disabled: boolean; tokensIssued: number; lastAssertion?: string; tokenStatus: number };
  rotate(): void;
}
export function fakeGcpKms(options: { http?: FakeHttp } = {}): FakeGcp {
  const http = options.http ?? new FakeHttp();
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const versions = new Map<number, Buffer>([[1, randomBytes(32)]]);
  const state = { primary: 1, disabled: false, tokensIssued: 0, tokenStatus: 200 } as FakeGcp['state'];
  const issued = new Set<string>(['direct-access-token-planted']);
  const serviceAccountJson = JSON.stringify({
    type: 'service_account', project_id: 'acme-prod-123', private_key_id: 'abc123def456',
    private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    client_email: 'keysentry@acme-prod-123.iam.gserviceaccount.com', client_id: '1234567890',
    token_uri: 'https://oauth2.googleapis.com/token',
  });
  http.on('POST', /^https:\/\/oauth2\.googleapis\.com\/token$/, req => {
    const form = new URLSearchParams(req.body ?? '');
    const assertion = form.get('assertion') ?? '';
    state.lastAssertion = assertion;
    const [head, claims, signature] = assertion.split('.');
    const valid = form.get('grant_type') === 'urn:ietf:params:oauth:grant-type:jwt-bearer' && !!signature
      && verify('sha256', Buffer.from(`${head}.${claims}`), publicKey, Buffer.from(signature, 'base64url'));
    if (!valid || state.tokenStatus !== 200) return json(state.tokenStatus === 200 ? 400 : state.tokenStatus, { error: 'invalid_grant', error_description: 'upstream-secret-detail' });
    const token = `ya29.issued-${++state.tokensIssued}`;
    issued.add(token);
    return json(200, { access_token: token, token_type: 'Bearer', expires_in: 3599 });
  });
  const cryptoKey = new RegExp(`^https://cloudkms\\.googleapis\\.com/v1/${GCP_KEY.replace(/\//g, '\\/')}:(encrypt|decrypt)$`);
  http.on('POST', cryptoKey, (req, match) => {
    if (!issued.has(header(req, 'authorization')?.replace(/^Bearer /, '') ?? '')) return json(401, { error: { code: 401, status: 'UNAUTHENTICATED', message: 'upstream-secret-detail' } });
    if (state.disabled) return json(400, { error: { code: 400, status: 'FAILED_PRECONDITION', message: 'upstream-secret-detail' } });
    const input = body(req);
    const aad = Buffer.from(String(input.additionalAuthenticatedData ?? ''), 'base64');
    if (input.additionalAuthenticatedDataCrc32c !== String(crc32c(aad))) return json(400, { error: { status: 'INVALID_ARGUMENT' } });
    if (match[1] === 'encrypt') {
      const plaintext = Buffer.from(String(input.plaintext), 'base64');
      if (input.plaintextCrc32c !== String(crc32c(plaintext))) return json(400, { error: { status: 'INVALID_ARGUMENT' } });
      const ciphertext = Buffer.concat([Buffer.from([state.primary]), seal(versions.get(state.primary)!, plaintext, aad)]);
      return json(200, { name: `${GCP_KEY}/cryptoKeyVersions/${state.primary}`, ciphertext: ciphertext.toString('base64'),
        ciphertextCrc32c: String(crc32c(ciphertext)), verifiedPlaintextCrc32c: true, verifiedAdditionalAuthenticatedDataCrc32c: true,
        protectionLevel: 'SOFTWARE' });
    }
    const ciphertext = Buffer.from(String(input.ciphertext), 'base64');
    if (input.ciphertextCrc32c !== String(crc32c(ciphertext))) return json(400, { error: { status: 'INVALID_ARGUMENT' } });
    const key = versions.get(ciphertext[0] ?? 0);
    const plain = key ? open(key, ciphertext.subarray(1), aad) : null;
    if (!plain) return json(400, { error: { code: 400, status: 'INVALID_ARGUMENT', message: 'Decryption failed: upstream-secret-detail' } });
    return json(200, { plaintext: plain.toString('base64'), plaintextCrc32c: String(crc32c(plain)), usedPrimary: ciphertext[0] === state.primary });
  });
  return { http, serviceAccountJson, publicKey: createPublicKey(privateKey), state,
    rotate() { state.primary += 1; versions.set(state.primary, randomBytes(32)); } };
}

// ------------------------------------------------------------------ Azure Key Vault
export const AZURE_VAULT = 'https://acme-keys.vault.azure.net';
export const AZURE_TENANT = '72f988bf-86f1-41af-91ab-2d7cd011db47';
const version = () => randomBytes(16).toString('hex');
export interface FakeAzure { http: FakeHttp; state: { latest: string; versions: Map<string, KeyObject>; disabled: boolean; tokensIssued: number } }
export function fakeAzureKeyVault(options: { http?: FakeHttp } = {}): FakeAzure {
  const http = options.http ?? new FakeHttp();
  const first = version();
  const state = { latest: first, versions: new Map([[first, generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey]]), disabled: false, tokensIssued: 0 };
  const issued = new Set<string>();
  http.on('POST', new RegExp(`^https://login\\.microsoftonline\\.com/${AZURE_TENANT}/oauth2/v2\\.0/token$`), req => {
    const form = new URLSearchParams(req.body ?? '');
    if (form.get('grant_type') !== 'client_credentials' || form.get('scope') !== 'https://vault.azure.net/.default'
      || form.get('client_id') !== 'app-client-id' || form.get('client_secret') !== 'azure-client-secret-planted') {
      return json(401, { error: 'invalid_client', error_description: 'upstream-secret-detail' });
    }
    const token = `eyJ0eXAi.azure-issued-${++state.tokensIssued}`;
    issued.add(token);
    return json(200, { token_type: 'Bearer', expires_in: 3599, access_token: token });
  });
  const authorized = (req: HttpRequest) => issued.has(header(req, 'authorization')?.replace(/^Bearer /, '') ?? '');
  http.on('GET', /^https:\/\/acme-keys\.vault\.azure\.net\/keys\/state-key\?api-version=2025-07-01$/, req => {
    if (!authorized(req)) return json(401, { error: { code: 'Unauthorized', message: 'upstream-secret-detail' } });
    return json(200, { key: { kid: `${AZURE_VAULT}/keys/state-key/${state.latest}`, kty: 'RSA', key_ops: ['wrapKey', 'unwrapKey'], n: 'x', e: 'AQAB' },
      attributes: { enabled: !state.disabled } });
  });
  http.on('POST', /^https:\/\/acme-keys\.vault\.azure\.net\/keys\/state-key\/([A-Za-z0-9]+)\/(wrapkey|unwrapkey)\?api-version=2025-07-01$/, (req, match) => {
    if (!authorized(req)) return json(401, { error: { code: 'Unauthorized', message: 'upstream-secret-detail' } });
    if (state.disabled) return json(403, { error: { code: 'Forbidden', message: 'upstream-secret-detail' } });
    const key = state.versions.get(match[1]!);
    if (!key) return json(404, { error: { code: 'KeyNotFound', message: 'upstream-secret-detail' } });
    const input = body(req);
    if (input.alg !== 'RSA-OAEP-256') return json(400, { error: { code: 'BadParameter' } });
    const value = Buffer.from(String(input.value), 'base64url');
    const kid = `${AZURE_VAULT}/keys/state-key/${match[1]}`;
    if (match[2] === 'wrapkey') {
      const wrapped = publicEncrypt({ key: createPublicKey(key), padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, value);
      return json(200, { kid, value: wrapped.toString('base64url') });
    }
    try {
      const plain = privateDecrypt({ key, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, value);
      return json(200, { kid, value: plain.toString('base64url') });
    } catch { return json(400, { error: { code: 'BadParameter', message: 'upstream-secret-detail' } }); }
  });
  return { http, state };
}
export function rotateAzure(fake: FakeAzure): string {
  const next = version();
  fake.state.versions.set(next, generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey);
  fake.state.latest = next;
  return next;
}

// ------------------------------------------------------------------ Vault Transit
export const VAULT_ADDR = 'https://vault.acme.example';
export interface FakeVaultTransit { http: FakeHttp; state: { type: string; derived: boolean; versions: Buffer[]; sealed: boolean; token: string; exists: boolean } }
export function fakeVaultTransit(options: { http?: FakeHttp; mount?: string; derived?: boolean; type?: string } = {}): FakeVaultTransit {
  const http = options.http ?? new FakeHttp();
  const mount = options.mount ?? 'transit';
  const state = { type: options.type ?? 'aes256-gcm96', derived: options.derived ?? false, versions: [randomBytes(32)], sealed: false,
    token: 'hvs.vault-token-planted', exists: true };
  const base = `^https://vault\\.acme\\.example/v1/${mount}/`;
  const guard = (req: HttpRequest): HttpResponse | null => {
    if (state.sealed) return json(503, { errors: ['Vault is sealed upstream-secret-detail'] });
    if (header(req, 'x-vault-token') !== state.token) return json(403, { errors: ['permission denied upstream-secret-detail'] });
    if (!state.exists) return json(404, { errors: [] });
    return null;
  };
  http.on('GET', new RegExp(`${base}keys/state$`), req => guard(req) ?? json(200, { data: {
    type: state.type, derived: state.derived, keys: Object.fromEntries(state.versions.map((_, index) => [String(index + 1), 1761650000])),
    latest_version: state.versions.length, min_decryption_version: 1, min_encryption_version: 0, name: 'state',
    supports_encryption: true, supports_decryption: true, supports_derivation: true, supports_signing: false } }));
  const aadOf = (input: Record<string, unknown>) => {
    // A derived key derives per context; model it by mixing the context into the AAD. Non-derived keys ignore context.
    const field = state.derived ? input.context : input.associated_data;
    return Buffer.from(typeof field === 'string' ? field : '', 'base64');
  };
  http.on('POST', new RegExp(`${base}encrypt/state$`), req => {
    const denied = guard(req); if (denied) return denied;
    const input = body(req);
    if (state.derived && typeof input.context !== 'string') return json(400, { errors: ['missing context for key derivation'] });
    const ciphertext = seal(state.versions.at(-1)!, Buffer.from(String(input.plaintext), 'base64'), aadOf(input));
    return json(200, { data: { ciphertext: `vault:v${state.versions.length}:${ciphertext.toString('base64')}`, key_version: state.versions.length } });
  });
  http.on('POST', new RegExp(`${base}decrypt/state$`), req => {
    const denied = guard(req); if (denied) return denied;
    const input = body(req);
    const match = /^vault:v(\d+):(.+)$/.exec(String(input.ciphertext));
    const key = match ? state.versions[Number(match[1]) - 1] : undefined;
    const plain = key && match ? open(key, Buffer.from(match[2]!, 'base64'), aadOf(input)) : null;
    if (!plain) return json(400, { errors: ['cipher: message authentication failed upstream-secret-detail'] });
    return json(200, { data: { plaintext: plain.toString('base64') } });
  });
  return { http, state };
}

export const sha256 = (value: string) => createHash('sha256').update(value).digest();

/** A CredentialSource over fixed values; records every (name, role) lookup. */
export function credentialSource(values: Record<string, string>): CredentialSource & { lookups: { name: string; role: TokenRole }[] } {
  const lookups: { name: string; role: TokenRole }[] = [];
  return {
    lookups,
    async get(name, role) {
      lookups.push({ name, role });
      const value = values[`${name}@${role}`] ?? values[name];
      return value === undefined ? null : { value, source: 'vault' };
    },
  };
}

/** Assert an error carries none of the given secret strings anywhere a user or log could see. */
export function secretFree(error: unknown, secrets: readonly string[]): boolean {
  const seen = [String(error), error instanceof Error ? error.message : '', error instanceof Error ? error.stack ?? '' : '', JSON.stringify(error)].join('\n');
  return secrets.every(secret => !seen.includes(secret)) && !seen.includes('upstream-secret-detail');
}

export async function failure(promise: Promise<unknown>): Promise<Error & { code?: string }> {
  try { await promise; } catch (error) { return error as Error & { code?: string }; }
  throw new Error('expected the operation to fail');
}
