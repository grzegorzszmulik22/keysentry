import { createPrivateKey, sign, type KeyObject } from 'node:crypto';
import { crc32c } from '../box/seal/kms.js';
import type { KeyWrapper, TokenRole } from '../types.js';
import { failureFor, invalidResponse, KmsError, missingCredentials, rejected } from './errors.js';
import {
  assertContext, assertDataKey, credential, decodeBase64, decodeEnvelope, encodeEnvelope, jsonObject, roleFor, send, TOKEN, validToken,
  type CachedToken, type KeyWrapperDeps, type KmsOperation,
} from './shared.js';
import type { GcpKmsSettings } from './settings.js';

const PROVIDER = 'gcp-kms' as const;
export const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
export const GOOGLE_KMS_SCOPE = 'https://www.googleapis.com/auth/cloudkms';
const JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

interface ServiceAccount { email: string; key: KeyObject; keyId?: string }

function badServiceAccount(): KmsError {
  return new KmsError('credentials', 'GOOGLE_SERVICE_ACCOUNT_KEY is not a usable service account key. Provide the JSON key file contents (or its base64 encoding).');
}

function parseServiceAccount(raw: string): ServiceAccount {
  let text = raw.trim();
  if (!text.startsWith('{')) {
    const decoded = decodeBase64(text.replace(/\s+/g, ''), 64 * 1024);
    if (!decoded) throw badServiceAccount();
    try { text = decoded.toString('utf8'); } finally { decoded.fill(0); }
  }
  let data: unknown;
  try { data = JSON.parse(text); } catch { throw badServiceAccount(); }
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw badServiceAccount();
  const record = data as Record<string, unknown>;
  const email = record.client_email, pem = record.private_key, keyId = record.private_key_id, tokenUri = record.token_uri;
  if (record.type !== 'service_account' || typeof email !== 'string' || !/^[A-Za-z0-9._%+-]{1,128}@[A-Za-z0-9.-]{1,253}$/.test(email)
    || typeof pem !== 'string' || pem.length > 16 * 1024 || (keyId !== undefined && (typeof keyId !== 'string' || !/^[A-Za-z0-9]{1,128}$/.test(keyId)))) {
    throw badServiceAccount();
  }
  // Only Google's own token endpoint is allowed; a key naming another endpoint is refused rather than followed.
  if (tokenUri !== undefined && tokenUri !== GOOGLE_TOKEN_URL) {
    throw new KmsError('credentials', 'GOOGLE_SERVICE_ACCOUNT_KEY names a token endpoint other than oauth2.googleapis.com, so keysentry did not use it.');
  }
  let key: KeyObject;
  try { key = createPrivateKey({ key: pem, format: 'pem' }); } catch { throw badServiceAccount(); }
  if (key.asymmetricKeyType !== 'rsa') throw badServiceAccount();
  return { email, key, ...(typeof keyId === 'string' ? { keyId } : {}) };
}

const segment = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');

/** RS256 JWT for the OAuth 2.0 JWT bearer grant (RFC 7523), signed with node:crypto. */
export function serviceAccountAssertion(account: ServiceAccount, now: Date): string {
  const iat = Math.floor(now.getTime() / 1000);
  const input = `${segment({ alg: 'RS256', typ: 'JWT', ...(account.keyId ? { kid: account.keyId } : {}) })}.${segment({
    iss: account.email, scope: GOOGLE_KMS_SCOPE, aud: GOOGLE_TOKEN_URL, iat, exp: iat + 3600,
  })}`;
  return `${input}.${sign('sha256', Buffer.from(input, 'utf8'), account.key).toString('base64url')}`;
}

/** Cloud KMS `cryptoKeys.encrypt`/`decrypt` with CRC32C integrity fields; the context is the additional authenticated data. */
export function createGcpKmsWrapper(settings: GcpKmsSettings, deps: KeyWrapperDeps): KeyWrapper {
  const now = deps.now ?? (() => new Date());
  const tokens = new Map<TokenRole, CachedToken>();
  const versionPrefix = `${settings.keyName}/cryptoKeyVersions/`;

  async function accessToken(role: TokenRole): Promise<string> {
    const direct = await credential(deps.credentials, 'GOOGLE_OAUTH_ACCESS_TOKEN', role);
    if (direct) {
      if (direct.length > 12 * 1024 || !TOKEN.test(direct)) throw new KmsError('credentials', 'GOOGLE_OAUTH_ACCESS_TOKEN is not in a valid format.');
      return direct;
    }
    const cached = tokens.get(role);
    if (cached && cached.expiresAt > now().getTime()) return cached.value;
    const raw = await credential(deps.credentials, 'GOOGLE_SERVICE_ACCOUNT_KEY', role);
    if (!raw) throw missingCredentials(PROVIDER, 'GOOGLE_OAUTH_ACCESS_TOKEN or a service account key in GOOGLE_SERVICE_ACCOUNT_KEY');
    const account = parseServiceAccount(raw);
    const issuedAt = now();
    const response = await send(PROVIDER, deps.http, {
      method: 'POST', url: GOOGLE_TOKEN_URL, headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=${encodeURIComponent(JWT_BEARER)}&assertion=${serviceAccountAssertion(account, issuedAt)}`,
    });
    if (response.status !== 200) throw failureFor(PROVIDER, response.status, 'token');
    const body = jsonObject(response);
    const expiresIn = body?.expires_in;
    if (!body || body.token_type !== 'Bearer' || typeof expiresIn !== 'number' || !Number.isSafeInteger(expiresIn) || expiresIn <= 0) throw invalidResponse(PROVIDER);
    const value = validToken(PROVIDER, body.access_token, 12 * 1024);
    tokens.set(role, { value, expiresAt: issuedAt.getTime() + Math.max(0, expiresIn - 60) * 1000 });
    return value;
  }

  async function call(operation: KmsOperation, body: Record<string, unknown>): Promise<Record<string, unknown>> {
    const token = await accessToken(roleFor(operation));
    const response = await send(PROVIDER, deps.http, {
      method: 'POST', url: `https://cloudkms.googleapis.com/v1/${settings.keyName}:${operation === 'wrap' ? 'encrypt' : 'decrypt'}`,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify(body),
    });
    const parsed = jsonObject(response);
    if (response.status !== 200) {
      const error = parsed?.error;
      const status = error && typeof error === 'object' && 'status' in error && typeof error.status === 'string' && /^[A-Z_]{1,64}$/.test(error.status) ? error.status : undefined;
      throw failureFor(PROVIDER, response.status, operation, status);
    }
    if (!parsed) throw invalidResponse(PROVIDER);
    return parsed;
  }

  const checksum = (value: unknown, bytes: Buffer) => (typeof value === 'string' && /^\d{1,10}$/.test(value)) || typeof value === 'number'
    ? Number(value) === crc32c(bytes) : false;

  return {
    provider: PROVIDER,
    keyRef: settings.keyName,
    async wrap(dataKey, context) {
      assertDataKey(dataKey, 8 * 1024); assertContext(context);
      const aad = Buffer.from(context, 'utf8');
      const body = await call('wrap', {
        plaintext: dataKey.toString('base64'), additionalAuthenticatedData: aad.toString('base64'),
        plaintextCrc32c: String(crc32c(dataKey)), additionalAuthenticatedDataCrc32c: String(crc32c(aad)),
      });
      const ciphertext = decodeBase64(body.ciphertext, 64 * 1024);
      const version = body.name;
      if (!ciphertext || body.verifiedPlaintextCrc32c !== true || body.verifiedAdditionalAuthenticatedDataCrc32c !== true
        || !checksum(body.ciphertextCrc32c, ciphertext)
        || typeof version !== 'string' || !version.startsWith(versionPrefix) || !/^\d{1,10}$/.test(version.slice(versionPrefix.length))) {
        ciphertext?.fill(0);
        throw invalidResponse(PROVIDER);
      }
      return encodeEnvelope({ version, ciphertext: ciphertext.toString('base64') });
    },
    async unwrap(wrapped, context) {
      assertContext(context);
      const envelope = decodeEnvelope(PROVIDER, wrapped, ['version', 'ciphertext']);
      const ciphertext = decodeBase64(envelope.ciphertext, 64 * 1024);
      if (!ciphertext || !envelope.version.startsWith(versionPrefix)) throw rejected(PROVIDER);
      const aad = Buffer.from(context, 'utf8');
      const body = await call('unwrap', {
        ciphertext: envelope.ciphertext, additionalAuthenticatedData: aad.toString('base64'),
        ciphertextCrc32c: String(crc32c(ciphertext)), additionalAuthenticatedDataCrc32c: String(crc32c(aad)),
      });
      const plaintext = decodeBase64(body.plaintext, 64 * 1024);
      if (!plaintext || !checksum(body.plaintextCrc32c, plaintext)) { plaintext?.fill(0); throw invalidResponse(PROVIDER); }
      return plaintext;
    },
  };
}

export function gcpKeyVersion(wrapped: Buffer): string | undefined {
  try { return decodeEnvelope(PROVIDER, wrapped, ['version', 'ciphertext']).version; } catch { return undefined; }
}
