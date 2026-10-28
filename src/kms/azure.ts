import { createHash, timingSafeEqual } from 'node:crypto';
import type { HttpRequest, KeyWrapper, TokenRole } from '../types.js';
import { failureFor, invalidResponse, KmsError, missingCredentials, rejected } from './errors.js';
import {
  assertContext, assertDataKey, credential, decodeBase64Url, decodeEnvelope, encodeEnvelope, jsonObject, roleFor, send, validToken,
  type CachedToken, type KeyWrapperDeps, type KmsOperation,
} from './shared.js';
import type { AzureKeyVaultSettings } from './settings.js';

const PROVIDER = 'azure-key-vault' as const;
/** Key Vault keys REST API version (learn.microsoft.com/rest/api/keyvault/keys/wrap-key/wrap-key, 2025-07-01). */
export const AZURE_KEYS_API_VERSION = '2025-07-01';
export const AZURE_VAULT_SCOPE = 'https://vault.azure.net/.default';
const VERSION = /^[A-Za-z0-9]{32}$/;

/**
 * Key Vault `wrapkey`/`unwrapkey` with RSA-OAEP-256. RSA wrapping has no additional authenticated data, so the
 * context is bound by wrapping `sha256(context) || dataKey` and checking that prefix after unwrapping.
 */
export function createAzureKeyVaultWrapper(settings: AzureKeyVaultSettings, deps: KeyWrapperDeps): KeyWrapper {
  const url = new URL(settings.vaultUrl);
  const hostname = url.hostname.toLowerCase();
  if (!hostname.endsWith('.vault.azure.net') || (url.pathname !== '/' && url.pathname !== '') || url.search || url.hash) {
    throw new KmsError('config', 'kms.vaultUrl must be an Azure Key Vault address such as https://example.vault.azure.net/.');
  }
  const origin = `https://${hostname}`;
  const now = deps.now ?? (() => new Date());
  const tokens = new Map<TokenRole, CachedToken>();
  const keyPath = `/keys/${settings.keyName.toLowerCase()}/`;

  /** The version in a `kid` that names this vault and key, or null. */
  function kidVersion(kid: unknown): string | null {
    if (typeof kid !== 'string' || kid.length > 1024) return null;
    try {
      const parsed = new URL(kid);
      const path = parsed.pathname.toLowerCase();
      if (parsed.protocol !== 'https:' || parsed.hostname.toLowerCase() !== hostname || !path.startsWith(keyPath)) return null;
      const version = parsed.pathname.slice(keyPath.length);
      return VERSION.test(version) ? version : null;
    } catch { return null; }
  }

  async function accessToken(role: TokenRole): Promise<string> {
    const cached = tokens.get(role);
    if (cached && cached.expiresAt > now().getTime()) return cached.value;
    const tenant = await credential(deps.credentials, 'AZURE_TENANT_ID', role);
    const clientId = await credential(deps.credentials, 'AZURE_CLIENT_ID', role);
    const secret = await credential(deps.credentials, 'AZURE_CLIENT_SECRET', role);
    if (!tenant || !clientId || !secret) throw missingCredentials(PROVIDER, 'AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET');
    if (!/^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/.test(tenant) || !/^[A-Za-z0-9-]{1,128}$/.test(clientId) || secret.length > 4096) {
      throw new KmsError('credentials', 'The Azure credentials for Key Vault are not in a valid format. Check AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET.');
    }
    const issuedAt = now();
    const response = await send(PROVIDER, deps.http, {
      method: 'POST', url: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: clientId, scope: AZURE_VAULT_SCOPE, client_secret: secret, grant_type: 'client_credentials' }).toString(),
    });
    if (response.status !== 200) throw failureFor(PROVIDER, response.status, 'token');
    const body = jsonObject(response);
    const expiresIn = typeof body?.expires_in === 'string' && /^\d{1,7}$/.test(body.expires_in) ? Number(body.expires_in) : body?.expires_in;
    if (!body || typeof body.token_type !== 'string' || body.token_type.toLowerCase() !== 'bearer'
      || typeof expiresIn !== 'number' || !Number.isSafeInteger(expiresIn) || expiresIn <= 0) throw invalidResponse(PROVIDER);
    const value = validToken(PROVIDER, body.access_token, 16 * 1024);
    tokens.set(role, { value, expiresAt: issuedAt.getTime() + Math.max(0, expiresIn - 60) * 1000 });
    return value;
  }

  async function call(operation: KmsOperation | 'describe', request: Omit<HttpRequest, 'headers'>): Promise<Record<string, unknown>> {
    const token = await accessToken(roleFor(operation === 'describe' ? 'wrap' : operation));
    const response = await send(PROVIDER, deps.http, { ...request,
      headers: { Authorization: `Bearer ${token}`, ...(request.body === undefined ? {} : { 'Content-Type': 'application/json' }) } });
    const parsed = jsonObject(response);
    if (response.status !== 200) {
      const error = parsed?.error;
      const code = error && typeof error === 'object' && 'code' in error && typeof error.code === 'string' && /^[A-Za-z]{1,64}$/.test(error.code) ? error.code : undefined;
      throw failureFor(PROVIDER, response.status, operation, code);
    }
    if (!parsed) throw invalidResponse(PROVIDER);
    return parsed;
  }

  /** Without a pinned version, wrap under the latest version (Get Key without a version returns the latest). */
  async function currentVersion(): Promise<string> {
    if (settings.keyVersion) return settings.keyVersion;
    const body = await call('describe', { method: 'GET', url: `${origin}/keys/${settings.keyName}?api-version=${AZURE_KEYS_API_VERSION}` });
    const key = body.key && typeof body.key === 'object' ? body.key as Record<string, unknown> : null;
    const attributes = body.attributes && typeof body.attributes === 'object' ? body.attributes as Record<string, unknown> : {};
    const version = kidVersion(key?.kid);
    if (!key || !version) throw invalidResponse(PROVIDER);
    if (attributes.enabled === false) throw failureFor(PROVIDER, 403, 'wrap', 'KeyDisabled');
    if (key.kty !== 'RSA' && key.kty !== 'RSA-HSM') throw failureFor(PROVIDER, 400, 'wrap', 'InvalidKeyUsageException');
    if (Array.isArray(key.key_ops) && !key.key_ops.includes('wrapKey')) throw failureFor(PROVIDER, 400, 'wrap', 'InvalidKeyUsageException');
    return version;
  }

  const binding = (context: string) => createHash('sha256').update(context, 'utf8').digest();

  return {
    provider: PROVIDER,
    keyRef: `${origin}/keys/${settings.keyName}`,
    async wrap(dataKey, context) {
      assertDataKey(dataKey, 128); assertContext(context);
      const version = await currentVersion();
      const payload = Buffer.concat([binding(context), dataKey]);
      let body: Record<string, unknown>;
      try {
        body = await call('wrap', { method: 'POST', url: `${origin}/keys/${settings.keyName}/${version}/wrapkey?api-version=${AZURE_KEYS_API_VERSION}`,
          body: JSON.stringify({ alg: 'RSA-OAEP-256', value: payload.toString('base64url') }) });
      } finally { payload.fill(0); }
      const ciphertext = decodeBase64Url(body.value, 1024);
      if (!ciphertext || kidVersion(body.kid) !== version) { ciphertext?.fill(0); throw invalidResponse(PROVIDER); }
      return encodeEnvelope({ version, ciphertext: ciphertext.toString('base64url') });
    },
    async unwrap(wrapped, context) {
      assertContext(context);
      const envelope = decodeEnvelope(PROVIDER, wrapped, ['version', 'ciphertext']);
      if (!VERSION.test(envelope.version) || !decodeBase64Url(envelope.ciphertext, 1024)) throw rejected(PROVIDER);
      const body = await call('unwrap', { method: 'POST', url: `${origin}/keys/${settings.keyName}/${envelope.version}/unwrapkey?api-version=${AZURE_KEYS_API_VERSION}`,
        body: JSON.stringify({ alg: 'RSA-OAEP-256', value: envelope.ciphertext }) });
      if (kidVersion(body.kid) !== envelope.version) throw invalidResponse(PROVIDER);
      const payload = decodeBase64Url(body.value, 1024);
      if (!payload) throw invalidResponse(PROVIDER);
      try {
        const expected = binding(context);
        if (payload.length <= expected.length || !timingSafeEqual(payload.subarray(0, expected.length), expected)) throw rejected(PROVIDER);
        return Buffer.from(payload.subarray(expected.length));
      } finally { payload.fill(0); }
    },
  };
}

export function azureKeyVersion(wrapped: Buffer): string | undefined {
  try { return decodeEnvelope(PROVIDER, wrapped, ['version', 'ciphertext']).version; } catch { return undefined; }
}
