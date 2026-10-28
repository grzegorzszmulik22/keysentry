import type { HttpRequest, KeyWrapper, TokenRole } from '../types.js';
import { failureFor, invalidResponse, KmsError, missingCredentials, rejected } from './errors.js';
import {
  assertContext, assertDataKey, credential, decodeBase64, decodeEnvelope, encodeEnvelope, jsonObject, roleFor, send,
  type KeyWrapperDeps, type KmsOperation,
} from './shared.js';
import type { VaultTransitSettings } from './settings.js';

const PROVIDER = 'vault-transit' as const;
/** Key types whose encryption authenticates `associated_data` (Vault transit API docs, "Encrypt data"). */
const AEAD_TYPES = new Set(['aes128-gcm96', 'aes256-gcm96', 'chacha20-poly1305']);
const CIPHERTEXT = /^vault:v(\d{1,10}):[A-Za-z0-9+/]+={0,2}$/;

type Binding = 'context' | 'associated_data';

const unbound = () => new KmsError('unsupported', 'Vault Transit did not apply keysentry\'s context binding to this key, so it was not used. '
  + 'Use a Vault version that supports associated_data for this key type, or a derived key.');

/**
 * Vault Transit `encrypt`/`decrypt`. The key is read first (needs `read` on `<mount>/keys/<name>`): a derived key gets
 * the context as `context`; a non-derived AEAD key gets it as `associated_data`; any other key type is refused, since
 * it could not bind the context. Reading first also means a missing key is never created by an encrypt upsert.
 */
export function createVaultTransitWrapper(settings: VaultTransitSettings, deps: KeyWrapperDeps): KeyWrapper {
  const address = new URL(settings.address);
  if (address.protocol !== 'https:' || address.username || address.password || address.search || address.hash) {
    throw new KmsError('config', 'kms.address must be the https address of your Vault server.');
  }
  const base = `${address.origin}${address.pathname.replace(/\/+$/, '')}`;
  const mount = settings.mount ?? 'transit';
  const paths = (action: 'keys' | 'encrypt' | 'decrypt') => `${base}/v1/${mount}/${action}/${settings.keyName}`;
  const bindings = new Map<TokenRole, Binding>();

  async function request(role: TokenRole, input: Omit<HttpRequest, 'headers'>) {
    const token = await credential(deps.credentials, 'VAULT_TOKEN', role);
    if (!token) throw missingCredentials(PROVIDER, 'VAULT_TOKEN');
    if (!/^[\x21-\x7e]{1,4096}$/.test(token)) throw new KmsError('credentials', 'VAULT_TOKEN is not in a valid format.');
    return send(PROVIDER, deps.http, { ...input, headers: {
      'X-Vault-Token': token, ...(settings.namespace ? { 'X-Vault-Namespace': settings.namespace } : {}),
      ...(input.body === undefined ? {} : { 'Content-Type': 'application/json' }),
    } });
  }

  async function call(operation: KmsOperation | 'describe', role: TokenRole, input: Omit<HttpRequest, 'headers'>, field?: Binding): Promise<Record<string, unknown>> {
    const response = await request(role, input);
    if (response.status !== 200) throw failureFor(PROVIDER, response.status, operation === 'describe' ? 'describe' : operation);
    const parsed = jsonObject(response);
    // Vault answers 200 with a warning when it ignores a request parameter (review L5). An ignored binding parameter
    // would silently drop the context binding, so it is refused. Only the parameter name is inspected, never echoed.
    if (field && Array.isArray(parsed?.warnings) && parsed.warnings.some(warning => typeof warning === 'string'
      && (warning.includes(field) || /ignor/i.test(warning)))) throw unbound();
    const data = parsed?.data;
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw invalidResponse(PROVIDER);
    return data as Record<string, unknown>;
  }

  /**
   * Once per wrapper, after the first wrap: decrypting with a different context must fail. A Vault (or something in
   * front of it) that drops the binding parameter without a warning is caught here instead of producing records whose
   * binding was never applied. Any non-200 answer counts as "bound"; the real unwrap check that follows a wrap still
   * proves the record opens with the right context.
   */
  let bindingChecked = false;
  async function checkBinding(ciphertext: string, context: string): Promise<void> {
    if (bindingChecked) return;
    const role = roleFor('unwrap');
    const field = await binding(role);
    const other = `${context}:binding-check`;
    const response = await request(role, { method: 'POST', url: paths('decrypt'),
      body: JSON.stringify({ ciphertext, [field]: Buffer.from(other, 'utf8').toString('base64') }) });
    if (response.status === 200) throw unbound();
    bindingChecked = true;
  }

  async function binding(role: TokenRole): Promise<Binding> {
    const known = bindings.get(role);
    if (known) return known;
    const data = await call('describe', role, { method: 'GET', url: paths('keys') });
    if (data.supports_encryption === false || data.supports_decryption === false) throw failureFor(PROVIDER, 400, 'wrap', 'InvalidKeyUsageException');
    let result: Binding;
    if (data.derived === true) result = 'context';
    else if (typeof data.type === 'string' && AEAD_TYPES.has(data.type)) result = 'associated_data';
    else throw new KmsError('unsupported', 'The Vault Transit key cannot bind keysentry\'s context. Use an aes256-gcm96, aes128-gcm96 or chacha20-poly1305 key, or a derived key.');
    bindings.set(role, result);
    return result;
  }

  return {
    provider: PROVIDER,
    keyRef: `${base}/v1/${settings.namespace ? `${settings.namespace.replace(/\/+$/, '')}/` : ''}${mount}/keys/${settings.keyName}`,
    async wrap(dataKey, context) {
      assertDataKey(dataKey, 32 * 1024); assertContext(context);
      const role = roleFor('wrap');
      const field = await binding(role);
      const data = await call('wrap', role, { method: 'POST', url: paths('encrypt'),
        body: JSON.stringify({ plaintext: dataKey.toString('base64'), [field]: Buffer.from(context, 'utf8').toString('base64') }) }, field);
      if (typeof data.ciphertext !== 'string' || data.ciphertext.length > 64 * 1024 || !CIPHERTEXT.test(data.ciphertext)) throw invalidResponse(PROVIDER);
      await checkBinding(data.ciphertext, context);
      return encodeEnvelope({ ciphertext: data.ciphertext });
    },
    async unwrap(wrapped, context) {
      assertContext(context);
      const envelope = decodeEnvelope(PROVIDER, wrapped, ['ciphertext']);
      if (!CIPHERTEXT.test(envelope.ciphertext)) throw rejected(PROVIDER);
      const role = roleFor('unwrap');
      const field = await binding(role);
      const data = await call('unwrap', role, { method: 'POST', url: paths('decrypt'),
        body: JSON.stringify({ ciphertext: envelope.ciphertext, [field]: Buffer.from(context, 'utf8').toString('base64') }) }, field);
      const plaintext = decodeBase64(data.plaintext, 32 * 1024);
      if (!plaintext) throw invalidResponse(PROVIDER);
      return plaintext;
    },
  };
}

export function vaultKeyVersion(wrapped: Buffer): string | undefined {
  try {
    const match = CIPHERTEXT.exec(decodeEnvelope(PROVIDER, wrapped, ['ciphertext']).ciphertext);
    return match ? `v${match[1]}` : undefined;
  } catch { return undefined; }
}
