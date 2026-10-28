import { EgressBlockedError } from '../net/index.js';
import { CaBundleError, TransportConfigError } from '../net/transport.js';
import type { CredentialSource, HttpClient, HttpRequest, HttpResponse, KmsProviderId, TokenRole } from '../types.js';
import { blocked, damaged, invalidResponse, networkRefused, unreachable } from './errors.js';

export interface KeyWrapperDeps {
  /** The egress-guarded client; see `createKmsHttp`. */
  http: HttpClient;
  credentials: CredentialSource;
  now?: () => Date;
}

/** Wrapping writes need the write-role credential; unwrapping prefers a dedicated read-role one. */
export type KmsOperation = 'wrap' | 'unwrap';
export const roleFor = (operation: KmsOperation): TokenRole => operation === 'wrap' ? 'write' : 'read';

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const BASE64URL = /^[A-Za-z0-9_-]*$/;

/** Canonical standard base64 only; anything else is treated as damaged input. */
export function decodeBase64(value: unknown, maxBytes: number): Buffer | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > Math.ceil(maxBytes / 3) * 4 || !BASE64.test(value)) return null;
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length === 0 || bytes.length > maxBytes || bytes.toString('base64') !== value) { bytes.fill(0); return null; }
  return bytes;
}

/** Unpadded base64url (RFC 7515). Azure documents base64url but has shown standard base64 in samples, so both decode. */
export function decodeBase64Url(value: unknown, maxBytes: number): Buffer | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > Math.ceil(maxBytes / 3) * 4 + 2) return null;
  const normalized = value.replace(/=+$/, '');
  const url = BASE64URL.test(normalized) ? normalized : /^[A-Za-z0-9+/]*$/.test(normalized) ? normalized.replace(/\+/g, '-').replace(/\//g, '_') : null;
  if (url === null || url.length % 4 === 1) return null;
  const bytes = Buffer.from(url, 'base64url');
  if (bytes.length === 0 || bytes.length > maxBytes || bytes.toString('base64url') !== url) { bytes.fill(0); return null; }
  return bytes;
}

export function jsonObject(response: HttpResponse): Record<string, unknown> | null {
  try {
    const body = response.json<unknown>();
    return body && typeof body === 'object' && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch { return null; }
}

/** All provider traffic goes through here: a blocked host or a transport failure becomes fixed text. */
export async function send(provider: KmsProviderId, http: HttpClient, request: HttpRequest): Promise<HttpResponse> {
  try { return await http.request(request); }
  catch (error) {
    if (error instanceof EgressBlockedError) throw blocked(provider);
    // A refusing transport (a broken proxy, CA or policy setting) is not a connection problem: name the setting.
    if (error instanceof TransportConfigError || error instanceof CaBundleError) throw networkRefused(provider, error.message);
    throw unreachable(provider);
  }
}

export async function credential(credentials: CredentialSource, name: string, role: TokenRole): Promise<string | null> {
  const found = await credentials.get(name, role);
  const value = found?.value.trim();
  return value ? value : null;
}

/** The opaque bytes each adapter returns: a small JSON envelope with the provider's ciphertext and version label. */
export function encodeEnvelope(fields: Record<string, string>): Buffer {
  return Buffer.from(JSON.stringify({ v: 1, ...fields }), 'utf8');
}

export function decodeEnvelope<K extends string>(provider: KmsProviderId, wrapped: Buffer, keys: readonly K[]): Record<K, string> {
  if (!Buffer.isBuffer(wrapped) || wrapped.length === 0 || wrapped.length > 16 * 1024) throw damaged(provider);
  let value: unknown;
  try { value = JSON.parse(wrapped.toString('utf8')); } catch { throw damaged(provider); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw damaged(provider);
  const record = value as Record<string, unknown>;
  const names = Object.keys(record).sort();
  const expected = ['v', ...keys].sort();
  if (record.v !== 1 || names.length !== expected.length || names.some((name, index) => name !== expected[index])) throw damaged(provider);
  const out = {} as Record<K, string>;
  for (const key of keys) {
    const item = record[key];
    if (typeof item !== 'string' || item.length === 0 || item.length > 12 * 1024) throw damaged(provider);
    out[key] = item;
  }
  return out;
}

export function assertDataKey(dataKey: Buffer, maxBytes: number): void {
  if (!Buffer.isBuffer(dataKey) || dataKey.length === 0 || dataKey.length > maxBytes) {
    throw new TypeError('The data key must be between 1 and the provider\'s maximum number of bytes.');
  }
}

export function assertContext(context: string): void {
  if (typeof context !== 'string' || context.length === 0 || context.length > 512 || !/^[\x21-\x7e]+$/.test(context)) {
    throw new TypeError('The KMS context must be 1 to 512 printable ASCII characters without spaces.');
  }
}

/** Short-lived OAuth tokens are cached per role in memory and never written anywhere. */
export interface CachedToken { value: string; expiresAt: number }
export const TOKEN = /^[A-Za-z0-9._~+/-]+=*$/;

export function validToken(provider: KmsProviderId, value: unknown, limit = 16 * 1024): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > limit || !TOKEN.test(value)) throw invalidResponse(provider);
  return value;
}
