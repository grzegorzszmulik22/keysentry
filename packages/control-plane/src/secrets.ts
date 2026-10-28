import type { HttpClient } from '../../../src/types.js';
import { SECRET_REFERENCE } from './egress.js';

/** Fixed text naming the setting whose reference could not be read; never the reference's value or the reply. */
export class SecretUnavailableError extends Error {
  constructor(readonly setting: string) {
    super(`${setting} could not be read from Secret Manager.`);
    this.name = 'SecretUnavailableError';
  }
}

const CRC32C_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0x82f63b78 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();
/** CRC-32C (Castagnoli), the checksum Secret Manager returns as `payload.dataCrc32c`. */
export function crc32c(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of data) crc = CRC32C_TABLE[(crc ^ byte) & 0xff]! ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

export interface ReadSecretOptions {
  /** Reaches only the `:access` URLs of the configured references (createSecretManagerHttp). */
  http: HttpClient;
  /** The runtime service account's token from the metadata server. */
  accessToken: () => Promise<string>;
  /** `projects/*\/secrets/*\/versions/*`. */
  reference: string;
  /** The environment variable that named the reference, for the error text. */
  setting: string;
  retries?: number;
  sleep?: (ms: number) => Promise<void>;
}

/**
 * Reads one secret version through the Secret Manager REST API
 * (`GET https://secretmanager.googleapis.com/v1/{name}:access`), verifies its CRC32C when present, and returns the
 * value with at most one trailing newline removed. Retries 429, 5xx and transport failures a bounded number of times.
 */
export async function readSecret(options: ReadSecretOptions): Promise<string> {
  const { http, reference, setting } = options;
  const retries = options.retries ?? 3;
  const sleep = options.sleep ?? (ms => new Promise<void>(done => setTimeout(done, ms)));
  if (typeof reference !== 'string' || !SECRET_REFERENCE.test(reference)) throw new SecretUnavailableError(setting);
  for (let attempt = 0; ; attempt++) {
    let response: Awaited<ReturnType<HttpClient['request']>> | undefined;
    try {
      const token = await options.accessToken();
      if (typeof token !== 'string' || !token || token.length > 16_384 || /[\r\n\x00]/.test(token)) throw new Error();
      response = await http.request({ method: 'GET', url: `https://secretmanager.googleapis.com/v1/${reference}:access`,
        headers: { authorization: `Bearer ${token}`, accept: 'application/json' } });
    } catch { response = undefined; }
    if (response && response.status === 200) return decodePayload(response.text, setting);
    const retryable = response === undefined || response.status === 429 || response.status >= 500;
    if (!retryable || attempt >= retries) throw new SecretUnavailableError(setting);
    await sleep(Math.min(2_000, 200 * 2 ** attempt));
  }
}

function decodePayload(text: string, setting: string): string {
  let data: Buffer | undefined;
  try {
    if (text.length > 256 * 1024) throw new Error();
    const body = JSON.parse(text) as { payload?: { data?: unknown; dataCrc32c?: unknown } };
    const encoded = body?.payload?.data;
    if (typeof encoded !== 'string' || encoded.length === 0 || encoded.length > 90_000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw new Error();
    data = Buffer.from(encoded, 'base64');
    if (data.length === 0 || data.length > 65_536 || data.toString('base64').replace(/=+$/, '') !== encoded.replace(/=+$/, '')) throw new Error();
    const checksum = body.payload!.dataCrc32c;
    // int64 in proto3 JSON is a decimal string; a plain number is accepted too.
    const sum = typeof checksum === 'string' && /^[0-9]{1,10}$/.test(checksum) ? Number(checksum) : typeof checksum === 'number' ? checksum : NaN;
    if (checksum !== undefined && sum !== crc32c(data)) throw new Error();
    const value = data.toString('utf8').replace(/\r?\n$/, '');
    if (!value || /[\r\n\x00]/.test(value)) throw new Error();
    return value;
  } catch {
    throw new SecretUnavailableError(setting);
  } finally {
    data?.fill(0);
  }
}
