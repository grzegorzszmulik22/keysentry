import { EgressBlockedError } from '../net/guarded-http.js';
import type { HttpClient, HttpRequest, HttpResponse, Vault } from '../types.js';
import { AuditExportError, exportSecretName, type ExportSecretField } from './types.js';

/** RFC 9110 §10.2.3: Retry-After is delay-seconds or an HTTP-date. */
export function retryAfterMs(headers: Record<string, string>, now: Date): number | undefined {
  const value = Object.entries(headers).find(([name]) => name.toLowerCase() === 'retry-after')?.[1]?.trim();
  if (!value) return undefined;
  if (/^\d{1,9}$/.test(value)) return Number(value) * 1000;
  const date = Date.parse(value);
  return Number.isFinite(date) ? Math.max(0, date - now.getTime()) : undefined;
}

/** Sends one request; transport failures become fixed text. Responses are returned for the caller to classify. */
export async function sendRequest(http: HttpClient, request: HttpRequest, receiver: string): Promise<HttpResponse> {
  try {
    return await http.request(request);
  } catch (error) {
    if (error instanceof EgressBlockedError) {
      throw new AuditExportError(`The request to the ${receiver} was blocked by keysentry's network allow-list.`, false);
    }
    throw new AuditExportError(`Could not reach the ${receiver}.`, true);
  }
}

/** Generic classification for receivers that follow ordinary HTTP semantics (webhooks, object storage). */
export function httpFailure(response: HttpResponse, receiver: string, now: Date, retryable: (status: number) => boolean): AuditExportError {
  const status = response.status;
  return new AuditExportError(`The ${receiver} answered HTTP ${status}.`, retryable(status),
    retryable(status) ? retryAfterMs(response.headers, now) : undefined);
}

/** Reads one optional export credential. The caller owns and clears the returned buffer. */
export async function readSecret(vault: Vault, id: string, field: ExportSecretField): Promise<Buffer | null> {
  try { return await vault.get(exportSecretName(id, field)); }
  catch { throw new AuditExportError('The vault could not be read for the export credentials.', false); }
}

/** Visible ASCII without spaces; credentials outside this range are refused rather than sent. */
export function credentialText(value: Buffer, max = 4096): string | null {
  const text = value.toString('utf8');
  return text.length >= 1 && text.length <= max && /^[\x21-\x7e]+$/.test(text) ? text : null;
}
