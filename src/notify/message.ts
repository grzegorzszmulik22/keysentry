import type { HttpClient, HttpResponse, NotifyChannelKind, Redactor, SignedNotifyMessage } from '../types.js';

export interface ChannelDeps { http: HttpClient; redactor: Redactor }

export const CHANNEL_LABELS: Record<NotifyChannelKind, string> = {
  telegram: 'Telegram', discord: 'Discord', slack: 'Slack', ntfy: 'ntfy', webhook: 'Webhook',
  resend: 'Resend', smtp: 'SMTP', console: 'Console',
};

/** Only fixed diagnostics cross the notification boundary; upstream errors are never retained. */
export class NotifyDeliveryError extends Error {
  constructor(readonly channel: NotifyChannelKind, readonly status?: number, readonly retryAfterMs?: number) {
    super(status === undefined ? `${CHANNEL_LABELS[channel]} delivery failed` : `${CHANNEL_LABELS[channel]} returned ${status}`);
    this.name = 'NotifyDeliveryError';
  }
}

/** Reject rather than alter signed content. Inspect values before JSON escaping can hide a registered secret. */
export function assertSafeText(text: string, redactor: Redactor): void {
  if (redactor.redact(text) !== text) throw new Error('Notification contains a secret');
}

function assertSafeValue(value: unknown, redactor: Redactor): void {
  const seen = new Set<object>();
  function check(value: unknown): void {
    if (typeof value === 'string') {
      assertSafeText(value, redactor);
    } else if (value && typeof value === 'object') {
      if (seen.has(value)) throw new Error('Invalid notification');
      seen.add(value);
      for (const [key, entry] of Object.entries(value)) { check(key); check(entry); }
      seen.delete(value);
    }
  }
  check(value);
}

export function assertSafeMessage(m: SignedNotifyMessage, redactor: Redactor): void {
  assertSafeValue(m, redactor);
}

export function header(response: HttpResponse, name: string): string | undefined {
  return Object.entries(response.headers).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1];
}

export function jsonReply(response: HttpResponse): Record<string, unknown> | null {
  if (Buffer.byteLength(response.text) > 16_384) return null;
  try {
    const value: unknown = JSON.parse(response.text);
    return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch { return null; }
}

export function retryDelay(response: HttpResponse): number | undefined {
  const raw = header(response, 'retry-after');
  if (raw !== undefined) {
    const seconds = /^\s*\d+(?:\.\d+)?\s*$/.test(raw) ? Number(raw) : undefined;
    const delay = seconds === undefined ? Date.parse(raw) - Date.now() : seconds * 1000;
    if (Number.isFinite(delay)) return Math.min(60_000, Math.max(0, delay));
  }
  if (response.status === 429) {
    const body = jsonReply(response);
    const parameters = body?.parameters;
    const retry = body?.retry_after ?? (parameters && typeof parameters === 'object' ? (parameters as Record<string, unknown>).retry_after : undefined)
      ?? header(response, 'x-ratelimit-reset-after');
    const seconds = typeof retry === 'string' && /^\d+(?:\.\d+)?$/.test(retry) ? Number(retry) : retry;
    if (typeof seconds === 'number' && Number.isFinite(seconds) && seconds >= 0) return Math.min(60_000, seconds * 1000);
  }
  return undefined;
}

export async function postJson(deps: ChannelDeps, kind: NotifyChannelKind, url: string, body: unknown,
  extraHeaders: Record<string, string> = {}): Promise<HttpResponse> {
  assertSafeValue(body, deps.redactor);
  let response: HttpResponse;
  try {
    response = await deps.http.request({ method: 'POST', url, headers: { 'Content-Type': 'application/json', ...extraHeaders }, body: JSON.stringify(body) });
  } catch { throw new NotifyDeliveryError(kind); }
  if (response.status < 200 || response.status >= 300) throw new NotifyDeliveryError(kind, response.status, retryDelay(response));
  return response;
}

export function assertHeader(value: string): void {
  if (/[\r\n\x00]/.test(value)) throw new Error('Invalid notification header');
}

/** Validation errors never echo user configuration, since webhook paths carry credentials. */
export function httpsUrl(raw: string): URL {
  try {
    const url = new URL(raw);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash || (url.port && url.port !== '443')) throw new Error();
    return url;
  } catch { throw new Error('Invalid notification URL'); }
}

export function escapeHtml(value: string): string {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}
