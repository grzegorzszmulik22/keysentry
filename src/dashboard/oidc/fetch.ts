import type { HttpClient, HttpRequest } from '../../types.js';
import { fail } from './errors.js';

export function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function header(headers: Record<string, string>, name: string): string {
  return Object.entries(headers).find(([key]) => key.toLowerCase() === name)?.[1] ?? '';
}

/**
 * Send one request through the injected (egress-guarded) client and parse a JSON object. Any transport failure,
 * non-200 status, oversized or non-object body becomes a fixed refusal; the upstream body is never surfaced.
 */
export async function requestJson(http: HttpClient, req: HttpRequest, maxChars: number, statusFailure: 'unavailable' | 'token-response' = 'unavailable'): Promise<{ body: Record<string, unknown>; headers: Record<string, string> }> {
  let response;
  try { response = await http.request(req); } catch { return fail('unavailable'); }
  if (response.status !== 200) return fail(statusFailure);
  if (typeof response.text !== 'string' || response.text.length > maxChars) return fail(statusFailure);
  let body: unknown;
  try { body = JSON.parse(response.text); } catch { return fail(statusFailure); }
  if (!record(body)) return fail(statusFailure);
  return { body, headers: response.headers ?? {} };
}
