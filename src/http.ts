import type { HttpClient, HttpRequest, HttpResponse } from './types.js';
import { createRedactor } from './core/redact.js';

/** Production HTTP client over global fetch. Adapters never call fetch directly. */
export function createFetchHttp(opts: { timeoutMs?: number; maxBytes?: number } = {}): HttpClient {
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const maxBytes = opts.maxBytes ?? 16 * 1024 * 1024;
  return {
    async request(req: HttpRequest): Promise<HttpResponse> {
      const res = await fetch(req.url, {
        method: req.method,
        headers: req.headers,
        body: req.body,
        signal: AbortSignal.timeout(timeoutMs),
        redirect: 'manual',
      });
      let text = '';
      if (res.body) {
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let bytes = 0;
        try {
          while (true) {
            const chunk = await reader.read();
            if (chunk.done) break;
            bytes += chunk.value.byteLength;
            if (bytes > maxBytes) {
              // A cancellation failure must not replace the useful size error.
              try { await reader.cancel(); } catch { /* Keep the size error. */ }
              throw new ResponseTooLargeError(requestHost(req.url), maxBytes);
            }
            text += decoder.decode(chunk.value, { stream: true });
          }
          text += decoder.decode();
        } finally {
          reader.releaseLock();
        }
      }
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => {
        headers[k.toLowerCase()] = v;
      });
      return makeResponse(res.status, text, headers);
    },
  };
}

function requestHost(url: string): string {
  try { return new URL(url).hostname.toLowerCase().replace(/\.$/, ''); }
  catch { return '(unparseable)'; }
}

export class ResponseTooLargeError extends Error {
  readonly code = 'RESPONSE_TOO_LARGE';

  constructor(host: string, maxBytes: number) {
    super(`Response from ${createRedactor().redact(host)} exceeds the ${maxBytes} byte limit.`);
    this.name = 'ResponseTooLargeError';
  }
}

export function makeResponse(status: number, text: string, headers: Record<string, string> = {}): HttpResponse {
  return {
    status,
    headers,
    text,
    json<T = unknown>(): T {
      return JSON.parse(text) as T;
    },
  };
}

export class HttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly url: string,
    /** Response body, already truncated; callers must not put secrets in URLs. */
    public readonly body: string,
  ) {
    super(`HTTP ${status} from ${url.split('?')[0]}: ${body.slice(0, 300)}`);
    this.name = 'HttpError';
  }
}

/** Throws HttpError unless 2xx; returns the response otherwise. */
export function ensureOk(res: HttpResponse, url: string): HttpResponse {
  if (res.status < 200 || res.status >= 300) throw new HttpError(res.status, url, res.text.slice(0, 1000));
  return res;
}
