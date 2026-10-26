import type { HttpClient, HttpRequest, HttpResponse } from './types.js';

/** Production HTTP client over global fetch. Adapters never call fetch directly. */
export function createFetchHttp(opts: { timeoutMs?: number } = {}): HttpClient {
  const timeoutMs = opts.timeoutMs ?? 30_000;
  return {
    async request(req: HttpRequest): Promise<HttpResponse> {
      const res = await fetch(req.url, {
        method: req.method,
        headers: req.headers,
        body: req.body,
        signal: AbortSignal.timeout(timeoutMs),
      });
      const text = await res.text();
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => {
        headers[k.toLowerCase()] = v;
      });
      return makeResponse(res.status, text, headers);
    },
  };
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
