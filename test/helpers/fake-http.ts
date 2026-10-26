import { makeResponse } from '../../src/http.js';
import type { HttpClient, HttpRequest, HttpResponse } from '../../src/types.js';

export type Handler = (req: HttpRequest, match: RegExpMatchArray) => HttpResponse | Promise<HttpResponse>;

interface Route {
  method: string;
  pattern: RegExp;
  handler: Handler;
}

/**
 * In-memory HTTP fake for adapter tests. Register routes by method + URL regex; every request is recorded.
 * Unmatched requests return 599 so tests fail loudly.
 */
export class FakeHttp implements HttpClient {
  readonly calls: HttpRequest[] = [];
  private routes: Route[] = [];

  on(method: HttpRequest['method'], pattern: RegExp, handler: Handler): this {
    this.routes.push({ method, pattern, handler });
    return this;
  }

  async request(req: HttpRequest): Promise<HttpResponse> {
    this.calls.push(req);
    for (const r of this.routes) {
      if (r.method !== req.method) continue;
      const m = req.url.match(r.pattern);
      if (m) return r.handler(req, m);
    }
    return makeResponse(599, JSON.stringify({ error: `FakeHttp: no route for ${req.method} ${req.url}` }));
  }

  callsTo(method: string, pattern: RegExp): HttpRequest[] {
    return this.calls.filter((c) => c.method === method && pattern.test(c.url));
  }
}

export const json = (status: number, body: unknown, headers: Record<string, string> = {}): HttpResponse =>
  makeResponse(status, JSON.stringify(body), { 'content-type': 'application/json', ...headers });

export const text = (status: number, body: string, headers: Record<string, string> = {}): HttpResponse =>
  makeResponse(status, body, headers);

export const silentLogger = {
  info() {},
  warn() {},
  error() {},
  debug() {},
};
