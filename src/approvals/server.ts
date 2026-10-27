import { createHash } from 'node:crypto';
import { createServer, STATUS_CODES, type IncomingMessage, type ServerResponse } from 'node:http';
import { isIP } from 'node:net';
import type { Duplex } from 'node:stream';
import { BUILD_VERSION } from '../release/build-info.js';
import { ApprovalError, type ApprovalService } from './service.js';
import { APPROVE_JS, approvalPage, approvedOutcome, disarmedPage, disarmPage } from './page.js';

type Service = Pick<ApprovalService, 'describe' | 'challenge' | 'approveWithPasskey' | 'recordDisarm'>;

export interface ApprovalServerOptions {
  service: Service;
  port: number;
  host?: string;
  publicOrigin: string;
  disarm: () => Promise<void>;
  rateLimitPerMinute?: number;
  disarmRateLimitPerMinute?: number;
  trustProxyHops?: 0 | 1;
  watcherCheckMinutes?: number;
  version?: string;
}

class HttpError extends Error {
  constructor(readonly status: number, message: string) { super(message); }
}

const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const JSON_LIMIT = 16 * 1024;
const FORM_LIMIT = 1024;
const ID = '[A-Za-z0-9_-]{1,128}';

function configuredOrigin(value: string): URL {
  try {
    const url = new URL(value);
    if (url.origin !== value || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error();
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && url.hostname === 'localhost')) throw new Error();
    return url;
  } catch { throw new TypeError('Approval publicOrigin must be an HTTPS origin or HTTP localhost origin.'); }
}

function contentType(req: IncomingMessage): string {
  if (req.headers['content-encoding'] && req.headers['content-encoding'].toLowerCase() !== 'identity') throw new HttpError(415, 'Unsupported media type.');
  return (req.headers['content-type'] ?? '').split(';', 1)[0]!.trim().toLowerCase();
}

function body(req: IncomingMessage, maxBytes: number): Promise<string> {
  const length = req.headers['content-length'];
  if (length && (!/^\d+$/.test(length) || Number(length) > maxBytes)) {
    req.resume();
    return Promise.reject(new HttpError(413, 'Request body is too large.'));
  }
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      chunks.length = 0;
      req.removeListener('data', data);
      req.resume();
      reject(error);
    };
    const data = (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) { fail(new HttpError(413, 'Request body is too large.')); return; }
      chunks.push(chunk);
    };
    req.on('data', data);
    req.once('aborted', () => fail(new HttpError(400, 'Invalid request.')));
    req.once('error', () => fail(new HttpError(400, 'Invalid request.')));
    req.once('end', () => {
      if (settled) return;
      settled = true;
      try { resolve(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); }
      catch { reject(new HttpError(400, 'Invalid request.')); }
    });
  });
}

async function jsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  if (contentType(req) !== 'application/json') throw new HttpError(415, 'Unsupported media type.');
  const input = await body(req, JSON_LIMIT);
  let parsed: unknown;
  try { parsed = JSON.parse(input); }
  catch { throw new HttpError(400, 'Invalid request.'); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new HttpError(400, 'Invalid request.');
  return parsed as Record<string, unknown>;
}

function decode(value: unknown, maxBytes: number): Buffer {
  if (typeof value !== 'string' || value.length === 0 || value.length > Math.ceil(maxBytes * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) throw new HttpError(400, 'Invalid assertion.');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length > maxBytes || bytes.toString('base64url') !== value) throw new HttpError(400, 'Invalid assertion.');
  return bytes;
}

function address(req: IncomingMessage, trustProxyHops: 0 | 1): string {
  if (trustProxyHops === 1) {
    const header = req.headers['x-forwarded-for'];
    if (typeof header === 'string' && header.length <= 4096) {
      const last = header.split(',').at(-1)!.trim();
      if (isIP(last)) return last;
    }
  }
  return req.socket.remoteAddress ?? 'unknown';
}

export function createApprovalServer(opts: ApprovalServerOptions): { listen(): Promise<{ port: number }>; close(): Promise<void> } {
  const origin = configuredOrigin(opts.publicOrigin);
  const publicOrigin = origin.origin;
  const service = opts.service;
  const disarm = opts.disarm;
  const version = opts.version ?? BUILD_VERSION;
  const budget = opts.rateLimitPerMinute ?? 30;
  const disarmBudget = opts.disarmRateLimitPerMinute ?? 10;
  const trustProxyHops = opts.trustProxyHops ?? 0;
  const watcherCheckMinutes = opts.watcherCheckMinutes ?? 10;
  if (!Number.isInteger(opts.port) || opts.port < 0 || opts.port > 65535
    || !Number.isSafeInteger(budget) || budget <= 0 || !Number.isSafeInteger(disarmBudget) || disarmBudget <= 0
    || !Number.isSafeInteger(watcherCheckMinutes) || watcherCheckMinutes <= 0
    || (trustProxyHops !== 0 && trustProxyHops !== 1)) throw new TypeError('Invalid approval server configuration.');
  const headers: Record<string, string> = {
    'Content-Security-Policy': CSP,
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
    'Permissions-Policy': 'publickey-credentials-get=(self)',
  };
  if (origin.protocol === 'https:') headers['Strict-Transport-Security'] = 'max-age=31536000';
  type Bucket = { tokens: number; at: number };
  // Each route group has its own capacity as well as its own token budget.
  const approvalBuckets = new Map<string, Bucket>();
  const disarmBuckets = new Map<string, Bucket>();
  function limit(req: IncomingMessage): { budget: number; buckets: Map<string, Bucket> } {
    return req.url === '/disarm' && (req.method === 'GET' || req.method === 'POST')
      ? { budget: disarmBudget, buckets: disarmBuckets } : { budget, buckets: approvalBuckets };
  }

  function take(req: IncomingMessage, client: string): boolean {
    const { budget, buckets } = limit(req);
    const now = Date.now();
    let bucket = buckets.get(client);
    if (!bucket) {
      for (const [key, entry] of buckets) if (now - entry.at >= 60_000) buckets.delete(key);
      // Bound memory without resetting an active client's budget under address churn.
      if (buckets.size >= 10_000) return false;
      bucket = { tokens: budget, at: now };
      buckets.set(client, bucket);
    }
    bucket.tokens = Math.min(budget, bucket.tokens + Math.max(0, now - bucket.at) * budget / 60_000);
    bucket.at = now;
    if (bucket.tokens < 1) return false;
    bucket.tokens--;
    return true;
  }

  function send(res: ServerResponse, status: number, text: string, type = 'text/plain; charset=utf-8'): void {
    res.writeHead(status, { ...headers, 'Content-Type': type });
    res.end(text);
  }
  const json = (res: ServerResponse, status: number, value: unknown) => send(res, status, JSON.stringify(value), 'application/json; charset=utf-8');
  const validHost = (req: IncomingMessage) => req.headers.host === origin.host && req.rawHeaders.filter((_, index) => index % 2 === 0 && req.rawHeaders[index]!.toLowerCase() === 'host').length === 1;

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      if (!validHost(req)) throw new HttpError(403, 'Request origin is not allowed.');
      const client = address(req, trustProxyHops);
      if (!take(req, client)) {
        res.setHeader('Retry-After', String(Math.ceil(60 / limit(req).budget)));
        throw new HttpError(429, 'Please wait before trying again.');
      }
      const path = req.url ?? '';
      const action = new RegExp(`^/a/(${ID})$`).exec(path);
      const challenge = new RegExp(`^/a/(${ID})/challenge$`).exec(path);
      const assertion = new RegExp(`^/a/(${ID})/assert$`).exec(path);
      const isGet = path === '/healthz' || path === '/static/approve.js' || path === '/disarm' || action !== null;
      const isPost = path === '/disarm' || challenge !== null || assertion !== null;
      if (!isGet && !isPost) { send(res, 404, 'Not found.\n'); return; }
      if (!((req.method === 'GET' && isGet) || (req.method === 'POST' && isPost))) {
        res.setHeader('Allow', path === '/disarm' ? 'GET, POST' : isGet ? 'GET' : 'POST');
        send(res, 405, 'Method not allowed.\n');
        return;
      }
      if (req.method === 'POST' && req.headers.origin !== publicOrigin) throw new HttpError(403, 'Request origin is not allowed.');
      if (req.method === 'GET') {
        if (path === '/healthz') { json(res, 200, { ok: true, version }); return; }
        if (path === '/static/approve.js') { send(res, 200, APPROVE_JS, 'text/javascript; charset=utf-8'); return; }
        if (path === '/disarm') { send(res, 200, disarmPage(), 'text/html; charset=utf-8'); return; }
        const details = await service.describe(action![1]!);
        if (!details) { send(res, 404, 'Not found.\n'); return; }
        send(res, 200, approvalPage(details, watcherCheckMinutes), 'text/html; charset=utf-8');
        return;
      }
      if (path === '/disarm') {
        if (contentType(req) !== 'application/x-www-form-urlencoded') throw new HttpError(415, 'Unsupported media type.');
        const fields = new URLSearchParams(await body(req, FORM_LIMIT));
        if (fields.getAll('confirm').length !== 1 || fields.get('confirm') !== 'DISARM' || [...fields.keys()].some((key) => key !== 'confirm')) throw new HttpError(400, 'Type DISARM to confirm.');
        await disarm();
        await service.recordDisarm(createHash('sha256').update(client).digest('hex'));
        send(res, 200, disarmedPage(), 'text/html; charset=utf-8');
        return;
      }
      const input = await jsonBody(req);
      if (typeof input.digest !== 'string' || !/^[a-f0-9]{64}$/.test(input.digest)) throw new HttpError(400, 'Invalid request.');
      if (challenge) {
        if (Object.keys(input).length !== 1) throw new HttpError(400, 'Invalid request.');
        json(res, 200, await service.challenge(challenge[1]!, input.digest));
        return;
      }
      const fields = ['digest', 'credentialId', 'clientDataJSON', 'authenticatorData', 'signature'];
      if (Object.keys(input).length !== fields.length || Object.keys(input).some((key) => !fields.includes(key))) throw new HttpError(400, 'Invalid assertion.');
      decode(input.credentialId, 1023);
      const approved = await service.approveWithPasskey(assertion![1]!, {
        credentialId: input.credentialId as string,
        clientDataJSON: decode(input.clientDataJSON, 8192),
        authenticatorData: decode(input.authenticatorData, JSON_LIMIT),
        signature: decode(input.signature, 1024),
      }, input.digest);
      json(res, 200, { ok: true, text: approvedOutcome(watcherCheckMinutes), actionId: approved.actionId });
    } catch (error) {
      if (res.headersSent) { res.end(); return; }
      if (error instanceof HttpError) { send(res, error.status, `${error.message}\n`); return; }
      if (error instanceof ApprovalError) { json(res, 403, { ok: false, text: error.message }); return; }
      send(res, 500, 'The request could not be completed.\n');
    }
  }

  const server = createServer({ headersTimeout: 10_000, requestTimeout: 10_000, connectionsCheckingInterval: 1000, maxHeaderSize: 16 * 1024 }, (req, res) => { void handle(req, res); });
  server.headersTimeout = 10_000;
  server.requestTimeout = 10_000;
  const expectation = (req: IncomingMessage, res: ServerResponse) => {
    req.resume();
    if (!validHost(req)) { send(res, 403, 'Request origin is not allowed.\n'); return; }
    if (!take(req, address(req, trustProxyHops))) { send(res, 429, 'Please wait before trying again.\n'); return; }
    send(res, 417, 'Expectation failed.\n');
  };
  server.on('checkContinue', expectation);
  server.on('checkExpectation', expectation);
  function sendSocket(socket: Duplex, status: number, text: string): void {
    if (!socket.writable) return;
    const responseHeaders = Object.entries({ ...headers, 'Content-Type': 'text/plain; charset=utf-8', 'Content-Length': String(Buffer.byteLength(text)), Connection: 'close' }).map(([key, value]) => `${key}: ${value}`).join('\r\n');
    socket.end(`HTTP/1.1 ${status} ${STATUS_CODES[status]}\r\n${responseHeaders}\r\n\r\n${text}`);
  }
  server.on('connect', (req, socket) => {
    if (!validHost(req)) { sendSocket(socket, 403, 'Request origin is not allowed.\n'); return; }
    if (!take(req, address(req, trustProxyHops))) { sendSocket(socket, 429, 'Please wait before trying again.\n'); return; }
    const known = /^(?:\/healthz|\/static\/approve\.js|\/disarm)$/.test(req.url ?? '') || new RegExp(`^/a/${ID}(?:/challenge|/assert)?$`).test(req.url ?? '');
    sendSocket(socket, known ? 405 : 404, known ? 'Method not allowed.\n' : 'Not found.\n');
  });
  server.on('clientError', (_error, socket) => {
    sendSocket(socket, 400, 'Invalid request.\n');
  });
  let listening: Promise<{ port: number }> | undefined;
  return {
    listen() {
      if (!listening) listening = new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(opts.port, opts.host ?? '127.0.0.1', () => {
          server.removeListener('error', reject);
          const bound = server.address();
          if (!bound || typeof bound === 'string') { reject(new Error('Approval server did not bind a TCP port.')); return; }
          resolve({ port: bound.port });
        });
      });
      return listening;
    },
    async close() {
      if (!listening) return;
      await listening.catch(() => undefined);
      if (!server.listening) return;
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    },
  };
}
