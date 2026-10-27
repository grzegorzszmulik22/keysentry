import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { ASSETS } from '../generated/assets.js';
import { apiRoute, bodyDigest, validateApi } from './api.js';
import type { DashboardApi } from './api.js';
import { createPasskeyGate, PasskeyGateError } from './passkey-gate.js';
import type { PasskeyStore } from './passkey-gate.js';
import { createSession, sameToken } from './session.js';
import { checkRequest, CSP, DashboardError, json, readJson, securityHeaders } from './security.js';

export interface DashboardOptions {
  api: DashboardApi;
  readOnly: boolean;
  /** Supply encrypted persistent storage when enrollment or changes are available. */
  passkeys?: PasskeyStore;
  idleMs?: number;
  open?: (url: string) => void;
  now?: () => number;
}

const START_PAGE = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>keysentry</title><body><p>Open keysentry from your terminal with keysentry ui.</p></body></html>';
const unavailablePasskeys: PasskeyStore = {
  list: async () => [],
  add: async () => { throw new DashboardError(409, 'Connect passkey storage before registering a passkey.'); },
  update: async () => { throw new DashboardError(409, 'Connect passkey storage before using a passkey.'); },
};

export async function startDashboard(opts: DashboardOptions): Promise<{ url: string; port: number; close(): Promise<void> }> {
  validateApi(opts.api);
  const idleMs = opts.idleMs ?? 15 * 60_000;
  if (!Number.isFinite(idleMs) || idleMs <= 0 || idleMs > 2_147_483_647) throw new Error('Choose a positive dashboard idle time.');
  const sessions = createSession({ idleMs, now: opts.now });
  const passkeys = opts.passkeys ?? unavailablePasskeys;
  let port = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let closed: Promise<void> | undefined;
  let gate: ReturnType<typeof createPasskeyGate>;
  const server = createServer({ maxHeaderSize: 16 * 1024, headersTimeout: 10_000, requestTimeout: 10_000 }, (req, res) => { void handle(req, res); });
  const close = (): Promise<void> => {
    if (closed) return closed;
    clearTimeout(timer);
    sessions.clear();
    closed = new Promise((resolve, reject) => {
      server.close(error => { if (error && (error as NodeJS.ErrnoException).code !== 'ERR_SERVER_NOT_RUNNING') reject(error); else resolve(); });
      server.closeAllConnections();
    });
    return closed;
  };
  const touch = () => {
    clearTimeout(timer);
    timer = setTimeout(() => { void close().catch(() => {}); }, idleMs);
    timer.unref();
  };

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    securityHeaders(res);
    try {
      checkRequest(req, port);
      const target = req.url ?? '';
      // Match raw paths: URL normalization must not turn traversal or encoded paths into assets/routes.
      if (!target.startsWith('/') || target.startsWith('//') || target.includes('#')) throw new DashboardError(404, 'This page is not available.');
      if (req.method !== 'GET' && req.method !== 'POST') throw new DashboardError(405, 'Use GET or POST for this request.');
      const session = sessions.authenticate(req.headers.cookie);
      if (req.method === 'GET' && target.startsWith('/?')) {
        const params = new URLSearchParams(target.slice(2));
        if (params.size !== 1 || params.getAll('t').length !== 1) throw new DashboardError(401, 'Open keysentry again from your terminal.');
        const granted = sessions.exchange(params.get('t') ?? '');
        if (!granted) throw new DashboardError(401, 'Open keysentry again from your terminal.');
        touch();
        res.setHeader('Set-Cookie', `ks_session=${granted.id}; HttpOnly; SameSite=Strict; Path=/`);
        res.writeHead(303, { Location: '/' }); res.end(); return;
      }
      if (req.method === 'GET' && target === '/' && !session) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(START_PAGE); return;
      }
      if (!session) throw new DashboardError(401, 'Open keysentry again from your terminal.');
      touch();
      if (req.method === 'GET' && (target === '/' || target.startsWith('/app/'))) {
        const asset = Object.hasOwn(ASSETS, target) ? ASSETS[target] : undefined;
        if (!asset) throw new DashboardError(404, 'This page is not available.');
        res.writeHead(200, { 'Content-Type': asset.type }); res.end(asset.body); return;
      }
      if (!target.startsWith('/api/') || target.includes('?')) throw new DashboardError(404, 'This page is not available.');
      const name = target.slice('/api/'.length);
      if (name === 'session') {
        if (req.method !== 'GET') throw new DashboardError(405, 'Use GET for this request.');
        json(res, 200, { csrf: session.csrf, readOnly: opts.readOnly, passkeys: (await passkeys.list()).length }); return;
      }
      if (req.method === 'POST') {
        const csrf = req.headers['x-csrf-token'];
        if (typeof csrf !== 'string' || !sameToken(csrf, session.csrf)) throw new DashboardError(403, 'Reload the dashboard before making this change.');
      }
      const builtIn = ['passkey/challenge', 'passkey/register/options', 'passkey/register/finish'].includes(name);
      const route = apiRoute(opts.api, name);
      if (!builtIn && !route) throw new DashboardError(404, 'This action is not available.');
      if (req.method !== (builtIn ? 'POST' : route!.method)) throw new DashboardError(405, 'Use the method provided for this action.');
      if (opts.readOnly && (builtIn || route!.mutating)) throw new DashboardError(403, 'This dashboard is read-only. Open keysentry from a human terminal to make changes.');
      const body = req.method === 'POST' ? await readJson(req) : undefined;
      const proof = req.headers['x-passkey-assertion'];
      if (Array.isArray(proof)) throw new DashboardError(403, 'Confirm this action with your passkey.');
      if (name === 'passkey/challenge') {
        const input = body as { route?: unknown; bodyDigest?: unknown } | null;
        if (!input || Array.isArray(input) || typeof input.route !== 'string' || typeof input.bodyDigest !== 'string' || !/^[0-9a-f]{64}$/.test(input.bodyDigest)) {
          throw new DashboardError(400, 'Choose an action and its JSON body digest.');
        }
        const action = apiRoute(opts.api, input.route);
        if (input.route !== 'passkey/register/options' && (!action || action.method !== 'POST' || !action.mutating)) throw new DashboardError(400, 'Choose an action that requires a passkey.');
        json(res, 200, await gate.challenge(session.id, input.route, input.bodyDigest)); return;
      }
      if (name === 'passkey/register/options') {
        if ((await passkeys.list()).length > 0) await gate.verify(session.id, name, bodyDigest(body), proof);
        json(res, 200, await gate.registrationOptions(session.id)); return;
      }
      if (name === 'passkey/register/finish') {
        await gate.registrationFinish(session.id, body);
        json(res, 200, { registered: true }); return;
      }
      if (route!.mutating) await gate.verify(session.id, name, bodyDigest(body), proof);
      const result = await route!.handler(body, { session: session.id });
      json(res, 200, result);
    } catch (error) {
      if (res.headersSent || res.destroyed) { res.destroy(); return; }
      if (error instanceof DashboardError || error instanceof PasskeyGateError) json(res, error.status, { error: error.message });
      else json(res, 400, { error: 'The request could not be completed. Try again from keysentry.' });
    }
  }

  // Node can otherwise send implicit responses without the dashboard's security headers.
  server.on('checkContinue', (req, res) => { securityHeaders(res); json(res, 417, { error: 'Send the request without an expectation header.' }); req.resume(); });
  server.on('checkExpectation', (req, res) => { securityHeaders(res); json(res, 417, { error: 'Send the request without an expectation header.' }); req.resume(); });
  server.on('connect', (_req, socket) => {
    socket.end(`HTTP/1.1 405 Method Not Allowed\r\nContent-Security-Policy: ${CSP}\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCache-Control: no-store\r\nX-Frame-Options: DENY\r\nPermissions-Policy: publickey-credentials-get=(self), publickey-credentials-create=(self)\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{"error":"Use GET or POST for this request."}`);
  });
  server.on('clientError', (_error, socket) => {
    if (socket.writable) socket.end(`HTTP/1.1 400 Bad Request\r\nContent-Security-Policy: ${CSP}\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCache-Control: no-store\r\nX-Frame-Options: DENY\r\nPermissions-Policy: publickey-credentials-get=(self), publickey-credentials-create=(self)\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{"error":"Send a valid HTTP request."}`);
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
  });
  const address = server.address();
  if (!address || typeof address === 'string') { await close(); throw new Error('The local dashboard could not start.'); }
  port = address.port;
  gate = createPasskeyGate({ passkeys, origin: `http://localhost:${port}`, now: opts.now });
  touch();
  const url = `http://localhost:${port}/?t=${sessions.token}`;
  try { opts.open?.(url); } catch { await close(); throw new Error('The browser could not open the local dashboard.'); }
  return { url, port, close };
}

