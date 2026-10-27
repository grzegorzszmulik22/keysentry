import { randomBytes, timingSafeEqual } from 'node:crypto';
import { execFile as nodeExecFile, type ExecFileOptions } from 'node:child_process';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { join, win32 } from 'node:path';
import { z } from 'zod';
import type { StateStore } from '../core/store.js';
import type { AuditLog, PasskeyCredential } from '../types.js';
import { verifyRegistration } from '../approvals/index.js';
import { CliError } from './errors.js';

const CSP = "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const FIVE_MINUTES = 5 * 60_000;
const BODY_LIMIT = 128 * 1024;
const credentialsSchema = z.object({ v: z.literal(1), credentials: z.array(z.object({
  id: z.string().regex(/^[A-Za-z0-9_-]+$/), publicKeyCose: z.string().regex(/^[A-Za-z0-9_-]+$/),
  alg: z.union([z.literal(-7), z.literal(-8), z.literal(-257)]), signCount: z.number().int().min(0).max(0xffffffff),
  backupEligible: z.boolean(), rpId: z.string().min(1), origins: z.array(z.string().url()).min(1),
  label: z.string().max(80), createdAt: z.string().datetime(),
}).strict()).max(100) }).strict();

export interface LocalOnlyOptions { relay?: boolean; remote?: boolean }
export interface PasskeyRegistrationReady { url: string; port: number }
export type PasskeyRegistrationResult = { status: 'registered'; credential: PasskeyCredential } | { status: 'expired' | 'cancelled' };
export interface PasskeyRegistrationServerOptions {
  existing: () => Promise<PasskeyCredential[]>;
  save: (credential: PasskeyCredential) => Promise<void>;
  label?: string;
  timeoutMs?: number;
  now?: () => Date;
}

export interface PasskeyBrowserOptions {
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  execFile?: (file: string, args: string[], options: ExecFileOptions, callback: (error: Error | null) => void) => unknown;
}

/** Only the locally generated registration URL may reach an OS browser opener. */
export async function openPasskeyBrowser(value: string, options: PasskeyBrowserOptions = {}): Promise<boolean> {
  let url: URL;
  try { url = new URL(value); } catch { return false; }
  const port = Number(url.port);
  if (url.protocol !== 'http:' || url.hostname !== 'localhost' || !Number.isInteger(port) || port < 1024 || port > 65535 ||
      url.username || url.password || url.pathname !== '/register' || url.hash || url.searchParams.size !== 1 ||
      !/^[A-Za-z0-9_-]{43}$/.test(url.searchParams.get('token') ?? '') || url.href !== value) return false;
  const platform = options.platform ?? process.platform;
  const source = options.env ?? process.env;
  const env: NodeJS.ProcessEnv = {};
  let file: string; let args: string[];
  if (platform === 'win32') {
    // Do not search a caller-controlled PATH or pass platform secret variables along.
    const root = source.SystemRoot ?? source.SYSTEMROOT ?? 'C:\\Windows';
    if (!/^[A-Za-z]:\\[^\u0000-\u001f\u007f]*$/.test(root)) return false;
    file = win32.join(root, 'System32', 'rundll32.exe');
    env.SystemRoot = root; env.WINDIR = root;
    env.PATH = win32.join(root, 'System32');
    args = ['url.dll,FileProtocolHandler', value];
  } else if (platform === 'darwin' || platform === 'linux') {
    file = platform === 'darwin' ? '/usr/bin/open' : '/usr/bin/xdg-open';
    args = [value]; env.PATH = '/usr/bin:/bin';
    // These desktop-session locations let xdg-open reach the existing browser.
    // Credential variables, BROWSER commands and arbitrary PATH entries are omitted.
    const names = platform === 'linux' ? ['HOME', 'DISPLAY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR', 'XDG_CURRENT_DESKTOP', 'DESKTOP_SESSION', 'DBUS_SESSION_BUS_ADDRESS'] : ['HOME'];
    for (const name of names) {
      const field = source[name];
      if (field && field.length <= 4096 && !/[\u0000-\u001f\u007f]/.test(field)) env[name] = field;
    }
  } else return false;
  return new Promise<boolean>(resolve => {
    try {
      const execute = options.execFile ?? ((command, arguments_, settings, callback) => nodeExecFile(command, arguments_, settings, error => callback(error)));
      // Output is captured by execFile, discarded by this callback and never logged.
      execute(file, args, { env, shell: false, windowsHide: true, timeout: 5000, maxBuffer: 1024 }, error => resolve(error === null));
    } catch { resolve(false); }
  });
}

function localOnly(options: LocalOnlyOptions): void {
  if (options.relay || options.remote) throw new CliError('Passkey changes require the local CLI on your own computer.');
}
function label(value: string | undefined): string {
  if (value !== undefined && (typeof value !== 'string' || value.length > 80 || /[\u0000-\u001f\u007f]/.test(value))) throw new CliError('Use a passkey label of at most 80 characters without control characters.');
  return value || 'Local passkey';
}
function same(a: string | undefined, b: string): boolean {
  if (typeof a !== 'string') return false;
  const left = Buffer.from(a); const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
function decode(value: unknown, maxBytes: number): Buffer {
  if (typeof value !== 'string' || !value.length || value.length > Math.ceil(maxBytes * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) throw new CliError('The passkey response could not be verified.');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length > maxBytes || bytes.toString('base64url') !== value) throw new CliError('The passkey response could not be verified.');
  return bytes;
}
async function jsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []; let length = 0;
  for await (const chunk of req) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
    length += bytes.length;
    if (length > BODY_LIMIT) throw new RangeError('Request too large.');
    chunks.push(bytes);
  }
  let value: unknown;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); }
  catch { throw new CliError('Invalid registration request.'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new CliError('Invalid registration request.');
  return value as Record<string, unknown>;
}

const SCRIPT = `'use strict';
history.replaceState(null, '', '/register');
const status = document.querySelector('[role="status"]');
const button = document.querySelector('button');
const csrf = document.querySelector('meta[name="csrf"]').content;
function decode(value) { return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)); }
function encode(value) { let out = ''; for (const byte of new Uint8Array(value)) out += String.fromCharCode(byte); return btoa(out).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, ''); }
async function post(path, body) {
  const response = await fetch(path, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Keysentry-CSRF': csrf }, body: JSON.stringify(body) });
  const result = await response.json(); if (!response.ok) throw new Error('Registration could not be completed. Return to keysentry to try again.'); return result;
}
button.addEventListener('click', async () => {
  button.disabled = true; status.textContent = 'Follow your browser’s passkey prompt.';
  try {
    const options = await post('/options', {});
    options.challenge = decode(options.challenge); options.user.id = decode(options.user.id);
    options.excludeCredentials = options.excludeCredentials.map(c => ({ ...c, id: decode(c.id) }));
    const credential = await navigator.credentials.create({ publicKey: options });
    if (!credential) throw new Error('Registration was cancelled.');
    await post('/register', { clientDataJSON: encode(credential.response.clientDataJSON), attestationObject: encode(credential.response.attestationObject) });
    status.textContent = 'Passkey registered. You can close this page.';
  } catch { status.textContent = 'Registration could not be completed. You can try again, or return to keysentry.'; button.disabled = false; }
});
`;

/** The URL token creates one browser session; only that session can register one credential. */
export function createPasskeyRegistrationServer(options: PasskeyRegistrationServerOptions): {
  listen(): Promise<PasskeyRegistrationReady>;
  close(): Promise<void>;
  done: Promise<PasskeyRegistrationResult>;
} {
  const timeoutMs = options.timeoutMs ?? FIVE_MINUTES;
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > FIVE_MINUTES) throw new CliError('Passkey registration may stay open for at most five minutes.');
  const credentialLabel = label(options.label);
  const token = randomBytes(32).toString('base64url');
  const session = randomBytes(32).toString('base64url');
  const csrf = randomBytes(32).toString('base64url');
  const challenge = randomBytes(32);
  const userId = randomBytes(32).toString('base64url');
  let origin = ''; let host = ''; let started = false; let used = false; let busy = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let completed = false; let closing: Promise<void> | undefined;
  let resolveDone!: (result: PasskeyRegistrationResult) => void;
  const done = new Promise<PasskeyRegistrationResult>(resolve => { resolveDone = resolve; });
  const shutdown = (result: PasskeyRegistrationResult) => {
    if (closing) return closing;
    completed = true;
    if (timer) clearTimeout(timer);
    process.removeListener('SIGINT', interrupted);
    closing = new Promise<void>(resolve => {
      if (!server.listening) { resolveDone(result); resolve(); return; }
      server.close(() => { resolveDone(result); resolve(); });
      server.closeIdleConnections();
      if (result.status !== 'registered') server.closeAllConnections();
    });
    return closing;
  };
  const interrupted = () => { void shutdown({ status: 'cancelled' }); };
  const headers = { 'Content-Security-Policy': CSP, 'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store', 'Permissions-Policy': 'publickey-credentials-create=(self)' };
  const reply = (res: ServerResponse, status: number, body: unknown, type = 'application/json; charset=utf-8') => {
    res.writeHead(status, { ...headers, 'Content-Type': type, Connection: 'close' });
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  };
  const server = createServer({ maxHeaderSize: 8192, requestTimeout: 15_000, headersTimeout: 10_000 }, (req, res) => {
    void (async () => {
      if (req.headers.host !== host || completed) return reply(res, 403, { message: 'This registration page is unavailable.' });
      if (typeof req.url !== 'string' || req.url.length > 2048 || !req.url.startsWith('/') || req.url.startsWith('//')) return reply(res, 404, { message: 'Page not found.' });
      const url = new URL(req.url, origin);
      if (req.method === 'GET' && url.pathname === '/register.js' && !url.search) return reply(res, 200, SCRIPT, 'text/javascript; charset=utf-8');
      if (req.method === 'GET' && url.pathname === '/register') {
        if (used || url.searchParams.size !== 1 || !same(url.searchParams.get('token') ?? undefined, token)) return reply(res, 403, { message: 'This registration link has already been used or is not valid.' });
        used = true;
        res.setHeader('Set-Cookie', `keysentry_registration=${session}; Path=/; HttpOnly; SameSite=Strict; Max-Age=300`);
        return reply(res, 200, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="csrf" content="${csrf}"><title>Register a passkey · keysentry</title><script src="/register.js" defer></script></head><body><main><h1>Register a passkey</h1><p>This passkey can approve actions proposed by keysentry on localhost. Policy changes require the local CLI.</p><button type="button">Register passkey</button><p role="status" aria-live="polite">Choose your device or security key in the next prompt.</p></main></body></html>`, 'text/html; charset=utf-8');
      }
      if (!['/options', '/register'].includes(url.pathname) || url.search) return reply(res, 404, { message: 'Page not found.' });
      if (req.method !== 'POST') return reply(res, 405, { message: 'Use POST for this request.' });
      if (req.headers.origin !== origin || !used || !same(req.headers.cookie, `keysentry_registration=${session}`) || !same(typeof req.headers['x-keysentry-csrf'] === 'string' ? req.headers['x-keysentry-csrf'] : undefined, csrf)) return reply(res, 403, { message: 'The registration session could not be verified.' });
      if (req.headers['content-type']?.split(';')[0]?.trim().toLowerCase() !== 'application/json') return reply(res, 415, { message: 'Use a JSON registration request.' });
      const declared = Number(req.headers['content-length']);
      if (Number.isFinite(declared) && declared > BODY_LIMIT) { req.resume(); return reply(res, 413, { message: 'The registration request is too large.' }); }
      if (busy) return reply(res, 409, { message: 'A registration request is already being checked.' });
      busy = true;
      try {
        const body = await jsonBody(req);
        const existing = await options.existing();
        if (completed) return;
        if (url.pathname === '/options') {
          if (Object.keys(body).length) return reply(res, 400, { message: 'Invalid registration request.' });
          return reply(res, 200, { rp: { id: 'localhost', name: 'keysentry' }, user: { id: userId, name: 'keysentry-local', displayName: 'Local keysentry approver' },
            challenge: challenge.toString('base64url'), pubKeyCredParams: [-8, -7, -257].map(alg => ({ type: 'public-key', alg })),
            timeout: Math.min(timeoutMs, FIVE_MINUTES), attestation: 'none', authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
            excludeCredentials: existing.map(c => ({ type: 'public-key', id: c.id })) });
        }
        if (Object.keys(body).length !== 2 || !Object.hasOwn(body, 'clientDataJSON') || !Object.hasOwn(body, 'attestationObject')) return reply(res, 400, { message: 'Invalid registration response.' });
        const credential = verifyRegistration({ clientDataJSON: decode(body.clientDataJSON, 8192), attestationObject: decode(body.attestationObject, 65536),
          expectedChallenge: challenge, expectedOrigins: [origin], rpId: 'localhost', requireUserVerification: true });
        if (existing.some(c => c.id === credential.id)) return reply(res, 409, { message: 'This passkey is already registered.' });
        credential.label = credentialLabel;
        credential.createdAt = (options.now?.() ?? new Date()).toISOString();
        await options.save(credential);
        reply(res, 200, { registered: true });
        setImmediate(() => { void shutdown({ status: 'registered', credential }); });
      } catch (error) {
        reply(res, error instanceof RangeError ? 413 : 400, { message: 'The passkey response could not be verified. Return to keysentry to try again.' });
      } finally { busy = false; }
    })().catch(() => { if (!res.headersSent) reply(res, 400, { message: 'This registration request could not be completed.' }); else res.end(); });
  });
  server.on('checkContinue', (_req, res) => { reply(res, 417, { message: 'Request expectations are not supported.' }); });
  server.on('checkExpectation', (_req, res) => { reply(res, 417, { message: 'Request expectations are not supported.' }); });
  server.on('connect', (_req, socket) => { socket.end('HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); });
  server.on('clientError', (_error, socket) => { socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); });
  return {
    async listen() {
      if (started || completed) throw new CliError('This registration server has already been started.');
      started = true;
      await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => { server.removeListener('error', reject); resolve(); }); });
      const address = server.address();
      if (!address || typeof address === 'string') throw new CliError('The local registration server could not start.');
      host = `localhost:${address.port}`; origin = `http://${host}`;
      timer = setTimeout(() => { void shutdown({ status: 'expired' }); }, timeoutMs);
      process.once('SIGINT', interrupted);
      return { port: address.port, url: `${origin}/register?token=${token}` };
    },
    close: () => shutdown({ status: 'cancelled' }), done,
  };
}

export async function listPasskeys(store: StateStore): Promise<PasskeyCredential[]> {
  const raw = await store.readJson('pending', join(store.paths.dir, 'passkeys.json'));
  if (raw === null) return [];
  const parsed = credentialsSchema.safeParse(raw);
  if (!parsed.success || new Set(parsed.data.credentials.map(c => c.id)).size !== parsed.data.credentials.length) throw new CliError('Saved passkeys could not be read.');
  return parsed.data.credentials;
}

export function createPasskeyManager(options: { store: StateStore; audit: Pick<AuditLog, 'append'>; assertHuman: (action: string) => void; now?: () => Date }) {
  const path = join(options.store.paths.dir, 'passkeys.json');
  return {
    async list() { return (await listPasskeys(options.store)).map(({ id, label, rpId, createdAt }) => ({ id, label, rpId, createdAt })); },
    async remove(id: string, forms: LocalOnlyOptions = {}) {
      options.assertHuman('remove a passkey'); localOnly(forms);
      const credentials = await listPasskeys(options.store);
      const remaining = credentials.filter(c => c.id !== id);
      const removed = remaining.length !== credentials.length;
      if (removed) {
        await options.store.writeJson('pending', path, { v: 1, credentials: remaining });
        await options.audit.append({ kind: 'passkey-remove', summary: 'Passkey removed.' });
      }
      return { id, removed };
    },
    async register(input: LocalOnlyOptions & { origin?: string; label?: string; open?: (url: string) => Promise<void>; onReady?: (ready: PasskeyRegistrationReady) => Promise<void> | void; timeoutMs?: number } = {}): Promise<PasskeyRegistrationResult | { status: 'public-origin'; message: string }> {
      options.assertHuman('register a passkey'); localOnly(input);
      if (input.origin !== undefined) {
        let url: URL;
        try { url = new URL(input.origin); } catch { throw new CliError('Use the watcher’s HTTPS origin for public registration.'); }
        if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new CliError('Use the watcher’s HTTPS origin without a path, credentials, query or fragment.');
        return { status: 'public-origin', message: `A passkey for ${url.origin} must be registered on that origin. Public registration is a phase 3 dashboard feature; this watcher does not serve a registration page.` };
      }
      const server = createPasskeyRegistrationServer({ label: input.label, timeoutMs: input.timeoutMs, now: options.now,
        existing: () => listPasskeys(options.store), save: async credential => {
          options.assertHuman('register a passkey');
          const credentials = await listPasskeys(options.store);
          if (credentials.length >= 100 || credentials.some(c => c.id === credential.id)) throw new CliError('This passkey cannot be added.');
          await options.store.writeJson('pending', path, { v: 1, credentials: [...credentials, credential] });
          await options.audit.append({ kind: 'passkey-register', summary: 'Passkey registered.' });
        } });
      try {
        const ready = await server.listen();
        await input.onReady?.(ready);
        if (input.open) await input.open(ready.url);
        return await server.done;
      } finally { await server.close(); }
    },
  };
}
