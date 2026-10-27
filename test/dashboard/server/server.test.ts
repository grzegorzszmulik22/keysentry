import { request as httpRequest } from 'node:http';
import { createHash } from 'node:crypto';
import { connect } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { startDashboard, type DashboardApi } from '../../../src/dashboard/server/index.js';
import { canonicalJson } from '../../../src/security/index.js';
import { createFakeAuthenticator } from '../helpers/fake-authenticator.js';
import type { PasskeyCredential } from '../../../src/types.js';
import { DashboardError } from '../../../src/dashboard/server/security.js';
import { VaultLockedError, VaultUnavailableError } from '../../../src/vault/errors.js';

interface Reply { status: number; headers: import('node:http').IncomingHttpHeaders; text: string; json: any }
const running: Awaited<ReturnType<typeof startDashboard>>[] = [];
async function start(extra: Partial<Parameters<typeof startDashboard>[0]> = {}) {
  const keys: PasskeyCredential[] = [];
  const handlers = { read: vi.fn(async () => ({ count: 2 })), write: vi.fn(async () => ({ done: true })) };
  const api: DashboardApi = {
    keys: { method: 'GET', mutating: false, handler: handlers.read },
    rotate: { method: 'POST', mutating: true, handler: handlers.write },
    disarm: { method: 'POST', mutating: false, handler: handlers.write },
    broken: { method: 'GET', mutating: false, handler: async () => { throw new Error('planted-private-value'); } },
  };
  const dashboard = await startDashboard({ api, readOnly: false, passkeys: {
    list: async () => structuredClone(keys),
    add: async c => { keys.push(structuredClone(c)); },
    update: async c => { keys[keys.findIndex(k => k.id === c.id)] = structuredClone(c); },
  }, ...extra });
  running.push(dashboard);
  return { ...dashboard, keys, handlers };
}
function req(port: number, path: string, opts: { method?: string; headers?: Record<string, string>; body?: string } = {}): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const request = httpRequest({ hostname: '127.0.0.1', port, path, method: opts.method ?? 'GET', headers: { Host: `localhost:${port}`, ...opts.headers } }, res => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { text += chunk; });
      res.on('end', () => { let json: any; try { json = JSON.parse(text); } catch { /* HTML */ } resolve({ status: res.statusCode!, headers: res.headers, text, json }); });
    });
    request.on('error', reject);
    request.end(opts.body);
  });
}
async function login(d: { port: number; url: string }) {
  const response = await req(d.port, new URL(d.url).search ? `/${new URL(d.url).search}` : '/');
  const cookie = response.headers['set-cookie']![0]!.split(';')[0]!;
  const session = await req(d.port, '/api/session', { headers: { Cookie: cookie } });
  return { cookie, csrf: session.json.csrf as string };
}
function post(port: number, path: string, auth: { cookie: string; csrf: string }, body: unknown = {}, headers: Record<string,string> = {}) {
  return req(port, path, { method: 'POST', headers: { Cookie: auth.cookie, Origin: `http://localhost:${port}`, 'X-CSRF-Token': auth.csrf, 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
}
afterEach(async () => { await Promise.all(running.splice(0).map(d => d.close())); });

describe('dashboard HTTP boundary', () => {
  it('binds loopback, exchanges token once, redirects, and serves only authenticated assets', async () => {
    const d = await start();
    expect(d.url).toMatch(new RegExp(`^http://localhost:${d.port}/\\?t=[A-Za-z0-9_-]{43}$`));
    const entry = await req(d.port, '/');
    expect(entry.text).toContain('Open keysentry from your terminal with keysentry ui.');
    expect((await req(d.port, '/app/main.js')).status).toBe(401);
    const exchange = await req(d.port, `/${new URL(d.url).search}`);
    expect(exchange.status).toBe(303);
    expect(exchange.headers.location).toBe('/');
    expect(exchange.headers['set-cookie']![0]).toMatch(new RegExp(`^ks_session_${d.port}=.+; HttpOnly; SameSite=Strict; Path=/$`));
    expect(exchange.headers['set-cookie']![0]).not.toContain('Secure');
    expect((await req(d.port, `/${new URL(d.url).search}`)).status).toBe(401);
    const cookie = exchange.headers['set-cookie']![0]!.split(';')[0]!;
    const page = await req(d.port, '/', { headers: { Cookie: cookie } });
    expect(page.text).toContain('/app/styles.css');
    expect(page.text).toContain('/app/main.js');
    expect(page.text).not.toMatch(/<script(?![^>]*\bsrc=)|<style|\sstyle=/i);
    expect((await req(d.port, '/app/main.js', { headers: { Cookie: cookie } })).status).toBe(200);
    expect((await req(d.port, '/app/../../package.json', { headers: { Cookie: cookie } })).status).toBe(404);
    expect((await req(d.port, '/api/keys', { headers: { Cookie: cookie } })).json).toEqual({ count: 2 });
  });

  it('reports the one-time token use once, so the launcher file can be deleted at once', async () => {
    const used = vi.fn();
    const d = await start({ onTokenUsed: used });
    expect(used).not.toHaveBeenCalled();
    expect((await req(d.port, `/${new URL(d.url).search}`)).status).toBe(303);
    expect(used).toHaveBeenCalledTimes(1);
    expect((await req(d.port, `/${new URL(d.url).search}`)).status).toBe(401);
    expect(used).toHaveBeenCalledTimes(1);
  });

  it('keeps dashboards on different ports authenticated in one browser cookie jar', async () => {
    const first = await start();
    const second = await start();
    const firstAuth = await login(first);
    const secondAuth = await login(second);
    expect(firstAuth.cookie).toMatch(new RegExp(`^ks_session_${first.port}=`));
    expect(secondAuth.cookie).toMatch(new RegExp(`^ks_session_${second.port}=`));
    const cookie = `${firstAuth.cookie}; ${secondAuth.cookie}`;
    expect((await req(first.port, '/api/session', { headers: { Cookie: cookie } })).status).toBe(200);
    expect((await req(second.port, '/api/session', { headers: { Cookie: cookie } })).status).toBe(200);
    expect((await req(first.port, '/api/session', { headers: { Cookie: secondAuth.cookie } })).status).toBe(401);
    expect((await req(second.port, '/api/session', { headers: { Cookie: firstAuth.cookie } })).status).toBe(401);
  });

  it('refuses rebinding Host, foreign Origin and missing CSRF without calling handlers', async () => {
    const d = await start(); const auth = await login(d);
    for (const Host of [`evil.test:${d.port}`, `localhost:${d.port}.evil.test`, 'localhost', `LOCALHOST:${d.port}`]) {
      expect((await req(d.port, '/api/session', { headers: { Host, Cookie: auth.cookie } })).status).toBe(403);
    }
    expect((await req(d.port, '/api/session', { headers: { Host: `127.0.0.1:${d.port}`, Cookie: auth.cookie } })).status).toBe(200);
    expect((await post(d.port, '/api/disarm', auth, {}, { Origin: 'https://elsewhere.test' })).status).toBe(403);
    expect((await post(d.port, '/api/disarm', auth, {}, { 'X-CSRF-Token': '' })).status).toBe(403);
    expect((await req(d.port, '/api/disarm', { method: 'POST', headers: { Cookie: auth.cookie, 'X-CSRF-Token': auth.csrf }, body: '{}' })).status).toBe(403);
    expect(d.handlers.write).not.toHaveBeenCalled();
  });

  it('requires an exact fresh passkey proof, consumes it once and persists the counter', async () => {
    const d = await start(); const auth = await login(d); const key = createFakeAuthenticator();
    d.keys.push(key.credential());
    const body = { b: 2, a: 1 };
    const bodyDigest = createHash('sha256').update(canonicalJson(body)).digest('hex');
    expect((await post(d.port, '/api/rotate', auth, body)).status).toBe(403);
    const challenge = await post(d.port, '/api/passkey/challenge', auth, { route: 'rotate', bodyDigest });
    expect(challenge.status).toBe(200);
    const header = key.assertionHeader(challenge.json.challenge, `http://localhost:${d.port}`);
    expect((await post(d.port, '/api/rotate', auth, body, { 'X-Passkey-Assertion': header })).status).toBe(200);
    expect(d.keys[0]!.signCount).toBe(1);
    expect((await post(d.port, '/api/rotate', auth, body, { 'X-Passkey-Assertion': header })).status).toBe(403);
    expect(d.handlers.write).toHaveBeenCalledTimes(1);
    const challenge2 = await post(d.port, '/api/passkey/challenge', auth, { route: 'rotate', bodyDigest });
    const header2 = key.assertionHeader(challenge2.json.challenge, `http://localhost:${d.port}`);
    expect((await post(d.port, '/api/rotate', auth, { a: 3 }, { 'X-Passkey-Assertion': header2 })).status).toBe(403);
    expect((await post(d.port, '/api/passkey/challenge', auth, { route: 'keys', bodyDigest })).status).toBe(400);
    expect((await post(d.port, '/api/passkey/challenge', auth, { route: 'constructor', bodyDigest })).status).toBe(400);
  });

  it('offers no browser registration route and requires terminal registration before changes', async () => {
    const d = await start(); const auth = await login(d); const key = createFakeAuthenticator();
    for (const path of ['options', 'finish']) {
      expect((await post(d.port, `/api/passkey/register/${path}`, auth)).status).toBe(404);
    }
    const expected = { error: 'Register a passkey with keysentry passkey register in your terminal, then reload this page.' };
    const mutation = await post(d.port, '/api/rotate', auth);
    expect(mutation.status).toBe(403); expect(mutation.json).toEqual(expected);
    const challenge = await post(d.port, '/api/passkey/challenge', auth, { route: 'rotate', bodyDigest: 'a'.repeat(64) });
    expect(challenge.status).toBe(403); expect(challenge.json).toEqual(expected);
    expect(d.handlers.write).not.toHaveBeenCalled();
    d.keys.push(key.credential());
    expect((await req(d.port, '/api/session', { headers: { Cookie: auth.cookie } })).json.passkeys).toBe(1);
    expect((await post(d.port, '/api/passkey/challenge', auth, { route: 'passkey/register/options', bodyDigest: 'a'.repeat(64) })).status).toBe(400);
    for (const path of ['options', 'finish']) expect((await post(d.port, `/api/passkey/register/${path}`, auth)).status).toBe(404);
  });

  it('refuses mutations and enrollment in read-only mode', async () => {
    const d = await start({ readOnly: true }); const auth = await login(d);
    expect((await req(d.port, '/api/session', { headers: { Cookie: auth.cookie } })).json.readOnly).toBe(true);
    for (const path of ['rotate', 'passkey/challenge']) {
      const response = await post(d.port, `/api/${path}`, auth);
      expect(response.status).toBe(403);
      expect(response.json).toEqual({ error: 'Register a passkey with keysentry passkey register in your terminal, then reload this page.' });
    }
    d.keys.push(createFakeAuthenticator().credential());
    for (const path of ['rotate', 'passkey/challenge']) {
      const response = await post(d.port, `/api/${path}`, auth);
      expect(response.status).toBe(403);
      expect(response.json).toEqual({ error: 'This dashboard is read-only. Open keysentry from a human terminal to make changes.' });
    }
    expect(d.handlers.write).not.toHaveBeenCalled();
  });

  it('caps JSON bytes, rejects malformed input, and hides handler diagnostics', async () => {
    const d = await start(); const auth = await login(d);
    expect((await post(d.port, '/api/disarm', auth, { text: 'x'.repeat(65_536) })).status).toBe(413);
    const headers = { Cookie: auth.cookie, Origin: `http://localhost:${d.port}`, 'X-CSRF-Token': auth.csrf, 'Content-Type': 'application/json' };
    expect((await req(d.port, '/api/disarm', { method: 'POST', headers, body: '{planted-private-value' })).json).toEqual({ error: 'Send a valid JSON body.' });
    expect((await post(d.port, '/api/disarm', auth, {}, { 'Content-Type': 'text/plain' })).status).toBe(415);
    expect((await post(d.port, '/api/disarm', auth, {}, { 'Content-Encoding': 'gzip' })).status).toBe(415);
    const error = await req(d.port, '/api/broken', { headers: { Cookie: auth.cookie } });
    expect(error.status).toBe(500); expect(error.text).not.toContain('planted-private-value');
  });

  it('refuses cross-site Fetch Metadata before running handlers or refreshing a session', async () => {
    let now = 0;
    const d = await start({ idleMs: 5000, now: () => now }); const auth = await login(d);
    now = 4000;
    for (const site of ['same-site', 'cross-site', 'unexpected', '']) {
      const response = await req(d.port, '/api/keys', { headers: { Cookie: auth.cookie, 'Sec-Fetch-Site': site } });
      expect(response.status).toBe(403);
      expect(response.json).toEqual({ error: 'Send this request from the local dashboard.' });
      expect(response.headers['cross-origin-resource-policy']).toBe('same-origin');
      expect(response.headers['cross-origin-opener-policy']).toBe('same-origin');
    }
    expect(d.handlers.read).not.toHaveBeenCalled();
    now = 5000;
    expect((await req(d.port, '/api/session', { headers: { Cookie: auth.cookie, 'Sec-Fetch-Site': 'same-origin' } })).status).toBe(401);
  });

  it('accepts same-origin and direct Fetch Metadata, but never exchanges a cross-site login token', async () => {
    const d = await start();
    const path = `/${new URL(d.url).search}`;
    expect((await req(d.port, path, { headers: { 'Sec-Fetch-Site': 'same-site' } })).status).toBe(403);
    const auth = await login(d);
    for (const site of ['same-origin', 'none']) {
      expect((await req(d.port, '/api/keys', { headers: { Cookie: auth.cookie, 'Sec-Fetch-Site': site } })).status).toBe(200);
    }
    expect((await post(d.port, '/api/disarm', auth, {}, { 'Sec-Fetch-Site': 'same-site' })).status).toBe(403);
    expect((await post(d.port, '/api/disarm', auth, {}, { 'Sec-Fetch-Site': 'same-site', Expect: '100-continue' })).status).toBe(403);
    expect(d.handlers.write).not.toHaveBeenCalled();
  });

  it('does not keep the server alive with refused cross-port requests', async () => {
    const d = await start({ idleMs: 150 }); const auth = await login(d);
    await new Promise(resolve => setTimeout(resolve, 80));
    expect((await req(d.port, '/api/keys', { headers: { Cookie: auth.cookie, 'Sec-Fetch-Site': 'same-site' } })).status).toBe(403);
    await new Promise(resolve => setTimeout(resolve, 90));
    await expect(req(d.port, '/')).rejects.toThrow();
    expect(d.handlers.read).not.toHaveBeenCalled();
  });

  it.each([
    [Object.assign(new Error('private-value'), { code: 'STATE_BUSY' }), 503, 'STATE_BUSY'],
    [new Error("keysentry's saved state is busy. Try again when the other operation finishes."), 503, 'STATE_BUSY'],
    [new VaultUnavailableError('private-value'), 503, 'VAULT_UNAVAILABLE'],
    [new VaultLockedError('The vault is busy in another keysentry process. Try again after it finishes.'), 503, 'VAULT_BUSY'],
    [new VaultLockedError('private-value'), 500, 'VAULT_LOCKED'],
    [Object.assign(new Error('private-value'), { name: 'private-name', code: 'private-code' }), 500, 'ERROR'],
  ])('classifies operational errors without returning or reporting values (%#)', async (error, status, errorClass) => {
    const onError = vi.fn();
    const d = await start({ onError, api: { broken: { method: 'GET', mutating: false, handler: async () => { throw error; } } } });
    const auth = await login(d);
    const response = await req(d.port, '/api/broken', { headers: { Cookie: auth.cookie } });
    expect(response.status).toBe(status);
    expect(response.json).toEqual({ error: 'The request could not be completed. Try again from keysentry.' });
    expect(response.headers['retry-after']).toBe(status === 503 ? '2' : undefined);
    expect(onError).toHaveBeenCalledExactlyOnceWith(errorClass);
  });

  it('keeps explicit input errors at 400 and safely handles a failing error reporter', async () => {
    const onError = vi.fn(() => { throw new Error('reporter-private-value'); });
    const d = await start({ onError, api: {
      invalid: { method: 'POST', mutating: false, handler: async () => { throw new DashboardError(400, 'Choose a key.'); } },
      broken: { method: 'GET', mutating: false, handler: async () => { throw new Error('handler-private-value'); } },
    } });
    const auth = await login(d);
    const invalid = await post(d.port, '/api/invalid', auth);
    expect(invalid.status).toBe(400); expect(invalid.json).toEqual({ error: 'Choose a key.' });
    expect(onError).not.toHaveBeenCalled();
    const broken = await req(d.port, '/api/broken', { headers: { Cookie: auth.cookie } });
    expect(broken.status).toBe(500); expect(broken.text).not.toContain('private-value');
  });

  it('caps streamed bodies without Content-Length and rejects invalid UTF-8 JSON', async () => {
    const d = await start(); const auth = await login(d);
    const response = await new Promise<number>((resolve, reject) => {
      const request = httpRequest({ hostname: '127.0.0.1', port: d.port, path: '/api/disarm', method: 'POST', headers: {
        Host: `localhost:${d.port}`, Cookie: auth.cookie, Origin: `http://localhost:${d.port}`, 'X-CSRF-Token': auth.csrf,
        'Content-Type': 'application/json', 'Transfer-Encoding': 'chunked',
      } }, reply => { reply.resume(); reply.on('end', () => resolve(reply.statusCode!)); });
      request.on('error', reject); request.write('{"text":"'); request.write('x'.repeat(65_536)); request.end('"}');
    });
    expect(response).toBe(413);
    const invalid = await new Promise<Reply>((resolve, reject) => {
      const request = httpRequest({ hostname: '127.0.0.1', port: d.port, path: '/api/disarm', method: 'POST', headers: {
        Host: `localhost:${d.port}`, Cookie: auth.cookie, Origin: `http://localhost:${d.port}`, 'X-CSRF-Token': auth.csrf, 'Content-Type': 'application/json',
      } }, reply => { let text = ''; reply.setEncoding('utf8'); reply.on('data', part => { text += part; }); reply.on('end', () => resolve({ status: reply.statusCode!, headers: reply.headers, text, json: JSON.parse(text) })); });
      request.on('error', reject); request.end(Buffer.from([0x22, 0xff, 0x22]));
    });
    expect(invalid.status).toBe(400); expect(invalid.json).toEqual({ error: 'Send a valid JSON body.' });
    expect(d.handlers.write).not.toHaveBeenCalled();
  });

  it('refuses incorrect methods and inherited routes', async () => {
    const d = await start(); const auth = await login(d);
    expect((await req(d.port, '/api/rotate', { headers: { Cookie: auth.cookie } })).status).toBe(405);
    expect((await post(d.port, '/api/keys', auth)).status).toBe(405);
    expect((await req(d.port, '/api/constructor', { headers: { Cookie: auth.cookie } })).status).toBe(404);
    expect((await req(d.port, '/', { method: 'OPTIONS' })).status).toBe(405);
    expect(d.handlers.write).not.toHaveBeenCalled();
    await expect(startDashboard({ readOnly: false, api: { reveal: { method: 'GET', mutating: true, handler: async () => ({ value: 'must-not-be-served' }) } } })).rejects.toThrow('Configure dashboard routes');
    await expect(startDashboard({ readOnly: false, api: { 'passkey/register/options': { method: 'POST', mutating: false, handler: async () => ({}) } } })).rejects.toThrow('Configure dashboard routes');
  });

  it('sets security headers on success, errors, redirects and unauthenticated pages', async () => {
    const d = await start();
    const replies = [await req(d.port, '/'), await req(d.port, '/api/session'), await req(d.port, '/wrong', { headers: { Host: 'evil' } }), await req(d.port, `/${new URL(d.url).search}`)];
    for (const response of replies) {
      expect(response.headers['content-security-policy']).toBe("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['referrer-policy']).toBe('no-referrer');
      expect(response.headers['cache-control']).toBe('no-store');
      expect(response.headers['cross-origin-resource-policy']).toBe('same-origin');
      expect(response.headers['cross-origin-opener-policy']).toBe('same-origin');
      expect(response.headers['access-control-allow-origin']).toBeUndefined();
    }
  });

  it('keeps security headers on every pipelined response', async () => {
    const d = await start();
    const raw = await new Promise<string>((resolve, reject) => {
      const socket = connect(d.port, '127.0.0.1');
      let result = '';
      socket.setEncoding('utf8'); socket.on('data', chunk => { result += chunk; });
      socket.on('error', reject); socket.on('end', () => resolve(result));
      socket.on('connect', () => socket.write(Array.from({ length: 101 }, (_, i) => `GET / HTTP/1.1\r\nHost: localhost:${d.port}\r\n${i === 100 ? 'Connection: close\r\n' : ''}\r\n`).join('')));
    });
    const replies = raw.split('HTTP/1.1 ').slice(1);
    expect(replies).toHaveLength(101);
    for (const reply of replies) expect(reply.split('\r\n\r\n')[0]).toContain('Content-Security-Policy:');
  });

  it('keeps security headers on parser, CONNECT and expectation refusals', async () => {
    const d = await start(); const auth = await login(d);
    const expected = await post(d.port, '/api/disarm', auth, {}, { Expect: '100-continue' });
    expect(expected.status).toBe(417); expect(expected.headers['content-security-policy']).toContain("default-src 'none'");
    for (const payload of [`CONNECT localhost:${d.port} HTTP/1.1\r\nHost: localhost:${d.port}\r\n\r\n`, 'broken HTTP request\r\n\r\n']) {
      const response = await new Promise<string>((resolve, reject) => {
        const socket = connect(d.port, '127.0.0.1'); let raw = '';
        socket.setEncoding('utf8'); socket.on('error', reject); socket.on('data', part => { raw += part; });
        socket.on('end', () => resolve(raw)); socket.on('connect', () => socket.write(payload));
      });
      expect(response).toContain('Content-Security-Policy:'); expect(response).toContain('Cache-Control: no-store');
      expect(response).toContain('X-Content-Type-Options: nosniff'); expect(response).toContain('Permissions-Policy:');
      expect(response).toContain('Cross-Origin-Resource-Policy: same-origin');
      expect(response).toContain('Cross-Origin-Opener-Policy: same-origin');
    }
    expect(d.handlers.write).not.toHaveBeenCalled();
  });

  it('keeps serving authenticated requests after an incomplete body is abandoned', async () => {
    const d = await start(); const auth = await login(d);
    await new Promise<void>(resolve => {
      const request = httpRequest({ hostname: '127.0.0.1', port: d.port, method: 'POST', path: '/api/disarm', headers: {
        Host: `localhost:${d.port}`, Cookie: auth.cookie, Origin: `http://localhost:${d.port}`, 'X-CSRF-Token': auth.csrf,
        'Content-Type': 'application/json', 'Content-Length': '1000',
      } });
      request.on('error', () => {}); request.on('close', resolve); request.write('{'); setTimeout(() => request.destroy(), 10);
    });
    expect((await req(d.port, '/api/session', { headers: { Cookie: auth.cookie } })).status).toBe(200);
    expect(d.handlers.write).not.toHaveBeenCalled();
  });

  it('refuses expired sessions and tokens using the same clock boundary', async () => {
    let now = 0;
    const d = await start({ idleMs: 5000, now: () => now }); const auth = await login(d);
    now = 5000;
    expect((await req(d.port, '/api/session', { headers: { Cookie: auth.cookie } })).status).toBe(401);
    const d2 = await start({ now: () => now }); now += 120_000;
    expect((await req(d2.port, `/${new URL(d2.url).search}`)).status).toBe(401);
  });

  it('closes after the idle budget and opens only the login URL', async () => {
    const open = vi.fn(); const d = await start({ idleMs: 30, open });
    expect(open).toHaveBeenCalledExactlyOnceWith(d.url);
    await new Promise(resolve => setTimeout(resolve, 90));
    await expect(req(d.port, '/')).rejects.toThrow();
  });
});
