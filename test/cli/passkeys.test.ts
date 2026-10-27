import { afterEach, expect, test, vi } from 'vitest';
import { request } from 'node:http';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createStateCipher, createStateStore } from '../../src/core/store.js';
import { generateDeviceKey } from '../../src/security/index.js';
import { createPasskeyManager, createPasskeyRegistrationServer, listPasskeys, openPasskeyBrowser } from '../../src/cli/passkeys.js';
import type { PasskeyCredential } from '../../src/types.js';

const servers: ReturnType<typeof createPasskeyRegistrationServer>[] = [];
const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => server.close()));
  await Promise.all(dirs.splice(0).map(dir => rm(dir, { recursive: true, force: true })));
});
function call(port: number, path: string, options: { method?: string; headers?: Record<string, string>; body?: string } = {}) {
  return new Promise<{ status: number; headers: import('node:http').IncomingHttpHeaders; body: string }>((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method: options.method ?? 'GET', agent: false,
      headers: { Host: `localhost:${port}`, ...options.headers } }, res => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject); req.end(options.body);
  });
}
async function start(options: Partial<Parameters<typeof createPasskeyRegistrationServer>[0]> = {}) {
  const saved: PasskeyCredential[] = [];
  const server = createPasskeyRegistrationServer({ existing: async () => [], save: async c => { saved.push(c); }, ...options });
  servers.push(server);
  const ready = await server.listen();
  const page = await call(ready.port, new URL(ready.url).pathname + new URL(ready.url).search);
  const cookie = page.headers['set-cookie']![0]!.split(';')[0]!;
  const csrf = /name="csrf" content="([A-Za-z0-9_-]+)"/.exec(page.body)![1]!;
  const headers = { Cookie: cookie, Origin: `http://localhost:${ready.port}`, 'Content-Type': 'application/json', 'X-Keysentry-CSRF': csrf };
  return { ...ready, server, saved, page, headers };
}
function registration(challenge: string, origin: string, id = 'local-credential') {
  const key = generateDeviceKey();
  const cose = Buffer.concat([Buffer.from('a4010103272006215820', 'hex'), key.publicKeyDer.subarray(-32)]);
  const credentialId = Buffer.from(id);
  const auth = Buffer.alloc(55);
  createHash('sha256').update('localhost').digest().copy(auth);
  auth[32] = 0x45; auth.writeUInt16BE(credentialId.length, 53);
  const authenticatorData = Buffer.concat([auth, credentialId, cose]);
  const length = Buffer.from([0x58, authenticatorData.length]);
  const object = Buffer.concat([Buffer.from('a363666d74646e6f6e656761747453746d74a0686175746844617461', 'hex'), length, authenticatorData]);
  return JSON.stringify({ clientDataJSON: Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin })).toString('base64url'), attestationObject: object.toString('base64url') });
}

test('passkey register serves localhost with CSP and a separate static script', async () => {
  const { port, page } = await start();
  expect(page.status).toBe(200);
  expect(page.headers['content-security-policy']).toContain("script-src 'self'");
  expect(page.headers['content-security-policy']).not.toContain('unsafe-inline');
  expect(page.headers['referrer-policy']).toBe('no-referrer');
  expect(page.headers['set-cookie']![0]).toContain('SameSite=Strict');
  expect(page.headers['set-cookie']![0]).toContain('HttpOnly');
  expect(page.body).toContain('<script src="/register.js" defer></script>');
  const script = await call(port, '/register.js');
  expect(script.status).toBe(200); expect(script.body).toContain('navigator.credentials.create');
});
test('Host checks reject IP, forwarded-host and rebinding forms', async () => {
  const { port } = await start();
  for (const host of [`127.0.0.1:${port}`, 'localhost', 'evil.example']) {
    expect((await call(port, '/register.js', { headers: { Host: host, 'X-Forwarded-Host': `localhost:${port}` } })).status).toBe(403);
  }
});
test('one-time URL cannot create a second session and unauthenticated requests reject', async () => {
  const { port, url } = await start();
  expect((await call(port, new URL(url).pathname + new URL(url).search)).status).toBe(403);
  expect((await call(port, '/register')).status).toBe(403);
  expect((await call(port, '/options', { method: 'POST', body: '{}' })).status).toBe(403);
});
test('Origin and CSRF checks are required for both registration endpoints', async () => {
  const { port, headers } = await start();
  for (const path of ['/options', '/register']) {
    for (const changes of [{ Origin: 'https://elsewhere.example' }, { Origin: '' }, { 'X-Keysentry-CSRF': '' }]) {
      expect((await call(port, path, { method: 'POST', headers: { ...headers, ...changes }, body: '{}' })).status).toBe(403);
    }
  }
});
test('successful registration verifies localhost RP and UV, saves once and shuts down', async () => {
  const { port, headers, server, saved } = await start();
  const opts = JSON.parse((await call(port, '/options', { method: 'POST', headers, body: '{}' })).body);
  expect(opts.rp.id).toBe('localhost');
  expect(opts.authenticatorSelection.userVerification).toBe('required');
  expect(opts.attestation).toBe('none');
  const reply = await call(port, '/register', { method: 'POST', headers, body: registration(opts.challenge, `http://localhost:${port}`) });
  expect(reply.status).toBe(200);
  expect(await server.done).toEqual({ status: 'registered', credential: saved[0] });
  expect(saved).toHaveLength(1); expect(saved[0]!.rpId).toBe('localhost');
  await expect(call(port, '/register.js')).rejects.toThrow();
});
test('malformed, oversized and wrong-origin ceremony payloads never save a credential', async () => {
  const { port, headers, saved } = await start();
  const opts = JSON.parse((await call(port, '/options', { method: 'POST', headers, body: '{}' })).body);
  for (const body of ['{"clientDataJSON":"!"}', registration(opts.challenge, 'https://evil.example'), JSON.stringify({ field: 'x'.repeat(140_000) })]) {
    const result = await call(port, '/register', { method: 'POST', headers, body });
    expect([400, 413]).toContain(result.status);
    expect(result.body).not.toContain('evil.example');
  }
  expect(saved).toHaveLength(0);
});
test('duplicate credential ids reject and leave the registration page available', async () => {
  const { port, headers, saved } = await start({ existing: async () => [{ id: Buffer.from('local-credential').toString('base64url') } as PasskeyCredential] });
  const opts = JSON.parse((await call(port, '/options', { method: 'POST', headers, body: '{}' })).body);
  const result = await call(port, '/register', { method: 'POST', headers, body: registration(opts.challenge, `http://localhost:${port}`) });
  expect(result.status).toBe(409); expect(saved).toHaveLength(0);
});
test('registration auto-shuts down at its time limit or Ctrl-C', async () => {
  const timed = createPasskeyRegistrationServer({ existing: async () => [], save: async () => {}, timeoutMs: 25 });
  servers.push(timed); await timed.listen();
  expect(await timed.done).toEqual({ status: 'expired' });
  const interrupted = await start();
  process.emit('SIGINT');
  expect(await interrupted.server.done).toEqual({ status: 'cancelled' });
});
test('expiry during an in-flight request prevents registration from being saved', async () => {
  let delayed = false;
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const { port, headers, server, saved } = await start({ timeoutMs: 50, existing: async () => { if (delayed) await gate; return []; } });
  const opts = JSON.parse((await call(port, '/options', { method: 'POST', headers, body: '{}' })).body);
  delayed = true;
  const pending = call(port, '/register', { method: 'POST', headers, body: registration(opts.challenge, `http://localhost:${port}`) }).catch(() => undefined);
  await new Promise(resolve => setTimeout(resolve, 75));
  release();
  expect(await server.done).toEqual({ status: 'expired' });
  await pending;
  expect(saved).toHaveLength(0);
});
test('manager stores encrypted credentials, lists public metadata, removes and audits', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'keysentry-cli-passkeys-')); dirs.push(dir);
  const store = createStateStore({ cwd: dir, cipher: createStateCipher(Buffer.alloc(32, 7)) });
  const events: unknown[] = []; const assertHuman = vi.fn();
  const manager = createPasskeyManager({ store, audit: { append: async e => { events.push(e); } }, assertHuman });
  const result = manager.register({ label: 'My laptop', onReady: async ({ url, port }) => {
    const page = await call(port, new URL(url).pathname + new URL(url).search);
    const cookie = page.headers['set-cookie']![0]!.split(';')[0]!;
    const csrf = /name="csrf" content="([A-Za-z0-9_-]+)"/.exec(page.body)![1]!;
    const headers = { Cookie: cookie, Origin: `http://localhost:${port}`, 'Content-Type': 'application/json', 'X-Keysentry-CSRF': csrf };
    const opts = JSON.parse((await call(port, '/options', { method: 'POST', headers, body: '{}' })).body);
    await call(port, '/register', { method: 'POST', headers, body: registration(opts.challenge, `http://localhost:${port}`) });
  } });
  expect((await result).status).toBe('registered');
  const credentials = await listPasskeys(store); expect(credentials).toHaveLength(1); expect(credentials[0]!.label).toBe('My laptop');
  expect(credentials[0]!.origins).toContain('http://localhost');
  expect(await readFile(join(store.paths.dir, 'passkeys.json'), 'utf8')).not.toContain('My laptop');
  expect(await manager.list()).toEqual([{ id: credentials[0]!.id, label: 'My laptop', rpId: 'localhost', createdAt: credentials[0]!.createdAt }]);
  expect(await manager.remove(credentials[0]!.id)).toEqual({ id: credentials[0]!.id, removed: true });
  expect(await listPasskeys(store)).toEqual([]); expect(events).toHaveLength(2); expect(assertHuman).toHaveBeenCalledTimes(3);
});
test('manager refuses remote mutation forms and explains that public registration is unavailable', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'keysentry-cli-passkeys-')); dirs.push(dir);
  const manager = createPasskeyManager({ store: createStateStore({ cwd: dir, cipher: createStateCipher(Buffer.alloc(32, 4)) }), audit: { append: async () => {} }, assertHuman: () => {} });
  await expect(manager.register({ relay: true })).rejects.toThrow(/local/i);
  await expect(manager.remove('id', { remote: true })).rejects.toThrow(/local/i);
  const publicResult = await manager.register({ origin: 'https://approvals.example.org' });
  expect(publicResult.status).toBe('public-origin');
  expect(publicResult.message).toContain('Public-origin passkey registration is not available');
  expect(publicResult.message).not.toContain('dashboard feature');
});

const browserUrl = `http://localhost:38493/register?token=${'A'.repeat(43)}`;
test.each(['win32', 'darwin', 'linux'] as const)('browser opener uses the %s OS executable without a shell or credential environment', async platform => {
  const dir = await mkdtemp(join(tmpdir(), 'keysentry-passkey-launcher-')); dirs.push(dir);
  const launcher = join(dir, 'register.html');
  await writeFile(launcher, '<!doctype html><title>Register</title>', { mode: 0o600 });
  const calls: unknown[][] = [];
  const execFile: NonNullable<Parameters<typeof openPasskeyBrowser>[1]>['execFile'] = (file, args, options, callback) => {
    calls.push([file, args, options]); callback(null);
  };
  expect(await openPasskeyBrowser(launcher, { platform, execFile, env: { SystemRoot: 'C:\\Windows', PATH: 'untrusted-path', BROWSER: 'untrusted-command', OPENAI_API_KEY: 'planted-value', KEYSENTRY_VAULT_PASSPHRASE: 'planted-password', HOME: '/home/test', DISPLAY: ':0' } })).toBe(true);
  expect(calls).toHaveLength(1);
  const [file, args, options] = calls[0]! as [string, string[], Record<string, unknown>];
  expect(file).toBe(platform === 'win32' ? 'C:\\Windows\\System32\\rundll32.exe' : platform === 'darwin' ? '/usr/bin/open' : '/usr/bin/xdg-open');
  expect(args).toEqual(platform === 'win32' ? ['url.dll,FileProtocolHandler', launcher] : [launcher]);
  expect(options.windowsHide).toBe(true); expect(options.shell).toBe(false);
  expect(JSON.stringify(options)).not.toContain('planted-'); expect(JSON.stringify(options)).not.toContain('untrusted');
  expect(Number(options.timeout)).toBeLessThanOrEqual(5000);
});
test('browser opener rejects bearer URLs before starting a child', async () => {
  const execFile = vi.fn();
  for (const url of [browserUrl, 'https://example.org/', 'http://127.0.0.1:38493/register?token=' + 'A'.repeat(43), browserUrl + '&extra=x', browserUrl + '#fragment', browserUrl.replace('/register?', '/other?'), browserUrl.replace('localhost:', 'localhost.evil:'), browserUrl.replace('token=', 'token=invalid')]) {
    expect(await openPasskeyBrowser(url, { execFile })).toBe(false);
  }
  expect(execFile).not.toHaveBeenCalled();
});
test('browser opener quietly falls back when process creation fails or the platform is unsupported', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'keysentry-passkey-launcher-')); dirs.push(dir);
  const launcher = join(dir, 'register.html');
  await writeFile(launcher, '<!doctype html><title>Register</title>', { mode: 0o600 });
  const failed: NonNullable<Parameters<typeof openPasskeyBrowser>[1]>['execFile'] = (_file, _args, _options, callback) => callback(new Error('private details'));
  expect(await openPasskeyBrowser(launcher, { platform: 'linux', execFile: failed })).toBe(false);
  expect(await openPasskeyBrowser(launcher, { platform: 'linux', execFile: () => { throw new Error('private details'); } })).toBe(false);
  const execFile = vi.fn();
  expect(await openPasskeyBrowser(launcher, { platform: 'freebsd', execFile })).toBe(false);
  expect(execFile).not.toHaveBeenCalled();
});
