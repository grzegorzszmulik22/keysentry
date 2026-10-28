import { randomBytes } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { TeeTokenError, createTeeTokenSource } from '../../../src/box/agent/index.js';

const JWT = `${'a'.repeat(20)}.${'b'.repeat(40)}.${'c'.repeat(60)}`;
const servers: Server[] = [];
const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); })));
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

/** A launcher token server on a Unix socket (a named pipe on Windows), like /run/container_launcher/teeserver.sock. */
async function launcher(handler: (req: IncomingMessage, body: string, res: ServerResponse) => void): Promise<string> {
  const socketPath = process.platform === 'win32' ? `\\\\.\\pipe\\keysentry-tee-${randomBytes(6).toString('hex')}`
    : join(await mkdtemp(join(tmpdir(), 'keysentry-tee-')).then(dir => { dirs.push(dir); return dir; }), 'teeserver.sock');
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => handler(req, Buffer.concat(chunks).toString('utf8'), res));
  });
  servers.push(server);
  await new Promise<void>(resolve => server.listen(socketPath, resolve));
  return socketPath;
}

describe('launcher token source', () => {
  it('posts exactly audience, nonces and token_type to /v1/token and reads the raw JWT whatever the content type', async () => {
    const seen: { method?: string; url?: string; type?: string; body: unknown }[] = [];
    const socketPath = await launcher((req, body, res) => {
      seen.push({ method: req.method, url: req.url, type: req.headers['content-type'], body: JSON.parse(body) });
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); res.end(`${JWT}\n`);
    });
    const tee = createTeeTokenSource({ socketPath, minIntervalMs: 0 });
    const nonces = ['n'.repeat(43), 'm'.repeat(43)];
    expect(await tee.token({ audience: 'keysentry-box:alpha', nonces })).toBe(JWT);
    expect(await tee.token({ audience: 'keysentry-box:alpha', nonces, tokenType: 'PKI' })).toBe(JWT);
    expect(seen).toEqual([
      { method: 'POST', url: '/v1/token', type: 'application/json', body: { audience: 'keysentry-box:alpha', nonces, token_type: 'OIDC' } },
      { method: 'POST', url: '/v1/token', type: 'application/json', body: { audience: 'keysentry-box:alpha', nonces, token_type: 'PKI' } },
    ]);
    expect(Object.keys(seen[0]!.body as object)).toEqual(['audience', 'nonces', 'token_type']);
  });

  it('refuses a failed request, a response over 64 KiB and a body that is not a JWT', async () => {
    let reply: (res: ServerResponse) => void = () => {};
    const socketPath = await launcher((_req, _body, res) => reply(res));
    const tee = createTeeTokenSource({ socketPath, minIntervalMs: 0 });
    const request = () => tee.token({ audience: 'keysentry-box:alpha', nonces: ['n'.repeat(43)] });
    reply = res => { res.writeHead(500); res.end(JWT); };
    await expect(request()).rejects.toBeInstanceOf(TeeTokenError);
    reply = res => { res.writeHead(200); res.end(`${JWT}${'x'.repeat(64 * 1024)}`); };
    await expect(request()).rejects.toThrow(/too large/);
    reply = res => { res.writeHead(200); res.end('{"error":"not a token"}'); };
    await expect(request()).rejects.toBeInstanceOf(TeeTokenError);
  });

  it('gives up after its timeout when the launcher does not answer', async () => {
    const socketPath = await launcher(() => { /* never answers */ });
    const tee = createTeeTokenSource({ socketPath, timeoutMs: 50, minIntervalMs: 0 });
    await expect(tee.token({ audience: 'keysentry-box:alpha', nonces: [] })).rejects.toThrow(/in time/);
  });

  it('checks nonces before any request: at most six, each 10 to 74 bytes', async () => {
    let requests = 0;
    const socketPath = await launcher((_req, _body, res) => { requests++; res.end(JWT); });
    const tee = createTeeTokenSource({ socketPath, minIntervalMs: 0 });
    for (const nonces of [['short'], ['n'.repeat(75)], Array.from({ length: 7 }, () => 'n'.repeat(43))]) {
      await expect(tee.token({ audience: 'keysentry-box:alpha', nonces })).rejects.toBeInstanceOf(TeeTokenError);
    }
    await expect(tee.token({ audience: '', nonces: [] })).rejects.toBeInstanceOf(TeeTokenError);
    expect(requests).toBe(0);
  });

  it('spaces requests to stay under the launcher limit of five a second', async () => {
    const socketPath = await launcher((_req, _body, res) => res.end(JWT));
    let clock = 1_000;
    const waits: number[] = [];
    const tee = createTeeTokenSource({ socketPath, now: () => clock, sleep: async ms => { waits.push(ms); clock += ms; } });
    await Promise.all([1, 2, 3].map(() => tee.token({ audience: 'keysentry-box:alpha', nonces: [] })));
    expect(waits).toEqual([250, 250]);
  });

  it('reads the default token from the launcher file with the same limits', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'keysentry-tee-file-')); dirs.push(dir);
    const path = join(dir, 'attestation_verifier_claims_token');
    const tee = createTeeTokenSource({ defaultTokenPath: path });
    await expect(tee.defaultToken()).rejects.toThrow(/could not read/);
    await writeFile(path, `${JWT}\n`);
    expect(await tee.defaultToken()).toBe(JWT);
    await writeFile(path, 'x'.repeat(64 * 1024 + 1));
    await expect(tee.defaultToken()).rejects.toThrow(/too large/);
  });
});
