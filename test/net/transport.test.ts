import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer as createHttpServer, type IncomingHttpHeaders, type IncomingMessage, type ServerResponse } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { connect as netConnect, createServer as createNetServer, type AddressInfo, type Server, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as tls from 'node:tls';
import { gzipSync } from 'node:zlib';
import { afterEach, describe, expect, test } from 'vitest';
import {
  bypassesProxy, CaBundleError, createNodeTransport, createUnavailableTransport, loadCaBundle, networkStatusLines,
  parseCaBundle, parseNoProxy, PROXY_AUTH_VAULT_NAME, resolveProxySettings, summarizeNetwork, TransportConfigError,
  TransportError, trustedCertificates, usesProxy,
} from '../../src/net/transport.js';
import { offlineEgressRules, offlineNotice, resolveFeedMode, selectFeedSources } from '../../src/feeds/offline.js';
import { fetchFeed } from '../../src/feeds/index.js';
import { DEFAULT_SOURCES } from '../../src/autopilot/sources.js';
import { DEFAULT_BREACH_FEEDS, detectBreachFeeds } from '../../src/monitor/detectors/breach-feed.js';
import { createGuardedHttp, EGRESS_RULES, EgressBlockedError, rulesForUserFeeds } from '../../src/net/index.js';
import { networkDoctorItems } from '../../src/doctor/network.js';
import { runDoctor } from '../../src/doctor/doctor.js';
import { createRedactor } from '../../src/core/redact.js';
import { FakeHttp, json, silentLogger } from '../helpers/fake-http.js';
import { createFakeVault } from '../helpers/fake-vault.js';

// ---------------------------------------------------------------- test certificates (DER built with node:crypto)

function derLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  for (let value = length; value > 0; value = Math.floor(value / 256)) bytes.unshift(value & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const tlv = (tag: number, ...parts: Buffer[]): Buffer => {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
};
const seq = (...parts: Buffer[]) => tlv(0x30, ...parts);
const set = (...parts: Buffer[]) => tlv(0x31, ...parts);
const integer = (bytes: Buffer) => tlv(0x02, bytes);
const oid = (dotted: string): Buffer => {
  const [first, second, ...rest] = dotted.split('.').map(Number);
  const out = [first! * 40 + second!];
  for (const value of rest) {
    const groups = [value & 0x7f];
    for (let rem = Math.floor(value / 128); rem > 0; rem = Math.floor(rem / 128)) groups.unshift((rem & 0x7f) | 0x80);
    out.push(...groups);
  }
  return tlv(0x06, Buffer.from(out));
};
const utf8 = (text: string) => tlv(0x0c, Buffer.from(text, 'utf8'));
const bits = (bytes: Buffer, unused = 0) => tlv(0x03, Buffer.from([unused]), bytes);
const octets = (bytes: Buffer) => tlv(0x04, bytes);
const bool = (value: boolean) => tlv(0x01, Buffer.from([value ? 0xff : 0]));
const utcTime = (date: Date) => tlv(0x17, Buffer.from(`${date.toISOString().replace(/[-:T]/g, '').slice(2, 14)}Z`));
const x500Name = (cn: string) => seq(set(seq(oid('2.5.4.10'), utf8('keysentry tests'))), set(seq(oid('2.5.4.3'), utf8(cn))));
const ECDSA_SHA256 = seq(oid('1.2.840.10045.4.3.2'));

interface Issued { cert: string; key: string; privateKey: KeyObject; subject: Buffer; keyId: Buffer }

function issue(options: { cn: string; ca?: boolean; issuer?: Issued; dns?: string[]; ips?: number[][] }): Issued {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const keyId = createHash('sha1').update(spki).digest();
  const subject = x500Name(options.cn);
  const extensions = [
    seq(oid('2.5.29.19'), bool(true), octets(options.ca ? seq(bool(true)) : seq())),
    seq(oid('2.5.29.15'), bool(true), octets(options.ca ? bits(Buffer.from([0x06]), 1) : bits(Buffer.from([0x80]), 7))),
    seq(oid('2.5.29.14'), octets(octets(keyId))),
    seq(oid('2.5.29.35'), octets(seq(tlv(0x80, options.issuer?.keyId ?? keyId)))),
  ];
  if (!options.ca) {
    extensions.push(seq(oid('2.5.29.37'), octets(seq(oid('1.3.6.1.5.5.7.3.1')))));
    extensions.push(seq(oid('2.5.29.17'), octets(seq(
      ...(options.dns ?? []).map(name => tlv(0x82, Buffer.from(name))),
      ...(options.ips ?? []).map(ip => tlv(0x87, Buffer.from(ip))),
    ))));
  }
  const serial = randomBytes(8);
  serial[0] = (serial[0]! & 0x3f) | 0x40;
  const now = Date.now();
  const tbs = seq(
    tlv(0xa0, integer(Buffer.from([2]))), integer(serial), ECDSA_SHA256, options.issuer?.subject ?? subject,
    seq(utcTime(new Date(now - 86_400_000)), utcTime(new Date(now + 30 * 86_400_000))),
    subject, spki, tlv(0xa3, seq(...extensions)),
  );
  const der = seq(tbs, ECDSA_SHA256, bits(sign('sha256', tbs, options.issuer?.privateKey ?? privateKey)));
  return {
    cert: `-----BEGIN CERTIFICATE-----\n${der.toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----\n`,
    key: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string, privateKey, subject, keyId,
  };
}

const caA = issue({ cn: 'Test Root A', ca: true });
const caB = issue({ cn: 'Test Root B', ca: true });
const apiCert = issue({ cn: 'api.example.test', issuer: caA, dns: ['api.example.test', 'localhost'], ips: [[127, 0, 0, 1]] });
const proxyCert = issue({ cn: 'Test Proxy', issuer: caA, dns: ['localhost'], ips: [[127, 0, 0, 1]] });
const proxyCertOtherCa = issue({ cn: 'Test Proxy', issuer: caB, dns: ['localhost'], ips: [[127, 0, 0, 1]] });

// ---------------------------------------------------------------- local servers

const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => { while (cleanup.length) await cleanup.pop()!(); });

interface Received { method?: string; url?: string; headers: IncomingHttpHeaders; rawHeaders: string[]; body: string }
type Handler = (req: IncomingMessage, res: ServerResponse, body: string) => void;

async function listen(server: Server, sockets: Set<Socket>): Promise<number> {
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); socket.on('error', () => {}); });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  cleanup.push(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>(resolve => server.close(() => resolve()));
  });
  return (server.address() as AddressInfo).port;
}

async function startDestination(handler?: Handler) {
  const requests: Received[] = [];
  const state = {
    port: 0, requests, connections: 0,
    handler: handler ?? ((_req: IncomingMessage, res: ServerResponse) => { res.writeHead(200, { 'Content-Type': 'text/plain', 'X-Test': 'yes' }); res.end('hello'); }),
  };
  const server = createHttpsServer({ key: apiCert.key, cert: apiCert.cert }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      requests.push({ method: req.method, url: req.url, headers: req.headers, rawHeaders: req.rawHeaders, body });
      state.handler(req, res, body);
    });
  });
  server.on('tlsClientError', () => {});
  server.on('connection', () => { state.connections += 1; });
  const sockets = new Set<Socket>();
  state.port = await listen(server, sockets);
  return state;
}

async function startProxy(options: { routes?: Record<string, number>; tls?: Issued; reply?: string } = {}) {
  const state = { port: 0, connections: 0, connects: [] as { url?: string; headers: IncomingHttpHeaders }[], tunnelBytes: [] as Buffer[] };
  const server = options.tls ? createHttpsServer({ key: options.tls.key, cert: options.tls.cert }) : createHttpServer();
  const sockets = new Set<Socket>();
  server.on('tlsClientError', () => {});
  server.on('connection', () => { state.connections += 1; });
  server.on('connect', (req: IncomingMessage, client: Socket, head: Buffer) => {
    state.connects.push({ url: req.url, headers: req.headers });
    client.on('error', () => {});
    if (options.reply) { client.end(options.reply); return; }
    const port = options.routes?.[req.url ?? ''];
    if (port === undefined) { client.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'); return; }
    const upstream = netConnect(port, '127.0.0.1', () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) { state.tunnelBytes.push(head); upstream.write(head); }
      client.on('data', chunk => state.tunnelBytes.push(chunk));
      client.pipe(upstream); upstream.pipe(client);
    });
    sockets.add(upstream);
    upstream.on('error', () => client.destroy());
    client.on('close', () => upstream.destroy());
  });
  state.port = await listen(server as unknown as Server, sockets);
  return state;
}

/** Accepts TCP connections and never answers. */
async function startSilentServer() {
  const server = createNetServer(() => {});
  return { port: await listen(server, new Set()) };
}

async function failure(promise: Promise<unknown>): Promise<Error> {
  try { await promise; } catch (error) { return error as Error; }
  throw new Error('expected the request to fail');
}

// ---------------------------------------------------------------- transport

describe('createNodeTransport through a CONNECT proxy', () => {
  test('tunnels to the destination and verifies its certificate against the extra CA', async () => {
    const destination = await startDestination();
    const proxy = await startProxy({ routes: { 'api.example.test:443': destination.port } });
    const http = createNodeTransport({ proxy: { url: `http://127.0.0.1:${proxy.port}` }, ca: [caA.cert] });
    const response = await http.request({ method: 'GET', url: 'https://api.example.test/v1/keys?limit=2', headers: { Accept: 'application/json' } });
    expect(response.status).toBe(200);
    expect(response.text).toBe('hello');
    expect(response.headers['x-test']).toBe('yes');
    // api.example.test does not resolve: the request can only have arrived through the tunnel.
    expect(proxy.connects.map(item => item.url)).toEqual(['api.example.test:443']);
    expect(destination.requests).toHaveLength(1);
    expect(destination.requests[0]).toMatchObject({ method: 'GET', url: '/v1/keys?limit=2' });
    expect(destination.requests[0]!.headers.host).toBe('api.example.test');
    expect(destination.requests[0]!.headers.accept).toBe('application/json');
    expect(destination.requests[0]!.headers['user-agent']).toMatch(/^keysentry\//);
  });

  test('sends the body and headers, and returns redirects without following them', async () => {
    const destination = await startDestination((req, res) => {
      if (req.url === '/move') { res.writeHead(302, { Location: 'https://elsewhere.example.test/' }); res.end(); return; }
      res.writeHead(201, { 'Content-Type': 'application/json' }); res.end('{"ok":true}');
    });
    const proxy = await startProxy({ routes: { 'api.example.test:443': destination.port } });
    const http = createNodeTransport({ proxy: { url: `http://127.0.0.1:${proxy.port}` }, ca: [caA.cert] });
    const created = await http.request({ method: 'POST', url: 'https://api.example.test/keys', headers: { 'Content-Type': 'application/json' }, body: '{"name":"€"}' });
    expect(created.status).toBe(201);
    expect(created.json()).toEqual({ ok: true });
    expect(destination.requests[0]).toMatchObject({ method: 'POST', body: '{"name":"€"}' });
    expect(destination.requests[0]!.headers['content-length']).toBe(String(Buffer.byteLength('{"name":"€"}')));
    const moved = await http.request({ method: 'GET', url: 'https://api.example.test/move' });
    expect(moved.status).toBe(302);
    expect(moved.headers.location).toBe('https://elsewhere.example.test/');
    expect(proxy.connects).toHaveLength(2);
  });

  test('refuses a destination certificate issued by another CA, before any request is sent', async () => {
    const destination = await startDestination();
    const proxy = await startProxy({ routes: { 'api.example.test:443': destination.port } });
    const http = createNodeTransport({ proxy: { url: `http://127.0.0.1:${proxy.port}` }, ca: [caB.cert] });
    const error = await failure(http.request({ method: 'GET', url: 'https://api.example.test/secret?token=hidden' }));
    expect(error).toBeInstanceOf(TransportError);
    expect(error).toMatchObject({ code: 'TLS_VERIFY_FAILED' });
    expect(error.message).toContain('api.example.test');
    expect(error.message).not.toMatch(/secret|token|hidden/);
    expect(destination.requests).toHaveLength(0);
  });

  test('keeps the system roots only when no CA file is configured, so a private CA is not trusted', async () => {
    const destination = await startDestination();
    const proxy = await startProxy({ routes: { 'api.example.test:443': destination.port } });
    const http = createNodeTransport({ proxy: { url: `http://127.0.0.1:${proxy.port}` } });
    await expect(http.request({ method: 'GET', url: 'https://api.example.test/' })).rejects.toMatchObject({ code: 'TLS_VERIFY_FAILED' });
    expect(destination.requests).toHaveLength(0);
  });

  test('checks the destination name with SNI, not the proxy name', async () => {
    const destination = await startDestination();
    const proxy = await startProxy({ routes: { 'other.example.test:443': destination.port } });
    const http = createNodeTransport({ proxy: { url: `http://127.0.0.1:${proxy.port}` }, ca: [caA.cert] });
    await expect(http.request({ method: 'GET', url: 'https://other.example.test/' })).rejects.toMatchObject({ code: 'TLS_VERIFY_FAILED' });
    expect(destination.requests).toHaveLength(0);
  });

  test('sends proxy credentials only in the CONNECT request', async () => {
    const password = 'proxy-pass-5f2b91c4';
    const destination = await startDestination();
    const proxy = await startProxy({ routes: { 'api.example.test:443': destination.port } });
    const http = createNodeTransport({ proxy: { url: `http://127.0.0.1:${proxy.port}`, credentials: { username: 'corp-user', password } }, ca: [caA.cert] });
    const token = Buffer.from(`corp-user:${password}`).toString('base64');
    await http.request({ method: 'POST', url: 'https://api.example.test/keys', body: 'x',
      headers: { 'Proxy-Authorization': 'Basic Y2FsbGVyOnN1cHBsaWVk', Authorization: 'Bearer destination-token' } });
    expect(proxy.connects[0]!.headers['proxy-authorization']).toBe(`Basic ${token}`);
    const received = destination.requests[0]!;
    expect(received.headers['proxy-authorization']).toBeUndefined();
    expect(received.headers.authorization).toBe('Bearer destination-token');
    expect(received.rawHeaders.join('\n')).not.toContain(password);
    expect(received.rawHeaders.join('\n')).not.toContain(token);
    // The tunnelled bytes are TLS: neither the credential nor the destination token is visible to the proxy.
    const tunnel = Buffer.concat(proxy.tunnelBytes);
    expect(tunnel.length).toBeGreaterThan(0);
    for (const secret of [password, token, 'destination-token']) expect(tunnel.includes(Buffer.from(secret))).toBe(false);
  });

  test('a 407 reply asks for credentials without echoing any', async () => {
    const proxy = await startProxy({ reply: 'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="corp"\r\nContent-Length: 0\r\n\r\n' });
    const withoutCredentials = createNodeTransport({ proxy: { url: `http://127.0.0.1:${proxy.port}` } });
    const missing = await failure(withoutCredentials.request({ method: 'GET', url: 'https://api.example.test/' }));
    expect(missing).toMatchObject({ code: 'PROXY_AUTH_REQUIRED' });
    expect(missing.message).toContain('KEYSENTRY_PROXY_AUTH');
    const withCredentials = createNodeTransport({ proxy: { url: `http://127.0.0.1:${proxy.port}`, credentials: { username: 'u', password: 'wrong-pass-123' } } });
    const refused = await failure(withCredentials.request({ method: 'GET', url: 'https://api.example.test/' }));
    expect(refused).toMatchObject({ code: 'PROXY_AUTH_REQUIRED' });
    expect(refused.message).not.toContain('wrong-pass-123');
  });

  test('another refusal from the proxy reports only its status', async () => {
    const proxy = await startProxy({ reply: 'HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\ndenied' });
    const error = await failure(createNodeTransport({ proxy: { url: `http://127.0.0.1:${proxy.port}` } })
      .request({ method: 'GET', url: 'https://api.example.test/' }));
    expect(error).toMatchObject({ code: 'PROXY_TUNNEL_REFUSED' });
    expect(error.message).toContain('403');
    expect(error.message).not.toContain('denied');
  });

  test('an https proxy has its own certificate check, separate from the destination', async () => {
    const destination = await startDestination();
    const goodProxy = await startProxy({ tls: proxyCert, routes: { 'api.example.test:443': destination.port } });
    const response = await createNodeTransport({ proxy: { url: `https://localhost:${goodProxy.port}` }, ca: [caA.cert] })
      .request({ method: 'GET', url: 'https://api.example.test/' });
    expect(response.text).toBe('hello');
    expect(goodProxy.connects).toHaveLength(1);

    const untrustedProxy = await startProxy({ tls: proxyCertOtherCa, routes: { 'api.example.test:443': destination.port } });
    const error = await failure(createNodeTransport({ proxy: { url: `https://localhost:${untrustedProxy.port}` }, ca: [caA.cert] })
      .request({ method: 'GET', url: 'https://api.example.test/' }));
    expect(error).toMatchObject({ code: 'PROXY_TLS_FAILED' });
    expect(untrustedProxy.connects).toHaveLength(0);
    expect(destination.requests).toHaveLength(1);
  });

  test('NO_PROXY hosts connect directly and the proxy is never contacted', async () => {
    const destination = await startDestination();
    const proxy = await startProxy({ routes: {} });
    const http = createNodeTransport({ proxy: { url: `http://127.0.0.1:${proxy.port}` }, noProxy: ['localhost', '127.0.0.1'], ca: [caA.cert] });
    expect((await http.request({ method: 'GET', url: `https://localhost:${destination.port}/a` })).text).toBe('hello');
    expect((await http.request({ method: 'GET', url: `https://127.0.0.1:${destination.port}/b` })).text).toBe('hello');
    expect(proxy.connections).toBe(0);
    expect(destination.requests.map(item => item.url)).toEqual(['/a', '/b']);
  });

  test('a policy that requires the proxy refuses no-proxy hosts and a missing proxy', async () => {
    const proxy = await startProxy({ routes: {} });
    const http = createNodeTransport({ proxy: { url: `http://127.0.0.1:${proxy.port}` }, noProxy: ['localhost'], requireProxy: true });
    await expect(http.request({ method: 'GET', url: 'https://localhost/' })).rejects.toMatchObject({ code: 'PROXY_REQUIRED' });
    expect(proxy.connections).toBe(0);
    expect(() => createNodeTransport({ requireProxy: true })).toThrow(TransportConfigError);
  });

  test('plain http destinations are refused without opening a connection', async () => {
    const destination = await startDestination();
    const proxy = await startProxy({ routes: {} });
    const http = createNodeTransport({ proxy: { url: `http://127.0.0.1:${proxy.port}` } });
    await expect(http.request({ method: 'GET', url: `http://127.0.0.1:${destination.port}/` })).rejects.toMatchObject({ code: 'PLAIN_HTTP_REFUSED' });
    await expect(createNodeTransport().request({ method: 'GET', url: `http://127.0.0.1:${destination.port}/` })).rejects.toMatchObject({ code: 'PLAIN_HTTP_REFUSED' });
    expect(proxy.connections).toBe(0);
    expect(destination.connections).toBe(0);
  });

  test('a header that cannot be sent is refused before any connection, with fixed text', async () => {
    const destination = await startDestination();
    const error = await failure(createNodeTransport({ ca: [caA.cert] }).request({ method: 'GET', url: `https://localhost:${destination.port}/`,
      headers: { 'X-Value': 'secret-value-991\r\nInjected: yes' } }));
    expect(error).toMatchObject({ code: 'INVALID_REQUEST' });
    expect(error.message).not.toMatch(/secret-value-991|X-Value/);
    expect(destination.connections).toBe(0);
  });

  test('refuses proxy URLs with credentials and unusable credentials', () => {
    expect(() => createNodeTransport({ proxy: { url: 'http://user:pass@proxy.example.test:3128' } })).toThrow(TransportConfigError);
    expect(() => createNodeTransport({ proxy: { url: 'socks5://proxy.example.test:1080' } })).toThrow(TransportConfigError);
    expect(() => createNodeTransport({ proxy: { url: 'http://proxy.example.test:3128', credentials: { username: 'a:b', password: 'c' } } })).toThrow(TransportConfigError);
  });

  test('an unavailable transport refuses every request with its fixed error', async () => {
    const error = new CaBundleError('network.caFile contains no certificates.');
    await expect(createUnavailableTransport(error).request({ method: 'GET', url: 'https://api.openai.com/' })).rejects.toBe(error);
  });
});

describe('timeouts and size limits', () => {
  test('one deadline covers a destination that never answers', async () => {
    const destination = await startDestination(() => {});
    const started = Date.now();
    const error = await failure(createNodeTransport({ timeoutMs: 300, ca: [caA.cert] }).request({ method: 'GET', url: `https://localhost:${destination.port}/?token=hidden` }));
    expect(error.name).toBe('TimeoutError');
    expect(error.message).toContain('300');
    expect(error.message).not.toContain('hidden');
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  test('the deadline also covers a proxy that never answers CONNECT and a body that stalls', async () => {
    const silent = await startSilentServer();
    await expect(createNodeTransport({ timeoutMs: 300, proxy: { url: `http://127.0.0.1:${silent.port}` } })
      .request({ method: 'GET', url: 'https://api.example.test/' })).rejects.toMatchObject({ name: 'TimeoutError' });
    const destination = await startDestination((_req, res) => { res.writeHead(200, { 'Content-Length': '100' }); res.write('partial'); });
    await expect(createNodeTransport({ timeoutMs: 300, ca: [caA.cert] }).request({ method: 'GET', url: `https://localhost:${destination.port}/` }))
      .rejects.toMatchObject({ name: 'TimeoutError' });
  });

  test('accepts a body exactly at the limit and refuses one byte more, naming only the host', async () => {
    const destination = await startDestination((req, res) => { res.end(req.url === '/four' ? 'abcd' : 'abcde'); });
    const proxy = await startProxy({ routes: { 'api.example.test:443': destination.port } });
    const http = createNodeTransport({ maxBytes: 4, proxy: { url: `http://127.0.0.1:${proxy.port}` }, ca: [caA.cert] });
    expect((await http.request({ method: 'GET', url: 'https://api.example.test/four' })).text).toBe('abcd');
    const error = await failure(http.request({ method: 'GET', url: 'https://api.example.test/five?token=hidden' }));
    expect(error).toMatchObject({ code: 'RESPONSE_TOO_LARGE', name: 'ResponseTooLargeError' });
    expect(error.message).toBe('Response from api.example.test exceeds the 4 byte limit.');
  });

  test('stops reading a large streamed body as soon as it passes the limit', async () => {
    const destination = await startDestination((_req, res) => {
      res.writeHead(200);
      const chunk = Buffer.alloc(64 * 1024, 0x61);
      let sent = 0;
      const pump = () => { while (sent < 400 && res.write(chunk)) sent += 1; if (sent < 400) res.once('drain', pump); else res.end(); };
      pump();
    });
    await expect(createNodeTransport({ maxBytes: 100_000, ca: [caA.cert] }).request({ method: 'GET', url: `https://localhost:${destination.port}/` }))
      .rejects.toMatchObject({ code: 'RESPONSE_TOO_LARGE' });
  });

  test('decodes gzip and counts decompressed bytes against the limit', async () => {
    const destination = await startDestination((req, res) => {
      res.writeHead(200, { 'Content-Encoding': 'gzip' });
      res.end(req.url === '/small' ? gzipSync('hello world') : gzipSync(Buffer.alloc(5_000_000)));
    });
    const http = createNodeTransport({ maxBytes: 100_000, ca: [caA.cert] });
    expect((await http.request({ method: 'GET', url: `https://localhost:${destination.port}/small` })).text).toBe('hello world');
    await expect(http.request({ method: 'GET', url: `https://localhost:${destination.port}/bomb` })).rejects.toMatchObject({ code: 'RESPONSE_TOO_LARGE' });
  });

  test('an empty body labelled as compressed is simply empty', async () => {
    const destination = await startDestination((req, res) => {
      res.writeHead(req.url === '/not-modified' ? 304 : 200, { 'Content-Encoding': 'gzip', ETag: '"v1"' });
      res.end();
    });
    const http = createNodeTransport({ ca: [caA.cert] });
    const notModified = await http.request({ method: 'GET', url: `https://localhost:${destination.port}/not-modified`, headers: { 'If-None-Match': '"v1"' } });
    expect(notModified).toMatchObject({ status: 304, text: '' });
    expect(notModified.headers.etag).toBe('"v1"');
    expect((await http.request({ method: 'GET', url: `https://localhost:${destination.port}/empty` })).text).toBe('');
  });

  test('a damaged compressed body is reported with fixed text', async () => {
    const destination = await startDestination((_req, res) => { res.writeHead(200, { 'Content-Encoding': 'gzip' }); res.end('not gzip at all'); });
    const error = await failure(createNodeTransport({ ca: [caA.cert] }).request({ method: 'GET', url: `https://localhost:${destination.port}/` }));
    expect(error).toMatchObject({ code: 'RESPONSE_INTERRUPTED' });
    expect(error.message).not.toContain('not gzip');
  });
});

// ---------------------------------------------------------------- settings

describe('proxy settings', () => {
  test('keysentry.yaml wins; HTTPS_PROXY credentials are used only for that same proxy', async () => {
    const redactor = createRedactor();
    const same = await resolveProxySettings({ configProxy: 'http://proxy.corp.test:3128',
      env: { HTTPS_PROXY: 'http://alice:s3cret-pass%21@proxy.corp.test:3128' }, redactor });
    expect(same).toMatchObject({ source: 'config', credentialSource: 'env',
      settings: { url: 'http://proxy.corp.test:3128', credentials: { username: 'alice', password: 's3cret-pass!' } } });
    expect(redactor.redact('value s3cret-pass! here')).not.toContain('s3cret-pass!');

    const vault = createFakeVault({ [PROXY_AUTH_VAULT_NAME]: Buffer.from('bob:vault-pass-7781') });
    const other = await resolveProxySettings({ configProxy: 'https://gateway.corp.test',
      env: { HTTPS_PROXY: 'http://alice:s3cret-pass@proxy.corp.test:3128' }, vault, redactor });
    expect(other).toMatchObject({ source: 'config', credentialSource: 'vault',
      settings: { url: 'https://gateway.corp.test:443', credentials: { username: 'bob', password: 'vault-pass-7781' } } });
    expect(redactor.redact('vault-pass-7781')).not.toContain('vault-pass-7781');
  });

  test('HTTPS_PROXY alone works, including the scheme-less form, and NO_PROXY joins network.noProxy', async () => {
    const resolved = await resolveProxySettings({ configNoProxy: ['vault.corp.test'],
      env: { https_proxy: 'proxy.corp.test:8080', NO_PROXY: 'localhost, .internal.test,*.svc.test' } });
    expect(resolved).toMatchObject({ source: 'env', credentialSource: null, settings: { url: 'http://proxy.corp.test:8080', credentials: null } });
    expect(resolved.noProxy).toEqual(['vault.corp.test', 'localhost', '.internal.test', '*.svc.test']);
    expect(await resolveProxySettings({ env: {} })).toEqual({ settings: null, noProxy: [], source: null, credentialSource: null });
  });

  test('a bad proxy setting fails closed without echoing the value', async () => {
    for (const value of ['socks5://user:hunter22@proxy:1080', 'http://user:hunter22@proxy:3128/path', 'http://user:hunter22@']) {
      const error = await failure(resolveProxySettings({ env: { HTTPS_PROXY: value } }));
      expect(error).toBeInstanceOf(TransportConfigError);
      expect(error.message).toContain('HTTPS_PROXY');
      expect(error.message).not.toContain('hunter22');
    }
    await expect(resolveProxySettings({ configProxy: 'http://user:pw@proxy.corp.test:3128', env: {} })).rejects.toThrow(/must not contain credentials/);
    const vault = createFakeVault({ [PROXY_AUTH_VAULT_NAME]: Buffer.from('bad:line\nbreak') });
    await expect(resolveProxySettings({ configProxy: 'http://proxy.corp.test:3128', env: {}, vault })).rejects.toThrow(TransportConfigError);
  });

  test('NO_PROXY matches exact hosts and dot-suffixes only', () => {
    const { entries, ignored } = parseNoProxy(['example.com', '.corp.test', '*.svc.test', 'pinned.test:8443', '10.0.0.0/8', '[::1]:443']);
    expect(ignored).toEqual(['10.0.0.0/8']);
    expect(bypassesProxy('example.com', 443, entries)).toBe(true);
    expect(bypassesProxy('EXAMPLE.com.', 443, entries)).toBe(true);
    expect(bypassesProxy('api.example.com', 443, entries)).toBe(false);
    expect(bypassesProxy('badexample.com', 443, entries)).toBe(false);
    expect(bypassesProxy('a.corp.test', 443, entries)).toBe(true);
    expect(bypassesProxy('corp.test', 443, entries)).toBe(false);
    expect(bypassesProxy('notcorp.test', 443, entries)).toBe(false);
    expect(bypassesProxy('db.svc.test', 443, entries)).toBe(true);
    expect(bypassesProxy('pinned.test', 443, entries)).toBe(false);
    expect(bypassesProxy('pinned.test', 8443, entries)).toBe(true);
    expect(bypassesProxy('::1', 443, entries)).toBe(true);
    expect(bypassesProxy('10.1.2.3', 443, entries)).toBe(false);
    expect(bypassesProxy('anything.test', 443, parseNoProxy(['*']).entries)).toBe(true);
  });
});

describe('custom CA bundle', () => {
  test('accepts PEM certificates with comments, de-duplicates them and describes each', () => {
    const bundle = parseCaBundle(`# Corporate roots\n\n${caA.cert}\r\n${caB.cert}${caA.cert}`, 'certs/corp.pem');
    expect(bundle.path).toBe('certs/corp.pem');
    expect(bundle.pems).toHaveLength(2);
    expect(bundle.certificates.map(item => item.subject)).toEqual(['O=keysentry tests, CN=Test Root A', 'O=keysentry tests, CN=Test Root B']);
    expect(bundle.certificates.every(item => item.isCa)).toBe(true);
  });

  test('rejects anything that is not PEM certificates, without echoing the file', () => {
    const leafKey = apiCert.key;
    const cases: (string | Buffer)[] = [
      `${caA.cert}${leafKey}`,
      `${caA.cert}stray text with a value-123\n`,
      '',
      '# only a comment\n',
      Buffer.from(caA.cert.replace(/-----[^-]+-----|\s/g, ''), 'base64'),
      caA.cert.replace('CERTIFICATE-----\n', 'TRUSTED CERTIFICATE-----\n').replace('END CERTIFICATE', 'END TRUSTED CERTIFICATE'),
      caA.cert.replace(/\n[A-Za-z0-9+/]{10}/, '\n**********'),
      caA.cert.replace('-----END CERTIFICATE-----\n', ''),
      '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n',
    ];
    for (const input of cases) {
      let error: unknown;
      try { parseCaBundle(input); } catch (caught) { error = caught; }
      expect(error).toBeInstanceOf(CaBundleError);
      expect((error as Error).message).not.toMatch(/value-123|PRIVATE KEY|MII/);
    }
  });

  test('reads the file once, relative to the project, and refuses a missing file', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'keysentry-ca-'));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));
    await writeFile(join(dir, 'corp.pem'), caA.cert);
    const bundle = await loadCaBundle('corp.pem', { cwd: dir });
    expect(bundle.certificates).toHaveLength(1);
    await expect(loadCaBundle('missing.pem', { cwd: dir })).rejects.toThrow(/could not be read/);
    await expect(loadCaBundle('.', { cwd: dir })).rejects.toBeInstanceOf(CaBundleError);
  });

  test('adds the extra certificates to the default roots instead of replacing them', () => {
    const trusted = trustedCertificates([caA.cert]);
    expect(trusted).toContain(caA.cert);
    expect(trusted).toContain(tls.rootCertificates[0]);
    expect(trusted.length).toBeGreaterThan(tls.rootCertificates.length);
  });
});

// ---------------------------------------------------------------- offline mode

describe('offline mode', () => {
  test('a signed policy wins over local configuration', () => {
    expect(resolveFeedMode({ configOffline: false, policy: { network: { offline: true } } })).toEqual({ offline: true, source: 'policy' });
    expect(resolveFeedMode({ configOffline: true, policy: null })).toEqual({ offline: true, source: 'config' });
    expect(resolveFeedMode({ configOffline: false, policy: { network: {} } })).toEqual({ offline: false, source: null });
  });

  test('watcher sources and monitor breach feeds make zero feed requests', async () => {
    const offline = resolveFeedMode({ configOffline: true });
    const http = new FakeHttp();
    await Promise.allSettled(selectFeedSources(DEFAULT_SOURCES, offline).map(source => fetchFeed(http, source, {})));
    const state = { seenFeedItems: {}, feedBaselines: {} };
    const ctx = { inventory: { hosts: ['railway', 'vercel'], clusters: [], findings: [] }, hosts: [], providers: [],
      providerCtx: { http, credentials: {}, log: silentLogger }, state, fingerprintKey: Buffer.alloc(32, 1), log: silentLogger };
    expect(await detectBreachFeeds(ctx as never, selectFeedSources(DEFAULT_BREACH_FEEDS, offline))).toEqual([]);
    expect(http.calls).toHaveLength(0);

    // The same calls online do reach the network, so the zero above is the switch, not the harness.
    const online = resolveFeedMode({ configOffline: false });
    await Promise.allSettled(selectFeedSources(DEFAULT_SOURCES, online).map(source => fetchFeed(http, source, {})));
    await detectBreachFeeds(ctx as never, selectFeedSources(DEFAULT_BREACH_FEEDS, online));
    expect(http.calls).toHaveLength(DEFAULT_SOURCES.length + DEFAULT_BREACH_FEEDS.length);
  });

  test('the egress backstop blocks every feed host while configured provider APIs still work', async () => {
    const inner = new FakeHttp().on('GET', /^https:\/\/api\.openai\.com\//, () => json(200, { ok: true }));
    const http = createGuardedHttp(inner, { rules: offlineEgressRules([...EGRESS_RULES, ...rulesForUserFeeds(['https://feeds.example.org/rss'])]) });
    for (const url of [...DEFAULT_SOURCES.map(source => source.url), ...DEFAULT_BREACH_FEEDS.map(feed => feed.url), 'https://feeds.example.org/rss']) {
      await expect(http.request({ method: 'GET', url })).rejects.toBeInstanceOf(EgressBlockedError);
    }
    expect(inner.calls).toHaveLength(0);
    expect((await http.request({ method: 'GET', url: 'https://api.openai.com/v1/models' })).status).toBe(200);
    expect(inner.calls).toHaveLength(1);
  });

  test('the notice states the consequence plainly', () => {
    expect(offlineNotice({ offline: false, source: null })).toBeNull();
    const notice = offlineNotice({ offline: true, source: 'policy' })!;
    expect(notice).toContain('signed team policy');
    expect(notice).toMatch(/does not poll breach feeds or security news/);
    expect(notice).toMatch(/only from your own signals/);
  });
});

// ---------------------------------------------------------------- doctor and status lines

describe('doctor and status reporting', () => {
  const bundle = parseCaBundle(`${caA.cert}${caB.cert}`, 'certs/corp.pem');

  test('reports the proxy without credentials, each trusted certificate and offline mode', async () => {
    const vault = createFakeVault({ [PROXY_AUTH_VAULT_NAME]: Buffer.from('bob:vault-pass-7781') });
    const proxy = await resolveProxySettings({ configProxy: 'http://proxy.corp.test:3128', configNoProxy: ['vault.corp.test'],
      env: { NO_PROXY: '10.0.0.0/8' }, vault });
    const summary = summarizeNetwork({ proxy, ca: bundle, feeds: { offline: true, source: 'config' } });
    const items = networkDoctorItems(summary);
    const text = JSON.stringify(items);
    expect(text).not.toContain('vault-pass-7781');
    expect(items.find(item => item.title === 'Proxy')).toMatchObject({ status: 'ok' });
    expect(items.find(item => item.title === 'Proxy')!.detail).toContain('http://proxy.corp.test:3128');
    expect(items.find(item => item.title === 'Proxy')!.detail).toContain('vault.corp.test');
    expect(items.find(item => item.title === 'No-proxy entries ignored')).toMatchObject({ status: 'warn' });
    expect(items.find(item => item.title === 'Extra certificate authorities')!.detail).toContain('2 extra certificates are trusted from certs/corp.pem');
    expect(items.filter(item => item.title.startsWith('Trusted certificate: ')).map(item => item.title))
      .toEqual(['Trusted certificate: O=keysentry tests, CN=Test Root A', 'Trusted certificate: O=keysentry tests, CN=Test Root B']);
    expect(items.find(item => item.title === 'Offline mode')!.detail).toMatch(/only from your own signals/);
    // Credentials sent to an http:// proxy cross the local network unencrypted.
    expect(items.find(item => item.title === 'Proxy credentials')).toMatchObject({ status: 'warn' });

    const doctor = await runDoctor({ vault: createFakeVault(), credentials: { get: async () => null }, enabledHosts: [], env: {},
      nodeVersion: 'v24.22.1', integrity: { status: 'dev' } as never, sandboxed: false, network: summary });
    expect(doctor.items.filter(item => item.area === 'network').length).toBe(items.length);
  });

  test('fails a broken CA file or a required proxy that is missing', () => {
    const items = networkDoctorItems(summarizeNetwork({ proxy: null, requireProxy: true,
      ca: { path: 'corp.pem', error: 'network.caFile contains no certificates.' }, feeds: { offline: false, source: null } }));
    expect(items.filter(item => item.status === 'fail').map(item => item.title)).toEqual(['Proxy', 'Extra certificate authorities']);
    expect(items.some(item => item.title === 'Offline mode')).toBe(false);
  });

  test('flags an expired certificate and one that is not a certificate authority', () => {
    const summary = summarizeNetwork({ proxy: null, feeds: { offline: false, source: null }, ca: { path: 'x.pem', pems: [],
      certificates: [{ subject: 'CN=Old', issuer: 'CN=Old', validFrom: 'Jan  1 00:00:00 2020 GMT', validTo: 'Jan  1 00:00:00 2021 GMT', fingerprint256: 'AA', isCa: false }] } });
    const item = networkDoctorItems(summary).find(entry => entry.title === 'Trusted certificate: CN=Old')!;
    expect(item.status).toBe('warn');
    expect(item.detail).toMatch(/expired/);
    expect(item.detail).toMatch(/not marked as a certificate authority/);
  });

  test('status lines for the network receipt and watch say when feeds are off', async () => {
    const proxy = await resolveProxySettings({ env: { HTTPS_PROXY: 'http://u:p-123456@proxy.corp.test:3128', NO_PROXY: 'localhost' } });
    const lines = networkStatusLines(summarizeNetwork({ proxy, ca: bundle, feeds: { offline: true, source: 'policy' } }));
    expect(lines).toEqual([
      'Offline mode is on (required by the signed team policy): breach feeds and security news are not contacted.',
      'Requests go through the proxy at http://proxy.corp.test:3128 (from HTTPS_PROXY).',
      'Direct connections, without the proxy: localhost.',
      '2 extra certificates are trusted in addition to Node\'s default roots.',
    ]);
    expect(lines.join('\n')).not.toContain('p-123456');
    expect(networkStatusLines(summarizeNetwork({ proxy: null, feeds: { offline: false, source: null } }))).toEqual([]);
  });

  test('describes what Node itself trusts, and flags certificate checks turned off (review L7)', () => {
    const none = networkDoctorItems(summarizeNetwork({ proxy: null, feeds: { offline: false, source: null }, env: {} }));
    expect(none.find(item => item.title === 'Certificate authorities')!.detail)
      .toBe('keysentry trusts Node\'s bundled roots; no network.caFile is configured. The operating system\'s certificate store is used only when Node runs with --use-system-ca.');
    const env = { NODE_EXTRA_CA_CERTS: '/etc/corp.pem', NODE_OPTIONS: '--use-system-ca', NODE_TLS_REJECT_UNAUTHORIZED: '0' };
    const summary = summarizeNetwork({ proxy: null, feeds: { offline: false, source: null }, env });
    expect(summary.nodeTrust).toEqual({ extraCaCerts: true, systemCa: true, tlsChecksOff: true });
    const items = networkDoctorItems(summary);
    expect(items.find(item => item.title === 'Certificate authorities')!.detail).toContain('the certificates in NODE_EXTRA_CA_CERTS and the operating system');
    expect(items.find(item => item.title === 'Certificate checks turned off')).toMatchObject({ status: 'warn' });
    expect(networkStatusLines(summary)).toContain('NODE_TLS_REJECT_UNAUTHORIZED=0 is set; keysentry\'s own connections ignore it and still check certificates.');
  });

  test('usesProxy makes the transport\'s own decision for connections that cannot be tunnelled (review L1)', () => {
    const env = { HTTPS_PROXY: '', https_proxy: 'http://proxy.corp.test:3128', NO_PROXY: 'corp.test,.internal.test,logs.corp.test:6514' };
    expect(usesProxy('corp.test', 443, { env })).toBe(false);
    expect(usesProxy('logs.corp.test', 443, { env })).toBe(true); // a bare entry is one exact host
    expect(usesProxy('logs.corp.test', 6514, { env })).toBe(false);
    expect(usesProxy('a.internal.test', 443, { env })).toBe(false);
    expect(usesProxy('corp.test', 443, { env, requireProxy: true })).toBe(true);
    expect(usesProxy('corp.test', 443, { env: {} })).toBe(false);
    expect(usesProxy('corp.test', 443, { env: {}, configProxy: 'http://proxy.corp.test:3128' })).toBe(true);
  });
});
