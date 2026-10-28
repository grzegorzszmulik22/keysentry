import { X509Certificate } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { request as httpsRequest } from 'node:https';
import { validateHeaderName, validateHeaderValue, type IncomingMessage } from 'node:http';
import { connect as netConnect, isIP, type Socket } from 'node:net';
import { resolve } from 'node:path';
import { Readable } from 'node:stream';
import * as tls from 'node:tls';
import { createBrotliDecompress, createGunzip, createInflate } from 'node:zlib';
import type { HttpClient, HttpRequest, HttpResponse, Redactor, Vault } from '../types.js';
import { createRedactor } from '../core/redact.js';
import { makeResponse, ResponseTooLargeError } from '../http.js';
import { BUILD_VERSION } from '../release/build-info.js';
import type { FeedMode } from '../feeds/offline.js';

/**
 * Enterprise transport (phase 5): HTTPS through an optional HTTP CONNECT proxy, with extra trusted certificate
 * authorities added to (never replacing) Node's default roots. Same contract and limits as createFetchHttp: redirects
 * are returned, not followed; the body is capped at maxBytes; one deadline covers the whole exchange. The egress guard
 * wraps this client unchanged, so the allow-list applies to the destination host and never to the proxy.
 */

/** Vault credential (`keysentry vault set KEYSENTRY_PROXY_AUTH`) holding `username:password` for the proxy. */
export const PROXY_AUTH_CREDENTIAL = 'KEYSENTRY_PROXY_AUTH';
export const PROXY_AUTH_VAULT_NAME = `cred/${PROXY_AUTH_CREDENTIAL}`;
export const MAX_CA_FILE_BYTES = 4 * 1024 * 1024;
export const MAX_CA_CERTIFICATES = 1000;
const MAX_CONNECT_RESPONSE_BYTES = 16 * 1024;

export interface ProxyCredentials { username: string; password: string }
export interface ProxySettings {
  /** `http://host:port` or `https://host:port`; never carries userinfo. */
  url: string;
  /** Sent only in the CONNECT request's Proxy-Authorization header, never to a destination. */
  credentials?: ProxyCredentials | null;
}

export interface NodeTransportOptions {
  proxy?: ProxySettings | null;
  /** Exact hosts, `.suffix` entries (subdomains), `host:port`, or `*`. */
  noProxy?: readonly string[];
  /** Extra PEM certificates, trusted in addition to the default roots (see loadCaBundle). */
  ca?: readonly string[] | null;
  timeoutMs?: number;
  maxBytes?: number;
  /** A signed team policy can require that every request goes through the proxy. */
  requireProxy?: boolean;
  /**
   * Called once per request that goes through the proxy: true when the connection to the proxy opened, false when it
   * failed or the request timed out before it opened. A deployed watcher counts these for its health (see
   * createProxyHealth).
   */
  onProxyResult?: (reached: boolean) => void;
}

/** How many failed connections to the proxy in a row make a deployed watcher report itself unhealthy. */
export const PROXY_FAILURES_UNHEALTHY = 3;

/**
 * Consecutive failed connections to the proxy (review EA H1). Pass `record` as `onProxyResult`; `unreachable()`
 * is true after `PROXY_FAILURES_UNHEALTHY` failures in a row, until a connection to the proxy opens again.
 */
export function createProxyHealth(threshold = PROXY_FAILURES_UNHEALTHY): { record(reached: boolean): void; unreachable(): boolean } {
  let failures = 0;
  return {
    record(reached) { failures = reached ? 0 : failures + 1; },
    unreachable: () => failures >= threshold,
  };
}

export type TransportErrorCode =
  | 'INVALID_URL' | 'PLAIN_HTTP_REFUSED' | 'INVALID_REQUEST' | 'PROXY_REQUIRED' | 'PROXY_UNREACHABLE'
  | 'PROXY_TLS_FAILED' | 'PROXY_AUTH_REQUIRED' | 'PROXY_TUNNEL_REFUSED' | 'PROXY_PROTOCOL' | 'CONNECT_FAILED'
  | 'TLS_VERIFY_FAILED' | 'TLS_HANDSHAKE_FAILED' | 'RESPONSE_INVALID' | 'RESPONSE_INTERRUPTED';

/** Fixed, secret-free text. `reason` is at most a system error code such as ECONNREFUSED. */
export class TransportError extends Error {
  readonly reason?: string;
  constructor(readonly code: TransportErrorCode, message: string, reason?: unknown) {
    super(message);
    this.name = 'TransportError';
    if (typeof reason === 'string' && /^[A-Z0-9_]{1,64}$/.test(reason)) this.reason = reason;
  }
}

/** Named like the DOMException fetch raises, so existing timeout checks keep working. */
export class TransportTimeoutError extends Error {
  readonly code = 'TIMEOUT';
  constructor(host: string, timeoutMs: number) {
    super(`The request to ${host} did not finish within ${timeoutMs} ms.`);
    this.name = 'TimeoutError';
  }
}

/** Proxy or trust settings that cannot be used. The message names the setting, never its value. */
export class TransportConfigError extends Error {
  readonly code = 'NETWORK_CONFIG';
  constructor(message: string) { super(message); this.name = 'TransportConfigError'; }
}

export class CaBundleError extends Error {
  readonly code = 'CA_BUNDLE_INVALID';
  constructor(message: string) { super(message); this.name = 'CaBundleError'; }
}

// ---------------------------------------------------------------- custom certificate authorities

export interface CaCertificateInfo {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  fingerprint256: string;
  /** Marked as a certificate authority (basicConstraints CA:TRUE). Other certificates are trusted only as themselves. */
  isCa: boolean;
}

export interface CaBundle {
  /** The path as configured (relative to the project), for display. */
  path: string;
  /** Canonical PEM of each distinct certificate, ready for createNodeTransport({ ca }). */
  pems: string[];
  certificates: CaCertificateInfo[];
}

function oneLine(value: string, max = 200): string {
  const flat = value.split('\n').map(part => part.trim()).filter(Boolean).join(', ')
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').replace(/\p{Zl}|\p{Zp}/gu, ' ');
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

/**
 * Accept only PEM CERTIFICATE blocks, blank lines and `#` comment lines. Anything else (a private key, another PEM
 * type, DER bytes, stray text, a damaged block) rejects the whole file so a mistake never widens or weakens trust.
 */
export function parseCaBundle(input: string | Buffer, path = 'network.caFile'): CaBundle {
  const bytes = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  if (bytes.length > MAX_CA_FILE_BYTES) throw new CaBundleError(`network.caFile is larger than ${MAX_CA_FILE_BYTES} bytes.`);
  let text: string;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { throw new CaBundleError('network.caFile must be a text file of PEM certificates, not binary (DER) data.'); }
  if (text.includes('\0')) throw new CaBundleError('network.caFile must be a text file of PEM certificates, not binary (DER) data.');

  const pems: string[] = [];
  const certificates: CaCertificateInfo[] = [];
  const seen = new Set<string>();
  let body: string[] | null = null;
  const damaged = () => new CaBundleError(`Certificate ${pems.length + 1} in network.caFile is damaged. Export the certificate again in PEM format.`);
  for (const raw of text.replace(/^﻿/, '').split(/\r?\n/)) {
    const line = raw.trim();
    if (body === null) {
      if (line === '' || line.startsWith('#')) continue;
      if (line === '-----BEGIN CERTIFICATE-----') { body = []; continue; }
      if (/^-----BEGIN [^-]*-----$/.test(line)) {
        throw new CaBundleError('network.caFile contains a PEM block that is not a certificate. Keep only CERTIFICATE blocks; a private key never belongs in this file.');
      }
      throw new CaBundleError('network.caFile must contain only PEM certificates. Remove any other text.');
    }
    if (line === '-----END CERTIFICATE-----') {
      const encoded = body.join('');
      body = null;
      const der = Buffer.from(encoded, 'base64');
      if (!encoded || der.toString('base64') !== encoded) throw damaged();
      let certificate: X509Certificate;
      try { certificate = new X509Certificate(der); } catch { throw damaged(); }
      if (seen.has(certificate.fingerprint256)) continue;
      seen.add(certificate.fingerprint256);
      if (pems.length >= MAX_CA_CERTIFICATES) throw new CaBundleError(`network.caFile contains more than ${MAX_CA_CERTIFICATES} certificates.`);
      pems.push(certificate.toString());
      certificates.push({
        subject: oneLine(certificate.subject), issuer: oneLine(certificate.issuer),
        validFrom: certificate.validFrom, validTo: certificate.validTo,
        fingerprint256: certificate.fingerprint256, isCa: certificate.ca,
      });
      continue;
    }
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(line)) throw damaged();
    body.push(line);
  }
  if (body !== null) throw damaged();
  if (pems.length === 0) throw new CaBundleError('network.caFile contains no certificates.');
  return { path, pems, certificates };
}

/** Read the bundle once at startup. `caFile` is relative to the project directory unless absolute. */
export async function loadCaBundle(caFile: string, options: { cwd: string }): Promise<CaBundle> {
  const path = resolve(options.cwd, caFile);
  let bytes: Buffer;
  try {
    const info = await stat(path);
    if (!info.isFile()) throw new CaBundleError('network.caFile must name a file.');
    if (info.size > MAX_CA_FILE_BYTES) throw new CaBundleError(`network.caFile is larger than ${MAX_CA_FILE_BYTES} bytes.`);
    bytes = await readFile(path);
  } catch (error) {
    if (error instanceof CaBundleError) throw error;
    throw new CaBundleError('network.caFile could not be read. Check the path (relative to the project) and its permissions.');
  }
  return parseCaBundle(bytes, caFile);
}

/** Node's default roots (bundled, NODE_EXTRA_CA_CERTS, and the OS store with --use-system-ca), then the extras. */
export function trustedCertificates(extra: readonly string[]): string[] {
  const getter = (tls as { getCACertificates?: (type?: 'default') => string[] }).getCACertificates;
  const defaults = typeof getter === 'function' ? getter('default') : [...tls.rootCertificates];
  return [...new Set([...defaults, ...extra])];
}

// ---------------------------------------------------------------- proxy settings

interface ParsedProxy {
  protocol: 'http:' | 'https:';
  /** Hostname without IPv6 brackets. */
  host: string;
  port: number;
  /** scheme://host:port with no userinfo; used for comparisons and display. */
  origin: string;
  credentials: ProxyCredentials | null;
}

function parseProxyUrl(value: string, setting: string): ParsedProxy {
  const trimmed = value.trim();
  // A scheme-less HTTPS_PROXY such as "proxy.corp:3128" means an HTTP proxy, as in curl and Go.
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  let url: URL;
  try { url = new URL(candidate); }
  catch { throw new TransportConfigError(`${setting} is not a valid proxy URL. Use http://host:port or https://host:port.`); }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new TransportConfigError(`${setting} uses an unsupported proxy type. Use an http:// or https:// proxy.`);
  }
  if (!url.hostname || (url.pathname !== '' && url.pathname !== '/') || url.search || url.hash) {
    throw new TransportConfigError(`${setting} is not a valid proxy URL. Use http://host:port or https://host:port.`);
  }
  let credentials: ProxyCredentials | null = null;
  if (url.username || url.password) {
    try { credentials = { username: decodeURIComponent(url.username), password: decodeURIComponent(url.password) }; }
    catch { throw new TransportConfigError(`${setting} has credentials that could not be decoded.`); }
  }
  const protocol = url.protocol;
  const port = url.port ? Number(url.port) : protocol === 'https:' ? 443 : 80;
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  const authority = isIP(host) === 6 ? `[${host}]` : host;
  return { protocol, host, port, origin: `${protocol}//${authority}:${port}`, credentials };
}

function checkCredentials(credentials: ProxyCredentials, setting: string): ProxyCredentials {
  // RFC 7617: the user-id cannot contain a colon; control characters cannot be sent safely.
  if (credentials.username.includes(':') || /[\u0000-\u001f\u007f]/.test(credentials.username + credentials.password)) {
    throw new TransportConfigError(`${setting} has proxy credentials keysentry cannot send. Use username:password without control characters, and no colon in the username.`);
  }
  return credentials;
}

export interface ResolvedProxy {
  /** Pass to createNodeTransport({ proxy }). Null when no proxy is configured. */
  settings: ProxySettings | null;
  /** Union of network.noProxy and NO_PROXY/no_proxy. */
  noProxy: string[];
  source: 'config' | 'env' | null;
  credentialSource: 'env' | 'vault' | null;
}

function envValue(env: Readonly<Record<string, string | undefined>>, ...names: string[]): string | undefined {
  for (const name of names) {
    const value = env[name]?.trim();
    if (value) return value;
  }
  return undefined;
}

/** The union of network.noProxy and NO_PROXY (or no_proxy, when NO_PROXY is unset or empty). */
export function noProxyList(configNoProxy: readonly string[] | undefined, env: Readonly<Record<string, string | undefined>>): string[] {
  return [...new Set([...(configNoProxy ?? []),
    ...(envValue(env, 'NO_PROXY', 'no_proxy') ?? '').split(/[\s,]+/)].map(entry => entry.trim()).filter(Boolean))];
}

/**
 * Whether a connection to host:port goes through the proxy, decided exactly as the transport decides it: the same proxy
 * selection (network.proxy, then a non-empty HTTPS_PROXY or https_proxy), the same no-proxy list and matching. For
 * connections that cannot be tunnelled (syslog over TLS), which must then be refused rather than made directly. A proxy
 * setting that cannot be parsed still counts (the transport refuses everything then), and a policy that requires the
 * proxy covers every connection.
 */
export function usesProxy(host: string, port: number, input: {
  configProxy?: string;
  configNoProxy?: readonly string[];
  env: Readonly<Record<string, string | undefined>>;
  requireProxy?: boolean;
}): boolean {
  if (input.requireProxy) return true;
  if (!input.configProxy && !envValue(input.env, 'HTTPS_PROXY', 'https_proxy')) return false;
  return !bypassesProxy(host, port, parseNoProxy(noProxyList(input.configNoProxy, input.env)).entries);
}

/**
 * keysentry.yaml's network.proxy wins; otherwise HTTPS_PROXY (or https_proxy). Credentials come from that
 * environment URL's userinfo only when it names the same proxy, otherwise from the vault; never from keysentry.yaml.
 * Every credential form is registered with the redactor before this returns.
 */
export async function resolveProxySettings(input: {
  configProxy?: string;
  configNoProxy?: readonly string[];
  env: Readonly<Record<string, string | undefined>>;
  vault?: Pick<Vault, 'get'>;
  redactor?: Pick<Redactor, 'register'>;
}): Promise<ResolvedProxy> {
  const rawEnv = envValue(input.env, 'HTTPS_PROXY', 'https_proxy');
  // Register before parsing so even an unparseable value with credentials stays out of output.
  if (rawEnv && /@/.test(rawEnv)) input.redactor?.register(rawEnv);
  const fromEnv = rawEnv ? parseProxyUrl(rawEnv, 'HTTPS_PROXY') : null;
  if (fromEnv?.credentials) {
    input.redactor?.register(fromEnv.credentials.password);
    input.redactor?.register(`${fromEnv.credentials.username}:${fromEnv.credentials.password}`);
  }
  const fromConfig = input.configProxy ? parseProxyUrl(input.configProxy, 'network.proxy') : null;
  if (fromConfig?.credentials) {
    throw new TransportConfigError(`network.proxy must not contain credentials. Store them with keysentry vault set ${PROXY_AUTH_CREDENTIAL} instead.`);
  }
  const noProxy = noProxyList(input.configNoProxy, input.env);
  const chosen = fromConfig ?? fromEnv;
  if (!chosen) return { settings: null, noProxy, source: null, credentialSource: null };

  let credentials: ProxyCredentials | null = null;
  let credentialSource: ResolvedProxy['credentialSource'] = null;
  if (fromEnv?.credentials && fromEnv.origin === chosen.origin) {
    credentials = checkCredentials(fromEnv.credentials, 'HTTPS_PROXY');
    credentialSource = 'env';
  } else if (input.vault) {
    const stored = await input.vault.get(PROXY_AUTH_VAULT_NAME);
    if (stored !== null) {
      try {
        const value = stored.toString('utf8');
        input.redactor?.register(value);
        const split = value.indexOf(':');
        const parsed = split === -1 ? { username: value, password: '' } : { username: value.slice(0, split), password: value.slice(split + 1) };
        input.redactor?.register(parsed.password);
        credentials = checkCredentials(parsed, PROXY_AUTH_CREDENTIAL);
        credentialSource = 'vault';
      } finally { stored.fill(0); }
    }
  }
  if (credentials) input.redactor?.register(basicAuthorization(credentials));
  return {
    settings: { url: chosen.origin, credentials }, noProxy,
    source: fromConfig ? 'config' : 'env', credentialSource,
  };
}

function basicAuthorization(credentials: ProxyCredentials): string {
  return `Basic ${Buffer.from(`${credentials.username}:${credentials.password}`, 'utf8').toString('base64')}`;
}

// ---------------------------------------------------------------- NO_PROXY

type NoProxyEntry = { kind: 'all' } | { kind: 'exact' | 'suffix'; host: string; port?: number };

/** Exact hosts, `.example.com` or `*.example.com` (subdomains only), optional `:port`, and `*`. CIDR is not supported. */
export function parseNoProxy(values: readonly string[]): { entries: NoProxyEntry[]; ignored: string[] } {
  const entries: NoProxyEntry[] = [];
  const ignored: string[] = [];
  for (const value of values.flatMap(item => item.split(/[\s,]+/))) {
    let entry = value.trim().toLowerCase();
    if (!entry) continue;
    if (entry === '*') { entries.push({ kind: 'all' }); continue; }
    let port: number | undefined;
    const bracketed = /^\[([0-9a-f:.]+)\](?::(\d{1,5}))?$/.exec(entry);
    if (bracketed) {
      entry = bracketed[1]!;
      if (bracketed[2] !== undefined) port = Number(bracketed[2]);
    } else if (entry.split(':').length === 2) {
      const [host, portText] = entry.split(':') as [string, string];
      if (!/^\d{1,5}$/.test(portText)) { ignored.push(value.trim()); continue; }
      entry = host; port = Number(portText);
    }
    if (port !== undefined && (port < 1 || port > 65535)) { ignored.push(value.trim()); continue; }
    if (entry.includes('/') || !entry) { ignored.push(value.trim()); continue; }
    if (entry.startsWith('*.')) entry = entry.slice(1);
    entry = entry.replace(/\.$/, '');
    if (entry.startsWith('.')) {
      if (entry.length < 2 || entry.includes('*')) { ignored.push(value.trim()); continue; }
      entries.push({ kind: 'suffix', host: entry, ...(port === undefined ? {} : { port }) });
    } else {
      if (entry.includes('*')) { ignored.push(value.trim()); continue; }
      entries.push({ kind: 'exact', host: entry, ...(port === undefined ? {} : { port }) });
    }
  }
  return { entries, ignored };
}

export function bypassesProxy(host: string, port: number, entries: readonly NoProxyEntry[]): boolean {
  const name = host.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  return entries.some(entry => {
    if (entry.kind === 'all') return true;
    if (entry.port !== undefined && entry.port !== port) return false;
    return entry.kind === 'exact' ? name === entry.host : name.endsWith(entry.host);
  });
}

// ---------------------------------------------------------------- transport

const STRIPPED_HEADERS = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'keep-alive', 'upgrade',
  'te', 'trailer', 'proxy-authorization', 'proxy-connection']);
const VERIFY_CODES = /CERT|SELF_SIGNED|UNABLE_TO_|ALTNAME|ISSUER|VERIFY|CHAIN|PATH_LENGTH|INVALID_PURPOSE|KEY_USAGE/;
const noop = (): void => {};
type Destroyable = { destroy(error?: Error): unknown; on(event: 'error', listener: (error: Error) => void): unknown };

function errorCode(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'code' in error && typeof error.code === 'string' ? error.code : undefined;
}

function displayHost(host: string): string {
  return createRedactor().redact(host) || '(unparseable)';
}

/** A transport that refuses every request with one fixed error, so a broken proxy or CA setting fails closed. */
export function createUnavailableTransport(error: Error): HttpClient {
  return { async request() { throw error; } };
}

export function createNodeTransport(options: NodeTransportOptions = {}): HttpClient {
  const timeoutMs = options.timeoutMs ?? 30_000;
  const maxBytes = options.maxBytes ?? 16 * 1024 * 1024;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new TypeError('The request timeout must be a positive whole number of milliseconds.');
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) throw new TypeError('The response size limit must be a positive whole number of bytes.');
  let proxy: ParsedProxy | null = null;
  if (options.proxy) {
    proxy = parseProxyUrl(options.proxy.url, 'The proxy URL');
    if (proxy.credentials) throw new TransportConfigError('Pass proxy credentials separately from the proxy URL.');
    proxy.credentials = options.proxy.credentials ? checkCredentials(options.proxy.credentials, 'The proxy credentials') : null;
  }
  if (options.requireProxy && !proxy) {
    throw new TransportConfigError('The team policy requires a proxy, but none is configured. Set network.proxy in keysentry.yaml or HTTPS_PROXY.');
  }
  const { entries: bypass } = parseNoProxy(options.noProxy ?? []);
  let secureContext: tls.SecureContext | undefined;
  if (options.ca?.length) {
    for (const pem of options.ca) {
      try { new X509Certificate(pem); } catch { throw new CaBundleError('An extra trusted certificate could not be read.'); }
    }
    secureContext = tls.createSecureContext({ ca: trustedCertificates(options.ca) });
  }
  const proxyAuthorization = proxy?.credentials ? basicAuthorization(proxy.credentials) : null;
  const userAgent = `keysentry/${BUILD_VERSION}`;

  return {
    async request(req: HttpRequest): Promise<HttpResponse> {
      let url: URL;
      try { url = new URL(req.url); } catch { throw new TransportError('INVALID_URL', 'The request URL could not be read.'); }
      const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
      const shown = displayHost(host);
      if (url.protocol !== 'https:') throw new TransportError('PLAIN_HTTP_REFUSED', `Only HTTPS requests are allowed; a request to ${shown} was refused.`);
      if (url.username || url.password) throw new TransportError('INVALID_REQUEST', 'Request URLs cannot carry credentials.');
      if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) throw new TransportError('INVALID_REQUEST', 'Unsupported request method.');
      if (req.method === 'GET' && req.body !== undefined) throw new TransportError('INVALID_REQUEST', 'A GET request cannot have a body.');
      const port = url.port ? Number(url.port) : 443;
      const viaProxy = proxy !== null && !bypassesProxy(host, port, bypass);
      let proxyReported = false;
      const reportProxy = (reached: boolean) => {
        if (!viaProxy || proxyReported) return;
        proxyReported = true;
        try { options.onProxyResult?.(reached); } catch { /* health bookkeeping never fails a request */ }
      };
      if (options.requireProxy && !viaProxy) {
        throw new TransportError('PROXY_REQUIRED', `The team policy requires the proxy, but ${shown} is on the no-proxy list. Remove it from NO_PROXY or network.noProxy.`);
      }
      const authority = isIP(host) === 6 ? `[${host}]` : host;
      const headers = requestHeaders(req, port === 443 ? authority : `${authority}:${port}`, userAgent);

      const streams = new Set<Destroyable>();
      let finished = false;
      const track = <T extends Destroyable>(stream: T): T => {
        streams.add(stream);
        // A late socket error must never become an unhandled 'error' event.
        stream.on('error', noop);
        // A step that resolves after the deadline must not leave a connection open.
        if (finished) stream.destroy();
        return stream;
      };
      let timer: NodeJS.Timeout | undefined;
      let timedOut = false;
      const deadline = new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          timedOut = true;
          // A request that timed out before the proxy connection opened counts as a failed connection to the proxy.
          reportProxy(false);
          for (const stream of streams) stream.destroy();
          reject(new TransportTimeoutError(shown, timeoutMs));
        }, timeoutMs);
      });
      deadline.catch(noop);

      async function exchange(): Promise<HttpResponse> {
        let socket: tls.TLSSocket;
        if (viaProxy) {
          const tunnel = await openTunnel(proxy!, authority, port, shown);
          socket = await startTls({ socket: tunnel }, host, shown);
        } else {
          socket = await startTls({ host, port }, host, shown);
        }
        return send(socket);
      }

      async function connectProxy(target: ParsedProxy): Promise<Socket> {
        if (target.protocol === 'https:') {
          const socket = track(tls.connect({
            host: target.host, port: target.port, secureContext, rejectUnauthorized: true, ALPNProtocols: ['http/1.1'],
            ...(isIP(target.host) ? {} : { servername: target.host }),
          }));
          try { await settled(socket, 'secureConnect'); }
          catch (error) {
            reportProxy(false);
            const code = errorCode(error);
            if (code && VERIFY_CODES.test(code)) {
              throw new TransportError('PROXY_TLS_FAILED', "The proxy's certificate could not be verified. If it is issued by your own certificate authority, add it with network.caFile.", code);
            }
            throw new TransportError('PROXY_UNREACHABLE', 'Could not connect to the proxy.', code);
          }
          if (!socket.authorized) { reportProxy(false); throw new TransportError('PROXY_TLS_FAILED', "The proxy's certificate could not be verified."); }
          reportProxy(true);
          return socket;
        }
        const socket = track(netConnect({ host: target.host, port: target.port }));
        try { await settled(socket, 'connect'); }
        catch (error) { reportProxy(false); throw new TransportError('PROXY_UNREACHABLE', 'Could not connect to the proxy.', errorCode(error)); }
        reportProxy(true);
        return socket;
      }

      async function openTunnel(target: ParsedProxy, destination: string, destinationPort: number, label: string): Promise<Socket> {
        const socket = await connectProxy(target);
        const lines = [`CONNECT ${destination}:${destinationPort} HTTP/1.1`, `Host: ${destination}:${destinationPort}`, `User-Agent: ${userAgent}`];
        if (proxyAuthorization) lines.push(`Proxy-Authorization: ${proxyAuthorization}`);
        socket.write(`${lines.join('\r\n')}\r\n\r\n`);
        const status = await readConnectResponse(socket);
        if (status === 407) {
          throw new TransportError('PROXY_AUTH_REQUIRED', target.credentials
            ? 'The proxy refused the credentials keysentry sent. Check the proxy credentials in HTTPS_PROXY or the vault.'
            : `The proxy asks for credentials. Store them with keysentry vault set ${PROXY_AUTH_CREDENTIAL}, or include them in HTTPS_PROXY.`);
        }
        if (status < 200 || status > 299) throw new TransportError('PROXY_TUNNEL_REFUSED', `The proxy refused the connection to ${label} (HTTP ${status}).`);
        return socket;
      }

      async function startTls(target: { socket: Socket } | { host: string; port: number }, name: string, label: string): Promise<tls.TLSSocket> {
        const socket = track(tls.connect({
          ...target, host: name, secureContext, rejectUnauthorized: true, ALPNProtocols: ['http/1.1'],
          ...(isIP(name) ? {} : { servername: name }),
        }));
        try { await settled(socket, 'secureConnect'); }
        catch (error) {
          const code = errorCode(error);
          if (code && VERIFY_CODES.test(code)) {
            throw new TransportError('TLS_VERIFY_FAILED', `The certificate for ${label} could not be verified. If your network inspects TLS, add its certificate authority with network.caFile.`, code);
          }
          if ('socket' in target) throw new TransportError('TLS_HANDSHAKE_FAILED', `A secure connection to ${label} through the proxy could not be set up.`, code);
          throw new TransportError('CONNECT_FAILED', `Could not connect to ${label}.`, code);
        }
        if (!socket.authorized) throw new TransportError('TLS_VERIFY_FAILED', `The certificate for ${label} could not be verified.`);
        return socket;
      }

      async function send(socket: tls.TLSSocket): Promise<HttpResponse> {
        const outgoing = httpsRequest({ method: req.method, path: `${url.pathname}${url.search}`, headers, setHost: false,
          createConnection: () => socket });
        track(outgoing);
        const response = await new Promise<IncomingMessage>((fulfil, reject) => {
          outgoing.once('response', fulfil);
          outgoing.once('error', error => reject(new TransportError('RESPONSE_INVALID', `The response from ${shown} could not be read.`, errorCode(error))));
          outgoing.end(req.body);
        });
        track(response);
        const responseHeaders: Record<string, string> = {};
        for (const [name, value] of Object.entries(response.headers)) {
          if (value !== undefined) responseHeaders[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : value;
        }
        const encoding = (responseHeaders['content-encoding'] ?? '').trim().toLowerCase();
        const makeDecoder = response.statusCode === 204 || response.statusCode === 304 ? null
          : encoding === 'gzip' || encoding === 'x-gzip' ? createGunzip
            : encoding === 'deflate' ? createInflate : encoding === 'br' ? createBrotliDecompress : null;
        const text = new TextDecoder();
        let content = '';
        let bytes = 0;
        try {
          // Peek first: zlib rejects an empty stream, while an empty encoded body is simply empty.
          const raw = nonEmptyChunks(response);
          const first = await raw.next();
          let body: AsyncIterable<Buffer> | Iterable<Buffer> = [];
          if (!first.done) {
            const rest = (async function* () { yield first.value; yield* raw; })();
            if (makeDecoder) {
              const source = track(Readable.from(rest));
              const decoder = track(makeDecoder());
              source.on('error', error => decoder.destroy(error));
              body = source.pipe(decoder);
            } else {
              body = rest;
            }
          }
          for await (const chunk of body) {
            const buffer = chunk as Buffer;
            bytes += buffer.byteLength;
            if (bytes > maxBytes) throw new ResponseTooLargeError(host, maxBytes);
            content += text.decode(buffer, { stream: true });
          }
          content += text.decode();
        } catch (error) {
          if (error instanceof ResponseTooLargeError) throw error;
          throw new TransportError('RESPONSE_INTERRUPTED', `The response from ${shown} ended early or could not be decoded.`, errorCode(error));
        }
        return makeResponse(response.statusCode ?? 0, content, responseHeaders);
      }

      try {
        return await Promise.race([exchange(), deadline]);
      } catch (error) {
        if (timedOut) throw new TransportTimeoutError(shown, timeoutMs);
        throw error;
      } finally {
        finished = true;
        clearTimeout(timer);
        for (const stream of streams) stream.destroy();
      }
    },
  };
}

async function* nonEmptyChunks(response: IncomingMessage): AsyncGenerator<Buffer> {
  for await (const chunk of response) {
    const buffer = chunk as Buffer;
    if (buffer.byteLength) yield buffer;
  }
}

function requestHeaders(req: HttpRequest, hostHeader: string, userAgent: string): Record<string, string> {
  const headers: Record<string, string> = { Host: hostHeader };
  const present = new Set<string>();
  for (const [name, value] of Object.entries(req.headers ?? {})) {
    const lower = name.toLowerCase();
    if (STRIPPED_HEADERS.has(lower)) continue;
    // Checked before any connection opens; Node's own message would name the header, so use fixed text.
    try { validateHeaderName(name); validateHeaderValue(name, value); }
    catch { throw new TransportError('INVALID_REQUEST', 'A request header contains characters that cannot be sent.'); }
    present.add(lower);
    headers[name] = value;
  }
  // Defaults that fetch also supplies; some APIs (GitHub) reject requests without a User-Agent.
  if (!present.has('user-agent')) headers['User-Agent'] = userAgent;
  if (!present.has('accept')) headers.Accept = '*/*';
  if (req.body !== undefined) {
    if (!present.has('content-type')) headers['Content-Type'] = 'text/plain;charset=UTF-8';
    headers['Content-Length'] = String(Buffer.byteLength(req.body, 'utf8'));
  } else if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
    headers['Content-Length'] = '0';
  }
  return headers;
}

function settled(socket: Socket, event: 'connect' | 'secureConnect'): Promise<void> {
  return new Promise((fulfil, reject) => {
    const onEvent = () => { cleanup(); fulfil(); };
    const onError = (error: Error) => { cleanup(); reject(error); };
    const onClose = () => { cleanup(); reject(Object.assign(new Error('closed'), { code: 'ECONNRESET' })); };
    const cleanup = () => {
      socket.removeListener(event, onEvent); socket.removeListener('error', onError); socket.removeListener('close', onClose);
    };
    socket.once(event, onEvent); socket.once('error', onError); socket.once('close', onClose);
  });
}

/** Read the proxy's reply to CONNECT without consuming any tunnelled bytes. */
function readConnectResponse(socket: Socket): Promise<number> {
  return new Promise((fulfil, reject) => {
    let buffered = Buffer.alloc(0);
    const protocolError = () => new TransportError('PROXY_PROTOCOL', 'The proxy sent a reply keysentry could not read.');
    const cleanup = () => {
      socket.removeListener('readable', onReadable); socket.removeListener('error', onError);
      socket.removeListener('end', onEnd); socket.removeListener('close', onEnd);
    };
    const onError = (error: Error) => {
      cleanup();
      reject(new TransportError('PROXY_UNREACHABLE', 'The connection to the proxy failed.', errorCode(error)));
    };
    const onEnd = () => { cleanup(); reject(new TransportError('PROXY_PROTOCOL', 'The proxy closed the connection before opening a tunnel.')); };
    const onReadable = () => {
      let chunk: Buffer | null;
      while ((chunk = socket.read() as Buffer | null) !== null) {
        buffered = Buffer.concat([buffered, chunk]);
        const end = buffered.indexOf('\r\n\r\n');
        if (end === -1) {
          if (buffered.length > MAX_CONNECT_RESPONSE_BYTES) { cleanup(); reject(protocolError()); return; }
          continue;
        }
        cleanup();
        const lineEnd = buffered.indexOf('\r\n');
        const match = /^HTTP\/1\.[01] (\d{3})(?: |$)/.exec(buffered.subarray(0, lineEnd).toString('latin1'));
        if (!match) { reject(protocolError()); return; }
        const status = Number(match[1]);
        // TLS clients speak first, so a proxy that sends bytes after a 2xx is not a plain tunnel.
        if (status >= 200 && status <= 299 && end + 4 !== buffered.length) { reject(protocolError()); return; }
        fulfil(status);
        return;
      }
    };
    socket.on('readable', onReadable); socket.once('error', onError);
    socket.once('end', onEnd); socket.once('close', onEnd);
  });
}

// ---------------------------------------------------------------- status for doctor, `network` and `watch`

export interface NetworkSummary {
  proxy: { origin: string; source: 'config' | 'env'; credentials: 'env' | 'vault' | 'none' } | null;
  noProxy: string[];
  /** NO_PROXY entries keysentry does not support (CIDR ranges, wildcards in the middle); they are not bypassed. */
  noProxyIgnored: string[];
  requireProxy: boolean;
  ca: { path: string; certificates: CaCertificateInfo[] } | { path: string; error: string } | null;
  feeds: FeedMode;
  /** What Node itself trusts besides network.caFile (present when the environment was given to summarizeNetwork). */
  nodeTrust?: NodeTrust;
}

/**
 * Node's default roots are its bundled Mozilla list, plus the certificates in NODE_EXTRA_CA_CERTS, plus the operating
 * system's store only when Node runs with --use-system-ca (or NODE_USE_SYSTEM_CA=1). NODE_TLS_REJECT_UNAUTHORIZED=0
 * turns certificate checks off for Node's own clients; keysentry then uses its own transport, which keeps them on.
 */
export interface NodeTrust { extraCaCerts: boolean; systemCa: boolean; tlsChecksOff: boolean }

export function nodeTrustFrom(env: Readonly<Record<string, string | undefined>>, execArgv: readonly string[] = process.execArgv): NodeTrust {
  const options = env.NODE_OPTIONS ?? '';
  return {
    extraCaCerts: !!env.NODE_EXTRA_CA_CERTS?.trim(),
    systemCa: execArgv.includes('--use-system-ca') || /(?:^|\s)--use-system-ca(?:\s|$)/.test(options) || env.NODE_USE_SYSTEM_CA === '1',
    tlsChecksOff: env.NODE_TLS_REJECT_UNAUTHORIZED === '0',
  };
}

/** "Node's default roots" in words, for status lines and doctor. */
export function defaultRootsText(trust?: NodeTrust): string {
  const parts = ['Node\'s bundled roots'];
  if (trust?.extraCaCerts) parts.push('the certificates in NODE_EXTRA_CA_CERTS');
  if (trust?.systemCa) parts.push('the operating system\'s certificate store (--use-system-ca)');
  return parts.length === 1 ? parts[0]! : `${parts.slice(0, -1).join(', ')} and ${parts.at(-1)}`;
}

/** Secret-free description of the network settings. `caError` is the fixed message of a CaBundleError. */
export function summarizeNetwork(input: {
  proxy: ResolvedProxy | null;
  requireProxy?: boolean;
  ca?: CaBundle | { path: string; error: string } | null;
  feeds: FeedMode;
  env?: Readonly<Record<string, string | undefined>>;
}): NetworkSummary {
  const settings = input.proxy?.settings ?? null;
  const parsed = parseNoProxy(input.proxy?.noProxy ?? []);
  return {
    ...(input.env ? { nodeTrust: nodeTrustFrom(input.env) } : {}),
    proxy: settings && input.proxy?.source ? {
      origin: settings.url, source: input.proxy.source, credentials: input.proxy.credentialSource ?? 'none',
    } : null,
    noProxy: [...(input.proxy?.noProxy ?? [])].filter(entry => !parsed.ignored.includes(entry)),
    noProxyIgnored: parsed.ignored,
    requireProxy: input.requireProxy === true,
    ca: !input.ca ? null : 'error' in input.ca ? { path: input.ca.path, error: input.ca.error }
      : { path: input.ca.path, certificates: input.ca.certificates },
    feeds: input.feeds,
  };
}

/** Plain lines for `keysentry network`, `watch` start-up and the dashboard network screen. */
export function networkStatusLines(summary: NetworkSummary): string[] {
  const lines: string[] = [];
  if (summary.feeds.offline) {
    lines.push(`Offline mode is on (${summary.feeds.source === 'policy' ? 'required by the signed team policy' : 'set in keysentry.yaml'}): breach feeds and security news are not contacted.`);
  }
  if (summary.proxy) {
    lines.push(`Requests go through the proxy at ${summary.proxy.origin} (${summary.proxy.source === 'config' ? 'from keysentry.yaml' : 'from HTTPS_PROXY'}).`);
    if (summary.noProxy.length) lines.push(`Direct connections, without the proxy: ${summary.noProxy.join(', ')}.`);
  } else if (summary.requireProxy) {
    lines.push('The team policy requires a proxy, but none is configured, so outbound requests are refused.');
  }
  if (summary.ca && 'certificates' in summary.ca) {
    const count = summary.ca.certificates.length;
    lines.push(`${count} extra ${count === 1 ? 'certificate is' : 'certificates are'} trusted in addition to Node's default roots.`);
  } else if (summary.ca) {
    lines.push('network.caFile could not be used, so outbound requests are refused until it is fixed.');
  }
  if (summary.nodeTrust?.tlsChecksOff) {
    lines.push('NODE_TLS_REJECT_UNAUTHORIZED=0 is set; keysentry\'s own connections ignore it and still check certificates.');
  }
  return lines;
}
