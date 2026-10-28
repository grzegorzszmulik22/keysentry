import { hostname as osHostname } from 'node:os';
import * as tls from 'node:tls';
import { canonicalJson } from '../security/index.js';
import type { AuditExportRecord, NetworkReceipt, NetworkReceiptEntry } from '../types.js';
import { AuditExportError, type ExportSink, type SyslogTarget } from './types.js';

/**
 * RFC 5424 §6.3.2: an SD-ID without "@" is reserved for IANA. keysentry has no Private Enterprise Number yet, so this
 * uses 32473, the number RFC 5612 reserves for documentation. Replace it when a PEN is registered (notes/audit-export.md).
 */
export const SYSLOG_SD_ID = 'keysentry@32473';
/** RFC 5424 §6.2.1: facility 13 is "log audit"; severity 6 is "Informational". PRI = facility * 8 + severity. */
export const SYSLOG_PRI = 13 * 8 + 6;
/** RFC 5425 §4.3.1: receivers MUST accept 2048 octets and SHOULD accept 8192. */
export const SYSLOG_MAX_MESSAGE_OCTETS = 8192;

/** RFC 5424 §6.4: MSG-UTF8 starts with the UTF-8 byte order mark (U+FEFF, octets EF BB BF). */
const BOM = String.fromCharCode(0xfeff);
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/;

/** PRINTUSASCII (%d33-126) of bounded length, or the NILVALUE. */
function printable(value: string, max: number): string {
  const clean = value.replace(/[^\x21-\x7e]/g, '_').slice(0, max);
  return clean || '-';
}

/** RFC 5424 §6.2.4 HOSTNAME, from this machine's name. */
export function syslogHostname(name: string = osHostname()): string {
  return /^[\x21-\x7e]{1,255}$/.test(name) ? name : '-';
}

/** RFC 5424 §6.3.3: '"', '\' and ']' are escaped inside PARAM-VALUE. */
function paramValue(value: string): string {
  return value.replace(/[\\"\]]/g, character => `\\${character}`);
}

function truncateUtf8(value: string, maxBytes: number): string {
  let bytes = 0;
  let result = '';
  for (const character of value) {
    const size = Buffer.byteLength(character);
    if (bytes + size > maxBytes) break;
    result += character;
    bytes += size;
  }
  return result;
}

/**
 * One RFC 5424 message: `<110>1 TIMESTAMP HOSTNAME APP-NAME - MSGID [keysentry@32473 seq=".." kind=".."] BOM{json}`.
 * MSG is the canonical JSON export record. A record above 8192 octets is sent without its data (truncated="data").
 */
export function formatSyslogMessage(record: AuditExportRecord, opts: { appName: string; hostname: string; logId?: string }): string {
  const timestamp = RFC3339.test(record.at) ? record.at : '-';
  const header = `<${SYSLOG_PRI}>1 ${timestamp} ${syslogHostname(opts.hostname)} ${printable(opts.appName, 48)} - ${printable(record.kind, 32)} `;
  const element = (extra: string) => `[${SYSLOG_SD_ID} seq="${record.seq}" kind="${paramValue(record.kind)}"`
    + `${opts.logId === undefined ? '' : ` log="${paramValue(opts.logId)}"`}${record.actor === undefined ? '' : ` actor="${paramValue(record.actor)}"`}${extra}]`;
  const full = `${header}${element('')} ${BOM}${canonicalJson(record)}`;
  if (Buffer.byteLength(full) <= SYSLOG_MAX_MESSAGE_OCTETS) return full;
  const { data: _omitted, ...rest } = record;
  const prefix = `${header}${element(' truncated="data"')} ${BOM}`;
  const reduced = `${prefix}${canonicalJson(rest)}`;
  if (Buffer.byteLength(reduced) <= SYSLOG_MAX_MESSAGE_OCTETS) return reduced;
  const budget = SYSLOG_MAX_MESSAGE_OCTETS - Buffer.byteLength(`${prefix}${canonicalJson({ ...rest, summary: '' })}`) - 16;
  let summary = truncateUtf8(rest.summary, Math.max(0, budget));
  // JSON escaping can grow the text; cut by the overflow (at least one character) until the message fits.
  for (;;) {
    const overflow = Buffer.byteLength(`${prefix}${canonicalJson({ ...rest, summary })}`) - SYSLOG_MAX_MESSAGE_OCTETS;
    if (overflow <= 0 || !summary) break;
    const shorter = truncateUtf8(summary, Math.max(0, Buffer.byteLength(summary) - overflow));
    summary = shorter.length < summary.length ? shorter : [...summary].slice(0, -1).join('');
  }
  return `${prefix}${canonicalJson({ ...rest, summary })}`;
}

/** RFC 5425 §4.3: SYSLOG-FRAME = MSG-LEN SP SYSLOG-MSG, where MSG-LEN is the octet count of SYSLOG-MSG. */
export function frameSyslogMessage(message: string): Buffer {
  const body = Buffer.from(message, 'utf8');
  return Buffer.concat([Buffer.from(`${body.length} `, 'ascii'), body]);
}

export interface SyslogConnection {
  write(data: Buffer): Promise<void>;
  /** Ends the TLS session cleanly; resolves once every byte was flushed and the session closed. */
  close(): Promise<void>;
  destroy(): void;
}

/** The only way audit export opens a raw TLS connection. It refuses any host:port not explicitly allowed. */
export interface SyslogConnector {
  connect(target: { host: string; port: number }): Promise<SyslogConnection>;
}

/** Node's default trust store (bundled roots, NODE_EXTRA_CA_CERTS, and the OS store when --use-system-ca is set). */
export function defaultCaCertificates(): string[] {
  const reader = (tls as { getCACertificates?: (type?: 'default') => string[] }).getCACertificates;
  return typeof reader === 'function' ? reader('default') : [...tls.rootCertificates];
}

const CONNECT_FAILED = 'Could not connect to the syslog server over TLS.';
const CERTIFICATE_FAILED = 'The syslog server certificate could not be verified. Check the server name and network.caFile.';
const SEND_FAILED = 'The syslog connection closed before every record was sent.';

function certificateError(error: unknown): boolean {
  const code = typeof error === 'object' && error !== null && 'code' in error ? String((error as { code: unknown }).code) : '';
  return /CERT|SIGNATURE|ALTNAME|ISSUER|HOSTNAME/.test(code);
}

export function createTlsSyslogConnector(opts: {
  /** Exactly the `syslog` targets from keysentry.yaml. */
  allow: readonly { host: string; port: number }[];
  /** Extra PEM certificates (network.caFile), trusted in addition to the defaults, never instead of them. */
  ca?: readonly string[];
  receipt?: NetworkReceipt;
  /** True when a configured proxy applies to the host: a direct connection is then refused, not made silently. */
  proxied?: (host: string) => boolean;
  timeoutMs?: number;
  now?: () => Date;
  /** Test seam over `tls.connect`. */
  connect?: (options: tls.ConnectionOptions) => tls.TLSSocket;
}): SyslogConnector {
  const allowed = new Set(opts.allow.map(entry => `${entry.host.toLowerCase()}:${entry.port}`));
  const ca = opts.ca?.length ? [...defaultCaCertificates(), ...opts.ca] : undefined;
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const now = opts.now ?? (() => new Date());

  async function record(entry: Omit<NetworkReceiptEntry, 'at'>): Promise<void> {
    try { await opts.receipt?.record({ at: now().toISOString(), ...entry }); } catch { /* A receipt failure must not change delivery. */ }
  }

  return {
    async connect({ host, port }) {
      const name = host.toLowerCase();
      const label = `syslog:${name}:${port}`;
      if (!allowed.has(`${name}:${port}`)) {
        await record({ host: label, method: 'SYSLOG', purpose: 'not on the allowed list', allowed: false });
        throw new AuditExportError('Blocked a syslog connection: that host and port are not an audit export target in keysentry.yaml.', false);
      }
      if (opts.proxied?.(name)) {
        throw new AuditExportError(`A proxy is configured for ${name}, and syslog export connects directly. Add ${name} to network.noProxy to allow a direct TLS connection, or export through OTLP or a webhook.`, false);
      }
      await record({ host: label, method: 'SYSLOG', purpose: 'audit export you configured', allowed: true });
      let socket: tls.TLSSocket;
      try {
        socket = (opts.connect ?? tls.connect)({ host: name, port, servername: name, rejectUnauthorized: true, minVersion: 'TLSv1.2', ...(ca ? { ca } : {}) });
      } catch { throw new AuditExportError(CONNECT_FAILED, true); }
      let failure: AuditExportError | undefined;
      // A persistent listener: a late socket error must never become an unhandled 'error' event.
      socket.on('error', error => { failure ??= certificateError(error) ? new AuditExportError(CERTIFICATE_FAILED, false) : new AuditExportError(CONNECT_FAILED, true); });
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => { cleanup(); socket.destroy(); reject(new AuditExportError(CONNECT_FAILED, true)); }, timeoutMs);
        const cleanup = () => { clearTimeout(timer); socket.off('secureConnect', connected); socket.off('error', failed); socket.off('close', failed); };
        const connected = () => {
          cleanup();
          if (!socket.authorized) { socket.destroy(); reject(new AuditExportError(CERTIFICATE_FAILED, false)); } else resolve();
        };
        const failed = (error?: unknown) => {
          cleanup(); socket.destroy();
          reject(failure ?? (certificateError(error) ? new AuditExportError(CERTIFICATE_FAILED, false) : new AuditExportError(CONNECT_FAILED, true)));
        };
        socket.once('secureConnect', connected);
        socket.once('error', failed);
        socket.once('close', failed);
      });
      return {
        write(data) {
          return new Promise<void>((resolve, reject) => {
            if (failure || socket.destroyed) { reject(failure ?? new AuditExportError(SEND_FAILED, true)); return; }
            socket.write(data, error => { if (error) reject(failure ?? new AuditExportError(SEND_FAILED, true)); else resolve(); });
          });
        },
        close() {
          return new Promise<void>((resolve, reject) => {
            if (failure || socket.destroyed) { reject(failure ?? new AuditExportError(SEND_FAILED, true)); return; }
            let finished = false;
            const timer = setTimeout(() => {
              socket.destroy();
              // The server kept its side open: every byte was flushed, so the batch counts as sent.
              if (finished && !failure) resolve(); else reject(failure ?? new AuditExportError(SEND_FAILED, true));
            }, Math.min(timeoutMs, 5_000));
            socket.once('finish', () => { finished = true; });
            socket.once('close', () => {
              clearTimeout(timer);
              if (finished && !failure) resolve(); else reject(failure ?? new AuditExportError(SEND_FAILED, true));
            });
            socket.end();
          });
        },
        destroy() { socket.destroy(); },
      };
    },
  };
}

export function createSyslogSink(target: SyslogTarget, deps: { connector: SyslogConnector; hostname?: string; logId?: string }): ExportSink {
  const hostname = deps.hostname ?? syslogHostname();
  const encode = (batch: readonly AuditExportRecord[]) =>
    Buffer.concat(batch.map(record => frameSyslogMessage(formatSyslogMessage(record, { appName: target.appName, hostname, ...(deps.logId ? { logId: deps.logId } : {}) }))));
  return {
    target,
    destination: `syslog over TLS to ${target.host}:${target.port}`,
    async deliver(batch) {
      const frames = encode(batch);
      const connection = await deps.connector.connect({ host: target.host, port: target.port });
      try {
        await connection.write(frames);
        await connection.close();
      } catch (error) {
        connection.destroy();
        throw error instanceof AuditExportError ? error : new AuditExportError(SEND_FAILED, true);
      }
      return {};
    },
    preview: batch => ({ location: `${target.host}:${target.port}`, bytes: encode(batch).length }),
    dispose() {},
  };
}
