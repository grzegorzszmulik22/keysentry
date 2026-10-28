import { readFile } from 'node:fs/promises';
import { createServer as createTcpServer, type Server, type Socket } from 'node:net';
import { connect as tlsConnect, createServer as createTlsServer, type ConnectionOptions } from 'node:tls';
import { afterEach, describe, expect, it } from 'vitest';
import {
  AuditExportError, SYSLOG_MAX_MESSAGE_OCTETS, createSyslogSink, createTlsSyslogConnector, formatSyslogMessage, frameSyslogMessage,
  syslogHostname,
} from '../../src/audit-export/index.js';
import type { NetworkReceiptEntry } from '../../src/types.js';
import { parseFrames, sampleRecord, unexpected } from './helpers.js';

const cert = await readFile(new URL('../fixtures/tls/cert.pem', import.meta.url), 'utf8');
const key = await readFile(new URL('../fixtures/tls/key.pem', import.meta.url), 'utf8');
const servers: { server: Server; sockets: Set<Socket> }[] = [];
const BOM = String.fromCharCode(0xfeff);

afterEach(async () => {
  for (const { server, sockets } of servers.splice(0)) {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});

/** A TLS syslog receiver: collects every byte of each connection and closes when the client closes. */
async function tlsReceiver() {
  const connections: Buffer[] = [];
  const sockets = new Set<Socket>();
  const server = createTlsServer({ key, cert }, socket => {
    sockets.add(socket);
    const chunks: Buffer[] = [];
    socket.on('data', chunk => chunks.push(chunk));
    socket.on('error', () => {});
    socket.on('end', () => { connections.push(Buffer.concat(chunks)); socket.end(); });
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  servers.push({ server, sockets });
  return { port: (server.address() as { port: number }).port, connections };
}

const target = (port: number) => ({ kind: 'syslog' as const, id: 'siem', host: 'localhost', port, appName: 'keysentry' });

describe('syslog message format (RFC 5424) and framing (RFC 5425)', () => {
  it('formats one record with PRI 110, version 1, structured data and a BOM-prefixed JSON message', () => {
    const message = formatSyslogMessage({ seq: 12, at: '2026-10-28T10:00:00.000Z', kind: 'vault-set', summary: 'Credential stored.',
      data: { name: 'OPENAI_API_KEY', role: 'write' } }, { appName: 'keysentry', hostname: 'build-01.example.com' });
    expect(message).toBe('<110>1 2026-10-28T10:00:00.000Z build-01.example.com keysentry - vault-set '
      + `[keysentry@32473 seq="12" kind="vault-set"] ${BOM}`
      + '{"at":"2026-10-28T10:00:00.000Z","data":{"name":"OPENAI_API_KEY","role":"write"},"kind":"vault-set","seq":12,"summary":"Credential stored."}');
  });

  it('adds the log identity to the structured data when known', () => {
    const message = formatSyslogMessage(sampleRecord(2, { actor: 'ana' }), { appName: 'keysentry', hostname: 'h', logId: '0123456789abcdef' });
    expect(message).toContain('[keysentry@32473 seq="2" kind="scan" log="0123456789abcdef" actor="ana"]');
  });

  it('frames with the octet count, not the character count', () => {
    const message = formatSyslogMessage(sampleRecord(1, { summary: 'Résumé ✓' }), { appName: 'keysentry', hostname: 'h' });
    const frame = frameSyslogMessage(message);
    const length = Buffer.byteLength(message, 'utf8');
    expect(length).toBeGreaterThan(message.length);
    expect(frame.subarray(0, String(length).length + 1).toString('ascii')).toBe(`${length} `);
    expect(frame.subarray(String(length).length + 1).toString('utf8')).toBe(message);
    expect(parseFrames(Buffer.concat([frame, frame]))).toEqual([message, message]);
  });

  it('escapes ", \\ and ] in SD parameter values and keeps MSGID and APP-NAME printable', () => {
    const message = formatSyslogMessage(sampleRecord(3, { kind: 'odd "kind"\\with]chars and spaces', actor: 'ana' }),
      { appName: 'key sentry', hostname: 'host name' });
    expect(message).toContain('[keysentry@32473 seq="3" kind="odd \\"kind\\"\\\\with\\]chars and spaces" actor="ana"]');
    const [pri, timestamp, hostname, app, procid, msgid] = message.split(' ');
    expect([pri, timestamp, hostname, app, procid]).toEqual(['<110>1', '2026-10-28T10:00:03.000Z', '-', 'key_sentry', '-']);
    expect(msgid).toBe('odd_"kind"\\with]chars_and_spaces');
    expect(msgid!.length).toBe(32);
    expect(syslogHostname('ok.example')).toBe('ok.example');
  });

  it('keeps every message within 8192 octets by dropping data first, then shortening the summary', () => {
    const big = formatSyslogMessage(sampleRecord(4, { data: { blob: 'x'.repeat(20_000) } }), { appName: 'keysentry', hostname: 'h' });
    expect(Buffer.byteLength(big)).toBeLessThanOrEqual(SYSLOG_MAX_MESSAGE_OCTETS);
    expect(big).toContain('truncated="data"');
    expect(big).not.toContain('"data":');
    const huge = formatSyslogMessage(sampleRecord(5, { summary: '"é'.repeat(9_000), data: undefined }), { appName: 'keysentry', hostname: 'h' });
    expect(Buffer.byteLength(huge)).toBeLessThanOrEqual(SYSLOG_MAX_MESSAGE_OCTETS);
    expect(() => JSON.parse(huge.slice(huge.indexOf(BOM) + 1))).not.toThrow();
  });
});

describe('syslog over TLS', () => {
  it('delivers octet-counted frames over a verified TLS connection and records the contact', async () => {
    const receiver = await tlsReceiver();
    const receipts: NetworkReceiptEntry[] = [];
    const connector = createTlsSyslogConnector({ allow: [{ host: 'localhost', port: receiver.port }], ca: [cert],
      receipt: { record: async entry => { receipts.push(entry); }, summarize: async () => [] } });
    const sink = createSyslogSink(target(receiver.port), { connector, hostname: 'h' });
    const batch = [sampleRecord(1), sampleRecord(2)];
    expect(await sink.deliver(batch)).toEqual({});
    expect(receiver.connections).toHaveLength(1);
    const expected = Buffer.concat(batch.map(record => frameSyslogMessage(formatSyslogMessage(record, { appName: 'keysentry', hostname: 'h' }))));
    expect(receiver.connections[0]!.equals(expected)).toBe(true);
    expect(receipts).toEqual([expect.objectContaining({ host: `syslog:localhost:${receiver.port}`, method: 'SYSLOG', allowed: true })]);
  });

  it('refuses a server whose certificate the system roots do not trust, and does not retry it', async () => {
    const receiver = await tlsReceiver();
    const connector = createTlsSyslogConnector({ allow: [{ host: 'localhost', port: receiver.port }] });
    const error = await createSyslogSink(target(receiver.port), { connector }).deliver([sampleRecord(1)]).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(AuditExportError);
    expect((error as AuditExportError).message).toBe('The syslog server certificate could not be verified. Check the server name and network.caFile.');
    expect((error as AuditExportError).retryable).toBe(false);
    expect(receiver.connections).toEqual([]);
  });

  it('checks the server name against the certificate even with a trusted CA', async () => {
    const receiver = await tlsReceiver();
    const connector = createTlsSyslogConnector({ allow: [{ host: 'syslog.example.com', port: receiver.port }], ca: [cert],
      connect: (options: ConnectionOptions) => tlsConnect({ ...options, host: '127.0.0.1' }) });
    const sink = createSyslogSink({ ...target(receiver.port), host: 'syslog.example.com' }, { connector });
    await expect(sink.deliver([sampleRecord(1)])).rejects.toThrow('certificate could not be verified');
  });

  it('never speaks plaintext: a plain TCP listener fails the TLS handshake and receives no record', async () => {
    const received: Buffer[] = [];
    const sockets = new Set<Socket>();
    const server = createTcpServer(socket => {
      sockets.add(socket);
      socket.on('data', chunk => { received.push(chunk); socket.end('not tls\r\n'); });
      socket.on('error', () => {});
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    servers.push({ server, sockets });
    const port = (server.address() as { port: number }).port;
    const connector = createTlsSyslogConnector({ allow: [{ host: 'localhost', port }], ca: [cert], timeoutMs: 2_000 });
    const error = await createSyslogSink(target(port), { connector }).deliver([sampleRecord(1)]).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(AuditExportError);
    // Only the TLS ClientHello reached the listener (handshake record type 0x16), never a syslog frame.
    expect(Buffer.concat(received)[0]).toBe(0x16);
    expect(Buffer.concat(received).includes(Buffer.from('keysentry@32473'))).toBe(false);
  });

  it('blocks a host:port that is not a configured target and records the refusal', async () => {
    const receipts: NetworkReceiptEntry[] = [];
    let opened = false;
    const connector = createTlsSyslogConnector({ allow: [{ host: 'syslog.example.com', port: 6514 }],
      receipt: { record: async entry => { receipts.push(entry); }, summarize: async () => [] },
      connect: () => { opened = true; throw new Error('must not connect'); } });
    await expect(connector.connect({ host: 'syslog.example.com', port: 514 })).rejects.toThrow('not an audit export target');
    await expect(connector.connect({ host: 'other.example.com', port: 6514 })).rejects.toThrow('not an audit export target');
    expect(opened).toBe(false);
    expect(receipts.map(entry => entry.allowed)).toEqual([false, false]);
  });

  it('refuses a direct connection when a proxy applies to the host, instead of bypassing it silently', async () => {
    let opened = false;
    const connector = createTlsSyslogConnector({ allow: [{ host: 'syslog.example.com', port: 6514 }], proxied: () => true,
      connect: () => { opened = true; throw new Error('must not connect'); } });
    const error = await connector.connect({ host: 'syslog.example.com', port: 6514 }).then(unexpected, (caught: unknown) => caught as AuditExportError);
    expect(error.message).toContain('Add syslog.example.com to network.noProxy');
    expect(error.retryable).toBe(false);
    expect(opened).toBe(false);
  });

  it('reports a refused connection as retryable with fixed text', async () => {
    const server = createTcpServer();
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as { port: number }).port;
    await new Promise<void>(resolve => server.close(() => resolve()));
    const connector = createTlsSyslogConnector({ allow: [{ host: 'localhost', port }], ca: [cert], timeoutMs: 2_000 });
    const error = await connector.connect({ host: 'localhost', port }).then(unexpected, (caught: unknown) => caught as AuditExportError);
    expect(error.message).toBe('Could not connect to the syslog server over TLS.');
    expect(error.retryable).toBe(true);
  });
});
