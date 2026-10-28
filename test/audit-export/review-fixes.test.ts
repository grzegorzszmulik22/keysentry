// Fix round for the phase 5 part A review (docs/review-phase5-enterprise-a.md): L1, L2, L3, L8 and M3 in audit export.
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import type { Server, Socket } from 'node:net';
import { createServer as createTlsServer } from 'node:tls';
import { afterEach, describe, expect, it } from 'vitest';
import {
  createAuditExporter, createSyslogSink, createTlsSyslogConnector, parseCaBundle, parseOtlpHeader, proxyAppliesTo, webhookPublicKey,
  type AuditExporterOptions, type AuditSnapshot,
} from '../../src/audit-export/index.js';
import { canonicalJson, generateDeviceKey } from '../../src/security/index.js';
import type { AuditLog } from '../../src/types.js';
import { FakeHttp } from '../helpers/fake-http.js';
import { auditFixture, cleanupDirs, fakeSyslog, memoryState, sampleRecord } from './helpers.js';

const cert = await readFile(new URL('../fixtures/tls/cert.pem', import.meta.url), 'utf8');
const key = await readFile(new URL('../fixtures/tls/key.pem', import.meta.url), 'utf8');
const servers: { server: Server; sockets: Set<Socket> }[] = [];
afterEach(async () => {
  await cleanupDirs();
  for (const { server, sockets } of servers.splice(0)) {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});

const syslog = { kind: 'syslog' as const, id: 'siem', host: 'syslog.example.com', port: 6514, appName: 'keysentry' };

async function exporterFor(count: number, overrides: Partial<AuditExporterOptions> = {}) {
  const f = await auditFixture(count);
  const tls = fakeSyslog();
  const options: AuditExporterOptions = { targets: [syslog], audit: f.audit, reader: f.reader, http: new FakeHttp(), tls: tls.connector,
    vault: f.vault, signingKey: f.signingKey, state: memoryState().store, sleep: async () => {}, ...overrides };
  return { f, tls, exporter: createAuditExporter(options) };
}

/** Rewrites every summary and recomputes the unkeyed chain, as a local process could. The MACs stay as they were. */
function forge(text: string): string {
  let prev = '0'.repeat(64);
  return text.trim().split('\n').map(raw => {
    const line = JSON.parse(raw) as Record<string, unknown>;
    line.summary = 'Forged summary';
    line.prev = prev;
    const { seq, at, kind, summary, data } = line;
    line.hash = createHash('sha256').update(canonicalJson({ seq, at, kind, summary, data, prev })).digest('hex');
    prev = line.hash as string;
    return JSON.stringify(line);
  }).join('\n') + '\n';
}

describe('audit export sends only entries it authenticated itself (review L2)', () => {
  it('refuses when every read between two good verifications returns re-chained entries', async () => {
    const f = await auditFixture(3);
    const genuine = await readFile(f.path, 'utf8');
    // Each verify sees the genuine file; each read in between sees the forged one.
    const racing: Pick<AuditLog, 'verify'> = { async verify() {
      await writeFile(f.path, genuine);
      const result = await f.audit.verify();
      await writeFile(f.path, forge(genuine));
      return result;
    } };
    const tls = fakeSyslog();
    const exporter = createAuditExporter({ targets: [syslog], audit: racing, reader: f.reader, http: new FakeHttp(), tls: tls.connector,
      vault: f.vault, signingKey: f.signingKey, state: memoryState().store, sleep: async () => {} });
    await expect(exporter.run({ force: true })).rejects.toThrow('changed while it was being read for export');
    expect(tls.deliveries).toEqual([]);
  });

  it('refuses a reader whose entries carry no MAC, and a missing audit key', async () => {
    const f = await auditFixture(2);
    const unkeyed = { async load(entries: number): Promise<AuditSnapshot> {
      const snapshot = await f.reader.load(entries);
      return { entries: snapshot.entries, records: snapshot.records, hashAt: seq => snapshot.hashAt(seq) };
    } };
    const base = { targets: [syslog], audit: f.audit, http: new FakeHttp(), tls: fakeSyslog().connector, vault: f.vault,
      signingKey: f.signingKey, state: memoryState().store, sleep: async () => {} };
    await expect(createAuditExporter({ ...base, reader: unkeyed }).run({ force: true })).rejects.toThrow('changed while it was being read');
    await expect(createAuditExporter({ ...base, reader: f.reader, macKey: async () => null }).run({ force: true }))
      .rejects.toThrow('The audit log key is not available here');
  });

  it('exports a genuine log, reading the key through the injected view', async () => {
    let reads = 0;
    const s = await exporterFor(3);
    const exporter = createAuditExporter({ targets: [syslog], audit: s.f.audit, reader: s.f.reader, http: new FakeHttp(), tls: s.tls.connector,
      vault: s.f.vault, signingKey: s.f.signingKey, state: memoryState().store, sleep: async () => {},
      macKey: async () => { reads++; return s.f.vault.get('audit/mac'); } });
    expect((await exporter.run({ force: true })).targets[0]!.status).toBe('sent');
    expect(s.tls.deliveries).toEqual([[1, 2, 3]]);
    expect(reads).toBe(1);
  });
});

describe('syslog decides "proxied?" exactly like the HTTPS transport (review L1)', () => {
  const env = { HTTPS_PROXY: 'http://proxy.corp.example:3128' };
  it('honours host:port no-proxy entries for the syslog port, and *.suffix entries for subdomains only', () => {
    expect(proxyAppliesTo('logs.corp.example', { env: { ...env, NO_PROXY: 'logs.corp.example:6514' }, port: 6514 })).toBe(false);
    expect(proxyAppliesTo('logs.corp.example', { env: { ...env, NO_PROXY: 'logs.corp.example:6514' }, port: 514 })).toBe(true);
    expect(proxyAppliesTo('logs.corp.example', { env: { ...env, NO_PROXY: '.corp.example' } })).toBe(false);
    expect(proxyAppliesTo('corp.example', { env: { ...env, NO_PROXY: '.corp.example' } })).toBe(true);
    expect(proxyAppliesTo('logs.corp.example', { proxy: 'http://proxy.corp.example:3128', noProxy: ['logs.corp.example'], env: {} })).toBe(false);
    expect(proxyAppliesTo('logs.corp.example', { env: {} })).toBe(false);
  });

  it('treats a policy that requires the proxy as covering every host, whatever the no-proxy lists say', () => {
    expect(proxyAppliesTo('logs.corp.example', { env: { ...env, NO_PROXY: '*' }, noProxy: ['logs.corp.example'], requireProxy: true })).toBe(true);
  });

  it('parses the CA bundle with the transport parser (comments allowed, keys refused)', () => {
    expect(parseCaBundle(`# Corp root\n\n${cert}`)).toHaveLength(1);
    expect(() => parseCaBundle(`${cert}${key}`)).toThrow('not a certificate');
  });

  it('refuses every syslog connection while the network settings cannot be used', async () => {
    let opened = false;
    const connector = createTlsSyslogConnector({ allow: [{ host: 'syslog.example.com', port: 6514 }],
      unavailable: 'network.caFile could not be read. Check the path (relative to the project) and its permissions.',
      connect: () => { opened = true; throw new Error('must not connect'); } });
    await expect(connector.connect({ host: 'syslog.example.com', port: 6514 }))
      .rejects.toThrow('Syslog export was not attempted because the network settings cannot be used: network.caFile could not be read.');
    expect(opened).toBe(false);
  });

  it('passes the target port to the proxy decision', async () => {
    const seen: [string, number][] = [];
    const connector = createTlsSyslogConnector({ allow: [{ host: 'syslog.example.com', port: 6514 }],
      proxied: (host, port) => { seen.push([host, port]); return true; } });
    await expect(connector.connect({ host: 'syslog.example.com', port: 6514 })).rejects.toThrow('network.noProxy');
    expect(seen).toEqual([['syslog.example.com', 6514]]);
  });
});

describe('syslog delivery a server never confirms (review L8)', () => {
  it('counts the flushed batch as sent but says the server did not confirm it', async () => {
    const sockets = new Set<Socket>();
    const received: Buffer[] = [];
    // allowHalfOpen: the receiver reads everything but never closes its side.
    const server = createTlsServer({ key, cert, allowHalfOpen: true }, socket => {
      sockets.add(socket); socket.on('data', chunk => received.push(chunk)); socket.on('error', () => {});
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    servers.push({ server, sockets });
    const port = (server.address() as { port: number }).port;
    const connector = createTlsSyslogConnector({ allow: [{ host: 'localhost', port }], ca: [cert], timeoutMs: 300 });
    const outcome = await createSyslogSink({ ...syslog, host: 'localhost', port }, { connector, hostname: 'h' }).deliver([sampleRecord(1)]);
    expect(outcome.warnings?.[0]).toContain('did not close the connection');
    expect(Buffer.concat(received).length).toBeGreaterThan(0);
  });
});

describe('OTLP custom header names (review L3)', () => {
  it('accepts any ordinary name on a single-host client and only credential-like names on a shared one', () => {
    expect(parseOtlpHeader('x-honeycomb-team: abc123', { singleHost: true })).toEqual({ name: 'x-honeycomb-team', value: 'abc123' });
    expect(parseOtlpHeader('X-Scope-OrgID: tenant-1', { singleHost: true })).toEqual({ name: 'x-scope-orgid', value: 'tenant-1' });
    expect(parseOtlpHeader('x-honeycomb-team: abc123', { singleHost: false })).toBeNull();
    expect(parseOtlpHeader('x-api-key: abc123', { singleHost: false })).toEqual({ name: 'x-api-key', value: 'abc123' });
    for (const line of ['Host: evil.example', 'Content-Type: text/plain', 'Proxy-Authorization: x', 'no colon', 'bad name!: x', 'x-a: \u0001']) {
      expect(parseOtlpHeader(line, { singleHost: true })).toBeNull();
    }
  });
});

describe('webhook signing keys in audit export status (review M3)', () => {
  it('lists this computer\'s key and every known watcher key once, each with who holds it', async () => {
    const watcher = generateDeviceKey(), box = generateDeviceKey();
    const hook = { kind: 'webhook' as const, id: 'hook', url: 'https://hooks.example.com/audit', signing: 'ed25519' as const };
    const s = await exporterFor(1);
    const status = await createAuditExporter({ targets: [hook], audit: s.f.audit, reader: s.f.reader, http: new FakeHttp(), tls: s.tls.connector,
      vault: s.f.vault, signingKey: s.f.signingKey, state: memoryState().store,
      otherSigningKeys: async () => [{ signer: 'deployed watcher', publicKeyDer: watcher.publicKeyDer },
        { signer: 'cloud box b1', publicKeyDer: box.publicKeyDer }, { signer: 'duplicate', publicKeyDer: watcher.publicKeyDer },
        { signer: 'garbage', publicKeyDer: Buffer.from('not a key') }] }).status();
    const keys = status.targets[0]!.publicKeys!;
    expect(keys.map(entry => entry.signer)).toEqual(['this computer', 'deployed watcher', 'cloud box b1']);
    expect(keys[1]).toMatchObject({ whpk: webhookPublicKey(watcher.publicKeyDer), keyId: watcher.keyId });
    expect(keys[0]!.keyId).toBe(s.f.key.keyId);
    expect(status.targets[0]!.publicKey!.keyId).toBe(s.f.key.keyId);
  });
});
