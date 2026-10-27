import { readFile } from 'node:fs/promises';
import { createServer, connect, type Socket, type Server } from 'node:net';
import { createSecureContext, createServer as createTlsServer, TLSSocket } from 'node:tls';
import { afterEach, describe, expect, test } from 'vitest';
import { createSmtpChannel } from '../../src/notify/channels/smtp.js';
import { createRedactor } from '../../src/core/redact.js';
import { FakeHttp } from '../helpers/fake-http.js';
import type { NetworkReceiptEntry, SignedNotifyMessage } from '../../src/types.js';

const certificate = await readFile(new URL('../fixtures/tls/cert.pem', import.meta.url));
const privateKey = await readFile(new URL('../fixtures/tls/key.pem', import.meta.url));
const message: SignedNotifyMessage = {
  id: 'notice-1', at: '2026-10-27T12:00:00.000Z', kind: 'test', severity: 'warning',
  title: 'Rotation finished', lines: ['All configured services were checked.', '.leading dot', '..two dots'],
  keyId: '1234567890abcdef', sig: Buffer.alloc(64).toString('base64'), code: 'ABCD-EFGH',
};
const servers: { server: Server; sockets: Set<Socket> }[] = [];

afterEach(async () => {
  for (const { server, sockets } of servers.splice(0)) {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

async function smtpServer(port: 465 | 587, options: { starttls?: boolean; plain?: boolean; authStatus?: number; stall?: boolean; eightBitMime?: boolean; preTlsEightBitMime?: boolean; ignoreQuit?: boolean } = {}) {
  const commands: { line: string; encrypted: boolean }[] = [];
  const messages: string[] = [];
  const sockets = new Set<Socket>();
  const clients: Socket[] = [];
  const context = createSecureContext({ key: privateKey, cert: certificate });
  const handle = (socket: Socket, encrypted: boolean, greeting = true) => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket));
    if (greeting && !options.stall) socket.write('220 localhost test server\r\n');
    let buffer = '';
    let inData = false;
    let bodyEightBitMime = false;
    let body: string[] = [];
    const onData = (chunk: Buffer) => {
      buffer += chunk.toString('utf8');
      while (buffer.includes('\r\n')) {
        const end = buffer.indexOf('\r\n');
        const line = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        if (inData) {
          if (line === '.') {
            const text = body.join('\r\n');
            const accepted = !/[^\u0000-\u007f]/u.test(text) || bodyEightBitMime;
            if (accepted) messages.push(text);
            body = [];
            inData = false;
            socket.write(accepted ? '250 message accepted\r\n' : '550 8BITMIME body parameter required\r\n');
          } else body.push(line);
          continue;
        }
        commands.push({ line, encrypted });
        if (line.startsWith('EHLO ')) {
          const capabilities = ['250-localhost'];
          if (!encrypted && options.starttls !== false) capabilities.push('250-STARTTLS');
          const eightBitMime = encrypted ? options.eightBitMime !== false : options.preTlsEightBitMime ?? options.eightBitMime !== false;
          if (eightBitMime) capabilities.push('250-8BITMIME');
          capabilities.push(options.plain === false && encrypted ? '250 AUTH LOGIN' : '250 AUTH PLAIN');
          socket.write(capabilities.join('\r\n') + '\r\n');
        } else if (line === 'STARTTLS') {
          socket.write('220 start TLS\r\n');
          socket.off('data', onData);
          handle(new TLSSocket(socket, { isServer: true, secureContext: context, allowHalfOpen: true }), true, false);
          return;
        } else if (line.startsWith('AUTH PLAIN ')) socket.write(`${options.authStatus ?? 235} authentication reply\r\n`);
        else if (line.startsWith('MAIL FROM:')) {
          bodyEightBitMime = / BODY=8BITMIME$/u.test(line);
          socket.write('250 accepted\r\n');
        } else if (line.startsWith('RCPT TO:')) socket.write('250 accepted\r\n');
        else if (line === 'DATA') { inData = true; socket.write('354 send message\r\n'); }
        else if (line === 'QUIT') { if (!options.ignoreQuit) socket.end('221 goodbye\r\n'); }
        else socket.write('500 unexpected command\r\n');
      }
    };
    socket.on('data', onData);
  };
  const server = port === 465
    ? createTlsServer({ key: privateKey, cert: certificate, allowHalfOpen: true }, (socket) => handle(socket, true))
    : createServer({ allowHalfOpen: true }, (socket) => handle(socket, false));
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  server.on('tlsClientError', () => {});
  servers.push({ server, sockets });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Test server did not bind');
  return { commands, messages, clients, connect: () => {
    const socket = connect({ host: '127.0.0.1', port: address.port });
    clients.push(socket);
    return socket;
  } };
}

function channel(port: 465 | 587, server: Awaited<ReturnType<typeof smtpServer>>, overrides: Record<string, unknown> = {}, deps: Record<string, unknown> = {}) {
  return createSmtpChannel({ host: 'smtp.example.test', port, username: 'notification-user', password: 'smtp-test-password', from: 'Watcher <watcher@example.test>', to: ['owner@example.test', 'backup@example.test'], ...overrides }, {
    http: new FakeHttp(), redactor: createRedactor(), ca: certificate, servername: 'localhost', connect: server.connect, ...deps,
  });
}

describe('SMTP channel', () => {
  test.each([465, 587] as const)('port %i authenticates only after verified TLS and sends required headers and dot-stuffed text', async (port) => {
    const server = await smtpServer(port);
    const entries: NetworkReceiptEntry[] = [];
    const receipt = { record: async (entry: NetworkReceiptEntry) => { entries.push(entry); }, summarize: async () => [] };
    await channel(port, server, { receipt }).send(message);
    const auth = server.commands.filter(({ line }) => line.startsWith('AUTH '));
    expect(auth).toHaveLength(1);
    expect(auth[0]?.encrypted).toBe(true);
    expect(server.commands.filter(({ line }) => line.startsWith('EHLO '))).toHaveLength(port === 587 ? 2 : 1);
    if (port === 587) expect(server.commands.find(({ line }) => line === 'STARTTLS')?.encrypted).toBe(false);
    expect(server.commands.find(({ line }) => line.startsWith('MAIL FROM:'))?.line).toContain(' BODY=8BITMIME');
    expect(server.messages).toHaveLength(1);
    const text = server.messages[0]!;
    for (const header of ['From:', 'To:', 'Subject:', 'Date:', 'Message-ID:', 'MIME-Version: 1.0', 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: 8bit']) expect(text).toContain(header);
    expect(text).toContain('\r\n..leading dot\r\n...two dots');
    expect(text).toContain('Verification code: ABCD-EFGH');
    expect(text).not.toContain('Bcc:');
    expect(text).not.toContain('smtp-test-password');
    expect(entries).toEqual([{ at: expect.any(String), host: 'smtp:smtp.example.test', method: 'SMTP', purpose: 'email you configured', allowed: true }]);
  });

  test('refuses plaintext AUTH when STARTTLS is absent even if PLAIN was advertised', async () => {
    const server = await smtpServer(587, { starttls: false });
    await expect(channel(587, server).send(message)).rejects.toThrow('SMTP');
    expect(server.commands.some(({ line }) => line.startsWith('AUTH '))).toBe(false);
    expect(server.messages).toHaveLength(0);
  });

  test('refuses AUTH when PLAIN is absent after the TLS upgrade', async () => {
    const server = await smtpServer(587, { plain: false });
    await expect(channel(587, server).send(message)).rejects.toThrow('SMTP');
    expect(server.commands.some(({ line }) => line.startsWith('AUTH '))).toBe(false);
  });

  test.each([465, 587] as const)('port %i rejects an untrusted certificate by default', async (port) => {
    const server = await smtpServer(port);
    await expect(channel(port, server, {}, { ca: undefined }).send(message)).rejects.toThrow('SMTP');
    expect(server.commands.some(({ line }) => line.startsWith('AUTH '))).toBe(false);
  });

  test('rejects header injection and overlong headers before connecting', async () => {
    const server = await smtpServer(465);
    for (const title of ['Title\r\nBcc: someone@example.test', 'x'.repeat(999)]) {
      await expect(channel(465, server).send({ ...message, title })).rejects.toThrow('SMTP');
    }
    expect(() => channel(465, server, { from: 'a@example.test\r\nBcc: b@example.test' })).toThrow('SMTP');
    await expect(channel(465, server).send({ ...message, at: 'Tue, 27 Oct 2026 12:00:00 GMT\r\n' })).rejects.toThrow('SMTP');
    expect(server.commands).toHaveLength(0);
  });

  test('rejects a credential used as the host before it can enter the network receipt', async () => {
    const server = await smtpServer(465);
    expect(() => channel(465, server, { host: 'smtp-test-password' })).toThrow('SMTP');
  });

  test('wraps UTF-8 body lines at 998 octets including dot stuffing', async () => {
    const server = await smtpServer(465);
    await channel(465, server).send({ ...message, lines: ['.' + 'é'.repeat(1300), 'a'.repeat(998) + '.tail'] });
    for (const line of server.messages[0]!.split('\r\n')) expect(Buffer.byteLength(line)).toBeLessThanOrEqual(998);
    expect(server.messages[0]).not.toContain('\uFFFD');
  });

  test('encodes non-ASCII subjects as MIME encoded words without requiring SMTPUTF8', async () => {
    const server = await smtpServer(465);
    await channel(465, server, { from: 'Équipe <watcher@example.test>' }).send({ ...message, title: 'État terminé' });
    expect(server.messages[0]).toContain('Subject: =?UTF-8?B?' + Buffer.from('État terminé').toString('base64') + '?=');
    expect(server.messages[0]).toContain('From: =?UTF-8?B?' + Buffer.from('Équipe').toString('base64') + '?= <watcher@example.test>');
  });

  test.each([465, 587] as const)('port %i refuses Unicode before AUTH when 8BITMIME is absent', async (port) => {
    const server = await smtpServer(port, { eightBitMime: false });
    await expect(channel(port, server).send({ ...message, lines: ['\u00e9'] })).rejects.toThrow('SMTP delivery failed');
    expect(server.commands.some(({ line }) => line.startsWith('AUTH '))).toBe(false);
    expect(server.messages).toHaveLength(0);
  });

  test('ignores plaintext 8BITMIME capability if it disappears after STARTTLS', async () => {
    const server = await smtpServer(587, { preTlsEightBitMime: true, eightBitMime: false });
    await expect(channel(587, server).send({ ...message, lines: ['\u00e9'] })).rejects.toThrow('SMTP delivery failed');
    expect(server.commands.some(({ line }) => line.startsWith('AUTH '))).toBe(false);
  });

  test('uses 8BITMIME offered only after STARTTLS for a Unicode message', async () => {
    const server = await smtpServer(587, { preTlsEightBitMime: false, eightBitMime: true });
    await channel(587, server).send({ ...message, lines: ['\u00e9'] });
    expect(server.commands.find(({ line }) => line.startsWith('MAIL FROM:'))?.line).toContain(' BODY=8BITMIME');
    expect(server.messages).toHaveLength(1);
  });

  test('sends ASCII text without requesting an unavailable 8BITMIME capability', async () => {
    const server = await smtpServer(465, { eightBitMime: false });
    await channel(465, server).send(message);
    expect(server.commands.find(({ line }) => line.startsWith('MAIL FROM:'))?.line).not.toContain(' BODY=');
    expect(server.messages).toHaveLength(1);
  });

  test('releases the connection after accepted DATA even when the server ignores QUIT', async () => {
    const server = await smtpServer(465, { ignoreQuit: true });
    await channel(465, server).send(message);
    await new Promise((resolve) => setTimeout(resolve, 25));
    expect(server.clients.every((socket) => socket.destroyed)).toBe(true);
    expect(server.messages).toHaveLength(1);
  });

  test('never sends a registered message secret and does not expose server authentication replies', async () => {
    const server = await smtpServer(465, { authStatus: 535 });
    const redactor = createRedactor();
    redactor.register('private-message-secret');
    const sender = channel(465, server, {}, { redactor });
    await expect(sender.send({ ...message, lines: ['private-message-secret'] })).rejects.toThrow();
    expect(server.commands).toHaveLength(0);
    await expect(sender.send(message)).rejects.toThrow('SMTP delivery failed');
  });

  test('refuses a registered secret assembled across rendered message fields', async () => {
    const server = await smtpServer(465);
    const redactor = createRedactor();
    redactor.register('First part\n\nSecond part');
    await expect(channel(465, server, {}, { redactor }).send({ ...message, title: 'First part', lines: ['Second part'] })).rejects.toThrow('SMTP delivery failed');
    expect(server.commands).toHaveLength(0);
  });

  test('records failed attempts once and times out without leaking endpoint or credentials', async () => {
    const server = await smtpServer(587, { stall: true });
    const entries: NetworkReceiptEntry[] = [];
    const receipt = { record: async (entry: NetworkReceiptEntry) => { entries.push(entry); }, summarize: async () => [] };
    await expect(channel(587, server, { receipt }, { timeoutMs: 40 }).send(message)).rejects.toThrow('SMTP delivery failed');
    expect(entries).toHaveLength(1);
  });
});
