import { randomUUID } from 'node:crypto';
import { createConnection, type Socket } from 'node:net';
import { connect as connectTls, type ConnectionOptions, type TLSSocket } from 'node:tls';
import type { HttpClient, NetworkReceipt, NotifyChannel, Redactor, SignedNotifyMessage } from '../../types.js';
import { assertSafeMessage } from '../message.js';
import { renderPlain } from '../render.js';

export interface SmtpConfig {
  id?: string;
  host: string;
  port: 465 | 587;
  username: string;
  password: string;
  from: string;
  to: string | string[];
  receipt?: NetworkReceipt;
}

export interface SmtpDeps {
  http: HttpClient;
  redactor: Redactor;
  ca?: ConnectionOptions['ca'];
  servername?: string;
  /** Test seam; the production default connects directly to the configured host and port. */
  connect?: (options: { host: string; port: number }) => Socket;
  /** Defaults to a 30-second deadline for the complete send. */
  timeoutMs?: number;
}

const failure = () => new Error('SMTP delivery failed');

function header(value: string): string {
  if (/[\r\n\u0000-\u001f\u007f]/u.test(value) || Buffer.byteLength(value) > 900) throw failure();
  return value;
}

function mailbox(value: string): string {
  header(value);
  const address = value.match(/^[^<>]*<([^<>]+)>$/u)?.[1] ?? value;
  if (!/^[^<>\s@]+@[^<>\s@]+$/u.test(address) || /[^\u0021-\u007e]/u.test(address)) throw failure();
  return address;
}

function encodedWords(value: string): string {
  if (!/[^\u0020-\u007e]/u.test(value)) return value;
  const words: string[] = [];
  let chunk = '';
  for (const character of value) {
    if (Buffer.byteLength(chunk + character) > 45) {
      words.push('=?UTF-8?B?' + Buffer.from(chunk).toString('base64') + '?=');
      chunk = '';
    }
    chunk += character;
  }
  if (chunk) words.push('=?UTF-8?B?' + Buffer.from(chunk).toString('base64') + '?=');
  return words.join('\r\n ');
}

function encodedMailbox(value: string): string {
  const match = /^(.*?)\s*<([^<>]+)>$/u.exec(value);
  return match ? `${encodedWords(match[1]!.trim())} <${match[2]!}>` : value;
}

/** Never split a UTF-8 code point; count the extra leading dot in the wire limit. */
function wrapBody(text: string): string[] {
  const result: string[] = [];
  for (const source of text.replace(/\r\n?/gu, '\n').split('\n')) {
    let current = '';
    let bytes = 0;
    for (const character of source) {
      const size = Buffer.byteLength(character);
      const budget = current.startsWith('.') || current === '' && character === '.' ? 997 : 998;
      if (bytes + size > budget) {
        result.push(current.startsWith('.') ? '.' + current : current);
        current = '';
        bytes = 0;
      }
      current += character;
      bytes += size;
    }
    result.push(current.startsWith('.') ? '.' + current : current);
  }
  return result;
}

function serialize(m: SignedNotifyMessage, from: string, to: string[], redactor: Redactor): string {
  const subject = header(m.title);
  const date = new Date(header(m.at));
  if (!Number.isFinite(date.getTime())) throw failure();
  const rendered = renderPlain(m);
  if (redactor.redact(rendered) !== rendered) throw failure();
  const headers = [
    `From: ${encodedMailbox(from)}`,
    `To: ${to.map(encodedMailbox).join(', ')}`,
    `Subject: ${encodedWords(subject)}`,
    `Date: ${date.toUTCString()}`,
    `Message-ID: <${randomUUID()}@keysentry.local>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 8bit',
  ];
  if (headers.flatMap((line) => line.split('\r\n')).some((line) => Buffer.byteLength(line) > 998)) throw failure();
  return headers.join('\r\n') + '\r\n\r\n' + wrapBody(rendered).join('\r\n') + '\r\n.\r\n';
}

interface Reply { code: number; lines: string[] }

/** One command in flight, bounded multiline replies, and no server text in errors. */
class Replies {
  private buffer = '';
  private current: Reply | undefined;
  private queue: Reply[] = [];
  private waiting: { resolve: (reply: Reply) => void; reject: (error: Error) => void } | undefined;
  private failed = false;

  constructor(private readonly socket: Socket) {
    socket.on('data', this.onData);
    socket.on('error', this.onError);
    socket.on('close', this.onError);
  }

  private onError = () => {
    this.failed = true;
    this.waiting?.reject(failure());
    this.waiting = undefined;
  };

  private onData = (chunk: Buffer) => {
    this.buffer += chunk.toString('utf8');
    if (this.buffer.length > 65_536) return this.abort();
    while (this.buffer.includes('\r\n')) {
      const end = this.buffer.indexOf('\r\n');
      const line = this.buffer.slice(0, end);
      this.buffer = this.buffer.slice(end + 2);
      const match = /^(\d{3})([ -])(.*)$/u.exec(line);
      if (!match || line.length > 2048) return this.abort();
      const code = Number(match[1]);
      if (this.current && this.current.code !== code) return this.abort();
      this.current ??= { code, lines: [] };
      this.current.lines.push(match[3]!);
      if (this.current.lines.length > 100) return this.abort();
      if (match[2] === ' ') {
        const reply = this.current;
        this.current = undefined;
        if (this.waiting) {
          this.waiting.resolve(reply);
          this.waiting = undefined;
        } else {
          this.queue.push(reply);
          if (this.queue.length > 10) return this.abort();
        }
      }
    }
  };

  private abort() {
    this.onError();
    this.socket.destroy();
  }

  read(): Promise<Reply> {
    const reply = this.queue.shift();
    if (reply) return Promise.resolve(reply);
    if (this.failed || this.waiting) return Promise.reject(failure());
    return new Promise((resolve, reject) => { this.waiting = { resolve, reject }; });
  }

  async expect(code: number): Promise<Reply> {
    const reply = await this.read();
    if (reply.code !== code) throw failure();
    return reply;
  }

  async command(command: string, code: number): Promise<Reply> {
    this.socket.write(command + '\r\n');
    return this.expect(code);
  }

  detach() {
    this.socket.off('data', this.onData);
    this.socket.off('error', this.onError);
    this.socket.off('close', this.onError);
  }
}

function hasCapability(reply: Reply, name: 'PLAIN' | 'STARTTLS' | '8BITMIME'): boolean {
  return name === 'PLAIN'
    ? reply.lines.some((line) => /^AUTH(?:=|\s+).*\bPLAIN\b/iu.test(line))
    : reply.lines.some((line) => line.split(/\s+/u)[0]?.toUpperCase() === name);
}

function requireCapability(reply: Reply, name: 'PLAIN' | 'STARTTLS'): void {
  if (!hasCapability(reply, name)) throw failure();
}

function secure(socket: Socket, config: SmtpConfig, deps: SmtpDeps): TLSSocket {
  return connectTls({ socket, servername: deps.servername ?? config.host, ca: deps.ca, rejectUnauthorized: true });
}

function handshake(socket: TLSSocket): Promise<void> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      socket.off('secureConnect', connected);
      socket.off('error', rejected);
      socket.off('close', rejected);
    };
    const connected = () => {
      cleanup();
      if (!socket.authorized) reject(failure());
      else resolve();
    };
    const rejected = () => { cleanup(); reject(failure()); };
    socket.once('secureConnect', connected);
    socket.once('error', rejected);
    socket.once('close', rejected);
  });
}

export function createSmtpChannel(config: SmtpConfig, deps: SmtpDeps): NotifyChannel {
  deps.redactor.register(config.username);
  deps.redactor.register(config.password);
  const from = header(config.from);
  const to = (Array.isArray(config.to) ? [...config.to] : [config.to]).map(header);
  const sender = mailbox(from);
  const recipients = to.map(mailbox);
  if (!recipients.length || !/^[a-z\d.-]{1,253}$/iu.test(config.host) || ![465, 587].includes(config.port)
    || /\u0000/u.test(config.username + config.password) || deps.redactor.redact(config.host) !== config.host
    || deps.timeoutMs !== undefined && (!Number.isFinite(deps.timeoutMs) || deps.timeoutMs <= 0)) throw failure();
  return {
    id: config.id ?? 'smtp', kind: 'smtp',
    async send(m) {
      let socket: Socket | undefined;
      let replies: Replies | undefined;
      let deadline: ReturnType<typeof setTimeout> | undefined;
      try {
        assertSafeMessage(m, deps.redactor);
        const data = serialize(m, from, to, deps.redactor);
        await config.receipt?.record({ at: new Date().toISOString(), host: `smtp:${config.host}`, method: 'SMTP', purpose: 'email you configured', allowed: true });
        socket = (deps.connect ?? createConnection)({ host: config.host, port: config.port });
        socket.on('error', () => {});
        deadline = setTimeout(() => socket?.destroy(failure()), deps.timeoutMs ?? 30_000);
        if (config.port === 465) {
          socket = secure(socket, config, deps);
          replies = new Replies(socket);
          await handshake(socket as TLSSocket);
        } else replies = new Replies(socket);
        await replies.expect(220);
        let capabilities = await replies.command('EHLO keysentry.local', 250);
        if (config.port === 587) {
          requireCapability(capabilities, 'STARTTLS');
          await replies.command('STARTTLS', 220);
          replies.detach();
          socket = secure(socket, config, deps);
          replies = new Replies(socket);
          await handshake(socket as TLSSocket);
          capabilities = await replies.command('EHLO keysentry.local', 250);
        }
        if (!(socket as TLSSocket).authorized || !(socket as TLSSocket).encrypted) throw failure();
        requireCapability(capabilities, 'PLAIN');
        const eightBitMime = hasCapability(capabilities, '8BITMIME');
        if (!eightBitMime && /[^\u0000-\u007f]/u.test(data)) throw failure();
        const credentials = Buffer.from(`\u0000${config.username}\u0000${config.password}`, 'utf8');
        try { await replies.command('AUTH PLAIN ' + credentials.toString('base64'), 235); }
        finally { credentials.fill(0); }
        await replies.command(`MAIL FROM:<${sender}>${eightBitMime ? ' BODY=8BITMIME' : ''}`, 250);
        for (const recipient of recipients) await replies.command(`RCPT TO:<${recipient}>`, 250);
        await replies.command('DATA', 354);
        socket.write(data);
        await replies.expect(250);
        // Acceptance of DATA confirms delivery; a lost QUIT reply must not cause a duplicate send.
        const acceptedSocket = socket;
        acceptedSocket.end('QUIT\r\n', () => acceptedSocket.destroy());
      } catch {
        throw failure();
      } finally {
        if (deadline) clearTimeout(deadline);
        replies?.detach();
        if (socket && !socket.writableEnded) socket.destroy();
        socket?.on('error', () => {});
      }
    },
  };
}
