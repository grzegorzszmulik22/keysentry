import { readFile } from 'node:fs/promises';
import { request as httpRequest, type ClientRequest, type IncomingMessage, type RequestOptions } from 'node:http';

/** The Confidential Space launcher's token server inside the box (notes/phase4-facts.md §1a). */
export const TEESERVER_SOCKET = '/run/container_launcher/teeserver.sock';
/** The launcher refreshes this default token (audience sts.googleapis.com) for STS and KMS. */
export const DEFAULT_TOKEN_PATH = '/run/container_launcher/attestation_verifier_claims_token';
export const TEE_TOKEN_MAX_BYTES = 64 * 1024;
export const TEE_TOKEN_TIMEOUT_MS = 10_000;
/** The launcher allows 5 token requests per second per project; stay below it. */
export const TEE_TOKEN_MIN_INTERVAL_MS = 250;

export interface TeeTokenRequest {
  audience: string;
  nonces: string[];
  tokenType?: 'OIDC' | 'PKI';
}

/** Attestation tokens for the box. Tests and the emulator supply their own. */
export interface TeeTokenSource {
  /** A custom-audience token whose nonces bind this session. Mint one per handshake step, never per relay poll. */
  token(request: TeeTokenRequest): Promise<string>;
  /** The launcher's default token, used only for the STS exchange behind KMS key release. */
  defaultToken(): Promise<string>;
}

export class TeeTokenError extends Error {
  constructor(message = 'The box could not get an attestation token from the launcher.') { super(message); this.name = 'TeeTokenError'; }
}

export interface TeeTokenSourceOptions {
  socketPath?: string;
  defaultTokenPath?: string;
  timeoutMs?: number;
  maxBytes?: number;
  minIntervalMs?: number;
  request?: (options: RequestOptions, callback: (response: IncomingMessage) => void) => ClientRequest;
  readFile?: (path: string) => Promise<Buffer>;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

const JWT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

function checkRequest(input: TeeTokenRequest): void {
  if (typeof input.audience !== 'string' || !input.audience || Buffer.byteLength(input.audience) > 512) throw new TeeTokenError('The attestation audience is invalid.');
  // Facts §1a: at most six nonces, each 10 to 74 bytes.
  if (!Array.isArray(input.nonces) || input.nonces.length > 6
    || input.nonces.some(nonce => typeof nonce !== 'string' || Buffer.byteLength(nonce) < 10 || Buffer.byteLength(nonce) > 74)) {
    throw new TeeTokenError('The attestation nonces are invalid.');
  }
  if (input.tokenType !== undefined && input.tokenType !== 'OIDC' && input.tokenType !== 'PKI') throw new TeeTokenError('The attestation token type is invalid.');
}

function token(text: string): string {
  const value = text.trim();
  if (!JWT.test(value)) throw new TeeTokenError();
  return value;
}

/** Talks to the launcher over its Unix socket with node:http; the body is exactly audience, nonces and token_type. */
export function createTeeTokenSource(options: TeeTokenSourceOptions = {}): TeeTokenSource {
  const socketPath = options.socketPath ?? TEESERVER_SOCKET;
  const timeoutMs = options.timeoutMs ?? TEE_TOKEN_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? TEE_TOKEN_MAX_BYTES;
  const minInterval = options.minIntervalMs ?? TEE_TOKEN_MIN_INTERVAL_MS;
  const send = options.request ?? httpRequest;
  const read = options.readFile ?? readFile;
  const now = options.now ?? Date.now;
  const sleep = options.sleep ?? (ms => new Promise<void>(resolve => setTimeout(resolve, ms)));
  let last = -Infinity;
  let queue: Promise<unknown> = Promise.resolve();

  function post(body: string): Promise<string> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (error: Error | null, value?: string) => {
        if (settled) return; settled = true;
        if (error) reject(error); else resolve(value!);
      };
      const req = send({ socketPath, method: 'POST', path: '/v1/token', timeout: timeoutMs,
        headers: { Host: 'localhost', 'Content-Type': 'application/json', 'Content-Length': String(Buffer.byteLength(body)) } }, response => {
        const chunks: Buffer[] = []; let length = 0;
        response.on('data', (chunk: Buffer) => {
          length += chunk.length;
          if (length > maxBytes) { response.destroy(); finish(new TeeTokenError('The launcher returned an attestation token that is too large.')); return; }
          chunks.push(chunk);
        });
        response.on('error', () => finish(new TeeTokenError()));
        response.on('end', () => {
          // The response is the raw JWT text whatever its Content-Type (facts §1a).
          if (response.statusCode !== 200) { finish(new TeeTokenError()); return; }
          try { finish(null, token(Buffer.concat(chunks).toString('utf8'))); } catch (error) { finish(error as Error); }
        });
      });
      req.on('timeout', () => { req.destroy(); finish(new TeeTokenError('The launcher did not return an attestation token in time.')); });
      req.on('error', () => finish(new TeeTokenError()));
      req.end(body);
    });
  }

  return {
    async token(input) {
      checkRequest(input);
      const body = JSON.stringify({ audience: input.audience, nonces: [...input.nonces], token_type: input.tokenType ?? 'OIDC' });
      const next = queue.catch(() => undefined).then(async () => {
        const wait = last + minInterval - now();
        if (wait > 0) await sleep(wait);
        last = now();
        return post(body);
      });
      queue = next;
      return next;
    },
    async defaultToken() {
      let bytes: Buffer;
      try { bytes = await read(options.defaultTokenPath ?? DEFAULT_TOKEN_PATH); }
      catch { throw new TeeTokenError('The box could not read the launcher\'s default attestation token.'); }
      if (bytes.length > maxBytes) throw new TeeTokenError('The launcher returned an attestation token that is too large.');
      return token(bytes.toString('utf8'));
    },
  };
}
