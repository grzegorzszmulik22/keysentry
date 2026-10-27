import type { IncomingMessage, ServerResponse } from 'node:http';

export const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

export class DashboardError extends Error {
  constructor(readonly status: number, message: string) { super(message); this.name = 'DashboardError'; }
}

export function securityHeaders(res: ServerResponse): void {
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'publickey-credentials-get=(self), publickey-credentials-create=(self)');
}

/** Forwarded headers never participate in the local-origin decision. */
export function checkRequest(req: IncomingMessage, port: number): void {
  if (req.headers.host !== `localhost:${port}` && req.headers.host !== `127.0.0.1:${port}`) {
    throw new DashboardError(403, 'Open keysentry using the local dashboard address.');
  }
  if (req.method === 'POST' && req.headers.origin !== `http://localhost:${port}`) {
    throw new DashboardError(403, 'Send this request from the local dashboard.');
  }
}

/** Bound bytes before decoding, then require valid UTF-8 JSON. */
export async function readJson(req: IncomingMessage): Promise<unknown> {
  const limit = 65_536;
  const type = req.headers['content-type'] ?? '';
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(type) || req.headers['content-encoding'] !== undefined) {
    throw new DashboardError(415, 'Send an uncompressed JSON body.');
  }
  const declared = req.headers['content-length'];
  if (declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > limit)) {
    req.resume();
    throw new DashboardError(413, 'Keep the JSON body within 64 KiB.');
  }
  const data = await new Promise<Buffer>((resolve, reject) => {
    let bytes = 0;
    const parts: Buffer[] = [];
    const cleanup = () => { req.off('data', chunk); req.off('end', end); req.off('error', error); req.off('aborted', aborted); };
    const error = () => { cleanup(); reject(new DashboardError(400, 'Send a complete JSON body.')); };
    const aborted = () => { error(); };
    const end = () => { cleanup(); resolve(Buffer.concat(parts, bytes)); };
    const chunk = (part: Buffer) => {
      bytes += part.length;
      if (bytes > limit) {
        cleanup(); req.resume(); reject(new DashboardError(413, 'Keep the JSON body within 64 KiB.'));
      } else parts.push(part);
    };
    req.on('data', chunk); req.on('end', end); req.on('error', error); req.on('aborted', aborted);
  });
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data)); }
  catch { throw new DashboardError(400, 'Send a valid JSON body.'); }
}

export function json(res: ServerResponse, status: number, value: unknown): void {
  // Serialize before writing headers so a handler's invalid result gets a clean fixed error.
  const body = JSON.stringify(value);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(body);
}
