import { createHash, randomBytes } from 'node:crypto';

export interface ParsedJwt {
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
  signingInput: Buffer;
  signature: Buffer;
}

/** Node's base64url decoder is permissive; a JWT segment must be canonical. */
export function decodeBase64url(segment: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) throw new Error('Invalid JWT encoding.');
  const bytes = Buffer.from(segment, 'base64url');
  if (bytes.toString('base64url') !== segment) throw new Error('Invalid JWT encoding.');
  return bytes;
}

function jsonObject(bytes: Buffer): Record<string, unknown> {
  const decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const value: unknown = JSON.parse(decoded);
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid JWT object.');
  }
  return value as Record<string, unknown>;
}

/** Parse only; no parsed claim or header is trusted until signature verification. */
export function parseJwt(token: string): ParsedJwt {
  if (typeof token !== 'string' || token.length > 128 * 1024) throw new Error('Invalid JWT size.');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Expected a three-part JWT.');
  const [header, payload, signature] = parts as [string, string, string];
  return {
    header: jsonObject(decodeBase64url(header)),
    claims: jsonObject(decodeBase64url(payload)),
    signingInput: Buffer.from(`${header}.${payload}`, 'ascii'),
    signature: decodeBase64url(signature),
  };
}

/** Bind the raw X25519 public key, rather than its SPKI or textual encoding. */
export function boxKeyNonce(publicKeyRaw: Buffer): string {
  if (publicKeyRaw.length !== 32) throw new Error('Expected a 32-byte X25519 public key.');
  return createHash('sha256').update(publicKeyRaw).digest('base64url');
}

export function challengeNonce(): string {
  return randomBytes(32).toString('base64url');
}
