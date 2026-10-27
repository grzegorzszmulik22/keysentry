import { createHash, generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { boxKeyNonce, challengeNonce, parseJwt } from '../../../src/box/attestation/jwt.js';

function encoded(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

const header = encoded({ alg: 'RS256', typ: 'JWT', kid: 'test-key' });
const payload = encoded({ iss: 'issuer' });
const signature = Buffer.alloc(256, 1).toString('base64url');

describe('strict JWT parsing', () => {
  it('preserves the exact signed bytes and decodes a compact token', () => {
    const result = parseJwt(`${header}.${payload}.${signature}`);
    expect(result.header).toEqual({ alg: 'RS256', typ: 'JWT', kid: 'test-key' });
    expect(result.claims).toEqual({ iss: 'issuer' });
    expect(result.signingInput.toString()).toBe(`${header}.${payload}`);
    expect(result.signature).toEqual(Buffer.alloc(256, 1));
  });

  it.each([
    '', `${header}.${payload}`, `${header}.${payload}.${signature}.extra`,
    `${header}=.${payload}.${signature}`, `${header}.${payload}=.${signature}`,
    `${header}.${payload}.${signature}=`, `${header}.${payload}.+w`,
    `${header}.${payload}./w`, `${header}.${payload}.AB`,
    `${header}.${payload}.A`, `.${payload}.${signature}`,
    `${encoded([])}.${payload}.${signature}`, `${header}.${encoded(null)}.${signature}`,
    `${header}.${encoded('text')}.${signature}`, `${header}.wyg.${signature}`,
    `${header}.${Buffer.from('{').toString('base64url')}.${signature}`,
  ])('rejects malformed compact encoding %#', (token) => {
    expect(() => parseJwt(token)).toThrow();
  });
});

describe('session nonces', () => {
  it('hashes exactly the raw 32-byte X25519 key', () => {
    const raw = generateKeyPairSync('x25519').publicKey.export({ format: 'jwk' }).x!;
    const key = Buffer.from(raw, 'base64url');
    const nonce = boxKeyNonce(key);
    expect(nonce).toBe(createHash('sha256').update(key).digest('base64url'));
    expect(nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it.each([0, 31, 33, 44])('rejects a raw key of %i bytes', (size) => {
    expect(() => boxKeyNonce(Buffer.alloc(size))).toThrow();
  });

  it('makes independent 32-byte challenges inside the nonce size limit', () => {
    const nonces = new Set(Array.from({ length: 20 }, () => challengeNonce()));
    expect(nonces.size).toBe(20);
    for (const nonce of nonces) {
      expect(nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(Buffer.from(nonce, 'base64url')).toHaveLength(32);
    }
  });
});
