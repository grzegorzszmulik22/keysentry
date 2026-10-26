import { describe, expect, it } from 'vitest';
import { generateSecret } from '../../src/core/random.js';

describe('generateSecret', () => {
  it('defaults to a fresh URL-safe encoding of 32 random bytes', () => {
    const values = Array.from({ length: 16 }, () => generateSecret());

    expect(values.every((value) => /^[A-Za-z0-9_-]{43}$/.test(value))).toBe(true);
    expect(values.every((value) => Buffer.from(value, 'base64url').length === 32)).toBe(true);
    expect(new Set(values).size).toBe(16);
  });

  it('preserves a clear 64-character hexadecimal format', () => {
    const value = generateSecret('0123456789abcdef'.repeat(4));

    expect(/^[0-9a-f]{64}$/.test(value)).toBe(true);
    expect(Buffer.from(value, 'hex').length).toBe(32);
  });

  it('preserves padded standard base64 with 32 bytes', () => {
    const value = generateSecret('//////////////////////////////////////////8=');

    expect(/^[A-Za-z0-9+/]{43}=$/.test(value)).toBe(true);
    expect(Buffer.from(value, 'base64').length).toBe(32);
  });

  it('preserves clear formats near 32 bytes without shrinking new entropy', () => {
    const hex = generateSecret('ABCDEF'.repeat(10));
    const base64 = generateSecret('////////////////////////////////////////');

    expect(/^[0-9a-f]{64}$/.test(hex)).toBe(true);
    expect(Buffer.from(hex, 'hex').length).toBe(32);
    expect(/^[A-Za-z0-9+/]{43}=$/.test(base64)).toBe(true);
    expect(Buffer.from(base64, 'base64').length).toBe(32);
  });

  it('preserves a URL-safe base64 format', () => {
    const value = generateSecret('__________________________________________8');

    expect(/^[A-Za-z0-9_-]{43}$/.test(value)).toBe(true);
    expect(Buffer.from(value, 'base64url').length).toBe(32);
  });

  it('uses the default format for unrelated or short values', () => {
    const values = ['', 'password', 'abcdef', 'invalid!'.repeat(8), 'a'.repeat(128), `${'a'.repeat(40)}====`, `${'/'.repeat(40)}=`]
      .map((likeValue) => generateSecret(likeValue));

    expect(values.every((value) => /^[A-Za-z0-9_-]{43}$/.test(value))).toBe(true);
    expect(values.every((value) => Buffer.from(value, 'base64url').length === 32)).toBe(true);
  });
});
