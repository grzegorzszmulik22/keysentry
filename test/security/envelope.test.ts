import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { DecryptError, openBytes, sealBytes } from '../../src/security/index.js';

const key = randomBytes(32);
const plaintext = Buffer.from('sk-or-v1-super-secret-value', 'utf8');

describe('sealBytes / openBytes', () => {
  it('round-trips and starts with the KS1 header', () => {
    const sealed = sealBytes(key, plaintext, 'state:inventory');
    expect(sealed.subarray(0, 3).toString('ascii')).toBe('KS1');
    expect(sealed[3]).toBe(0x01);
    expect(sealed.length).toBe(4 + 12 + 16 + plaintext.length);
    expect(openBytes(key, sealed, 'state:inventory').equals(plaintext)).toBe(true);
  });

  it('uses a fresh IV every time', () => {
    const a = sealBytes(key, plaintext, 'x');
    const b = sealBytes(key, plaintext, 'x');
    expect(a.equals(b)).toBe(false);
  });

  it('never contains the plaintext', () => {
    const sealed = sealBytes(key, plaintext, 'x');
    expect(sealed.includes(plaintext)).toBe(false);
  });

  it('rejects every flipped byte', () => {
    const sealed = sealBytes(key, plaintext, 'x');
    for (let i = 0; i < sealed.length; i++) {
      const bad = Buffer.from(sealed);
      bad[i] ^= 0x01;
      expect(() => openBytes(key, bad, 'x')).toThrow(DecryptError);
    }
  });

  it('rejects a wrong aad, a wrong key and truncated input without leaking', () => {
    const sealed = sealBytes(key, plaintext, 'vault:a');
    const wrongKey = randomBytes(32);
    for (const attempt of [
      () => openBytes(key, sealed, 'vault:b'),
      () => openBytes(wrongKey, sealed, 'vault:a'),
      () => openBytes(key, sealed.subarray(0, 20), 'vault:a'),
      () => openBytes(key, Buffer.alloc(0), 'vault:a'),
    ]) {
      let caught: unknown;
      try {
        attempt();
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(DecryptError);
      const err = caught as DecryptError;
      expect(err.code).toBe('DECRYPT_FAILED');
      expect(err.message).not.toContain(plaintext.toString('utf8'));
      expect(err.message).not.toContain(key.toString('hex'));
      expect(err.message).not.toContain(wrongKey.toString('hex'));
    }
  });

  it('requires a 32-byte key', () => {
    expect(() => sealBytes(randomBytes(16), plaintext, 'x')).toThrow(TypeError);
    expect(() => openBytes(randomBytes(31), sealBytes(key, plaintext, 'x'), 'x')).toThrow(TypeError);
  });

  it('round-trips an empty plaintext', () => {
    const sealed = sealBytes(key, Buffer.alloc(0), 'empty');
    expect(openBytes(key, sealed, 'empty').length).toBe(0);
  });
});
