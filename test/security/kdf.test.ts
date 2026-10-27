import { describe, expect, it } from 'vitest';
import { DEFAULT_SCRYPT, deriveKeyFromPassphrase } from '../../src/security/index.js';

const fast = { N: 1024, r: 8, p: 1 };

describe('deriveKeyFromPassphrase', () => {
  it('has the documented defaults', () => {
    expect(DEFAULT_SCRYPT).toEqual({ N: 131072, r: 8, p: 1 });
  });

  it('is deterministic per salt and returns 32 bytes', async () => {
    const salt = Buffer.alloc(16, 7);
    const a = await deriveKeyFromPassphrase(Buffer.from('correct horse'), salt, fast);
    const b = await deriveKeyFromPassphrase(Buffer.from('correct horse'), salt, fast);
    expect(a.length).toBe(32);
    expect(a.equals(b)).toBe(true);
  });

  it('changes with the salt and with the passphrase', async () => {
    const salt = Buffer.alloc(16, 7);
    const base = await deriveKeyFromPassphrase(Buffer.from('correct horse'), salt, fast);
    const otherSalt = await deriveKeyFromPassphrase(Buffer.from('correct horse'), Buffer.alloc(16, 8), fast);
    const otherPass = await deriveKeyFromPassphrase(Buffer.from('correct horsf'), salt, fast);
    expect(base.equals(otherSalt)).toBe(false);
    expect(base.equals(otherPass)).toBe(false);
  });

  it('runs with the default parameters', async () => {
    const key = await deriveKeyFromPassphrase(Buffer.from('pw'), Buffer.alloc(16, 1));
    expect(key.length).toBe(32);
  });

  it('rejects a short salt', async () => {
    await expect(deriveKeyFromPassphrase(Buffer.from('pw'), Buffer.alloc(4), fast)).rejects.toThrow(TypeError);
  });
});
