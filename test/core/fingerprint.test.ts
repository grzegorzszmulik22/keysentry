import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fingerprint, loadOrCreateFingerprintKey, makeHint } from '../../src/core/fingerprint.js';

const dirs: string[] = [];
async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'keysentry-fingerprint-'));
  dirs.push(dir);
  return dir;
}
afterEach(async () => { await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true }))); });

describe('fingerprint', () => {
  it('uses keyed SHA256 truncated to 128 bits', () => {
    expect(fingerprint('The quick brown fox jumps over the lazy dog', Buffer.from('key')))
      .toBe('f7bc83f430538424b13298e6aa6fb143');
    expect(fingerprint('same value', Buffer.alloc(32, 1))).not.toBe(fingerprint('same value', Buffer.alloc(32, 2)));
  });

  it('persists one private, complete key across simultaneous first calls', async () => {
    const dir = join(await tempDir(), '.keysentry');
    const keys = await Promise.all(Array.from({ length: 24 }, () => loadOrCreateFingerprintKey(dir)));
    expect(keys.every((key) => key.length === 32 && key.equals(keys[0]!))).toBe(true);
    expect(await readFile(join(dir, 'fingerprint.key'))).toEqual(keys[0]);
    expect(await loadOrCreateFingerprintKey(dir)).toEqual(keys[0]);
    expect(await readFile(join(dir, '.gitignore'), 'utf8')).toContain('*');
    expect((await readdir(dir)).filter((name) => name !== '.gitignore')).toEqual(['fingerprint.key']);
    if (process.platform !== 'win32') expect((await stat(join(dir, 'fingerprint.key'))).mode & 0o777).toBe(0o600);
  });

  it('preserves another operation’s temporary file on an exclusive-create collision', async () => {
    const dir = await tempDir();
    const collision = join(dir, `.fingerprint-${'42'.repeat(16)}.tmp`);
    const sentinel = Buffer.from('owned-by-another-operation');
    await writeFile(collision, sentinel);
    vi.doMock('node:crypto', async () => ({
      ...await vi.importActual<typeof import('node:crypto')>('node:crypto'),
      randomBytes: (size: number) => Buffer.alloc(size, 0x42),
    }));
    vi.resetModules();
    try {
      const module = await import('../../src/core/fingerprint.js');
      await expect(module.loadOrCreateFingerprintKey(dir)).rejects.toThrow(/fingerprint key/i);
      const remaining = await readFile(collision).catch(() => null);
      expect(remaining?.equals(sentinel) ?? false).toBe(true);
    } finally {
      vi.doUnmock('node:crypto');
      vi.resetModules();
    }
  });

  it.each([0, 31, 33, 64])('rejects corrupt key files of length %i without exposing their contents', async (length) => {
    const dir = await tempDir();
    const corrupt = 's'.repeat(length);
    await writeFile(join(dir, 'fingerprint.key'), corrupt);
    await expect(loadOrCreateFingerprintKey(dir)).rejects.toThrow(/fingerprint key/i);
    if (length > 0) {
      try { await loadOrCreateFingerprintKey(dir); } catch (error) { expect(String(error)).not.toContain(corrupt); }
    }
    expect(await readFile(join(dir, 'fingerprint.key'), 'utf8')).toBe(corrupt);
  });
});

describe('makeHint', () => {
  it.each([
    ['sk-or-v1-abcdefgh1234', 'sk-or-v…1234'],
    ['sk_live_abcdefgh1234', 'sk_live…1234'],
    ['sk-ant-abcdefgh1234', 'sk-ant-…1234'],
    ['ghp_abcdefghijkl1234', 'ghp_…1234'],
    ['AKIAabcdefghijkl1234', 'AKIA…1234'],
    ['randomvalueabcdefgh', 'rand…efgh'],
    ['0123456789abcdef', '0123…cdef'],
  ])('returns a bounded hint for %s', (value, hint) => {
    expect(makeHint(value)).toBe(hint);
    expect(makeHint(value)!.split('…')[0]!.length).toBeLessThanOrEqual(7);
  });
  it.each(['', 'short-value', '0123456789abcde'])('does not hint at short values', (value) => {
    expect(makeHint(value)).toBeNull();
  });
});
