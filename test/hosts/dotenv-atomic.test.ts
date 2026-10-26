import { mkdtemp, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createDotenvHost } from '../../src/hosts/dotenv.js';
import { silentLogger } from '../helpers/fake-http.js';

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>();
  return { ...actual, rename: vi.fn(actual.rename), readFile: vi.fn(actual.readFile) };
});

const roots: string[] = [];
afterEach(async () => {
  vi.mocked(rename).mockReset();
  const actual = await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises');
  vi.mocked(rename).mockImplementation(actual.rename);
  vi.mocked(readFile).mockImplementation(actual.readFile);
  await Promise.all(roots.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function fixture() {
  const dir = await mkdtemp(join(resolve('test/hosts'), '.dotenv-atomic-test-'));
  roots.push(dir);
  const file = join(dir, '.env.local');
  await writeFile(file, 'KEY=original\n', { mode: 0o644 });
  const host = createDotenvHost({ roots: [dir], log: silentLogger });
  const [service] = await host.listServices();
  return { dir, file, host, service: service! };
}

describe('dotenv atomic file boundary', () => {
  it('keeps the complete temporary file under .env* and private until rename', async () => {
    const { dir, file, host, service } = await fixture();
    const actual = await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises');
    vi.mocked(rename).mockImplementationOnce(async (from, to) => {
      expect(dirname(String(from))).toBe(dir);
      expect(basename(String(from))).toMatch(/^\.env\.local\.keysentry-[0-9a-f-]+\.tmp$/);
      expect(to).toBe(file);
      expect(await readFile(from, 'utf8')).toBe('KEY=replacement\n');
      if (process.platform !== 'win32') expect((await stat(from)).mode & 0o777).toBe(0o600);
      await actual.rename(from, to);
    });
    await host.writeVariables(service, { KEY: 'replacement' }, { skipDeploy: true });
    expect(await readFile(file, 'utf8')).toBe('KEY=replacement\n');
    expect(await readdir(dir)).toEqual(['.env.local']);
  });

  it('unlinks a complete plaintext temporary file if rename fails and sanitizes the error', async () => {
    const { dir, file, host, service } = await fixture();
    vi.mocked(rename).mockImplementationOnce(async (from) => {
      expect(await readFile(from, 'utf8')).toBe('KEY=secret-replacement\n');
      throw new Error('secret-replacement upstream details');
    });
    const error = await host.writeVariables(service, { KEY: 'secret-replacement' }, { skipDeploy: true }).catch((err: unknown) => err);
    expect(String(error)).toContain('atomic write failed');
    expect(String(error)).not.toContain('secret-replacement');
    expect(await readFile(file, 'utf8')).toBe('KEY=original\n');
    expect(await readdir(dir)).toEqual(['.env.local']);
  });

  it('warns and skips an unreadable file without failing discovery of other env files', async () => {
    const { dir, host } = await fixture();
    const bad = join(dir, '.env.bad');
    await writeFile(bad, 'KEY=hidden-content\n');
    const actual = await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises');
    vi.mocked(readFile).mockImplementation((...args: Parameters<typeof readFile>) => {
      if (args[0] === bad) return Promise.reject(new Error('hidden-content permission details'));
      return actual.readFile(...args);
    });
    const warnings: unknown[] = [];
    const checked = createDotenvHost({ roots: [dir], log: { ...silentLogger, warn: (...args) => { warnings.push(args); } } });
    expect((await checked.listServices()).map((service) => service.serviceName)).toEqual(['.env.local']);
    expect(warnings).toHaveLength(1);
    expect(JSON.stringify(warnings)).not.toContain('hidden-content');
    // The original adapter also uses per-file resilience rather than failing the entire host.
    expect((await host.listServices()).map((service) => service.serviceName)).toEqual(['.env.local']);
  });
});
