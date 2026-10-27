import { afterEach, expect, test, vi } from 'vitest';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openVault, VaultUnavailableError } from '../../src/vault/index.js';
import type { Logger } from '../../src/types.js';
import type { runHelper } from '../../src/vault/exec.js';

const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map(d => rm(d, { recursive: true, force: true }))); });
async function options() {
  const userDir = await mkdtemp(join(tmpdir(), 'keysentry-open-')); dirs.push(userDir);
  return { userDir, env: {} as NodeJS.ProcessEnv, log: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() } as Logger,
    allowFileFallback: vi.fn(async (_reason: string) => true), passphrase: async () => Buffer.from('passphrase') };
}

test('openVault asks before falling back and explains how to install secret-tool', async () => {
  const opts = await options();
  const exec = vi.fn(async () => { throw new Error('missing helper'); });
  const vault = await openVault({ ...opts, platform: 'linux', env: { DBUS_SESSION_BUS_ADDRESS: 'session' }, exec });
  expect(vault.backend).toBe('encrypted-file');
  expect(opts.allowFileFallback).toHaveBeenCalledOnce();
  expect(opts.allowFileFallback.mock.calls[0]![0]).toContain('install libsecret-tools (Debian/Ubuntu) or libsecret (Fedora/Arch)');
  expect(opts.allowFileFallback.mock.calls[0]![0]).toContain('desktop session');
  await vault.set('item', Buffer.from('value'));
  expect(JSON.parse(await readFile(join(opts.userDir, 'vault.enc'), 'utf8')).v).toBe(1);
});
test('linux without D-Bus immediately asks for fallback without invoking helpers', async () => {
  const opts = await options();
  const exec = vi.fn();
  await openVault({ ...opts, platform: 'linux', exec });
  expect(exec).not.toHaveBeenCalled();
  expect(opts.allowFileFallback).toHaveBeenCalledOnce();
});
test.each([
  ['linux', 'install libsecret-tools'], ['darwin', 'unlock the login keychain (Keychain Access)'],
  ['win32', 'check that Windows PowerShell (powershell.exe) can run'],
])('declining fallback on %s explains the platform fix', async (platform, fix) => {
  const opts = await options();
  const exec = vi.fn(async () => { throw new Error('stdout-is-not-safe'); });
  const call = openVault({ ...opts, platform: platform as NodeJS.Platform, exec, allowFileFallback: async () => false });
  await expect(call).rejects.toBeInstanceOf(VaultUnavailableError);
  await expect(call).rejects.toMatchObject({ code: 'VAULT_UNAVAILABLE' });
  await expect(call).rejects.toThrow(fix);
  await expect(call).rejects.not.toThrow('stdout-is-not-safe');
});
test('KEYSENTRY_VAULT=env selects the env backend', async () => {
  const opts = await options();
  expect((await openVault({ ...opts, env: { KEYSENTRY_VAULT: 'env' } })).backend).toBe('env');
  expect(opts.allowFileFallback).not.toHaveBeenCalled();
});
test('explicit memory warns that nothing will be kept after exit', async () => {
  const opts = await options();
  expect((await openVault({ ...opts, env: { KEYSENTRY_VAULT: 'memory' } })).backend).toBe('memory');
  expect(opts.log.warn).toHaveBeenCalledWith(expect.stringMatching(/nothing will be kept after exit/i));
});
test('unknown KEYSENTRY_VAULT lists every valid backend', async () => {
  const opts = await options();
  const call = openVault({ ...opts, env: { KEYSENTRY_VAULT: 'unknown' } });
  await expect(call).rejects.toBeInstanceOf(TypeError);
  for (const id of ['macos-keychain', 'windows-dpapi', 'linux-secret-service', 'encrypted-file', 'env', 'memory']) {
    await expect(call).rejects.toThrow(id);
  }
});
test('platform backend is selected only after a set/get/delete probe round trip', async () => {
  const opts = await options();
  const items = new Map<string, Buffer>();
  const operations: string[] = [];
  const exec: typeof runHelper = async (_cmd, args, options) => {
    if (args[0] === '-i') {
      const line = options!.stdin!.toString().trim();
      const match = /^add-generic-password -U -s keysentry -a (\S+) -w (\S+)$/.exec(line)!;
      items.set(match[1]!, Buffer.from(match[2]!, 'base64'));
      operations.push(`set:${match[1]}`);
    } else if (args[0] === 'find-generic-password') {
      const name = args[args.indexOf('-a') + 1]!;
      operations.push(`get:${name}`);
      const item = items.get(name);
      return { code: item ? 0 : 44, stdout: Buffer.from(item?.toString('base64') ?? ''), stderr: '' };
    } else {
      const name = args[args.indexOf('-a') + 1]!;
      items.delete(name); operations.push(`delete:${name}`);
    }
    return { code: 0, stdout: Buffer.alloc(0), stderr: '' };
  };
  const vault = await openVault({ ...opts, platform: 'darwin', exec });
  expect(vault.backend).toBe('macos-keychain');
  expect(operations).toContain('set:__probe__');
  expect(operations).toContain('get:__probe__');
  expect(operations).toContain('delete:__probe__');
  expect(await vault.list()).toEqual([]);
  expect(opts.allowFileFallback).not.toHaveBeenCalled();
});
test('unsupported platform offers the encrypted file', async () => {
  const opts = await options();
  expect((await openVault({ ...opts, platform: 'freebsd' })).backend).toBe('encrypted-file');
  expect(opts.allowFileFallback).toHaveBeenCalledOnce();
});

test('probe rejects a successful helper that returns a different value', async () => {
  const opts = await options();
  const exec: typeof runHelper = async (_cmd, args) => ({
    code: 0, stdout: Buffer.from(args[0] === 'find-generic-password' ? Buffer.from('different').toString('base64') : ''), stderr: '',
  });
  const vault = await openVault({ ...opts, platform: 'darwin', exec });
  expect(vault.backend).toBe('encrypted-file');
  expect(opts.allowFileFallback).toHaveBeenCalledOnce();
});

test('explicit encrypted-file chooses vault.enc without asking for a fallback', async () => {
  const opts = await options();
  const vault = await openVault({ ...opts, env: { KEYSENTRY_VAULT: 'encrypted-file' } });
  expect(vault.backend).toBe('encrypted-file');
  expect(opts.allowFileFallback).not.toHaveBeenCalled();
});

test('explicit unavailable operating system backend gives its fix without substituting another backend', async () => {
  const opts = await options();
  await expect(openVault({ ...opts, env: { KEYSENTRY_VAULT: 'windows-dpapi' }, platform: 'linux',
    exec: async () => { throw new Error('blocked'); } })).rejects.toThrow('check that Windows PowerShell (powershell.exe) can run');
  expect(opts.allowFileFallback).not.toHaveBeenCalled();
});

test('missing passphrase callback explains how to open the encrypted file', async () => {
  const opts = await options();
  await expect(openVault({ ...opts, passphrase: undefined, env: { KEYSENTRY_VAULT: 'encrypted-file' } })).rejects.toThrow('passphrase');
});
