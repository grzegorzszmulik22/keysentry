import { afterEach, expect, test, vi } from 'vitest';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openVault, VaultUnavailableError } from '../../src/vault/index.js';
import type { Logger } from '../../src/types.js';
import type { runHelper } from '../../src/vault/exec.js';
import { getProjectId, stateKey } from '../../src/vault/keys.js';

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

function fakeSecretTool(): typeof runHelper {
  const items = new Map<string, string>();
  return async (_cmd, args, opts) => {
    const account = args[args.indexOf('account') + 1]!;
    if (args[0] === 'store') { items.set(account, opts?.stdin?.toString('utf8').trim() ?? ''); return { code: 0, stdout: Buffer.alloc(0), stderr: '' }; }
    if (args[0] === 'lookup') return items.has(account) ? { code: 0, stdout: Buffer.from(items.get(account)!), stderr: '' } : { code: 1, stdout: Buffer.alloc(0), stderr: '' };
    if (args[0] === 'clear') return { code: items.delete(account) ? 0 : 1, stdout: Buffer.alloc(0), stderr: '' };
    return { code: 2, stdout: Buffer.alloc(0), stderr: 'unexpected' };
  };
}

test('an accepted encrypted-file fallback retains the same state key when the OS store becomes reachable', async () => {
  const opts = await options();
  const projectId = await getProjectId(join(opts.userDir, 'project', '.keysentry'));
  const exec = fakeSecretTool();
  const overSsh = await openVault({ ...opts, platform: 'linux', exec });
  expect(overSsh.backend).toBe('encrypted-file');
  const firstKey = await stateKey(overSsh, projectId);
  opts.allowFileFallback.mockClear();

  const onDesktop = await openVault({ ...opts, platform: 'linux', env: { DBUS_SESSION_BUS_ADDRESS: 'session' }, exec });
  const secondKey = await stateKey(onDesktop, projectId);
  expect({ backend: onDesktop.backend, sameStateKey: secondKey.equals(firstKey), asked: opts.allowFileFallback.mock.calls.length > 0 })
    .toEqual({ backend: 'encrypted-file', sameStateKey: true, asked: false });
  expect(JSON.parse(await readFile(join(opts.userDir, 'vault-backend.json'), 'utf8'))).toEqual({ backend: 'encrypted-file' });
});

test('an existing file without a remembered choice is selected with a warning non-interactively', async () => {
  const opts = await options();
  const initial = await openVault({ ...opts, env: { KEYSENTRY_VAULT: 'encrypted-file' } });
  await initial.set('item', Buffer.from('value'));
  await rm(join(opts.userDir, 'vault-backend.json'), { force: true });
  const vault = await openVault({ ...opts, platform: 'linux', env: { DBUS_SESSION_BUS_ADDRESS: 'session' }, exec: fakeSecretTool() });
  expect(vault.backend).toBe('encrypted-file');
  expect(opts.log.warn).toHaveBeenCalledWith(expect.stringMatching(/both.*encrypted file.*operating system.*using the encrypted file/i));
  expect(opts.allowFileFallback).not.toHaveBeenCalled();
});

test.each(['encrypted-file', 'linux-secret-service'] as const)('an interactive choice between existing stores remembers %s', async backend => {
  const opts = await options();
  const initial = await openVault({ ...opts, env: { KEYSENTRY_VAULT: 'encrypted-file' } });
  await initial.set('item', Buffer.from('value'));
  await rm(join(opts.userDir, 'vault-backend.json'), { force: true });
  const chooseBackend = vi.fn(async () => backend);
  const vault = await openVault({ ...opts, platform: 'linux', env: { DBUS_SESSION_BUS_ADDRESS: 'session' }, exec: fakeSecretTool(), chooseBackend });
  expect(vault.backend).toBe(backend);
  expect(chooseBackend).toHaveBeenCalledExactlyOnceWith('linux-secret-service');
  expect(JSON.parse(await readFile(join(opts.userDir, 'vault-backend.json'), 'utf8'))).toEqual({ backend });
});

test('a remembered OS backend does not switch to a different key set when unavailable', async () => {
  const opts = await options();
  await openVault({ ...opts, platform: 'linux', env: { DBUS_SESSION_BUS_ADDRESS: 'session' }, exec: fakeSecretTool() });
  await expect(openVault({ ...opts, platform: 'linux' })).rejects.toThrow(VaultUnavailableError);
  expect(opts.allowFileFallback).not.toHaveBeenCalled();
});

test('an invalid backend preference fails closed instead of selecting a different key set', async () => {
  const opts = await options();
  await writeFile(join(opts.userDir, 'vault-backend.json'), JSON.stringify({ backend: 'unknown' }));
  await expect(openVault({ ...opts, platform: 'linux', exec: fakeSecretTool() })).rejects.toThrow(/saved vault backend choice/i);
  expect(opts.allowFileFallback).not.toHaveBeenCalled();
});

test('an explicit backend overrides and replaces the remembered choice', async () => {
  const opts = await options();
  await writeFile(join(opts.userDir, 'vault-backend.json'), JSON.stringify({ backend: 'linux-secret-service' }));
  const vault = await openVault({ ...opts, env: { KEYSENTRY_VAULT: 'memory' } });
  expect(vault.backend).toBe('memory');
  expect(JSON.parse(await readFile(join(opts.userDir, 'vault-backend.json'), 'utf8'))).toEqual({ backend: 'memory' });
});
