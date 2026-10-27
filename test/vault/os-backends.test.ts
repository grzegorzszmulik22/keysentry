import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { createMacosKeychainVault } from '../../src/vault/backends/macos-keychain.js';
import { createLinuxSecretServiceVault } from '../../src/vault/backends/linux-secret-service.js';
import { createWindowsDpapiVault } from '../../src/vault/backends/windows-dpapi.js';
import type { runHelper } from '../../src/vault/exec.js';

const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true }))); });

async function directory() {
  const dir = await mkdtemp(join(tmpdir(), 'keysentry-os-vault-'));
  dirs.push(dir);
  return dir;
}

function osFake(kind: 'macos' | 'linux') {
  const items = new Map<string, string>();
  const exec = vi.fn<typeof runHelper>(async (_cmd, args, opts) => {
    const ok = (stdout = '') => ({ code: 0, stdout: Buffer.from(stdout), stderr: '' });
    if (kind === 'macos') {
      if (args[0] === '-i') {
        const line = opts!.stdin!.toString('utf8');
        const match = /^add-generic-password -U -s keysentry -a ([A-Za-z0-9/_.@#-]+) -w ([A-Za-z0-9+/=]+|"")\n$/.exec(line);
        if (!match) throw new Error('Unexpected keychain input');
        items.set(match[1]!, match[2] === '""' ? '' : match[2]!);
        return ok();
      }
      const name = args[args.indexOf('-a') + 1]!;
      if (args[0] === 'find-generic-password') return items.has(name) ? ok(items.get(name)! + '\n') : { code: 44, stdout: Buffer.alloc(0), stderr: 'item not found' };
      if (args[0] === 'delete-generic-password') return items.delete(name) ? ok() : { code: 44, stdout: Buffer.alloc(0), stderr: 'item not found' };
    } else {
      const name = args[args.indexOf('account') + 1]!;
      if (args[0] === 'store') { items.set(name, opts!.stdin!.toString('utf8').trim()); return ok(); }
      if (args[0] === 'lookup') return items.has(name) ? ok(items.get(name)! + '\n') : { code: 1, stdout: Buffer.alloc(0), stderr: '' };
      if (args[0] === 'clear') return items.delete(name) ? ok() : { code: 1, stdout: Buffer.alloc(0), stderr: '' };
    }
    throw new Error('Unexpected helper operation');
  });
  return { items, exec };
}

describe.each(['macos', 'linux'] as const)('%s credential store', (kind) => {
  const create = (exec: typeof runHelper) => kind === 'macos' ? createMacosKeychainVault({ exec }) : createLinuxSecretServiceVault({ exec });

  test('round-trips binary values and persists a sorted names index without internal items', async () => {
    const { items, exec } = osFake(kind);
    const vault = create(exec);
    const value = Buffer.from([0, 255, 10, 13, 128]);
    await vault.set('cred/Z', value);
    await vault.set('cred/A@read', Buffer.from('read-token'));
    await vault.set('__probe__', Buffer.from('probe'));
    expect(await vault.get('cred/Z')).toEqual(value);
    expect(await create(exec).list('cred/')).toEqual(['cred/A@read', 'cred/Z']);
    expect(JSON.parse(Buffer.from(items.get('__index__')!, 'base64').toString())).toEqual(['cred/A@read', 'cred/Z']);
    expect(await vault.list()).toEqual(['cred/A@read', 'cred/Z']);
    expect(await vault.delete('cred/Z')).toBe(true);
    expect(await vault.delete('cred/Z')).toBe(false);
    expect(await vault.get('cred/Z')).toBeNull();
    expect(await vault.list()).toEqual(['cred/A@read']);
  });

  test('helpers never receive plaintext or its base64 in args or an environment', async () => {
    const { exec } = osFake(kind);
    const value = Buffer.from('unique-plaintext-secret-293847');
    await create(exec).set('cred/TOKEN', value);
    for (const [, args, opts] of exec.mock.calls) {
      expect(JSON.stringify(args)).not.toContain(value.toString());
      expect(JSON.stringify(args)).not.toContain(value.toString('base64'));
      expect(opts).not.toHaveProperty('env');
    }
    const call = exec.mock.calls.find(([, args]) => args[0] === (kind === 'macos' ? '-i' : 'store'))!;
    expect(call[2]!.stdin!.toString()).toContain(value.toString('base64'));
    if (kind === 'macos') expect(call[1]).toEqual(['-i']);
    else expect(call[1]).toEqual(['store', '--label', 'keysentry cred/TOKEN', 'service', 'keysentry', 'account', 'cred/TOKEN']);
  });

  test.each(['bad name', 'bad\nname', 'bad"name', "bad'name", ''])('rejects invalid name %j before invoking a helper', async (name) => {
    const { exec } = osFake(kind);
    const vault = create(exec);
    await expect(vault.get(name)).rejects.toBeInstanceOf(TypeError);
    await expect(vault.set(name, Buffer.from('value'))).rejects.toBeInstanceOf(TypeError);
    await expect(vault.delete(name)).rejects.toBeInstanceOf(TypeError);
    expect(exec).not.toHaveBeenCalled();
  });

  test('serializes concurrent writes so the index retains every name', async () => {
    const { exec } = osFake(kind);
    const vault = create(exec);
    await Promise.all(Array.from({ length: 8 }, (_, n) => vault.set(`cred/${n}`, Buffer.from(String(n)))));
    expect(await vault.list()).toEqual(Array.from({ length: 8 }, (_, n) => `cred/${n}`));
  });

  test('round-trips an empty buffer', async () => {
    const { exec } = osFake(kind);
    const vault = create(exec);
    await vault.set('empty', Buffer.alloc(0));
    expect(await vault.get('empty')).toEqual(Buffer.alloc(0));
  });

  test('rejects helper failures without echoing stdout, stderr, or helper errors', async () => {
    const secret = 'unique-helper-secret-223344';
    for (const result of [
      { code: 2, stdout: Buffer.from(secret), stderr: secret },
      { code: 0, stdout: Buffer.from(secret), stderr: secret },
    ]) {
      const exec = vi.fn<typeof runHelper>(async () => result);
      await expect(create(exec).get('cred/TOKEN')).rejects.not.toThrow(secret);
    }
    const exec = vi.fn<typeof runHelper>(async () => { throw new Error(secret); });
    await expect(create(exec).set('cred/TOKEN', Buffer.from(secret))).rejects.not.toThrow(secret);
  });

  test('rejects a malformed names index without returning its contents', async () => {
    const { exec, items } = osFake(kind);
    items.set('__index__', Buffer.from('secret-corrupt-index').toString('base64'));
    await expect(create(exec).list()).rejects.not.toThrow('secret-corrupt-index');
  });
});

test('linux delete reports missing items even when secret-tool clear would succeed', async () => {
  const exec = vi.fn<typeof runHelper>(async (_cmd, args) => args[0] === 'lookup'
    ? { code: 1, stdout: Buffer.alloc(0), stderr: '' }
    : { code: 0, stdout: Buffer.alloc(0), stderr: '' });
  const vault = createLinuxSecretServiceVault({ exec });
  expect(await vault.delete('cred/MISSING')).toBe(false);
  expect(exec.mock.calls.some(([, args]) => args[0] === 'clear')).toBe(false);
});

test('linux delete discards its lookup output after checking an existing item', async () => {
  const stdout = Buffer.from(Buffer.from('temporary-existing-secret').toString('base64'));
  const exec = vi.fn<typeof runHelper>(async (_cmd, args) => {
    if (args[0] === 'lookup') return { code: 0, stdout, stderr: '' };
    return { code: 0, stdout: Buffer.alloc(0), stderr: '' };
  });
  expect(await createLinuxSecretServiceVault({ exec }).delete('__probe__')).toBe(true);
  expect(stdout).toEqual(Buffer.alloc(stdout.length));
  expect(exec.mock.calls.map(([, args]) => args[0])).toEqual(['lookup', 'clear']);
});

function dpapiFake() {
  return vi.fn<typeof runHelper>(async (cmd, args, opts) => {
    expect(cmd).toBe('powershell.exe');
    expect(args.slice(0, 3)).toEqual(['-NoProfile', '-NonInteractive', '-EncodedCommand']);
    const script = Buffer.from(args[3]!, 'base64').toString('utf16le');
    const [name, payload] = opts!.stdin!.toString('utf8').trimEnd().split('\n');
    expect(name).toMatch(/^[A-Za-z0-9/_.@#-]+$/);
    if (script.includes('::Protect(')) return { code: 0, stdout: Buffer.from(Buffer.from(`protected:${payload}`).toString('base64')), stderr: '' };
    expect(script).toContain('::Unprotect(');
    const protectedValue = Buffer.from(payload!, 'base64').toString();
    expect(protectedValue).toMatch(/^protected:/);
    return { code: 0, stdout: Buffer.from(protectedValue.slice('protected:'.length)), stderr: '' };
  });
}

test('windows backend passes a fixed UTF-16LE script via -EncodedCommand and name/value via stdin', async () => {
  const dir = await directory();
  const exec = dpapiFake();
  const vault = createWindowsDpapiVault({ dir, exec });
  const value = Buffer.from('unique-dpapi-secret-882211');
  await vault.set('cred/TOKEN', value);
  expect(await vault.get('cred/TOKEN')).toEqual(value);
  await vault.set('cred/OTHER', Buffer.from('other-value'));
  const first = exec.mock.calls[0]!;
  const script = Buffer.from(first[1][3]!, 'base64').toString('utf16le');
  expect(script).toContain('Add-Type -AssemblyName System.Security');
  expect(script).toContain('keysentry-v1:');
  expect(script).toContain('CurrentUser');
  expect(script).not.toContain('cred/TOKEN');
  expect(script).not.toContain(value.toString('base64'));
  expect(first[2]!.stdin!.toString()).toBe(`cred/TOKEN\n${value.toString('base64')}\n`);
  const protectCalls = exec.mock.calls.filter(([, args]) => Buffer.from(args[3]!, 'base64').toString('utf16le').includes('::Protect('));
  expect(protectCalls[0]![1]).toEqual(protectCalls[1]![1]);
  for (const [, args, opts] of exec.mock.calls) {
    expect(JSON.stringify(args)).not.toContain(value.toString());
    expect(JSON.stringify(args)).not.toContain(value.toString('base64'));
    expect(opts).not.toHaveProperty('env');
  }
});

test('windows backend stores only protected bytes in hashed files and a names-only index', async () => {
  const dir = await directory();
  const exec = dpapiFake();
  const vault = createWindowsDpapiVault({ dir, exec });
  const value = Buffer.from('unique-dpapi-secret-552211');
  await vault.set('cred/Z', value);
  await vault.set('cred/A', Buffer.from('another'));
  await vault.set('__probe__', Buffer.from('probe'));
  const hash = createHash('sha256').update('cred/Z').digest('hex');
  const raw = await readFile(join(dir, `${hash}.dpapi`), 'utf8');
  expect(raw).not.toContain(value.toString());
  expect(raw).not.toContain(value.toString('base64'));
  expect(await readFile(join(dir, 'index.json'), 'utf8')).toBe('["cred/A","cred/Z"]');
  expect(await createWindowsDpapiVault({ dir, exec }).list('cred/')).toEqual(['cred/A', 'cred/Z']);
  expect((await readdir(dir)).every((name) => name.endsWith('.dpapi') || name === 'index.json')).toBe(true);
  if (process.platform !== 'win32') expect((await stat(join(dir, `${hash}.dpapi`))).mode & 0o777).toBe(0o600);
  expect(await vault.delete('cred/Z')).toBe(true);
  expect(await vault.delete('cred/Z')).toBe(false);
  expect(await vault.get('cred/Z')).toBeNull();
  expect(await vault.list()).toEqual(['cred/A']);
});

test('windows backend serializes concurrent index writes', async () => {
  const vault = createWindowsDpapiVault({ dir: await directory(), exec: dpapiFake() });
  await Promise.all(Array.from({ length: 8 }, (_, n) => vault.set(`cred/${n}`, Buffer.from(String(n)))));
  expect(await vault.list()).toEqual(Array.from({ length: 8 }, (_, n) => `cred/${n}`));
});

test('windows backend rejects invalid names before helper or file I/O', async () => {
  const dir = join(await directory(), 'not-created');
  const exec = dpapiFake();
  const vault = createWindowsDpapiVault({ dir, exec });
  for (const name of ['bad name', 'bad\nname', 'bad"name']) {
    await expect(vault.get(name)).rejects.toBeInstanceOf(TypeError);
    await expect(vault.set(name, Buffer.from('secret'))).rejects.toBeInstanceOf(TypeError);
    await expect(vault.delete(name)).rejects.toBeInstanceOf(TypeError);
  }
  expect(exec).not.toHaveBeenCalled();
  await expect(stat(dir)).rejects.toHaveProperty('code', 'ENOENT');
});

test('windows backend refuses helper failures and malformed ciphertext without leaking outputs', async () => {
  const secret = 'unique-dpapi-error-secret-119988';
  const dir = await directory();
  const hash = createHash('sha256').update('cred/TOKEN').digest('hex');
  await writeFile(join(dir, `${hash}.dpapi`), 'not valid base64!');
  const exec = dpapiFake();
  await expect(createWindowsDpapiVault({ dir, exec }).get('cred/TOKEN')).rejects.toThrow();
  expect(exec).not.toHaveBeenCalled();
  for (const result of [
    { code: 1, stdout: Buffer.from(secret), stderr: secret },
    { code: 0, stdout: Buffer.from(secret), stderr: secret },
  ]) {
    await expect(createWindowsDpapiVault({ dir, exec: async () => result }).set('cred/TOKEN', Buffer.from(secret))).rejects.not.toThrow(secret);
  }
});

test('windows backend accepts PowerShell progress records on stderr when the helper succeeds', async () => {
  // Windows PowerShell 5.1 writes "Preparing modules for first use" as CLIXML to stderr with a minimal environment.
  const fake = dpapiFake();
  const noisy = vi.fn<typeof runHelper>(async (cmd, args, opts) => ({
    ...(await fake(cmd, args, opts)),
    stderr: '#< CLIXML\r\n<Objs Version="1.1.0.1"><Obj S="progress" RefId="0"></Obj></Objs>',
  }));
  const vault = createWindowsDpapiVault({ dir: await directory(), exec: noisy });
  await vault.set('cred/TOKEN', Buffer.from('value-with-progress-noise'));
  expect((await vault.get('cred/TOKEN'))?.toString()).toBe('value-with-progress-noise');
});
