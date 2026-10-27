import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { afterEach, expect, test, vi } from 'vitest';
import { runHelper, type SpawnLike } from '../../src/vault/exec.js';

function fakeChild() {
  return Object.assign(new EventEmitter(), {
    stdin: new PassThrough(),
    stdout: new PassThrough(),
    stderr: new PassThrough(),
    kill: vi.fn(() => true),
  });
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

test('runHelper passes only set allow-listed environment variables and sends secrets through stdin', async () => {
  const child = fakeChild();
  const secret = Buffer.from('private helper input');
  vi.stubEnv('KEYSENTRY_TEST_SECRET', secret.toString());
  vi.stubEnv('PATH', 'test-search-path');
  vi.stubEnv('HOME', undefined);
  vi.stubEnv('DBUS_SESSION_BUS_ADDRESS', 'unix:path=/run/user/test/bus');
  const spawnImpl = vi.fn(() => child) as unknown as SpawnLike;
  const promise = runHelper('secret-tool', ['lookup', 'service', 'keysentry'], { stdin: secret, spawnImpl });
  const stdin = child.stdin.read();
  child.emit('close', 0);
  await promise;

  expect(spawnImpl).toHaveBeenCalledTimes(1);
  const [command, args, options] = vi.mocked(spawnImpl).mock.calls[0]!;
  expect(command).toBe('secret-tool');
  expect(args).toEqual(['lookup', 'service', 'keysentry']);
  expect(options).toMatchObject({ shell: false, windowsHide: true });
  expect(options.env).toEqual(Object.fromEntries(
    ['PATH', 'SystemRoot', 'HOME', 'USERPROFILE', 'DBUS_SESSION_BUS_ADDRESS', 'XDG_RUNTIME_DIR']
      .filter((name) => process.env[name] !== undefined)
      .map((name) => [name, process.env[name]]),
  ));
  expect(Object.hasOwn(options.env!, 'HOME')).toBe(false);
  expect(JSON.stringify([args, options.env])).not.toContain(secret.toString());
  expect(stdin).toEqual(secret);
});

test('runHelper collects binary stdout, the exit code, and stderr capped at 64 KiB', async () => {
  const child = fakeChild();
  const promise = runHelper('security', ['-i'], { spawnImpl: (() => child) as unknown as SpawnLike });
  child.stdout.write(Buffer.from([0, 255]));
  child.stdout.write(Buffer.from([128, 1]));
  child.stderr.write('a'.repeat(65_530));
  child.stderr.write('bc'.repeat(20));
  child.emit('close', 44);
  const result = await promise;
  expect(result.stdout).toEqual(Buffer.from([0, 255, 128, 1]));
  expect(result.code).toBe(44);
  expect(Buffer.byteLength(result.stderr)).toBe(65_536);
  expect(result.stderr).toBe('a'.repeat(65_530) + 'bcbcbc');
  expect(child.stdin.writableEnded).toBe(true);
});

test('runHelper kills and rejects a helper that exceeds its timeout without exposing its input', async () => {
  vi.useFakeTimers();
  const child = fakeChild();
  const secret = Buffer.from('do not echo this input');
  const promise = runHelper('powershell.exe', ['-NoProfile'], {
    stdin: secret, timeoutMs: 25, spawnImpl: (() => child) as unknown as SpawnLike,
  });
  const assertion = expect(promise).rejects.toThrow(/powershell\.exe.*timed out/i);
  await vi.advanceTimersByTimeAsync(25);
  await assertion;
  expect(child.kill).toHaveBeenCalledTimes(1);
  await expect(promise).rejects.not.toThrow(secret.toString());
  child.emit('close', null, 'SIGTERM');
});

test('runHelper defaults to a 15 second timeout', async () => {
  vi.useFakeTimers();
  const child = fakeChild();
  const promise = runHelper('secret-tool', [], { spawnImpl: (() => child) as unknown as SpawnLike });
  const assertion = expect(promise).rejects.toThrow(/secret-tool.*timed out/i);
  await vi.advanceTimersByTimeAsync(14_999);
  expect(child.kill).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(1);
  await assertion;
  expect(child.kill).toHaveBeenCalledTimes(1);
});

test('runHelper sanitizes launch errors instead of forwarding helper input or arguments', async () => {
  const secret = 'private helper input';
  const child = fakeChild();
  const promise = runHelper('security', ['-i'], {
    stdin: Buffer.from(secret), spawnImpl: (() => child) as unknown as SpawnLike,
  });
  child.emit('error', new Error(`failure echoed ${secret}`));
  await expect(promise).rejects.toThrow(/security/);
  await expect(promise).rejects.not.toThrow(secret);

  const spawnImpl = (() => { throw new Error(secret); }) as SpawnLike;
  await expect(runHelper('security', ['-i'], { stdin: Buffer.from(secret), spawnImpl })).rejects.not.toThrow(secret);
});

test('runHelper reports signal termination and stdin errors without helper output', async () => {
  const child = fakeChild();
  const promise = runHelper('security', [], { spawnImpl: (() => child) as unknown as SpawnLike });
  child.stdout.write('private helper output');
  child.stderr.write('private helper error');
  child.emit('close', null, 'SIGTERM');
  await expect(promise).rejects.toThrow(/security/);
  await expect(promise).rejects.not.toThrow(/private helper/);

  const next = fakeChild();
  const failedInput = runHelper('security', [], { spawnImpl: (() => next) as unknown as SpawnLike });
  next.stdin.emit('error', new Error('private helper input'));
  await expect(failedInput).rejects.toThrow(/security/);
  await expect(failedInput).rejects.not.toThrow(/private helper/);
  expect(next.kill).toHaveBeenCalledTimes(1);
});
