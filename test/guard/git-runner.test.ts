import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { spawn } = vi.hoisted(() => ({ spawn: vi.fn() }));
vi.mock('node:child_process', () => ({ spawn }));
// The shared version query is covered with real helper integration in index-file.test.ts.
vi.mock('../../src/firstrun/git.js', () => ({ gitScanOptions: async () => ['--no-lazy-fetch'] }));
import { defaultGitRunner } from '../../src/guard/guard.js';

function fakeChild() {
  return Object.assign(new EventEmitter(), { stdout: new PassThrough(), kill: vi.fn() });
}

describe('default staged diff runner', () => {
  beforeEach(() => { spawn.mockReset(); });
  afterEach(() => { vi.unstubAllEnvs(); });

  it('streams split UTF-8 lines and the final line under a minimal environment', async () => {
    vi.stubEnv('KEYSENTRY_TEST_SECRET', 'never-pass-this-fake-secret');
    vi.stubEnv('GIT_EXTERNAL_DIFF', 'untrusted-program');
    vi.stubEnv('GIT_CONFIG_COUNT', '1');
    const child = fakeChild();
    spawn.mockImplementation(() => {
      queueMicrotask(() => {
        const bytes = Buffer.from('first\r\né\nlast');
        child.stdout.emit('data', bytes.subarray(0, 8));
        child.stdout.emit('data', bytes.subarray(8));
        child.emit('close', 0);
      });
      return child;
    });
    const lines: string[] = [];
    const result = await defaultGitRunner(['diff', '--cached'], {
      cwd: 'test-root', onLine: (line) => lines.push(line), signal: new AbortController().signal,
    });
    expect(lines).toEqual(['first', 'é', 'last']);
    expect(result).toEqual({ code: 0 });
    const [command, args, opts] = spawn.mock.calls[0]!;
    expect(command).toBe('git');
    expect(args).toEqual(['--no-lazy-fetch', '-c', 'core.hooksPath=/dev/null', '-c', 'diff.external=', '-c', 'core.fsmonitor=false', 'diff', '--cached']);
    expect(opts).toMatchObject({ cwd: 'test-root', shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
    expect(Object.keys(opts.env).sort()).toEqual(Object.keys(opts.env).filter((key) => [
      'PATH', 'SystemRoot', 'HOME', 'USERPROFILE', 'GIT_CONFIG_NOSYSTEM', 'GIT_TERMINAL_PROMPT',
      'GIT_PAGER', 'GIT_OPTIONAL_LOCKS', 'LC_ALL',
      'GIT_INDEX_FILE', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES',
    ].includes(key)).sort());
    expect(opts.env).toMatchObject({ GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0',
      GIT_PAGER: 'cat', GIT_OPTIONAL_LOCKS: '0', LC_ALL: 'C' });
    expect(JSON.stringify(opts.env)).not.toContain('never-pass-this-fake-secret');
  });

  it('replaces synchronous spawn failures with a safe error', async () => {
    spawn.mockImplementation(() => { throw new Error('fake-secret-in-system-error'); });
    await expect(defaultGitRunner([], { cwd: '.', onLine() {}, signal: new AbortController().signal }))
      .rejects.toThrow('Unable to check staged changes. The commit was not checked.');
  });

  it('replaces emitted process failures and callback failures with safe errors', async () => {
    for (const failure of ['process', 'callback']) {
      const child = fakeChild();
      spawn.mockImplementation(() => {
        queueMicrotask(() => {
          if (failure === 'process') child.emit('error', new Error('fake-secret-in-system-error'));
          else child.stdout.emit('data', Buffer.from('line\n'));
        });
        return child;
      });
      await expect(defaultGitRunner([], { cwd: '.', onLine() { throw new Error('fake-secret-in-callback'); },
        signal: new AbortController().signal })).rejects.toThrow('Unable to check staged changes. The commit was not checked.');
      expect(child.kill).toHaveBeenCalled();
    }
  });

  it('kills an aborted process and never spawns for an already aborted request', async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(defaultGitRunner([], { cwd: '.', onLine() {}, signal: controller.signal })).rejects.toThrow();
    expect(spawn).not.toHaveBeenCalled();
    const child = fakeChild();
    const active = new AbortController();
    spawn.mockImplementation(() => { queueMicrotask(() => active.abort()); return child; });
    await expect(defaultGitRunner([], { cwd: '.', onLine() {}, signal: active.signal })).rejects.toThrow();
    expect(child.kill).toHaveBeenCalled();
  });

  it('refuses an oversized streaming line without delivering it to the scanner', async () => {
    const child = fakeChild();
    spawn.mockImplementation(() => {
      queueMicrotask(() => child.stdout.emit('data', Buffer.alloc(1024 * 1024 + 1, 65)));
      return child;
    });
    const lines: string[] = [];
    await expect(defaultGitRunner([], { cwd: '.', onLine: (line) => lines.push(line), signal: new AbortController().signal }))
      .rejects.toThrow('Unable to check staged changes. The commit was not checked.');
    expect(lines).toEqual([]);
    expect(child.kill).toHaveBeenCalled();
  });

  it('preserves nonzero exit status and treats signal termination as failure', async () => {
    for (const code of [128, null]) {
      const child = fakeChild();
      spawn.mockImplementation(() => { queueMicrotask(() => child.emit('close', code)); return child; });
      const result = await defaultGitRunner([], { cwd: '.', onLine() {}, signal: new AbortController().signal });
      expect(result.code).not.toBe(0);
      if (code !== null) expect(result.code).toBe(128);
    }
  });
});
