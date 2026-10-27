import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PassThrough } from 'node:stream';
import type { SpawnOptions } from 'node:child_process';

const { spawnMock } = vi.hoisted(() => ({ spawnMock: vi.fn() }));
vi.mock('node:child_process', async (original) => ({
  ...await original<typeof import('node:child_process')>(),
  spawn: spawnMock,
}));

import { installHook, uninstallHook } from '../../src/guard/hook.js';

interface Reply {
  chunks?: string[];
  code?: number | null;
  error?: Error;
  stdoutError?: Error;
  throwOnSpawn?: boolean;
}

describe('default hook Git query runner', () => {
  let root: string;
  let replies: Reply[];
  let children: (EventEmitter & { stdout: PassThrough; kill: ReturnType<typeof vi.fn> })[];

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'keysentry-hook-runner-'));
    replies = [];
    children = [];
    spawnMock.mockReset();
    spawnMock.mockImplementation(() => {
      const reply = replies.shift();
      if (!reply) throw new Error('Unexpected child process');
      if (reply.throwOnSpawn) throw reply.error;
      const child = Object.assign(new EventEmitter(), {
        stdout: new PassThrough(),
        kill: vi.fn(() => {
          queueMicrotask(() => child.emit('close', null, 'SIGTERM'));
          return true;
        }),
      });
      children.push(child);
      queueMicrotask(() => {
        if (reply.error) {
          child.emit('error', reply.error);
          child.emit('close', null);
          return;
        }
        for (const chunk of reply.chunks ?? []) child.stdout.write(chunk);
        if (reply.stdoutError) {
          child.stdout.destroy(reply.stdoutError);
          setImmediate(() => child.emit('close', 0));
          return;
        }
        child.stdout.end();
        setImmediate(() => child.emit('close', reply.code === undefined ? 0 : reply.code));
      });
      return child;
    });
  });

  afterEach(async () => {
    for (const child of children) child.stdout.destroy();
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
    await rm(root, { recursive: true, force: true });
  });

  it('passes only the minimal environment and read-only hardened Git arguments', async () => {
    vi.stubEnv('KEYSENTRY_TEST_SECRET', 'planted-secret-for-child-env');
    vi.stubEnv('AWS_SECRET_ACCESS_KEY', 'planted-provider-secret');
    vi.stubEnv('GIT_CONFIG_COUNT', '1');
    vi.stubEnv('GIT_CONFIG_KEY_0', 'core.hooksPath');
    vi.stubEnv('GIT_CONFIG_VALUE_0', 'untrusted-hooks');
    vi.stubEnv('GIT_DIR', 'untrusted-git-dir');
    vi.stubEnv('GIT_WORK_TREE', 'untrusted-work-tree');
    vi.stubEnv('GIT_EXEC_PATH', 'untrusted-executables');
    vi.stubEnv('GIT_EXTERNAL_DIFF', 'untrusted-extension');
    vi.stubEnv('GIT_PAGER', 'untrusted-pager');
    vi.stubEnv('GIT_SSH_COMMAND', 'untrusted-ssh');
    replies.push({ chunks: ['.git\n'] }, { chunks: ['.configured-hooks\n'] });

    const installed = await installHook(root, { binPath: 'keysentry' });

    expect(installed.path).toBe(join(root, '.configured-hooks', 'pre-commit'));
    expect(await readFile(installed.path, 'utf8')).toContain('exec keysentry guard --staged');
    expect(spawnMock.mock.calls).toHaveLength(2);
    const queries = [
      ['rev-parse', '--git-common-dir'],
      ['config', '--path', '--get', 'core.hooksPath'],
    ];
    for (const [index, call] of spawnMock.mock.calls.entries()) {
      const [command, args, options] = call as [string, string[], SpawnOptions];
      expect(command).toBe('git');
      expect(args).toEqual(['-c', 'diff.external=', '-c', 'core.fsmonitor=false', ...queries[index]!]);
      expect(options).toMatchObject({
        cwd: resolve(root), shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'],
      });
      expect(options.signal).toBeInstanceOf(AbortSignal);
      expect(options.env).toMatchObject({
        GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0', GIT_PAGER: 'cat', GIT_OPTIONAL_LOCKS: '0', LC_ALL: 'C',
      });
      const allowed = new Set(['PATH', 'SystemRoot', 'HOME', 'USERPROFILE', 'GIT_CONFIG_NOSYSTEM', 'GIT_TERMINAL_PROMPT', 'GIT_PAGER', 'GIT_OPTIONAL_LOCKS', 'LC_ALL']);
      expect(Object.keys(options.env!).every((name) => allowed.has(name))).toBe(true);
      expect(JSON.stringify(options.env)).not.toMatch(/planted-|untrusted-/);
      for (const name of ['PATH', 'SystemRoot', 'HOME', 'USERPROFILE']) {
        const inherited = Object.entries(process.env).find(([key]) => key.toLowerCase() === name.toLowerCase());
        if (inherited) expect(options.env![name]).toBe(inherited[1]);
      }
    }
  });

  it('decodes chunked CRLF output and uses configured absolute paths without a final newline', async () => {
    const configured = join(root, 'shared hook directory');
    replies.push({ chunks: ['.g', 'it\r', '\n'] }, { chunks: [configured.slice(0, 7), configured.slice(7)] });
    const installed = await installHook(root, { binPath: 'keysentry' });
    expect(installed.path).toBe(join(configured, 'pre-commit'));
    expect(await readFile(installed.path, 'utf8')).toContain('#!/bin/sh\n');
  });

  it('uses the common Git directory only when config reports the value is absent', async () => {
    replies.push({ chunks: ['shared/.git\n'] }, { code: 1 });
    const installed = await installHook(root, { binPath: 'keysentry' });
    expect(installed.path).toBe(join(root, 'shared', '.git', 'hooks', 'pre-commit'));
    replies.push({ chunks: ['shared/.git\n'] }, { code: 1 });
    await uninstallHook(root);
    expect(await readdir(join(root, 'shared', '.git', 'hooks'))).toEqual([]);
  });

  it.each([
    { name: 'nonzero repository exit', replies: [{ code: 128 }], message: /repository/ },
    { name: 'nonzero config exit', replies: [{ chunks: ['.git\n'] }, { code: 128 }], message: /configuration/ },
    { name: 'signal termination during config', replies: [{ chunks: ['.git\n'] }, { code: null }], message: /configuration/ },
    { name: 'empty configured path', replies: [{ chunks: ['.git\n'] }, { chunks: ['\n'] }], message: /empty hooks path/ },
    { name: 'multiple configured paths', replies: [{ chunks: ['.git\n'] }, { chunks: ['first\nsecond\n'] }], message: /unsupported hooks path/ },
    { name: 'NUL in configured path', replies: [{ chunks: ['.git\n'] }, { chunks: ['hooks\0other\n'] }], message: /unsupported hooks path/ },
  ])('refuses $name without writing', async (fixture) => {
    replies.push(...fixture.replies);
    await expect(installHook(root, { binPath: 'keysentry' })).rejects.toThrow(fixture.message);
    expect(await readdir(root)).toEqual([]);
  });

  it.each([false, true])('sanitizes process errors without echoing child diagnostics (synchronous: %s)', async (throwOnSpawn) => {
    const secret = 'planted-secret-in-child-error';
    replies.push({ error: new Error(`git failed: ${secret}`), throwOnSpawn });
    const outcome = await installHook(root, { binPath: 'keysentry' }).catch((error: unknown) => error);
    expect(outcome).toBeInstanceOf(Error);
    expect((outcome as Error).message).toBe('Git configuration could not be read.');
    expect(JSON.stringify(outcome)).not.toContain(secret);
    expect(await readdir(root)).toEqual([]);
  });

  it('kills a query that streams more than 32 KiB and does not expose its output', async () => {
    const planted = 'planted-secret-in-oversized-output';
    replies.push({ chunks: ['.git\n'] }, { chunks: ['x'.repeat(16_384), 'x'.repeat(16_384), planted] });
    const outcome = await installHook(root, { binPath: 'keysentry' }).catch((error: unknown) => error);
    expect(outcome).toBeInstanceOf(Error);
    expect((outcome as Error).message).toBe('Git configuration could not be read.');
    expect(children[1]!.kill).toHaveBeenCalledOnce();
    expect(await readdir(root)).toEqual([]);
  });

  it('rejects stdout stream errors without exposing their diagnostics', async () => {
    replies.push({ chunks: ['.git\n'] }, { chunks: ['.custom\n'], stdoutError: new Error('planted-secret-in-stream-error') });
    const outcome = await installHook(root, { binPath: 'keysentry' }).catch((error: unknown) => error);
    expect(outcome).toBeInstanceOf(Error);
    expect((outcome as Error).message).toBe('Git configuration could not be read.');
    expect(await readdir(root)).toEqual([]);
  });
});
