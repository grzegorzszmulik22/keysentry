import { randomInt } from 'node:crypto';
import { mkdir, open, stat, unlink, utimes, type FileHandle } from 'node:fs/promises';
import type { Stats } from 'node:fs';
import { dirname } from 'node:path';
import { KmsError } from './errors.js';

/**
 * Serializes creating a project's first wrapped state key (review M1). In one process, calls with the same key run one
 * after another; across processes, an exclusively created lock file in the project's state directory does the same.
 * The holder renews the file's time while it works, so a lock left by a crashed process is taken over after `staleMs`.
 */
export interface StateKeyLockOptions {
  /** In-process serialization key (the project id). */
  key: string;
  /** Lock file; omitted means in-process serialization only (tests, embedders without a state directory). */
  lockPath?: string;
  /** How long to wait for another holder. A first start makes a few KMS calls, each bounded by the client timeout. */
  waitMs?: number;
  /** A lock whose time was not renewed for this long is abandoned. */
  staleMs?: number;
}

const local = new Map<string, Promise<unknown>>();

function serial<T>(name: string, operation: () => Promise<T>): Promise<T> {
  const pending = (local.get(name) ?? Promise.resolve()).catch(() => undefined).then(operation);
  local.set(name, pending);
  const cleanup = () => { if (local.get(name) === pending) local.delete(name); };
  void pending.then(cleanup, cleanup);
  return pending;
}

const isCode = (error: unknown, code: string) => typeof error === 'object' && error !== null && 'code' in error && error.code === code;
const sameFile = (left: Stats, right: Stats) => left.dev === right.dev && left.ino === right.ino;
const busy = () => new KmsError('busy', 'Another keysentry process is creating this project\'s state key. Try again when it finishes.');
const unusable = () => new KmsError('config', 'The state key lock in the .keysentry directory could not be used. Check that the directory is writable.');

async function acquire(path: string, waitMs: number, staleMs: number): Promise<FileHandle> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 }).catch(() => { throw unusable(); });
  const deadline = Date.now() + waitMs;
  let backoff = 10;
  for (;;) {
    try {
      const handle = await open(path, 'wx', 0o600);
      try { await handle.writeFile(JSON.stringify({ pid: process.pid })); } catch { /* The file's existence is the lock. */ }
      return handle;
    } catch (error) {
      if (!isCode(error, 'EEXIST')) throw unusable();
    }
    try {
      const candidate = await stat(path);
      if (Date.now() - candidate.mtimeMs > staleMs) {
        // Another waiter may already have replaced the abandoned lock: recheck its identity and age before removing it.
        const current = await stat(path);
        if (sameFile(candidate, current) && candidate.mtimeMs === current.mtimeMs) {
          await unlink(path).catch((error: unknown) => { if (!isCode(error, 'ENOENT')) throw unusable(); });
          continue;
        }
      }
    } catch (error) {
      if (isCode(error, 'ENOENT')) continue;
      if (error instanceof KmsError) throw error;
      throw unusable();
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw busy();
    await new Promise<void>(done => setTimeout(done, Math.min(remaining, randomInt(backoff, backoff * 2 + 1))));
    backoff = Math.min(backoff * 2, 250);
  }
}

export function withStateKeyLock<T>(options: StateKeyLockOptions, work: () => Promise<T>): Promise<T> {
  const waitMs = options.waitMs ?? 180_000;
  const staleMs = options.staleMs ?? 30_000;
  return serial(options.key, async () => {
    if (!options.lockPath) return work();
    const path = options.lockPath;
    const handle = await acquire(path, waitMs, staleMs);
    const identity = await handle.stat();
    // Path-based renewal: FileHandle.utimes is unavailable under the Node permission model.
    const heartbeat = setInterval(() => { const time = new Date(); void utimes(path, time, time).catch(() => {}); }, Math.max(1_000, Math.floor(staleMs / 6)));
    heartbeat.unref();
    try {
      return await work();
    } finally {
      clearInterval(heartbeat);
      try {
        // Leave a lock that replaced ours (after a long stall) to its owner.
        const current = await stat(path).catch(() => null);
        if (current && sameFile(identity, current)) await unlink(path).catch(() => {});
      } finally { await handle.close().catch(() => {}); }
    }
  });
}
