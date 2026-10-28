import { basename, dirname } from 'node:path';
import { withDirectoryLock } from '../core/store.js';
import { KmsError } from './errors.js';

/**
 * Serializes creating a project's first wrapped state key (review M1). In one process, calls with the same key run one
 * after another; across processes, a lock file in the project's state directory does the same. The lock file is the
 * saved state lock's kind (core/store.ts withDirectoryLock, review L-d): it is published atomically with its owner's
 * pid, waited for while that process lives, and waited for through Windows "delete pending" contention. A lock left by
 * a process that has stopped is never taken over automatically (stat and unlink cannot do that atomically, so two
 * waiters could each remove the other's fresh lock): the start stops with an instruction to remove it by hand.
 */
export interface StateKeyLockOptions {
  /** In-process serialization key (the project id). */
  key: string;
  /** Lock file; omitted means in-process serialization only (tests, embedders without a state directory). */
  lockPath?: string;
  /** How long to wait for another holder. A first start makes a few KMS calls, each bounded by the client timeout. */
  waitMs?: number;
}

const local = new Map<string, Promise<unknown>>();

function serial<T>(name: string, operation: () => Promise<T>): Promise<T> {
  const pending = (local.get(name) ?? Promise.resolve()).catch(() => undefined).then(operation);
  local.set(name, pending);
  const cleanup = () => { if (local.get(name) === pending) local.delete(name); };
  void pending.then(cleanup, cleanup);
  return pending;
}

const BUSY = 'Another keysentry process is creating this project\'s state key. Try again when it finishes.';
const UNUSABLE = 'The state key lock in the .keysentry directory could not be used. Check that the directory is writable.';

export function withStateKeyLock<T>(options: StateKeyLockOptions, work: () => Promise<T>): Promise<T> {
  const waitMs = options.waitMs ?? 180_000;
  return serial(options.key, async () => {
    if (!options.lockPath) return work();
    const file = basename(options.lockPath);
    return withDirectoryLock(dirname(options.lockPath), {
      file, temporaryPrefix: `.${file.replace(/\.lock$/, '')}-lock`, what: 'state key lock', busy: BUSY, waitMs, shownPath: `.keysentry/${file}`,
      failure: (kind, message) => kind === 'unusable' ? new KmsError('config', UNUSABLE)
        : new KmsError(kind === 'attention' ? 'config' : 'busy', message),
    }, () => work());
  });
}
