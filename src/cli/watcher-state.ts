import { resolve } from 'node:path';
import type { StateKind, StateStore } from '../core/store.js';
import { createSequencedStateRecord, type SequencedStatePersistence } from '../watcher/index.js';
import { CliError } from './errors.js';

const records = [
  'autopilot.json', 'watcher-tick.json', 'watcher-recovery.json', 'watcher-incidents.json',
  'watcher-relay.json', 'approvals.json', 'watcher-approvals.json', 'watcher-feeds.json',
  'watcher-check.json', 'watcher-activation.json', 'monitor.json',
];
const wrappers = new WeakMap<StateStore, StateStore>();

/**
 * Actions caches retain the sequence inside each encrypted record. Guards survive repeated runtime construction
 * in this process; a complete cache rollback across restarts still needs an independent retained high-water mark.
 * Local state remains compatible with commands that read ordinary encrypted JSON.
 */
export function createWatcherStateStore(store: StateStore, actions: boolean): StateStore {
  if (!actions) return store;
  const existing = wrappers.get(store);
  if (existing) return existing;
  const pathKey = (file: string) => process.platform === 'win32' ? resolve(file).toLowerCase() : resolve(file);
  const protectedPaths = new Map(records.map(name => {
    const file = resolve(store.paths.dir, name); return [pathKey(file), file];
  }));
  protectedPaths.set(pathKey(store.paths.monitor), resolve(store.paths.monitor));
  const guards = new Map<string, SequencedStatePersistence<unknown>>();
  function guard(kind: StateKind, file: string): SequencedStatePersistence<unknown> | undefined {
    const key = pathKey(file);
    const target = protectedPaths.get(key);
    if (!target) return undefined;
    const id = `${kind}\0${key}`;
    let selected = guards.get(id);
    if (!selected) {
      selected = createSequencedStateRecord({ store, kind, path: target });
      guards.set(id, selected);
    }
    return selected;
  }
  async function verified<T>(operation: () => Promise<T>): Promise<T> {
    try { return await operation(); }
    catch { throw new CliError('Saved watcher state could not be verified. Automatic actions are paused.'); }
  }
  const wrapped: StateStore = {
    paths: store.paths,
    async readJson<T = unknown>(kind: StateKind, file: string): Promise<T | null> {
      const selected = guard(kind, file);
      return selected ? verified(async () => await selected.load() as T | null) : store.readJson<T>(kind, file);
    },
    async writeJson(kind, file, data, opts) {
      const selected = guard(kind, file);
      if (selected) await verified(() => selected.save(data));
      else await store.writeJson(kind, file, data, opts);
    },
    saveInventory: inventory => store.saveInventory(inventory),
    loadInventory: () => store.loadInventory(),
    journal: () => store.journal(),
    migratePlaintext: () => store.migratePlaintext(),
  };
  wrappers.set(store, wrapped);
  wrappers.set(wrapped, wrapped);
  return wrapped;
}
