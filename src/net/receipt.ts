import { appendFile, mkdir, readFile, rename, stat } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import type { NetworkReceipt, NetworkReceiptEntry } from '../types.js';

// Share the queue between receipt instances using the same file in this process.
const queues = new Map<string, Promise<void>>();
function serialize<T>(path: string, operation: () => Promise<T>): Promise<T> {
  const result = (queues.get(path) ?? Promise.resolve()).then(operation);
  const tail = result.then(() => {}, () => {});
  queues.set(path, tail);
  void tail.then(() => { if (queues.get(path) === tail) queues.delete(path); });
  return result;
}

async function readIfPresent(path: string): Promise<string> {
  try { return await readFile(path, 'utf8'); } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return '';
    throw error;
  }
}

export function createFileReceipt(path: string, opts: { now?: () => Date; maxBytes?: number } = {}): NetworkReceipt {
  const file = resolve(path);
  const maxBytes = opts.maxBytes ?? 5 * 1024 * 1024;
  const now = opts.now ?? (() => new Date());

  return {
    record(entry) {
      // Copy only the contract's fields, even when the caller supplies extras.
      const snapshot: NetworkReceiptEntry = {
        at: entry.at ?? now().toISOString(), host: entry.host, method: entry.method,
        purpose: entry.purpose, allowed: entry.allowed,
        ...(entry.status === undefined ? {} : { status: entry.status }),
      };
      return serialize(file, async () => {
        await mkdir(dirname(file), { recursive: true });
        await appendFile(file, `${JSON.stringify(snapshot)}\n`, { mode: 0o600 });
        if ((await stat(file)).size > maxBytes) await rename(file, `${file}.1`);
      });
    },

    summarize(sinceIso) {
      return serialize(file, async () => {
        const groups = new Map<string, { host: string; purpose: string; count: number; blocked: number; lastAt: string }>();
        const since = sinceIso === undefined ? -Infinity : Date.parse(sinceIso);
        for (const source of [`${file}.1`, file]) {
          const text = await readIfPresent(source);
          for (const line of text.split('\n')) {
            if (!line.trim()) continue;
            const entry = JSON.parse(line) as NetworkReceiptEntry;
            if (Date.parse(entry.at) < since) continue;
            const key = JSON.stringify([entry.host, entry.purpose]);
            const group = groups.get(key) ?? { host: entry.host, purpose: entry.purpose, count: 0, blocked: 0, lastAt: entry.at };
            group.count += 1;
            if (!entry.allowed) group.blocked += 1;
            if (Date.parse(entry.at) > Date.parse(group.lastAt)) group.lastAt = entry.at;
            groups.set(key, group);
          }
        }
        return [...groups.values()].sort((a, b) => a.host.localeCompare(b.host) || a.purpose.localeCompare(b.purpose));
      });
    },
  };
}
