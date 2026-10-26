import { randomBytes } from 'node:crypto';
import { mkdir, open, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import type { Inventory, Journal, JournalEntry } from '../types.js';

export interface StatePaths {
  dir: string;
  inventory: string;
  journal: string;
  audit: string;
  monitor: string;
  plans: string;
}

export function statePaths(cwd = process.cwd()): StatePaths {
  const dir = resolve(cwd, '.keysentry');
  return {
    dir,
    inventory: join(dir, 'inventory.json'),
    journal: join(dir, 'journal.jsonl'),
    audit: join(dir, 'audit.jsonl'),
    monitor: join(dir, 'monitor.json'),
    plans: join(dir, 'plans'),
  };
}

function hasCode(error: unknown, code: string): boolean {
  return error instanceof Error && 'code' in error && error.code === code;
}

/** Protect state even when the first operation is a read or a nested plan write. */
async function preparePath(path: string): Promise<void> {
  const parent = dirname(resolve(path));
  await mkdir(parent, { recursive: true, mode: 0o700 });
  let ancestor = parent;
  while (true) {
    if (basename(ancestor) === '.keysentry') {
      const ignore = join(ancestor, '.gitignore');
      let existing = '';
      try {
        existing = await readFile(ignore, 'utf8');
      } catch (error) {
        if (!hasCode(error, 'ENOENT')) throw error;
      }
      // Append protection instead of truncating a currently effective ignore file.
      if (existing.trimEnd().split(/\r?\n/).at(-1) !== '*') {
        const separator = existing && !existing.endsWith('\n') ? '\n' : '';
        await writeFile(ignore, `${separator}*\n`, { flag: 'a', mode: 0o600 });
      }
      break;
    }
    const next = dirname(ancestor);
    if (next === ancestor) break;
    ancestor = next;
  }
}

function serialize(data: unknown, pretty = false): string {
  const json = JSON.stringify(data, null, pretty ? 2 : undefined);
  if (json === undefined) throw new Error('Unsupported JSON state.');
  return `${json}\n`;
}

/** Callers supply sanitized state: this generic storage layer does not inspect secret values. */
export async function writeJsonAtomic(path: string, data: unknown): Promise<void> {
  return enqueue(path, async () => {
    let temp: string | undefined;
    try {
      const content = serialize(data, true);
      const target = resolve(path);
      await preparePath(target);
      const candidate = join(dirname(target), `.${basename(target)}-${randomBytes(16).toString('hex')}.tmp`);
      const handle = await open(candidate, 'wx', 0o600);
      temp = candidate;
      try {
        await handle.writeFile(content, 'utf8');
        await handle.sync();
      } finally {
        await handle.close();
      }
      // Windows may temporarily deny replacement while another process reads the target.
      // Retry the same complete temporary file; never unlink the last good document.
      for (let attempt = 0; ; attempt++) {
        try {
          await rename(temp, target);
          break;
        } catch (error) {
          const transient = hasCode(error, 'EPERM') || hasCode(error, 'EACCES') || hasCode(error, 'EBUSY');
          if (process.platform !== 'win32' || !transient || attempt >= 8) throw error;
          await new Promise<void>((done) => setTimeout(done, 5 * (attempt + 1)));
        }
      }
    } catch {
      throw new Error('Unable to write JSON state.');
    } finally {
      if (temp) await unlink(temp).catch(() => undefined);
    }
  });
}

export async function readJson<T = unknown>(path: string): Promise<T | null> {
  try {
    await preparePath(path);
    let content: string;
    try {
      content = await readFile(path, 'utf8');
    } catch (error) {
      if (hasCode(error, 'ENOENT')) return null;
      throw error;
    }
    return JSON.parse(content) as T;
  } catch {
    // JSON parser diagnostics may echo the input; never propagate them.
    throw new Error('Unable to read valid JSON state.');
  }
}

export async function saveInventory(inventory: Inventory, cwd = process.cwd()): Promise<void> {
  await writeJsonAtomic(statePaths(cwd).inventory, inventory);
}

export async function loadInventory(cwd = process.cwd()): Promise<Inventory | null> {
  return readJson<Inventory>(statePaths(cwd).inventory);
}

// Shared by all journal/audit instances for a file, including reads queued behind appends.
const queues = new Map<string, Promise<unknown>>();

function enqueue<T>(path: string, operation: () => Promise<T>): Promise<T> {
  const key = resolve(path);
  const previous = queues.get(key) ?? Promise.resolve();
  const current = previous.catch(() => undefined).then(operation);
  queues.set(key, current);
  return current.finally(() => {
    if (queues.get(key) === current) queues.delete(key);
  });
}

function appendLine(path: string, data: unknown): Promise<void> {
  return enqueue(path, async () => {
    try {
      const line = serialize(data);
      await preparePath(path);
      const handle = await open(path, 'a', 0o600);
      try {
        await handle.writeFile(line, 'utf8');
      } finally {
        await handle.close();
      }
    } catch {
      throw new Error('Unable to append JSONL state.');
    }
  });
}

export function createFileJournal(path: string): Journal {
  const target = resolve(path);
  return {
    append(entry) {
      return appendLine(target, entry);
    },
    read(planId) {
      return enqueue(target, async () => {
        try {
          await preparePath(target);
          let content: string;
          try {
            content = await readFile(target, 'utf8');
          } catch (error) {
            if (hasCode(error, 'ENOENT')) return [];
            throw error;
          }
          const entries = content.split(/\r?\n/).filter((line) => line.trim() !== '')
            .map((line) => JSON.parse(line) as JournalEntry);
          return planId === undefined ? entries : entries.filter((entry) => entry.planId === planId);
        } catch {
          throw new Error('Unable to read valid journal JSONL state.');
        }
      });
    },
  };
}

export async function appendAudit(path: string, event: Record<string, unknown>): Promise<void> {
  await appendLine(resolve(path), event);
}
