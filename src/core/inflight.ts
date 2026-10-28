import { createHash } from 'node:crypto';
import { mkdir, open, readFile, stat, unlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import type { InFlightStore, Vault } from '../types.js';
import { DecryptError, openBytes, sealBytes } from '../security/index.js';
import { deleteInflightKey, inflightKey } from '../vault/index.js';
import { syncFile } from '../security/durable.js';

export class InFlightClosedError extends Error {
  readonly code = 'INFLIGHT_CLOSED';
  constructor() {
    super('This rotation has finished. Its temporary values can no longer be stored.');
    this.name = 'InFlightClosedError';
  }
}

const queues = new Map<string, Promise<unknown>>();
function enqueue<T>(path: string, operation: () => Promise<T>): Promise<T> {
  const pending = (queues.get(path) ?? Promise.resolve()).catch(() => undefined).then(operation);
  queues.set(path, pending);
  const cleanup = () => { if (queues.get(path) === pending) queues.delete(path); };
  void pending.then(cleanup, cleanup);
  return pending;
}

function validateIdentifier(value: string): void {
  if (typeof value !== 'string' || !/^[A-Za-z0-9:._-]{1,128}$/.test(value)) {
    throw new TypeError('Rotation and slot identifiers must use 1 to 128 letters, numbers, colons, dots, underscores or hyphens.');
  }
}

function missing(error: unknown): boolean { return (error as NodeJS.ErrnoException)?.code === 'ENOENT'; }

function decode(line: string): Buffer {
  if (!line || line.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(line)) {
    throw new DecryptError();
  }
  const bytes = Buffer.from(line, 'base64');
  if (bytes.toString('base64') !== line) throw new DecryptError();
  return bytes;
}

function parse(bytes: Buffer): unknown {
  try { return JSON.parse(bytes.toString('utf8')); }
  catch { throw new DecryptError(); }
  finally { bytes.fill(0); }
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Colon-bearing IDs need a filename and vault-name representation supported on Windows. */
function vaultPlanId(planId: string): string {
  return planId.includes(':') || planId.startsWith('encoded_')
    ? `encoded_${createHash('sha256').update(planId).digest('hex')}` : planId;
}

function sealRecord(key: Buffer, planId: string, slot: string, value: string): string {
  const plaintext = Buffer.from(JSON.stringify({ slot, value }));
  let routing: Buffer | undefined;
  try {
    const sealed = sealBytes(key, plaintext, `keysentry-inflight:${planId}:${slot}`).toString('base64');
    // The outer record encrypts the slot needed to authenticate and discover the inner record.
    routing = Buffer.from(JSON.stringify({ slot, sealed }));
    return `${sealBytes(key, routing, `keysentry-inflight:${planId}`).toString('base64')}\n`;
  } finally { plaintext.fill(0); routing?.fill(0); }
}

function openRecord(key: Buffer, planId: string, line: string): { slot: string; value: string } {
  const routing = parse(openBytes(key, decode(line), `keysentry-inflight:${planId}`));
  if (!object(routing) || typeof routing.slot !== 'string' || typeof routing.sealed !== 'string') throw new DecryptError();
  try { validateIdentifier(routing.slot); } catch { throw new DecryptError(); }
  const record = parse(openBytes(key, decode(routing.sealed), `keysentry-inflight:${planId}:${routing.slot}`));
  if (!object(record) || record.slot !== routing.slot || typeof record.value !== 'string') throw new DecryptError();
  return { slot: routing.slot, value: record.value };
}

function openRecords(key: Buffer, planId: string, contents: Buffer): { values: Map<string, string>; completeBytes: number } {
  // A record is committed only when its newline reached the file. Ignore the final torn write in full.
  const completeBytes = contents.lastIndexOf(0x0a) + 1;
  const lines = contents.subarray(0, completeBytes).toString('utf8').split('\n');
  lines.pop();
  const values = new Map<string, string>();
  for (const line of lines) {
    const record = openRecord(key, planId, line.endsWith('\r') ? line.slice(0, -1) : line);
    values.set(record.slot, record.value);
  }
  return { values, completeBytes };
}

/** No key is retained in memory between calls, including after crypto-shredding. */
export function createInFlightStore(opts: { dir: string; vault: Vault; projectId: string }): InFlightStore {
  const dir = resolve(opts.dir);
  const closed = new Set<string>();
  function pathFor(planId: string): string {
    validateIdentifier(planId);
    return join(dir, `${planId.replaceAll(':', '%3A')}.jsonl`);
  }

  async function readContents(path: string): Promise<Buffer | null> {
    try { return await readFile(path); }
    catch (error) { if (missing(error)) return null; throw new Error('Unable to read temporary rotation values.'); }
  }

  async function readValues(planId: string, path: string): Promise<Map<string, string>> {
    const key = await inflightKey(opts.vault, opts.projectId, vaultPlanId(planId), false);
    if (key === null) return new Map();
    try {
      const contents = await readContents(path);
      return contents === null ? new Map() : openRecords(key, planId, contents).values;
    } finally { key.fill(0); }
  }

  return {
    async put(planId, slot, value) {
      const path = pathFor(planId);
      validateIdentifier(slot);
      return enqueue(path, async () => {
        if (closed.has(planId)) throw new InFlightClosedError();
        const contents = await readContents(path);
        let key = await inflightKey(opts.vault, opts.projectId, vaultPlanId(planId), false);
        if (key === null) {
          if (contents !== null) {
            throw new Error(`The temporary values for rotation plan ${planId} cannot be opened because its vault key is missing. Check the provider for unrecorded keys, then run "keysentry state reset --force" before starting over.`);
          }
          key = await inflightKey(opts.vault, opts.projectId, vaultPlanId(planId), true);
        }
        if (key === null) throw new Error('Unable to create a temporary rotation key.');
        try {
          // Validate every complete record before changing any bytes, including when a torn tail follows it.
          const completeBytes = contents === null ? 0 : openRecords(key, planId, contents).completeBytes;
          const line = Buffer.from(sealRecord(key, planId, slot, value), 'utf8');
          await mkdir(dir, { recursive: true, mode: 0o700 });
          if (contents !== null && completeBytes < contents.length) {
            // Windows append handles cannot truncate, so repair the tail before opening for append.
            const repair = await open(path, 'r+');
            try { await repair.truncate(completeBytes); }
            finally { await repair.close(); }
          }
          const handle = await open(path, 'a', 0o600);
          try {
            const { bytesWritten } = await handle.write(line);
            if (bytesWritten !== line.length) throw new Error('Unable to store temporary rotation values completely.');
            await syncFile(handle);
          } finally { await handle.close(); }
        } catch { throw new Error('Unable to store temporary rotation values.'); }
        finally { key.fill(0); }
      });
    },
    async get(planId, slot) {
      const path = pathFor(planId);
      validateIdentifier(slot);
      return enqueue(path, async () => (await readValues(planId, path)).get(slot) ?? null);
    },
    async slots(planId) {
      const path = pathFor(planId);
      return enqueue(path, async () => [...(await readValues(planId, path)).keys()]);
    },
    async shred(planId) {
      const path = pathFor(planId);
      return enqueue(path, async () => {
        const keyId = vaultPlanId(planId);
        const key = await inflightKey(opts.vault, opts.projectId, keyId, false);
        const hasKey = key !== null;
        key?.fill(0);
        let hasFile = false;
        try { await stat(path); hasFile = true; }
        catch (error) { if (!missing(error)) throw new Error('Unable to inspect temporary rotation values.'); }
        if (!hasKey && !hasFile) return;
        await deleteInflightKey(opts.vault, opts.projectId, keyId);
        // Close immediately after key deletion even when a later filesystem operation fails.
        closed.add(planId);
        if (!hasFile) return;
        try {
          const handle = await open(path, 'r+');
          try {
            const { size } = await handle.stat();
            const zeros = Buffer.alloc(Math.min(size, 64 * 1024));
            let offset = 0;
            while (offset < size) {
              const { bytesWritten } = await handle.write(zeros, 0, Math.min(zeros.length, size - offset), offset);
              if (bytesWritten === 0) throw new Error('Unable to clear temporary rotation values completely.');
              offset += bytesWritten;
            }
            await syncFile(handle);
          } finally { await handle.close(); }
          await unlink(path);
        } catch (error) { if (!missing(error)) throw new Error('Unable to remove temporary rotation values.'); }
      });
    },
  };
}
