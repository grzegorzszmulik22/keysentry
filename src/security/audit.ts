import { createHash, createHmac, randomInt, timingSafeEqual } from 'node:crypto';
import { mkdir, open, readFile, stat, unlink, utimes } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import type { Stats } from 'node:fs';
import { dirname, resolve } from 'node:path';
import type { AuditEvent, AuditLog, AuditVerifyResult, Redactor, Vault } from '../types.js';
import { canonicalJson } from './canonical.js';
import { signDetached, verifyDetached } from './signing.js';
import type { DeviceKey } from './signing.js';
import { getOrCreateKey } from '../vault/keys.js';
import { syncFile } from './durable.js';

export const AUDIT_CHECKPOINT_PREFIX = 'keysentry-audit-checkpoint:v1:';

const ZERO_HASH = '0'.repeat(64);
const HASH = /^[0-9a-f]{64}$/;
const LINE_FIELDS = new Set(['seq', 'at', 'kind', 'summary', 'data', 'prev', 'hash', 'mac']);
const queues = new Map<string, Promise<void>>();

interface AuditLine extends AuditEvent {
  seq: number;
  at: string;
  prev: string;
  hash: string;
  mac?: string;
}

interface Head { seq: number; hash: string }
interface Tail { last: AuditLine | null; events: number; needsNewline: boolean }
type AssertLock = () => Promise<void>;

/** Serialize instances sharing a resolved path, including after a rejected operation. */
function enqueue<T>(path: string, work: () => Promise<T>): Promise<T> {
  const result = (queues.get(path) ?? Promise.resolve()).then(work);
  const settled = result.then(() => {}, () => {});
  queues.set(path, settled);
  void settled.then(() => { if (queues.get(path) === settled) queues.delete(path); });
  return result;
}

function isCode(error: unknown, code: string): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === code;
}

function sameFile(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

async function withLock<T>(path: string, work: (assertLock: AssertLock) => Promise<T>): Promise<T> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const lockPath = `${path}.lock`;
  const deadline = Date.now() + 10_000;
  let lock: FileHandle;
  let backoff = 10;
  for (;;) {
    if (Date.now() >= deadline) throw new Error('The audit log is busy. Try again when the other operation finishes.');
    try {
      lock = await open(lockPath, 'wx', 0o600);
      break;
    } catch (error) {
      if (!isCode(error, 'EEXIST')) throw new Error('The audit log lock could not be opened.');
    }
    try {
      const candidate = await stat(lockPath);
      if (Date.now() - candidate.mtimeMs > 30_000) {
        // Another waiter may already have taken over the old lock. Recheck its identity and lease.
        const current = await stat(lockPath);
        if (sameFile(candidate, current) && candidate.mtimeMs === current.mtimeMs && Date.now() - current.mtimeMs > 30_000) {
          await unlink(lockPath);
          continue;
        }
      }
    } catch (error) {
      if (isCode(error, 'ENOENT')) continue;
      throw new Error('The audit log lock could not be checked.');
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error('The audit log is busy. Try again when the other operation finishes.');
    await new Promise<void>((done) => setTimeout(done, Math.min(remaining, randomInt(backoff, backoff * 2 + 1))));
    backoff = Math.min(backoff * 2, 200);
  }
  const identity = await lock.stat();
  let lost = false;
  async function assertLock(): Promise<void> {
    try {
      if (lost || !sameFile(identity, await stat(lockPath))) throw new Error();
      const time = new Date();
      // Path-based: FileHandle.utimes is disabled under the Node permission model.
      await utimes(lockPath, time, time);
    } catch {
      lost = true;
      throw new Error('The audit log lock changed or is no longer held. Try the operation again.');
    }
  }
  // Long vault calls must not make a live operation look like an abandoned lock.
  let renewal = Promise.resolve();
  const heartbeat = setInterval(() => {
    renewal = renewal.then(assertLock).catch(() => { lost = true; });
  }, 5_000);
  heartbeat.unref();
  try {
    const result = await work(assertLock);
    await assertLock();
    return result;
  } finally {
    clearInterval(heartbeat);
    await renewal;
    try {
      // Leave a detected replacement lock for its owner.
      const current = await stat(lockPath).catch((error: unknown) => { if (!isCode(error, 'ENOENT')) throw new Error('The audit log lock could not be checked.'); return null; });
      if (current && sameFile(identity, current)) {
        await unlink(lockPath).catch((error: unknown) => { if (!isCode(error, 'ENOENT')) throw new Error('The audit log lock could not be released.'); });
      }
    } finally {
      await lock.close();
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isLine(value: unknown): value is AuditLine {
  return isRecord(value) && Object.keys(value).every((key) => LINE_FIELDS.has(key))
    && Number.isSafeInteger(value.seq) && (value.seq as number) > 0
    && typeof value.at === 'string' && typeof value.kind === 'string' && typeof value.summary === 'string'
    && (value.data === undefined || isRecord(value.data))
    && typeof value.prev === 'string' && HASH.test(value.prev)
    && typeof value.hash === 'string';
}

function lineHash(line: Omit<AuditLine, 'hash' | 'mac'>): string {
  const { seq, at, kind, summary, data, prev } = line;
  return createHash('sha256').update(canonicalJson({ seq, at, kind, summary, data, prev })).digest('hex');
}

function lineMac(hash: string, key: Buffer): string {
  return createHmac('sha256', key).update(hash, 'utf8').digest('hex');
}

function validMac(line: AuditLine, key: Buffer | null): boolean {
  if (!key || key.length !== 32 || typeof line.mac !== 'string' || !HASH.test(line.mac)) return false;
  return timingSafeEqual(Buffer.from(line.mac, 'hex'), Buffer.from(lineMac(line.hash, key), 'hex'));
}

/** Read backwards in chunks: appends never load the whole history just to find its head. */
async function* reverseLines(file: FileHandle, size: number): AsyncGenerator<string> {
  let position = size;
  let pending: Buffer[] = [];
  let atEnd = true;
  while (position > 0) {
    const length = Math.min(position, 64 * 1024);
    position -= length;
    const chunk = Buffer.alloc(length);
    let read = 0;
    while (read < length) {
      const { bytesRead } = await file.read(chunk, read, length - read, position + read);
      if (bytesRead === 0) throw new Error('The audit log changed while its tail was being read.');
      read += bytesRead;
    }
    let end = chunk.length;
    for (let index = chunk.length - 1; index >= 0; index--) {
      if (chunk[index] !== 10) continue;
      const line = Buffer.concat([chunk.subarray(index + 1, end), ...pending]);
      pending = [];
      end = index;
      if (!(atEnd && line.length === 0)) yield line.toString('utf8');
      atEnd = false;
    }
    pending.unshift(chunk.subarray(0, end));
  }
  yield Buffer.concat(pending).toString('utf8');
}

async function readTail(file: FileHandle, interval: number, head: Head | null, macKey: Buffer): Promise<Tail> {
  const { size } = await file.stat();
  if (size === 0) {
    if (head) throw new Error('The audit log is shorter than its vault head. Run audit verify before continuing.');
    return { last: null, events: 0, needsNewline: false };
  }
  const finalByte = Buffer.alloc(1);
  await file.read(finalByte, 0, 1, size - 1);
  let last: AuditLine | null = null;
  let events = 0;
  let counting = true;
  let anchored = head === null;
  let next: AuditLine | undefined;
  for await (const text of reverseLines(file, size)) {
    let line: unknown;
    try {
      line = JSON.parse(text);
      if (!isLine(line) || lineHash(line) !== line.hash) throw new Error();
    } catch {
      throw new Error('The audit log tail is unreadable or has a hash mismatch. Run audit verify before appending.');
    }
    if (!validMac(line, macKey)) throw new Error(`Audit entry ${line.seq} was not written by keysentry on this computer. Run audit verify before appending.`);
    last ??= line;
    if (next && (line.seq !== next.seq - 1 || line.hash !== next.prev)) {
      throw new Error('The audit log tail is not connected to its vault head. Run audit verify before continuing.');
    }
    if (head && !anchored) {
      if (line.seq < head.seq || (line.seq === head.seq && line.hash !== head.hash)) {
        throw new Error('The audit log is shorter than or differs from its vault head. Run audit verify before continuing.');
      }
      anchored = line.seq === head.seq;
    }
    if (counting) {
      if (line.kind === 'checkpoint') counting = false;
      else if (++events >= interval) counting = false;
    }
    if (!counting && anchored) break;
    next = line;
  }
  if (!anchored) throw new Error('The audit log is shorter than or differs from its vault head. Run audit verify before continuing.');
  return { last, events, needsNewline: finalByte[0] !== 10 };
}

/** Snapshot JSON-compatible data without invoking toJSON; sanitize errors before exposing them. */
function cleanData(value: unknown, redactor?: Redactor, ancestors = new Set<object>()): unknown {
  if (typeof value === 'string') return redactor ? redactor.redact(value) : value;
  if (value === null || value === undefined || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'object' || ancestors.has(value)) throw new TypeError('Audit data must contain finite, acyclic JSON values.');
  ancestors.add(value);
  try {
    if (Array.isArray(value)) return Array.from(value, (entry) => cleanData(entry, redactor, ancestors));
    const result: Record<string, unknown> = Object.create(null);
    for (const [key, entry] of Object.entries(value)) {
      result[redactor ? redactor.redact(key) : key] = cleanData(entry, redactor, ancestors);
    }
    return result;
  } finally {
    ancestors.delete(value);
  }
}

export function createAuditLog(opts: {
  path: string;
  vault: Vault;
  deviceKey: () => Promise<DeviceKey>;
  checkpointEvery?: number;
  redactor?: Redactor;
  now?: () => Date;
  /** A shared per-user path; the existing lock protocol adds the .lock suffix. */
  keyLockPath?: string;
}): AuditLog {
  const path = resolve(opts.path);
  const headName = `audit/head/${createHash('sha256').update(path).digest('hex').slice(0, 16)}`;
  const interval = opts.checkpointEvery ?? 50;
  if (!Number.isSafeInteger(interval) || interval < 1) throw new TypeError('The audit checkpoint interval must be a positive integer.');
  const now = opts.now ?? (() => new Date());

  function mutationMacKey(): Promise<Buffer> {
    // Vault wrappers can share a backing store without sharing object identity. Serialize first-use
    // initialization across all instances here and, in production, across projects/processes too.
    return enqueue('audit/mac', async () => {
      let key: Buffer | undefined;
      const acquire = async () => { key = await getOrCreateKey(opts.vault, 'audit/mac', 32); return key; };
      try {
        return opts.keyLockPath ? await withLock(resolve(opts.keyLockPath), acquire) : await acquire();
      } catch (error) {
        key?.fill(0);
        throw error;
      }
    });
  }

  async function vaultHead(): Promise<Head | null> {
    const bytes = await opts.vault.get(headName);
    if (bytes === null) return null;
    try {
      const head: unknown = JSON.parse(bytes.toString('utf8'));
      if (!isRecord(head) || !Number.isSafeInteger(head.seq) || (head.seq as number) < 1 || typeof head.hash !== 'string' || !HASH.test(head.hash)) throw new Error();
      return { seq: head.seq as number, hash: head.hash };
    } catch {
      throw new Error('The audit head stored in the vault is unreadable.');
    }
  }

  function makeLine(event: AuditEvent, last: AuditLine | null, macKey: Buffer): AuditLine {
    const content = { seq: (last?.seq ?? 0) + 1, at: now().toISOString(), ...event, prev: last?.hash ?? ZERO_HASH };
    if (!Number.isSafeInteger(content.seq)) throw new Error('The audit log sequence limit has been reached.');
    const hash = lineHash(content);
    return { ...content, hash, mac: lineMac(hash, macKey) };
  }

  async function writeLine(file: FileHandle, line: AuditLine, needsNewline: boolean, assertLock: AssertLock): Promise<void> {
    const bytes = Buffer.from(`${needsNewline ? '\n' : ''}${canonicalJson(line)}\n`, 'utf8');
    await assertLock();
    const { bytesWritten } = await file.write(bytes);
    if (bytesWritten !== bytes.length) throw new Error('The audit log entry could not be written completely. Run audit verify before continuing.');
    await syncFile(file);
    await assertLock();
  }

  async function writeCheckpoint(file: FileHandle, last: AuditLine, needsNewline: boolean, assertLock: AssertLock, macKey: Buffer): Promise<void> {
    const key = await opts.deviceKey();
    const seq = last.seq + 1;
    const sig = signDetached(key.privateKeyDer, Buffer.from(`${AUDIT_CHECKPOINT_PREFIX}${seq}:${last.hash}`, 'utf8')).toString('base64');
    const line = makeLine({ kind: 'checkpoint', summary: 'Audit checkpoint', data: { head: last.hash, keyId: key.keyId, sig } }, last, macKey);
    await writeLine(file, line, needsNewline, assertLock);
    await opts.vault.set(headName, Buffer.from(JSON.stringify({ seq: line.seq, hash: line.hash }), 'utf8'));
  }

  async function mutate(event?: AuditEvent): Promise<void> {
    return enqueue(path, () => withLock(path, async (assertLock) => {
      const file = await open(path, 'a+', 0o600);
      let macKey: Buffer | undefined;
      try {
        const head = await vaultHead();
        macKey = await mutationMacKey();
        const tail = await readTail(file, event ? interval : 1, head, macKey);
        if (!event) {
          if (tail.last && tail.last.kind !== 'checkpoint') await writeCheckpoint(file, tail.last, tail.needsNewline, assertLock, macKey);
          return;
        }
        const line = makeLine(event, tail.last, macKey);
        await writeLine(file, line, tail.needsNewline, assertLock);
        if (tail.events + 1 >= interval) await writeCheckpoint(file, line, false, assertLock, macKey);
      } finally {
        macKey?.fill(0);
        await file.close();
      }
    }));
  }

  async function verify(): Promise<AuditVerifyResult> {
    return enqueue(path, () => withLock(path, async () => {
      let text: string;
      try {
        text = await readFile(path, 'utf8');
      } catch (error) {
        if (!isCode(error, 'ENOENT')) throw new Error('The audit log could not be read.');
        text = '';
      }
      const raw = text === '' ? [] : text.split('\n');
      if (raw.at(-1) === '') raw.pop();
      const parsed: unknown[] = raw.map((line) => { try { return JSON.parse(line) as unknown; } catch { return undefined; } });
      const entries = raw.length;
      const checkpoints = parsed.filter((line) => isRecord(line) && line.kind === 'checkpoint').length;
      const macKey = entries ? await opts.vault.get('audit/mac') : null;
      try {
        let failure: AuditVerifyResult | undefined;
        let previous = ZERO_HASH;
        let key: DeviceKey | undefined;
        for (let index = 0; index < parsed.length; index++) {
          const expected = index + 1;
          const line = parsed[index];
          let problem: string | undefined;
          if (!isRecord(line)) problem = `Unreadable line ${expected}.`;
          else if (line.seq !== expected) problem = `Sequence gap at line ${expected}.`;
          else if (line.prev !== previous) problem = `Prev mismatch at line ${expected}.`;
          else if (!isLine(line)) problem = `Unreadable line ${expected}.`;
          else {
            try {
              if (lineHash(line) !== line.hash) problem = `Hash mismatch at line ${expected}.`;
            } catch {
              problem = `Unreadable line ${expected}.`;
            }
            if (!problem && !validMac(line, macKey)) problem = `entry ${expected} was not written by keysentry on this computer`;
            if (!problem && line.kind === 'checkpoint') {
              const data = line.data;
              if (!data || data.head !== previous) problem = `Checkpoint head mismatch at line ${expected}.`;
              else {
                key ??= await opts.deviceKey();
                if (data.keyId !== key.keyId) problem = `Checkpoint at line ${expected} was signed by a different device key.`;
                else if (typeof data.sig !== 'string') problem = `Checkpoint signature check failed at line ${expected}.`;
                else {
                  const sig = Buffer.from(data.sig, 'base64');
                  if (sig.toString('base64') !== data.sig || !verifyDetached(key.publicKeyDer, Buffer.from(`${AUDIT_CHECKPOINT_PREFIX}${line.seq}:${data.head}`, 'utf8'), sig)) {
                    problem = `Checkpoint signature check failed at line ${expected}.`;
                  }
                }
              }
            }
          }
          if (problem) { failure = { ok: false, entries, checkpoints, firstBadSeq: expected, problem }; break; }
          previous = (line as AuditLine).hash;
        }
        const head = await vaultHead();
        if (head) {
          const recorded = parsed[head.seq - 1];
          if (entries < head.seq || !isRecord(recorded) || recorded.hash !== head.hash) {
            return { ...(failure ?? { ok: false, entries, checkpoints, problem: entries < head.seq ? 'The audit log is shorter than the last head stored in the vault.' : 'The audit log differs from the last head stored in the vault.' }), truncatedSinceLastKnownHead: true };
          }
        }
        return failure ?? { ok: true, entries, checkpoints };
      } finally { macKey?.fill(0); }
    }));
  }

  return {
    append(event) {
      try {
        if (event.kind === 'checkpoint') throw new TypeError('Use checkpoint() to write a signed checkpoint.');
        const clean: AuditEvent = {
          kind: event.kind,
          summary: opts.redactor ? opts.redactor.redact(event.summary) : event.summary,
          ...(event.data === undefined ? {} : { data: cleanData(event.data, opts.redactor) as Record<string, unknown> }),
        };
        // Validate now, before callers can change their data and before acquiring the lock.
        canonicalJson(clean);
        return mutate(clean);
      } catch {
        return Promise.reject(new TypeError('The audit event could not be encoded. Use checkpoint() for signed checkpoints and finite, acyclic JSON data for events.'));
      }
    },
    checkpoint: () => mutate(),
    verify,
  };
}
