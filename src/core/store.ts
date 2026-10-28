import { createHash, randomBytes } from 'node:crypto';
import { link, mkdir, open, readFile, readdir, realpath, rename, unlink, writeFile } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import type { Stats } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { DecryptError, openBytes, sealBytes } from '../security/index.js';
import type { Inventory, Journal, JournalEntry, StateCipher, Vault } from '../types.js';
import { bindProjectPath, getProjectId } from '../vault/keys.js';
import { syncFile } from '../security/durable.js';

export interface StatePaths {
  dir: string;
  inventory: string;
  journal: string;
  audit: string;
  monitor: string;
  plans: string;
}

export type StateKind = 'inventory' | 'plan' | 'report' | 'monitor' | 'journal' | 'pending' | 'canary' | 'doctor' | 'legacy' | 'passkeys';

export interface StateStore {
  paths: StatePaths;
  writeJson(kind: StateKind, path: string, data: unknown, opts?: { replaceUndecryptable?: boolean }): Promise<void>;
  readJson<T = unknown>(kind: StateKind, path: string): Promise<T | null>;
  saveInventory(inventory: Inventory): Promise<void>;
  loadInventory(): Promise<Inventory | null>;
  journal(): Journal;
  migratePlaintext(): Promise<{ migrated: string[] }>;
}

export class StateLockedError extends Error {
  readonly code = 'STATE_LOCKED';
  constructor(dir: string, message?: string) {
    super(message ?? `keysentry's saved state in ${dir} can't be decrypted on this computer. Run "keysentry scan" in a terminal to replace the saved inventory with a fresh scan (it asks first), or "keysentry state reset" to start over.`);
    this.name = 'StateLockedError';
  }
}

export class StateCorruptError extends Error {
  readonly code = 'STATE_CORRUPT';
  constructor(readonly line: number) {
    super(`The journal at line ${line} was changed or damaged.`);
    this.name = 'StateCorruptError';
  }
}

export function createStateCipher(key: Buffer): StateCipher {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new TypeError('Encryption key must be exactly 32 bytes.');
  const ownedKey = Buffer.from(key);
  return {
    seal: (kind, plaintext) => sealBytes(ownedKey, plaintext, `keysentry-state:v2:${kind}`),
    open: (kind, sealed) => openBytes(ownedKey, sealed, `keysentry-state:v2:${kind}`),
  };
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
    try {
      await writeTextAtomic(path, serialize(data, true));
    } catch {
      throw new Error('Unable to write JSON state.');
    }
  });
}

/** Optional verification happens on the durable encrypted temporary file before replacing the original. */
async function writeTextAtomic(path: string, content: string, verify?: (saved: string) => void,
  beforeReplace?: () => Promise<void>): Promise<void> {
  const target = resolve(path);
  await preparePath(target);
  const temp = join(dirname(target), `.${basename(target)}-${randomBytes(16).toString('hex')}.tmp`);
  let created = false;
  try {
    const handle = await open(temp, 'wx', 0o600);
    created = true;
    try { await handle.writeFile(content, 'utf8'); await syncFile(handle); }
    finally { await handle.close(); }
    if (verify) verify(await readFile(temp, 'utf8'));
    // Persist the migration boundary before publishing encrypted state, including on a partial migration.
    await beforeReplace?.();
    // Windows may temporarily deny replacement while another process reads the target.
    for (let attempt = 0; ; attempt++) {
      try { await rename(temp, target); break; }
      catch (error) {
        const transient = hasCode(error, 'EPERM') || hasCode(error, 'EACCES') || hasCode(error, 'EBUSY');
        if (process.platform !== 'win32' || !transient || attempt >= 32) throw error;
        await new Promise<void>((done) => setTimeout(done, Math.min(50, 5 * (attempt + 1))));
      }
    }
  } finally { if (created) await unlink(temp).catch(() => undefined); }
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

const ENCRYPTED_HEADER = 'keysentry-encrypted:v1';

function encrypted(content: string): boolean {
  return content.split(/\r?\n/, 1)[0] === ENCRYPTED_HEADER;
}

function parseJson<T>(content: string): T {
  try { return JSON.parse(content) as T; }
  catch { throw new Error('Unable to read valid JSON state.'); }
}

function decodeBase64(line: string): Buffer {
  // Buffer.from accepts malformed and truncated base64; state must fail closed instead.
  if (!line || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(line)) throw new DecryptError();
  const bytes = Buffer.from(line, 'base64');
  if (bytes.toString('base64') !== line) throw new DecryptError();
  return bytes;
}

async function readText(path: string): Promise<string | null> {
  await preparePath(path);
  try { return await readFile(path, 'utf8'); }
  catch (error) { if (hasCode(error, 'ENOENT')) return null; throw error; }
}

function sealJson(cipher: StateCipher, context: string, data: unknown): string {
  let plaintext: Buffer | undefined;
  try {
    plaintext = Buffer.from(serialize(data));
    return cipher.seal(context, plaintext).toString('base64');
  } catch { throw new Error('Unable to write JSON state.'); }
  finally { plaintext?.fill(0); }
}

function unencryptedState(dir: string, path: string): StateLockedError {
  const rel = relative(dir, path).split(sep).join('/');
  return new StateLockedError(dir, `An unencrypted file appeared in keysentry's saved state: ${rel}. It was not written by keysentry; remove it or run keysentry state reset.`);
}

function openJson<T>(cipher: StateCipher | null, context: string, content: string, dir: string, path: string): T {
  if (!encrypted(content)) throw unencryptedState(dir, path);
  if (!cipher) throw new StateLockedError(dir);
  const lines = content.split(/\r?\n/);
  let plaintext: Buffer;
  try {
    if (lines.length < 2 || lines.slice(2).some(line => line !== '')) throw new DecryptError();
    plaintext = cipher.open(context, decodeBase64(lines[1]!));
  } catch (error) {
    if (error instanceof DecryptError) throw new StateLockedError(dir);
    throw new Error('Unable to read encrypted JSON state.');
  }
  try { return parseJson<T>(plaintext.toString('utf8')); }
  finally { plaintext.fill(0); }
}

const FIRST_RECORD_PREV = '0'.repeat(64);
interface JournalSnapshot { entries: JournalEntry[]; content: string; head: string }
interface SealedJournalRecord { entry: JournalEntry; prev: string; n: number }

function sealedLineHash(line: string): string {
  return createHash('sha256').update(line).digest('hex');
}

function plaintextJournal(content: string): JournalEntry[] {
  return content.split(/\r?\n/).filter(line => line.trim() !== '').map((line, index) => {
    try { return JSON.parse(line) as JournalEntry; }
    catch { throw new StateCorruptError(index + 1); }
  });
}

function openJournal(cipher: StateCipher | null, context: string, content: string, dir: string, path: string): JournalSnapshot {
  if (!encrypted(content)) throw unencryptedState(dir, path);
  if (!cipher) throw new StateLockedError(dir);
  const lines = content.split('\n');
  const entries: JournalEntry[] = [];
  const failures: { line: number; locked: boolean; torn: boolean; offset: number }[] = [];
  let authenticated = 0;
  let head = FIRST_RECORD_PREV;
  let offset = lines[0]!.length + 1;
  for (let index = 1; index < lines.length; index++) {
    const raw = lines[index]!;
    if (index === lines.length - 1 && raw === '') break;
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    const torn = index === lines.length - 1 && !content.endsWith('\n');
    let plaintext: Buffer | undefined;
    let decoded = false;
    let opened = false;
    try {
      const sealed = decodeBase64(line);
      // A partial envelope is a torn record, not evidence of a different key.
      decoded = sealed.length >= 32 && sealed.subarray(0, 4).equals(Buffer.from([75, 83, 49, 1]));
      plaintext = cipher.open(context, sealed);
      opened = true;
      authenticated++;
      const record = JSON.parse(plaintext.toString('utf8')) as SealedJournalRecord | null;
      if (!record || record.n !== index || record.prev !== head || !record.entry || typeof record.entry !== 'object') {
        throw new StateCorruptError(index + 1);
      }
      entries.push(record.entry);
      head = sealedLineHash(line);
    } catch (error) {
      failures.push({ line: index + 1, locked: decoded && error instanceof DecryptError,
        torn: torn && !opened, offset });
    } finally { plaintext?.fill(0); }
    offset += raw.length + 1;
  }
  // Authentication cannot distinguish a wrong key from damage to every record. Keep the file untouched.
  if (authenticated === 0 && failures.some(failure => failure.locked && !failure.torn)) throw new StateLockedError(dir);
  const corrupt = failures.find(failure => !failure.torn);
  if (corrupt) throw new StateCorruptError(corrupt.line);
  const tail = failures.find(failure => failure.torn);
  return { entries, content: tail ? content.slice(0, tail.offset) : content, head };
}

function sealedJournal(cipher: StateCipher, context: string, entries: JournalEntry[]): string {
  let prev = FIRST_RECORD_PREV;
  const lines = entries.map((entry, index) => {
    const line = sealJson(cipher, context, { entry, prev, n: index + 1 } satisfies SealedJournalRecord);
    prev = sealedLineHash(line);
    return `${line}\n`;
  });
  return `${ENCRYPTED_HEADER}\n${lines.join('')}`;
}

/** Resolve existing links even if the final file or its parents have not been created yet. */
async function physicalPath(path: string): Promise<string> {
  try { return await realpath(path); }
  catch (error) {
    if (!hasCode(error, 'ENOENT')) throw error;
    const parent = dirname(path);
    if (parent === path) throw error;
    return join(await physicalPath(parent), basename(path));
  }
}

async function appendDurable(path: string, line: string): Promise<void> {
  const bytes = Buffer.from(line, 'utf8');
  const handle = await open(path, 'a', 0o600);
  try {
    const { bytesWritten } = await handle.write(bytes);
    if (bytesWritten !== bytes.length) throw new Error('Unable to append a complete journal record.');
    await syncFile(handle);
  } finally { await handle.close(); }
}

export interface StateStoreOptions {
  cwd: string;
  cipher: StateCipher | null;
  /** Supply both to persist project-path binding and the one-time migration marker in the vault. */
  vault?: Vault;
  projectId?: string;
}

interface StateLockSnapshot { identity: Stats; content: string; pid: number | null }

function sameStateLock(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs && left.size === right.size;
}

async function inspectStateLock(path: string): Promise<StateLockSnapshot | null> {
  let handle: FileHandle;
  try { handle = await open(path, 'r'); }
  catch (error) { if (hasCode(error, 'ENOENT')) return null; throw error; }
  try {
    const identity = await handle.stat();
    const content = await handle.readFile('utf8');
    if (!sameStateLock(identity, await handle.stat())) return null;
    let pid: number | null = null;
    try {
      const metadata = JSON.parse(content) as { pid?: unknown } | null;
      if (metadata && typeof metadata.pid === 'number' && Number.isInteger(metadata.pid)
        && metadata.pid > 0 && metadata.pid <= 2_147_483_647) pid = metadata.pid;
    } catch { /* A crash may leave an incomplete metadata write. */ }
    return { identity, content, pid };
  } finally { await handle.close(); }
}

function stateLockOwnerExited(pid: number): boolean {
  try { process.kill(pid, 0); return false; }
  catch (error) { return hasCode(error, 'ESRCH'); }
}

/**
 * On Windows a lock file another process has just deleted stays "delete pending" until every handle closes, and
 * opening, linking or statting it fails with EPERM, EACCES or EBUSY. That is contention, not a broken lock.
 */
function windowsLockContention(error: unknown): boolean {
  return process.platform === 'win32' && (hasCode(error, 'EPERM') || hasCode(error, 'EACCES') || hasCode(error, 'EBUSY'));
}

/** The filesystem lock also serializes independent modules, processes, and aliases of the same directory. */
async function withStateLock<T>(dir: string, operation: (assertLock: () => Promise<void>) => Promise<T>): Promise<T> {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const path = join(dir, '.state.lock');
  const token = randomBytes(16).toString('hex');
  const temporary = join(dir, `.state-lock-${process.pid}-${token}.tmp`);
  const metadata = JSON.stringify({ pid: process.pid, token });
  const busy = () => new Error('keysentry\'s saved state is busy. Try again when the other operation finishes.');
  let handle: FileHandle;
  try { handle = await open(temporary, 'wx', 0o600); }
  catch { throw new Error('Unable to open the saved state lock.'); }
  let temporaryExists = true;
  let published = false;
  let identity: Stats | undefined;
  try {
    // Metadata is coordination data, not durable state; journal appends retain their single write/fsync.
    await handle.writeFile(metadata, 'utf8');
    const deadline = Date.now() + 10_000;
    let backoff = 10;
    for (;;) {
      if (Date.now() >= deadline) throw busy();
      try {
        // Publish complete owner metadata atomically, with no empty-lock window for another process.
        await link(temporary, path);
        published = true;
        break;
      } catch (error) { if (!hasCode(error, 'EEXIST') && !windowsLockContention(error)) throw new Error('Unable to open the saved state lock.'); }
      let current: StateLockSnapshot | null | 'contended';
      try { current = await inspectStateLock(path); }
      catch (error) {
        if (!windowsLockContention(error)) throw new Error('Unable to check the saved state lock.');
        current = 'contended';
      }
      if (current === null) continue;
      if (current === 'contended') {
        const remaining = deadline - Date.now();
        if (remaining <= 0) throw busy();
        await new Promise<void>(done => setTimeout(done, Math.min(remaining, backoff)));
        backoff = Math.min(backoff * 2, 200);
        continue;
      }
      if (current.pid === null || stateLockOwnerExited(current.pid)) {
        // stat/unlink cannot atomically avoid deleting a new owner during concurrent stale recovery.
        throw new Error('The saved state lock needs attention. Confirm that no keysentry command is running, then remove ".keysentry/.state.lock" and try again.');
      }
      // Never expire a live PID, even during a long vault call or a suspended event loop.
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw busy();
      await new Promise<void>(done => setTimeout(done, Math.min(remaining, backoff)));
      backoff = Math.min(backoff * 2, 200);
    }
    await unlink(temporary);
    temporaryExists = false;
    identity = await handle.stat();
    async function assertLock(): Promise<void> {
      const current = await inspectStateLock(path);
      if (!current || !identity || !sameStateLock(identity, current.identity) || current.content !== metadata) {
        throw new Error('The saved state lock changed. Try the operation again.');
      }
    }
    await assertLock();
    const result = await operation(assertLock);
    await assertLock();
    return result;
  } finally {
    try {
      if (published) {
        // Check the held inode again before unlinking; leave a replacement lock for its owner.
        const owned = identity ?? await handle.stat();
        const current = await inspectStateLock(path);
        if (current && sameStateLock(owned, current.identity) && current.content === metadata) {
          await unlink(path).catch((error: unknown) => { if (!hasCode(error, 'ENOENT')) throw error; });
        }
      }
    } finally {
      try { await handle.close(); }
      finally {
        if (temporaryExists) await unlink(temporary).catch((error: unknown) => { if (!hasCode(error, 'ENOENT')) throw error; });
      }
    }
  }
}

export function createStateStore(opts: StateStoreOptions): StateStore {
  const paths = statePaths(opts.cwd);
  const { cipher, vault, projectId } = opts;
  if ((vault === undefined) !== (projectId === undefined)) throw new TypeError('State project binding needs both a vault and a project identifier.');
  let identityBound = false;
  let initialized = false;

  function relativePath(path: string): string {
    return relative(paths.dir, path).split(sep).join('/');
  }

  function context(kind: StateKind, path: string): string {
    return `${kind}:${relativePath(path)}`;
  }

  function plaintextByDesign(path: string): boolean {
    return ['project.json', '.gitignore', 'audit.jsonl', 'network.jsonl'].includes(relativePath(path));
  }

  async function initialize(): Promise<void> {
    if (!vault || !projectId || identityBound) return;
    await checkedPath(join(paths.dir, 'project.json'));
    const actualId = await getProjectId(paths.dir);
    if (actualId !== projectId) {
      throw new StateLockedError(paths.dir, 'project.json was changed or copied from another project. Restore the original project.json before opening saved state.');
    }
    await bindProjectPath(vault, opts.cwd, projectId);
    identityBound = true;
  }

  async function isInitialized(): Promise<boolean> {
    if (initialized) return true;
    if (vault && projectId) {
      const marker = await vault.get(`project/${projectId}/state-initialized`);
      initialized = marker !== null;
      marker?.fill(0);
    }
    return initialized;
  }

  async function markInitialized(): Promise<void> {
    if (await isInitialized()) return;
    if (vault && projectId) await vault.set(`project/${projectId}/state-initialized`, Buffer.from('1'));
    initialized = true;
  }

  // A migration and the first encrypted write must not race over the initialization marker.
  function operate<T>(path: string, operation: () => Promise<T>): Promise<T> {
    return enqueue(paths.dir, () => withStateLock(paths.dir, async assertLock => {
      await initialize();
      return enqueue(path, async () => { await assertLock(); return operation(); });
    }));
  }

  function targetPath(path: string): string {
    const target = resolve(path);
    const rel = relative(paths.dir, target);
    if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
      throw new TypeError('State paths must resolve inside the project .keysentry directory.');
    }
    return target;
  }

  async function checkedPath(path: string): Promise<void> {
    const target = targetPath(path);
    const [base, physical] = await Promise.all([physicalPath(paths.dir), physicalPath(target)]);
    const rel = relative(base, physical);
    if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
      throw new TypeError('State paths must resolve inside the project .keysentry directory.');
    }
  }

  async function readStateText(path: string): Promise<string | null> {
    await checkedPath(path);
    await checkedPath(join(paths.dir, '.gitignore'));
    return readText(path);
  }

  async function read<T>(kind: StateKind, path: string): Promise<T | null> {
    const target = targetPath(path);
    return operate(target, async () => {
      const content = await readStateText(target);
      if (content === null) return null;
      if (!encrypted(content) && plaintextByDesign(target)) return parseJson<T>(content);
      return openJson<T>(cipher, context(kind, target), content, paths.dir, target);
    });
  }

  async function write(kind: StateKind, path: string, data: unknown, options: { replaceUndecryptable?: boolean } = {}): Promise<void> {
    const target = targetPath(path);
    return operate(target, async () => {
      const existing = await readStateText(target);
      if (existing !== null) {
        if (!encrypted(existing)) throw unencryptedState(paths.dir, target);
        if (!options.replaceUndecryptable) openJson(cipher, context(kind, target), existing, paths.dir, target);
      }
      if (!cipher) throw new StateLockedError(paths.dir);
      let content: string;
      try { content = `${ENCRYPTED_HEADER}\n${sealJson(cipher, context(kind, target), data)}\n`; }
      catch { throw new Error('Unable to write JSON state.'); }
      await markInitialized();
      try { await writeTextAtomic(target, content); }
      catch { throw new Error('Unable to write JSON state.'); }
    });
  }

  function journal(): Journal {
    return {
      read(planId) {
        return operate(paths.journal, async () => {
          const content = await readStateText(paths.journal);
          const entries = content === null ? [] : openJournal(cipher, context('journal', paths.journal), content, paths.dir, paths.journal).entries;
          return planId === undefined ? entries : entries.filter(entry => entry.planId === planId);
        });
      },
      append(entry) {
        return operate(paths.journal, async () => {
          const content = await readStateText(paths.journal);
          const aad = context('journal', paths.journal);
          const snapshot: JournalSnapshot = content === null ? { entries: [], content: '', head: FIRST_RECORD_PREV }
            : openJournal(cipher, aad, content, paths.dir, paths.journal);
          if (!cipher) throw new StateLockedError(paths.dir);
          const record = sealJson(cipher, aad, { entry, prev: snapshot.head, n: snapshot.entries.length + 1 } satisfies SealedJournalRecord);
          const prefix = !snapshot.content ? `${ENCRYPTED_HEADER}\n` : snapshot.content.endsWith('\n') ? '' : '\n';
          if (content !== null && content !== snapshot.content) {
            // Windows append handles cannot truncate. Repair only the ignored torn tail first.
            const repair = await open(paths.journal, 'r+');
            try { await repair.truncate(Buffer.byteLength(snapshot.content)); }
            finally { await repair.close(); }
          }
          await markInitialized();
          await appendDurable(paths.journal, `${prefix}${record}\n`);
        });
      },
    };
  }

  async function migrateJson(path: string, kind: StateKind): Promise<boolean> {
    return enqueue(path, async () => {
      const content = await readStateText(path);
      if (content === null || encrypted(content)) return false;
      const data = parseJson<unknown>(content);
      await writeTextAtomic(path, `${ENCRYPTED_HEADER}\n${sealJson(cipher!, context(kind, path), data)}\n`, saved => {
        if (!isDeepStrictEqual(openJson(cipher, context(kind, path), saved, paths.dir, path), data)) throw new Error('Unable to verify state migration.');
      }, markInitialized);
      return true;
    });
  }

  async function migrateJournal(): Promise<boolean> {
    return enqueue(paths.journal, async () => {
      const content = await readStateText(paths.journal);
      if (content === null || encrypted(content)) return false;
      const entries = plaintextJournal(content);
      const aad = context('journal', paths.journal);
      await writeTextAtomic(paths.journal, sealedJournal(cipher!, aad, entries), saved => {
        if (!isDeepStrictEqual(openJournal(cipher, aad, saved, paths.dir, paths.journal).entries, entries)) throw new Error('Unable to verify journal migration.');
      }, markInitialized);
      return true;
    });
  }

  async function migrateAudit(): Promise<boolean> {
    return enqueue(paths.audit, async () => {
      const content = await readStateText(paths.audit);
      if (content === null || encrypted(content)) return false;
      const entries = plaintextJournal(content) as unknown[];
      const hasHash = (entry: unknown) => entry !== null && typeof entry === 'object' && Object.hasOwn(entry, 'hash');
      if (entries.length && entries.every(hasHash)) return false;
      if (entries.some(hasHash)) throw new Error('Unable to migrate mixed audit formats. The original log was kept.');
      const archive = join(paths.dir, 'audit-0.1.enc');
      await enqueue(archive, async () => {
        const existing = await readStateText(archive);
        if (existing !== null) {
          const data = encrypted(existing) ? openJson(cipher, context('legacy', archive), existing, paths.dir, archive) : parseJson(existing);
          if (!isDeepStrictEqual(data, entries)) throw new Error('Unable to verify legacy audit migration. The original log was kept.');
        }
        if (existing === null || !encrypted(existing)) {
          await writeTextAtomic(archive, `${ENCRYPTED_HEADER}\n${sealJson(cipher!, context('legacy', archive), entries)}\n`, saved => {
            if (!isDeepStrictEqual(openJson(cipher, context('legacy', archive), saved, paths.dir, archive), entries)) throw new Error('Unable to verify legacy audit migration.');
          }, markInitialized);
        }
      });
      await markInitialized();
      await unlink(paths.audit);
      return true;
    });
  }

  return {
    paths, writeJson: write, readJson: read,
    saveInventory: inventory => write('inventory', paths.inventory, inventory),
    loadInventory: () => read<Inventory>('inventory', paths.inventory),
    journal,
    async migratePlaintext() {
      return enqueue(paths.dir, () => withStateLock(paths.dir, async assertLock => {
        await initialize();
        await assertLock();
        if (!cipher || await isInitialized()) return { migrated: [] };
        await readStateText(paths.inventory);
        const files: { path: string; kind: StateKind }[] = [];
        for (const entry of await readdir(paths.dir, { withFileTypes: true })) {
          if (!entry.isFile()) continue;
          let kind: StateKind | undefined;
          if (entry.name === 'inventory.json') kind = 'inventory';
          else if (entry.name === 'monitor.json') kind = 'monitor';
          else if (entry.name === 'rotation-report.json') kind = 'report';
          else if (entry.name === 'passkeys.json') kind = 'passkeys';
          else if (/^pending.*\.json$/.test(entry.name)) kind = 'pending';
          else if (/^canar(?:y|ies).*\.json$/.test(entry.name)) kind = 'canary';
          if (kind) files.push({ path: join(paths.dir, entry.name), kind });
        }
        try {
          await checkedPath(paths.plans);
          for (const entry of await readdir(paths.plans, { withFileTypes: true })) {
            if (entry.isFile() && entry.name.endsWith('.json')) files.push({ path: join(paths.plans, entry.name), kind: 'plan' });
          }
        } catch (error) { if (!hasCode(error, 'ENOENT')) throw error; }
        const migrated: string[] = [];
        for (const file of files) {
          if (await migrateJson(file.path, file.kind)) migrated.push(relativePath(file.path));
        }
        if (await migrateJournal()) migrated.push('journal.jsonl');
        if (await migrateAudit()) migrated.push('audit.jsonl');
        return { migrated };
      }));
    },
  };
}
