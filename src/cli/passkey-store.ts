import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { link, lstat, mkdir, open, unlink, type FileHandle } from 'node:fs/promises';
import type { Stats } from 'node:fs';
import { z } from 'zod';
import type { StateStore } from '../core/store.js';
import type { PasskeyCredential, Vault } from '../types.js';
import { CliError } from './errors.js';

const credentialSchema = z.object({
  id: z.string().regex(/^[A-Za-z0-9_-]{1,1364}$/),
  publicKeyCose: z.string().regex(/^[A-Za-z0-9_-]{1,16384}$/),
  alg: z.union([z.literal(-7), z.literal(-8), z.literal(-257)]),
  signCount: z.number().int().min(0).max(0xffffffff), backupEligible: z.boolean(),
  rpId: z.string().min(1), origins: z.array(z.string().url()).min(1).max(100),
  label: z.string().max(80), createdAt: z.string().datetime(),
}).strict();
const credentialsSchema = z.array(credentialSchema).max(100);
const legacySchema = z.object({ v: z.literal(1), credentials: credentialsSchema }).strict();
const queues = new Map<string, Promise<unknown>>();

function code(error: unknown, expected: string): boolean {
  return error instanceof Error && 'code' in error && error.code === expected;
}
function sameLock(a: Stats, b: Stats): boolean {
  return a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeMs === b.mtimeMs && a.ctimeMs === b.ctimeMs;
}
async function inspectLock(path: string): Promise<{ identity: Stats; content: string; pid: number | null } | null> {
  let handle: FileHandle;
  try {
    const entry = await lstat(path);
    if (!entry.isFile() || entry.isSymbolicLink()) throw new CliError('The passkey lock needs attention. Confirm that no keysentry command is running, then remove ".keysentry/.passkeys.lock" and try again.');
    handle = await open(path, 'r');
  } catch (error) { if (code(error, 'ENOENT')) return null; throw error; }
  try {
    const identity = await handle.stat();
    const content = await handle.readFile('utf8');
    if (!sameLock(identity, await handle.stat())) return null;
    let pid: number | null = null;
    try {
      const metadata = JSON.parse(content) as { pid?: unknown } | null;
      if (metadata && typeof metadata.pid === 'number' && Number.isInteger(metadata.pid) && metadata.pid > 0 && metadata.pid <= 2_147_483_647) pid = metadata.pid;
    } catch { /* Interrupted or changed metadata requires explicit recovery. */ }
    return { identity, content, pid };
  } finally { await handle.close(); }
}
function ownerExited(pid: number): boolean {
  try { process.kill(pid, 0); return false; }
  catch (error) { return code(error, 'ESRCH'); }
}

/** Hold a distinct filesystem lock over the full credential read/modify/write transaction. */
async function withPasskeyLock<T>(dir: string, operation: (assertLock: () => Promise<void>) => Promise<T>): Promise<T> {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const path = join(dir, '.passkeys.lock');
  const token = randomBytes(16).toString('hex');
  const temporary = join(dir, `.passkey-lock-${process.pid}-${token}.tmp`);
  const content = JSON.stringify({ pid: process.pid, token });
  const handle = await open(temporary, 'wx', 0o600);
  let temporaryExists = true; let published = false; let identity: Stats | undefined;
  try {
    await handle.writeFile(content, 'utf8');
    const deadline = Date.now() + 10_000;
    let backoff = 10;
    for (;;) {
      try { await link(temporary, path); published = true; break; }
      catch (error) { if (!code(error, 'EEXIST')) throw new CliError('The passkey lock could not be opened.'); }
      const current = await inspectLock(path);
      if (current === null) continue;
      // Do not unlink even a dead owner: checking then unlinking could erase a new owner's lock.
      if (current.pid === null || ownerExited(current.pid)) throw new CliError('The passkey lock needs attention. Confirm that no keysentry command is running, then remove ".keysentry/.passkeys.lock" and try again.');
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new CliError('Saved passkeys are busy. Try again when the other keysentry operation finishes.');
      await new Promise<void>(done => setTimeout(done, Math.min(remaining, backoff)));
      backoff = Math.min(backoff * 2, 200);
    }
    await unlink(temporary); temporaryExists = false;
    identity = await handle.stat();
    const assertLock = async () => {
      const current = await inspectLock(path);
      if (!current || !identity || !sameLock(identity, current.identity) || current.content !== content) throw new CliError('The passkey lock changed. Try the operation again.');
    };
    await assertLock();
    const result = await operation(assertLock);
    await assertLock();
    return result;
  } finally {
    try {
      if (published) {
        const owned = identity ?? await handle.stat();
        const current = await inspectLock(path);
        if (current && sameLock(owned, current.identity) && current.content === content) await unlink(path).catch(error => { if (!code(error, 'ENOENT')) throw error; });
      }
    } finally {
      try { await handle.close(); }
      finally { if (temporaryExists) await unlink(temporary).catch(error => { if (!code(error, 'ENOENT')) throw error; }); }
    }
  }
}

function invalid(): CliError { return new CliError('Saved passkeys could not be read.'); }
function parse(value: unknown): PasskeyCredential[] {
  const parsed = credentialsSchema.safeParse(value);
  if (!parsed.success || new Set(parsed.data.map(item => item.id)).size !== parsed.data.length) throw invalid();
  return parsed.data;
}
function sameKey(a: PasskeyCredential, b: PasskeyCredential): boolean {
  return a.publicKeyCose === b.publicKeyCose && a.alg === b.alg && a.rpId === b.rpId
    && a.backupEligible === b.backupEligible && JSON.stringify(a.origins) === JSON.stringify(b.origins);
}
function localOrigins(credential: PasskeyCredential): boolean {
  return credential.rpId === 'localhost' && credential.origins.every(origin => {
    try {
      const url = new URL(origin);
      return url.protocol === 'http:' && url.hostname === 'localhost' && !url.username && !url.password
        && url.pathname === '/' && !url.search && !url.hash && url.origin === origin;
    } catch { return false; }
  });
}

export interface PasskeyStateStore {
  list(): Promise<PasskeyCredential[]>;
  add(credential: PasskeyCredential): Promise<void>;
  update(credential: PasskeyCredential): Promise<void>;
  remove(id: string): Promise<boolean>;
}

/** CLI registration and dashboard assertions share this encrypted state record. */
export function createPasskeyStore(store: StateStore, vault?: Vault): PasskeyStateStore {
  const path = join(store.paths.dir, 'passkeys.json');
  const queueKey = resolve(path);
  function serial<T>(operation: (assertLock: () => Promise<void>) => Promise<T>): Promise<T> {
    const previous = queues.get(queueKey) ?? Promise.resolve();
    const pending = previous.catch(() => undefined).then(() => withPasskeyLock(store.paths.dir, operation));
    queues.set(queueKey, pending);
    return pending.finally(() => { if (queues.get(queueKey) === pending) queues.delete(queueKey); });
  }
  async function load(assertLock: () => Promise<void>): Promise<PasskeyCredential[]> {
    let raw: unknown;
    let oldKind = false;
    try { raw = await store.readJson('passkeys', path); }
    catch (error) {
      // The earlier CLI used the pending kind. Only migrate after authenticating it.
      try { raw = await store.readJson('pending', path); oldKind = true; }
      catch { throw error; }
    }
    const legacy = legacySchema.safeParse(raw);
    const credentials = raw === null ? [] : parse(legacy.success ? legacy.data.credentials : raw);
    if (legacy.success) {
      for (const item of credentials) {
        if (localOrigins(item) && !item.origins.includes('http://localhost')) item.origins.push('http://localhost');
      }
    }
    let changed = oldKind || legacy.success;
    const names = vault ? await vault.list('passkey/') : [];
    if (names.length > 100) throw invalid();
    for (const name of names) {
      const bytes = await vault!.get(name);
      if (!bytes) throw invalid();
      let value: PasskeyCredential;
      try {
        if (bytes.length > 65_536) throw invalid();
        const result = credentialSchema.safeParse(JSON.parse(bytes.toString('utf8')));
        if (!result.success || name !== `passkey/${result.data.id}`) throw invalid();
        value = result.data;
      } catch { throw invalid(); }
      finally { bytes.fill(0); }
      const previous = credentials.find(item => item.id === value.id);
      if (previous) {
        if (!sameKey(previous, value)) throw invalid();
        previous.signCount = Math.max(previous.signCount, value.signCount);
      } else credentials.push(value);
      changed = true;
    }
    parse(credentials);
    if (changed) {
      await assertLock();
      await store.writeJson('passkeys', path, credentials, { replaceUndecryptable: oldKind });
      const verified = parse(await store.readJson('passkeys', path));
      if (JSON.stringify(verified) !== JSON.stringify(credentials)) throw invalid();
      // Never discard a source credential before durable encrypted read-back succeeds.
      for (const name of names) { await assertLock(); await vault!.delete(name); }
    }
    return credentials;
  }
  async function put(input: PasskeyCredential, update: boolean, assertLock: () => Promise<void>): Promise<void> {
    const value = parse([input])[0]!;
    const credentials = await load(assertLock);
    const index = credentials.findIndex(item => item.id === value.id);
    const previous = credentials[index];
    if (update ? !previous || !sameKey(previous, value) || value.signCount < previous.signCount : !!previous || credentials.length >= 100) {
      throw new CliError('This passkey cannot be saved.');
    }
    if (update) credentials[index] = value;
    else credentials.push(value);
    await assertLock(); await store.writeJson('passkeys', path, credentials);
  }
  return {
    list: () => serial(load),
    add: value => serial(assertLock => put(value, false, assertLock)),
    update: value => serial(assertLock => put(value, true, assertLock)),
    remove: id => serial(async assertLock => {
      const credentials = await load(assertLock);
      const remaining = credentials.filter(item => item.id !== id);
      if (remaining.length === credentials.length) return false;
      await assertLock(); await store.writeJson('passkeys', path, remaining);
      return true;
    }),
  };
}
