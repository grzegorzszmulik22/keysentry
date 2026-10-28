import { randomBytes } from 'node:crypto';
import { link, mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import type { Vault } from '../../types.js';
import { DEFAULT_SCRYPT, deriveKeyFromPassphrase, openBytes, sealBytes, type ScryptParams } from '../../security/index.js';
import { VaultLockedError } from '../errors.js';
import { validateVaultName } from '../names.js';
import { syncFile } from '../../security/durable.js';

interface VaultFile {
  v: 1;
  salt: string;
  params: ScryptParams;
  check: string;
  entries: Record<string, string>;
}

const CHECK = Buffer.from('keysentry-vault-check');

function parseFile(raw: string): VaultFile {
  try {
    const data: unknown = JSON.parse(raw);
    if (!data || typeof data !== 'object') throw new Error();
    const file = data as VaultFile;
    if (file.v !== 1 || typeof file.salt !== 'string' || Buffer.from(file.salt, 'base64').length !== 16
      || !file.params || ![file.params.N, file.params.r, file.params.p].every(n => Number.isSafeInteger(n) && n > 0)
      || typeof file.check !== 'string' || !file.entries || typeof file.entries !== 'object' || Array.isArray(file.entries)) throw new Error();
    for (const [name, sealed] of Object.entries(file.entries)) {
      validateVaultName(name);
      if (typeof sealed !== 'string') throw new Error();
    }
    return file;
  } catch {
    throw new VaultLockedError();
  }
}

export function createEncryptedFileVault(opts: { path: string; passphrase: () => Promise<Buffer>; scrypt?: ScryptParams }): Vault {
  const path = resolve(opts.path);
  let opened: Promise<{ key: Buffer; salt: string; params: ScryptParams }> | undefined;
  // Asked for before the lock is taken, so a prompt left waiting never blocks other keysentry processes
  // and closing the terminal at the prompt leaves no lock behind.
  let asked: Promise<Buffer> | undefined;
  let tail = Promise.resolve();

  async function load(): Promise<{ file: VaultFile; key: Buffer }> {
    let file: VaultFile | undefined;
    try { file = parseFile(await readFile(path, 'utf8')); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    if (!file && opened) throw new VaultLockedError('The vault file was removed. Reopen the vault before continuing.');
    const salt = file?.salt ?? randomBytes(16).toString('base64');
    const params = file?.params ?? { ...(opts.scrypt ?? DEFAULT_SCRYPT) };
    opened ??= (async () => {
      // The callback's returned buffer is consumed here and cleared after derivation.
      const passphrase = await (asked ??= opts.passphrase());
      let key: Buffer;
      try { key = await deriveKeyFromPassphrase(passphrase, Buffer.from(salt, 'base64'), params); }
      catch { throw new VaultLockedError(); }
      finally { passphrase.fill(0); }
      return { key, salt, params };
    })();
    const cached = await opened;
    if (salt !== cached.salt || params.N !== cached.params.N || params.r !== cached.params.r || params.p !== cached.params.p) {
      throw new VaultLockedError('The vault file changed. Reopen the vault before continuing.');
    }
    if (file) {
      try {
        const check = openBytes(cached.key, Buffer.from(file.check, 'base64'), 'vault:__check__');
        try { if (!check.equals(CHECK)) throw new Error(); }
        finally { check.fill(0); }
      } catch { throw new VaultLockedError(); }
    } else {
      file = { v: 1, salt, params,
        check: sealBytes(cached.key, CHECK, 'vault:__check__').toString('base64'), entries: Object.create(null) as Record<string, string> };
      await persist(file);
    }
    return { file, key: cached.key };
  }

  async function locked<T>(fn: () => Promise<T>): Promise<T> {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    const lockPath = `${path}.lock`;
    const temporary = `${lockPath}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
    const started = Date.now();
    function recovery(): VaultLockedError {
      return new VaultLockedError(`The vault lock needs checking. If no keysentry process is running, remove ${lockPath} and try again.`);
    }
    let acquired = false;
    try {
      const handle = await open(temporary, 'wx', 0o600);
      try { await handle.writeFile(JSON.stringify({ pid: process.pid })); await syncFile(handle); }
      finally { await handle.close(); }
      while (!acquired) {
        // Linking a complete record gives exclusive publication without exposing
        // a partial PID record. Never unlink another process's lock automatically.
        try { await link(temporary, lockPath); acquired = true; }
        catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
          let owner: unknown;
          try { owner = JSON.parse(await readFile(lockPath, 'utf8')); }
          catch (failure) {
            if ((failure as NodeJS.ErrnoException).code === 'ENOENT') continue;
            throw recovery();
          }
          const pid = owner && typeof owner === 'object' && 'pid' in owner ? owner.pid : undefined;
          if (typeof pid !== 'number' || !Number.isSafeInteger(pid) || pid < 1) throw recovery();
          try { process.kill(pid, 0); }
          catch (failure) {
            if ((failure as NodeJS.ErrnoException).code === 'ESRCH') throw recovery();
          }
          if (Date.now() - started > 15_000) throw new VaultLockedError('The vault is busy in another keysentry process. Try again after it finishes.');
          await delay(25);
        }
      }
      return await fn();
    } finally {
      if (acquired) await rm(lockPath, { force: true });
      await rm(temporary, { force: true });
    }
  }

  function serial<T>(fn: () => Promise<T>): Promise<T> {
    const pending = tail.then(async () => {
      if (!opened) await (asked ??= opts.passphrase());
      return locked(fn);
    });
    tail = pending.then(() => undefined, () => undefined);
    return pending;
  }

  async function persist(file: VaultFile): Promise<void> {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    const temporary = `${path}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
    try {
      const handle = await open(temporary, 'wx', 0o600);
      try { await handle.writeFile(JSON.stringify(file)); await syncFile(handle); }
      finally { await handle.close(); }
      await rename(temporary, path);
    } finally { await rm(temporary, { force: true }); }
  }

  return {
    backend: 'encrypted-file',
    weakness: "Keys are in an encrypted file protected by your passphrase, not by the operating system's credential store.",
    async get(name) {
      validateVaultName(name);
      return serial(async () => {
        const { file, key } = await load();
        const value = Object.hasOwn(file.entries, name) ? file.entries[name] : undefined;
        if (value === undefined) return null;
        try { return openBytes(key, Buffer.from(value, 'base64'), `vault:${name}`); }
        catch { throw new VaultLockedError(); }
      });
    },
    async set(name, value) {
      validateVaultName(name);
      const copy = Buffer.from(value);
      try {
        await serial(async () => {
          const { file, key } = await load();
          const entries = { ...file.entries, [name]: sealBytes(key, copy, `vault:${name}`).toString('base64') };
          const next = { ...file, entries };
          await persist(next);
          file.entries = entries;
        });
      } finally { copy.fill(0); }
    },
    async delete(name) {
      validateVaultName(name);
      return serial(async () => {
        const { file } = await load();
        if (!Object.hasOwn(file.entries, name)) return false;
        const entries = { ...file.entries };
        delete entries[name];
        await persist({ ...file, entries });
        file.entries = entries;
        return true;
      });
    },
    async list(prefix = '') {
      if (prefix) validateVaultName(prefix);
      return serial(async () => Object.keys((await load()).file.entries).filter(name => name.startsWith(prefix)).sort());
    },
  };
}
