import { createHash, randomBytes } from 'node:crypto';
import { link, mkdir, open, readFile, realpath, unlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import type { Vault } from '../types.js';
import { deviceKeyFromPrivate, generateDeviceKey, type DeviceKey } from '../security/index.js';
import { environmentVariableForName } from './backends/env.js';
import { VaultLockedError, VaultReadOnlyError } from './errors.js';
import { validateVaultName } from './names.js';

const projectLocks = new Map<string, Promise<unknown>>();
const vaultLocks = new WeakMap<Vault, Map<string, Promise<unknown>>>();

function serial<T>(locks: Map<string, Promise<unknown>>, name: string, operation: () => Promise<T>): Promise<T> {
  const pending = (locks.get(name) ?? Promise.resolve()).catch(() => undefined).then(operation);
  locks.set(name, pending);
  const cleanup = () => { if (locks.get(name) === pending) locks.delete(name); };
  void pending.then(cleanup, cleanup);
  return pending;
}

function withVaultLock<T>(vault: Vault, name: string, operation: () => Promise<T>): Promise<T> {
  let locks = vaultLocks.get(vault);
  if (!locks) { locks = new Map(); vaultLocks.set(vault, locks); }
  return serial(locks, name, operation);
}

function assertLength(key: Buffer, bytes: number): Buffer {
  if (key.length !== bytes) {
    key.fill(0);
    throw new VaultLockedError('A saved vault key has an unexpected length. Restore the matching vault key before continuing.');
  }
  return key;
}

function readOnlyKey(name: string, bytes = 32): VaultReadOnlyError {
  return new VaultReadOnlyError(`Set ${environmentVariableForName(name)} to a base64 key. Generate a value with: node -e "console.log(require('node:crypto').randomBytes(${bytes}).toString('base64'))"`);
}

export function getProjectId(stateDir: string): Promise<string> {
  const path = join(resolve(stateDir), 'project.json');
  return serial(projectLocks, path, async () => {
    async function read(): Promise<string> {
      let data: unknown;
      try { data = JSON.parse(await readFile(path, 'utf8')); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw error;
        throw new TypeError('The project identifier file is invalid. Restore project.json before continuing.');
      }
      const id = data && typeof data === 'object' && 'id' in data ? data.id : undefined;
      if (typeof id !== 'string' || !/^[0-9a-f]{16}$/.test(id)) throw new TypeError('The project identifier file is invalid. Restore project.json before continuing.');
      return id;
    }
    try { return await read(); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    await mkdir(stateDir, { recursive: true, mode: 0o700 });
    const id = randomBytes(8).toString('hex');
    const temporary = `${path}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
    try {
      const handle = await open(temporary, 'wx', 0o600);
      try { await handle.writeFile(JSON.stringify({ id })); await handle.sync(); }
      finally { await handle.close(); }
      // Publishing a completed inode prevents a partial project.json after a
      // crash; link also refuses to replace another process's project identity.
      await link(temporary, path);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') return read();
      throw error;
    } finally {
      await unlink(temporary).catch((error: unknown) => {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      });
    }
    return id;
  });
}

/** Keep the project identity outside the project files that it authenticates. */
export async function bindProjectPath(vault: Vault, projectDir: string, projectId: string): Promise<void> {
  if (!/^[0-9a-f]{16}$/.test(projectId)) throw new TypeError('The project identifier is invalid. Restore project.json before continuing.');
  // Canonicalize physical aliases and Windows casing so the same directory cannot acquire a second identity.
  const projectPath = await realpath(resolve(projectDir));
  const name = `projects/by-path/${createHash('sha256').update(projectPath).digest('hex').slice(0, 32)}`;
  return withVaultLock(vault, name, async () => {
    const existing = await vault.get(name);
    try {
      if (existing !== null) {
        if (!existing.equals(Buffer.from(projectId))) {
          throw new VaultLockedError('project.json was changed or copied from another project. Restore the original project.json before opening saved state.');
        }
        return;
      }
      await vault.set(name, Buffer.from(projectId));
    } finally { existing?.fill(0); }
  });
}

export function getOrCreateKey(vault: Vault, name: string, bytes = 32): Promise<Buffer> {
  validateVaultName(name);
  if (!Number.isSafeInteger(bytes) || bytes < 1) throw new TypeError('The key length must be a positive integer.');
  return withVaultLock(vault, name, async () => {
    const existing = await vault.get(name);
    if (existing !== null) return assertLength(existing, bytes);
    const key = randomBytes(bytes);
    try { await vault.set(name, key); }
    catch (error) {
      key.fill(0);
      if (error instanceof VaultReadOnlyError) throw readOnlyKey(name, bytes);
      throw error;
    }
    return key;
  });
}

export function stateKey(vault: Vault, projectId: string): Promise<Buffer> {
  return getOrCreateKey(vault, `project/${projectId}/key/state`);
}

export function fingerprintKey(vault: Vault, projectId: string, legacyFile?: string): Promise<Buffer> {
  const name = `project/${projectId}/key/fingerprint`;
  validateVaultName(name);
  return withVaultLock(vault, 'fingerprint-migration', async () => {
    const existing = await vault.get(name);
    if (existing !== null) return assertLength(existing, 32);
    const imported = await vault.get('key/fingerprint-legacy');
    if (imported !== null) {
      assertLength(imported, 32);
      try { await vault.set(name, imported); return Buffer.from(imported); }
      finally { imported.fill(0); }
    }
    let legacy: Buffer | undefined;
    if (legacyFile) {
      try { legacy = assertLength(await readFile(legacyFile), 32); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    }
    if (!legacy) return getOrCreateKey(vault, name);
    try {
      await vault.set('key/fingerprint-legacy', legacy);
      await vault.set(name, legacy);
      const [savedLegacy, savedProject] = await Promise.all([vault.get('key/fingerprint-legacy'), vault.get(name)]);
      try {
        if (!savedLegacy?.equals(legacy) || !savedProject?.equals(legacy)) {
          throw new VaultLockedError('The legacy fingerprint key could not be verified in the vault. The original file was kept.');
        }
      } finally { savedLegacy?.fill(0); savedProject?.fill(0); }
      await unlink(legacyFile!);
      return Buffer.from(legacy);
    } finally { legacy.fill(0); }
  });
}

export function deviceKey(vault: Vault): Promise<DeviceKey> {
  const name = 'key/device-ed25519';
  return withVaultLock(vault, name, async () => {
    const existing = await vault.get(name);
    if (existing !== null) {
      try { return deviceKeyFromPrivate(existing); }
      catch { throw new VaultLockedError('The device signing key could not be opened. Restore the matching vault key before continuing.'); }
      finally { existing.fill(0); }
    }
    if (vault.backend === 'env') {
      throw new VaultReadOnlyError(`Set KEYSENTRY_DEVICE_KEY to a base64 Ed25519 private key in PKCS#8 DER format. Generate a value with: node -e "console.log(require('node:crypto').generateKeyPairSync('ed25519').privateKey.export({type:'pkcs8',format:'der'}).toString('base64'))"`);
    }
    const key = generateDeviceKey();
    try { await vault.set(name, key.privateKeyDer); }
    catch (error) { key.privateKeyDer.fill(0); throw error; }
    return key;
  });
}

export async function inflightKey(vault: Vault, projectId: string, planId: string, create: boolean): Promise<Buffer | null> {
  const name = `project/${projectId}/inflight/${planId}`;
  validateVaultName(name);
  if (create) return getOrCreateKey(vault, name);
  const key = await vault.get(name);
  return key === null ? null : assertLength(key, 32);
}

export function deleteInflightKey(vault: Vault, projectId: string, planId: string): Promise<boolean> {
  const name = `project/${projectId}/inflight/${planId}`;
  validateVaultName(name);
  return withVaultLock(vault, name, () => vault.delete(name));
}
