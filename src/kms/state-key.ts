import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { KeyWrapper, KmsProviderId, Logger, Vault } from '../types.js';
import { stateKey as plainStateKey, VaultLockedError, VaultReadOnlyError } from '../vault/index.js';
import { KmsError, PROVIDER_LABELS } from './errors.js';
import { decodeBase64 } from './shared.js';
import { wrappedKeyVersion } from './wrapper.js';

const PROVIDERS: readonly KmsProviderId[] = ['aws-kms', 'gcp-kms', 'azure-key-vault', 'vault-transit'];
const PROJECT_ID = /^[0-9a-f]{16}$/;
const MAX_RECORD_BYTES = 32 * 1024;

/** The additional authenticated data every state-key wrap binds: the key only unwraps for this project. */
export function stateKeyContext(projectId: string): string {
  assertProjectId(projectId);
  return `keysentry-state:v1:${projectId}`;
}
export const plainStateKeyName = (projectId: string) => `project/${projectId}/key/state`;
export const wrappedStateKeyName = (projectId: string) => `project/${projectId}/key/state.wrapped`;

/** The vault entry `project/<id>/key/state.wrapped` (and, base64-encoded, `KEYSENTRY_STATE_KEY_WRAPPED`). */
export interface WrappedStateKey {
  v: 1;
  provider: KmsProviderId;
  /** The configured key it was wrapped with (non-secret). */
  keyRef: string;
  /** base64 of the provider adapter's opaque bytes. */
  ciphertext: string;
  wrappedAt: string;
}

function assertProjectId(projectId: string): void {
  if (typeof projectId !== 'string' || !PROJECT_ID.test(projectId)) throw new TypeError('The project identifier is invalid. Restore project.json before continuing.');
}

const damagedRecord = () => new KmsError('damaged', 'The wrapped state key in the vault is damaged or was changed. Restore it from a backup; keysentry did not create a new state key.');
const keptLocked = (error: unknown): unknown => error instanceof KmsError
  ? new KmsError(error.code, `${error.message} Saved state stays locked, and keysentry did not create a new state key.`)
  : error;

export function encodeWrappedStateKey(record: WrappedStateKey): Buffer {
  return Buffer.from(JSON.stringify({ v: 1, provider: record.provider, keyRef: record.keyRef, ciphertext: record.ciphertext, wrappedAt: record.wrappedAt }), 'utf8');
}

export function decodeWrappedStateKey(bytes: Buffer): WrappedStateKey {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > MAX_RECORD_BYTES) throw damagedRecord();
  let value: unknown;
  try { value = JSON.parse(bytes.toString('utf8')); } catch { throw damagedRecord(); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw damagedRecord();
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort().join(',');
  if (keys !== 'ciphertext,keyRef,provider,v,wrappedAt' || record.v !== 1 || !PROVIDERS.includes(record.provider as KmsProviderId)
    || typeof record.keyRef !== 'string' || !/^[\x20-\x7e]{1,2048}$/.test(record.keyRef)
    || typeof record.wrappedAt !== 'string' || record.wrappedAt.length > 64 || !Number.isFinite(Date.parse(record.wrappedAt))) throw damagedRecord();
  const opaque = decodeBase64(record.ciphertext, 16 * 1024);
  if (!opaque) throw damagedRecord();
  opaque.fill(0);
  return { v: 1, provider: record.provider as KmsProviderId, keyRef: record.keyRef, ciphertext: record.ciphertext as string, wrappedAt: record.wrappedAt };
}

/** `KEYSENTRY_STATE_KEY_WRAPPED`: base64 of the same record the vault entry holds. */
export function encodeWatcherWrappedStateKey(record: WrappedStateKey): string {
  return encodeWrappedStateKey(record).toString('base64');
}

export function decodeWatcherWrappedStateKey(encoded: string): WrappedStateKey {
  const bytes = decodeBase64(typeof encoded === 'string' ? encoded.trim() : encoded, MAX_RECORD_BYTES);
  if (!bytes) throw new KmsError('damaged', 'KEYSENTRY_STATE_KEY_WRAPPED is not a valid wrapped state key. Copy it again from watcher setup.');
  try { return decodeWrappedStateKey(bytes); }
  catch { throw new KmsError('damaged', 'KEYSENTRY_STATE_KEY_WRAPPED is not a valid wrapped state key. Copy it again from watcher setup.'); }
  finally { bytes.fill(0); }
}

/** Unwrap a record with the configured wrapper; a record made with another key is refused before any KMS call. */
export async function unwrapStateKey(wrapper: KeyWrapper, record: WrappedStateKey, projectId: string): Promise<Buffer> {
  if (record.provider !== wrapper.provider || record.keyRef !== wrapper.keyRef) {
    throw new KmsError('wrong-key', 'The state key was wrapped with a different KMS key than keysentry.yaml names. Restore the earlier kms settings; "keysentry kms status" shows both.');
  }
  const opaque = Buffer.from(record.ciphertext, 'base64');
  let key: Buffer;
  try { key = await wrapper.unwrap(opaque, stateKeyContext(projectId)); } finally { opaque.fill(0); }
  if (key.length !== 32) { key.fill(0); throw damagedRecord(); }
  return key;
}

/** Wrap, then prove the KMS gives the same key back before anything relies on the wrapped copy. */
export async function wrapStateKey(wrapper: KeyWrapper, key: Buffer, projectId: string, now: () => Date = () => new Date()): Promise<WrappedStateKey> {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new TypeError('The state key must be 32 bytes.');
  const opaque = await wrapper.wrap(key, stateKeyContext(projectId));
  const record: WrappedStateKey = { v: 1, provider: wrapper.provider, keyRef: wrapper.keyRef, ciphertext: opaque.toString('base64'), wrappedAt: now().toISOString() };
  opaque.fill(0);
  const check = await unwrapStateKey(wrapper, record, projectId);
  try {
    if (!timingSafeEqual(check, key)) {
      throw new KmsError('invalid-response', `${PROVIDER_LABELS[wrapper.provider]} did not give back the same key when keysentry checked the wrapped copy. Nothing was changed.`);
    }
  } finally { check.fill(0); }
  return record;
}

function sameKey(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

async function readRecord(vault: Vault, projectId: string, envWrapped?: string): Promise<WrappedStateKey | null> {
  const bytes = await vault.get(wrappedStateKeyName(projectId));
  if (bytes) { try { return decodeWrappedStateKey(bytes); } finally { bytes.fill(0); } }
  return envWrapped ? decodeWatcherWrappedStateKey(envWrapped) : null;
}

async function writeVerified(vault: Vault, wrapper: KeyWrapper, projectId: string, record: WrappedStateKey, key: Buffer): Promise<void> {
  try { await vault.set(wrappedStateKeyName(projectId), encodeWrappedStateKey(record)); }
  catch (error) {
    if (error instanceof VaultReadOnlyError) throw new KmsError('read-only', 'This vault is read-only, so the wrapped state key cannot be saved here. Nothing was changed.');
    throw error;
  }
  const saved = await readRecord(vault, projectId);
  if (!saved) throw new KmsError('invalid-response', 'The vault did not keep the wrapped state key. The plain copy was kept.');
  const check = await unwrapStateKey(wrapper, saved, projectId);
  try { if (!sameKey(check, key)) throw new KmsError('mismatch', 'The saved wrapped state key did not unwrap to the same key. The plain copy was kept.'); }
  finally { check.fill(0); }
}

export interface LoadStateKeyOptions {
  vault: Vault;
  projectId: string;
  /** Present exactly when keysentry.yaml has a `kms` section. */
  wrapper?: KeyWrapper;
  /** `KEYSENTRY_STATE_KEY_WRAPPED`, consulted only when the vault has no wrapped entry (environment vaults). */
  envWrapped?: string;
  log?: Pick<Logger, 'warn'>;
  now?: () => Date;
}

/**
 * The state key for runtime startup. Without kms it is the plain vault key, as before, unless only a wrapped copy
 * exists. With kms it is unwrapped into memory; any KMS failure refuses to start and never creates a new key.
 */
export async function loadProjectStateKey(options: LoadStateKeyOptions): Promise<Buffer> {
  const { vault, projectId, wrapper } = options;
  assertProjectId(projectId);
  if (!wrapper) {
    const wrapped = await vault.get(wrappedStateKeyName(projectId));
    wrapped?.fill(0);
    if (wrapped || options.envWrapped) {
      const plain = await vault.get(plainStateKeyName(projectId));
      plain?.fill(0);
      if (!plain) {
        throw new KmsError('config', 'This project\'s state key is wrapped with a KMS key, but keysentry.yaml has no kms section. Restore the kms settings to open saved state; keysentry did not create a new state key.');
      }
    }
    return plainStateKey(vault, projectId);
  }
  let record: WrappedStateKey | null;
  let plain: Buffer | null = null;
  try {
    record = await readRecord(vault, projectId, options.envWrapped);
    plain = await vault.get(plainStateKeyName(projectId));
    if (record) {
      const key = await unwrapStateKey(wrapper, record, projectId);
      if (plain) {
        if (!sameKey(plain, key)) {
          key.fill(0);
          throw new KmsError('mismatch', 'The wrapped state key and the plain state key in the vault are different keys. Run "keysentry kms status", then restore the vault entry that matches your saved state.');
        }
        options.log?.warn('The state key is wrapped, but its plain copy is still in the vault. Run "keysentry kms migrate" to finish removing it.');
      }
      return key;
    }
    if (plain) {
      if (plain.length !== 32) throw new VaultLockedError('A saved vault key has an unexpected length. Restore the matching vault key before continuing.');
      options.log?.warn('keysentry.yaml names a KMS key, but this project\'s state key is not wrapped yet. Run "keysentry kms migrate" to wrap it.');
      return Buffer.from(plain);
    }
    // Neither copy exists: a new project. Its first state key is created wrapped and is never stored in plain.
    if (vault.backend === 'env') {
      throw new KmsError('read-only', 'The environment vault cannot save a new wrapped state key. Set KEYSENTRY_STATE_KEY_WRAPPED (or KEYSENTRY_STATE_KEY) to the value from watcher setup.');
    }
    const key = randomBytes(32);
    try {
      const created = await wrapStateKey(wrapper, key, projectId, options.now);
      await writeVerified(vault, wrapper, projectId, created, key);
      return key;
    } catch (error) { key.fill(0); throw error; }
  } catch (error) {
    throw keptLocked(error);
  } finally { plain?.fill(0); }
}

export type MigrationPoint = 'wrapped-saved' | 'plain-deleted';
export interface MigrateStateKeyOptions {
  vault: Vault; projectId: string; wrapper: KeyWrapper; now?: () => Date;
  /** Test hook: called at each durable step, so a crash can be simulated there. */
  checkpoint?: (point: MigrationPoint) => void | Promise<void>;
}
export interface MigrationResult { result: 'migrated' | 'finished' | 'already-wrapped'; record: WrappedStateKey }

/**
 * Wrap the existing plain state key: save the wrapped copy, prove it unwraps to the same key, and only then delete the
 * plain copy. A crash before the deletion leaves both copies (the next run finishes); after it, only the wrapped one.
 */
export async function migrateStateKey(options: MigrateStateKeyOptions): Promise<MigrationResult> {
  const { vault, projectId, wrapper } = options;
  assertProjectId(projectId);
  if (vault.backend === 'env') {
    throw new KmsError('read-only', 'The environment vault is read-only, so the state key cannot be migrated here. Use KEYSENTRY_STATE_KEY_WRAPPED from watcher setup instead.');
  }
  const plainName = plainStateKeyName(projectId);
  const plain = await vault.get(plainName);
  try {
    const existing = await readRecord(vault, projectId);
    if (existing) {
      const key = await unwrapStateKey(wrapper, existing, projectId);
      try {
        if (!plain) return { result: 'already-wrapped', record: existing };
        if (!sameKey(plain, key)) {
          throw new KmsError('mismatch', 'The wrapped state key and the plain state key in the vault are different keys. Nothing was changed. Run "keysentry kms status".');
        }
      } finally { key.fill(0); }
      await deletePlain(vault, plainName, options);
      return { result: 'finished', record: existing };
    }
    if (!plain) throw new KmsError('not-wrapped', 'This project has no state key to migrate yet. Run "keysentry scan" first.');
    if (plain.length !== 32) throw new VaultLockedError('A saved vault key has an unexpected length. Restore the matching vault key before continuing.');
    const record = await wrapStateKey(wrapper, plain, projectId, options.now);
    await writeVerified(vault, wrapper, projectId, record, plain);
    await options.checkpoint?.('wrapped-saved');
    await deletePlain(vault, plainName, options);
    return { result: 'migrated', record };
  } finally { plain?.fill(0); }
}

async function deletePlain(vault: Vault, name: string, options: MigrateStateKeyOptions): Promise<void> {
  await vault.delete(name);
  const left = await vault.get(name);
  if (left) { left.fill(0); throw new KmsError('invalid-response', 'The vault still holds the plain state key after it was deleted. Run "keysentry kms migrate" again.'); }
  await options.checkpoint?.('plain-deleted');
}

export interface RotationResult { before?: string; after?: string; record: WrappedStateKey }

/** Rewrap under the key's current version (the provider's primary or latest version, or the pinned Key Vault version). */
export async function rotateStateKey(options: { vault: Vault; projectId: string; wrapper: KeyWrapper; now?: () => Date }): Promise<RotationResult> {
  const { vault, projectId, wrapper } = options;
  assertProjectId(projectId);
  if (vault.backend === 'env') throw new KmsError('read-only', 'The environment vault is read-only, so the wrapped state key cannot be replaced here.');
  const existing = await readRecord(vault, projectId);
  if (!existing) throw new KmsError('not-wrapped', 'The state key is not wrapped yet. Run "keysentry kms migrate" first.');
  const key = await unwrapStateKey(wrapper, existing, projectId);
  try {
    const record = await wrapStateKey(wrapper, key, projectId, options.now);
    await writeVerified(vault, wrapper, projectId, record, key);
    return { before: versionOf(existing), after: versionOf(record), record };
  } finally { key.fill(0); }
}

function versionOf(record: WrappedStateKey): string | undefined {
  const opaque = Buffer.from(record.ciphertext, 'base64');
  try { return wrappedKeyVersion(record.provider, opaque); } finally { opaque.fill(0); }
}

export interface StateKeyStatus {
  configured: { provider: KmsProviderId; keyRef: string } | null;
  wrapped: { provider: KmsProviderId; keyRef: string; keyVersion?: string; wrappedAt: string; matchesConfig: boolean } | null;
  plainCopy: boolean;
  check: { ok: boolean; message: string };
}

/** Read-only: what is configured, what the vault holds, and a live unwrap of the wrapped copy. */
export async function stateKeyStatus(options: { vault: Vault; projectId: string; wrapper?: KeyWrapper; envWrapped?: string }): Promise<StateKeyStatus> {
  const { vault, projectId, wrapper } = options;
  assertProjectId(projectId);
  const plain = await vault.get(plainStateKeyName(projectId));
  try {
    let record: WrappedStateKey | null = null;
    let damagedMessage: string | undefined;
    try { record = await readRecord(vault, projectId, options.envWrapped); }
    catch (error) { if (error instanceof KmsError) damagedMessage = error.message; else throw error; }
    const configured = wrapper ? { provider: wrapper.provider, keyRef: wrapper.keyRef } : null;
    const wrapped = record ? { provider: record.provider, keyRef: record.keyRef, wrappedAt: record.wrappedAt,
      matchesConfig: !!wrapper && record.provider === wrapper.provider && record.keyRef === wrapper.keyRef,
      ...(versionOf(record) ? { keyVersion: versionOf(record)! } : {}) } : null;
    const result = (ok: boolean, message: string): StateKeyStatus => ({ configured, wrapped, plainCopy: !!plain, check: { ok, message } });
    if (damagedMessage) return result(false, damagedMessage);
    if (!wrapper) {
      return record ? result(false, 'The state key is wrapped, but keysentry.yaml has no kms section. Restore the kms settings.')
        : result(true, 'No KMS is configured. The state key is kept in the vault.');
    }
    if (!record) {
      return plain ? result(false, 'The state key is not wrapped yet. Run "keysentry kms migrate".')
        : result(false, 'This project has no state key yet.');
    }
    let key: Buffer;
    try { key = await unwrapStateKey(wrapper, record, projectId); }
    catch (error) { if (error instanceof KmsError) return result(false, error.message); throw error; }
    try {
      if (plain && !sameKey(plain, key)) return result(false, 'The wrapped state key and the plain state key in the vault are different keys.');
      return result(true, plain ? 'The wrapped state key unwraps. Its plain copy is still in the vault: run "keysentry kms migrate" to finish.'
        : 'The wrapped state key unwraps with the configured key.');
    } finally { key.fill(0); }
  } finally { plain?.fill(0); }
}

/** For watcher setup: wrap a freshly generated watcher state key for `KEYSENTRY_STATE_KEY_WRAPPED`. */
export async function wrapWatcherStateKey(options: { wrapper: KeyWrapper; projectId: string; stateKey: Buffer; now?: () => Date }): Promise<string> {
  return encodeWatcherWrappedStateKey(await wrapStateKey(options.wrapper, options.stateKey, options.projectId, options.now));
}

/** For watcher bootstrap: unwrap `KEYSENTRY_STATE_KEY_WRAPPED`. Any failure refuses to start. */
export async function unwrapWatcherStateKey(options: { wrapper: KeyWrapper; projectId: string; encoded: string }): Promise<Buffer> {
  try { return await unwrapStateKey(options.wrapper, decodeWatcherWrappedStateKey(options.encoded), options.projectId); }
  catch (error) { throw keptLocked(error); }
}
