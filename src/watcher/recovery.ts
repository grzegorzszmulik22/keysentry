import { createHash } from 'node:crypto';
import type { StateKind, StateStore } from '../core/store.js';
import { canonicalJson, signDetached, verifyDetached, type DeviceKey } from '../security/index.js';

export const RESUME_PREFIX = 'keysentry-resume:v1\n';
const DAY_MS = 86_400_000;
const MAX_RESUME_SIGNATURES = 10_000;

export interface SignedWatcherResume {
  type: 'keysentry-resume';
  v: 1;
  watcherId: string;
  keyId: string;
  at: string;
  /** Canonical standard base64 Ed25519 signature. */
  sig: string;
}

export interface RecoveryDeviceKey {
  keyId: string;
  publicKeyDer: Buffer;
}

export type WatcherResumeVerification = { ok: true; resume: SignedWatcherResume } | { ok: false; reason: string };

export interface ActionsRecoveryState {
  v: 1;
  watcherId: string;
  requiresResume: boolean;
  /** Retain this replay set in encrypted state across scheduled runs. */
  usedResumeSignatures: string[];
}

export interface ActionsRecoveryOptions {
  watcherId: string;
  state?: ActionsRecoveryState | null;
  trustedKeyIds: string[];
  deviceKeys: () => Promise<RecoveryDeviceKey[]>;
  now?: () => Date;
  /** Required for durable production use. Resolves only after encrypted persistence succeeds. */
  saveState?: (state: ActionsRecoveryState) => Promise<void>;
}

export interface ActionsRecovery {
  /** The supplied object is retained so callers can persist it with their other metadata. */
  state: ActionsRecoveryState;
  alertOnly(): boolean;
  resume(message: unknown): Promise<WatcherResumeVerification>;
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function fields(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === expected.length && actual.every(key => expected.includes(key));
}

function validWatcherId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 256 && !/[\u0000-\u001f\u007f]/u.test(value);
}

function validAt(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) return false;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return false;
  const canonical = new Date(timestamp).toISOString();
  return canonical === value || canonical.replace('.000Z', 'Z') === value;
}

function validSignature(value: unknown): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(value)) return false;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length === 64 && bytes.toString('base64') === value;
}

function validResume(value: unknown): value is SignedWatcherResume {
  return record(value) && fields(value, ['type', 'v', 'watcherId', 'keyId', 'at', 'sig'])
    && value.type === 'keysentry-resume' && value.v === 1 && validWatcherId(value.watcherId)
    && typeof value.keyId === 'string' && /^[a-f0-9]{16}$/.test(value.keyId)
    && validAt(value.at) && validSignature(value.sig);
}

function resumeBytes(input: Pick<SignedWatcherResume, 'watcherId' | 'keyId' | 'at'>): Buffer {
  return Buffer.from(RESUME_PREFIX + canonicalJson({ watcherId: input.watcherId, keyId: input.keyId, at: input.at }), 'utf8');
}

/** A recovery authorization releases only the missing-state latch; it does not re-arm a disarmed plan. */
export function signWatcherResume(input: { watcherId: string; at: string }, key: DeviceKey): SignedWatcherResume {
  try {
    if (!validWatcherId(input.watcherId) || !validAt(input.at)
      || !Buffer.isBuffer(key.publicKeyDer) || !Buffer.isBuffer(key.privateKeyDer)
      || createHash('sha256').update(key.publicKeyDer).digest('hex').slice(0, 16) !== key.keyId) {
      throw new TypeError();
    }
    const body = { watcherId: input.watcherId, keyId: key.keyId, at: input.at };
    const bytes = resumeBytes(body);
    const signature = signDetached(key.privateKeyDer, bytes);
    if (!verifyDetached(key.publicKeyDer, bytes, signature)) throw new TypeError();
    return { type: 'keysentry-resume', v: 1, ...body, sig: signature.toString('base64') };
  } catch { throw new TypeError('Watcher resume metadata or device key is invalid.'); }
}

/** Pure authentication/freshness check. Replay consumption belongs to createActionsRecovery. */
export function verifyWatcherResume(message: unknown, opts: {
  watcherId: string;
  trustedKeyIds: string[];
  deviceKeys: RecoveryDeviceKey[];
  now: Date;
}): WatcherResumeVerification {
  try {
    if (!validResume(message)) return { ok: false, reason: 'Watcher resume format is invalid.' };
    if (message.watcherId !== opts.watcherId) return { ok: false, reason: 'Watcher resume belongs to another watcher.' };
    const now = opts.now.getTime();
    const age = now - Date.parse(message.at);
    if (!Number.isFinite(now) || age < 0 || age > DAY_MS) return { ok: false, reason: 'Watcher resume is outside its valid time window.' };
    if (!opts.trustedKeyIds.includes(message.keyId)) return { ok: false, reason: 'Watcher resume signer is not trusted.' };
    const bytes = resumeBytes(message);
    const authenticated = opts.deviceKeys.some(key => key.keyId === message.keyId && Buffer.isBuffer(key.publicKeyDer)
      && createHash('sha256').update(key.publicKeyDer).digest('hex').slice(0, 16) === key.keyId
      && verifyDetached(key.publicKeyDer, bytes, Buffer.from(message.sig, 'base64')));
    if (!authenticated) return { ok: false, reason: 'Watcher resume signature is invalid.' };
    return { ok: true, resume: { ...message } };
  } catch { return { ok: false, reason: 'Watcher resume could not be verified.' }; }
}

function validRecoveryState(value: unknown, watcherId: string): value is ActionsRecoveryState {
  return record(value) && fields(value, ['v', 'watcherId', 'requiresResume', 'usedResumeSignatures'])
    && value.v === 1 && value.watcherId === watcherId && typeof value.requiresResume === 'boolean'
    && Array.isArray(value.usedResumeSignatures) && value.usedResumeSignatures.length <= MAX_RESUME_SIGNATURES
    && value.usedResumeSignatures.every(validSignature)
    && new Set(value.usedResumeSignatures).size === value.usedResumeSignatures.length;
}

/** Empty Actions state always needs a signed resume. Persist the returned state using an encrypted StateStore. */
export function createActionsRecovery(opts: ActionsRecoveryOptions): ActionsRecovery {
  if (!validWatcherId(opts.watcherId)) throw new TypeError('Watcher recovery identity is invalid.');
  const state = opts.state ?? { v: 1, watcherId: opts.watcherId, requiresResume: true, usedResumeSignatures: [] };
  if (!validRecoveryState(state, opts.watcherId)) throw new TypeError('Watcher recovery state format or identity is invalid.');
  let tail: Promise<unknown> = Promise.resolve();

  async function resume(message: unknown): Promise<WatcherResumeVerification> {
    // Revalidate because the supplied state remains owned by the integration layer.
    if (!validRecoveryState(state, opts.watcherId)) return { ok: false, reason: 'Watcher recovery state format or identity is invalid.' };
    let verified: WatcherResumeVerification;
    try {
      verified = verifyWatcherResume(message, {
        watcherId: opts.watcherId, trustedKeyIds: opts.trustedKeyIds,
        deviceKeys: await opts.deviceKeys(), now: (opts.now ?? (() => new Date()))(),
      });
    } catch { return { ok: false, reason: 'Watcher resume could not be verified.' }; }
    if (!verified.ok) return verified;
    if (state.usedResumeSignatures.includes(verified.resume.sig)) return { ok: false, reason: 'Watcher resume has already been used.' };
    if (state.usedResumeSignatures.length >= MAX_RESUME_SIGNATURES) return { ok: false, reason: 'Watcher resume history is full.' };
    const next: ActionsRecoveryState = {
      v: 1, watcherId: opts.watcherId, requiresResume: false,
      usedResumeSignatures: [...state.usedResumeSignatures, verified.resume.sig],
    };
    try { await opts.saveState?.(structuredClone(next)); }
    catch { return { ok: false, reason: 'Watcher resume state could not be saved.' }; }
    Object.assign(state, next);
    return verified;
  }

  return {
    state,
    alertOnly: () => !validRecoveryState(state, opts.watcherId) || state.requiresResume,
    resume(message) {
      const result = tail.then(() => resume(message));
      tail = result.then(() => undefined, () => undefined);
      return result;
    },
  };
}

export interface SequencedStateRecord<T> {
  type: 'keysentry-watcher-state';
  v: 1;
  sequence: number;
  data: T;
}

export interface SequencedStatePersistence<T> {
  load(): Promise<T | null>;
  save(data: T): Promise<void>;
  highestSequence(): number;
}

/**
 * One guard per encrypted record, retained for the process lifetime. The StateStore must have an authenticated
 * cipher: its envelope protects the sequence and payload together. An initial external high-water mark is optional.
 * This detects rollback observed during this process; a full rollback across restarts needs an independent anchor.
 */
export function createSequencedStateRecord<T>(opts: {
  store: Pick<StateStore, 'readJson' | 'writeJson'>;
  kind: StateKind;
  path: string;
  initialHighestSequence?: number;
}): SequencedStatePersistence<T> {
  let highest = opts.initialHighestSequence ?? 0;
  if (!Number.isSafeInteger(highest) || highest < 0) throw new TypeError('Watcher state sequence is invalid.');
  let tail: Promise<unknown> = Promise.resolve();

  function enqueue<R>(operation: () => Promise<R>): Promise<R> {
    const result = tail.then(operation);
    tail = result.then(() => undefined, () => undefined);
    return result;
  }

  async function read(): Promise<SequencedStateRecord<T> | null> {
    const saved = await opts.store.readJson<unknown>(opts.kind, opts.path);
    if (saved === null) {
      if (highest > 0) throw new Error('Watcher state is missing after an earlier sequence was observed.');
      return null;
    }
    if (!record(saved) || !fields(saved, ['type', 'v', 'sequence', 'data'])
      || saved.type !== 'keysentry-watcher-state' || saved.v !== 1
      || typeof saved.sequence !== 'number' || !Number.isSafeInteger(saved.sequence) || saved.sequence < 1) {
      throw new Error('Watcher state record format is invalid.');
    }
    if (saved.sequence < highest) throw new Error('Watcher state sequence is lower than the sequence already observed.');
    highest = saved.sequence;
    return saved as unknown as SequencedStateRecord<T>;
  }

  return {
    load: () => enqueue(async () => {
      const saved = await read();
      return saved === null ? null : saved.data;
    }),
    save: data => enqueue(async () => {
      // Capture the JSON value before awaiting I/O; omitted data would create an unreadable envelope.
      let snapshot: T;
      try {
        const json = JSON.stringify(data);
        if (json === undefined) throw new TypeError();
        snapshot = JSON.parse(json) as T;
      } catch { throw new TypeError('Watcher state payload cannot be saved as JSON.'); }
      // Never overwrite a restored older record, even when the caller has not loaded it explicitly.
      await read();
      if (highest === Number.MAX_SAFE_INTEGER) throw new Error('Watcher state sequence cannot be advanced.');
      const sequence = highest + 1;
      const saved: SequencedStateRecord<T> = { type: 'keysentry-watcher-state', v: 1, sequence, data: snapshot };
      await opts.store.writeJson(opts.kind, opts.path, saved);
      highest = sequence;
    }),
    highestSequence: () => highest,
  };
}
