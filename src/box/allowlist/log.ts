import { createHash } from 'node:crypto';
import { canonicalJson, deviceKeyFromPrivate, signDetached } from '../../security/index.js';
import type { AllowListEntry } from '../../types.js';

export const ALLOWLIST_ENTRY_PREFIX = 'keysentry-allowlist:v1\n';
export const ALLOWLIST_HEAD_PREFIX = 'keysentry-allowlist-head:v1\n';
export const ALLOWLIST_GENESIS_HASH = '0'.repeat(64);

export type AllowListEntryInput = Omit<AllowListEntry, 'hash' | 'sig'>;
export interface AllowListHeadInput { seq: number; hash: string; at: string }
export interface AllowListHead extends AllowListHeadInput { keyId: string; sig: string }

export function isDigest(value: unknown): value is string {
  return typeof value === 'string' && /^sha256:[a-fA-F0-9]{64}$/.test(value);
}

export function isHash(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

/** UTC ISO timestamps, with optional millisecond precision; reject date rollover. */
export function isTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,3}))?Z$/.exec(value);
  if (!match) return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === `${match[1]}.${(match[2] ?? '').padEnd(3, '0')}Z`;
}

function nonempty(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

export function exactFields(value: unknown, fields: readonly string[]): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
}

export function isSignature(value: unknown): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(value)) return false;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length === 64 && bytes.toString('base64') === value;
}

function validEntryInput(input: AllowListEntryInput): boolean {
  return Number.isSafeInteger(input.seq) && input.seq > 0 && isDigest(input.digest)
    && nonempty(input.reference) && nonempty(input.reason) && isTimestamp(input.addedAt)
    && isHash(input.prev) && (input.seq !== 1 || input.prev === ALLOWLIST_GENESIS_HASH);
}

export function isAllowListEntry(value: unknown): value is AllowListEntry {
  return exactFields(value, ['seq', 'digest', 'reference', 'addedAt', 'reason', 'prev', 'hash', 'sig'])
    && validEntryInput(value as unknown as AllowListEntryInput) && isHash(value.hash) && isSignature(value.sig);
}

function validHeadInput(input: AllowListHeadInput): boolean {
  return Number.isSafeInteger(input.seq) && input.seq >= 0 && isHash(input.hash) && isTimestamp(input.at)
    && (input.seq !== 0 || input.hash === ALLOWLIST_GENESIS_HASH);
}

export function isAllowListHead(value: unknown): value is AllowListHead {
  return exactFields(value, ['seq', 'hash', 'at', 'keyId', 'sig'])
    && validHeadInput(value as unknown as AllowListHeadInput) && nonempty(value.keyId) && isSignature(value.sig);
}

export function hashAllowListEntry(input: AllowListEntryInput): string {
  // Select fields explicitly: neither the hash nor its signature hashes itself.
  const { seq, digest, reference, addedAt, reason, prev } = input;
  return createHash('sha256').update(canonicalJson({ seq, digest, reference, addedAt, reason, prev }), 'utf8').digest('hex');
}

export function headSigningBytes(input: AllowListHeadInput): Buffer {
  const { seq, hash, at } = input;
  return Buffer.from(ALLOWLIST_HEAD_PREFIX + canonicalJson({ seq, hash, at }), 'utf8');
}

/** Authoring helper; appenders are responsible for extending a verified log. */
export function createAllowListEntry(input: AllowListEntryInput, privateKeyDer: Buffer): AllowListEntry {
  if (!exactFields(input, ['seq', 'digest', 'reference', 'addedAt', 'reason', 'prev']) || !validEntryInput(input)) {
    throw new TypeError('Allow-list entry fields are not valid.');
  }
  const key = deviceKeyFromPrivate(privateKeyDer);
  try {
    const hash = hashAllowListEntry(input);
    const sig = signDetached(key.privateKeyDer, Buffer.from(ALLOWLIST_ENTRY_PREFIX + hash, 'utf8')).toString('base64');
    return { ...input, hash, sig };
  } finally {
    key.privateKeyDer.fill(0);
  }
}

export function createAllowListHead(input: AllowListHeadInput, privateKeyDer: Buffer): AllowListHead {
  if (!exactFields(input, ['seq', 'hash', 'at']) || !validHeadInput(input)) {
    throw new TypeError('Allow-list head fields are not valid.');
  }
  const key = deviceKeyFromPrivate(privateKeyDer);
  try {
    return { ...input, keyId: key.keyId, sig: signDetached(key.privateKeyDer, headSigningBytes(input)).toString('base64') };
  } finally {
    key.privateKeyDer.fill(0);
  }
}

/** Use only entries returned by a successful verifyAllowList call. Latest event wins. */
export function isAllowed(entries: readonly AllowListEntry[], digest: string, at: Date | string): boolean {
  if (!isDigest(digest)) return false;
  const time = at instanceof Date ? at.getTime() : isTimestamp(at) ? Date.parse(at) : NaN;
  if (!Number.isFinite(time)) return false;
  let allowed = false;
  for (const entry of entries) {
    if (entry.digest.toLowerCase() === digest.toLowerCase() && Date.parse(entry.addedAt) <= time) {
      allowed = entry.reason !== 'revoked';
    }
  }
  return allowed;
}
