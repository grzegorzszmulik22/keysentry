import { verifyDetached } from '../../security/index.js';
import type { AllowListEntry } from '../../types.js';
import {
  ALLOWLIST_ENTRY_PREFIX, ALLOWLIST_GENESIS_HASH, hashAllowListEntry, headSigningBytes,
  isAllowListEntry, isAllowListHead, isHash,
} from './log.js';
import type { AllowListHeadInput } from './log.js';

export interface AllowListVerificationKey { keyId: string; publicKeyDer: Buffer }
export interface VerifyAllowListOptions { previousHead?: Pick<AllowListHeadInput, 'seq' | 'hash'> }
export interface AllowListVerifyResult { ok: boolean; entries: AllowListEntry[]; problems: string[] }

function parse(text: string): unknown {
  try { return JSON.parse(text) as unknown; } catch { return null; }
}

/** Offline verification against independently pinned release keys and an optional saved head. */
export function verifyAllowList(
  log: string,
  head: string,
  keys: readonly AllowListVerificationKey[],
  opts: VerifyAllowListOptions = {},
): AllowListVerifyResult {
  const problems: string[] = [];
  const entries: AllowListEntry[] = [];
  const keyIds = new Set<string>();
  for (const key of keys) {
    if (!key.keyId || keyIds.has(key.keyId)) problems.push('Release signing key IDs must be nonempty and unique.');
    keyIds.add(key.keyId);
  }

  const lines = log === '' ? [] : log.split(/\r?\n/);
  if (lines.at(-1) === '') lines.pop();
  let previous = ALLOWLIST_GENESIS_HASH;
  let previousTime = -Infinity;
  for (const [index, line] of lines.entries()) {
    const value = parse(line);
    const label = `Allow-list entry ${index + 1}`;
    if (!isAllowListEntry(value)) {
      problems.push(`${label} has invalid fields.`);
      continue;
    }
    if (value.seq !== index + 1) problems.push(`${label} has a sequence gap or is out of order.`);
    if (value.prev !== previous) problems.push(`${label} does not extend the previous hash.`);
    if (hashAllowListEntry(value) !== value.hash) problems.push(`${label} hash does not match its contents.`);
    const data = Buffer.from(ALLOWLIST_ENTRY_PREFIX + value.hash, 'utf8');
    if (!keys.some(key => verifyDetached(key.publicKeyDer, data, Buffer.from(value.sig, 'base64')))) {
      problems.push(`${label} signature is not valid under a known release signing key.`);
    }
    const time = Date.parse(value.addedAt);
    if (time < previousTime) problems.push(`${label} timestamp precedes the previous entry.`);
    previousTime = time;
    previous = value.hash;
    entries.push(value);
  }

  const treeHead = parse(head);
  if (!isAllowListHead(treeHead)) {
    problems.push('Allow-list head has invalid fields.');
  } else {
    const key = keys.find(item => item.keyId === treeHead.keyId);
    if (!key) problems.push('Allow-list head uses an unknown release signing key.');
    else if (!verifyDetached(key.publicKeyDer, headSigningBytes(treeHead), Buffer.from(treeHead.sig, 'base64'))) {
      problems.push('Allow-list head signature is not valid.');
    }
    const last = entries.at(-1);
    if (treeHead.seq !== lines.length || treeHead.hash !== (last?.hash ?? ALLOWLIST_GENESIS_HASH)) {
      problems.push('Allow-list head does not match the last entry; the log may be truncated or forked.');
    }
    if (Date.parse(treeHead.at) < previousTime) problems.push('Allow-list head timestamp precedes the last entry.');
  }

  if (opts.previousHead !== undefined) {
    const saved = opts.previousHead;
    if (!Number.isSafeInteger(saved.seq) || saved.seq < 0 || !isHash(saved.hash)
      || (saved.seq === 0 && saved.hash !== ALLOWLIST_GENESIS_HASH)) {
      problems.push('Previously saved allow-list head has invalid fields.');
    } else if (saved.seq > entries.length || (saved.seq === 0 ? ALLOWLIST_GENESIS_HASH : entries[saved.seq - 1]?.hash) !== saved.hash) {
      problems.push('Allow-list does not extend the previously saved head; it is rolled back or forked.');
    }
  }

  // Never hand membership callers a usable prefix of an unverified history.
  return { ok: problems.length === 0, entries: problems.length === 0 ? entries : [], problems };
}
