import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import type { AllowListEntry } from '../../../src/types.js';
import { canonicalJson } from '../../../src/security/index.js';
import {
  createAllowListEntry, createAllowListHead, isAllowed, verifyAllowList,
} from '../../../src/box/allowlist/index.js';

const pair = generateKeyPairSync('ed25519');
const privateKeyDer = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
const publicKeyDer = pair.publicKey.export({ format: 'der', type: 'spki' });
const keyId = createHash('sha256').update(publicKeyDer).digest('hex').slice(0, 16);
const keys = [{ keyId, publicKeyDer }];
const genesis = '0'.repeat(64);
const digestA = `sha256:${'a'.repeat(64)}`;
const digestB = `sha256:${'b'.repeat(64)}`;
const t1 = '2026-10-27T10:00:00.000Z';
const t2 = '2026-10-27T11:00:00.000Z';
const t3 = '2026-10-27T12:00:00.000Z';

// Sign independently of the production builders so verifier tests do not bless
// a shared hashing or domain-separation mistake.
function entry(seq: number, prev: string, changes: Partial<AllowListEntry> = {}): AllowListEntry {
  const payload = {
    seq, digest: digestA, reference: 'keysentry/box@v1.0.0', addedAt: t1,
    reason: 'release', prev, ...changes,
  };
  const { hash: _hash, sig: _sig, ...unsigned } = payload;
  const hash = createHash('sha256').update(canonicalJson(unsigned)).digest('hex');
  const sig = sign(null, Buffer.from(`keysentry-allowlist:v1\n${hash}`), pair.privateKey).toString('base64');
  return { ...unsigned, hash, sig };
}

function head(last: Pick<AllowListEntry, 'seq' | 'hash'> = { seq: 0, hash: genesis }, at = t3): string {
  const payload = { seq: last.seq, hash: last.hash, at };
  const sig = sign(null, Buffer.from(`keysentry-allowlist-head:v1\n${canonicalJson(payload)}`), pair.privateKey).toString('base64');
  return JSON.stringify({ ...payload, keyId, sig });
}

function log(entries: AllowListEntry[]): string {
  return entries.map(item => JSON.stringify(item)).join('\n') + (entries.length ? '\n' : '');
}

function chain(): AllowListEntry[] {
  const a = entry(1, genesis);
  const b = entry(2, a.hash, { digest: digestB, addedAt: t2 });
  return [a, b, entry(3, b.hash, { reason: 'revoked', addedAt: t3 })];
}

describe('allow-list verification', () => {
  test('accepts a valid log and its signed head, including CRLF transport', () => {
    const entries = chain();
    expect(verifyAllowList(log(entries).replaceAll('\n', '\r\n'), head(entries[2]), keys)).toEqual({ ok: true, entries, problems: [] });
  });

  test('accepts a signed empty log and refuses an unsigned empty log', () => {
    expect(verifyAllowList('', head(), keys)).toEqual({ ok: true, entries: [], problems: [] });
    expect(verifyAllowList('', '', keys).ok).toBe(false);
  });

  test('detects an edited entry and returns no usable entries', () => {
    const entries = chain();
    entries[0] = { ...entries[0]!, reference: 'altered' };
    const result = verifyAllowList(log(entries), head(entries[2]), keys);
    expect(result.ok).toBe(false);
    expect(result.entries).toEqual([]);
    expect(result.problems.join(' ')).toMatch(/hash/i);
  });

  test('detects a deleted middle entry', () => {
    const entries = chain();
    expect(verifyAllowList(log([entries[0]!, entries[2]!]), head(entries[2]), keys).ok).toBe(false);
  });

  test('detects reordering', () => {
    const entries = chain();
    expect(verifyAllowList(log([entries[1]!, entries[0]!, entries[2]!]), head(entries[2]), keys).ok).toBe(false);
  });

  test('detects a truncated tail against the signed head', () => {
    const entries = chain();
    expect(verifyAllowList(log(entries.slice(0, 2)), head(entries[2]), keys).ok).toBe(false);
  });

  test('detects a correctly signed head for a different branch', () => {
    const entries = chain();
    const fork = entry(3, entries[1]!.hash, { reason: 'different release', addedAt: t3 });
    expect(verifyAllowList(log(entries), head(fork), keys).ok).toBe(false);
  });

  test('requires an extension of a previously observed head', () => {
    const entries = chain();
    const previousHead = { seq: entries[1]!.seq, hash: entries[1]!.hash };
    expect(verifyAllowList(log(entries), head(entries[2]), keys, { previousHead }).ok).toBe(true);
    const fork2 = entry(2, entries[0]!.hash, { reference: 'alternate release', addedAt: t2 });
    expect(verifyAllowList(log([entries[0]!, fork2]), head(fork2), keys, { previousHead }).ok).toBe(false);
    expect(verifyAllowList(log(entries.slice(0, 1)), head(entries[0]), keys, { previousHead }).ok).toBe(false);
  });

  test('detects unknown entry signing keys separately from the head key', () => {
    const foreign = generateKeyPairSync('ed25519');
    const a = entry(1, genesis);
    a.sig = sign(null, Buffer.from(`keysentry-allowlist:v1\n${a.hash}`), foreign.privateKey).toString('base64');
    expect(verifyAllowList(log([a]), head(a), keys).ok).toBe(false);
  });

  test('refuses unknown and mismatched head key IDs', () => {
    const a = entry(1, genesis);
    const wrongKey = generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' });
    expect(verifyAllowList(log([a]), head(a), []).ok).toBe(false);
    expect(verifyAllowList(log([a]), head(a), [{ keyId: 'another-key', publicKeyDer }]).ok).toBe(false);
    expect(verifyAllowList(log([a]), head(a), [{ keyId, publicKeyDer: wrongKey }]).ok).toBe(false);
  });

  test('accepts historical entries from another pinned release key', () => {
    const other = generateKeyPairSync('ed25519');
    const a = entry(1, genesis);
    a.sig = sign(null, Buffer.from(`keysentry-allowlist:v1\n${a.hash}`), other.privateKey).toString('base64');
    const otherDer = other.publicKey.export({ format: 'der', type: 'spki' });
    expect(verifyAllowList(log([a]), head(a), [...keys, { keyId: 'historical-key', publicKeyDer: otherDer }]).ok).toBe(true);
  });

  test.each(['sha256:abc', `sha256:${'g'.repeat(64)}`, 'latest', `SHA256:${'a'.repeat(64)}`, `${digestA}\n`])('refuses a signed malformed digest (%s)', digest => {
    const a = entry(1, genesis, { digest });
    expect(verifyAllowList(log([a]), head(a), keys).ok).toBe(false);
  });

  test.each(['not json', '{}', 'null', '[]', '\n', '{"seq":1}\n'])('fails closed on malformed log input (%j)', input => {
    expect(verifyAllowList(input, head(), keys)).toMatchObject({ ok: false, entries: [] });
  });

  test.each(['not json', '{}', 'null', '[]'])('fails closed on malformed head input (%j)', input => {
    expect(verifyAllowList('', input, keys)).toMatchObject({ ok: false, entries: [] });
  });

  test('rejects extra unsigned entry or head fields', () => {
    const a = entry(1, genesis);
    expect(verifyAllowList(log([{ ...a, extra: true } as AllowListEntry]), head(a), keys).ok).toBe(false);
    expect(verifyAllowList(log([a]), JSON.stringify({ ...JSON.parse(head(a)), extra: true }), keys).ok).toBe(false);
  });

  test('rejects invalid signatures, sequence numbers and timestamps without throwing', () => {
    for (const changes of [{ sig: '!' }, { seq: 0 }, { seq: 1.5 }, { addedAt: 'no date' }, { addedAt: '2026-02-30T00:00:00.000Z' }]) {
      const a = { ...entry(1, genesis), ...changes };
      expect(verifyAllowList(log([a]), head(a), keys).ok).toBe(false);
    }
  });

  test('rejects backwards entry time or a head earlier than the last entry', () => {
    const a = entry(1, genesis, { addedAt: t2 });
    const b = entry(2, a.hash, { addedAt: t1 });
    expect(verifyAllowList(log([a, b]), head(b), keys).ok).toBe(false);
    expect(verifyAllowList(log([a]), head(a, t1), keys).ok).toBe(false);
  });

  test('rejects malformed previous heads and ambiguous key IDs', () => {
    const a = entry(1, genesis);
    for (const previousHead of [{ seq: -1, hash: genesis }, { seq: 0, hash: 'x' }, { seq: 0, hash: a.hash }]) {
      expect(verifyAllowList(log([a]), head(a), keys, { previousHead }).ok).toBe(false);
    }
    expect(verifyAllowList(log([a]), head(a), [...keys, ...keys]).ok).toBe(false);
  });
});

describe('allow-list authoring and membership', () => {
  test('builds a canonical hash and domain-separated entry signature', () => {
    const input = { seq: 1, digest: digestA, reference: 'release', addedAt: t1, reason: 'release', prev: genesis };
    const result = createAllowListEntry(input, privateKeyDer);
    const hash = createHash('sha256').update('{"addedAt":"2026-10-27T10:00:00.000Z","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","prev":"0000000000000000000000000000000000000000000000000000000000000000","reason":"release","reference":"release","seq":1}').digest('hex');
    expect(result.hash).toBe(hash);
    expect(verify(null, Buffer.from(`keysentry-allowlist:v1\n${hash}`), pair.publicKey, Buffer.from(result.sig, 'base64'))).toBe(true);
    expect(verify(null, Buffer.from(hash), pair.publicKey, Buffer.from(result.sig, 'base64'))).toBe(false);
  });

  test('builds a signed head with a release-key-derived key ID', () => {
    const result = createAllowListHead({ seq: 0, hash: genesis, at: t1 }, privateKeyDer);
    expect(result).toMatchObject({ seq: 0, hash: genesis, at: t1, keyId });
    expect(verifyAllowList('', JSON.stringify(result), keys).ok).toBe(true);
  });

  test('refuses to author malformed entries or sign with a non-Ed25519 key', () => {
    const input = { seq: 1, digest: 'bad', reference: 'release', addedAt: t1, reason: 'release', prev: genesis };
    expect(() => createAllowListEntry(input, privateKeyDer)).toThrow();
    const wrong = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ format: 'der', type: 'pkcs8' });
    expect(() => createAllowListHead({ seq: 0, hash: genesis, at: t1 }, wrong)).toThrow();
  });

  test('refuses a hash with a trailing newline when authoring', () => {
    expect(() => createAllowListHead({ seq: 1, hash: `${genesis}\n`, at: t1 }, privateKeyDer)).toThrow();
    expect(() => createAllowListEntry({ seq: 2, digest: digestA, reference: 'release', addedAt: t1, reason: 'release', prev: `${genesis}\n` }, privateKeyDer)).toThrow();
  });

  test('applies revocation at its timestamp, ignoring future entries', () => {
    const entries = chain();
    expect(isAllowed(entries, digestA, new Date('2026-10-27T09:59:59.999Z'))).toBe(false);
    expect(isAllowed(entries, digestA, new Date(t1))).toBe(true);
    expect(isAllowed(entries, digestA, new Date(t2))).toBe(true);
    expect(isAllowed(entries, digestA, new Date(t3))).toBe(false);
    expect(isAllowed(entries, digestB, new Date(t3))).toBe(true);
  });

  test('case changes cannot bypass a revocation', () => {
    const entries = chain();
    expect(isAllowed(entries, `sha256:${'A'.repeat(64)}`, new Date(t3))).toBe(false);
    expect(isAllowed(entries, `sha256:${'A'.repeat(64)}`, new Date(t1))).toBe(true);
  });

  test('an explicit later entry may re-allow a digest', () => {
    const entries = chain();
    entries.push(entry(4, entries[2]!.hash, { addedAt: '2026-10-27T13:00:00.000Z' }));
    expect(isAllowed(entries, digestA, new Date('2026-10-27T13:00:00.000Z'))).toBe(true);
  });

  test('refuses invalid digest and time queries', () => {
    expect(isAllowed(chain(), 'latest', new Date(t1))).toBe(false);
    expect(isAllowed(chain(), digestA, new Date('invalid'))).toBe(false);
  });
});
