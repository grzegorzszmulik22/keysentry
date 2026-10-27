import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createStateCipher, createStateStore } from '../../src/core/store.js';
import { canonicalJson, generateDeviceKey, signDetached, verifyDetached } from '../../src/security/index.js';
import {
  createActionsRecovery, createSequencedStateRecord, signWatcherResume, verifyWatcherResume,
  type ActionsRecoveryState, type SignedWatcherResume,
} from '../../src/watcher/recovery.js';

const now = new Date('2026-10-27T12:00:00.000Z');
const watcherId = 'watcher-example';
const key = generateDeviceKey();
const publicKeys = [{ keyId: key.keyId, publicKeyDer: key.publicKeyDer }];
const verification = { watcherId, trustedKeyIds: [key.keyId], deviceKeys: publicKeys, now };
const directories: string[] = [];

function signed(at = now.toISOString()): SignedWatcherResume {
  return signWatcherResume({ watcherId, at }, key);
}

async function fixture() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-recovery-'));
  directories.push(cwd);
  const store = createStateStore({ cwd, cipher: createStateCipher(randomBytes(32)) });
  const path = join(store.paths.dir, 'watcher-recovery.json');
  return { store, path };
}

afterEach(async () => {
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
});

describe('watcher resume signatures', () => {
  it('signs the watcher, key and timestamp under the resume domain', () => {
    const message = signed();
    expect(message).toMatchObject({ type: 'keysentry-resume', v: 1, watcherId, keyId: key.keyId, at: now.toISOString() });
    const payload = Buffer.from('keysentry-resume:v1\n' + canonicalJson({ watcherId, keyId: key.keyId, at: now.toISOString() }));
    expect(verifyDetached(key.publicKeyDer, payload, Buffer.from(message.sig, 'base64'))).toBe(true);
    expect(verifyWatcherResume(message, verification)).toEqual({ ok: true, resume: message });
  });

  it.each([
    { watcherId: 'another-watcher' }, { keyId: '0123456789abcdef' },
    { at: '2026-10-27T11:59:59.000Z' }, { type: 'keysentry-disarm' }, { v: 2 },
    { sig: Buffer.alloc(64).toString('base64') }, { extra: true }, { sig: 'not-base64' },
  ])('rejects changed signed fields and malformed envelopes: %j', changes => {
    expect(verifyWatcherResume({ ...signed(), ...changes }, verification).ok).toBe(false);
  });

  it('rejects a valid signature under another domain', () => {
    const message = signed();
    const body = { watcherId, keyId: key.keyId, at: message.at };
    message.sig = signDetached(key.privateKeyDer, Buffer.from('keysentry-disarm:v1\n' + canonicalJson(body))).toString('base64');
    expect(verifyWatcherResume(message, verification).ok).toBe(false);
  });

  it('requires both a trusted key ID and its matching public key', () => {
    expect(verifyWatcherResume(signed(), { ...verification, trustedKeyIds: [] }).ok).toBe(false);
    expect(verifyWatcherResume(signed(), { ...verification, deviceKeys: [] }).ok).toBe(false);
    const other = generateDeviceKey();
    const forged = { ...signed(), keyId: other.keyId };
    forged.sig = signDetached(key.privateKeyDer, Buffer.from('keysentry-resume:v1\n' + canonicalJson({
      watcherId, keyId: other.keyId, at: forged.at,
    }))).toString('base64');
    expect(verifyWatcherResume(forged, {
      ...verification, trustedKeyIds: [other.keyId], deviceKeys: [{ keyId: other.keyId, publicKeyDer: key.publicKeyDer }],
    }).ok).toBe(false);
  });

  it('accepts the 24-hour boundary and rejects older, future or invalid time', () => {
    expect(verifyWatcherResume(signed('2026-10-26T12:00:00.000Z'), verification).ok).toBe(true);
    expect(verifyWatcherResume(signed('2026-10-26T11:59:59.999Z'), verification).ok).toBe(false);
    expect(verifyWatcherResume(signed('2026-10-27T12:00:00.001Z'), verification).ok).toBe(false);
    expect(verifyWatcherResume(signed(), { ...verification, now: new Date(NaN) }).ok).toBe(false);
    expect(verifyWatcherResume({ ...signed(), at: '2026-02-30T12:00:00.000Z' }, verification).ok).toBe(false);
  });

  it('refuses signing invalid metadata or mismatched key material', () => {
    expect(() => signWatcherResume({ watcherId: '', at: now.toISOString() }, key)).toThrow(TypeError);
    expect(() => signWatcherResume({ watcherId, at: 'tomorrow' }, key)).toThrow(TypeError);
    expect(() => signWatcherResume({ watcherId, at: now.toISOString() }, { ...key, keyId: '0123456789abcdef' })).toThrow(TypeError);
    expect(() => signWatcherResume({ watcherId, at: now.toISOString() }, { ...key, privateKeyDer: generateDeviceKey().privateKeyDer })).toThrow(TypeError);
  });
});

describe('Actions recovery latch', () => {
  const options = { watcherId, trustedKeyIds: [key.keyId], deviceKeys: async () => publicKeys, now: () => now };

  it('starts empty state alert-only and saves authorization before enabling work', async () => {
    const snapshots: ActionsRecoveryState[] = [];
    let recovery: ReturnType<typeof createActionsRecovery>;
    recovery = createActionsRecovery({ ...options, saveState: async state => {
      expect(recovery.alertOnly()).toBe(true);
      snapshots.push(structuredClone(state));
    } });
    expect(recovery.alertOnly()).toBe(true);
    expect((await recovery.resume(signed())).ok).toBe(true);
    expect(recovery.alertOnly()).toBe(false);
    expect(snapshots).toHaveLength(1);
    expect(snapshots[0]).toMatchObject({ watcherId, requiresResume: false, usedResumeSignatures: [signed().sig] });
  });

  it('keeps a supplied state object and rejects replay after encrypted persistence and restart', async () => {
    const { store, path } = await fixture();
    const record = createSequencedStateRecord<ActionsRecoveryState>({ store, path, kind: 'monitor' });
    const first = createActionsRecovery({ ...options, saveState: state => record.save(state) });
    expect((await first.resume(signed())).ok).toBe(true);
    const state = (await record.load())!;
    state.requiresResume = true;
    const restarted = createActionsRecovery({ ...options, state, saveState: next => record.save(next) });
    expect((await restarted.resume(signed())).ok).toBe(false);
    expect(restarted.alertOnly()).toBe(true);
    expect(state.requiresResume).toBe(true);
    const fresh = signed('2026-10-27T11:59:59.000Z');
    expect((await restarted.resume(fresh)).ok).toBe(true);
    expect(state.requiresResume).toBe(false);
    expect(state.usedResumeSignatures).toEqual([signed().sig, fresh.sig]);
  });

  it('does not release the latch or consume a signature when saving fails', async () => {
    let fail = true;
    const recovery = createActionsRecovery({ ...options, saveState: async () => { if (fail) throw new Error('private details'); } });
    const result = await recovery.resume(signed());
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result)).not.toContain('private details');
    expect(recovery.alertOnly()).toBe(true);
    expect(recovery.state.usedResumeSignatures).toEqual([]);
    fail = false;
    expect((await recovery.resume(signed())).ok).toBe(true);
  });

  it('serializes concurrent requests so a signature is consumed once', async () => {
    const recovery = createActionsRecovery(options);
    const results = await Promise.all([recovery.resume(signed()), recovery.resume(signed())]);
    expect(results.map(result => result.ok)).toEqual([true, false]);
    expect(recovery.state.usedResumeSignatures).toHaveLength(1);
  });

  it('keeps the latch set for invalid messages and unavailable device keys', async () => {
    const recovery = createActionsRecovery(options);
    expect((await recovery.resume({ ...signed(), watcherId: 'other' })).ok).toBe(false);
    expect(recovery.alertOnly()).toBe(true);
    const unavailable = createActionsRecovery({ ...options, deviceKeys: async () => { throw new Error('private details'); } });
    const result = await unavailable.resume(signed());
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result)).not.toContain('private details');
    expect(unavailable.alertOnly()).toBe(true);
  });

  it('refuses malformed or cross-watcher persisted state rather than trusting its latch', () => {
    const state = createActionsRecovery(options).state;
    expect(() => createActionsRecovery({ ...options, state: { ...state, watcherId: 'other', requiresResume: false } })).toThrow();
    expect(() => createActionsRecovery({ ...options, state: { ...state, requiresResume: undefined } as unknown as ActionsRecoveryState })).toThrow();
    const restored = createActionsRecovery({ ...options, state: { ...state, requiresResume: false } });
    expect(restored.alertOnly()).toBe(false);
  });
});

describe('sequenced encrypted state', () => {
  it('stores the sequence inside encrypted records and continues it after restart', async () => {
    const { store, path } = await fixture();
    const record = createSequencedStateRecord<{ disarmed: boolean }>({ store, path, kind: 'monitor' });
    expect(await record.load()).toBeNull();
    await record.save({ disarmed: false });
    await record.save({ disarmed: true });
    expect(record.highestSequence()).toBe(2);
    expect(await store.readJson('monitor', path)).toEqual({ type: 'keysentry-watcher-state', v: 1, sequence: 2, data: { disarmed: true } });
    const disk = await readFile(path, 'utf8');
    expect(disk).not.toContain('sequence');
    expect(disk).not.toContain('disarmed');
    const restarted = createSequencedStateRecord<{ disarmed: boolean }>({ store, path, kind: 'monitor' });
    await restarted.save({ disarmed: true });
    expect(restarted.highestSequence()).toBe(3);
    expect(await restarted.load()).toEqual({ disarmed: true });
  });

  it('refuses a lower restored encrypted sequence on both read and write', async () => {
    const { store, path } = await fixture();
    const record = createSequencedStateRecord<{ disarmed: boolean }>({ store, path, kind: 'monitor' });
    await record.save({ disarmed: false });
    const old = await readFile(path);
    await record.save({ disarmed: true });
    await writeFile(path, old);
    await expect(record.load()).rejects.toThrow(/sequence/i);
    await expect(record.save({ disarmed: false })).rejects.toThrow(/sequence/i);
    expect(await readFile(path)).toEqual(old);
  });

  it('refuses disappearing state after a successful read or an external high-water mark', async () => {
    const { store, path } = await fixture();
    const record = createSequencedStateRecord<boolean>({ store, path, kind: 'monitor' });
    await record.save(true);
    await rm(path);
    await expect(record.load()).rejects.toThrow(/missing/i);
    await expect(record.save(false)).rejects.toThrow(/missing/i);
    const anchored = createSequencedStateRecord({ store, path, kind: 'monitor', initialHighestSequence: 7 });
    await expect(anchored.load()).rejects.toThrow(/missing/i);
  });

  it.each([0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, '2', undefined])('rejects an invalid restored sequence: %s', async sequence => {
    const { store, path } = await fixture();
    await store.writeJson('monitor', path, { type: 'keysentry-watcher-state', v: 1, sequence, data: true });
    const record = createSequencedStateRecord<boolean>({ store, path, kind: 'monitor' });
    await expect(record.load()).rejects.toThrow(/format/i);
    await expect(record.save(false)).rejects.toThrow(/format/i);
  });

  it('rejects exhausted sequences and malformed record envelopes', async () => {
    const { store, path } = await fixture();
    const record = createSequencedStateRecord({ store, path, kind: 'monitor' });
    await store.writeJson('monitor', path, { type: 'keysentry-watcher-state', v: 1, sequence: Number.MAX_SAFE_INTEGER, data: true });
    await expect(record.save(false)).rejects.toThrow(/sequence/i);
    await store.writeJson('monitor', path, { type: 'keysentry-watcher-state', v: 2, sequence: 1, data: true });
    await expect(record.load()).rejects.toThrow(/format/i);
    expect(() => createSequencedStateRecord({ store, path, kind: 'monitor', initialHighestSequence: -1 })).toThrow();
  });

  it('serializes saves so every successful write has a distinct increasing sequence', async () => {
    const { store, path } = await fixture();
    const record = createSequencedStateRecord<number>({ store, path, kind: 'monitor' });
    await Promise.all([record.save(1), record.save(2), record.save(3)]);
    expect(record.highestSequence()).toBe(3);
    expect(await record.load()).toBe(3);
  });

  it.each([undefined, Symbol('unsupported'), () => undefined, { toJSON: () => undefined }])('refuses payloads JSON would omit before replacing a valid record: %s', async data => {
    const { store, path } = await fixture();
    const record = createSequencedStateRecord<unknown>({ store, path, kind: 'monitor' });
    await record.save({ disarmed: true });
    const original = await readFile(path);
    await expect(record.save(data)).rejects.toThrow(/payload/i);
    expect(await readFile(path)).toEqual(original);
    expect(await record.load()).toEqual({ disarmed: true });
    expect(record.highestSequence()).toBe(1);
  });

  it('recovers the persisted sequence when a writer throws after its effect', async () => {
    const { store, path } = await fixture();
    let fail = true;
    const record = createSequencedStateRecord<boolean>({ path, kind: 'monitor', store: {
      readJson: store.readJson,
      writeJson: async (kind, destination, data) => {
        await store.writeJson(kind, destination, data);
        if (fail) throw new Error('save acknowledgment failed');
      },
    } });
    await expect(record.save(true)).rejects.toThrow();
    fail = false;
    await record.save(false);
    expect(record.highestSequence()).toBe(2);
    expect(await record.load()).toBe(false);
  });

  it('does not overwrite state when authenticated decryption fails', async () => {
    const { store, path } = await fixture();
    const record = createSequencedStateRecord<boolean>({ store, path, kind: 'monitor' });
    await record.save(true);
    const original = await readFile(path, 'utf8');
    const lines = original.split('\n');
    const bytes = Buffer.from(lines[1]!, 'base64');
    bytes[bytes.length - 1]! ^= 1;
    lines[1] = bytes.toString('base64');
    const changed = lines.join('\n');
    await writeFile(path, changed);
    await expect(record.load()).rejects.toThrow();
    await expect(record.save(false)).rejects.toThrow();
    expect(await readFile(path, 'utf8')).toBe(changed);
  });
});
