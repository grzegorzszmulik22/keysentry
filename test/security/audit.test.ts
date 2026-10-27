import { createHash, createHmac } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, stat, unlink, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { createRedactor } from '../../src/core/redact.js';
import { createAuditLog } from '../../src/security/audit.js';
import { AUDIT_CHECKPOINT_PREFIX, canonicalJson, generateDeviceKey, verifyDetached } from '../../src/security/index.js';
import { createFakeVault } from '../helpers/fake-vault.js';

interface Line {
  seq: number;
  at: string;
  kind: string;
  summary: string;
  data?: Record<string, unknown>;
  prev: string;
  hash: string;
  mac?: string;
}

let dir: string;
let path: string;
let vault: ReturnType<typeof createFakeVault>;
let key: ReturnType<typeof generateDeviceKey>;
const at = '2026-10-27T12:00:00.000Z';

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'keysentry-audit-'));
  path = join(dir, 'private', 'audit.jsonl');
  vault = createFakeVault();
  key = generateDeviceKey();
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

function log(options: Partial<Parameters<typeof createAuditLog>[0]> = {}) {
  return createAuditLog({ path, vault, deviceKey: async () => key, now: () => new Date(at), ...options });
}

async function lines(): Promise<Line[]> {
  return (await readFile(path, 'utf8')).trimEnd().split('\n').map((line) => JSON.parse(line) as Line);
}

async function save(entries: Line[]): Promise<void> {
  await writeFile(path, entries.map((line) => JSON.stringify(line)).join('\n') + (entries.length ? '\n' : ''));
}

function hash(line: Omit<Line, 'hash'> | Line): string {
  const { seq, at: time, kind, summary, data, prev } = line;
  return createHash('sha256').update(canonicalJson({ seq, at: time, kind, summary, data, prev })).digest('hex');
}

function headName(): string {
  return 'audit/head/' + createHash('sha256').update(resolve(path)).digest('hex').slice(0, 16);
}

test('audit verify passes on an untouched log of 3 entries', async () => {
  const audit = log();
  for (let n = 0; n < 3; n++) await audit.append({ kind: 'scan', summary: `Scan ${n}` });
  expect(await audit.verify()).toEqual({ ok: true, entries: 3, checkpoints: 0 });
  const entries = await lines();
  expect(entries.map((entry) => entry.seq)).toEqual([1, 2, 3]);
  expect(entries[0]).toEqual({ seq: 1, at, kind: 'scan', summary: 'Scan 0', prev: '0'.repeat(64), hash: hash(entries[0]!), mac: expect.stringMatching(/^[a-f0-9]{64}$/) });
  expect(entries[1]!.prev).toBe(entries[0]!.hash);
});

test('audit verify reports the first edited entry', async () => {
  const audit = log();
  for (let n = 0; n < 3; n++) await audit.append({ kind: 'scan', summary: 'Scan complete' });
  const entries = await lines();
  entries[1]!.summary = 'Changed';
  await save(entries);
  expect(await audit.verify()).toMatchObject({ ok: false, entries: 3, firstBadSeq: 2, problem: expect.stringMatching(/hash mismatch/i) });
});

test('audit verify detects a deleted line', async () => {
  const audit = log();
  for (let n = 0; n < 3; n++) await audit.append({ kind: 'scan', summary: 'Scan complete' });
  const entries = await lines();
  entries.splice(1, 1);
  await save(entries);
  expect(await audit.verify()).toMatchObject({ ok: false, firstBadSeq: 2, problem: expect.stringMatching(/gap/i) });
});

test('audit verify detects a previous hash mismatch', async () => {
  const audit = log();
  await audit.append({ kind: 'scan', summary: 'First scan' });
  await audit.append({ kind: 'scan', summary: 'Second scan' });
  const entries = await lines();
  entries[1]!.prev = 'f'.repeat(64);
  entries[1]!.hash = hash(entries[1]!);
  await save(entries);
  expect(await audit.verify()).toMatchObject({ ok: false, firstBadSeq: 2, problem: expect.stringMatching(/prev mismatch/i) });
});

test('audit verify reports unreadable JSON without including line content', async () => {
  const audit = log();
  await audit.append({ kind: 'scan', summary: 'Scan complete' });
  const marker = 'private-value-that-must-not-appear';
  await writeFile(path, (await readFile(path, 'utf8')) + marker + '\n');
  const result = await audit.verify();
  expect(result).toMatchObject({ ok: false, entries: 2, firstBadSeq: 2, problem: expect.stringMatching(/unreadable line 2/i) });
  expect(JSON.stringify(result)).not.toContain(marker);
});

test('audit verify reports a malformed stored hash as a hash mismatch', async () => {
  const audit = log();
  await audit.append({ kind: 'scan', summary: 'Scan complete' });
  const entries = await lines();
  entries[0]!.hash = 'invalid-hash';
  await save(entries);
  expect(await audit.verify()).toMatchObject({ ok: false, firstBadSeq: 1, problem: expect.stringMatching(/hash mismatch/i) });
});

test('audit verify rejects extra fields that the fixed hash format does not cover', async () => {
  const audit = log();
  await audit.append({ kind: 'scan', summary: 'Scan complete' });
  const entries = await lines();
  await writeFile(path, JSON.stringify({ ...entries[0], added: 'Unhashed edit' }) + '\n');
  expect(await audit.verify()).toMatchObject({ ok: false, firstBadSeq: 1, problem: expect.stringMatching(/unreadable line 1/i) });
});

test.each(['null', '[]', '{}'])('audit verify rejects an invalid line shape: %s', async (bad) => {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, bad + '\n');
  expect(await log().verify()).toMatchObject({ ok: false, entries: 1, firstBadSeq: 1 });
});

test('checkpoint signs the previous hash with the fixed prefix and stores the checkpoint head', async () => {
  const audit = log();
  await audit.append({ kind: 'scan', summary: 'Scan complete' });
  await audit.checkpoint();
  const entries = await lines();
  const checkpoint = entries[1]!;
  expect(checkpoint).toMatchObject({ seq: 2, kind: 'checkpoint', prev: entries[0]!.hash, data: { head: entries[0]!.hash, keyId: key.keyId } });
  expect(AUDIT_CHECKPOINT_PREFIX).toBe('keysentry-audit-checkpoint:v1:');
  expect(verifyDetached(key.publicKeyDer, Buffer.from(`keysentry-audit-checkpoint:v1:2:${entries[0]!.hash}`), Buffer.from(checkpoint.data!.sig as string, 'base64'))).toBe(true);
  expect(JSON.parse((await vault.get(headName()))!.toString('utf8'))).toEqual({ seq: 2, hash: checkpoint.hash });
  expect(await audit.verify()).toEqual({ ok: true, entries: 2, checkpoints: 1 });
});

test('audit verify rejects a forged checkpoint signature even with a correct line hash', async () => {
  const audit = log();
  await audit.append({ kind: 'scan', summary: 'Scan complete' });
  await audit.checkpoint();
  const entries = await lines();
  entries[1]!.data!.sig = Buffer.alloc(64).toString('base64');
  entries[1]!.hash = hash(entries[1]!);
  // A valid MAC isolates the signature check; forged entries without it now fail authentication first.
  const macKey = (await vault.get('audit/mac'))!;
  try { entries[1]!.mac = createHmac('sha256', macKey).update(entries[1]!.hash).digest('hex'); }
  finally { macKey.fill(0); }
  await save(entries);
  await vault.delete(headName());
  expect(await audit.verify()).toMatchObject({ ok: false, firstBadSeq: 2, problem: expect.stringMatching(/signature/i) });
});

test('audit verify rejects a checkpoint on a different device key', async () => {
  const audit = log();
  await audit.append({ kind: 'scan', summary: 'Scan complete' });
  await audit.checkpoint();
  const otherKey = generateDeviceKey();
  expect(await log({ deviceKey: async () => otherKey }).verify()).toMatchObject({ ok: false, firstBadSeq: 2, problem: expect.stringMatching(/different device key/i) });
});

test('audit verify detects truncation behind the vault head', async () => {
  const audit = log();
  await audit.append({ kind: 'scan', summary: 'Scan complete' });
  await audit.checkpoint();
  await save((await lines()).slice(0, 1));
  expect(await audit.verify()).toMatchObject({ ok: false, entries: 1, truncatedSinceLastKnownHead: true, problem: expect.stringMatching(/shorter|truncat/i) });
});

test('audit verify detects a different hash at the vault head sequence', async () => {
  const audit = log();
  await audit.append({ kind: 'scan', summary: 'Scan complete' });
  await audit.checkpoint();
  const entries = await lines();
  entries[1]!.summary = 'Changed checkpoint';
  entries[1]!.hash = hash(entries[1]!);
  await save(entries);
  expect(await audit.verify()).toMatchObject({ ok: false, truncatedSinceLastKnownHead: true, problem: expect.any(String) });
});

test.each(['missing', 'empty'])('a %s log without a vault head verifies as empty', async (state) => {
  if (state === 'empty') { await mkdir(dirname(path), { recursive: true }); await writeFile(path, ''); }
  expect(await log().verify()).toEqual({ ok: true, entries: 0, checkpoints: 0 });
});

test.each(['missing', 'empty'])('a %s log with a vault head reports truncation', async (state) => {
  const audit = log();
  await audit.append({ kind: 'scan', summary: 'Scan complete' });
  await audit.checkpoint();
  if (state === 'missing') await unlink(path); else await writeFile(path, '');
  expect(await audit.verify()).toMatchObject({ ok: false, entries: 0, checkpoints: 0, truncatedSinceLastKnownHead: true });
});

test('20 concurrent appends from multiple instances produce a valid chain', async () => {
  const instances = [log(), log(), log({ path: join(dirname(path), '.', 'audit.jsonl') })];
  await Promise.all(Array.from({ length: 20 }, (_, n) => instances[n % 3]!.append({ kind: 'scan', summary: `Scan ${n}` })));
  expect(await log().verify()).toEqual({ ok: true, entries: 20, checkpoints: 0 });
});

test('audit append redacts registered secrets deeply before hashing without mutating the event', async () => {
  const redactor = createRedactor();
  const secret = 'registered-private-value';
  redactor.register(secret);
  const data = { nested: [secret, { value: `Value: ${secret}` }], count: 3, absent: null };
  const audit = log({ redactor });
  await audit.append({ kind: 'scan', summary: `Scan ${secret}`, data });
  const raw = await readFile(path, 'utf8');
  expect(raw).not.toContain(secret);
  expect((await lines())[0]).toMatchObject({ summary: redactor.redact(`Scan ${secret}`), data: { nested: [redactor.redact(secret), { value: redactor.redact(`Value: ${secret}`) }], count: 3, absent: null } });
  expect(data.nested[0]).toBe(secret);
  expect(await audit.verify()).toEqual({ ok: true, entries: 1, checkpoints: 0 });
});

test('automatic checkpoints after every 3 events verify and survive reopening', async () => {
  for (let n = 0; n < 6; n++) await log({ checkpointEvery: 3 }).append({ kind: 'scan', summary: `Scan ${n}` });
  expect((await lines()).map((line) => line.kind)).toEqual(['scan', 'scan', 'scan', 'checkpoint', 'scan', 'scan', 'scan', 'checkpoint']);
  expect(await log().verify()).toEqual({ ok: true, entries: 8, checkpoints: 2 });
});

test('the default interval checkpoints after 50 ordinary entries', async () => {
  const audit = log();
  for (let n = 0; n < 49; n++) await audit.append({ kind: 'scan', summary: `Scan ${n}` });
  expect(await audit.verify()).toEqual({ ok: true, entries: 49, checkpoints: 0 });
  await audit.append({ kind: 'scan', summary: 'Scan 50' });
  expect(await audit.verify()).toEqual({ ok: true, entries: 51, checkpoints: 1 });
});

test('checkpoint is a no-op without a new event, including after reopening', async () => {
  await log().checkpoint();
  expect(await log().verify()).toEqual({ ok: true, entries: 0, checkpoints: 0 });
  const audit = log({ checkpointEvery: 3 });
  await audit.append({ kind: 'scan', summary: 'Scan complete' });
  await audit.checkpoint();
  await log().checkpoint();
  expect(await log().verify()).toEqual({ ok: true, entries: 2, checkpoints: 1 });
});

test('a manual checkpoint resets the automatic checkpoint interval', async () => {
  const audit = log({ checkpointEvery: 3 });
  await audit.append({ kind: 'scan', summary: 'First scan' });
  await audit.checkpoint();
  await audit.append({ kind: 'scan', summary: 'Second scan' });
  await audit.append({ kind: 'scan', summary: 'Third scan' });
  expect(await audit.verify()).toEqual({ ok: true, entries: 4, checkpoints: 1 });
  await audit.append({ kind: 'scan', summary: 'Fourth scan' });
  expect(await audit.verify()).toEqual({ ok: true, entries: 6, checkpoints: 2 });
});

test('a lock older than 30 seconds is taken over and removed on release', async () => {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path + '.lock', '');
  const old = new Date(Date.now() - 31_000);
  await utimes(path + '.lock', old, old);
  const audit = log();
  await audit.append({ kind: 'scan', summary: 'Scan complete' });
  expect(await audit.verify()).toEqual({ ok: true, entries: 1, checkpoints: 0 });
  await expect(stat(path + '.lock')).rejects.toMatchObject({ code: 'ENOENT' });
});

test('an active external lock holds appends until it is released', async () => {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path + '.lock', '');
  let finished = false;
  const pending = log().append({ kind: 'scan', summary: 'Scan complete' }).then(() => { finished = true; });
  try {
    await new Promise((done) => setTimeout(done, 80));
    expect(finished).toBe(false);
    await expect(stat(path)).rejects.toMatchObject({ code: 'ENOENT' });
  } finally {
    await unlink(path + '.lock');
    await pending;
  }
  expect(await log().verify()).toEqual({ ok: true, entries: 1, checkpoints: 0 });
});

test('an operation that loses its lock refuses to checkpoint and preserves the replacement lock', async () => {
  await log().append({ kind: 'scan', summary: 'Scan complete' });
  let entered!: () => void;
  let resume!: () => void;
  const waiting = new Promise<void>((done) => { entered = done; });
  const gate = new Promise<void>((done) => { resume = done; });
  const audit = log({ deviceKey: async () => { entered(); await gate; return key; } });
  const checkpoint = audit.checkpoint();
  await waiting;
  try {
    await unlink(path + '.lock');
    await writeFile(path + '.lock', 'replacement owner');
  } finally {
    resume();
  }
  await expect(checkpoint).rejects.toThrow(/lock.*changed|lock.*held|lock.*lost/i);
  expect(await readFile(path + '.lock', 'utf8')).toBe('replacement owner');
  expect(await lines()).toHaveLength(1);
  expect(await vault.get(headName())).toBeNull();
});

test('a live operation renews its lock lease while waiting for the device key', async () => {
  await log().append({ kind: 'scan', summary: 'Scan complete' });
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
  let entered!: () => void;
  let resume!: () => void;
  const waiting = new Promise<void>((done) => { entered = done; });
  const gate = new Promise<void>((done) => { resume = done; });
  const audit = log({ deviceKey: async () => { entered(); await gate; return key; } });
  const checkpoint = audit.checkpoint();
  try {
    await waiting;
    const old = new Date(Date.now() - 20_000);
    await utimes(path + '.lock', old, old);
    await vi.advanceTimersByTimeAsync(5_000);
    await vi.waitFor(async () => { expect((await stat(path + '.lock')).mtimeMs).toBeGreaterThan(old.getTime() + 10_000); });
  } finally {
    resume();
    await checkpoint;
    vi.useRealTimers();
  }
  expect(await log().verify()).toEqual({ ok: true, entries: 2, checkpoints: 1 });
});

test('tail reading supports long UTF-8 lines and an existing final line without a newline', async () => {
  const audit = log();
  await audit.append({ kind: 'scan', summary: 'Scan ' + '漢字'.repeat(30_000) });
  await writeFile(path, (await readFile(path, 'utf8')).trimEnd());
  await audit.append({ kind: 'scan', summary: 'Next scan' });
  await audit.checkpoint();
  expect(await audit.verify()).toEqual({ ok: true, entries: 3, checkpoints: 1 });
});

test('invalid event data is rejected before a valid event can be appended', async () => {
  const audit = log();
  await expect(audit.append({ kind: 'scan', summary: 'Invalid', data: { privateField: Number.NaN } })).rejects.toThrow();
  await audit.append({ kind: 'scan', summary: 'Valid' });
  expect(await audit.verify()).toEqual({ ok: true, entries: 1, checkpoints: 0 });
});

test('a busy lock times out and the queued next append can still succeed', async () => {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path + '.lock', '');
  const audit = log();
  await expect(audit.append({ kind: 'scan', summary: 'Blocked' })).rejects.toThrow(/busy/i);
  await unlink(path + '.lock');
  await audit.append({ kind: 'scan', summary: 'Scan complete' });
  expect(await audit.verify()).toEqual({ ok: true, entries: 1, checkpoints: 0 });
}, 15_000);

test('serialization failures do not include secret property names in errors', async () => {
  const marker = 'private-property-name';
  const error = await log().append({ kind: 'scan', summary: 'Invalid', data: { [marker]: Number.NaN } }).catch((error: Error) => error);
  expect(error).toBeInstanceOf(Error);
  expect(String(error)).not.toContain(marker);
});

test('a rejected checkpoint cannot be supplied through append', async () => {
  await expect(log().append({ kind: 'checkpoint', summary: 'Unsigned' })).rejects.toThrow(/checkpoint/i);
});

test('a truncated log cannot replace the stored vault head through a new checkpoint', async () => {
  const audit = log();
  await audit.append({ kind: 'scan', summary: 'Scan complete' });
  await audit.checkpoint();
  const savedHead = await vault.get(headName());
  await save((await lines()).slice(0, 1));
  await expect(audit.checkpoint()).rejects.toThrow(/shorter|truncat|vault head/i);
  expect(await vault.get(headName())).toEqual(savedHead);
});

test.each(['append', 'checkpoint'])('a longer rewritten chain cannot reset the vault head through %s', async (operation) => {
  const audit = log({ checkpointEvery: 3 });
  await audit.append({ kind: 'scan', summary: 'Original scan' });
  await audit.checkpoint();
  const savedHead = await vault.get(headName());
  const replacement: Line[] = [];
  for (let n = 0; n < 3; n++) {
    const content = { seq: n + 1, at, kind: 'scan', summary: 'Rewritten scan', prev: replacement.at(-1)?.hash ?? '0'.repeat(64) };
    replacement.push({ ...content, hash: hash(content) });
  }
  await save(replacement);
  const attempt = operation === 'append' ? audit.append({ kind: 'scan', summary: 'Next scan' }) : audit.checkpoint();
  // MACs now reject a fabricated replacement before tail traversal reaches the older vault head.
  await expect(attempt).rejects.toThrow(/vault head|truncat|not written by keysentry/i);
  expect(await vault.get(headName())).toEqual(savedHead);
  expect(await audit.verify()).toMatchObject({ ok: false, truncatedSinceLastKnownHead: true });
});

test('concurrent appends and explicit checkpoints share one valid chain', async () => {
  const audit = log();
  const work = Array.from({ length: 10 }, (_, n) => n % 2 === 0 ? audit.append({ kind: 'scan', summary: `Scan ${n}` }) : log().checkpoint());
  await Promise.all(work);
  expect(await audit.verify()).toEqual({ ok: true, entries: 10, checkpoints: 5 });
});

test.each([0, -1, 1.5, Number.NaN])('checkpointEvery rejects an invalid interval %s', (checkpointEvery) => {
  expect(() => log({ checkpointEvery })).toThrow(TypeError);
});

test.skipIf(process.platform === 'win32')('new audit directories and files have private permissions', async () => {
  await log().append({ kind: 'scan', summary: 'Scan complete' });
  expect((await stat(dirname(path))).mode & 0o777).toBe(0o700);
  expect((await stat(path)).mode & 0o777).toBe(0o600);
});

test('every event and checkpoint has an HMAC from a stable 32-byte vault key', async () => {
  await log().append({ kind: 'scan', summary: 'Scan complete' });
  const firstKey = (await vault.get('audit/mac'))!;
  try {
    expect(firstKey).toHaveLength(32);
    await log().checkpoint();
    expect(await vault.get('audit/mac')).toEqual(firstKey);
    for (const line of await lines()) {
      expect(line.mac).toBe(createHmac('sha256', firstKey).update(line.hash).digest('hex'));
    }
  } finally { firstKey.fill(0); }
});

test.each(['missing', 'wrong'])('audit verification identifies a %s entry MAC without echoing content', async mode => {
  const audit = log();
  await audit.append({ kind: 'scan', summary: 'First scan' });
  await audit.checkpoint();
  const entries = await lines();
  const prior = entries.at(-1)!;
  const forged = { seq: prior.seq + 1, at, kind: 'state-reset', summary: 'Reset that did not happen', prev: prior.hash };
  entries.push({ ...forged, hash: hash(forged), ...(mode === 'wrong' ? { mac: '0'.repeat(64) } : {}) });
  await save(entries);
  expect(await audit.verify()).toMatchObject({ ok: false, firstBadSeq: 3, problem: 'entry 3 was not written by keysentry on this computer' });
  await expect(audit.append({ kind: 'scan', summary: 'Next scan' })).rejects.toThrow(/not written by keysentry/i);
});

test('verification never creates a missing audit MAC key', async () => {
  const audit = log();
  await audit.append({ kind: 'scan', summary: 'Scan complete' });
  await vault.delete('audit/mac');
  expect(await audit.verify()).toMatchObject({ ok: false, firstBadSeq: 1, problem: 'entry 1 was not written by keysentry on this computer' });
  expect(await vault.get('audit/mac')).toBeNull();
});

test('concurrent projects share one MAC key even through separate vault wrappers', async () => {
  const first = log({ vault: { ...vault } });
  const second = log({ path: join(dir, 'another-project', 'audit.jsonl'), vault: { ...vault } });
  await Promise.all([
    first.append({ kind: 'scan', summary: 'First project' }),
    second.append({ kind: 'scan', summary: 'Second project' }),
  ]);
  expect((await first.verify()).ok).toBe(true);
  expect((await second.verify()).ok).toBe(true);
});

test('MAC key initialization waits for the shared per-user filesystem lock', async () => {
  const keyLockPath = join(dir, 'user', 'audit-mac');
  await mkdir(dirname(keyLockPath), { recursive: true });
  await writeFile(`${keyLockPath}.lock`, '');
  let finished = false;
  const pending = log({ keyLockPath }).append({ kind: 'scan', summary: 'Scan complete' }).then(() => { finished = true; });
  try {
    await new Promise(done => setTimeout(done, 80));
    expect(finished).toBe(false);
    expect(await vault.get('audit/mac')).toBeNull();
  } finally {
    await unlink(`${keyLockPath}.lock`);
    await pending;
  }
  expect((await log({ keyLockPath }).verify()).ok).toBe(true);
  await expect(stat(`${keyLockPath}.lock`)).rejects.toMatchObject({ code: 'ENOENT' });
});
