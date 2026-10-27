import { createHash, generateKeyPairSync, verify } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, test } from 'vitest';
import { appendAllowList } from '../../../scripts/allowlist-append.mjs';
import { canonicalJson } from '../../../src/security/index.js';

const directories: string[] = [];
const digest = `sha256:${'a'.repeat(64)}`;
const secondDigest = `sha256:${'b'.repeat(64)}`;
const at = '2026-10-27T12:00:00.000Z';

async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), 'keysentry-allowlist-'));
  directories.push(dir);
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateDer = privateKey.export({ format: 'der', type: 'pkcs8' });
  const publicDer = publicKey.export({ format: 'der', type: 'spki' });
  return {
    dir, publicKey, publicDer,
    env: { KEYSENTRY_RELEASE_SIGNING_KEY: privateDer.toString('base64') },
    options: {
      logPath: join(dir, 'log.jsonl'), headPath: join(dir, 'head.json'),
      digest, reference: 'ghcr.io/keysentry/box:v1', reason: 'release', at,
    },
  };
}

afterEach(async () => {
  await Promise.all(directories.splice(0).map(dir => rm(dir, { recursive: true, force: true })));
});

test('append writes an independently verifiable entry and signed head using the release domains', async () => {
  const { options, env, publicKey, publicDer } = await fixture();
  await appendAllowList(options, env);
  const log = await readFile(options.logPath, 'utf8');
  const entry = JSON.parse(log);
  const head = JSON.parse(await readFile(options.headPath, 'utf8'));
  expect(entry).toMatchObject({ seq: 1, digest, addedAt: at, prev: '0'.repeat(64), reason: 'release' });
  expect(Object.keys(entry).sort()).toEqual(['addedAt', 'digest', 'hash', 'prev', 'reason', 'reference', 'seq', 'sig']);
  const payload = { seq: 1, digest, reference: options.reference, addedAt: at, reason: 'release', prev: '0'.repeat(64) };
  const hash = createHash('sha256').update(canonicalJson(payload)).digest('hex');
  expect(entry.hash).toBe(hash);
  expect(verify(null, Buffer.from(`keysentry-allowlist:v1\n${hash}`), publicKey, Buffer.from(entry.sig, 'base64'))).toBe(true);
  expect(verify(null, Buffer.from(hash), publicKey, Buffer.from(entry.sig, 'base64'))).toBe(false);
  expect(head).toMatchObject({ seq: 1, hash, at, keyId: createHash('sha256').update(publicDer).digest('hex').slice(0, 16) });
  expect(Object.keys(head).sort()).toEqual(['at', 'hash', 'keyId', 'seq', 'sig']);
  expect(verify(null, Buffer.from(`keysentry-allowlist-head:v1\n${canonicalJson({ seq: 1, hash, at })}`), publicKey,
    Buffer.from(head.sig, 'base64'))).toBe(true);
  expect(log.endsWith('\n')).toBe(true);
});

test('a second append preserves every existing byte and links to the last hash', async () => {
  const { options, env } = await fixture();
  await appendAllowList(options, env);
  const before = await readFile(options.logPath, 'utf8');
  await appendAllowList({ ...options, digest: secondDigest, reason: 'revoked', at: new Date('2026-10-27T13:00:00.000Z') }, env);
  const after = await readFile(options.logPath, 'utf8');
  const entries = after.trimEnd().split('\n').map(line => JSON.parse(line));
  expect(after.startsWith(before)).toBe(true);
  expect(entries[1]).toMatchObject({ seq: 2, digest: secondDigest, reason: 'revoked', prev: entries[0].hash });
  expect(JSON.parse(await readFile(options.headPath, 'utf8'))).toMatchObject({ seq: 2, hash: entries[1].hash });
});

test.each(['sha256:abc', `sha256:${'z'.repeat(64)}`, `sha512:${'a'.repeat(64)}`, `sha256:${'a'.repeat(65)}`])(
  'malformed digest is rejected before creating output (%#)', async invalidDigest => {
    const { options, env } = await fixture();
    await expect(appendAllowList({ ...options, digest: invalidDigest }, env)).rejects.toThrow(/digest/i);
    await expect(readFile(options.logPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(options.headPath)).rejects.toMatchObject({ code: 'ENOENT' });
  },
);

test('missing release signing key leaves both files absent', async () => {
  const { options } = await fixture();
  await expect(appendAllowList(options, {})).rejects.toThrow(/KEYSENTRY_RELEASE_SIGNING_KEY/);
  await expect(readFile(options.logPath)).rejects.toMatchObject({ code: 'ENOENT' });
});

test.each(['private-material-is-not-base64', Buffer.from('private-material').toString('base64')])(
  'malformed key errors contain no key material (%#)', async material => {
    const { options } = await fixture();
    const error = await appendAllowList(options, { KEYSENTRY_RELEASE_SIGNING_KEY: material }).catch((error: Error) => error);
    expect(error).toBeInstanceOf(Error);
    expect(error.message).toMatch(/Ed25519/);
    expect(error.message).not.toContain(material);
    expect(error.message).not.toContain('private-material');
  },
);

test('a non-Ed25519 signing key is refused', async () => {
  const { options } = await fixture();
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const material = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
  await expect(appendAllowList(options, { KEYSENTRY_RELEASE_SIGNING_KEY: material })).rejects.toThrow(/Ed25519/);
});

test.each(['entry-edit', 'head-edit', 'tail-deletion', 'head-deletion', 'unknown-key']) (
  'refuses to extend an unverified existing history (%s)', async change => {
    const { options, env } = await fixture();
    await appendAllowList(options, env);
    await appendAllowList({ ...options, digest: secondDigest }, env);
    if (change === 'entry-edit') {
      const log = await readFile(options.logPath, 'utf8');
      await writeFile(options.logPath, log.replace('release', 'changed'));
    } else if (change === 'head-edit') {
      const head = JSON.parse(await readFile(options.headPath, 'utf8'));
      await writeFile(options.headPath, JSON.stringify({ ...head, hash: '0'.repeat(64) }));
    } else if (change === 'tail-deletion') {
      const log = await readFile(options.logPath, 'utf8');
      await writeFile(options.logPath, `${log.split('\n')[0]}\n`);
    } else if (change === 'head-deletion') {
      await rm(options.headPath);
    }
    const before = await readFile(options.logPath, 'utf8');
    const replacement = change === 'unknown-key' ? (await fixture()).env : env;
    await expect(appendAllowList({ ...options, reason: 'revoked' }, replacement)).rejects.toThrow(/allow-list|history|head/i);
    expect(await readFile(options.logPath, 'utf8')).toBe(before);
  },
);

test('an append cannot backdate an event before the existing signed head', async () => {
  const { options, env } = await fixture();
  await appendAllowList(options, env);
  const before = await readFile(options.logPath, 'utf8');
  await expect(appendAllowList({ ...options, at: '2026-10-27T11:00:00.000Z' }, env)).rejects.toThrow(/time|date/i);
  expect(await readFile(options.logPath, 'utf8')).toBe(before);
});

test('an existing writer lock prevents another append without changing the log', async () => {
  const { options, env } = await fixture();
  await appendAllowList(options, env);
  const before = await readFile(options.logPath, 'utf8');
  await writeFile(`${options.logPath}.lock`, 'another writer\n');
  await expect(appendAllowList(options, env)).rejects.toThrow(/writer|progress|lock/i);
  expect(await readFile(options.logPath, 'utf8')).toBe(before);
  expect(await readFile(`${options.logPath}.lock`, 'utf8')).toBe('another writer\n');
});

test.each(['', 'not-a-date', '2026-02-30T12:00:00.000Z'])('invalid event time creates no entry (%#)', async invalidAt => {
  const { options, env } = await fixture();
  await expect(appendAllowList({ ...options, at: invalidAt }, env)).rejects.toThrow(/time|date/i);
  await expect(readFile(options.logPath)).rejects.toMatchObject({ code: 'ENOENT' });
});

test('log and head must be different files', async () => {
  const { options, env } = await fixture();
  await expect(appendAllowList({ ...options, headPath: options.logPath }, env)).rejects.toThrow(/different/i);
  await expect(readFile(options.logPath)).rejects.toMatchObject({ code: 'ENOENT' });
});

test.skipIf(process.platform !== 'win32')('Windows path case aliases cannot overwrite a new log with its head', async () => {
  const { options, env, dir } = await fixture();
  await expect(appendAllowList({ ...options, headPath: join(dir, 'LOG.JSONL') }, env)).rejects.toThrow(/different/i);
  await expect(readFile(options.logPath)).rejects.toMatchObject({ code: 'ENOENT' });
});
