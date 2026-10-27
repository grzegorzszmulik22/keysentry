import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, beforeEach, expect, test } from 'vitest';
import { checkLocalIntegrity, computeSha256File } from '../../src/release/integrity.js';

let dir: string;
let originalEntry: string | undefined;
const originalArgv = [...process.argv];
const sha = (value: string) => createHash('sha256').update(value).digest('hex');

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'keysentry-integrity-'));
  originalEntry = process.argv[1];
});
afterEach(async () => {
  process.argv.splice(0, process.argv.length, ...originalArgv);
  await rm(dir, { recursive: true, force: true });
});

async function fixture(value = 'readable bundle\n', expected = sha(value)): Promise<string> {
  const path = join(dir, 'keysentry.mjs');
  await writeFile(path, value);
  await writeFile(join(dir, 'release-manifest.json'), JSON.stringify({
    name: 'keysentry', version: '1.0.0', commit: 'test', node: 'v22.23.4',
    files: { 'keysentry.mjs': expected },
  }));
  return path;
}

test('computeSha256File hashes the bytes on disk', async () => {
  const path = join(dir, 'bytes');
  await writeFile(path, 'abc');
  expect(await computeSha256File(path)).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('checkLocalIntegrity returns ok for the manifest beside the bundle', async () => {
  const bundlePath = await fixture();
  expect(await checkLocalIntegrity({ bundlePath })).toEqual({
    status: 'ok', expected: sha('readable bundle\n'), actual: sha('readable bundle\n'),
  });
});

test('checkLocalIntegrity reports mismatch after a bundle edit and leaves files untouched', async () => {
  const bundlePath = await fixture();
  await writeFile(bundlePath, 'changed');
  expect(await checkLocalIntegrity({ bundlePath })).toEqual({
    status: 'mismatch', expected: sha('readable bundle\n'), actual: sha('changed'),
  });
  expect(await readFile(bundlePath, 'utf8')).toBe('changed');
});

test('checkLocalIntegrity reports a missing-manifest', async () => {
  const bundlePath = join(dir, 'keysentry.mjs');
  await writeFile(bundlePath, 'bundle');
  expect(await checkLocalIntegrity({ bundlePath })).toMatchObject({ status: 'missing-manifest' });
});

test('checkLocalIntegrity uses the resolved running keysentry.mjs by default', async () => {
  process.argv[1] = await fixture();
  expect(await checkLocalIntegrity()).toMatchObject({ status: 'ok' });
  process.argv[1] = resolve(dir, 'src/cli/index.ts');
  expect(await checkLocalIntegrity()).toEqual({ status: 'dev' });
});

test('checkLocalIntegrity returns dev with no running entry or explicit null', async () => {
  process.argv.splice(1, 1);
  expect(await checkLocalIntegrity()).toEqual({ status: 'dev' });
  process.argv[1] = originalEntry ?? 'src/cli/index.ts';
  expect(await checkLocalIntegrity({ bundlePath: null })).toEqual({ status: 'dev' });
});

test.each([
  '{broken json',
  'null',
  JSON.stringify({ files: {} }),
  JSON.stringify({ files: { 'keysentry.mjs': 'not-a-sha256' } }),
  JSON.stringify({ files: { 'keysentry.mjs': 42 } }),
])('checkLocalIntegrity never accepts an unusable manifest: %s', async manifest => {
  const bundlePath = await fixture();
  await writeFile(join(dir, 'release-manifest.json'), manifest);
  expect(await checkLocalIntegrity({ bundlePath })).toMatchObject({ status: 'mismatch' });
});

test('checkLocalIntegrity reports mismatch if a manifest exists but its bundle is missing', async () => {
  const bundlePath = await fixture();
  await rm(bundlePath);
  expect(await checkLocalIntegrity({ bundlePath })).toMatchObject({ status: 'mismatch' });
});
