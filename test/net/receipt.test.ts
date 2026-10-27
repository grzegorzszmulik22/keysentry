import { afterEach, beforeEach, expect, test } from 'vitest';
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { NetworkReceiptEntry } from '../../src/types.js';
import { createFileReceipt } from '../../src/net/receipt.js';

let dir: string;
beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), 'keysentry-receipt-')); });
afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

const entry = (overrides: Partial<NetworkReceiptEntry> = {}): NetworkReceiptEntry => ({ at: '2026-10-27T12:00:00.000Z', host: 'api.openai.com', method: 'GET', purpose: 'OpenAI API', allowed: true, status: 200, ...overrides });

test('creates a missing parent and writes only the receipt contract fields as JSONL', async () => {
  const path = join(dir, 'nested', 'network.jsonl');
  const receipt = createFileReceipt(path);
  await receipt.record({ ...entry(), url: '/private?query=secret', headers: { authorization: 'secret' }, body: 'secret' } as NetworkReceiptEntry);
  const text = await readFile(path, 'utf8');
  expect(text.endsWith('\n')).toBe(true);
  expect(JSON.parse(text)).toEqual(entry());
  expect(text).not.toMatch(/private|query|authorization|secret/);
  if (process.platform !== 'win32') expect((await stat(path)).mode & 0o777).toBe(0o600);
});

test('summarize groups by host and purpose, counts blocked and uses latest at', async () => {
  const receipt = createFileReceipt(join(dir, 'network.jsonl'));
  await receipt.record(entry({ host: 'z.example.com', at: '2026-10-27T14:00:00.000Z' }));
  await receipt.record(entry({ host: 'z.example.com', at: '2026-10-27T10:00:00.000Z' }));
  await receipt.record(entry({ host: 'a.example.com', purpose: 'not on the allowed list', allowed: false, status: undefined }));
  await receipt.record(entry({ host: 'a.example.com', purpose: 'not on the allowed list', allowed: false, at: '2026-10-27T13:00:00.000Z', status: undefined }));
  await receipt.record(entry({ host: 'a.example.com', purpose: 'another purpose', status: 204 }));
  expect(await receipt.summarize()).toEqual([
    { host: 'a.example.com', purpose: 'another purpose', count: 1, blocked: 0, lastAt: '2026-10-27T12:00:00.000Z' },
    { host: 'a.example.com', purpose: 'not on the allowed list', count: 2, blocked: 2, lastAt: '2026-10-27T13:00:00.000Z' },
    { host: 'z.example.com', purpose: 'OpenAI API', count: 2, blocked: 0, lastAt: '2026-10-27T14:00:00.000Z' },
  ]);
});

test('summarize filters since inclusively and returns empty for absent files', async () => {
  const receipt = createFileReceipt(join(dir, 'network.jsonl'));
  expect(await receipt.summarize()).toEqual([]);
  await receipt.record(entry({ at: '2026-10-27T11:59:59.000Z' }));
  await receipt.record(entry({ allowed: false, status: undefined }));
  expect(await receipt.summarize('2026-10-27T12:00:00.000Z')).toEqual([
    { host: 'api.openai.com', purpose: 'OpenAI API', count: 1, blocked: 1, lastAt: '2026-10-27T12:00:00.000Z' },
  ]);
});

test('a receipt over maxBytes rotates to path.1 and replaces its older backup', async () => {
  const path = join(dir, 'network.jsonl');
  await writeFile(`${path}.1`, 'older backup\n');
  const receipt = createFileReceipt(path, { maxBytes: 1 });
  await receipt.record(entry());
  expect(await readdir(dir)).toEqual(['network.jsonl.1']);
  expect(JSON.parse(await readFile(`${path}.1`, 'utf8'))).toEqual(entry());
  await receipt.record(entry({ host: 'api.anthropic.com' }));
  expect(JSON.parse(await readFile(`${path}.1`, 'utf8'))).toEqual(entry({ host: 'api.anthropic.com' }));
});

test('summarize includes both the rotated and current receipt', async () => {
  const path = join(dir, 'network.jsonl');
  const receipt = createFileReceipt(path, { maxBytes: Buffer.byteLength(`${JSON.stringify(entry())}\n`) });
  await receipt.record(entry());
  await receipt.record(entry({ allowed: false, status: undefined }));
  await receipt.record(entry({ at: '2026-10-27T13:00:00.000Z' }));
  expect(await receipt.summarize()).toEqual([
    { host: 'api.openai.com', purpose: 'OpenAI API', count: 3, blocked: 1, lastAt: '2026-10-27T13:00:00.000Z' },
  ]);
});

test('serializes concurrent records so rotation never loses or duplicates a line', async () => {
  const receipt = createFileReceipt(join(dir, 'network.jsonl'), { maxBytes: 1000 });
  await Promise.all(Array.from({ length: 8 }, (_, i) => receipt.record(entry({ method: `METHOD${i}` }))));
  expect(await receipt.summarize()).toEqual([
    { host: 'api.openai.com', purpose: 'OpenAI API', count: 8, blocked: 0, lastAt: '2026-10-27T12:00:00.000Z' },
  ]);
});
