import { afterEach, expect, test } from 'vitest';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { EgressRule, HttpRequest, NetworkReceipt, NetworkReceiptEntry } from '../../src/types.js';
import { makeResponse } from '../../src/http.js';
import { createGuardedHttp, EgressBlockedError } from '../../src/net/guarded-http.js';
import { createFileReceipt } from '../../src/net/receipt.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';

const rules: EgressRule[] = [
  { host: 'api.openai.com', owner: 'openai', purpose: 'OpenAI API' },
  { host: 'downloads.example.com', owner: 'openai', purpose: 'OpenAI downloads' },
  { host: 'api.anthropic.com', owner: 'anthropic', purpose: 'Anthropic API' },
];
const date = new Date('2026-10-27T12:00:00.000Z');
const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map(dir => rm(dir, { recursive: true, force: true }))); });

function memoryReceipt(): NetworkReceipt & { entries: NetworkReceiptEntry[] } {
  const entries: NetworkReceiptEntry[] = [];
  return { entries, async record(entry) { entries.push(entry); }, async summarize() { return []; } };
}

test('allows an exact host and records only response metadata without the path', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'keysentry-guard-'));
  dirs.push(dir);
  const path = join(dir, 'network.jsonl');
  const inner = new FakeHttp().on('POST', /api\.openai\.com/, () => makeResponse(201, 'created'));
  const http = createGuardedHttp(inner, { rules, receipt: createFileReceipt(path), now: () => date });
  const response = await http.request({ method: 'POST', url: 'https://api.openai.com/v1/private?token=private-query', headers: { Authorization: 'private-header' }, body: 'private-body' });
  expect(response.status).toBe(201);
  const text = await readFile(path, 'utf8');
  expect(JSON.parse(text)).toEqual({ at: date.toISOString(), host: 'api.openai.com', method: 'POST', purpose: 'OpenAI API', allowed: true, status: 201 });
  for (const value of ['/v1/', 'private-query', 'private-header', 'private-body']) expect(text).not.toContain(value);
});

test.each([
  ['https://api.openai.com.evil.com/private?query=hidden', 'api.openai.com.evil.com'],
  ['https://evil.com/api.openai.com?query=hidden', 'evil.com'],
  ['http://api.openai.com/private?query=hidden', 'api.openai.com'],
  ['https://1.2.3.4/private?query=hidden', '1.2.3.4'],
  ['https://[::1]/private?query=hidden', '[::1]'],
  ['https://user:pw@api.openai.com/private?query=hidden', 'api.openai.com'],
  ['https://api.openai.com:8443/private?query=hidden', 'api.openai.com'],
  ['not a URL/private?query=hidden', '(unparseable)'],
])('blocks lookalike and malformed URL %s without storing its path or query', async (url, host) => {
  const inner = new FakeHttp();
  const receipt = memoryReceipt();
  const http = createGuardedHttp(inner, { rules, receipt, now: () => date });
  await expect(http.request({ method: 'GET', url })).rejects.toMatchObject({
    name: 'EgressBlockedError', code: 'EGRESS_BLOCKED',
    message: `Blocked a request to ${host}: it is not on keysentry's list of allowed hosts. Run "keysentry network" to see the list.`,
  });
  expect(inner.calls).toHaveLength(0);
  expect(receipt.entries).toEqual([{ at: date.toISOString(), host, method: 'GET', purpose: 'not on the allowed list', allowed: false }]);
  expect(JSON.stringify(receipt.entries)).not.toMatch(/private|hidden|query=|user:pw/);
});

test('normalises case and trailing dot', async () => {
  const receipt = memoryReceipt();
  const inner = new FakeHttp().on('GET', /./, () => makeResponse(200, 'ok'));
  await createGuardedHttp(inner, { rules, receipt }).request({ method: 'GET', url: 'https://API.OPENAI.COM./v1/models' });
  expect(inner.calls).toHaveLength(1);
  expect(receipt.entries[0]).toMatchObject({ host: 'api.openai.com', allowed: true });
});

test.each([
  `https://api.openai.com/v1/models?key=sk-or-v1-${'a'.repeat(64)}`,
  `https://api.openai.com/v1/sk-or-v1-${'b'.repeat(64)}`,
  `https://api.openai.com/v1/models?key=%73k-or-v1-${'c'.repeat(64)}`,
])('blocks a URL containing a secret-shaped value', async url => {
  const receipt = memoryReceipt();
  const inner = new FakeHttp();
  await expect(createGuardedHttp(inner, { rules, receipt }).request({ method: 'GET', url })).rejects.toBeInstanceOf(EgressBlockedError);
  expect(inner.calls).toHaveLength(0);
  expect(JSON.stringify(receipt.entries)).not.toContain('sk-or-v1-');
});

test('blocked receipts and errors redact a secret-shaped hostname label', async () => {
  const secret = `sk-or-v1-${'a'.repeat(64)}`;
  const receipt = memoryReceipt();
  const inner = new FakeHttp();
  const error = await createGuardedHttp(inner, { rules, receipt })
    .request({ method: 'GET', url: `https://${secret}.example.com/private?query=hidden` })
    .catch((failure: unknown) => failure);
  expect(error).toBeInstanceOf(EgressBlockedError);
  expect((error as Error).message).toContain('«redacted».example.com');
  expect((error as Error).message).not.toContain(secret);
  expect(receipt.entries[0]?.host).toBe('«redacted».example.com');
  expect(JSON.stringify(receipt.entries)).not.toMatch(/sk-or-v1-|private|hidden/);
  expect(inner.calls).toHaveLength(0);
  expect(new EgressBlockedError(`${secret}.example.com`).message).not.toContain(secret);
});

test('follows a same-owner redirect and drops authorization and cookie on host change', async () => {
  const receipt = memoryReceipt();
  const inner = new FakeHttp()
    .on('POST', /api\.openai\.com/, () => makeResponse(307, '', { Location: 'https://downloads.example.com/result' }))
    .on('POST', /downloads\.example\.com/, () => makeResponse(200, 'ok'));
  const request: HttpRequest = { method: 'POST', url: 'https://api.openai.com/start', body: 'payload', headers: { aUtHoRiZaTiOn: 'token', CoOkIe: 'session', Accept: 'application/json' } };
  expect((await createGuardedHttp(inner, { rules, receipt }).request(request)).text).toBe('ok');
  expect(inner.calls[1]).toMatchObject({ method: 'POST', body: 'payload', headers: { Accept: 'application/json' } });
  expect(Object.keys(inner.calls[1]!.headers!)).toEqual(['Accept']);
  expect(request.headers).toHaveProperty('aUtHoRiZaTiOn', 'token');
  expect(receipt.entries.map(({ host, status }) => [host, status])).toEqual([['api.openai.com', 307], ['downloads.example.com', 200]]);
});

test.each([301, 302, 303])('redirect %i changes a POST to GET without body', async status => {
  const inner = new FakeHttp()
    .on('POST', /\/start$/, () => makeResponse(status, '', { location: '/result' }))
    .on('GET', /\/result$/, () => makeResponse(200, 'ok'));
  await createGuardedHttp(inner, { rules }).request({ method: 'POST', url: 'https://api.openai.com/start', body: 'payload', headers: { Authorization: 'token', 'Content-Length': '7', 'Content-Type': 'text/plain' } });
  expect(inner.calls[1]).toEqual({ method: 'GET', url: 'https://api.openai.com/result', headers: { Authorization: 'token' } });
});

test.each([307, 308])('redirect %i keeps method and body', async status => {
  const inner = new FakeHttp()
    .on('PATCH', /\/start$/, () => makeResponse(status, '', { location: '/result' }))
    .on('PATCH', /\/result$/, () => makeResponse(200, 'ok'));
  await createGuardedHttp(inner, { rules }).request({ method: 'PATCH', url: 'https://api.openai.com/start', body: 'payload' });
  expect(inner.calls[1]).toMatchObject({ method: 'PATCH', url: 'https://api.openai.com/result', body: 'payload' });
});

test.each(['https://api.anthropic.com/private?hidden=yes', 'https://api.openai.com.evil.com/private?hidden=yes', 'http://api.openai.com/private?hidden=yes', 'https://[bad'])('redirect to another owner or disallowed URL is blocked and recorded once', async location => {
  const inner = new FakeHttp().on('POST', /api\.openai\.com/, () => makeResponse(302, '', { location }));
  const receipt = memoryReceipt();
  await expect(createGuardedHttp(inner, { rules, receipt }).request({ method: 'POST', url: 'https://api.openai.com/start', body: 'payload' })).rejects.toBeInstanceOf(EgressBlockedError);
  expect(inner.calls).toHaveLength(1);
  expect(receipt.entries).toHaveLength(2);
  expect(receipt.entries[0]).toMatchObject({ allowed: true, method: 'POST', status: 302 });
  expect(receipt.entries[1]).toMatchObject({ allowed: false, method: 'GET', purpose: 'not on the allowed list' });
  expect(receipt.entries[1]).not.toHaveProperty('status');
  expect(JSON.stringify(receipt.entries)).not.toMatch(/private|hidden|payload|start/);
});

test('same-owner redirects still check secret-shaped URLs', async () => {
  const inner = new FakeHttp().on('GET', /./, () => makeResponse(307, '', { location: `/private?key=sk-or-v1-${'a'.repeat(64)}` }));
  const receipt = memoryReceipt();
  await expect(createGuardedHttp(inner, { rules, receipt }).request({ method: 'GET', url: 'https://api.openai.com/start' })).rejects.toBeInstanceOf(EgressBlockedError);
  expect(inner.calls).toHaveLength(1);
  expect(receipt.entries.map(entry => entry.allowed)).toEqual([true, false]);
});

test.each([undefined, 0, 1])('limits redirects to the configured count (%s)', async maxRedirects => {
  const inner = new FakeHttp().on('GET', /./, () => makeResponse(302, '', { location: '/again' }));
  const receipt = memoryReceipt();
  await expect(createGuardedHttp(inner, { rules, receipt, maxRedirects }).request({ method: 'GET', url: 'https://api.openai.com/start' })).rejects.toThrow('Too many redirects from api.openai.com');
  expect(inner.calls).toHaveLength((maxRedirects ?? 3) + 1);
  expect(receipt.entries).toHaveLength(inner.calls.length);
});

test.each([300, 304, 305, 306, 399])('returns status %i without following a location', async status => {
  const inner = new FakeHttp().on('GET', /./, () => makeResponse(status, '', { location: '/next' }));
  expect((await createGuardedHttp(inner, { rules }).request({ method: 'GET', url: 'https://api.openai.com/start' })).status).toBe(status);
  expect(inner.calls).toHaveLength(1);
});

test('returns redirect responses without a location', async () => {
  const inner = new FakeHttp().on('GET', /./, () => makeResponse(302, 'no location'));
  expect((await createGuardedHttp(inner, { rules }).request({ method: 'GET', url: 'https://api.openai.com/start' })).status).toBe(302);
  expect(inner.calls).toHaveLength(1);
});

test('records after the response arrives using its status and completion time', async () => {
  let resolve!: (response: ReturnType<typeof makeResponse>) => void;
  let time = new Date('2026-10-27T11:00:00.000Z');
  const pending = new Promise<ReturnType<typeof makeResponse>>(done => { resolve = done; });
  const inner = new FakeHttp().on('GET', /./, () => pending);
  const receipt = memoryReceipt();
  const request = createGuardedHttp(inner, { rules, receipt, now: () => time }).request({ method: 'GET', url: 'https://api.openai.com/start' });
  expect(receipt.entries).toHaveLength(0);
  time = date;
  resolve(makeResponse(503, 'unavailable'));
  await request;
  expect(receipt.entries).toEqual([{ at: date.toISOString(), host: 'api.openai.com', method: 'GET', purpose: 'OpenAI API', allowed: true, status: 503 }]);
});

test('records a failed transport without status and rethrows the original error', async () => {
  const error = new Error('transport failed');
  const inner = new FakeHttp().on('GET', /./, () => { throw error; });
  const receipt = memoryReceipt();
  await expect(createGuardedHttp(inner, { rules, receipt }).request({ method: 'GET', url: 'https://api.openai.com/start' })).rejects.toBe(error);
  expect(receipt.entries).toHaveLength(1);
  expect(receipt.entries[0]).toMatchObject({ host: 'api.openai.com', allowed: true });
  expect(receipt.entries[0]).not.toHaveProperty('status');
});

test('receipt write failures warn without exposing the exception or failing the request', async () => {
  const messages: unknown[] = [];
  const log = { ...silentLogger, warn(message: string, data?: Record<string, unknown>) { messages.push([message, data]); } };
  const receipt: NetworkReceipt = { async record() { throw new Error('secret-path?token=private'); }, async summarize() { return []; } };
  const inner = new FakeHttp().on('GET', /./, () => makeResponse(200, 'ok'));
  const http = createGuardedHttp(inner, { rules, receipt, log });
  expect((await http.request({ method: 'GET', url: 'https://api.openai.com/start' })).text).toBe('ok');
  await expect(http.request({ method: 'GET', url: 'https://evil.com/private' })).rejects.toBeInstanceOf(EgressBlockedError);
  expect(messages).toHaveLength(2);
  expect(JSON.stringify(messages)).not.toMatch(/private|secret-path|token=/);
});

test('a configured webhook URL with a credential in its path is allowed only exactly as configured', async () => {
  const hook = 'https://hooks.slack.com/services/T0000000/B0000000/abcdefghijklmnopqrstuvwx';
  const userRules = [{ host: 'hooks.slack.com', purpose: 'notification webhook you configured', owner: 'user' }];
  const inner = new FakeHttp().on('POST', /hooks\.slack\.com/, () => makeResponse(200, 'ok'));
  const blockedWithoutTrust = createGuardedHttp(inner, { rules: userRules });
  await expect(blockedWithoutTrust.request({ method: 'POST', url: hook, body: '{}' })).rejects.toThrow(EgressBlockedError);
  const http = createGuardedHttp(inner, { rules: userRules, trustedUrls: [hook] });
  expect((await http.request({ method: 'POST', url: hook, body: '{}' })).status).toBe(200);
  // Another credential-bearing path on the same host is still blocked.
  await expect(http.request({ method: 'POST', url: hook.replace('abcdef', 'zzzzzz'), body: '{}' })).rejects.toThrow(EgressBlockedError);
});

test('a trusted URL does not exempt its redirect target', async () => {
  const hook = 'https://hooks.slack.com/services/T0000000/B0000000/abcdefghijklmnopqrstuvwx';
  const userRules = [{ host: 'hooks.slack.com', purpose: 'notification webhook you configured', owner: 'user' }];
  const inner = new FakeHttp().on('POST', /hooks\.slack\.com/, () => makeResponse(307, '', { location: `${hook}/again` }));
  const http = createGuardedHttp(inner, { rules: userRules, trustedUrls: [hook] });
  await expect(http.request({ method: 'POST', url: hook, body: '{}' })).rejects.toThrow(EgressBlockedError);
});
