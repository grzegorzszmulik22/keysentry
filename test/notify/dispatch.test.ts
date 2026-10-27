import { expect, test } from 'vitest';
import { createDispatcher } from '../../src/notify/dispatch.js';
import { createDiscordChannel } from '../../src/notify/channels/discord.js';
import { signMessage } from '../../src/notify/sign.js';
import { generateDeviceKey } from '../../src/security/index.js';
import { createRedactor } from '../../src/core/redact.js';
import { NotifyDeliveryError } from '../../src/notify/message.js';
import { FakeHttp, json, silentLogger } from '../helpers/fake-http.js';
import type { NotifyChannel } from '../../src/types.js';

const m = () => signMessage({ id: 'm1', at: '2026-10-27T12:00:00Z', kind: 'test', title: 'Update', lines: [], severity: 'info' }, generateDeviceKey());

test('dispatcher keeps going when one channel fails and reports lastSuccessAt', async () => {
  const sleeps: number[] = [];
  let attempts = 0;
  let instant = '2026-10-27T12:01:00Z';
  const logLines: unknown[] = [];
  const channels: NotifyChannel[] = [
    { id: 'broken', kind: 'webhook', async send() { attempts++; throw new Error('https://secret.example/private recipient@example.org'); } },
    { id: 'working', kind: 'console', async send() {} },
  ];
  const d = createDispatcher(channels, { log: { ...silentLogger, warn: (...args) => logLines.push(args) }, now: () => new Date(instant), sleep: async ms => { sleeps.push(ms); } });
  expect(d.lastSuccessAt()).toBeNull();
  expect(d.lastExternalSuccessAt()).toBeNull();
  expect(await d.send(m())).toEqual({ delivered: ['working'], failed: [{ id: 'broken', reason: 'Webhook delivery failed' }] });
  expect(attempts).toBe(3);
  expect(sleeps).toEqual([1000, 2000]);
  expect(d.lastSuccessAt()).toBe('2026-10-27T12:01:00.000Z');
  expect(d.lastExternalSuccessAt()).toBeNull();
  expect(JSON.stringify(logLines)).not.toContain('secret.example');
  expect(JSON.stringify(logLines)).not.toContain('recipient@');
  instant = '2026-10-27T12:02:00Z';
  await d.send(m());
  expect(d.lastSuccessAt()).toBe('2026-10-27T12:02:00.000Z');
  expect(d.lastExternalSuccessAt()).toBeNull();
});

test.each(['telegram', 'discord', 'slack', 'ntfy', 'webhook', 'resend', 'smtp'] as const)(
  '%s delivery advances external success time and later console delivery cannot refresh it', async kind => {
    let externalFails = false;
    let consoleFails = false;
    let instant = '2026-10-27T12:01:00Z';
    const d = createDispatcher([
      { id: 'console', kind, async send() { if (externalFails) throw new Error('failure'); } },
      { id: 'local-output', kind: 'console', async send() { if (consoleFails) throw new Error('failure'); } },
    ], { log: silentLogger, retries: 1, now: () => new Date(instant) });

    expect((await d.send(m())).delivered).toEqual(['console', 'local-output']);
    expect(d.lastSuccessAt()).toBe('2026-10-27T12:01:00.000Z');
    expect(d.lastExternalSuccessAt()).toBe('2026-10-27T12:01:00.000Z');

    externalFails = true;
    instant = '2026-10-27T13:01:00Z';
    expect((await d.send(m())).delivered).toEqual(['local-output']);
    expect(d.lastSuccessAt()).toBe('2026-10-27T13:01:00.000Z');
    expect(d.lastExternalSuccessAt()).toBe('2026-10-27T12:01:00.000Z');

    consoleFails = true;
    instant = '2026-10-27T14:01:00Z';
    expect((await d.send(m())).delivered).toEqual([]);
    expect(d.lastSuccessAt()).toBe('2026-10-27T13:01:00.000Z');
    expect(d.lastExternalSuccessAt()).toBe('2026-10-27T12:01:00.000Z');
  },
);

test('one blocked channel does not delay delivery through the others', async () => {
  let release!: () => void;
  const blocked = new Promise<void>(resolve => { release = resolve; });
  let fastDelivered = false;
  const d = createDispatcher([
    { id: 'blocked', kind: 'console', send: () => blocked },
    { id: 'fast', kind: 'console', async send() { fastDelivered = true; } },
  ], { log: silentLogger });
  const pending = d.send(m());
  await Promise.resolve();
  expect(fastDelivered).toBe(true);
  release();
  expect((await pending).delivered).toEqual(['blocked', 'fast']);
});

test('dispatcher retries independently, honors Retry-After capped at 60 s, and retains safe status', async () => {
  const sleeps: number[] = [];
  const http = new FakeHttp().on('POST', /.*/, () => json(429, { retry_after: 1000 }, { 'Retry-After': '90' }));
  const c = createDiscordChannel({ webhookUrl: 'https://discord.com/api/webhooks/id/private' }, { http, redactor: createRedactor() });
  const d = createDispatcher([c], { log: silentLogger, retries: 4, sleep: async ms => { sleeps.push(ms); } });
  expect(await d.send(m())).toEqual({ delivered: [], failed: [{ id: 'discord', reason: 'Discord returned 429' }] });
  expect(http.calls).toHaveLength(4);
  expect(sleeps).toEqual([60000, 60000, 60000]);
  expect(d.lastSuccessAt()).toBeNull();
});

test('backoff is 1 s, 2 s, 4 s and stops after a successful attempt', async () => {
  let attempts = 0;
  const sleeps: number[] = [];
  const d = createDispatcher([{ id: 'retry', kind: 'console', async send() { if (++attempts < 4) throw new Error('failure'); } }],
    { log: silentLogger, retries: 4, sleep: async ms => { sleeps.push(ms); } });
  expect((await d.send(m())).delivered).toEqual(['retry']);
  expect(sleeps).toEqual([1000, 2000, 4000]);
});

test('later total failures do not erase the last successful timestamp', async () => {
  let fail = false;
  const d = createDispatcher([{ id: 'console', kind: 'console', async send() { if (fail) throw new Error('failure'); } }],
    { log: silentLogger, retries: 1, now: () => new Date('2026-10-27T12:01:00Z') });
  await d.send(m());
  fail = true;
  await d.send(m());
  expect(d.lastSuccessAt()).toBe('2026-10-27T12:01:00.000Z');
});

test('invalid attempts and duplicate channel ids reject configuration', () => {
  for (const retries of [0, -1, NaN, Infinity, 1.5]) expect(() => createDispatcher([], { log: silentLogger, retries })).toThrow();
  const c: NotifyChannel = { id: 'same', kind: 'console', async send() {} };
  expect(() => createDispatcher([c, c], { log: silentLogger })).toThrow();
});

test('failure reasons are reconstructed from fixed phrases even if a channel mutates an error', async () => {
  const error = new NotifyDeliveryError('discord', 404);
  error.message = 'https://discord.com/api/webhooks/id/private-token recipient@example.org';
  const logs: string[] = [];
  const d = createDispatcher([{ id: 'discord', kind: 'discord', async send() { throw error; } }],
    { log: { ...silentLogger, warn: text => logs.push(text) }, retries: 1 });
  expect((await d.send(m())).failed).toEqual([{ id: 'discord', reason: 'Discord returned 404' }]);
  expect(logs).toEqual(['Discord returned 404']);
});
