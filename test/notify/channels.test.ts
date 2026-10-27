import { describe, expect, test } from 'vitest';
import { createRedactor } from '../../src/core/redact.js';
import { generateDeviceKey } from '../../src/security/index.js';
import { createGuardedHttp, EGRESS_RULES } from '../../src/net/index.js';
import { FakeHttp, json, text } from '../helpers/fake-http.js';
import { createTelegramChannel, telegramUrl } from '../../src/notify/channels/telegram.js';
import { createDiscordChannel, discordWebhookUrl } from '../../src/notify/channels/discord.js';
import { createSlackChannel } from '../../src/notify/channels/slack.js';
import { createNtfyChannel } from '../../src/notify/channels/ntfy.js';
import { createWebhookChannel } from '../../src/notify/channels/webhook.js';
import { createResendChannel } from '../../src/notify/channels/resend.js';
import { createConsoleChannel } from '../../src/notify/channels/console.js';
import { signMessage, verifyMessage } from '../../src/notify/sign.js';
import type { NotifyChannel, NotifySeverity } from '../../src/types.js';

const key = generateDeviceKey();
function message(severity: NotifySeverity = 'warning', lines = ['Details <tag> & @everyone <@123>']) {
  return signMessage({ id: 'notify-1', at: '2026-10-27T12:00:00Z', kind: 'incident', severity,
    title: 'A platform update', lines, approveUrl: 'https://approve.example/action?id=1&x=2' }, key);
}
const payload = (http: FakeHttp) => JSON.parse(http.calls.at(-1)!.body!);
const deps = () => ({ http: new FakeHttp().on('POST', /.*/, req => req.url.startsWith('https://hooks.slack.com/') ? text(200, 'ok') : json(200, { ok: true, id: '1' })), redactor: createRedactor() });

test('telegram escapes HTML, disables previews, and keeps its exact credential URL across sends', async () => {
  const d = deps();
  const channel = createTelegramChannel({ botToken: '123:private-token', chatId: '1234' }, d);
  await channel.send(message('info'));
  await channel.send(message('urgent'));
  expect(d.http.calls.map(c => c.url)).toEqual(Array(2).fill('https://api.telegram.org/bot123:private-token/sendMessage'));
  expect(payload(d.http)).toMatchObject({ chat_id: '1234', parse_mode: 'HTML', link_preview_options: { is_disabled: true }, disable_notification: false });
  expect(payload(d.http).text).toContain('&lt;tag&gt; &amp;');
  expect(JSON.parse(d.http.calls[0]!.body!).disable_notification).toBe(true);
});

test('discord uses wait=true and disables and escapes all mentions', async () => {
  const d = deps();
  const channel = createDiscordChannel({ webhookUrl: 'https://discord.com/api/v10/webhooks/123/private?thread_id=7&wait=false' }, d);
  await channel.send(message());
  await channel.send(message());
  expect(d.http.calls[0]!.url).toBe('https://discord.com/api/v10/webhooks/123/private?thread_id=7&wait=true');
  expect(d.http.calls[1]!.url).toBe(d.http.calls[0]!.url);
  expect(payload(d.http).allowed_mentions).toEqual({ parse: [] });
  expect(payload(d.http).content).not.toContain('@everyone');
  expect(payload(d.http).content).not.toContain('<@123>');
});

test('slack uses escaped text only and preserves its webhook URL', async () => {
  const d = deps();
  const url = 'https://hooks.slack.com/services/T/B/private';
  await createSlackChannel({ webhookUrl: url }, d).send(message());
  expect(d.http.calls[0]!.url).toBe(url);
  expect(Object.keys(payload(d.http))).toEqual(['text']);
  expect(payload(d.http).text).toContain('&lt;tag&gt; &amp;');
  expect(payload(d.http).text).not.toContain('<@123>');
});

test.each([['info', 3], ['warning', 4], ['urgent', 5]] as const)('ntfy maps %s severity to priority and publishes JSON at the root', async (severity, priority) => {
  const d = deps();
  await createNtfyChannel({ server: 'https://ntfy.example/', topic: 'topic-1', token: 'tk_private' }, d).send(message(severity));
  expect(d.http.calls[0]!.url).toBe('https://ntfy.example/');
  expect(d.http.calls[0]!.headers?.Authorization).toBe('Bearer tk_private');
  expect(payload(d.http)).toMatchObject({ topic: 'topic-1', priority });
  expect(payload(d.http).message).toContain('Verification code:');
});

test.each(['telegram', 'discord', 'slack', 'ntfy'] as const)('%s truncates after escaping without losing the verification code', async kind => {
  const d = deps();
  const m = message('urgent', ['<&>🙂@'.repeat(5000)]);
  const channel = {
    telegram: () => createTelegramChannel({ botToken: '123:private', chatId: '1234' }, d),
    discord: () => createDiscordChannel({ webhookUrl: 'https://discord.com/api/webhooks/123/private' }, d),
    slack: () => createSlackChannel({ webhookUrl: 'https://hooks.slack.com/services/T/B/private' }, d),
    ntfy: () => createNtfyChannel({ server: 'https://ntfy.sh', topic: 'topic' }, d),
  }[kind]();
  await channel.send(m);
  const p = payload(d.http);
  const content: string = p.text ?? p.content ?? p.message;
  const size = kind === 'ntfy' ? Buffer.byteLength(content) : content.length;
  expect(size).toBeLessThanOrEqual({ telegram: 4096, discord: 2000, slack: 4000, ntfy: 4096 }[kind]);
  expect(content).toContain(`Verification code: ${m.code}`);
  expect(content.endsWith('… (shortened)')).toBe(true);
});

test('webhook sends the exact signed message and verifiable signature headers', async () => {
  const d = deps();
  const m = message();
  await createWebhookChannel({ url: 'https://notify.example/hook' }, d).send(m);
  expect(payload(d.http)).toEqual(m);
  expect(verifyMessage(payload(d.http), key.publicKeyDer)).toBe(true);
  expect(d.http.calls[0]!.headers).toMatchObject({ 'X-Keysentry-Signature': `v1,keyId=${m.keyId},sig=${m.sig}`, 'X-Keysentry-Code': m.code });
});

test('resend sends text fields and a stable idempotency key', async () => {
  const d = deps();
  await createResendChannel({ apiKey: 're_private', from: 'Sender <sender@example.org>', to: ['recipient@example.org'] }, d).send(message());
  expect(d.http.calls[0]).toMatchObject({ url: 'https://api.resend.com/emails', headers: { Authorization: 'Bearer re_private', 'Idempotency-Key': 'notify-1' } });
  expect(payload(d.http)).toMatchObject({ from: 'Sender <sender@example.org>', to: ['recipient@example.org'], subject: 'A platform update' });
  expect(payload(d.http).text).toContain('Verification code:');
  expect(payload(d.http)).not.toHaveProperty('html');
});

test.each(['telegram', 'discord', 'slack', 'ntfy', 'webhook', 'resend'] as const)('%s rejects messages containing a registered secret before sending', async kind => {
  const d = deps();
  const secret = 'private-value-with-no-recognizable-prefix';
  d.redactor.register(secret);
  const channels: Record<string, () => NotifyChannel> = {
    telegram: () => createTelegramChannel({ botToken: '123:private', chatId: '1234' }, d),
    discord: () => createDiscordChannel({ webhookUrl: 'https://discord.com/api/webhooks/123/private' }, d),
    slack: () => createSlackChannel({ webhookUrl: 'https://hooks.slack.com/services/T/B/private' }, d),
    ntfy: () => createNtfyChannel({ server: 'https://ntfy.sh', topic: 'topic' }, d),
    webhook: () => createWebhookChannel({ url: 'https://notify.example/hook' }, d),
    resend: () => createResendChannel({ apiKey: 're_private', from: 'a@b.org', to: 'b@c.org' }, d),
  };
  await expect(channels[kind]!().send(message('warning', [secret]))).rejects.toThrow('Notification contains a secret');
  expect(d.http.calls).toHaveLength(0);
});

test('console uses the shared renderer and refuses registered secrets when given a redactor', async () => {
  const lines: string[] = [];
  const d = deps();
  d.redactor.register('private-console-value');
  const channel = createConsoleChannel(line => lines.push(line), { redactor: d.redactor });
  await channel.send(message());
  expect(lines[0]).toContain(`Verification code: ${message().code}`);
  await expect(channel.send(message('info', ['private-console-value']))).rejects.toThrow('Notification contains a secret');
  expect(lines).toHaveLength(1);
});

test('rendering cannot assemble a registered secret from separate message fields', async () => {
  const d = deps();
  const m = signMessage({ id: 'm2', at: '2026-10-27T12:00:00Z', kind: 'test', severity: 'info', title: 'First part', lines: ['Second part'] }, key);
  d.redactor.register('First part\n\nSecond part');
  await expect(createNtfyChannel({ server: 'https://ntfy.sh', topic: 'topic' }, d).send(m)).rejects.toThrow('Notification contains a secret');
  expect(d.http.calls).toHaveLength(0);
  const writes: string[] = [];
  await expect(createConsoleChannel(line => writes.push(line), { redactor: d.redactor }).send(m)).rejects.toThrow('Notification contains a secret');
  expect(writes).toHaveLength(0);
});

test('credential URLs work unchanged through the exact trusted egress exemption', async () => {
  const inner = deps().http;
  const botToken = '123:private-token';
  const discord = 'https://discord.com/api/v10/webhooks/123/private-token?wait=false';
  const slack = 'https://hooks.slack.com/services/T/B/private-token';
  const http = createGuardedHttp(inner, { rules: EGRESS_RULES,
    trustedUrls: [telegramUrl(botToken), discordWebhookUrl(discord), slack] });
  const redactor = createRedactor();
  const channels = [createTelegramChannel({ botToken, chatId: '1234' }, { http, redactor }),
    createDiscordChannel({ webhookUrl: discord }, { http, redactor }), createSlackChannel({ webhookUrl: slack }, { http, redactor })];
  for (const channel of channels) { await channel.send(message()); await channel.send(message()); }
  expect(inner.calls).toHaveLength(6);
  expect(new Set(inner.calls.map(call => call.url)).size).toBe(3);
});

describe('safe failures and retry hints', () => {
  test('HTTP failures carry only the channel, status and a bounded Retry-After', async () => {
    const d = deps();
    d.http = new FakeHttp().on('POST', /.*/, () => text(404, 'private-url-token', { 'Retry-After': '120' }));
    const c = createDiscordChannel({ webhookUrl: 'https://discord.com/api/webhooks/id/private-url-token' }, d);
    await expect(c.send(message())).rejects.toMatchObject({ message: 'Discord returned 404', retryAfterMs: 60_000 });
  });
  test('transport failures never echo URLs, tokens, addresses or response text', async () => {
    const d = deps();
    d.http = new FakeHttp().on('POST', /.*/, () => { throw new Error('https://api.telegram.org/botprivate-token recipient@example.org'); });
    await expect(createTelegramChannel({ botToken: 'private-token', chatId: '1234' }, d).send(message())).rejects.toThrow(/^Telegram delivery failed$/);
  });
  test('Telegram ok=false is a delivery failure even with HTTP 200 and honors retry_after', async () => {
    const d = deps();
    d.http = new FakeHttp().on('POST', /.*/, () => json(200, { ok: false, error_code: 429, description: 'private', parameters: { retry_after: 5 } }));
    await expect(createTelegramChannel({ botToken: 'private-token', chatId: '1234' }, d).send(message())).rejects.toMatchObject({ message: 'Telegram returned 429', retryAfterMs: 5000 });
  });
  test('Slack requires its success response rather than accepting a 200 error body', async () => {
    const d = deps();
    d.http = new FakeHttp().on('POST', /.*/, () => text(200, 'invalid_payload'));
    await expect(createSlackChannel({ webhookUrl: 'https://hooks.slack.com/services/T/B/private' }, d).send(message())).rejects.toThrow('Slack delivery failed');
  });
  test('Discord rate limit JSON supplies fractional retry_after', async () => {
    const d = deps();
    d.http = new FakeHttp().on('POST', /.*/, () => json(429, { retry_after: 1.5 }));
    await expect(createDiscordChannel({ webhookUrl: 'https://discord.com/api/webhooks/id/private' }, d).send(message())).rejects.toMatchObject({ retryAfterMs: 1500 });
  });
});
