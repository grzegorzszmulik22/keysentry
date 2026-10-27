import { afterEach, describe, expect, test } from 'vitest';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Command } from 'commander';
import { createRedactor, createStateCipher, createStateStore } from '../../src/core/index.js';
import { generateDeviceKey } from '../../src/security/index.js';
import { signMessage, verifyMessage } from '../../src/notify/index.js';
import { createGuardedHttp } from '../../src/net/index.js';
import { FakeHttp, json, silentLogger } from '../helpers/fake-http.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createNotificationChannels, notificationEgress, registerNotificationCommands, type NotificationContext, type NotifyChannelSettings } from '../../src/cli/notifications.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
async function setup(settings: NotifyChannelSettings[] = [], answers: (string | null)[] = []) {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-notifications-')); dirs.push(cwd);
  const vault = createFakeVault();
  const store = createStateStore({ cwd, cipher: createStateCipher(Buffer.alloc(32, 7)) });
  const key = generateDeviceKey(); const watcher = generateDeviceKey();
  const http = new FakeHttp().on('POST', /.*/, () => json(200, { ok: true }));
  const saved: NotifyChannelSettings[][] = []; const outputs: unknown[] = []; const gates: string[] = [];
  const prompts: { field: string; secret: boolean }[] = [];
  const context: NotificationContext = { settings, vault, store, http, redactor: createRedactor(), log: silentLogger,
    deviceKey: async () => key, watcherPublicKeys: async () => [watcher.publicKeyDer],
    saveSettings: async value => { saved.push(value); context.settings = value; }, now: () => new Date('2026-10-27T12:00:00Z') };
  const run = async (args: string[], human = (action: string) => { gates.push(action); }) => {
    const program = new Command().option('--json').exitOverride();
    registerNotificationCommands(program, { getContext: async () => context, human,
      emit: value => { outputs.push(value); }, prompt: async (field, secret) => { prompts.push({ field, secret }); return answers.shift() ?? null; } });
    await program.parseAsync(['notify', ...args], { from: 'user' });
  };
  return { cwd, vault, store, key, watcher, http, saved, outputs, gates, prompts, context, run };
}

describe('notification CLI', () => {
  test('add hides webhook input and writes only non-secret settings to config', async () => {
    const f = await setup([], ['ops', 'https://hooks.example.test/private-webhook']);
    await f.run(['add', 'webhook']);
    expect(f.gates).toEqual(['add a notification channel']);
    expect(f.saved).toEqual([[{ id: 'ops', kind: 'webhook' }]]);
    expect((await f.vault.get('notify/ops/url'))?.toString()).toBe('https://hooks.example.test/private-webhook');
    expect(f.prompts).toContainEqual({ field: 'url', secret: true });
    expect(JSON.stringify(f.outputs)).not.toContain('private-webhook');
  });
  test('ntfy keeps its topic and token in the vault and its server in config', async () => {
    const f = await setup([], ['phone', 'https://push.example.test', 'private-topic', 'private-token']);
    await f.run(['add', 'ntfy']);
    expect(f.saved[0]).toEqual([{ id: 'phone', kind: 'ntfy', server: 'https://push.example.test' }]);
    expect((await f.vault.get('notify/phone/topic'))?.toString()).toBe('private-topic');
    expect((await f.vault.get('notify/phone/token'))?.toString()).toBe('private-token');
  });
  test('list exposes ids and kinds only', async () => {
    const f = await setup([{ id: 'mail', kind: 'smtp', host: 'mail.example.test', port: 465, from: 'from@example.test', to: ['to@example.test'] }]);
    await f.run(['list']);
    expect(f.outputs).toEqual([[{ id: 'mail', kind: 'smtp' }]]);
    expect(f.gates).toEqual([]);
  });
  test('remove deletes only the selected channel vault namespace and its settings', async () => {
    const f = await setup([{ id: 'ops', kind: 'webhook' }, { id: 'ops2', kind: 'console' }]);
    await f.vault.set('notify/ops/url', Buffer.from('private'));
    await f.vault.set('notify/ops2/url', Buffer.from('other-private'));
    await f.run(['remove', 'ops']);
    expect(await f.vault.list()).toEqual(['notify/ops2/url']);
    expect(f.saved).toEqual([[{ id: 'ops2', kind: 'console' }]]);
    expect(f.gates).toEqual(['remove a notification channel']);
  });
  test.each([['add', 'webhook', '--relay'], ['add', 'webhook', '--remote'], ['remove', 'ops', '--relay']])('policy widening refuses remote form %j', async (...args) => {
    const f = await setup(); await expect(f.run(args)).rejects.toThrow(/local/i); expect(f.saved).toEqual([]);
  });
  test('human refusal happens before prompts, secrets or settings can change', async () => {
    const f = await setup([], ['ops', 'https://hooks.example.test/private']);
    await expect(f.run(['add', 'webhook'], () => { throw new Error('human refused'); })).rejects.toThrow('human refused');
    expect(f.prompts).toEqual([]); expect(await f.vault.list()).toEqual([]);
  });
  test('test sends a signed message to every channel and persists the signed verification record encrypted', async () => {
    const f = await setup([{ id: 'ops', kind: 'webhook' }, { id: 'bad', kind: 'webhook' }]);
    await f.vault.set('notify/ops/url', Buffer.from('https://hooks.example.test/private'));
    await f.vault.set('notify/bad/url', Buffer.from('https://bad.example.test/private'));
    f.http.on('POST', /^https:\/\/bad\./, () => json(500, {}));
    // First route wins in FakeHttp, so use a dedicated response fake.
    f.context.http = new FakeHttp().on('POST', /^https:\/\/hooks\./, () => json(200, {})).on('POST', /^https:\/\/bad\./, () => json(500, {}));
    await f.run(['test']);
    expect(f.gates).toEqual(['test notification channels']);
    const payload = JSON.parse((f.context.http as FakeHttp).calls[0]!.body!);
    expect(verifyMessage(payload, f.key.publicKeyDer)).toBe(true);
    expect(f.outputs.at(-1)).toMatchObject({ delivered: ['ops'], failed: [{ id: 'bad' }] });
    const state = await f.store.readJson<{ messages: unknown[]; lastSuccessAt: string }>('plan', join(f.store.paths.dir, 'notification-messages.json'));
    expect(state?.messages).toContainEqual(payload);
    expect(state?.lastSuccessAt).toBe('2026-10-27T12:00:00.000Z');
    expect(await readFile(join(f.store.paths.dir, 'notification-messages.json'), 'utf8')).not.toContain('Notification test');
    await f.run(['verify', payload.code]);
    expect(f.outputs.at(-1)).toMatchObject({ valid: true, keyId: f.key.keyId });
  });
  test('test reports a missing channel credential without stopping delivery to the other channels', async () => {
    const f = await setup([{ id: 'missing', kind: 'webhook' }, { id: 'ops', kind: 'webhook' }]);
    await f.vault.set('notify/ops/url', Buffer.from('https://hooks.example.test/private'));
    await f.run(['test']);
    expect(f.http.calls).toHaveLength(1);
    expect(f.outputs.at(-1)).toMatchObject({ delivered: ['ops'], failed: [{ id: 'missing', reason: 'Webhook delivery failed' }] });
  });
  test('verify --file accepts the configured watcher key and rejects edits', async () => {
    const f = await setup(); const file = join(f.cwd, 'notification.json');
    const message = signMessage({ id: 'm', at: '2026-10-27T12:00:00Z', kind: 'test', severity: 'info', title: 'Watcher test', lines: [] }, f.watcher);
    await writeFile(file, JSON.stringify(message)); await f.run(['verify', '--file', file]);
    expect(f.outputs.at(-1)).toMatchObject({ valid: true, keyId: f.watcher.keyId });
    await writeFile(file, JSON.stringify({ ...message, title: 'Edited' }));
    await expect(f.run(['verify', '--file', file])).rejects.toThrow(/signature/i);
  });
  test('verify rejects a bare unknown code and oversized files without reflecting contents', async () => {
    const f = await setup(); await expect(f.run(['verify', 'AAAA-BBBB'])).rejects.toThrow(/not found/i);
    const file = join(f.cwd, 'large.json'); await writeFile(file, 'private-secret'.repeat(100_000));
    await expect(f.run(['verify', '--file', file])).rejects.toThrow(/too large/i);
  });
});

test('notification egress contains every exact configured URL and adds custom hosts as user rules', async () => {
  const vault = createFakeVault({ 'notify/chat/botToken': Buffer.from('123:private-token'), 'notify/chat/chatId': Buffer.from('1234'),
    'notify/discord/webhookUrl': Buffer.from('https://discord.com/api/webhooks/123/private'), 'notify/web/url': Buffer.from('https://hooks.example.test/private') });
  const settings: NotifyChannelSettings[] = [{ id: 'chat', kind: 'telegram' }, { id: 'discord', kind: 'discord' },
    { id: 'web', kind: 'webhook' }, { id: 'push', kind: 'ntfy', server: 'https://push.example.test' },
    { id: 'mail', kind: 'resend', from: 'from@example.test', to: ['to@example.test'] }];
  const egress = await notificationEgress(settings, vault);
  expect(egress.trustedUrls).toEqual(['https://api.telegram.org/bot123:private-token/sendMessage', 'https://discord.com/api/webhooks/123/private?wait=true',
    'https://hooks.example.test/private', 'https://push.example.test/', 'https://api.resend.com/emails']);
  expect(egress.rules).toEqual(egress.trustedUrls.map(url => ({ host: new URL(url).hostname, owner: 'user', purpose: 'notification channel you configured' })));
});

test('notification factory shares the guarded client, preserving signed payloads and host-only receipt', async () => {
  const f = await setup([{ id: 'ops', kind: 'webhook' }]);
  await f.vault.set('notify/ops/url', Buffer.from('https://custom.example.test/sk-proj-abcdefghijklmnopqrstuvwxyz1234567890'));
  const egress = await notificationEgress(f.context.settings, f.vault); const receipt: unknown[] = [];
  const http = createGuardedHttp(f.http, { rules: egress.rules, trustedUrls: egress.trustedUrls,
    receipt: { record: async value => { receipt.push(value); }, summarize: async () => [] } });
  const channels = await createNotificationChannels(f.context.settings, { ...f.context, http });
  const m = signMessage({ id: 'm', at: '2026-10-27T12:00:00Z', kind: 'test', severity: 'info', title: 'Test', lines: [] }, f.key);
  await channels[0]!.send(m); expect(f.http.calls).toHaveLength(1);
  expect(receipt).toEqual([expect.objectContaining({ host: 'custom.example.test', allowed: true })]);
  expect(JSON.stringify(receipt)).not.toContain('sk-proj-');
});

test('ntfy egress trusts the factory root URL and transmits its private topic only in the request body', async () => {
  const f = await setup([{ id: 'push', kind: 'ntfy', server: 'https://push.example.test' }]);
  await f.vault.set('notify/push/topic', Buffer.from('private-topic'));
  const egress = await notificationEgress(f.context.settings, f.vault);
  expect(egress.trustedUrls).toEqual(['https://push.example.test/']);
  const http = createGuardedHttp(f.http, { rules: egress.rules, trustedUrls: egress.trustedUrls });
  const channels = await createNotificationChannels(f.context.settings, { ...f.context, http });
  await channels[0]!.send(signMessage({ id: 'test', at: '2026-10-27T12:00:00Z', kind: 'test', severity: 'info', title: 'Test', lines: [] }, f.key));
  expect(f.http.calls[0]?.url).toBe('https://push.example.test/');
  expect(JSON.parse(f.http.calls[0]!.body!).topic).toBe('private-topic');
  expect(f.http.calls[0]?.url).not.toContain('private-topic');
});
