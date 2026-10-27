import type { Command } from 'commander';
import { randomUUID } from 'node:crypto';
import { open } from 'node:fs/promises';
import { join } from 'node:path';
import type { DeviceKey } from '../security/index.js';
import type { StateStore } from '../core/index.js';
import type { HttpClient, Logger, NotifyChannel, NotifyChannelKind, Redactor, Vault, NetworkReceipt, AuditLog, SignedNotifyMessage, EgressRule } from '../types.js';
import { createConsoleChannel, createDiscordChannel, createDispatcher, createNtfyChannel, createResendChannel, createSlackChannel,
  createSmtpChannel, createTelegramChannel, createWebhookChannel, discordWebhookUrl, signMessage, telegramUrl, verifyMessage } from '../notify/index.js';
import { rulesForUserUrls } from '../net/index.js';
import { promptVaultValue, type PromptIO } from './prompts.js';
import { CliError } from './errors.js';

export interface NotifyChannelSettings {
  id: string; kind: NotifyChannelKind; server?: string; from?: string; to?: string[]; host?: string; port?: 465 | 587;
}
export interface NotificationContext {
  settings: NotifyChannelSettings[]; vault: Vault; http: HttpClient; redactor: Redactor; log: Logger; store: StateStore;
  deviceKey(): Promise<DeviceKey>; watcherPublicKeys?(): Promise<Buffer[]>;
  saveSettings(settings: NotifyChannelSettings[]): Promise<void>;
  now?: () => Date; receipt?: NetworkReceipt; audit?: AuditLog; write?: (text: string) => void;
}
export interface NotificationCommandsOptions {
  getContext(): Promise<NotificationContext>; human(action: string): void;
  emit(value: unknown, human?: string): void; prompt?(field: string, secret: boolean): Promise<string | null>;
  promptIO?: PromptIO; write?: (text: string) => void;
}

const kinds: readonly NotifyChannelKind[] = ['telegram', 'discord', 'slack', 'ntfy', 'webhook', 'resend', 'smtp', 'console'];
const identifier = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/;
const secretName = (id: string, field: string) => `notify/${id}/${field}`;
const messagePath = (store: StateStore) => join(store.paths.dir, 'notification-messages.json');
interface MessageCache { messages: SignedNotifyMessage[]; lastSuccessAt: string | null }

function validId(id: string): void {
  if (!identifier.test(id) || id === 'relay') throw new CliError('Use a channel id with 1 to 64 letters, numbers, underscores or dashes. The id relay is reserved.');
}
async function value(vault: Vault, id: string, field: string, optional = false): Promise<string> {
  validId(id);
  const bytes = await vault.get(secretName(id, field));
  if (!bytes) { if (optional) return ''; throw new CliError('A notification credential is missing. Remove and add the channel again.'); }
  try { return bytes.toString('utf8'); } finally { bytes.fill(0); }
}
const required = (item: string | undefined): string => {
  if (!item) throw new CliError('A notification setting is missing. Remove and add the channel again.');
  return item;
};

/** Resolve credentials only in memory. Callers supply their already guarded HTTP client. */
export async function createNotificationChannels(settings: NotifyChannelSettings[], deps: Pick<NotificationContext, 'vault' | 'http' | 'redactor'> & Partial<Pick<NotificationContext, 'receipt' | 'write'>>): Promise<NotifyChannel[]> {
  const channels: NotifyChannel[] = [];
  for (const setting of settings) {
    validId(setting.id);
    const { id, kind } = setting;
    const secret = (field: string, optional = false) => value(deps.vault, id, field, optional);
    try {
      switch (kind) {
        case 'telegram': channels.push(createTelegramChannel({ id, botToken: await secret('botToken'), chatId: await secret('chatId') }, deps)); break;
        case 'discord': channels.push(createDiscordChannel({ id, webhookUrl: await secret('webhookUrl') }, deps)); break;
        case 'slack': channels.push(createSlackChannel({ id, webhookUrl: await secret('webhookUrl') }, deps)); break;
        case 'ntfy': channels.push(createNtfyChannel({ id, server: required(setting.server), topic: await secret('topic'), token: await secret('token', true) || undefined }, deps)); break;
        case 'webhook': channels.push(createWebhookChannel({ id, url: await secret('url') }, deps)); break;
        case 'resend': channels.push(createResendChannel({ id, apiKey: await secret('apiKey'), from: required(setting.from), to: setting.to ?? [] }, deps)); break;
        case 'smtp': channels.push(createSmtpChannel({ id, host: required(setting.host), port: setting.port ?? 465, username: await secret('username'), password: await secret('password'),
          from: required(setting.from), to: setting.to ?? [], receipt: deps.receipt }, deps)); break;
        case 'console': channels.push({ ...createConsoleChannel(deps.write ?? (() => {}), deps), id }); break;
        default: throw new Error();
      }
    } catch { throw new CliError('The notification channel configuration is incomplete or invalid.'); }
  }
  if (new Set(channels.map(channel => channel.id)).size !== channels.length) throw new CliError('Notification channel ids must be unique.');
  return channels;
}

/** Exact credential URLs remain in memory; rules contain host names only. */
export async function notificationEgress(settings: NotifyChannelSettings[], vault: Vault): Promise<{ rules: EgressRule[]; trustedUrls: string[] }> {
  const trustedUrls: string[] = [];
  try {
    for (const setting of settings) {
      validId(setting.id);
      switch (setting.kind) {
        case 'telegram': trustedUrls.push(telegramUrl(await value(vault, setting.id, 'botToken'))); break;
        case 'discord': trustedUrls.push(discordWebhookUrl(await value(vault, setting.id, 'webhookUrl'))); break;
        case 'slack': trustedUrls.push(await value(vault, setting.id, 'webhookUrl')); break;
        case 'webhook': trustedUrls.push(await value(vault, setting.id, 'url')); break;
        case 'ntfy': trustedUrls.push(new URL('/', required(setting.server)).href); break;
        case 'resend': trustedUrls.push('https://api.resend.com/emails'); break;
        case 'smtp': case 'console': break;
        default: throw new Error();
      }
    }
    return { rules: rulesForUserUrls(trustedUrls, 'notification channel you configured'), trustedUrls };
  } catch { throw new CliError('The notification channel URL is incomplete or invalid.'); }
}

function localOnly(opts: { relay?: boolean; remote?: boolean | string }): void {
  if (opts.relay !== undefined || opts.remote !== undefined) throw new CliError('Notification settings can only be changed with the local CLI.');
}
async function audit(context: NotificationContext, kind: string, summary: string): Promise<void> {
  await context.audit?.append({ kind, summary });
}
export async function cacheNotificationMessage(context: Pick<NotificationContext, 'store' | 'now'>, message: SignedNotifyMessage, delivered: boolean): Promise<void> {
  const previous = await context.store.readJson<MessageCache>('plan', messagePath(context.store));
  await context.store.writeJson('plan', messagePath(context.store), { messages: [...(previous?.messages ?? []), message].slice(-100),
    lastSuccessAt: delivered ? (context.now?.() ?? new Date()).toISOString() : previous?.lastSuccessAt ?? null } satisfies MessageCache);
}

export function registerNotificationCommands(program: Command, options: NotificationCommandsOptions): void {
  const notify = program.command('notify').description('Manage signed notification channels');
  const prompt = options.prompt ?? ((field: string, _secret: boolean) => promptVaultValue(field, options.write ?? (() => {}), options.promptIO));
  notify.command('add <kind>').description('Add a channel locally; secret settings use hidden input')
    .option('--relay', 'Remote changes are not supported').option('--remote [url]', 'Remote changes are not supported')
    .action(async (kind: string, opts: { relay?: boolean; remote?: boolean | string }) => {
      options.human('add a notification channel'); localOnly(opts);
      if (!kinds.includes(kind as NotifyChannelKind)) throw new CliError('Unknown notification kind. Choose telegram, discord, slack, ntfy, webhook, resend, smtp or console.');
      const context = await options.getContext();
      const id = await prompt('channel id', false);
      if (id === null) { options.emit({ cancelled: true }, 'Channel setup cancelled.'); return; }
      validId(id);
      if (context.settings.some(setting => setting.id === id) || (await context.vault.list(`notify/${id}/`)).length) throw new CliError('That notification channel id is already in use.');
      const setting: NotifyChannelSettings = { id, kind: kind as NotifyChannelKind }; const secrets = new Map<string, string>();
      const ask = async (field: string, secret: boolean, optional = false): Promise<string> => {
        const result = await prompt(field, secret);
        if (result === null || result === '') { if (optional) return ''; throw new CliError('Channel setup cancelled. No settings were saved.'); }
        if (Buffer.byteLength(result) > 16_384 || /[\x00-\x1f\x7f]/.test(result)) throw new CliError('The notification setting contains unsupported characters or is too long.');
        if (secret) { secrets.set(field, result); context.redactor.register(result); }
        return result;
      };
      const email = async () => { setting.from = await ask('from', false); setting.to = (await ask('to', false)).split(',').map(item => item.trim()).filter(Boolean); };
      switch (setting.kind) {
        case 'telegram': await ask('botToken', true); await ask('chatId', true); break;
        case 'discord': case 'slack': await ask('webhookUrl', true); break;
        case 'webhook': await ask('url', true); break;
        case 'ntfy': setting.server = await ask('server', false); await ask('topic', true); await ask('token', true, true); break;
        case 'resend': await email(); await ask('apiKey', true); break;
        case 'smtp': {
          setting.host = await ask('host', false); const port = await ask('port (465 or 587)', false);
          if (port !== '465' && port !== '587') throw new CliError('SMTP port must be 465 or 587.');
          setting.port = Number(port) as 465 | 587; await email(); await ask('username', true); await ask('password', true); break;
        }
        case 'console': break;
      }
      // Validate before committing any vault or configuration change.
      const staged: Vault = { ...context.vault, get: async name => {
        const field = name.startsWith(`notify/${id}/`) ? name.slice(`notify/${id}/`.length) : undefined;
        return field !== undefined && secrets.has(field) ? Buffer.from(secrets.get(field)!) : context.vault.get(name);
      } };
      await notificationEgress([setting], staged); await createNotificationChannels([setting], { ...context, vault: staged });
      const written: string[] = [];
      try {
        for (const [field, secret] of secrets) {
          const name = secretName(id, field); const bytes = Buffer.from(secret);
          try { await context.vault.set(name, bytes); written.push(name); } finally { bytes.fill(0); }
        }
        await context.saveSettings([...context.settings, setting]);
      } catch {
        for (const name of written) try { await context.vault.delete(name); } catch { /* Preserve the original fixed error. */ }
        throw new CliError('The notification channel could not be saved.');
      }
      await audit(context, 'notify-add', 'Notification channel added locally.');
      options.emit({ id, kind, added: true }, `Notification channel ${id} added.`);
    });
  notify.command('list').description('List configured channel ids and kinds').action(async () => {
    const context = await options.getContext(); const channels = context.settings.map(({ id, kind }) => ({ id, kind }));
    options.emit(channels, channels.length ? channels.map(channel => `${channel.id}: ${channel.kind}`).join('\n') : 'No notification channels are configured.');
  });
  notify.command('remove <id>').description('Remove a channel and its saved credentials locally')
    .option('--relay', 'Remote changes are not supported').option('--remote [url]', 'Remote changes are not supported')
    .action(async (id: string, opts: { relay?: boolean; remote?: boolean | string }) => {
      options.human('remove a notification channel'); localOnly(opts); validId(id);
      const context = await options.getContext();
      if (!context.settings.some(setting => setting.id === id)) throw new CliError('That notification channel was not found.');
      await context.saveSettings(context.settings.filter(setting => setting.id !== id));
      for (const name of await context.vault.list(`notify/${id}/`)) await context.vault.delete(name);
      await audit(context, 'notify-remove', 'Notification channel removed locally.');
      options.emit({ id, removed: true }, `Notification channel ${id} removed.`);
    });
  notify.command('test').description('Send a signed test to every channel').action(async () => {
    options.human('test notification channels');
    const context = await options.getContext(); const channels: NotifyChannel[] = [];
    for (const setting of context.settings) {
      try { channels.push(...await createNotificationChannels([setting], context)); }
      catch {
        channels.push({ id: setting.id, kind: setting.kind, async send() { throw new Error('Notification configuration is incomplete.'); } });
      }
    }
    const message = signMessage({ id: randomUUID(), at: (context.now?.() ?? new Date()).toISOString(), kind: 'test', severity: 'info', title: 'Notification test',
      lines: ['keysentry can reach this notification channel.'] }, await context.deviceKey());
    const result = await createDispatcher(channels, { log: context.log, now: context.now, retries: 1 }).send(message);
    await cacheNotificationMessage(context, message, result.delivered.length > 0);
    await audit(context, 'notify-test', 'Signed notification test completed.');
    options.emit({ ...result, code: message.code }, channels.length ? `Delivered: ${result.delivered.join(', ') || 'none'}\nFailed: ${result.failed.map(item => item.id).join(', ') || 'none'}\nVerification code: ${message.code}` : 'No notification channels are configured.');
  });
  notify.command('verify [code]').description('Verify a saved message code or a signed JSON message')
    .option('--file <json>', 'Read one signed notification JSON file').action(async (code: string | undefined, opts: { file?: string }) => {
      if (!!code === !!opts.file) throw new CliError('Provide a saved notification code or --file with signed JSON.');
      const context = await options.getContext(); let message: SignedNotifyMessage;
      if (opts.file) {
        let handle;
        try {
          handle = await open(opts.file, 'r');
          if ((await handle.stat()).size > 1_048_576) throw new CliError('The notification file is too large.');
          const buffer = Buffer.alloc(1_048_577); const read = await handle.read(buffer, 0, buffer.length, 0);
          if (read.bytesRead > 1_048_576) throw new CliError('The notification file is too large.');
          message = JSON.parse(buffer.subarray(0, read.bytesRead).toString('utf8')) as SignedNotifyMessage;
        } catch (error) { if (error instanceof CliError) throw error; throw new CliError('The signed notification file could not be read.'); }
        finally { await handle?.close(); }
      } else {
        const normalized = code!.toUpperCase();
        if (!/^[A-Z2-7]{4}-[A-Z2-7]{4}$/.test(normalized)) throw new CliError('That notification code was not found in local saved messages. Use --file for a signed message received elsewhere.');
        const cache = await context.store.readJson<MessageCache>('plan', messagePath(context.store));
        const found = cache?.messages.find(item => item.code === normalized);
        if (!found) throw new CliError('That notification code was not found in local saved messages. Use --file for a signed message received elsewhere.');
        message = found;
      }
      const key = await context.deviceKey(); const trusted = [key.publicKeyDer, ...await context.watcherPublicKeys?.() ?? []];
      if (!trusted.some(publicKey => verifyMessage(message, publicKey))) throw new CliError('The notification signature did not verify with a trusted local key.');
      options.emit({ valid: true, id: message.id, keyId: message.keyId, code: message.code }, `Notification signature verified. Code: ${message.code}`);
    });
}
