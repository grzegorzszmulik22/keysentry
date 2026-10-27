import type { NotifyChannel } from '../../types.js';
import { assertSafeMessage, httpsUrl, postJson } from '../message.js';
import type { ChannelDeps } from '../message.js';
import { renderLimited } from '../render.js';

export interface DiscordConfig { webhookUrl: string; id?: string }

export function discordWebhookUrl(webhookUrl: string): string {
  const url = httpsUrl(webhookUrl);
  if (url.hostname !== 'discord.com' || !/^\/api\/(?:v\d+\/)?webhooks\/[^/]+\/[^/]+$/.test(url.pathname)) throw new Error('Invalid Discord configuration');
  url.searchParams.set('wait', 'true');
  return url.href;
}

export function createDiscordChannel(config: DiscordConfig, deps: ChannelDeps): NotifyChannel {
  const url = discordWebhookUrl(config.webhookUrl);
  deps.redactor.register(config.webhookUrl);
  deps.redactor.register(new URL(url).pathname.split('/').at(-1)!);
  return { id: config.id ?? 'discord', kind: 'discord', async send(m) {
    assertSafeMessage(m, deps.redactor);
    await postJson(deps, 'discord', url, {
      content: renderLimited(m, { limit: 2000, escape: value => value.replaceAll('@', '@\u200b') }), allowed_mentions: { parse: [] },
    });
  } };
}
