import type { NotifyChannel } from '../../types.js';
import { assertSafeMessage, escapeHtml, httpsUrl, NotifyDeliveryError, postJson } from '../message.js';
import type { ChannelDeps } from '../message.js';
import { renderLimited } from '../render.js';

export interface SlackConfig { webhookUrl: string; id?: string }

export function createSlackChannel(config: SlackConfig, deps: ChannelDeps): NotifyChannel {
  const parsed = httpsUrl(config.webhookUrl);
  if (parsed.hostname !== 'hooks.slack.com' || !/^\/services\/[^/]+\/[^/]+\/[^/]+$/.test(parsed.pathname)) throw new Error('Invalid Slack configuration');
  const url = config.webhookUrl;
  deps.redactor.register(url);
  deps.redactor.register(parsed.pathname.split('/').at(-1)!);
  return { id: config.id ?? 'slack', kind: 'slack', async send(m) {
    assertSafeMessage(m, deps.redactor);
    const response = await postJson(deps, 'slack', url, { text: renderLimited(m, { limit: 4000, escape: escapeHtml }) });
    if (response.text.trim() !== 'ok') throw new NotifyDeliveryError('slack');
  } };
}
