import type { NotifyChannel } from '../../types.js';
import { assertSafeMessage, jsonReply, NotifyDeliveryError, postJson, retryDelay, escapeHtml } from '../message.js';
import type { ChannelDeps } from '../message.js';
import { renderLimited } from '../render.js';

export interface TelegramConfig { botToken: string; chatId: string; id?: string }

export function telegramUrl(botToken: string): string {
  if (!/^[A-Za-z0-9_:-]+$/.test(botToken)) throw new Error('Invalid Telegram configuration');
  return `https://api.telegram.org/bot${botToken}/sendMessage`;
}

export function createTelegramChannel(config: TelegramConfig, deps: ChannelDeps): NotifyChannel {
  const url = telegramUrl(config.botToken);
  deps.redactor.register(config.botToken);
  return { id: config.id ?? 'telegram', kind: 'telegram', async send(m) {
    assertSafeMessage(m, deps.redactor);
    const response = await postJson(deps, 'telegram', url, {
      chat_id: config.chatId, text: renderLimited(m, { limit: 4096, escape: escapeHtml }), parse_mode: 'HTML',
      link_preview_options: { is_disabled: true }, disable_notification: m.severity === 'info',
    });
    const body = jsonReply(response);
    if (body?.ok !== true) {
      const status = typeof body?.error_code === 'number' && Number.isInteger(body.error_code) && body.error_code >= 400 && body.error_code <= 599 ? body.error_code : undefined;
      const failure = { ...response, status: status ?? response.status };
      throw new NotifyDeliveryError('telegram', status, retryDelay(failure));
    }
  } };
}
