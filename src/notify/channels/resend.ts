import type { NotifyChannel } from '../../types.js';
import { assertHeader, assertSafeMessage, postJson } from '../message.js';
import type { ChannelDeps } from '../message.js';
import { renderLimited } from '../render.js';

export interface ResendConfig { apiKey: string; from: string; to: string | string[]; id?: string }
// Resend caps the email at 40 MB. Leave room for JSON and envelope overhead.
export const RESEND_TEXT_LIMIT = 40_000_000 - 65_536;

export function createResendChannel(config: ResendConfig, deps: ChannelDeps): NotifyChannel {
  assertHeader(config.from);
  const to = typeof config.to === 'string' ? config.to : [...config.to];
  const recipients = typeof to === 'string' ? [to] : to;
  if (recipients.length < 1 || recipients.length > 50) throw new Error('Invalid Resend configuration');
  recipients.forEach(assertHeader);
  deps.redactor.register(config.apiKey);
  return { id: config.id ?? 'resend', kind: 'resend', async send(m) {
    assertSafeMessage(m, deps.redactor);
    assertHeader(m.title); assertHeader(m.id);
    if (m.id.length > 256) throw new Error('Invalid notification header');
    await postJson(deps, 'resend', 'https://api.resend.com/emails', {
      from: config.from, to, subject: m.title, text: renderLimited(m, { limit: RESEND_TEXT_LIMIT, bytes: true }),
    }, { Authorization: `Bearer ${config.apiKey}`, 'Idempotency-Key': m.id });
  } };
}
