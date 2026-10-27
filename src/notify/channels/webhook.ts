import type { NotifyChannel } from '../../types.js';
import { assertHeader, assertSafeMessage, httpsUrl, postJson } from '../message.js';
import type { ChannelDeps } from '../message.js';

export interface WebhookConfig { url: string; id?: string }

export function createWebhookChannel(config: WebhookConfig, deps: ChannelDeps): NotifyChannel {
  httpsUrl(config.url);
  const url = config.url;
  deps.redactor.register(url);
  return { id: config.id ?? 'webhook', kind: 'webhook', async send(m) {
    assertSafeMessage(m, deps.redactor);
    assertHeader(m.keyId); assertHeader(m.sig); assertHeader(m.code);
    await postJson(deps, 'webhook', url, m, { 'X-Keysentry-Signature': `v1,keyId=${m.keyId},sig=${m.sig}`, 'X-Keysentry-Code': m.code });
  } };
}
