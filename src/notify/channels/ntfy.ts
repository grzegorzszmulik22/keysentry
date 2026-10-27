import type { NotifyChannel } from '../../types.js';
import { assertSafeMessage, httpsUrl, postJson } from '../message.js';
import type { ChannelDeps } from '../message.js';
import { renderLimited } from '../render.js';

export interface NtfyConfig { server: string; topic: string; token?: string; id?: string }

export function createNtfyChannel(config: NtfyConfig, deps: ChannelDeps): NotifyChannel {
  const server = httpsUrl(config.server);
  if (server.pathname !== '/' || server.search || !/^[A-Za-z0-9_-]{1,64}$/.test(config.topic)) throw new Error('Invalid ntfy configuration');
  const url = server.origin + '/';
  if (config.token) deps.redactor.register(config.token);
  return { id: config.id ?? 'ntfy', kind: 'ntfy', async send(m) {
    assertSafeMessage(m, deps.redactor);
    await postJson(deps, 'ntfy', url, { topic: config.topic, message: renderLimited(m, { limit: 4096, bytes: true }),
      priority: { info: 3, warning: 4, urgent: 5 }[m.severity] }, config.token ? { Authorization: `Bearer ${config.token}` } : {});
  } };
}
