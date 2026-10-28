import { createRedactor } from '../../core/redact.js';
import { createGuardedHttp } from '../../net/index.js';
import { createDispatcher } from '../../notify/index.js';
import { createMemoryVault } from '../../vault/index.js';
import { createNotificationChannels, notificationEgress } from '../../cli/notifications.js';
import type { HttpClient, Logger, SignedNotifyMessage } from '../../types.js';
import type { BoxNoticeKit } from './payload.js';

/**
 * A locked box's one path to the user: the channels from the sealed notice kit, with their secrets in a memory-only
 * vault and egress limited to exactly those channel URLs.
 */
export function createNoticeSender(options: { transport: HttpClient; log: Logger }): (kit: BoxNoticeKit, message: SignedNotifyMessage) => Promise<void> {
  return async (kit, message) => {
    const vault = createMemoryVault();
    for (const secret of kit.secrets) await vault.set(secret.name, Buffer.from(secret.value, 'utf8'));
    const egress = await notificationEgress(kit.channels, vault);
    const http = createGuardedHttp(options.transport, { rules: egress.rules, trustedUrls: egress.trustedUrls, log: options.log });
    const redactor = createRedactor();
    for (const secret of kit.secrets) redactor.register(secret.value);
    const channels = await createNotificationChannels(kit.channels, { vault, http, redactor });
    const result = await createDispatcher(channels, { log: options.log }).send(message);
    if (result.delivered.length === 0) throw new Error('No channel delivered the box notice.');
  };
}
