// Tell the team's notification channels about a team dashboard event that matters even when it is allowed: a key value
// was revealed (review M2) or autopilot was disarmed (review M3). Messages are signed like every other notification,
// routed by the roster, and carry no value: only what happened and which member did it.
import { randomUUID } from 'node:crypto';
import { signMessage } from '../notify/index.js';
import { createRoutedDispatcher, loadTeam } from '../team/index.js';
import type { NotifySeverity } from '../types.js';
import { createNotificationChannels, notificationEgress } from './notifications.js';
import type { KeysentryRuntime } from './runtime.js';

export interface TeamNotice { kind: string; severity: NotifySeverity; title: string; lines: string[] }

/**
 * Best effort: a delivery failure never undoes or blocks the event it reports, but it is recorded in the audit log.
 * Returns how many channels delivered and failed.
 */
export async function notifyTeam(rt: KeysentryRuntime, notice: TeamNotice): Promise<{ delivered: number; failed: number }> {
  const settings = rt.config.settings.notify.channels;
  let delivered = 0;
  let failed = settings.length;
  try {
    if (!settings.length) return { delivered: 0, failed: 0 };
    const egress = await notificationEgress(settings, rt.vault);
    const http = rt.httpForUrls(egress.trustedUrls, 'notification channel you configured');
    const channels = await createNotificationChannels(settings, { vault: rt.vault, http, redactor: rt.redactor, receipt: rt.receipt });
    const team = await loadTeam(rt.store, { anchor: rt.teamAnchors.roster });
    const key = await rt.signingKey();
    try {
      const signed = signMessage({ id: `team-${randomUUID()}`, at: rt.now().toISOString(), kind: notice.kind, severity: notice.severity, title: notice.title,
        lines: [...notice.lines] }, key);
      const result = await createRoutedDispatcher(channels, team?.roster.roster ?? null, { log: rt.log, now: rt.now, retries: 1 }).send(signed);
      delivered = result.delivered.length; failed = result.failed.length;
    } finally { key.privateKeyDer.fill(0); }
  } catch {
    rt.log.warn('The team notification could not be sent. Check the notification channels with keysentry notify test.');
  }
  await rt.audit.append({ kind: 'notify:team', summary: delivered > 0 ? 'Team notification sent.' : 'Team notification not delivered.',
    data: { notice: notice.kind, delivered, failed } }).catch(() => rt.log.warn('A team notification could not be added to the audit log.'));
  return { delivered, failed };
}
