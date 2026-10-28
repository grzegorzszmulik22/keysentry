import { describe, expect, test } from 'vitest';
import { createRoutedDispatcher, routeChannels } from '../../src/team/index.js';
import { NotifyDeliveryError } from '../../src/notify/index.js';
import type { NotifyChannel, NotifySeverity, SignedNotifyMessage, TeamRoster } from '../../src/types.js';
import { silentLogger } from '../helpers/fake-http.js';
import { rosterOf, testMember } from './helpers.js';

const ana = testMember('ana', 'admin');
const ben = testMember('ben', 'operator');
const cat = testMember('cat', 'viewer');

function roster(assign: Record<string, { channels: string[]; minSeverity: NotifySeverity }>): TeamRoster {
  const value = rosterOf([ana, ben, cat]);
  for (const member of value.members) if (assign[member.id]) member.notify = assign[member.id];
  return value;
}
const ids = ['ops-slack', 'ana-phone', 'ben-mail', 'console'];
const message = (severity: NotifySeverity) => ({ severity });

describe('routeChannels', () => {
  test('without a roster every channel receives everything', () => {
    expect(routeChannels(null, ids, message('info'))).toEqual(ids);
  });

  test('assigned channels receive only messages at or above the member\'s minimum; unassigned ones receive everything', () => {
    const team = roster({ ana: { channels: ['ana-phone'], minSeverity: 'urgent' }, ben: { channels: ['ben-mail'], minSeverity: 'warning' } });
    expect(routeChannels(team, ids, message('info'))).toEqual(['ops-slack', 'console']);
    expect(routeChannels(team, ids, message('warning'))).toEqual(['ops-slack', 'ben-mail', 'console']);
    expect(routeChannels(team, ids, message('urgent'))).toEqual(ids);
  });

  test('a channel shared by members uses the lowest minimum; unknown severities are treated as urgent', () => {
    const team = roster({ ana: { channels: ['ops-slack'], minSeverity: 'urgent' }, cat: { channels: ['ops-slack'], minSeverity: 'warning' } });
    expect(routeChannels(team, ['ops-slack'], message('info'))).toEqual([]);
    expect(routeChannels(team, ['ops-slack'], message('warning'))).toEqual(['ops-slack']);
    expect(routeChannels(team, ['ops-slack'], { severity: 'bogus' as NotifySeverity })).toEqual(['ops-slack']);
  });

  test('a member with an empty channel list changes nothing', () => {
    expect(routeChannels(roster({ ana: { channels: [], minSeverity: 'urgent' } }), ids, message('info'))).toEqual(ids);
  });
});

describe('createRoutedDispatcher', () => {
  const signed = (severity: NotifySeverity): SignedNotifyMessage => ({ id: 'm1', at: '2026-10-28T10:00:00.000Z', kind: 'test', severity, title: 'Test',
    lines: [], keyId: 'k', sig: 's', code: 'AAAA-BBBB' });
  function channel(id: string, kind: NotifyChannel['kind'], sent: string[], fail = false): NotifyChannel {
    return { id, kind, async send() { if (fail) throw new NotifyDeliveryError(kind, 503); sent.push(id); } };
  }

  test('sends each message only to its routed channels and reports the skipped ones', async () => {
    const sent: string[] = [];
    const team = roster({ ana: { channels: ['ana-phone'], minSeverity: 'urgent' } });
    const dispatcher = createRoutedDispatcher([channel('ops-slack', 'slack', sent), channel('ana-phone', 'ntfy', sent)], team,
      { log: silentLogger, now: () => new Date('2026-10-28T10:00:00.000Z'), sleep: async () => {} });
    expect(await dispatcher.send(signed('info'))).toEqual({ delivered: ['ops-slack'], failed: [], skipped: ['ana-phone'] });
    expect(await dispatcher.send(signed('urgent'))).toEqual({ delivered: ['ops-slack', 'ana-phone'], failed: [], skipped: [] });
    expect(sent).toEqual(['ops-slack', 'ops-slack', 'ana-phone']);
    expect(dispatcher.lastExternalSuccessAt()).toBe('2026-10-28T10:00:00.000Z');
  });

  test('keeps per-channel retries and fixed failure reasons; when everything is skipped nothing was expected', async () => {
    const sent: string[] = [];
    let current: TeamRoster | null = roster({ ben: { channels: ['ben-mail'], minSeverity: 'urgent' } });
    const dispatcher = createRoutedDispatcher([channel('ben-mail', 'webhook', sent, true)], () => current,
      { log: silentLogger, retries: 2, sleep: async () => {} });
    expect(await dispatcher.send(signed('info'))).toEqual({ delivered: [], failed: [], skipped: ['ben-mail'] });
    expect(await dispatcher.send(signed('urgent'))).toEqual({ delivered: [], failed: [{ id: 'ben-mail', reason: 'Webhook returned 503' }], skipped: [] });
    current = null;
    expect((await dispatcher.send(signed('info'))).skipped).toEqual([]);
    expect(dispatcher.lastSuccessAt()).toBeNull();
  });

  test('refuses duplicate channel ids', () => {
    expect(() => createRoutedDispatcher([channel('a', 'slack', []), channel('a', 'ntfy', [])], null, { log: silentLogger })).toThrow();
  });
});
