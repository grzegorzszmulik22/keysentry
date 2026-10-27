import { describe, expect, it } from 'vitest';
import type { JournalEntry, TimelineEvent } from '../../src/types.js';
import { createRedactor } from '../../src/core/redact.js';
import { buildTimeline, renderTimelineMarkdown, type TimelineAuditEntry } from '../../src/report/timeline.js';

const at = (seconds: number) => new Date(Date.UTC(2026, 9, 27, 12, 0, seconds)).toISOString();
function entry(event: JournalEntry['event'], seconds = 0, fields: Partial<JournalEntry> = {}): JournalEntry {
  return { at: at(seconds), planId: 'plan-1', event, ...fields };
}
function audit(kind: string, seconds = 0, data?: Record<string, unknown>): TimelineAuditEntry {
  return { at: at(seconds), kind, summary: 'Untrusted source summary', data };
}

describe('incident timeline', () => {
  it('orders journal and audit entries by instant, normalizes UTC, and preserves equal-time order', () => {
    const journal = [entry('written', 2, { clusterId: 'b' }), entry('created', 1, { clusterId: 'b' })];
    const logs = [audit('notify:sent', 2), { ...audit('autopilot:detected'), at: '2026-10-27T14:00:00+02:00' }];
    const before = JSON.stringify({ journal, logs });
    const result = buildTimeline(journal, logs);
    expect(result.map(event => [event.at, event.kind])).toEqual([
      [at(0), 'detected'], [at(1), 'created'], [at(2), 'written'], [at(2), 'notified'],
    ]);
    expect(JSON.stringify({ journal, logs })).toBe(before);
  });

  it.each([
    ['plan-start', 'decided', 'Rotation started'],
    ['created', 'created', 'New key created (key 1 of 1)'],
    ['written', 'written', 'New key written (key 1 of 1)'],
    ['redeploy', 'deployed', 'Deployment requested'],
    ['deploy-result', 'deployed', 'Deployment succeeded'],
    ['verified', 'verified', 'New key verified (key 1 of 1)'],
    ['revoked', 'revoked', 'Old key revoked (key 1 of 1)'],
    ['failed', 'failed', 'Rotation step failed (key 1 of 1)'],
    ['plan-end', 'decided', 'Rotation finished'],
    ['value-stored', 'decided', 'Recovery copy stored (key 1 of 1)'],
    ['grace-start', 'grace', 'Grace period started (key 1 of 1)'],
    ['grace-end', 'grace', 'Grace period ended (key 1 of 1)'],
    ['undo', 'undone', 'Old key restored (key 1 of 1)'],
    ['resume', 'decided', 'Rotation resumed'],
    ['shredded', 'decided', 'Recovery copies removed'],
    ['orphan-suspected', 'failed', 'A provider key may need review (key 1 of 1)'],
  ] as const)('includes the %s journal event', (event, kind, summary) => {
    const result = buildTimeline([entry(event, 0, { clusterId: 'a', data: { state: 'success' } })], []);
    expect(result).toEqual([{ at: at(0), kind, summary, clusterId: 'a' }]);
  });

  it('describes deployments, incomplete endings and grace without claiming activation or completion', () => {
    const result = buildTimeline([
      entry('deploy-result', 0, { serviceKey: 'place', data: { state: 'failed', phase: 'grace-health' } }),
      entry('deploy-result', 1, { data: { state: 'unconfirmed' } }),
      entry('deploy-result', 2, { data: { state: 'skipped' } }),
      entry('deploy-result', 3, { data: { state: 'pending' } }),
      entry('plan-end', 4, { data: { status: 'partial' } }),
      entry('plan-end', 5, { data: { status: 'grace-pending' } }),
      entry('grace-end', 6, { data: { pending: true } }),
      entry('plan-start', 7, { data: { dryRun: true } }),
      entry('plan-end', 8, { data: { dryRun: true } }),
    ], []);
    expect(result.map(({ kind, summary }) => [kind, summary])).toEqual([
      ['failed', 'Health check failed during grace'], ['deployed', 'Activation unconfirmed'],
      ['deployed', 'Deployment skipped'], ['deployed', 'Deployment pending'],
      ['failed', 'Rotation needs follow-up'], ['grace', 'Rotation is waiting in grace'],
      ['grace', 'Grace period ended; old key retirement is pending'],
      ['decided', 'Dry run started'], ['decided', 'Dry run finished'],
    ]);
    expect(result[0]?.serviceKey).toBe('place');
  });

  it('distinguishes undo, unused replacement cleanup and guided fallback from a completed rotation', () => {
    const result = buildTimeline([
      entry('resume', 0, { data: { undo: true } }),
      entry('written', 1, { data: { undo: true } }),
      entry('redeploy', 2, { data: { undo: true } }),
      entry('verified', 3, { data: { undo: true } }),
      entry('revoked', 4, { data: { undo: true } }),
      entry('revoked', 5, { data: { cleanup: true } }),
      entry('created', 6, { data: { phase: 'guided-fallback' } }),
      entry('plan-end', 7, { data: { undone: true, status: 'complete' } }),
    ], []);
    expect(result.map(event => event.summary)).toEqual([
      'Undo started', 'Old key written during undo', 'Deployment requested during undo',
      'Old key verified during undo', 'Replacement key revoked during undo', 'Unused replacement key revoked',
      'Replacement needs human input', 'Undo finished',
    ]);
    expect(result.filter(event => event.kind === 'undone')).toHaveLength(6);
    expect(result.at(-2)?.kind).toBe('decided');
  });

  it('uses key ordinals by default, even when raw journal or audit text contains hints or values', () => {
    const value = 'plain-session-secret-that-must-stay-private';
    const journal = [entry('created', 1, { clusterId: 'a' }), entry('verified', 3, { clusterId: 'b',
      data: { provider: 'openai', hint: 'sk-proj…ABCD', value, error: value, newKeyRef: value } }),
    entry('created', 2, { clusterId: 'b' }), entry('created', 4, { clusterId: 'c' })];
    const result = buildTimeline(journal, [{ ...audit('autopilot:end', 5), summary: value,
      data: { body: value, counts: { failed: 0 } } }]);
    expect(result.find(event => event.kind === 'verified')?.summary).toBe('New key verified (key 2 of 3)');
    expect(JSON.stringify(result)).not.toContain(value);
    expect(JSON.stringify(result)).not.toContain('sk-proj');
    expect(JSON.stringify(result)).not.toContain('OpenAI');
  });

  it('shows only bounded hints from explicit cluster metadata when hints are allowed', () => {
    const journal = [entry('verified', 0, { clusterId: 'a' }), entry('verified', 1, { clusterId: 'b' })];
    const clusters = [
      { id: 'a', provider: 'openai' as const, hint: 'sk-proj…ABCD' },
      { id: 'b', provider: 'openai' as const, hint: 'sk-proj-this-is-a-full-secret-ABCD' },
    ];
    expect(buildTimeline(journal, [], { clusters })[0]?.summary).toBe('New key verified (key 1 of 2)');
    const result = buildTimeline(journal, [], { clusters, showHints: true });
    expect(result[0]?.summary).toBe('New key verified for OpenAI key sk-proj…ABCD');
    expect(result[1]?.summary).toBe('New key verified (key 2 of 2)');
    expect(JSON.stringify(result)).not.toContain('full-secret');
  });

  it('uses fixed summaries for autopilot and notification audit entries, ignoring other audit kinds', () => {
    const result = buildTimeline([], [
      audit('scan'), audit('autopilot:scope', 1), audit('autopilot:ask', 2),
      audit('autopilot:verified', 3), audit('autopilot:verification-failed', 4),
      audit('autopilot:start', 5), audit('autopilot:stopped', 6),
      audit('autopilot:end', 7, { counts: { failed: 1 } }),
      audit('autopilot:a-new-future-event', 8), audit('notification:failed', 9),
      audit('notify:sent', 10), audit('notifications:queued', 11),
    ]);
    expect(result.map(event => [event.kind, event.summary])).toEqual([
      ['decided', 'Autopilot scope checked'], ['decided', 'Human approval requested'],
      ['decided', 'Armed plan verified'], ['failed', 'Armed plan verification failed'],
      ['decided', 'Autopilot rotation started'], ['failed', 'Autopilot stopped'],
      ['failed', 'Autopilot finished with failed or skipped keys'], ['decided', 'Autopilot activity recorded'],
      ['failed', 'Notification delivery failed'], ['notified', 'Notification sent'],
      ['notified', 'Notification activity recorded'],
    ]);
  });

  it('includes the current CLI notification audit kinds without claiming that a test was delivered', () => {
    const result = buildTimeline([], [audit('notify-add'), audit('notify-remove', 1), audit('notify-test', 2)]);
    expect(result.map(event => [event.kind, event.summary])).toEqual([
      ['notified', 'Notification channel added'], ['notified', 'Notification channel removed'],
      ['notified', 'Notification test completed'],
    ]);
  });

  it('retains autopilot journal mirrors as events without pretending their plan verification verifies a key', () => {
    const result = buildTimeline([], [audit('autopilot:grace-start'), audit('autopilot:shredded', 1),
      audit('autopilot:orphan-suspected', 2), audit('autopilot:undo', 3), audit('autopilot:revoked', 4)]);
    expect(result.map(event => event.kind)).toEqual(['grace', 'decided', 'failed', 'undone', 'revoked']);
    expect(result[1]?.summary).toContain('Recovery copies removed');
  });

  it('distinguishes actual runner key verification counts and uses neutral summaries where mirror context was discarded', () => {
    const result = buildTimeline([], [
      audit('autopilot:verified', 0, { counts: { clusters: 3 } }),
      audit('autopilot:verified', 1, { counts: { clusters: 3, affected: 1 } }),
      audit('autopilot:created', 2, { counts: { clusters: 3, affected: 1 } }),
      audit('autopilot:written', 3, { counts: { clusters: 3, affected: 1 } }),
      audit('autopilot:revoked', 4, { counts: { clusters: 3, affected: 1 } }),
      audit('autopilot:deploy-result', 5, { counts: { clusters: 3, deployments: 1 } }),
      audit('autopilot:plan-end', 6, { counts: { clusters: 3 } }),
    ]);
    expect(result.map(({ kind, summary }) => [kind, summary])).toEqual([
      ['decided', 'Armed plan verified'], ['verified', 'Key verification recorded'],
      ['created', 'Key preparation recorded'], ['written', 'Key write recorded'],
      ['revoked', 'Key revocation recorded'], ['deployed', 'Deployment result recorded'],
      ['decided', 'Rotation attempt ended'],
    ]);
  });

  it('redacts recognized values in identifiers and accepts the runtime redactor for arbitrary secrets', () => {
    const secret = 'private-session-material';
    const redactor = createRedactor(); redactor.register(secret);
    const result = buildTimeline([entry('verified', 0, { clusterId: secret, serviceKey: 'sk-proj-' + 'A'.repeat(48) })], [], { redactor });
    expect(JSON.stringify(result)).not.toContain(secret);
    expect(JSON.stringify(result)).not.toContain('sk-proj-');
    expect(result[0]?.summary).toBe('New key verified (key 1 of 1)');
  });

  it.each(['not a timestamp', '2026-10-27T12:00:00', '<script>value</script>', '2026-02-30T12:00:00Z', '2026-10-27T24:00:00Z'])('refuses an invalid or timezone-free timestamp without echoing it', timestamp => {
    expect(() => buildTimeline([entry('verified', 0, { at: timestamp })], [])).toThrow('Timeline timestamps must include a valid UTC offset.');
  });
});

describe('timeline Markdown', () => {
  it('renders a title, duration, unique completed rotations, failures and a UTC event table', () => {
    const events = buildTimeline([
      entry('plan-start'), entry('revoked', 60, { clusterId: 'a' }),
      entry('revoked', 61, { clusterId: 'a' }), entry('revoked', 62, { clusterId: 'b' }),
      entry('failed', 70, { clusterId: 'c' }), entry('plan-end', 125, { data: { status: 'partial' } }),
    ], []);
    const result = renderTimelineMarkdown(events);
    expect(result).toContain('# Incident timeline\n');
    expect(result).toContain('Duration: 2 min 5 s; 2 keys rotated; failures recorded.');
    expect(result).toContain('| Time (UTC) | Event | Detail |');
    expect(result).toContain('| 2026-10-27 12:01:10.000 UTC | Failed | Rotation step failed (key 3 of 3) |');
    expect(result.endsWith('\n')).toBe(true);
  });

  it('does not count unused-key cleanup, undo or duplicated audit mirrors as keys rotated', () => {
    const events = buildTimeline([
      entry('revoked', 0, { clusterId: 'a', data: { cleanup: true } }),
      entry('revoked', 1, { clusterId: 'b', data: { undo: true } }),
      entry('revoked', 2, { clusterId: 'c' }),
    ], [audit('autopilot:revoked', 3)]);
    expect(renderTimelineMarkdown(events)).toContain('1 key rotated; no failures recorded.');
  });

  it('escapes Markdown, HTML, line breaks and recognized values in a supplied event summary', () => {
    const value = 'sk-proj-' + 'A'.repeat(48);
    const events: TimelineEvent[] = [{ at: at(0), kind: 'failed', summary: `<img src=x onerror=alert(1)> | [open](https://example.test)\n${value}` }];
    const result = renderTimelineMarkdown(events);
    expect(result).not.toContain('<img');
    expect(result).not.toContain(value);
    expect(result).not.toContain('[open]');
    expect(result).toContain('&lt;img');
    expect(result).toContain('&#124;');
    expect(result.split('\n').filter(line => line.startsWith('|'))).toHaveLength(3);
  });

  it('handles an empty timeline and sorts a supplied timeline without mutating it', () => {
    expect(renderTimelineMarkdown([])).toContain('Duration: 0 min 0 s; 0 keys rotated; no failures recorded.');
    const events: TimelineEvent[] = [
      { at: at(5), kind: 'notified', summary: 'Notification sent' },
      { at: at(0), kind: 'detected', summary: 'Platform incident detected' },
    ];
    const result = renderTimelineMarkdown(events);
    expect(result.indexOf('Platform incident detected')).toBeLessThan(result.indexOf('Notification sent'));
    expect(events[0]?.kind).toBe('notified');
  });
});
