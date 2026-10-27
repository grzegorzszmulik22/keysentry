import { describe, expect, it } from 'vitest';
import { buildDigest } from '../../src/hygiene/digest.js';
import type { AutopilotWave } from '../../src/autopilot/runner.js';
import type { Cluster, FirstRunFinding, Incident, Inventory, KeyHygiene, Signal } from '../../src/types.js';

const since = '2026-10-20T12:00:00.000Z';
const now = '2026-10-27T12:00:00.000Z';
const old = '2026-09-01T12:00:00.000Z';
const cluster: Cluster = {
  id: 'cluster-a', fingerprint: 'fingerprint-a', provider: 'openrouter', tier: 'ai', method: 'auto',
  hint: 'sk-or-v\u20261234', consumers: [],
};
const inventory: Inventory = {
  version: 1, scannedAt: now, hosts: [], services: [], findings: [], clusters: [cluster], errors: [],
};
const incident: Incident = {
  id: 'incident-a', host: 'railway', openedAt: now, evidence: [], status: 'alerted',
};
const wave: AutopilotWave = {
  id: 'wave-a', incidentId: incident.id, planId: 'plan-a', startedAt: now, status: 'stopped',
};
const signal: Signal = {
  id: 'signal-a', at: now, kind: 'usage_anomaly', confidence: 'high', clusterIds: [cluster.id],
  summary: 'Untrusted provider text.', evidence: {},
};
const finding: FirstRunFinding = {
  id: 'history-a', provider: 'openrouter', tier: 'ai', hint: cluster.hint,
  locations: [{ kind: 'history', path: '.env', committedAt: old, stillPresent: false }],
  inGitHistory: true, likelyDeployedOn: [],
};
function input() {
  return { since, now, inventory, hygiene: [] as KeyHygiene[], incidents: [] as Incident[],
    waves: [] as AutopilotWave[], signals: [] as Signal[] };
}

describe('weekly digest', () => {
  it('returns one calm info message with the exact quiet line', () => {
    const message = buildDigest(input());
    expect(message).toMatchObject({ at: now, kind: 'digest', severity: 'info', title: 'Weekly digest',
      lines: ['Nothing needed your attention this week.'] });
    expect(message.id).toMatch(/^digest-/);
  });

  it('orders categories by priority and includes the full count before the detail limit', () => {
    const message = buildDigest({ ...input(),
      incidents: [incident], waves: [wave, { ...wave, id: 'pending', status: 'grace' }], findings: [finding],
      hygiene: [{ clusterId: cluster.id, firstSeen: old, ageDays: 120, copies: 1, rotateBy: old, unusedDays: 30 }],
      signals: [signal],
    });
    expect(message.lines).toEqual([
      '7 items needed your attention this week.',
      'A Railway incident needs review.',
      'A rotation stopped and needs review.',
      'A rotation is waiting for its grace period to finish.',
      'A key appears in git history; rotate it.',
      'A key is past its rotate-by date.',
      'A key shows no usage for 30 days.',
      'A spend spike needs review.',
    ]);
    const many = buildDigest({ ...input(), incidents: Array.from({ length: 12 }, (_, index) => ({ ...incident, id: String(index) })), signals: [signal] });
    expect(many.lines[0]).toBe('13 items needed your attention this week.');
    expect(many.lines).toHaveLength(9);
    expect(many.lines.slice(1).every(line => line === 'A Railway incident needs review.')).toBe(true);
  });

  it('filters dated events to the window, including an older incident triggered this week', () => {
    const message = buildDigest({ ...input(), incidents: [
      { ...incident, id: 'old', openedAt: old },
      { ...incident, id: 'fresh-trigger', openedAt: old, status: 'triggered', trigger: { at: now, rule: 'official' } },
      { ...incident, id: 'future', openedAt: '2026-10-28T00:00:00Z' },
    ], signals: [
      { ...signal, id: 'old', at: old }, { ...signal, id: 'boundary', at: since },
      { ...signal, id: 'future', at: '2026-10-28T00:00:00Z' }, { ...signal, id: 'invalid', at: 'invalid' },
      { ...signal, id: 'other-kind', kind: 'leak_detected' },
    ] });
    expect(message.lines).toEqual(['2 items needed your attention this week.',
      'A Railway incident triggered a rotation.', 'A spend spike needs review.']);
  });

  it('retains old outstanding actions but ignores finished, future and invalid rotations', () => {
    const message = buildDigest({ ...input(), waves: [
      { ...wave, startedAt: old }, { ...wave, id: 'running', startedAt: old, status: 'running' },
      { ...wave, id: 'done', status: 'done' },
      { ...wave, id: 'future', startedAt: '2026-10-28T00:00:00Z' },
      { ...wave, id: 'invalid', startedAt: 'invalid' },
    ], findings: [finding] });
    expect(message.lines).toEqual(['3 items needed your attention this week.',
      'A rotation stopped and needs review.', 'A rotation is still pending.',
      'A key appears in git history; rotate it.']);
  });

  it('reports hygiene only for current inventory keys and only confirmed unused periods', () => {
    const clean = { clusterId: cluster.id, firstSeen: old, ageDays: 30, copies: 1 };
    const message = buildDigest({ ...input(), hygiene: [
      { ...clean, clusterId: 'retired', rotateBy: old, unusedDays: 90 },
      { ...clean, rotateBy: '2026-10-28T00:00:00Z', unusedDays: 29 },
    ] });
    expect(message.lines).toEqual(['Nothing needed your attention this week.']);
    expect(buildDigest({ ...input(), hygiene: [{ ...clean, rotateBy: now, unusedDays: 31.8 }] }).lines)
      .toEqual(['1 item needed your attention this week.', 'A key shows no usage for 31 days.']);
  });

  it('deduplicates repeated entities without mutating any inputs', () => {
    const data = { ...input(), incidents: [incident, incident], waves: [wave, wave], signals: [signal, signal], findings: [finding, finding],
      hygiene: [
        { clusterId: cluster.id, firstSeen: old, ageDays: 120, copies: 1, rotateBy: old },
        { clusterId: cluster.id, firstSeen: old, ageDays: 120, copies: 1, rotateBy: old },
      ] };
    const before = JSON.stringify(data);
    expect(buildDigest(data).lines[0]).toBe('5 items needed your attention this week.');
    expect(JSON.stringify(data)).toBe(before);
  });

  it('shows only validated hints when explicitly requested', () => {
    const data = { ...input(), signals: [signal], findings: [finding],
      hygiene: [{ clusterId: cluster.id, firstSeen: old, ageDays: 120, copies: 1, rotateBy: old, unusedDays: 30 }] };
    expect(JSON.stringify(buildDigest(data)).includes(cluster.hint!)).toBe(false);
    const withHints = buildDigest({ ...data, showHints: true });
    expect(withHints.lines.slice(1).every(line => line.includes(cluster.hint!))).toBe(true);
    expect(buildDigest({ ...data, showHints: true, inventory: { ...inventory, clusters: [{ ...cluster, hint: 'full-plaintext-key-without-ellipsis' }] },
      findings: [{ ...finding, hint: 'line\nbreak' }] }).lines.some(line => line.includes('full-plaintext') || line.includes('\n'))).toBe(false);
  });

  it('never reflects raw summaries, metadata, identifiers, locations or planted values', () => {
    const secret = 'sk-or-v1-' + 'x'.repeat(64);
    const opaque = 'arbitrary-opaque-plaintext';
    const message = buildDigest({ ...input(), showHints: true,
      inventory: { ...inventory, errors: [{ host: 'railway', message: secret }], clusters: [{ ...cluster, hint: secret }] },
      incidents: [{ ...incident, id: secret, evidence: [{ sourceId: opaque, kind: 'news', outlet: secret, owner: opaque,
        itemKey: secret, title: secret, link: 'https://example.test/' + secret, publishedAt: now, credentialExposure: true, confidence: 'high' }] }],
      waves: [{ ...wave, id: secret, planId: opaque }],
      signals: [{ ...signal, id: secret, summary: secret, evidence: { value: opaque } }],
      findings: [{ ...finding, id: opaque, hint: secret, locations: [{ kind: 'history', path: secret, stillPresent: false }] }],
    });
    const serialized = JSON.stringify(message);
    expect(serialized.includes(secret)).toBe(false);
    expect(serialized.includes(opaque)).toBe(false);
  });

  it('rejects a hint with a trailing line terminator', () => {
    for (const ending of ['\n', '\r', '\u2028', '\u2029']) {
      const message = buildDigest({ ...input(), showHints: true, signals: [signal],
        inventory: { ...inventory, clusters: [{ ...cluster, hint: cluster.hint + ending }] } });
      expect(message.lines).toEqual(['1 item needed your attention this week.', 'A spend spike needs review.']);
    }
  });

  it('rejects invalid date windows with fixed value-free diagnostics', () => {
    expect(() => buildDigest({ ...input(), now: 'private-input' })).toThrow('Invalid digest time window.');
    expect(() => buildDigest({ ...input(), since: '2026-10-28T00:00:00Z' })).toThrow('Invalid digest time window.');
  });
});
