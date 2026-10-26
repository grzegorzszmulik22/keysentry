import { describe, expect, it } from 'vitest';
import type { Cluster, Inventory, ServiceRef, Signal } from '../../src/types.js';
import { serviceKey } from '../../src/core/service-key.js';
import { decide, defaultPolicy } from '../../src/monitor/policy.js';
import { createMonitorState } from '../../src/monitor/state.js';
import { svc } from '../helpers/fakes.js';

const at = '2026-10-26T12:00:00.000Z';

function cluster(id: string, services: ServiceRef[]): Cluster {
  return {
    id, fingerprint: id, provider: 'openrouter', tier: 'ai', method: 'auto', hint: null,
    consumers: services.map(service => ({ service, varName: 'API_KEY', fingerprint: id, hint: null, sealed: false })),
  };
}

function inventory(clusters: Cluster[]): Inventory {
  const services = [...new Map(clusters.flatMap(c => c.consumers.map(v => [serviceKey(v.service), v.service] as const))).values()];
  return { version: 1, scannedAt: at, hosts: [...new Set(services.map(s => s.host))], services, findings: [], clusters, errors: [] };
}

function signal(overrides: Partial<Signal> = {}): Signal {
  return { id: 'signal-1', kind: 'leak_detected', at, confidence: 'high', clusterIds: ['a'], summary: 'A leak was detected.', evidence: {}, ...overrides };
}

describe('monitor policy', () => {
  it('uses the documented default actions, scopes and guardrails', () => {
    const policy = defaultPolicy();
    expect(policy.autoExecute).toBe(false);
    expect(policy.cooldownMinutes).toBe(60);
    expect(policy.maxAutoRotationsPerDay).toBe(10);
    expect(policy.autoContain).toBe(false);
    expect(policy.containCooldownMinutes).toBe(60);
    expect(policy.revokeUnconfirmedOnHighConfidence).toBe(true);
    expect(policy.rules).toMatchObject({
      canary_triggered: { action: 'rotate', scope: 'service', minConfidence: 'medium' },
      leak_detected: { action: 'rotate', scope: 'cluster' },
      revoked_upstream: { action: 'rotate', scope: 'cluster' },
      usage_anomaly: { action: 'cap', scope: 'cluster', minConfidence: 'medium' },
      host_breach_advisory: { action: 'alert', scope: 'host' },
    });
  });

  it('alerts below minConfidence without scheduling a rotation', () => {
    const policy = defaultPolicy();
    policy.autoExecute = true;
    const decisions = decide(signal({ confidence: 'low' }), inventory([cluster('a', [svc('railway', 'one')])]), policy, createMonitorState());
    expect(decisions).toHaveLength(1);
    expect(decisions[0]).toMatchObject({ action: 'alert', automatic: false, reason: 'min-confidence' });
  });

  it('leaves default rotations and containment pending', () => {
    const inv = inventory([cluster('a', [svc('railway', 'one')])]);
    const state = createMonitorState();
    expect(decide(signal(), inv, defaultPolicy(), state)[0]).toMatchObject({ action: 'rotate', automatic: false });
    expect(decide(signal({ kind: 'usage_anomaly' }), inv, defaultPolicy(), state)[0]).toMatchObject({ action: 'cap', automatic: false });
  });

  it('uses independent containment opt-in, cooldown and daily capacity', () => {
    const inv = inventory([cluster('a', [svc('railway', 'one')])]);
    const state = createMonitorState();
    const policy = defaultPolicy();
    policy.autoExecute = true;
    const hit = signal({ kind: 'usage_anomaly' });
    expect(decide(hit, inv, policy, state)[0]).toMatchObject({ automatic: false });
    policy.autoContain = true;
    policy.autoExecute = false;
    state.autoRotations['2026-10-26'] = 10;
    expect(decide(hit, inv, policy, state)[0]).toMatchObject({ action: 'cap', automatic: true });
    state.containCooldowns.a = '2026-10-26T11:30:00.000Z';
    expect(decide(hit, inv, policy, state)[0]).toMatchObject({ automatic: false, reason: 'cooldown' });
    delete state.containCooldowns.a;
    state.autoContainments['2026-10-26'] = 10;
    expect(decide(hit, inv, policy, state)[0]).toMatchObject({ automatic: false, reason: 'daily-cap' });
    expect(decide({ ...hit, at: '2026-10-27T00:00:00.000Z' }, inv, policy, state)[0]).toMatchObject({ automatic: true });
  });

  it.each(['rotate', 'cap', 'breach-mode'] as const)('alerts for failed-host consumers while other %s targets proceed', action => {
    const one = svc('railway', 'one');
    const inv = inventory([cluster('shared', [one, svc('vercel', 'unavailable')]), cluster('safe', [one])]);
    inv.errors = [{ host: 'vercel', message: 'Scan failed.' }];
    const policy = defaultPolicy();
    policy.autoExecute = policy.autoContain = true;
    policy.rules.leak_detected.action = action;
    const decisions = decide(signal({ clusterIds: ['shared', 'safe'] }), inv, policy, createMonitorState());
    expect(decisions.find(d => d.clusterIds.includes('shared'))).toMatchObject({ action: 'alert', automatic: false, reason: 'incomplete-scan' });
    expect(decisions.find(d => d.clusterIds.includes('safe'))).toMatchObject({ action, automatic: true });
  });

  it.each(['rotate', 'breach-mode'] as const)('excludes generated secrets from a %s plan and alerts', action => {
    const one = svc('railway', 'one');
    const generated = { ...cluster('generated', [one]), method: 'generate' as const };
    const policy = defaultPolicy(); policy.autoExecute = true;
    policy.rules.canary_triggered.action = action;
    const decisions = decide(signal({ kind: 'canary_triggered', serviceKeys: [serviceKey(one)] }), inventory([generated, cluster('safe', [one])]), policy, createMonitorState());
    expect(decisions.find(d => d.clusterIds.includes('generated'))).toMatchObject({ action: 'alert', automatic: false, reason: 'generate-disabled' });
    expect(decisions.find(d => d.clusterIds.includes('safe'))).toMatchObject({ action, automatic: true });
  });

  it('expands a canary service only to clusters consumed in that service', () => {
    const one = svc('railway', 'one');
    const two = svc('railway', 'two');
    const remote = svc('vercel', 'remote');
    const inv = inventory([cluster('a', [one, remote]), cluster('b', [one]), cluster('c', [two]), cluster('d', [remote])]);
    const hit = signal({ kind: 'canary_triggered', clusterIds: ['a'], host: 'railway', serviceKeys: [serviceKey(one)] });
    expect(decide(hit, inv, defaultPolicy(), createMonitorState())[0]?.clusterIds).toEqual(['a', 'b']);
    const policy = defaultPolicy();
    policy.rules.canary_triggered.scope = 'host';
    expect(decide(hit, inv, policy, createMonitorState())[0]?.clusterIds).toEqual(['a', 'b', 'c']);
  });

  it('expands a canary with no direct cluster ids by its service key', () => {
    const one = svc('railway', 'one');
    const inv = inventory([cluster('a', [one]), cluster('b', [one]), cluster('c', [svc('railway', 'two')])]);
    const hit = signal({ kind: 'canary_triggered', clusterIds: [], host: 'railway', serviceKeys: [serviceKey(one)] });
    expect(decide(hit, inv, defaultPolicy(), createMonitorState())[0]?.clusterIds).toEqual(['a', 'b']);
  });

  it('keeps a second rotation in cooldown pending, without mutating state', () => {
    const inv = inventory([cluster('a', [svc('railway', 'one')])]);
    const policy = defaultPolicy();
    policy.autoExecute = true;
    const state = createMonitorState();
    state.cooldowns.a = '2026-10-26T11:30:00.000Z';
    const before = JSON.stringify(state);
    expect(decide(signal(), inv, policy, state)[0]).toMatchObject({ action: 'rotate', automatic: false, reason: 'cooldown' });
    expect(JSON.stringify(state)).toBe(before);
  });

  it('blocks the eleventh automatic rotation and restores capacity next UTC day', () => {
    const inv = inventory([cluster('a', [svc('railway', 'one')])]);
    const policy = defaultPolicy();
    policy.autoExecute = true;
    const state = createMonitorState();
    state.autoRotations['2026-10-26'] = 10;
    expect(decide(signal(), inv, policy, state)[0]).toMatchObject({ automatic: false, reason: 'daily-cap' });
    expect(decide(signal({ at: '2026-10-27T00:00:00.000Z' }), inv, policy, state)[0]).toMatchObject({ automatic: true });
  });

  it('counts clusters toward capacity and splits the overflow into pending work', () => {
    const service = svc('railway', 'one');
    const inv = inventory([cluster('a', [service]), cluster('b', [service]), cluster('c', [service])]);
    const policy = defaultPolicy();
    policy.autoExecute = true;
    const state = createMonitorState();
    state.autoRotations['2026-10-26'] = 9;
    const decisions = decide(signal({ clusterIds: ['a', 'b', 'c'] }), inv, policy, state);
    expect(decisions.filter(d => d.automatic).flatMap(d => d.clusterIds)).toEqual(['a']);
    expect(decisions.filter(d => !d.automatic).flatMap(d => d.clusterIds)).toEqual(['b', 'c']);
  });
});
