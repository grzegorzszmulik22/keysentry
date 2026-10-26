import { randomUUID } from 'node:crypto';
import { serviceKey } from '../core/service-key.js';
import type { ActionKind, HostId, Inventory, Policy, PolicyRule, Signal } from '../types.js';
import type { MonitorState } from './state.js';

export interface Decision {
  id: string;
  signalId: string;
  action: ActionKind;
  clusterIds: string[];
  /** A rotation is permitted to execute without a pending human approval. */
  automatic: boolean;
  reason?: string;
  signal: Signal;
}

const CONFIDENCE = { low: 0, medium: 1, high: 2 } as const;

export function defaultPolicy(): Policy {
  return {
    autoExecute: false,
    cooldownMinutes: 60,
    maxAutoRotationsPerDay: 10,
    rules: {
      canary_triggered: { action: 'rotate', scope: 'service', minConfidence: 'medium' },
      leak_detected: { action: 'rotate', scope: 'cluster', minConfidence: 'high' },
      revoked_upstream: { action: 'rotate', scope: 'cluster', minConfidence: 'high' },
      usage_anomaly: { action: 'cap', scope: 'cluster', minConfidence: 'medium' },
      host_breach_advisory: { action: 'alert', scope: 'host', minConfidence: 'medium' },
    },
  };
}

function expandScope(signal: Signal, inv: Inventory, scope: PolicyRule['scope']): string[] {
  const implicated = new Set(signal.clusterIds);
  if (scope === 'cluster') return inv.clusters.filter(cluster => implicated.has(cluster.id)).map(cluster => cluster.id);

  const direct = inv.clusters.filter(cluster => implicated.has(cluster.id));
  // Explicit canary placement takes precedence: a shared secret's other consumers
  // do not turn an incident in service A into evidence of compromise in service B.
  const services = new Set(signal.serviceKeys?.length
    ? signal.serviceKeys
    : direct.flatMap(cluster => cluster.consumers.map(consumer => serviceKey(consumer.service))));
  if (scope === 'service') {
    return inv.clusters.filter(cluster => cluster.consumers.some(consumer => services.has(serviceKey(consumer.service))))
      .map(cluster => cluster.id);
  }

  const hosts = new Set<HostId>(signal.host
    ? [signal.host]
    : [
      ...inv.services.filter(service => services.has(serviceKey(service))).map(service => service.host),
      ...direct.flatMap(cluster => cluster.consumers.map(consumer => consumer.service.host)),
    ]);
  return inv.clusters.filter(cluster => cluster.consumers.some(consumer => hosts.has(consumer.service.host)))
    .map(cluster => cluster.id);
}

/** Pure policy evaluation. The action executor reserves cooldown/capacity before any rotation call. */
export function decide(signal: Signal, inv: Inventory, policy: Policy, state: MonitorState): Decision[] {
  const rule = policy.rules[signal.kind];
  const clusterIds = expandScope(signal, inv, rule.scope);
  const decision = (ids: string[], automatic: boolean, reason?: string, action: ActionKind = rule.action): Decision => ({
    id: `decision-${randomUUID()}`,
    signalId: signal.id,
    action,
    clusterIds: ids,
    automatic,
    ...(reason ? { reason } : {}),
    signal,
  });
  if (CONFIDENCE[signal.confidence] < CONFIDENCE[rule.minConfidence]) {
    return [decision(clusterIds, false, 'min-confidence', 'alert')];
  }
  if (rule.action === 'alert') return [decision(clusterIds, false)];
  if (clusterIds.length === 0) return [decision([], false, 'no-targets', 'alert')];
  if (rule.action === 'cap') return [decision(clusterIds, true)];
  if (!policy.autoExecute) return [decision(clusterIds, false, 'auto-execute-disabled')];

  const timestamp = Date.parse(signal.at);
  if (!Number.isFinite(timestamp)) return [decision(clusterIds, false, 'invalid-time')];
  const cooldownMs = Math.max(0, policy.cooldownMinutes) * 60_000;
  const cooling: string[] = [];
  const eligible: string[] = [];
  for (const id of clusterIds) {
    const last = state.cooldowns[id];
    const lastAt = last === undefined ? NaN : Date.parse(last);
    if (last !== undefined && (!Number.isFinite(lastAt) || timestamp - lastAt < cooldownMs)) cooling.push(id);
    else eligible.push(id);
  }

  const day = new Date(timestamp).toISOString().slice(0, 10);
  const used = state.autoRotations[day] ?? 0;
  const remaining = Number.isFinite(policy.maxAutoRotationsPerDay) && Number.isFinite(used)
    ? Math.max(0, Math.floor(policy.maxAutoRotationsPerDay) - Math.max(0, used))
    : 0;
  const allowed = eligible.slice(0, remaining);
  const overflow = eligible.slice(remaining);
  const decisions: Decision[] = [];
  if (allowed.length) decisions.push(decision(allowed, true));
  if (cooling.length) decisions.push(decision(cooling, false, 'cooldown'));
  if (overflow.length) decisions.push(decision(overflow, false, 'daily-cap'));
  return decisions;
}
