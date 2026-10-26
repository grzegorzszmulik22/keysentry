import { randomUUID } from 'node:crypto';
import { serviceKey } from '../core/service-key.js';
import type { ActionKind, HostId, Inventory, Policy, PolicyRule, Signal } from '../types.js';
import { usageKey, type MonitorState } from './state.js';

export interface Decision {
  id: string;
  signalId: string;
  action: ActionKind;
  clusterIds: string[];
  /** A destructive action is permitted to execute without a pending human approval. */
  automatic: boolean;
  reason?: string;
  signal: Signal;
}

const CONFIDENCE = { low: 0, medium: 1, high: 2 } as const;

export function defaultPolicy(): Policy {
  return {
    autoExecute: false,
    autoContain: false,
    containCooldownMinutes: 60,
    revokeUnconfirmedOnHighConfidence: true,
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
  let clusterIds = expandScope(signal, inv, rule.scope);
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
  const decisions: Decision[] = [];
  const failedHosts = new Set(inv.errors.map(error => error.host));
  const incomplete = inv.clusters.filter(cluster => clusterIds.includes(cluster.id)
    && cluster.consumers.some(consumer => failedHosts.has(consumer.service.host))).map(cluster => cluster.id);
  if (incomplete.length) decisions.push(decision(incomplete, false, 'incomplete-scan', 'alert'));
  clusterIds = clusterIds.filter(id => !incomplete.includes(id));
  const containment = rule.action === 'cap';
  if (!containment) {
    const generated = inv.clusters.filter(cluster => clusterIds.includes(cluster.id) && cluster.method === 'generate').map(cluster => cluster.id);
    if (generated.length) decisions.push(decision(generated, false, 'generate-disabled', 'alert'));
    clusterIds = clusterIds.filter(id => !generated.includes(id));
  }
  if (!clusterIds.length) return decisions;
  const enabled = containment ? policy.autoContain : policy.autoExecute;
  if (!enabled) return [...decisions, decision(clusterIds, false, containment ? 'auto-contain-disabled' : 'auto-execute-disabled')];

  const timestamp = Date.parse(signal.at);
  if (!Number.isFinite(timestamp)) return [...decisions, decision(clusterIds, false, 'invalid-time')];
  const cooldownMs = Math.max(0, containment ? policy.containCooldownMinutes : policy.cooldownMinutes) * 60_000;
  const cooling: string[] = [];
  const eligible: string[] = [];
  for (const id of clusterIds) {
    const cluster = inv.clusters.find(cluster => cluster.id === id)!;
    const ref = state.keyRefs[id];
    const last = containment ? [state.containCooldowns[id], ref ? state.containCooldowns[usageKey(cluster.provider, ref)] : undefined]
      : [state.cooldowns[id]];
    if (last.some(value => value !== undefined && (!Number.isFinite(Date.parse(value)) || timestamp - Date.parse(value) < cooldownMs))) cooling.push(id);
    else eligible.push(id);
  }

  const day = new Date(timestamp).toISOString().slice(0, 10);
  const used = (containment ? state.autoContainments : state.autoRotations)[day] ?? 0;
  const remaining = Number.isFinite(policy.maxAutoRotationsPerDay) && Number.isFinite(used)
    ? Math.max(0, Math.floor(policy.maxAutoRotationsPerDay) - Math.max(0, used))
    : 0;
  const allowed = eligible.slice(0, remaining);
  const overflow = eligible.slice(remaining);
  if (allowed.length) decisions.push(decision(allowed, true));
  if (cooling.length) decisions.push(decision(cooling, false, 'cooldown'));
  if (overflow.length) decisions.push(decision(overflow, false, 'daily-cap'));
  return decisions;
}
