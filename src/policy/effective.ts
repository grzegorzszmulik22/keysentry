// Apply a verified team policy to local settings. Every rule here only narrows: nothing a policy says can enable
// a host, provider, channel, egress destination or action that local configuration does not already allow.
import type { ConfigSettings } from '../cli/config.js';
import { tierFor } from '../core/classify.js';
import type { ArmedPlan, EgressRule, HostId, ProviderId, RiskTier, TeamPolicy, TeamRoster } from '../types.js';
import { TIER_ORDER } from '../types.js';

const REVOKE_RANK = { never: 0, 'after-deploy': 1, immediately: 2 } as const;

function hostOf(value: string): string | null {
  try { return new URL(value).hostname.replace(/^\[|\]$/g, '').toLowerCase(); } catch { return null; }
}

/** A narrowed copy of `settings`; the input is not changed. Without a policy, an identical copy. */
export function effectiveSettings(settings: ConfigSettings, policy: TeamPolicy | null | undefined): ConfigSettings {
  const result = structuredClone(settings);
  if (!policy) return result;
  const { autopilot, network, notify, rotation } = policy;

  if (autopilot.maxServicesPerWave !== undefined) result.autopilot.maxServices = Math.min(result.autopilot.maxServices, autopilot.maxServicesPerWave);

  if (network.offline === true) result.network.offline = true;
  // A required proxy carries every request: nothing may bypass it.
  if (network.requireProxy === true) result.network.noProxy = [];
  if (network.allowHosts !== undefined) {
    const allowed = new Set(network.allowHosts);
    const ok = (value: string | undefined) => value !== undefined && allowed.has(hostOf(value) ?? '');
    result.network.allowHosts = result.network.allowHosts.filter(host => allowed.has(host));
    result.autopilot.healthChecks = result.autopilot.healthChecks.filter(check => ok(check.url));
    result.monitor.webhooks = result.monitor.webhooks.filter(url => ok(url));
    if (result.monitor.feeds) result.monitor.feeds = result.monitor.feeds.filter(feed => ok(feed.url));
    if (result.notify.relay && !ok(result.notify.relay.server)) delete result.notify.relay;
    result.notify.channels = result.notify.channels.filter(channel =>
      (channel.server === undefined || ok(channel.server)) && (channel.host === undefined || allowed.has(channel.host)));
    result.audit.export = result.audit.export.filter(target => target.kind === 'syslog' ? allowed.has(target.host)
      : ok(target.kind === 's3' ? target.endpoint : target.url));
  }

  if (notify.allowedKinds !== undefined) {
    const kinds = new Set<string>(notify.allowedKinds);
    result.notify.channels = result.notify.channels.filter(channel => kinds.has(channel.kind));
  }

  if (rotation.revoke !== undefined && REVOKE_RANK[rotation.revoke] < REVOKE_RANK[result.rotation.revoke]) result.rotation.revoke = rotation.revoke;
  if (rotation.minGraceSeconds !== undefined) {
    result.rotation.graceSeconds = Math.max(result.rotation.graceSeconds, rotation.minGraceSeconds);
    result.autopilot.graceMinutes = Math.max(result.autopilot.graceMinutes, Math.ceil(rotation.minGraceSeconds / 60));
  }
  return result;
}

/**
 * Clamp per-run rotation options (for example `rotate --revoke immediately`, or a grace period chosen in the dashboard)
 * to the policy. Returns a copy; options the policy does not mention are unchanged.
 */
export function narrowRotationOptions<T extends { revoke?: 'after-deploy' | 'immediately' | 'never'; graceMs?: number }>(options: T, policy: TeamPolicy | null | undefined): T {
  const result = { ...options };
  if (!policy) return result;
  const { revoke, minGraceSeconds } = policy.rotation;
  // Undefined means "use the configured value", which effectiveSettings has already narrowed.
  if (revoke !== undefined && result.revoke !== undefined && REVOKE_RANK[revoke] < REVOKE_RANK[result.revoke]) result.revoke = revoke;
  if (minGraceSeconds !== undefined && result.graceMs !== undefined) result.graceMs = Math.max(result.graceMs, minGraceSeconds * 1000);
  return result;
}

/**
 * Requirements a policy places on settings that narrowing alone cannot meet. Each entry is a fixed message; any
 * entry means changes must not run.
 */
export function policyBlockers(settings: ConfigSettings, policy: TeamPolicy | null | undefined, env: NodeJS.ProcessEnv = {}): string[] {
  if (!policy) return [];
  const blockers: string[] = [];
  if (policy.network.requireProxy === true && !settings.network.proxy && !env.HTTPS_PROXY?.trim() && !env.https_proxy?.trim()) {
    blockers.push('The team policy requires an HTTP proxy. Set network.proxy in keysentry.yaml or HTTPS_PROXY.');
  }
  if (policy.audit.exportRequired === true && settings.audit.export.length === 0) {
    blockers.push('The team policy requires audit export. Add an audit.export destination in keysentry.yaml (one the policy allows).');
  }
  return blockers;
}

/** Drop user-added egress destinations (owner `user`) that the policy's network.allowHosts does not list. */
export function restrictUserEgress<T extends EgressRule>(rules: readonly T[], policy: TeamPolicy | null | undefined): T[] {
  const allowHosts = policy?.network.allowHosts;
  if (allowHosts === undefined) return [...rules];
  const allowed = new Set(allowHosts);
  return rules.filter(rule => rule.owner !== 'user' || allowed.has(rule.host.toLowerCase()));
}

function hostFromServiceKey(serviceKey: string): string {
  const at = serviceKey.indexOf(':');
  return at > 0 ? serviceKey.slice(0, at) : '';
}

/** Why the policy keeps autopilot away from a key, or null when it may be armed. */
export function autopilotRefusal(cluster: { provider: ProviderId; hosts: readonly HostId[] }, policy: TeamPolicy | null | undefined): string | null {
  if (!policy) return null;
  const { allowedHosts, allowedProviders, approvalTiers } = policy.autopilot;
  if (allowedProviders !== undefined && !allowedProviders.includes(cluster.provider)) return 'The team policy does not let autopilot rotate keys from this provider.';
  if (allowedHosts !== undefined && cluster.hosts.some(host => !allowedHosts.includes(host))) return 'The team policy does not let autopilot change one of the hosts that use this key.';
  if (approvalTiers?.includes(tierFor(cluster.provider))) return 'The team policy says keys in this risk tier always need an approval.';
  return null;
}

/** Is `tier` one the policy says always needs an approval, even inside an armed plan? */
export function alwaysNeedsApproval(tier: RiskTier, policy: TeamPolicy | null | undefined): boolean {
  return policy?.autopilot.approvalTiers?.includes(tier) ?? false;
}

export type PlanCheck = { ok: true; reasons: [] } | { ok: false; reasons: string[] };

/** Is this armed plan inside the policy? Checked at arm time and again by the watcher before acting on it. */
export function checkArmedPlan(plan: Pick<ArmedPlan, 'hosts' | 'clusters' | 'maxServicesPerWave' | 'graceSeconds' | 'healthChecks' | 'nextDeployAcceptance'>,
  policy: TeamPolicy | null | undefined): PlanCheck {
  if (!policy) return { ok: true, reasons: [] };
  const reasons: string[] = [];
  const { allowedHosts, maxServicesPerWave } = policy.autopilot;
  if (allowedHosts !== undefined && plan.hosts.some(host => !allowedHosts.includes(host))) reasons.push('The armed plan watches a host the team policy does not allow.');
  const refused = new Map<string, number>();
  for (const cluster of plan.clusters) {
    const reason = autopilotRefusal({ provider: cluster.provider, hosts: [...new Set(cluster.consumers.map(consumer => hostFromServiceKey(consumer.serviceKey) as HostId))] }, policy);
    if (reason) refused.set(reason, (refused.get(reason) ?? 0) + 1);
  }
  for (const [reason, count] of refused) reasons.push(`${count} armed key${count === 1 ? '' : 's'}: ${reason}`);
  if (maxServicesPerWave !== undefined && plan.maxServicesPerWave > maxServicesPerWave) reasons.push(`The armed plan allows ${plan.maxServicesPerWave} services per wave; the team policy allows at most ${maxServicesPerWave}.`);
  const minGrace = policy.rotation.minGraceSeconds;
  if (minGrace !== undefined && plan.graceSeconds < minGrace) reasons.push(`The armed plan's grace period is shorter than the team policy's minimum of ${minGrace} seconds.`);
  if (policy.rotation.revoke === 'never' && plan.nextDeployAcceptance.some(entry => entry.revokeAfterMax)) reasons.push('The armed plan revokes old keys, but the team policy says keysentry never revokes them.');
  const allowHosts = policy.network.allowHosts;
  if (allowHosts !== undefined && plan.healthChecks.some(check => !allowHosts.includes(hostOf(check.url) ?? ''))) reasons.push('The armed plan has a health check on a host the team policy\'s network.allowHosts does not list.');
  return reasons.length ? { ok: false, reasons } : { ok: true, reasons: [] };
}

/**
 * Distinct approvers an action needs. Ordinary actions: `requiredByTier[tier] ?? required` operators or admins, the
 * strictest tier of the action when it touches several, and the strictest of all tiers when its tiers are unknown.
 * Policy-widening actions: `wideningAdmins` admins. Without a policy: one operator, and the roster's admin threshold
 * of admins for widening actions.
 */
export function approvalsRequired(action: { widening: boolean; tiers?: readonly RiskTier[] | null }, policy: TeamPolicy | null | undefined,
  roster?: Pick<TeamRoster, 'adminThreshold'> | null): { count: number; role: 'operator' | 'admin' } {
  if (action.widening) return { count: Math.max(1, policy ? policy.approvals.wideningAdmins : roster?.adminThreshold ?? 1), role: 'admin' };
  if (!policy) return { count: 1, role: 'operator' };
  const { required, requiredByTier } = policy.approvals;
  const forTier = (tier: RiskTier) => requiredByTier?.[tier] ?? required;
  const tiers = action.tiers === null || action.tiers === undefined ? TIER_ORDER : action.tiers;
  return { count: Math.max(1, ...(tiers.length ? tiers.map(forTier) : [required])), role: 'operator' };
}

/** Tiers of an approval action's clusters; null when any cluster is unknown (the strictest rule then applies). */
export function tiersForClusters(clusterIds: readonly string[], clusters: readonly { id: string; tier: RiskTier }[]): RiskTier[] | null {
  const tiers: RiskTier[] = [];
  for (const id of clusterIds) {
    const cluster = clusters.find(candidate => candidate.id === id);
    if (!cluster) return null;
    tiers.push(cluster.tier);
  }
  return [...new Set(tiers)];
}
