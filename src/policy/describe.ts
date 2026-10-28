// Plain-English summary of a team policy, for `policy show` and for review before signing or applying.
import type { TeamPolicy } from '../types.js';

const list = (values: readonly string[]) => values.length ? values.join(', ') : '(none)';

export function describePolicy(policy: TeamPolicy): string[] {
  const lines: string[] = [];
  const { autopilot, approvals, network, notify, rotation, audit } = policy;
  if (autopilot.allowedHosts) lines.push(`Autopilot may change keys only on: ${list(autopilot.allowedHosts)}.`);
  if (autopilot.allowedProviders) lines.push(`Autopilot may rotate keys only from: ${list(autopilot.allowedProviders)}.`);
  if (autopilot.maxServicesPerWave !== undefined) lines.push(`Autopilot changes at most ${autopilot.maxServicesPerWave} service${autopilot.maxServicesPerWave === 1 ? '' : 's'} per wave.`);
  if (autopilot.approvalTiers?.length) lines.push(`Keys in these risk tiers always need an approval: ${list(autopilot.approvalTiers)}.`);
  lines.push(autopilot.allowMonitorAutomation === true
    ? 'The monitor may rotate or contain keys automatically where keysentry.yaml turns that on, within the autopilot limits above.'
    : 'The monitor never rotates or contains keys automatically; every monitor action waits for approval.');
  const byTier = Object.entries(approvals.requiredByTier ?? {}).filter(([, count]) => count !== undefined).map(([tier, count]) => `${tier}: ${count}`);
  lines.push(`Approvals: ${approvals.required} operator${approvals.required === 1 ? '' : 's'} or admin${approvals.required === 1 ? '' : 's'}${byTier.length ? ` (${byTier.join(', ')})` : ''}; policy-widening changes: ${approvals.wideningAdmins} admin${approvals.wideningAdmins === 1 ? '' : 's'}.`);
  if (network.offline) lines.push('Offline: no breach feeds or news are fetched.');
  if (network.requireProxy) lines.push('Every outbound request goes through the configured HTTP proxy.');
  if (network.allowHosts) lines.push(`Outbound hosts you add are limited to: ${list(network.allowHosts)}.`);
  if (notify.allowedKinds) lines.push(`Notification channel types allowed: ${list(notify.allowedKinds)}.`);
  if (rotation.revoke === 'never') lines.push('keysentry never revokes old keys; people do.');
  if (rotation.revoke === 'after-deploy') lines.push('Old keys are revoked only after the new key is deployed and verified.');
  if (rotation.minGraceSeconds !== undefined) lines.push(`Grace period before revoking: at least ${rotation.minGraceSeconds} seconds.`);
  if (audit.exportRequired) lines.push('Audit export is required.');
  return lines;
}
