import { randomBytes } from 'node:crypto';
import { TIER_ORDER } from '../types.js';
import type { Cluster, Consumer, HostId, Inventory, PlanStep, ProviderId, Redactor, RiskTier, RotationPlan, ServiceRef } from '../types.js';
import { createRedactor } from './redact.js';
import { serviceKey } from './service-key.js';

interface PlanOptions {
  tiers?: RiskTier[];
  clusterIds?: string[];
  hosts?: HostId[];
  serviceKeys?: string[];
}

// Dashboard entry points are advisory hints, not API endpoints. Provider adapters own live guidance.
const DASHBOARD_HINTS: Record<ProviderId, string> = {
  openai: 'https://platform.openai.com/api-keys',
  anthropic: 'https://console.anthropic.com/settings/keys',
  openrouter: 'https://openrouter.ai/settings/keys',
  stripe: 'https://dashboard.stripe.com/apikeys',
  resend: 'https://resend.com/api-keys',
  cloudflare: 'https://dash.cloudflare.com/profile/api-tokens',
  github: 'https://github.com/settings/tokens',
  aws: 'https://console.aws.amazon.com/iam/home#/security_credentials',
  supabase: 'https://supabase.com/dashboard',
  database: 'the database administration console for the issuing provider',
  slack: 'https://api.slack.com/apps',
  sendgrid: 'https://app.sendgrid.com/settings/api_keys',
  twilio: 'https://console.twilio.com/',
  google: 'https://console.cloud.google.com/apis/credentials',
  'private-key': 'the issuing provider or key management system',
  'crypto-wallet': 'the wallet or custody provider; confirm the asset migration procedure before rotating',
  'app-secret': 'the application secret configuration',
  'encryption-key': 'the application’s data-encryption key migration procedure',
  unknown: 'the issuing provider dashboard; identify the credential owner first',
};

function compareIds(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function compareClusters(a: Cluster, b: Cluster): number {
  return TIER_ORDER.indexOf(a.tier) - TIER_ORDER.indexOf(b.tier)
    || b.consumers.length - a.consumers.length
    || compareIds(a.id, b.id);
}

function uniqueServices(consumers: Consumer[]): ServiceRef[] {
  const services = new Map<string, ServiceRef>();
  for (const { service } of consumers) {
    const key = serviceKey(service);
    if (!services.has(key)) services.set(key, service);
  }
  return [...services.values()];
}

export function buildPlan(inv: Inventory, opts: PlanOptions = {}): RotationPlan {
  const clusters = inv.clusters.filter(cluster =>
    (opts.tiers === undefined || opts.tiers.includes(cluster.tier))
    && (opts.clusterIds === undefined || opts.clusterIds.includes(cluster.id))
    && (opts.hosts === undefined || cluster.consumers.some(consumer => opts.hosts!.includes(consumer.service.host)))
    && (opts.serviceKeys === undefined || cluster.consumers.some(consumer => opts.serviceKeys!.includes(serviceKey(consumer.service))))
  ).sort(compareClusters);

  // Filters select whole clusters: every copy must receive the replacement before revocation.
  const steps: PlanStep[] = clusters.map(cluster => ({
    clusterId: cluster.id,
    provider: cluster.provider,
    tier: cluster.tier,
    method: cluster.method,
    hint: cluster.hint,
    consumers: [...cluster.consumers],
  }));
  const createdAt = new Date().toISOString();
  const timestamp = createdAt.slice(0, 19).replace(/[-:T]/g, '');
  return {
    id: `plan-${timestamp}-${randomBytes(2).toString('hex')}`,
    createdAt,
    steps,
    services: uniqueServices(steps.flatMap(step => step.consumers)),
  };
}

function code(text: string, redactor: Redactor): string {
  // Freeform metadata is untrusted even though Inventory intentionally contains no raw values.
  return '`' + redactor.redact(text).replace(/[\r\n]+/g, ' ').replace(/`/g, "'") + '`';
}

function serviceLabel(service: ServiceRef): string {
  return `${service.host}/${service.serviceName || service.serviceId || 'shared'}`;
}

function serviceContext(service: ServiceRef, redactor: Redactor): string {
  return `project ${code(service.projectName || service.projectId, redactor)}, environment ${code(service.environmentName || service.environmentId || 'default', redactor)}`;
}

function renderConsumers(consumers: Consumer[], redactor: Redactor): string[] {
  return consumers.map(consumer => `- ${code(`${serviceLabel(consumer.service)}:${consumer.varName}`, redactor)} (${serviceContext(consumer.service, redactor)})${consumer.sealed ? ' — sealed' : ''}${consumer.reference ? ' — reference — redeploy only; do not overwrite' : ''}`);
}

function instructions(step: PlanStep): string[] {
  const stage = step.consumers.some(consumer => consumer.reference)
    ? 'Stage the replacement in directly stored variables, suppressing deployments until all plan steps are staged. Leave reference variables unchanged and include their services in the shared redeploy pass.'
    : 'Stage the replacement in every consumer listed above, suppressing deployments until all plan steps are staged.';
  switch (step.method) {
    case 'auto':
      return [
        'Create a replacement with the provider API while keeping the old key active.',
        'Verify the replacement before changing consumers; stop on any verification failure and keep the old key.',
        stage,
        'Keep the old key active through the shared redeploy and verification pass below. Revoke last.',
      ];
    case 'atomic-roll':
      return [
        'Coordinate a maintenance window: the old key is invalidated immediately when the provider rolls it.',
        'Defer the irreversible roll until every guided task and all other replacements are prepared and verified.',
        step.consumers.some(consumer => consumer.reference)
          ? 'During final staging, roll the key, verify the replacement, and immediately write it to every directly stored consumer variable; leave reference variables unchanged and stop on verification failure.'
          : 'During final staging, roll the key, verify the replacement, and immediately write it to every consumer listed above; stop on verification failure.',
        'Proceed directly to the shared redeploy pass, prioritizing these consumers. The old key is already revoked; there is no later revoke step.',
      ];
    case 'generate':
      return [
        'Generate a cryptographically random replacement in memory for this self-issued session or signing secret; plan for sessions and JWTs signed with the old secret to become invalid.',
        'Verify the replacement format and application compatibility; stop on failure.',
        stage,
        'After the shared redeploy pass, verify application health and retire the old secret last.',
      ];
    case 'guided':
      return [
        ...(step.provider === 'encryption-key' ? ['Replacing a data-encryption key requires re-encrypting existing data first; never swap the variable on its own.'] : []),
        `Open ${DASHBOARD_HINTS[step.provider]} and create a replacement with the required permissions, keeping the old key active where supported.`,
        'Provide the replacement through the hidden prompt; never put its value in this runbook.',
        'Verify the replacement before changing consumers; stop on any verification failure and keep the old key.',
        stage,
        'Keep the old key active through the shared redeploy and verification pass below. Revoke last. If the issuer only supports an immediate roll, coordinate that outage before proceeding.',
      ];
  }
}

function renderErrors(inv: Inventory, redactor: Redactor): string[] {
  return inv.errors.length === 0
    ? ['No scan errors.']
    : ['The scan is incomplete; unscanned copies may exist.', '', ...inv.errors.map(error => `- ${code(error.host, redactor)}: ${code(error.message, redactor)}`)];
}

export function renderRunbook(plan: RotationPlan, inv: Inventory): string {
  const redactor = createRedactor();
  const consumers = plan.steps.flatMap(step => step.consumers);
  const services = uniqueServices(consumers);
  const atomicServices = new Set(plan.steps.filter(step => step.method === 'atomic-roll')
    .flatMap(step => step.consumers.map(consumer => serviceKey(consumer.service))));
  services.sort((a, b) => Number(atomicServices.has(serviceKey(b))) - Number(atomicServices.has(serviceKey(a))));
  const lines = [
    '# Rotation runbook', '',
    `Plan: ${code(plan.id, redactor)}`,
    `Created: ${code(plan.createdAt, redactor)}`,
    `Inventory scanned: ${code(inv.scannedAt, redactor)}`, '',
    `${plan.steps.length} secret clusters · ${consumers.length} variable locations · ${services.length} services · ${new Set(consumers.map(consumer => consumer.service.host)).size} hosts.`, '',
    'Review this plan and run a dry run before executing writes.', '',
  ];
  if (atomicServices.size > 0) lines.push('Preparation phase: finish all guided tasks, prepare and verify other replacements, and stage non-atomic changes first. Defer atomic rolls to final staging immediately before the shared deployment pass.', '');
  lines.push('## Rotation steps', '');
  if (plan.steps.length === 0) lines.push('No rotation steps selected.', '');
  for (const [index, step] of plan.steps.entries()) {
    lines.push(
      `### ${index + 1}. ${step.tier} · ${step.provider}`, '',
      `Cluster: ${code(step.clusterId, redactor)}`,
      `Hint: ${step.hint === null ? 'unavailable' : code(step.hint, redactor)}`,
      `Method: ${code(step.method, redactor)}`, '',
      'Consumers:', '', ...renderConsumers(step.consumers, redactor), '',
    );
    if (step.consumers.some(consumer => consumer.sealed)) {
      lines.push('Blind rotation: sealed values cannot be read or matched to other copies. Confirm every consumer with the credential owner.', '');
    }
    lines.push(...instructions(step).map((instruction, index) => `${index + 1}. ${instruction}`), '');
  }
  lines.push('## One redeploy per service', '');
  if (services.length === 0) lines.push('No services to redeploy.', '');
  else {
    if (atomicServices.size > 0) lines.push('Final staging: execute the deferred atomic rolls and immediately update every atomic consumer. Do not wait for further manual work after rolling an atomic key.', '');
    lines.push('After every plan step is staged, redeploy each service below exactly once (or apply its host-specific next-deployment procedure).', '');
    for (const service of services) lines.push(`- ${code(serviceLabel(service), redactor)} (${serviceContext(service, redactor)}; ${code(serviceKey(service), redactor)})`);
    lines.push('',
      'Wait for every deployment to succeed. Verify each replacement credential and application health across every consumer; stop on any failure and keep any old keys that are still active.',
      'Revoke old keys only after all consumers have the replacement and deployments and verification have succeeded. Atomic-roll keys are already revoked by the provider.', '',
    );
  }
  lines.push('## Scan errors', '', ...renderErrors(inv, redactor));
  return redactor.redact(lines.join('\n') + '\n');
}

export function renderBlastRadius(inv: Inventory): string {
  const redactor = createRedactor();
  const consumers = inv.clusters.flatMap(cluster => cluster.consumers);
  const sealed = consumers.filter(consumer => consumer.sealed);
  const clusters = [...inv.clusters].sort((a, b) =>
    Number(b.consumers.length > 1) - Number(a.consumers.length > 1) || compareClusters(a, b));
  const lines = [
    '# Secret blast radius', '',
    `Inventory scanned: ${code(inv.scannedAt, redactor)}`, '',
    `${inv.clusters.length} secret clusters · ${consumers.length} variable locations · ${uniqueServices(consumers).length} affected services · ${inv.services.length} scanned services · ${new Set(inv.hosts).size} scanned hosts.`, '',
    '## Secret clusters', '',
  ];
  if (clusters.length === 0) lines.push('No secret clusters found.', '');
  for (const [index, cluster] of clusters.entries()) {
    lines.push(
      `### ${index + 1}. ${code(cluster.id, redactor)}`, '',
      `${cluster.tier} · ${cluster.provider} · ${code(cluster.method, redactor)}`,
      `Hint: ${cluster.hint === null ? 'unavailable' : code(cluster.hint, redactor)}`,
      cluster.consumers.length > 1 ? `Shared secret: this key lives in ${cluster.consumers.length} places. Rotate every copy together.` : `This key lives in ${cluster.consumers.length} place.`,
      '', ...renderConsumers(cluster.consumers, redactor), '',
    );
  }
  lines.push('## Tier breakdown', '', '| Tier | Secret clusters | Variable locations |', '| --- | ---: | ---: |');
  for (const tier of TIER_ORDER) {
    const tierClusters = inv.clusters.filter(cluster => cluster.tier === tier);
    lines.push(`| ${tier} | ${tierClusters.length} | ${tierClusters.reduce((total, cluster) => total + cluster.consumers.length, 0)} |`);
  }
  lines.push('', '## Sealed secrets', '');
  if (sealed.length === 0) lines.push('No sealed secret locations.');
  else {
    lines.push(`${sealed.length} sealed variable locations must be rotated blind. Their values cannot be read or matched to copies elsewhere; the true blast radius may be larger.`, '', ...renderConsumers(sealed, redactor));
  }
  lines.push('', '## Scan errors', '', ...renderErrors(inv, redactor));
  return redactor.redact(lines.join('\n') + '\n');
}
