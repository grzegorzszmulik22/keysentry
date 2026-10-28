import { describe, expect, test } from 'vitest';
import { configSchema, type ConfigSettings } from '../../src/cli/config.js';
import {
  alwaysNeedsApproval, approvalsRequired, autopilotRefusal, checkArmedPlan, describePolicy, effectiveSettings, narrowRotationOptions, policyBlockers,
  restrictUserEgress, tiersForClusters,
} from '../../src/policy/index.js';
import type { ArmedPlan, EgressRule, TeamPolicy } from '../../src/types.js';

function policy(rules: Partial<Omit<TeamPolicy, 'v' | 'teamId' | 'version' | 'prev' | 'updatedAt'>> = {}): TeamPolicy {
  return { v: 1, teamId: 'team-test-0001', version: 1, prev: null, updatedAt: '2026-10-28T00:00:00.000Z',
    autopilot: {}, approvals: { required: 1, wideningAdmins: 1 }, network: {}, notify: {}, rotation: {}, audit: {}, ...rules };
}

function settings(): ConfigSettings {
  return configSchema.parse({
    rotation: { graceSeconds: 120, revoke: 'immediately' },
    network: { allowHosts: ['hooks.example.com', 'other.example.net'], noProxy: ['internal.example.com'] },
    autopilot: { maxServices: 10, graceMinutes: 15, healthChecks: [
      { serviceKey: 'vercel:p/production/s', url: 'https://app.example.com/health' },
      { serviceKey: 'railway:p/e/s', url: 'https://status.other.example.net/ok' },
    ] },
    notify: {
      channels: [
        { id: 'ops', kind: 'slack' }, { id: 'phone', kind: 'ntfy', server: 'https://ntfy.example.com' },
        { id: 'mail', kind: 'smtp', host: 'smtp.example.com', port: 465, from: 'k@example.com', to: ['a@example.com'] }, { id: 'local', kind: 'console' },
      ],
      relay: { server: 'https://relay.example.com' },
    },
    audit: { export: [
      { kind: 'syslog', id: 'siem', host: 'siem.example.com' },
      { kind: 'webhook', id: 'hook', url: 'https://hooks.example.com/audit' },
      { kind: 's3', id: 'archive', endpoint: 'https://s3.example.org', bucket: 'audit-bucket', region: 'eu-west-1' },
    ] },
    monitor: { webhooks: ['https://hooks.example.com/alert', 'https://elsewhere.example.org/x'], feeds: [{ url: 'https://feeds.example.com/rss' }] },
  });
}

describe('effectiveSettings only narrows', () => {
  test('without a policy it returns an identical copy, and never changes its input', () => {
    const input = settings();
    const before = structuredClone(input);
    const copy = effectiveSettings(input, null);
    expect(copy).toEqual(input);
    expect(copy).not.toBe(input);
    effectiveSettings(input, policy({ network: { offline: true, allowHosts: [] }, notify: { allowedKinds: [] } }));
    expect(input).toEqual(before);
  });

  test('maxServicesPerWave lowers the configured maximum but never raises it', () => {
    expect(effectiveSettings(settings(), policy({ autopilot: { maxServicesPerWave: 3 } })).autopilot.maxServices).toBe(3);
    expect(effectiveSettings(settings(), policy({ autopilot: { maxServicesPerWave: 50 } })).autopilot.maxServices).toBe(10);
  });

  test('offline and requireProxy force their settings; false never turns them off', () => {
    const offline = { ...settings(), network: { ...settings().network, offline: true } };
    expect(effectiveSettings(settings(), policy({ network: { offline: true } })).network.offline).toBe(true);
    expect(effectiveSettings(offline, policy({ network: { offline: false } })).network.offline).toBe(true);
    expect(effectiveSettings(settings(), policy({ network: { requireProxy: true } })).network.noProxy).toEqual([]);
    expect(effectiveSettings(settings(), policy({ network: { requireProxy: false } })).network.noProxy).toEqual(['internal.example.com']);
  });

  test('network.allowHosts limits every user egress addition to its list', () => {
    const result = effectiveSettings(settings(), policy({ network: { allowHosts: ['hooks.example.com', 'app.example.com', 'smtp.example.com', 'siem.example.com', 'new.example.com'] } }));
    expect(result.network.allowHosts).toEqual(['hooks.example.com']);
    expect(result.autopilot.healthChecks.map(check => check.url)).toEqual(['https://app.example.com/health']);
    expect(result.monitor.webhooks).toEqual(['https://hooks.example.com/alert']);
    expect(result.monitor.feeds).toEqual([]);
    expect(result.notify.relay).toBeUndefined();
    expect(result.notify.channels.map(channel => channel.id)).toEqual(['ops', 'mail', 'local']);
    expect(result.audit.export.map(target => target.id)).toEqual(['siem', 'hook']);
  });

  test('notify.allowedKinds drops other channels', () => {
    expect(effectiveSettings(settings(), policy({ notify: { allowedKinds: ['slack', 'console'] } })).notify.channels.map(channel => channel.id)).toEqual(['ops', 'local']);
  });

  test('rotation.revoke and minGraceSeconds tighten rotation', () => {
    expect(effectiveSettings(settings(), policy({ rotation: { revoke: 'after-deploy' } })).rotation.revoke).toBe('after-deploy');
    expect(effectiveSettings(settings(), policy({ rotation: { revoke: 'never' } })).rotation.revoke).toBe('never');
    const never = { ...settings(), rotation: { ...settings().rotation, revoke: 'never' as const } };
    expect(effectiveSettings(never, policy({ rotation: { revoke: 'after-deploy' } })).rotation.revoke).toBe('never');
    const longer = effectiveSettings(settings(), policy({ rotation: { minGraceSeconds: 1800 } }));
    expect(longer.rotation.graceSeconds).toBe(1800);
    expect(longer.autopilot.graceMinutes).toBe(30);
    const shorter = effectiveSettings(settings(), policy({ rotation: { minGraceSeconds: 10 } }));
    expect(shorter.rotation.graceSeconds).toBe(120);
    expect(shorter.autopilot.graceMinutes).toBe(15);
  });
});

describe('per-run rotation options', () => {
  test('a requested revoke or grace is clamped; an unset revoke keeps the narrowed configuration', () => {
    const rules = policy({ rotation: { revoke: 'after-deploy', minGraceSeconds: 600 } });
    expect(narrowRotationOptions({ revoke: 'immediately', graceMs: 60_000, dryRun: false }, rules)).toEqual({ revoke: 'after-deploy', graceMs: 600_000, dryRun: false });
    expect(narrowRotationOptions({ revoke: 'never', graceMs: 900_000 }, rules)).toEqual({ revoke: 'never', graceMs: 900_000 });
    expect(narrowRotationOptions({}, rules)).toEqual({});
    expect(narrowRotationOptions({ revoke: 'after-deploy' }, policy({ rotation: { revoke: 'never' } }))).toEqual({ revoke: 'never' });
    const input = { revoke: 'immediately' as const };
    expect(narrowRotationOptions(input, null)).toEqual(input);
    expect(narrowRotationOptions(input, rules)).not.toBe(input);
  });
});

describe('requirements narrowing cannot meet', () => {
  test('requireProxy needs a proxy; exportRequired needs an export the policy allows', () => {
    const base = settings();
    expect(policyBlockers(base, policy({ network: { requireProxy: true } }), {})).toEqual(['The team policy requires an HTTP proxy. Set network.proxy in keysentry.yaml or HTTPS_PROXY.']);
    expect(policyBlockers(base, policy({ network: { requireProxy: true } }), { HTTPS_PROXY: 'http://proxy.internal:3128' })).toEqual([]);
    expect(policyBlockers({ ...base, network: { ...base.network, proxy: 'http://proxy.internal:3128' } }, policy({ network: { requireProxy: true } }))).toEqual([]);
    const narrowed = effectiveSettings(base, policy({ network: { allowHosts: [] }, audit: { exportRequired: true } }));
    expect(policyBlockers(narrowed, policy({ audit: { exportRequired: true } }))).toEqual([expect.stringMatching(/requires audit export/)]);
    expect(policyBlockers(base, policy({ audit: { exportRequired: true } }))).toEqual([]);
    expect(policyBlockers(base, null)).toEqual([]);
  });
});

describe('egress, autopilot scope and armed plans', () => {
  test('restrictUserEgress drops only user destinations outside the list', () => {
    const rules: EgressRule[] = [
      { host: 'api.vercel.com', owner: 'vercel', purpose: 'Vercel' }, { host: 'hooks.example.com', owner: 'user', purpose: 'webhook' },
      { host: 'evil.example.net', owner: 'user', purpose: 'notification channel' },
    ];
    expect(restrictUserEgress(rules, policy({ network: { allowHosts: ['hooks.example.com'] } })).map(rule => rule.host)).toEqual(['api.vercel.com', 'hooks.example.com']);
    expect(restrictUserEgress(rules, policy())).toEqual(rules);
    expect(restrictUserEgress(rules, null)).toEqual(rules);
  });

  test('autopilotRefusal filters by host, provider and always-ask tiers', () => {
    const rules = policy({ autopilot: { allowedHosts: ['vercel'], allowedProviders: ['openai', 'stripe'], approvalTiers: ['payments'] } });
    expect(autopilotRefusal({ provider: 'openai', hosts: ['vercel'] }, rules)).toBeNull();
    expect(autopilotRefusal({ provider: 'anthropic', hosts: ['vercel'] }, rules)).toMatch(/provider/);
    expect(autopilotRefusal({ provider: 'openai', hosts: ['vercel', 'railway'] }, rules)).toMatch(/hosts/);
    expect(autopilotRefusal({ provider: 'stripe', hosts: ['vercel'] }, rules)).toMatch(/always need an approval/);
    expect(alwaysNeedsApproval('payments', rules)).toBe(true);
    expect(alwaysNeedsApproval('ai', rules)).toBe(false);
    expect(autopilotRefusal({ provider: 'stripe', hosts: ['railway'] }, null)).toBeNull();
  });

  const plan: Pick<ArmedPlan, 'hosts' | 'clusters' | 'maxServicesPerWave' | 'graceSeconds' | 'healthChecks' | 'nextDeployAcceptance'> = {
    hosts: ['vercel', 'railway'],
    clusters: [
      { clusterId: 'c1', provider: 'openai', method: 'auto', consumers: [{ serviceKey: 'vercel:p/production/s', varName: 'OPENAI_API_KEY', fingerprint: 'f1' }] },
      { clusterId: 'c2', provider: 'stripe', method: 'auto', consumers: [{ serviceKey: 'railway:p/e/s', varName: 'STRIPE_KEY', fingerprint: 'f2' }] },
    ] as ArmedPlan['clusters'],
    maxServicesPerWave: 10, graceSeconds: 900, healthChecks: [{ serviceKey: 'vercel:p/production/s', url: 'https://app.example.com/health' }],
    nextDeployAcceptance: [{ host: 'vercel', maxHours: 24, revokeAfterMax: true }],
  };

  test('a plan inside the policy passes', () => {
    expect(checkArmedPlan(plan, null)).toEqual({ ok: true, reasons: [] });
    expect(checkArmedPlan(plan, policy({ autopilot: { allowedHosts: ['vercel', 'railway'], maxServicesPerWave: 10 }, rotation: { minGraceSeconds: 900 },
      network: { allowHosts: ['app.example.com'] } }))).toEqual({ ok: true, reasons: [] });
  });

  test('a plan outside the policy is refused, with every reason', () => {
    const result = checkArmedPlan(plan, policy({
      autopilot: { allowedHosts: ['vercel'], allowedProviders: ['openai', 'stripe'], maxServicesPerWave: 5, approvalTiers: ['payments'] },
      rotation: { minGraceSeconds: 1800, revoke: 'never' }, network: { allowHosts: ['status.example.com'] },
    }));
    expect(result.ok).toBe(false);
    expect(result.reasons).toEqual([
      'The armed plan watches a host the team policy does not allow.',
      '1 armed key: The team policy does not let autopilot change one of the hosts that use this key.',
      'The armed plan allows 10 services per wave; the team policy allows at most 5.',
      'The armed plan\'s grace period is shorter than the team policy\'s minimum of 1800 seconds.',
      'The armed plan revokes old keys, but the team policy says keysentry never revokes them.',
      'The armed plan has a health check on a host the team policy\'s network.allowHosts does not list.',
    ]);
    expect(checkArmedPlan(plan, policy({ autopilot: { allowedProviders: ['openai'] } })).reasons).toEqual(['1 armed key: The team policy does not let autopilot rotate keys from this provider.']);
    expect(checkArmedPlan(plan, policy({ autopilot: { approvalTiers: ['payments', 'ai'] } })).reasons).toEqual(['2 armed keys: The team policy says keys in this risk tier always need an approval.']);
  });
});

describe('approvalsRequired', () => {
  const rules = policy({ approvals: { required: 2, requiredByTier: { crypto: 3, ai: 1 }, wideningAdmins: 2 } });
  test('per tier, strictest tier, unknown tiers and widening', () => {
    expect(approvalsRequired({ widening: false, tiers: ['ai'] }, rules)).toEqual({ count: 1, role: 'operator' });
    expect(approvalsRequired({ widening: false, tiers: ['cloud'] }, rules)).toEqual({ count: 2, role: 'operator' });
    expect(approvalsRequired({ widening: false, tiers: ['ai', 'crypto'] }, rules)).toEqual({ count: 3, role: 'operator' });
    expect(approvalsRequired({ widening: false, tiers: null }, rules)).toEqual({ count: 3, role: 'operator' });
    expect(approvalsRequired({ widening: false, tiers: [] }, rules)).toEqual({ count: 2, role: 'operator' });
    expect(approvalsRequired({ widening: true, tiers: ['ai'] }, rules)).toEqual({ count: 2, role: 'admin' });
  });
  test('without a policy: one operator, and the admin threshold for widening', () => {
    expect(approvalsRequired({ widening: false }, null)).toEqual({ count: 1, role: 'operator' });
    expect(approvalsRequired({ widening: true }, null, { adminThreshold: 3 })).toEqual({ count: 3, role: 'admin' });
    expect(approvalsRequired({ widening: true }, null)).toEqual({ count: 1, role: 'admin' });
  });
  test('tiersForClusters is null when a cluster is unknown', () => {
    const clusters = [{ id: 'a', tier: 'ai' as const }, { id: 'b', tier: 'crypto' as const }];
    expect(tiersForClusters(['a', 'b', 'a'], clusters)).toEqual(['ai', 'crypto']);
    expect(tiersForClusters(['a', 'zzz'], clusters)).toBeNull();
  });
});

test('describePolicy summarises every rule in plain English', () => {
  const lines = describePolicy(policy({ autopilot: { allowedHosts: ['vercel'], allowedProviders: ['openai'], maxServicesPerWave: 1, approvalTiers: ['crypto'] },
    approvals: { required: 2, requiredByTier: { crypto: 3 }, wideningAdmins: 2 }, network: { offline: true, requireProxy: true, allowHosts: ['a.example.com'] },
    notify: { allowedKinds: ['slack'] }, rotation: { revoke: 'never', minGraceSeconds: 600 }, audit: { exportRequired: true } }));
  expect(lines).toContain('Approvals: 2 operators or admins (crypto: 3); policy-widening changes: 2 admins.');
  expect(lines).toContain('Autopilot changes at most 1 service per wave.');
  expect(lines).toHaveLength(12);
});
