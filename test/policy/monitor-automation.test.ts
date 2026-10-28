// Review H2 and M1: under a signed team policy the monitor's automatic actions are off unless the policy allows them,
// and a minimum grace period also stops "revoke immediately".
import { writeFile } from 'node:fs/promises';
import { afterEach, describe, expect, it } from 'vitest';
import { configSchema } from '../../src/cli/config.js';
import { defaultPolicy } from '../../src/monitor/policy.js';
import { effectiveSettings, narrowMonitorPolicy, narrowRotationOptions } from '../../src/policy/index.js';
import { TIER_ORDER, type TeamPolicy } from '../../src/types.js';
import { cleanup, computer } from '../cli/team-dashboard-fixture.js';

afterEach(cleanup);

const rules = (body: Partial<TeamPolicy> = {}): TeamPolicy => ({ v: 1, teamId: 'team-test-0001', version: 1, prev: null, updatedAt: '2026-10-28T10:00:00.000Z',
  autopilot: {}, approvals: { required: 1, wideningAdmins: 1 }, network: {}, notify: {}, rotation: {}, audit: {}, ...body });

describe('monitor automation under a team policy', () => {
  it('is off by default, stays on only when the policy allows it, and is unchanged without a policy', () => {
    const settings = configSchema.parse({ monitor: { autoExecute: true, autoContain: true, revokeUnconfirmedOnHighConfidence: true } });
    expect(effectiveSettings(settings, rules()).monitor).toMatchObject({ autoExecute: false, autoContain: false, revokeUnconfirmedOnHighConfidence: false });
    expect(effectiveSettings(settings, rules({ autopilot: { allowMonitorAutomation: true } })).monitor).toMatchObject({ autoExecute: true, autoContain: true });
    expect(effectiveSettings(settings, null).monitor).toMatchObject({ autoExecute: true, autoContain: true });
    const monitor = { ...defaultPolicy(), autoExecute: true, autoContain: true };
    expect(narrowMonitorPolicy(monitor, rules())).toMatchObject({ autoExecute: false, autoContain: false, revokeUnconfirmedOnHighConfidence: false });
    expect(narrowMonitorPolicy(monitor, rules({ autopilot: { allowMonitorAutomation: true } }))).toMatchObject({ autoExecute: true, autoContain: true });
    expect(monitor.autoExecute).toBe(true);
  });

  it('a runtime under a policy ignores KEYSENTRY_AUTO_EXECUTE and KEYSENTRY_AUTO_CONTAIN unless the policy allows automation', async () => {
    const f = await computer();
    let rt = await f.runtime();
    expect((await f.cli(rt, ['team', 'init', '--id', 'ana'])).code).toBe(0);
    await writeFile(f.path('team-policy.json'), JSON.stringify({ approvals: { required: 1, wideningAdmins: 1 } }));
    expect((await f.cli(rt, ['policy', 'sign', 'team-policy.json', '--yes'])).code).toBe(0);
    expect((await f.cli(rt, ['policy', 'apply', 'team-policy.json', '--yes'])).code).toBe(0);
    const env = { KEYSENTRY_AUTO_EXECUTE: 'true', KEYSENTRY_AUTO_CONTAIN: 'true' };
    rt = await f.runtime(env);
    expect({ execute: rt.config.monitor.policy.autoExecute, contain: rt.config.monitor.policy.autoContain }).toEqual({ execute: false, contain: false });
    expect(rt.config.settings.monitor.autoExecute).toBe(false);

    await writeFile(f.path('allow.json'), JSON.stringify({ approvals: { required: 1, wideningAdmins: 1 }, autopilot: { allowMonitorAutomation: true, approvalTiers: [...TIER_ORDER] } }));
    expect((await f.cli(rt, ['policy', 'sign', 'allow.json', '--yes'])).code).toBe(0);
    expect((await f.cli(rt, ['policy', 'apply', 'allow.json', '--yes'])).code).toBe(0);
    rt = await f.runtime(env);
    expect(rt.config.monitor.policy.autoExecute).toBe(true);
  });
});

describe('a minimum grace period (M1)', () => {
  it('turns "revoke immediately" into revoking after deploy', () => {
    expect(narrowRotationOptions({ revoke: 'immediately' as const, graceMs: 0 }, rules({ rotation: { minGraceSeconds: 600 } }))).toEqual({ revoke: 'after-deploy', graceMs: 600_000 });
    expect(narrowRotationOptions({ revoke: 'immediately' as const }, rules({ rotation: { minGraceSeconds: 0 } }))).toEqual({ revoke: 'immediately' });
    expect(effectiveSettings(configSchema.parse({ rotation: { revoke: 'immediately' } }), rules({ rotation: { minGraceSeconds: 60 } })).rotation.revoke).toBe('after-deploy');
  });

  it('finish --now keeps the old key until the policy minimum has passed, then revokes it before the grace deadline', async () => {
    let clock = Date.parse('2026-10-28T10:00:00.000Z');
    const f = await computer({ zeroGrace: false, grace: async () => 'defer', now: () => new Date(clock) });
    let rt = await f.runtime();
    expect((await f.cli(rt, ['team', 'init', '--id', 'ana'])).code).toBe(0);
    await writeFile(f.path('team-policy.json'), JSON.stringify({ approvals: { required: 1, wideningAdmins: 1 }, rotation: { minGraceSeconds: 600 } }));
    expect((await f.cli(rt, ['policy', 'sign', 'team-policy.json', '--yes'])).code).toBe(0);
    expect((await f.cli(rt, ['policy', 'apply', 'team-policy.json', '--yes'])).code).toBe(0);
    rt = await f.runtime();
    Object.assign(rt.config.rotation, { graceMs: 3_600_000 });
    expect(rt.config.rotation.minGraceMs).toBe(600_000);
    const plan = await rt.plan({ clusterIds: (await rt.inventory()).clusters.map(cluster => cluster.id) });
    const report = await rt.dashboardAction(() => rt.rotate(plan, { execute: true, prompt: async () => null }));
    expect(report.status).toBe('grace-pending');
    const early = await rt.dashboardAction(() => rt.finish(plan.id, true));
    expect(f.provider.revoked).toEqual([]);
    expect(early.steps[0]!.warnings).toContain('The team policy keeps old keys for a minimum grace period, which has not passed; the old key is retained.');
    // Eleven minutes later: past the policy's 10-minute minimum, still well before the one-hour grace deadline.
    clock += 11 * 60_000;
    await rt.dashboardAction(() => rt.finish(plan.id, true));
    expect(f.provider.revoked).toHaveLength(1);
  });
});
