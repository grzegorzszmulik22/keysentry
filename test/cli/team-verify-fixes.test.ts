// Verification review fixes for team mode (docs/review-verify-p4-6.md): a dismissal carries the clusters of what it
// dismisses so per-tier rules apply (L-a), and an approved arm action covers the adoption rotations it names, with the
// approvals those rotations need (L-b).
import { writeFile } from 'node:fs/promises';
import { afterEach, describe, expect, it } from 'vitest';
import { actionDigest, ApprovalPendingError } from '../../src/approvals/index.js';
import { createMonitorState } from '../../src/monitor/index.js';
import { loadTeam } from '../../src/team/index.js';
import { card, cleanup, computer, member, teamDashboard, type Member, type Runtime } from './team-dashboard-fixture.js';

afterEach(cleanup);

async function team(roles: Record<string, 'viewer' | 'operator' | 'admin'>, policy: Record<string, unknown>) {
  const f = await computer();
  let rt = await f.runtime();
  expect((await f.cli(rt, ['team', 'init', '--id', 'ana', '--email', 'ana@example.test'])).code).toBe(0);
  const people: Record<string, Member> = {};
  for (const [id, role] of Object.entries(roles)) {
    people[id] = member();
    await writeFile(f.path(`${id}.json`), card(people[id]!));
    expect((await f.cli(rt, ['team', 'add', id, '--role', role, '--card', `${id}.json`, '--email', `${id}@example.test`])).code).toBe(0);
  }
  await writeFile(f.path('team-policy.json'), JSON.stringify(policy));
  expect((await f.cli(rt, ['policy', 'sign', 'team-policy.json', '--yes'])).code).toBe(0);
  expect((await f.cli(rt, ['policy', 'apply', 'team-policy.json', '--yes'])).code).toBe(0);
  rt = await f.runtime();
  const dash = await teamDashboard(rt);
  const signIn = async (id: string) => (await dash.signIn({ sub: `sub-${id}`, email: `${id}@example.test`, email_verified: true }))!;
  return { f, rt, dash, people, signIn };
}

const onlyCluster = async (rt: Runtime) => {
  const clusters = (await rt.inventory()).clusters;
  expect(clusters.map(cluster => cluster.tier)).toEqual(['ai']);
  return clusters[0]!.id;
};

describe('dismissals carry the clusters they concern (L-a)', () => {
  it('dismissing a pending rotation of an AI-tier key needs the AI tier approvals, and runs once they are met', async () => {
    const { rt, dash, people, signIn } = await team({ ben: 'operator', cy: 'operator' }, { approvals: { required: 1, requiredByTier: { ai: 2 }, wideningAdmins: 1 } });
    const clusterId = await onlyCluster(rt);
    const state = createMonitorState();
    state.pendingActions.push({ id: 'action-x', createdAt: new Date().toISOString(), signalId: 'signal-x', action: 'rotate', clusterIds: [clusterId], status: 'pending' });
    await rt.store.writeJson('monitor', rt.paths.monitor, state);
    const ben = await signIn('ben');

    const dismissal = await dash.change(ben, people.ben!.passkey, 'approvals/dismiss', { id: 'action-x' });
    expect(dismissal).toMatchObject({ status: 202, json: { approvals: 1, required: 2 } });
    expect((await rt.pendingActions()).map(action => action.id)).toEqual(['action-x']);
    const cy = await signIn('cy');
    const item = await dash.pending(cy, entry => entry.kind === 'approvals/dismiss');
    expect(item.changes.join(' ')).toMatch(/It concerns 1 key, so dismissing it needs the approvals a change of that key needs/);
    expect(await dash.change(cy, people.cy!.passkey, 'approvals/approve', { id: item.id, reviewHash: item.reviewHash }))
      .toMatchObject({ status: 200, json: { result: 'executed' } });
    expect(await rt.pendingActions()).toEqual([]);
  });

  it('a dismissal of something unknown still needs the policy\'s base count', async () => {
    const { dash, people, signIn } = await team({ ben: 'operator' }, { approvals: { required: 1, requiredByTier: { ai: 2 }, wideningAdmins: 1 } });
    const ben = await signIn('ben');
    const dismissal = await dash.change(ben, people.ben!.passkey, 'approvals/dismiss', { id: 'no-such-action' });
    // With no clusters the base count (1) applies: it runs, and finds nothing to dismiss.
    expect(dismissal.status).not.toBe(202);
  });
});

describe('arming with adoption on the team dashboard (L-b)', () => {
  it('an arm request that adopts a key also needs that key\'s rotation approvals', async () => {
    const { rt, dash, people, signIn } = await team({ bea: 'admin', cy: 'admin' }, { approvals: { required: 1, requiredByTier: { ai: 2 }, wideningAdmins: 1 } });
    const clusterId = await onlyCluster(rt);
    const bea = await signIn('bea');
    const armed = await dash.change(bea, people.bea!.passkey, 'autopilot/arm', { clusterIds: [clusterId], adopt: [clusterId], graceMinutes: 0, maxServices: 5, validDays: 30 });
    expect(armed).toMatchObject({ status: 202, json: { approvals: 1, required: 2 } });
    const cy = await signIn('cy');
    const item = await dash.pending(cy, entry => entry.kind === 'autopilot/arm');
    expect(item.changes.join(' ')).toMatch(/this approval covers that rotation, so it also needs the approvals rotating that key needs/);
  });

  it('the approved arm grant covers exactly the rotations it names, and checking it does not use it up', async () => {
    const { rt } = await team({ bea: 'admin', cy: 'admin' }, { approvals: { required: 1, requiredByTier: { ai: 2 }, wideningAdmins: 1 } });
    const clusterId = await onlyCluster(rt);
    const roster = (await loadTeam(rt.store, { anchor: rt.teamAnchors.roster }))!.roster.roster;
    const passkey = (id: string) => ({ memberId: id, credentialId: roster.members.find(entry => entry.id === id)!.passkeys[0]!.id });
    const service = rt.teamApprovalService();
    async function approvedArm(id: string, rotates?: string[]) {
      const action = { id, kind: 'dashboard:autopilot/arm', clusterIds: [clusterId], planHash: 'b'.repeat(64), ...(rotates ? { rotates } : {}) };
      const digest = actionDigest(action);
      await service.request(action, false, { admins: true });
      const first = await service.approveAsMember(id, passkey('bea'), digest).then(() => null, (error: unknown) => error);
      if (rotates) {
        expect(first).toBeInstanceOf(ApprovalPendingError);
        expect(first).toMatchObject({ approvals: 1, required: 2 });
        await service.approveAsMember(id, passkey('cy'), digest);
      } else expect(first).toBeNull();
      return { actionId: id, digest, kind: 'dashboard:autopilot/arm' };
    }
    const adopting = await approvedArm(`team-${'a'.repeat(32)}`, [clusterId]);
    const check = (grant: { actionId: string; digest: string; kind: string }, rotating?: string[]) =>
      rt.dashboardAction(() => rt.requireTeamGrant('dashboard:rotate/execute', rotating ? { rotating } : {}), { memberId: 'cy', grant });

    await expect(check(adopting, [clusterId])).resolves.toBeUndefined();
    await expect(check(adopting, ['sealed:another-key'])).rejects.toThrow(/needs the team's approvals first/);
    await expect(check(adopting, [clusterId, 'sealed:another-key'])).rejects.toThrow(/needs the team's approvals first/);
    await expect(check(adopting)).rejects.toThrow(/needs the team's approvals first/);
    // An arm action that names no adoption covers no rotation.
    const plain = await approvedArm(`team-${'c'.repeat(32)}`);
    await expect(check(plain, [clusterId])).rejects.toThrow(/needs the team's approvals first/);
    // The arm itself still runs under its grant afterwards: the adoption check did not use it up.
    await expect(rt.dashboardAction(() => rt.requireTeamGrant('dashboard:autopilot/arm'), { memberId: 'cy', grant: adopting })).resolves.toBeUndefined();
    await expect(service.checkGrant(adopting.actionId, adopting.digest)).resolves.toBeDefined();
  });
});
