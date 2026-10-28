// Fix round for the team-mode review: on the team dashboard every change is request-then-run under the team's quorum
// (C1), reveal needs the policy's admins and tells the team (M2), disarm needs the member's passkey and tells the team
// (M3), every dashboard event names the member (M4), and dismissing a team request needs the quorum too (L5).
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { actionDigest } from '../../src/approvals/index.js';
import { toExportRecord } from '../../src/audit-export/index.js';
import { createPhase3Runtime } from '../../src/cli/phase3-runtime.js';
import { createMonitorState } from '../../src/monitor/index.js';
import { card, cleanup, computer, member, teamDashboard, type Member, type Runtime } from './team-dashboard-fixture.js';

afterEach(cleanup);

const CONSOLE = 'rotation:\n  graceSeconds: 0\nnotify:\n  channels:\n    - id: team-console\n      kind: console\n';

/** Ana (admin, no dashboard passkey) starts the team on this computer; the others get cards with dashboard passkeys. */
async function team(roles: Record<string, 'viewer' | 'operator' | 'admin'>, policy?: Record<string, unknown>, yaml?: string) {
  const f = await computer(yaml ? { yaml } : {});
  let rt = await f.runtime();
  expect((await f.cli(rt, ['team', 'init', '--id', 'ana', '--email', 'ana@example.test'])).code).toBe(0);
  const people: Record<string, Member> = {};
  for (const [id, role] of Object.entries(roles)) {
    people[id] = member();
    await writeFile(f.path(`${id}.json`), card(people[id]!));
    expect((await f.cli(rt, ['team', 'add', id, '--role', role, '--card', `${id}.json`, '--email', `${id}@example.test`])).code).toBe(0);
  }
  if (policy) {
    await writeFile(f.path('team-policy.json'), JSON.stringify(policy));
    expect((await f.cli(rt, ['policy', 'sign', 'team-policy.json', '--yes'])).code).toBe(0);
    expect((await f.cli(rt, ['policy', 'apply', 'team-policy.json', '--yes'])).code).toBe(0);
  }
  rt = await f.runtime();
  const dash = await teamDashboard(rt);
  const signIn = async (id: string) => (await dash.signIn({ sub: `sub-${id}`, email: `${id}@example.test`, email_verified: true }))!;
  return { f, rt, dash, people, signIn };
}

const everyCluster = async (rt: Runtime) => (await rt.inventory()).clusters.map(cluster => cluster.id);

describe('team dashboard changes run only under the team quorum (C1)', () => {
  it('an operator\'s rotation waits for another member and runs when they approve it on the Approvals screen', async () => {
    const { f, rt, dash, people, signIn } = await team({ ben: 'operator', cy: 'operator' }, { approvals: { required: 2, wideningAdmins: 1 } });
    const ben = await signIn('ben');
    const preview = await dash.plain(ben, 'rotate/preview', { clusterIds: await everyCluster(rt) });
    expect(preview.status).toBe(200);
    const body = { planId: preview.json.planId, planHash: preview.json.planHash };

    const first = await dash.change(ben, people.ben!.passkey, 'rotate/execute', body);
    expect(first).toMatchObject({ status: 202, json: { teamRequest: 'recorded', approvals: 1, required: 2, text: expect.stringMatching(/1 of 2 team approvals so far/) } });
    expect({ keys: f.provider.keys.size, writes: f.host.writes.length, revoked: f.provider.revoked.length }).toEqual({ keys: 1, writes: 0, revoked: 0 });
    // The same change again by Ben reports progress; it is not a second approval.
    const again = await dash.change(ben, people.ben!.passkey, 'rotate/execute', body);
    expect(again).toMatchObject({ status: 202, json: { approvals: 1, required: 2, text: expect.stringMatching(/You already approved this change/) } });

    const cy = await signIn('cy');
    const item = await dash.pending(cy, entry => entry.source === 'team');
    expect(item).toMatchObject({ kind: 'rotate/execute', summary: 'Rotate 1 key (requested by ben)', quorum: { approvals: 1, required: 2 } });
    expect(item.changes[0]).toMatch(/Create replacement keys/);
    // Ben cannot complete his own request on the Approvals screen.
    expect(await dash.change(ben, people.ben!.passkey, 'approvals/approve', { id: item.id, reviewHash: item.reviewHash }))
      .toMatchObject({ status: 409, json: { error: expect.stringMatching(/already/) } });
    expect(f.provider.keys.size).toBe(1);

    const done = await dash.change(cy, people.cy!.passkey, 'approvals/approve', { id: item.id, reviewHash: item.reviewHash });
    expect(done).toMatchObject({ status: 200, json: { result: 'executed', text: 'Approved by the team and done: Rotate 1 key.' } });
    expect({ keys: f.provider.keys.size, writes: f.host.writes.length }).toEqual({ keys: 2, writes: 1 });
    expect(await dash.pending(cy, entry => entry.id === item.id)).toBeUndefined();

    // M4: the rotation's audit events name the member whose approval ran it; exports carry that actor.
    const journal = (await f.events()).filter(event => event.kind.startsWith('journal:'));
    expect(journal.length).toBeGreaterThan(0);
    expect(journal.every(event => event.data?.memberId === 'cy')).toBe(true);
    expect((await f.events()).find(event => event.kind === 'approvals:quorum-progress')?.data).toMatchObject({ memberId: 'ben' });
    const end = (await f.events()).find(entry => entry.kind === 'journal:plan-end') as unknown as Parameters<typeof toExportRecord>[0];
    expect(toExportRecord(end).actor).toBe('cy');
  });

  it('runtime entry points refuse a team dashboard change without a met grant of their own kind', async () => {
    const { f, rt, people } = await team({ ben: 'operator' });
    const plan = await rt.plan({ clusterIds: await everyCluster(rt) });
    const refused = /needs the team's approvals first/;
    const asBen = <T>(operation: () => Promise<T>, grant?: { actionId: string; digest: string; kind: string }) =>
      rt.dashboardAction(operation, { memberId: 'ben', ...(grant ? { grant } : {}) });
    await expect(asBen(() => rt.rotate(plan, { execute: true, prompt: async () => null }))).rejects.toThrow(refused);
    await expect(asBen(() => rt.finish(plan.id, true))).rejects.toThrow(refused);
    await expect(asBen(() => rt.vaultSet('RAILWAY_TOKEN', 'railway-value-123456', 'write'))).rejects.toThrow(refused);
    await expect(asBen(() => rt.vaultRemove('RAILWAY_TOKEN', 'write'))).rejects.toThrow(refused);
    await expect(asBen(() => createPhase3Runtime(rt).updateSettings({ showHints: false }))).rejects.toThrow(refused);
    await expect(asBen(() => createPhase3Runtime(rt).spendLimits(true))).rejects.toThrow(refused);
    await expect(asBen(() => rt.dismiss('action-x'))).rejects.toThrow(refused);

    // An approved request for another kind of change does not authorize this one.
    const service = rt.teamApprovalService();
    const action = { id: 'team-0123456789abcdef0123456789abcdef', kind: 'dashboard:settings/update', clusterIds: [], planHash: 'a'.repeat(64) };
    await service.request(action, false, { admins: true });
    await expect(service.approveAsMember(action.id, { memberId: 'ben', credentialId: people.ben!.passkey.id }, actionDigest(action))).rejects.toThrow(/needs approval from team admins/);
    const operatorAction = { ...action, id: 'team-fedcba9876543210fedcba9876543210', kind: 'dashboard:spend-limits/apply' };
    await service.request(operatorAction, false);
    await service.approveAsMember(operatorAction.id, { memberId: 'ben', credentialId: people.ben!.passkey.id }, actionDigest(operatorAction));
    const grant = { actionId: operatorAction.id, digest: actionDigest(operatorAction), kind: 'dashboard:rotate/execute' };
    await expect(asBen(() => rt.rotate(plan, { execute: true, prompt: async () => null }), grant)).rejects.toThrow(refused);
    expect(f.provider.keys.size).toBe(1);

    // Terminal and local dashboard (no member) are unchanged.
    await rt.dashboardAction(() => rt.vaultSet('RAILWAY_TOKEN', 'railway-value-123456', 'write'));
    expect((await rt.vaultList()).some(entry => entry.name === 'RAILWAY_TOKEN')).toBe(true);
  });

  it('re-checks the approvers against the current roster when the change runs', async () => {
    const { f, rt, people } = await team({ ben: 'operator', cy: 'operator' }, { approvals: { required: 2, wideningAdmins: 1 } });
    const plan = await rt.plan({ clusterIds: await everyCluster(rt) });
    const service = rt.teamApprovalService();
    const action = { id: 'team-00112233445566778899aabbccddeeff', kind: 'dashboard:rotate/execute', clusterIds: plan.steps.map(step => step.clusterId), planHash: 'b'.repeat(64) };
    await service.request(action, false);
    await expect(service.approveAsMember(action.id, { memberId: 'ben', credentialId: people.ben!.passkey.id }, actionDigest(action))).rejects.toThrow(/1 of 2/);
    await service.approveAsMember(action.id, { memberId: 'cy', credentialId: people.cy!.passkey.id }, actionDigest(action));
    // Cy leaves the team before the change runs: her approval stops counting.
    expect((await f.cli(rt, ['team', 'remove', 'cy'])).code).toBe(0);
    const grant = { actionId: action.id, digest: actionDigest(action), kind: action.kind };
    await expect(rt.dashboardAction(() => rt.rotate(plan, { execute: true, prompt: async () => null }), { memberId: 'ben', grant }))
      .rejects.toThrow(/no longer meet the team policy \(1 of 2 still count\)/);
    expect(f.provider.keys.size).toBe(1);
  });

  it('a credential is stored only after the admins approve, and its value is never kept with the request', async () => {
    const { rt, dash, people, signIn } = await team({ bea: 'admin', dan: 'admin', ben: 'operator' }, { approvals: { required: 1, wideningAdmins: 2 } });
    const bea = await signIn('bea');
    const value = 'railway-token-for-the-team-server-0123';
    const body = { name: 'RAILWAY_TOKEN', role: 'write', value };
    const first = await dash.change(bea, people.bea!.passkey, 'vault/store', body);
    expect(first).toMatchObject({ status: 202, json: { teamRequest: 'recorded', approvals: 1, required: 2, text: expect.stringMatching(/make the same change again here/) } });
    expect((await rt.vaultList()).some(entry => entry.name === 'RAILWAY_TOKEN')).toBe(false);
    const kept = JSON.stringify([await rt.store.readJson('pending', join(rt.paths.dir, 'team-dashboard-requests.json')), await rt.store.readJson('pending', join(rt.paths.dir, 'approvals.json'))]);
    expect(kept).not.toContain(value);

    // An operator cannot approve an admin change.
    const ben = await signIn('ben');
    const item = await dash.pending(ben, entry => entry.source === 'team');
    expect(item).toMatchObject({ kind: 'vault/store', summary: 'Store the RAILWAY_TOKEN credential (requested by bea)', quorum: { approvals: 1, required: 2 } });
    expect(await dash.change(ben, people.ben!.passkey, 'approvals/approve', { id: item.id, reviewHash: item.reviewHash }))
      .toMatchObject({ status: 409, json: { error: 'This change needs approval from team admins.' } });
    const dan = await signIn('dan');
    expect(await dash.change(dan, people.dan!.passkey, 'approvals/approve', { id: item.id, reviewHash: item.reviewHash }))
      .toMatchObject({ status: 200, json: { result: 'approved', text: 'Approved by the team. bea can now make this change: Store the RAILWAY_TOKEN credential.' } });
    expect((await rt.vaultList()).some(entry => entry.name === 'RAILWAY_TOKEN')).toBe(false);
    // Bea enters it again: now it is stored, once.
    expect(await dash.change(bea, people.bea!.passkey, 'vault/store', body)).toMatchObject({ status: 200, json: { stored: true } });
    expect((await rt.vaultList()).some(entry => entry.name === 'RAILWAY_TOKEN')).toBe(true);
    expect(await dash.change(bea, people.bea!.passkey, 'vault/store', body)).toMatchObject({ status: 202 });
  });

  it('dismissing a pending action on the team dashboard needs the quorum too (L5)', async () => {
    const { rt, dash, people, signIn } = await team({ ben: 'operator', cy: 'operator' }, { approvals: { required: 2, wideningAdmins: 1 } });
    const state = createMonitorState();
    state.pendingActions.push({ id: 'action-x', createdAt: new Date().toISOString(), signalId: 'signal-x', action: 'rotate', clusterIds: await everyCluster(rt), status: 'pending' });
    await rt.store.writeJson('monitor', rt.paths.monitor, state);
    const ben = await signIn('ben');
    expect(await dash.change(ben, people.ben!.passkey, 'approvals/dismiss', { id: 'action-x' })).toMatchObject({ status: 202, json: { approvals: 1, required: 2 } });
    expect((await rt.pendingActions()).map(action => action.id)).toEqual(['action-x']);
    const cy = await signIn('cy');
    const item = await dash.pending(cy, entry => entry.source === 'team' && entry.kind === 'approvals/dismiss');
    expect(item.summary).toBe('Dismiss a pending request (requested by ben)');
    expect(await dash.change(cy, people.cy!.passkey, 'approvals/approve', { id: item.id, reviewHash: item.reviewHash })).toMatchObject({ status: 200, json: { result: 'executed' } });
    expect(await rt.pendingActions()).toEqual([]);
  });

  it('"n of m" counts only approvers who are still on the roster', async () => {
    const { f, rt, dash, people, signIn } = await team({ ben: 'operator', cy: 'operator', dee: 'operator' }, { approvals: { required: 2, wideningAdmins: 1 } });
    const ben = await signIn('ben');
    const preview = await dash.plain(ben, 'rotate/preview', { clusterIds: await everyCluster(rt) });
    expect((await dash.change(ben, people.ben!.passkey, 'rotate/execute', { planId: preview.json.planId, planHash: preview.json.planHash })).status).toBe(202);
    const cy = await signIn('cy');
    expect((await dash.pending(cy, entry => entry.source === 'team')).quorum).toEqual({ approvals: 1, required: 2 });
    expect((await f.cli(rt, ['team', 'remove', 'ben'])).code).toBe(0);
    expect((await dash.pending(cy, entry => entry.source === 'team')).quorum).toEqual({ approvals: 0, required: 2 });
  });
});

describe('reveal and disarm on the team dashboard (M2, M3)', () => {
  it('a reveal runs after the policy\'s admins approve it, and the team\'s channels are told who revealed a value', async () => {
    const { f, rt, dash, people, signIn } = await team({ bea: 'admin', dan: 'admin' }, { approvals: { required: 1, wideningAdmins: 2 } }, CONSOLE);
    const bea = await signIn('bea');
    const cluster = (await rt.inventory()).clusters[0]!;
    const first = await dash.change(bea, people.bea!.passkey, 'reveal', { clusterId: cluster.id });
    expect(first.status).toBe(202);
    expect(first.json.value).toBeUndefined();
    const dan = await signIn('dan');
    const item = await dash.pending(dan, entry => entry.source === 'team');
    expect(item.changes).toContain('The team\'s notification channels are told who revealed it.');
    // Dan's approval does not show him the value; Bea's browser gets it when she reveals again.
    const approved = await dash.change(dan, people.dan!.passkey, 'approvals/approve', { id: item.id, reviewHash: item.reviewHash });
    expect(approved).toMatchObject({ status: 200, json: { result: 'approved' } });
    expect(approved.text).not.toContain(f.original.value);
    const shown = await dash.change(bea, people.bea!.passkey, 'reveal', { clusterId: cluster.id });
    expect(shown).toMatchObject({ status: 200, json: { value: f.original.value } });
    const told = (await f.events()).find(event => event.kind === 'notify:team');
    expect(told).toMatchObject({ data: { notice: 'team-reveal', delivered: 1, failed: 0, memberId: 'bea' } });
    expect((await f.events()).find(event => event.kind === 'reveal')?.data?.memberId).toBe('bea');
  });

  it('disarm needs the member\'s own passkey (an identity provider session alone cannot) and tells the team', async () => {
    const { f, dash, people, signIn } = await team({ ben: 'operator' }, undefined, CONSOLE);
    const ben = await signIn('ben');
    expect((await dash.plain(ben, 'autopilot/disarm', {})).status).toBe(403);
    expect(await dash.change(ben, people.ben!.passkey, 'autopilot/disarm', {})).toMatchObject({ status: 200, json: { state: 'disarmed' } });
    expect((await f.events()).find(event => event.kind === 'notify:team')).toMatchObject({ data: { notice: 'team-disarm', delivered: 1, memberId: 'ben' } });
  });
});
