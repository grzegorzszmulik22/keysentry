// The watcher in team mode: routed notifications, the policy's channel kinds and armed-plan check, members' roster
// passkeys and device keys, and quorum progress on the approval page.
import { request as httpRequest } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';
import { createWatchRuntime, type WatchRuntimeDependencies } from '../../src/cli/watcher.js';
import { buildArmedPlan, signArmedPlan } from '../../src/autopilot/index.js';
import { signDisarm } from '../../src/approvals/index.js';
import { createStateCipher, createStateStore } from '../../src/core/index.js';
import { signRoster } from '../../src/team/index.js';
import { generateDeviceKey } from '../../src/security/index.js';
import type { NotifyChannel, NotifyMessage, SignedNotifyMessage, SignedTeamPolicy, TeamPolicy, TeamRoster } from '../../src/types.js';
import { FakeHttp, text } from '../helpers/fake-http.js';
import { recoveryFixture } from '../rotate/recovery-fixture.js';
import { createWatcherStateStore } from '../../src/cli/watcher-state.js';
import { assertionFor, NOW, rosterOf, testMember } from '../team/helpers.js';

const dirs: string[] = [];
const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const close of closers.splice(0)) await close();
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

const ana = testMember('ana', 'admin', { origin: 'http://localhost' });
const ben = testMember('ben', 'operator', { origin: 'http://localhost' });
const cy = testMember('cy', 'operator', { origin: 'http://localhost' });
const vic = testMember('vic', 'viewer', { origin: 'http://localhost' });

function policy(rules: Partial<Pick<TeamPolicy, 'autopilot' | 'approvals' | 'notify'>>): SignedTeamPolicy {
  const body: TeamPolicy = { v: 1, teamId: 'team-test-0001', version: 1, prev: null, updatedAt: NOW.toISOString(), autopilot: {},
    approvals: { required: 1, wideningAdmins: 1 }, network: {}, notify: {}, rotation: {}, audit: {}, ...rules };
  return { policy: body, signatures: [] };
}

async function fixture(team: { roster: TeamRoster; policy: SignedTeamPolicy | null }) {
  const f = await recoveryFixture();
  const dir = await mkdtemp(join(tmpdir(), 'keysentry-team-watch-')); dirs.push(dir);
  const store = createWatcherStateStore(createStateStore({ cwd: dir, cipher: createStateCipher(Buffer.alloc(32, 5)) }), false);
  const key = generateDeviceKey();
  const armed = signArmedPlan(buildArmedPlan({ projectId: 'project', inventory: f.inv, clusterIds: [f.clusterId], hosts: ['railway'], options: {}, now: f.deps.now!() }).plan, key);
  await store.writeJson('plan', join(store.paths.dir, 'armed-plan.json'), armed);
  await store.writeJson('plan', join(store.paths.dir, 'autopilot.json'), { armedPlanId: armed.id, disarmed: false, waves: [] });
  await store.saveInventory(f.inv);
  const received: Record<string, SignedNotifyMessage[]> = { ops: [], team: [], chat: [] };
  const channel = (id: string, kind: NotifyChannel['kind']): NotifyChannel => ({ id, kind, async send(message) { received[id]!.push(message); } });
  const http = new FakeHttp();
  const events: unknown[] = [];
  const deps: WatchRuntimeDependencies = {
    store, audit: { async append(event) { events.push(event); }, async checkpoint() {}, async verify() { return { ok: true, entries: 0, checkpoints: 0 }; } },
    http, log: f.deps.log, rotation: f.opts, now: f.deps.now, env: {}, fingerprintKey: f.deps.fingerprintKey, projectId: 'project',
    signingKey: async () => key, deviceKeys: async () => [{ keyId: key.keyId, publicKeyDer: key.publicKeyDer }], passkeys: async () => [],
    channels: async () => [channel('ops', 'webhook'), channel('team', 'console'), channel('chat', 'slack')],
    sources: [], engine: async () => f.deps, freshInventory: async () => f.inv, async monitor() {}, assertHuman() {},
    team: { roster: signRoster(team.roster, 'ana', ana.key), policy: team.policy },
  };
  return { ...f, store, deps, received, key, http, events };
}

const message = (severity: NotifyMessage['severity']): NotifyMessage => ({ id: `m-${severity}`, at: NOW.toISOString(), kind: 'test', severity, title: 'Test', lines: [] });

describe('team notifications', () => {
  test('route by member severity, keep unassigned channels, and drop kinds the policy does not allow', async () => {
    const roster = rosterOf([ana, ben]);
    roster.members[1]!.notify = { channels: ['ops'], minSeverity: 'urgent' };
    const f = await fixture({ roster, policy: policy({ notify: { allowedKinds: ['webhook', 'console'] } }) });
    const watcher = await createWatchRuntime(f.deps);
    await watcher.notify(message('warning'));
    expect(f.received.ops).toHaveLength(0);
    expect(f.received.team).toHaveLength(1);
    await watcher.notify(message('urgent'));
    expect(f.received.ops).toHaveLength(1);
    expect(f.received.team).toHaveLength(2);
    expect(f.received.chat).toHaveLength(0);
  });

  test('a message routed to no channel is not a delivery failure, but no channel at all still fails closed', async () => {
    const roster = rosterOf([ana, ben]);
    roster.members[1]!.notify = { channels: ['ops'], minSeverity: 'urgent' };
    const f = await fixture({ roster, policy: policy({ notify: { allowedKinds: ['webhook'] } }) });
    const watcher = await createWatchRuntime(f.deps);
    await expect(watcher.notify(message('info'))).resolves.toBeUndefined();
    const none = await fixture({ roster, policy: policy({ notify: { allowedKinds: ['smtp'] } }) });
    await expect((await createWatchRuntime(none.deps)).notify(message('urgent'))).rejects.toThrow(/No notification channel delivered/);
  });
});

describe('team policy and roster on the watcher', () => {
  test('an armed plan outside the policy stops automatic actions', async () => {
    const inside = await fixture({ roster: rosterOf([ana]), policy: policy({ autopilot: { allowedHosts: ['railway'] } }) });
    expect((await (await createWatchRuntime(inside.deps)).check()).reasons).not.toContain('The armed plan is outside the team policy. Re-arm within the policy.');
    const outside = await fixture({ roster: rosterOf([ana]), policy: policy({ autopilot: { allowedHosts: ['vercel'] } }) });
    const checked = await (await createWatchRuntime(outside.deps)).check();
    expect(checked.ok).toBe(false);
    expect(checked.reasons).toContain('The armed plan is outside the team policy. Re-arm within the policy.');
  });

  test('operators may disarm through the relay with their roster device key; viewers may not', async () => {
    for (const [member, disarmed] of [[ben, true], [vic, false]] as const) {
      const f = await fixture({ roster: rosterOf([ana, ben, vic]), policy: null });
      f.deps.relay = { server: 'https://ntfy.sh', topic: 'team-topic' };
      const signed = signDisarm(member.key, { watcherId: 'project', at: f.deps.now!().toISOString() });
      f.http.on('GET', /ntfy\.sh/, () => text(200, JSON.stringify({ id: 'message-one', time: Math.floor(f.deps.now!().getTime() / 1000),
        event: 'message', topic: 'team-topic', message: JSON.stringify({ type: 'keysentry-disarm', v: 2, ...signed }) })));
      const watcher = await createWatchRuntime(f.deps);
      await watcher.tick();
      expect(watcher.state.disarmed).toBe(disarmed);
    }
  });

  test('the approval page counts roster passkeys toward the quorum and reports progress as 202, not a failure', async () => {
    const f = await fixture({ roster: rosterOf([ana, ben, cy, vic]), policy: policy({ approvals: { required: 2, wideningAdmins: 1 } }) });
    const watcher = await createWatchRuntime(f.deps);
    const request = await watcher.approvals.request({ id: 'approval-team', kind: 'autopilot', clusterIds: [f.clusterId] }, false);
    // A fixed local port, as the watcher's --port option takes one.
    const port = 43_000 + Math.floor(Math.random() * 2_000);
    const server = await watcher.server(port);
    closers.push(() => server.close());
    const origin = `http://localhost:${port}`;
    const post = (path: string, body: unknown) => new Promise<{ status: number; json: any }>((resolve, reject) => {
      const req = httpRequest({ hostname: '127.0.0.1', port, path, method: 'POST', headers: { Host: `localhost:${port}`, Origin: origin, 'Content-Type': 'application/json' } }, res => {
        let data = ''; res.setEncoding('utf8'); res.on('data', chunk => { data += chunk; });
        res.on('end', () => resolve({ status: res.statusCode!, json: JSON.parse(data) }));
      });
      req.on('error', reject); req.end(JSON.stringify(body));
    });
    const assert = (member: typeof ben) => {
      const assertion = assertionFor(member, request.challenge, 1, origin);
      return post(`/a/${request.actionId}/assert`, { digest: request.digest, credentialId: assertion.credentialId, clientDataJSON: assertion.clientDataJSON.toString('base64url'),
        authenticatorData: assertion.authenticatorData.toString('base64url'), signature: assertion.signature.toString('base64url') });
    };
    const challenge = await post(`/a/${request.actionId}/challenge`, { digest: request.digest });
    expect(challenge.json.allowCredentials.map((item: { id: string }) => item.id).sort()).toEqual([ana.credential.id, ben.credential.id, cy.credential.id].sort());
    expect(await assert(vic)).toMatchObject({ status: 403, json: { ok: false, text: 'Viewers can see approval requests but cannot approve them.' } });
    const first = await assert(ben);
    expect(first).toMatchObject({ status: 202, json: { ok: true, pending: true, approvals: 1, required: 2 } });
    expect(first.json.text).toBe('Your approval was recorded: 1 of 2 team approvals so far. The action runs only after 2 different team members approve it. 1 more approval from a team operator or admin who has not approved yet.');
    expect(await watcher.approvals.status(request.actionId)).toBe('pending');
    const second = await assert(cy);
    expect(second).toMatchObject({ status: 200, json: { ok: true } });
    expect(await watcher.approvals.status(request.actionId)).toBe('approved');
    const [approved] = await watcher.approvals.approved();
    expect(approved!.grant.approvers?.map(approver => approver.memberId)).toEqual(['ben', 'cy']);
  });
});
