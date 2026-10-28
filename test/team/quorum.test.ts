import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createStateCipher, createStateStore } from '../../src/core/store.js';
import { canonicalJson, generateDeviceKey, signDetached, type DeviceKey } from '../../src/security/index.js';
import { ApprovalError, ApprovalPendingError, createApprovalService, type ApprovalQuorum } from '../../src/approvals/service.js';
import type { ApprovalRequest, AuditEvent, AuditLog, PasskeyCredential, TeamPolicy, TeamRoster } from '../../src/types.js';
import { assertionFor, rosterOf, testMember, type TestMember } from './helpers.js';

const origin = 'https://watcher.example.org';
const ana = testMember('ana', 'admin');
const ben = testMember('ben', 'admin');
const cat = testMember('cat', 'operator');
const dan = testMember('dan', 'operator');
const vic = testMember('vic', 'viewer');
const outsider = testMember('zed', 'operator');
const action = { id: 'rotate-one', kind: 'rotation', clusterIds: ['cluster-a'] };

function policyWith(approvals: TeamPolicy['approvals']): TeamPolicy {
  return { v: 1, teamId: 'team-test-0001', version: 1, prev: null, updatedAt: '2026-10-28T00:00:00.000Z', autopilot: {}, approvals,
    network: {}, notify: {}, rotation: {}, audit: {} };
}

let dir: string;
let now: Date;
let events: AuditEvent[];
let roster: TeamRoster | null;
let policy: TeamPolicy | null;
let local: PasskeyCredential[];
let tiers: ApprovalQuorum['tiers'];
let teamFails: boolean;

function service(withQuorum = true) {
  const audit: AuditLog = { append: async (event) => { events.push(event); }, checkpoint: async () => {}, verify: async () => ({ ok: true, entries: events.length, checkpoints: 0 }) };
  return createApprovalService({
    store: createStateStore({ cwd: dir, cipher: createStateCipher(Buffer.alloc(32, 9)) }), audit,
    credentials: async () => local, deviceKeys: async () => [], rpId: 'watcher.example.org', origins: [origin], now: () => now,
    ...(withQuorum ? { quorum: { team: async () => { if (teamFails) throw new Error('boom'); return roster ? { roster, policy } : null; }, tiers: (input) => tiers?.(input) ?? null } } : {}),
  });
}

function device(request: ApprovalRequest, key: DeviceKey, at = now) {
  const message = { actionId: request.actionId, digest: request.digest, at: at.toISOString() };
  return { ...message, keyId: key.keyId, sig: signDetached(key.privateKeyDer, Buffer.from('keysentry-approval:v1\n' + canonicalJson(message))).toString('base64') };
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'keysentry-quorum-'));
  now = new Date('2026-10-28T10:00:00.000Z');
  events = [];
  roster = rosterOf([ana, ben, cat, dan, vic]);
  policy = policyWith({ required: 2, wideningAdmins: 2 });
  local = [];
  tiers = undefined;
  teamFails = false;
});
afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

describe('team quorum', () => {
  test('two of three operators approve; the request stays pending until the second', async () => {
    const approvals = service();
    const request = await approvals.request(action, false);
    expect(await approvals.describe(action.id)).toMatchObject({ status: 'pending', quorum: { approvals: 0, required: 2 } });
    const first = approvals.approveWithPasskey(action.id, assertionFor(cat, request.challenge));
    await expect(first).rejects.toBeInstanceOf(ApprovalPendingError);
    await expect(first).rejects.toThrow('Your approval was recorded: 1 of 2 team approvals so far.');
    expect(await approvals.status(action.id)).toBe('pending');
    expect(await approvals.describe(action.id)).toMatchObject({ quorum: { approvals: 1, required: 2 } });
    expect(events.some(event => event.kind === 'approvals:quorum-progress')).toBe(true);
    // A new service instance sees the recorded approval (it is durable).
    now = new Date(now.getTime() + 1000);
    const grant = await service().approveWithPasskey(action.id, assertionFor(dan, request.challenge));
    expect(grant.by).toEqual({ kind: 'passkey', credentialId: dan.credential.id });
    expect(grant.approvers).toEqual([
      { kind: 'passkey', credentialId: cat.credential.id, memberId: 'cat', at: '2026-10-28T10:00:00.000Z' },
      { kind: 'passkey', credentialId: dan.credential.id, memberId: 'dan', at: '2026-10-28T10:00:01.000Z' },
    ]);
    expect(await approvals.status(action.id)).toBe('approved');
    expect((await approvals.approved())[0]!.grant.approvers).toHaveLength(2);
  });

  test('a viewer cannot approve and is not counted', async () => {
    const approvals = service();
    const request = await approvals.request(action, false);
    await expect(approvals.approveWithPasskey(action.id, assertionFor(vic, request.challenge))).rejects.toThrow('Viewers can see approval requests but cannot approve them.');
    expect(await approvals.describe(action.id)).toMatchObject({ quorum: { approvals: 0 } });
    expect(events.some(event => event.kind === 'approvals:role-refused')).toBe(true);
  });

  test('the same member counts once, even with a second passkey', async () => {
    const second = testMember('cat', 'operator');
    const cat2: TestMember = { ...second, member: cat.member };
    roster!.members.find(member => member.id === 'cat')!.passkeys.push(second.credential);
    const approvals = service();
    const request = await approvals.request(action, false);
    await expect(approvals.approveWithPasskey(action.id, assertionFor(cat, request.challenge))).rejects.toBeInstanceOf(ApprovalPendingError);
    await expect(approvals.approveWithPasskey(action.id, assertionFor(cat2, request.challenge))).rejects.toThrow(/already approved this action/);
    // The same credential again is a replay, even with a higher counter.
    await expect(approvals.approveWithPasskey(action.id, assertionFor(cat, request.challenge, 1))).rejects.toThrow('This approval has already been used.');
    expect(await approvals.status(action.id)).toBe('pending');
  });

  test('a passkey that is not on the roster is refused, even when registered on this computer', async () => {
    local = [outsider.credential];
    const approvals = service();
    const request = await approvals.request(action, false);
    await expect(approvals.approveWithPasskey(action.id, assertionFor(outsider, request.challenge))).rejects.toThrow('This passkey or device key is not on the team roster.');
    // A local credential reusing a member's credential id with another key verifies against the local key but maps to no member.
    local = [{ ...outsider.credential, id: cat.credential.id }];
    const forged = { ...assertionFor(outsider, request.challenge), credentialId: cat.credential.id };
    await expect(approvals.approveWithPasskey(action.id, forged)).rejects.toThrow('This passkey or device key is not on the team roster.');
  });

  test('a credential unknown to both the roster and this computer counts as a failed attempt', async () => {
    roster = rosterOf([ana, cat, dan]);
    const approvals = service();
    const request = await approvals.request(action, false);
    for (let attempt = 0; attempt < 5; attempt++) {
      await expect(approvals.approveWithPasskey(action.id, assertionFor(outsider, request.challenge))).rejects.toThrow('This approval could not be verified.');
    }
    expect(await approvals.status(action.id)).toBe('rejected');
  });

  test('counters are per credential and a replayed assertion is refused', async () => {
    const approvals = service();
    const request = await approvals.request(action, false);
    await expect(approvals.approveWithPasskey(action.id, assertionFor(cat, request.challenge, 7))).rejects.toBeInstanceOf(ApprovalPendingError);
    // Dan's own counter starts at zero; Cat's does not affect it.
    const replay = assertionFor(cat, request.challenge, 7);
    await expect(approvals.approveWithPasskey(action.id, replay)).rejects.toThrow('This approval could not be verified.');
    await expect(approvals.approveWithPasskey(action.id, assertionFor(dan, request.challenge, 1))).resolves.toMatchObject({ actionId: action.id });
    // Replay after approval.
    await expect(approvals.approveWithPasskey(action.id, assertionFor(ana, request.challenge, 1))).rejects.toThrow('This approval has already been used.');
  });

  test('a partial approval does not survive expiry', async () => {
    const approvals = service();
    const request = await approvals.request(action, false);
    await expect(approvals.approveWithPasskey(action.id, assertionFor(cat, request.challenge))).rejects.toBeInstanceOf(ApprovalPendingError);
    now = new Date(now.getTime() + 11 * 60 * 1000);
    await expect(approvals.approveWithPasskey(action.id, assertionFor(dan, request.challenge))).rejects.toThrow('This approval request has expired.');
  });

  test('policy-widening actions need admins, approving with their device keys', async () => {
    const approvals = service();
    const request = await approvals.request({ ...action, id: 'widen-one', kind: 'arm' }, true);
    expect(await approvals.describe('widen-one')).toMatchObject({ quorum: { required: 2 } });
    await expect(approvals.approveWithPasskey('widen-one', assertionFor(ana, request.challenge))).rejects.toThrow(/only be approved on your own computer/);
    await expect(approvals.approveWithDevice('widen-one', device(request, cat.key))).rejects.toThrow('This change needs approval from team admins.');
    await expect(approvals.approveWithDevice('widen-one', device(request, ana.key))).rejects.toBeInstanceOf(ApprovalPendingError);
    const grant = await approvals.approveWithDevice('widen-one', device(request, ben.key));
    expect(grant.approvers!.map(approver => approver.memberId)).toEqual(['ana', 'ben']);
    expect(grant.by).toEqual({ kind: 'device', keyId: ben.key.keyId });
  });

  test('a device key outside the roster is not a member; a forged device signature is a failed attempt', async () => {
    const approvals = service();
    const request = await approvals.request(action, false);
    await expect(approvals.approveWithDevice(action.id, device(request, outsider.key))).rejects.toThrow('This approval could not be verified.');
    const forged = { ...device(request, generateDeviceKey()), keyId: cat.key.keyId };
    await expect(approvals.approveWithDevice(action.id, forged)).rejects.toThrow('This approval could not be verified.');
    await expect(approvals.approveWithDevice(action.id, device(request, cat.key))).rejects.toBeInstanceOf(ApprovalPendingError);
    await expect(approvals.approveWithDevice(action.id, device(request, cat.key, new Date(now.getTime() + 1)))).rejects.toThrow('This approval has already been used.');
  });

  test('requiredByTier applies to the action\'s tiers; unknown tiers use the strictest', async () => {
    policy = policyWith({ required: 1, requiredByTier: { crypto: 3 }, wideningAdmins: 1 });
    tiers = () => ['ai'];
    const approvals = service();
    const ai = await approvals.request(action, false);
    expect(await approvals.approveWithPasskey(action.id, assertionFor(cat, ai.challenge))).toMatchObject({ approvers: [{ memberId: 'cat' }] });
    tiers = () => ['ai', 'crypto'];
    const crypto = await approvals.request({ ...action, id: 'rotate-two' }, false);
    expect(await approvals.describe('rotate-two')).toMatchObject({ quorum: { required: 3 } });
    tiers = () => { throw new Error('inventory unavailable'); };
    await approvals.request({ ...action, id: 'rotate-three' }, false);
    expect(await approvals.describe('rotate-three')).toMatchObject({ quorum: { required: 3 } });
    void crypto;
  });

  test('a member removed after approving no longer counts', async () => {
    const approvals = service();
    const request = await approvals.request(action, false);
    await expect(approvals.approveWithPasskey(action.id, assertionFor(cat, request.challenge))).rejects.toBeInstanceOf(ApprovalPendingError);
    roster = rosterOf([ana, ben, dan, vic]);
    await expect(approvals.approveWithPasskey(action.id, assertionFor(dan, request.challenge))).rejects.toThrow('Your approval was recorded: 1 of 2');
    expect(await approvals.approveWithPasskey(action.id, assertionFor(ana, request.challenge))).toMatchObject({ approvers: [{ memberId: 'dan' }, { memberId: 'ana' }] });
  });

  test('a stricter policy during a pending request applies; a looser one does not', async () => {
    const approvals = service();
    const request = await approvals.request(action, false);
    policy = policyWith({ required: 1, wideningAdmins: 1 });
    await expect(approvals.approveWithPasskey(action.id, assertionFor(cat, request.challenge))).rejects.toThrow('1 of 2');
  });

  test('challenge offers only credentials of members who may still approve', async () => {
    const approvals = service();
    const request = await approvals.request(action, false);
    const ids = (await approvals.challenge(action.id)).allowCredentials.map(entry => entry.id);
    expect(ids.sort()).toEqual([ana, ben, cat, dan].map(entry => entry.credential.id).sort());
    await expect(approvals.approveWithPasskey(action.id, assertionFor(cat, request.challenge))).rejects.toBeInstanceOf(ApprovalPendingError);
    expect((await approvals.challenge(action.id)).allowCredentials.map(entry => entry.id)).not.toContain(cat.credential.id);
  });

  test('a roster that cannot be read pauses approvals instead of falling back to one approver', async () => {
    const approvals = service();
    const request = await approvals.request(action, false);
    teamFails = true;
    await expect(approvals.approveWithPasskey(action.id, assertionFor(cat, request.challenge))).rejects.toThrow('The team roster or policy could not be verified, so approvals are paused.');
    await expect(approvals.request({ ...action, id: 'rotate-two' }, false)).rejects.toBeInstanceOf(ApprovalError);
    teamFails = false;
    expect(await approvals.status(action.id)).toBe('pending');
  });

  test('a team of one approves with one approval and records the approver', async () => {
    roster = rosterOf([ana]);
    policy = null;
    const approvals = service();
    const request = await approvals.request(action, false);
    expect(await approvals.approveWithPasskey(action.id, assertionFor(ana, request.challenge))).toEqual({
      actionId: action.id, digest: request.digest, at: now.toISOString(), by: { kind: 'passkey', credentialId: ana.credential.id },
      approvers: [{ kind: 'passkey', credentialId: ana.credential.id, memberId: 'ana', at: now.toISOString() }],
    });
  });

  test('without a team the service behaves as before', async () => {
    roster = null;
    local = [cat.credential];
    for (const approvals of [service(), service(false)]) {
      const id = `rotate-${Math.random().toString(36).slice(2, 8)}`;
      const request = await approvals.request({ ...action, id }, false);
      expect(await approvals.describe(id)).not.toHaveProperty('quorum');
      const grant = await approvals.approveWithPasskey(id, assertionFor(cat, request.challenge, 0));
      expect(grant).toEqual({ actionId: id, digest: request.digest, at: now.toISOString(), by: { kind: 'passkey', credentialId: cat.credential.id } });
      local = [{ ...cat.credential }];
      now = new Date(now.getTime() + 1000);
    }
  });
});

describe('review fixes: stored quorums, admin quorums, run-time checks and honest counts', () => {
  test('L1: a request that recorded a quorum is never approved alone once the team stops being visible', async () => {
    const approvals = service();
    const request = await approvals.request(action, false);
    await expect(approvals.approveWithPasskey(action.id, assertionFor(cat, request.challenge))).rejects.toBeInstanceOf(ApprovalPendingError);
    roster = null;
    local = [cat.credential, dan.credential];
    const gone = /team roster is not available here, so approvals are paused/;
    await expect(approvals.approveWithPasskey(action.id, assertionFor(dan, request.challenge, 1))).rejects.toThrow(gone);
    await expect(approvals.approveWithDevice(action.id, device(request, dan.key))).rejects.toThrow(gone);
    await expect(approvals.challenge(action.id)).rejects.toThrow(gone);
    expect(await approvals.status(action.id)).toBe('pending');
  });

  test('an admin quorum takes wideningAdmins admins, each with a passkey; operators are refused', async () => {
    const approvals = service();
    const reveal = { ...action, id: 'reveal-one', kind: 'dashboard:reveal' };
    const request = await approvals.request(reveal, false, { admins: true });
    expect(await approvals.describe('reveal-one')).toMatchObject({ quorum: { approvals: 0, required: 2 } });
    // The same pending action cannot be requested again with the weaker operator rule.
    await expect(approvals.request(reveal, false)).resolves.toMatchObject({ digest: request.digest });
    expect(await approvals.describe('reveal-one')).toMatchObject({ quorum: { required: 2 } });
    await expect(approvals.approveWithPasskey('reveal-one', assertionFor(cat, request.challenge))).rejects.toThrow('This change needs approval from team admins.');
    await expect(approvals.approveAsMember('reveal-one', { memberId: 'ana', credentialId: ana.credential.id }, request.digest)).rejects.toBeInstanceOf(ApprovalPendingError);
    const grant = await approvals.approveAsMember('reveal-one', { memberId: 'ben', credentialId: ben.credential.id }, request.digest);
    expect(grant.approvers?.map(approver => approver.memberId)).toEqual(['ana', 'ben']);
  });

  test('checkGrant re-checks approvers against the current roster and policy when the action runs', async () => {
    const approvals = service();
    const request = await approvals.request(action, false);
    await expect(approvals.approveWithPasskey(action.id, assertionFor(cat, request.challenge))).rejects.toBeInstanceOf(ApprovalPendingError);
    await approvals.approveWithPasskey(action.id, assertionFor(dan, request.challenge));
    expect((await approvals.checkGrant(action.id, request.digest)).approvers).toHaveLength(2);
    await expect(approvals.checkGrant(action.id, 'f'.repeat(64))).rejects.toThrow('This action has no approval to run. Request it again.');
    // A raised requirement applies to a grant that has not run yet.
    policy = policyWith({ required: 3, wideningAdmins: 2 });
    await expect(approvals.checkGrant(action.id, request.digest)).rejects.toThrow('The approvals for this action no longer meet the team policy (2 of 3 still count). Ask team members to approve it again.');
    policy = policyWith({ required: 2, wideningAdmins: 2 });
    // Dan is demoted to viewer: his approval stops counting.
    roster = rosterOf([ana, ben, cat, { ...dan, member: { ...dan.member, role: 'viewer' } }, vic]);
    await expect(approvals.checkGrant(action.id, request.digest)).rejects.toThrow(/\(1 of 2 still count\)/);
    roster = null;
    await expect(approvals.checkGrant(action.id, request.digest)).rejects.toThrow(/team roster is not available here/);
    roster = rosterOf([ana, ben, cat, dan, vic]);
    await approvals.markExecuted(action.id, request.digest);
    await expect(approvals.checkGrant(action.id, request.digest)).rejects.toThrow('This action has no approval to run. Request it again.');
  });

  test('L5: "n of m" counts only approvers who still qualify', async () => {
    const approvals = service();
    const request = await approvals.request(action, false);
    await expect(approvals.approveWithPasskey(action.id, assertionFor(cat, request.challenge))).rejects.toBeInstanceOf(ApprovalPendingError);
    expect(await approvals.describe(action.id)).toMatchObject({ quorum: { approvals: 1, required: 2 } });
    roster = rosterOf([ana, ben, dan, vic]);
    expect(await approvals.describe(action.id)).toMatchObject({ quorum: { approvals: 0, required: 2 } });
    teamFails = true;
    expect(await approvals.describe(action.id)).toMatchObject({ quorum: { approvals: 0, required: 2 } });
  });
});

describe('verification review fixes: claims, adoption rotations and the approvals lock', () => {
  test('L-c: a run claims the approval first; a claimed approval never starts again, while its own checks still pass', async () => {
    const approvals = service();
    const request = await approvals.request(action, false);
    await expect(approvals.approveWithPasskey(action.id, assertionFor(cat, request.challenge))).rejects.toBeInstanceOf(ApprovalPendingError);
    await approvals.approveWithPasskey(action.id, assertionFor(dan, request.challenge));
    await expect(approvals.claim(action.id, 'f'.repeat(64))).rejects.toThrow('This action has no approval to run. Request it again.');
    expect((await approvals.claim(action.id, request.digest)).approvers).toHaveLength(2);
    expect(events.some(event => event.kind === 'approvals:claimed')).toBe(true);
    // The change's own entry-point checks still see the grant while it runs.
    await expect(approvals.checkGrant(action.id, request.digest)).resolves.toBeDefined();
    expect((await approvals.approved()).map(entry => entry.action.id)).toEqual([action.id]);
    // Another run (a retry, another request handler or another process) is refused, also by a new service instance.
    await expect(approvals.claim(action.id, request.digest)).rejects.toThrow('This change has already started with this approval.');
    await expect(service().claim(action.id, request.digest)).rejects.toThrow('This change has already started with this approval.');
    await approvals.markExecuted(action.id, request.digest);
    await expect(approvals.claim(action.id, request.digest)).rejects.toThrow('This action has no approval to run. Request it again.');
  });

  test('L-c: a claim re-checks the quorum like checkGrant', async () => {
    const approvals = service();
    const request = await approvals.request(action, false);
    await expect(approvals.approveWithPasskey(action.id, assertionFor(cat, request.challenge))).rejects.toBeInstanceOf(ApprovalPendingError);
    await approvals.approveWithPasskey(action.id, assertionFor(dan, request.challenge));
    roster = rosterOf([ana, ben, cat, vic]);
    await expect(approvals.claim(action.id, request.digest)).rejects.toThrow(/\(1 of 2 still count\)/);
    roster = rosterOf([ana, ben, cat, dan, vic]);
    await expect(approvals.claim(action.id, request.digest)).resolves.toBeDefined();
  });

  test('L-b: an admin request that also rotates keys needs those keys\' rotation approvals, and binds them into its digest', async () => {
    policy = policyWith({ required: 1, requiredByTier: { ai: 3 }, wideningAdmins: 1 });
    tiers = (input) => input.clusterIds.includes('cluster-ai') ? ['ai'] : ['app'];
    const approvals = service();
    const arm = { id: 'arm-one', kind: 'dashboard:autopilot/arm', clusterIds: ['cluster-a', 'cluster-ai'] };
    await approvals.request(arm, false, { admins: true });
    expect(await approvals.describe('arm-one')).toMatchObject({ quorum: { required: 1 } });
    const adopting = { ...arm, id: 'arm-two', rotates: ['cluster-ai'] };
    const request = await approvals.request(adopting, false, { admins: true });
    expect(await approvals.describe('arm-two')).toMatchObject({ quorum: { required: 3 } });
    expect(request.digest).not.toBe((await approvals.request({ ...adopting, id: 'arm-three', rotates: ['cluster-a'] }, false, { admins: true })).digest);
    // Only admins approve it.
    await expect(approvals.approveAsMember('arm-two', { memberId: 'cat', credentialId: cat.credential.id }, request.digest)).rejects.toThrow('This change needs approval from team admins.');
    await expect(approvals.request({ ...adopting, id: 'arm-bad', rotates: [] }, false, { admins: true })).rejects.toThrow('This action description is not valid.');
    await expect(approvals.request({ ...adopting, id: 'arm-dup', rotates: ['cluster-ai', 'cluster-ai'] }, false, { admins: true })).rejects.toThrow('This action description is not valid.');
  });

  test('L-c: transactions wait for another process\'s approvals lock and refuse one left by a process that exited', async () => {
    const approvals = service();
    const lock = join(dir, '.keysentry', '.approvals.lock');
    const { mkdir, writeFile, unlink } = await import('node:fs/promises');
    await mkdir(join(dir, '.keysentry'), { recursive: true });
    await writeFile(lock, JSON.stringify({ pid: process.pid, token: 'other' }));
    let done = false;
    const waiting = approvals.request(action, false).then(result => { done = true; return result; });
    await new Promise(resolve => setTimeout(resolve, 150));
    expect(done).toBe(false);
    await unlink(lock);
    await expect(waiting).resolves.toMatchObject({ actionId: action.id });
    await writeFile(lock, JSON.stringify({ pid: 2_147_483_646, token: 'gone' }));
    await expect(approvals.status(action.id)).rejects.toThrow('The approvals lock needs attention. Confirm that no keysentry command is running, then remove ".keysentry/.approvals.lock" and try again.');
    await unlink(lock);
    expect(await approvals.status(action.id)).toBe('pending');
  });
});
