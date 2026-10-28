import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { copyFile, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createStateCipher, createStateStore, type StateStore } from '../../src/core/store.js';
import {
  applyPolicy, checkPolicyProposal, loadPolicy, loadPolicyHead, policyHash, policyStatePath, preparePolicyDraft, requirePolicyForChanges, signPolicy,
  verifyPolicy, PolicyError,
} from '../../src/policy/index.js';
import { applyRoster, nextRoster, signRoster, vaultTeamAnchor, type LoadedTeam } from '../../src/team/index.js';
import type { SignedTeamPolicy, SignedTeamRoster, TeamRoster } from '../../src/types.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { NOW, rosterOf, testMember } from '../team/helpers.js';

const ana = testMember('ana', 'admin');
const ben = testMember('ben', 'admin');
const cat = testMember('cat', 'operator');

let dir: string;
let store: StateStore;
let roster: TeamRoster;
let team: LoadedTeam;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'keysentry-policy-'));
  store = createStateStore({ cwd: dir, cipher: createStateCipher(Buffer.alloc(32, 4)) });
  roster = rosterOf([ana, ben, cat], { adminThreshold: 2 });
  const signed = signRoster(signRoster(roster, 'ana', ana.key), 'ben', ben.key);
  const applied = await applyRoster(store, signed);
  team = { roster: applied.roster, hash: applied.hash };
});
afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

function draft(body: Record<string, unknown> = {}, head: { policy: SignedTeamPolicy; hash: string } | null = null): SignedTeamPolicy {
  return preparePolicyDraft({ approvals: { required: 2, wideningAdmins: 2 }, ...body }, { roster, head, now: NOW });
}
function signedBy(policy: SignedTeamPolicy, ...admins: typeof ana[]): SignedTeamPolicy {
  return admins.reduce((value, admin) => signPolicy(value, admin.member.id, admin.key), policy);
}

describe('policy drafts and signatures', () => {
  test('a draft gets the team, version, previous hash and time; defaults fill missing sections', () => {
    const prepared = preparePolicyDraft({}, { roster, head: null, now: NOW });
    expect(prepared).toEqual({ signatures: [], policy: { v: 1, teamId: roster.teamId, version: 1, prev: null, updatedAt: NOW.toISOString(),
      autopilot: {}, approvals: { required: 1, wideningAdmins: 1 }, network: {}, notify: {}, rotation: {}, audit: {} } });
    const v1 = signedBy(prepared, ana, ben);
    const next = preparePolicyDraft({ policy: { network: { offline: true } } }, { roster, head: { policy: v1, hash: policyHash(v1) }, now: NOW });
    expect(next.policy).toMatchObject({ version: 2, prev: policyHash(v1), network: { offline: true } });
  });

  test('a draft that names another team, version or previous hash, or has unknown fields, is refused', () => {
    expect(() => preparePolicyDraft({ teamId: 'another-team-01' }, { roster, head: null, now: NOW })).toThrow('This policy draft belongs to a different team.');
    expect(() => preparePolicyDraft({ version: 3 }, { roster, head: null, now: NOW })).toThrow(/next version is 1/);
    expect(() => preparePolicyDraft({ prev: 'a'.repeat(64) }, { roster, head: null, now: NOW })).toThrow(/does not extend/);
    expect(() => preparePolicyDraft({ autopilot: { allowedHosts: ['nowhere'] } }, { roster, head: null, now: NOW })).toThrow(/check autopilot.allowedHosts/);
    expect(() => preparePolicyDraft({ approvals: { required: 0 } }, { roster, head: null, now: NOW })).toThrow(PolicyError);
    expect(() => preparePolicyDraft({ surprise: true }, { roster, head: null, now: NOW })).toThrow(PolicyError);
    expect(() => preparePolicyDraft({ network: { allowHosts: ['10.0.0.1'] } }, { roster, head: null, now: NOW })).toThrow(PolicyError);
    expect(() => preparePolicyDraft({ network: { allowHosts: ['*.example.com'] } }, { roster, head: null, now: NOW })).toThrow(PolicyError);
  });

  test('a policy needs the roster\'s admin threshold of current admins', () => {
    const prepared = draft();
    expect(verifyPolicy(signedBy(prepared, ana), roster, null)).toEqual({ ok: false, reason: 'This change has 1 of the 2 admin signatures it needs.' });
    expect(verifyPolicy(signedBy(prepared, ana, cat), roster, null)).toMatchObject({ ok: false, reason: expect.stringMatching(/not an admin/) });
    expect(verifyPolicy(signedBy(prepared, ana, ben), roster, null)).toMatchObject({ ok: true, relation: 'first', signers: ['ana', 'ben'] });
    expect(checkPolicyProposal(signedBy(prepared, ana), roster, null)).toMatchObject({ ok: true, signers: ['ana'] });
    expect(() => signPolicy(signedBy(prepared, ana), 'ana', ana.key)).toThrow(/already signed/);
  });

  test('a changed body, a different team, or an admin removed since signing is refused', () => {
    const v1 = signedBy(draft(), ana, ben);
    const changed = structuredClone(v1); changed.policy.approvals.required = 1;
    expect(verifyPolicy(changed, roster, null)).toMatchObject({ ok: false, reason: expect.stringMatching(/changed after signing/) });
    expect(verifyPolicy(v1, { ...roster, teamId: 'another-team-01' }, null)).toMatchObject({ ok: false, reason: 'This policy belongs to a different team.' });
    const withoutBen = rosterOf([ana, cat], { adminThreshold: 1 });
    expect(verifyPolicy(v1, withoutBen, null)).toMatchObject({ ok: false, reason: expect.stringMatching(/not an admin/) });
  });

  test('chain: next version links by hash; rollback and same-version forks are refused; later versions may skip', () => {
    const v1 = signedBy(draft(), ana, ben);
    const head = { policy: v1, hash: policyHash(v1) };
    const v2 = signedBy(draft({ network: { offline: true } }, head), ana, ben);
    expect(verifyPolicy(v2, roster, head)).toMatchObject({ ok: true, relation: 'newer' });
    expect(verifyPolicy(v1, roster, head)).toMatchObject({ ok: true, relation: 'same' });
    const v2head = { policy: v2, hash: policyHash(v2) };
    expect(verifyPolicy(v1, roster, v2head)).toMatchObject({ ok: false, reason: expect.stringMatching(/rollback/) });
    const fork = signedBy(draft({ network: { requireProxy: true } }, head), ana, ben);
    expect(verifyPolicy(fork, roster, v2head)).toMatchObject({ ok: false, reason: expect.stringMatching(/fork/) });
    const badLink = signedBy({ policy: { ...v2.policy, prev: 'b'.repeat(64) }, signatures: [] }, ana, ben);
    expect(verifyPolicy(badLink, roster, head)).toMatchObject({ ok: false, reason: expect.stringMatching(/does not extend/) });
    const v4 = signedBy({ policy: { ...v2.policy, version: 4, prev: 'c'.repeat(64) }, signatures: [] }, ana, ben);
    expect(verifyPolicy(v4, roster, head)).toMatchObject({ ok: true, relation: 'newer' });
  });
});

describe('saved policy and the policy file', () => {
  async function writePolicy(value: unknown, name = 'keysentry-policy.json') { await writeFile(join(dir, name), JSON.stringify(value)); return name; }
  const load = (policyFile: string | undefined, loaded: LoadedTeam | null = team, anchor?: ReturnType<typeof vaultTeamAnchor>) =>
    loadPolicy({ store, cwd: dir, policyFile, team: loaded, anchor });

  test('no policy file and nothing applied means no policy', async () => {
    expect(await load(undefined)).toEqual({ status: 'none' });
    expect(requirePolicyForChanges({ status: 'none' })).toBeNull();
  });

  test('each refusal says which: missing file, invalid JSON, bad signature, no roster, unset file after applying', async () => {
    expect(await load('missing.json')).toEqual({ status: 'refused', reason: 'The team policy file named in team.policyFile was not found.' });
    await writeFile(join(dir, 'broken.json'), '{ not json');
    expect(await load('broken.json')).toEqual({ status: 'refused', reason: 'The team policy file named in team.policyFile is not valid JSON.' });
    const unsigned = await writePolicy(signedBy(draft(), ana));
    expect(await load(unsigned)).toEqual({ status: 'refused', reason: 'The team policy file is not valid: This change has 1 of the 2 admin signatures it needs.' });
    const valid = await writePolicy(signedBy(draft(), ana, ben));
    expect(await load(valid, null)).toMatchObject({ status: 'refused', reason: expect.stringMatching(/no team roster/) });
    expect(await load(valid)).toMatchObject({ status: 'ok', advanced: true });
    expect(await load(undefined)).toMatchObject({ status: 'refused', reason: expect.stringMatching(/team.policyFile is not set/) });
    expect(() => requirePolicyForChanges({ status: 'refused', reason: 'The team policy file was not found.' })).toThrow('Changes are paused: The team policy file was not found.');
  });

  test('a verified newer file becomes the applied head; an older file is refused', async () => {
    const v1 = signedBy(draft(), ana, ben);
    await writePolicy(v1);
    expect(await load('keysentry-policy.json')).toMatchObject({ status: 'ok', advanced: true });
    expect(await load('keysentry-policy.json')).toMatchObject({ status: 'ok', advanced: false });
    const v2 = signedBy(draft({ network: { offline: true } }, { policy: v1, hash: policyHash(v1) }), ana, ben);
    await writePolicy(v2);
    expect(await load('keysentry-policy.json')).toMatchObject({ status: 'ok', advanced: true });
    expect((await loadPolicyHead(store))!.policy.policy.version).toBe(2);
    await writePolicy(v1);
    expect(await load('keysentry-policy.json')).toMatchObject({ status: 'refused', reason: expect.stringMatching(/rollback protection/) });
  });

  test('applyPolicy refuses rollback; an older saved head is caught by the checkpoint', async () => {
    const anchor = vaultTeamAnchor(createFakeVault(), 'project-1', 'policy');
    const v1 = signedBy(draft(), ana, ben);
    expect(await applyPolicy(store, v1, { roster, anchor })).toMatchObject({ status: 'applied' });
    expect(await applyPolicy(store, v1, { roster, anchor })).toMatchObject({ status: 'unchanged' });
    await copyFile(policyStatePath(store), join(dir, 'saved-v1'));
    const v2 = signedBy(draft({ rotation: { revoke: 'never' } }, { policy: v1, hash: policyHash(v1) }), ana, ben);
    await applyPolicy(store, v2, { roster, anchor });
    await expect(applyPolicy(store, v1, { roster, anchor })).rejects.toThrow(/rollback/);
    await copyFile(join(dir, 'saved-v1'), policyStatePath(store));
    await expect(loadPolicyHead(store, { anchor })).rejects.toThrow(/rollback protection/);
    expect(await load(undefined, team, anchor)).toMatchObject({ status: 'refused', reason: expect.stringMatching(/rollback protection/) });
  });

  test('a policy file that is not a regular file or is too large is refused', async () => {
    expect(await load('.')).toMatchObject({ status: 'refused', reason: expect.stringMatching(/regular file/) });
    await writeFile(join(dir, 'huge.json'), ' '.repeat(1024 * 1024 + 1));
    expect(await load('huge.json')).toMatchObject({ status: 'refused', reason: expect.stringMatching(/larger than 1 MiB/) });
  });

  test('after a roster change removes a signer, the policy must be signed again', async () => {
    await writePolicy(signedBy(draft(), ana, ben));
    expect(await load('keysentry-policy.json')).toMatchObject({ status: 'ok' });
    const smaller = nextRoster(team.roster, { kind: 'threshold', adminThreshold: 1 }, NOW);
    const v2: SignedTeamRoster = signRoster(signRoster(smaller, 'ana', ana.key), 'ben', ben.key);
    const v3 = signRoster(nextRoster(v2, { kind: 'remove', memberId: 'ben' }, NOW), 'ana', ana.key);
    await applyRoster(store, v2);
    const applied = await applyRoster(store, v3);
    expect(await load('keysentry-policy.json', { roster: applied.roster, hash: applied.hash })).toMatchObject({ status: 'refused', reason: expect.stringMatching(/not an admin/) });
  });
});
