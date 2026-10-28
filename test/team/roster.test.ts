import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { copyFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createStateCipher, createStateStore, type StateStore } from '../../src/core/store.js';
import {
  applyRoster, checkProposal, createRoster, describeRosterChange, devicePublicKey, fingerprint, loadTeam, memberForDeviceKey, memberForEmail, memberForPasskey,
  nextRoster, rosterHash, rosterPath, signRoster, TEAM_SIGNATURE_PREFIX, TeamError, teamDeviceKeys, teamPasskeys, vaultTeamAnchor, verifyFirstUse, verifyRoster,
} from '../../src/team/index.js';
import { canonicalJson, verifyDetached } from '../../src/security/index.js';
import type { SignedTeamRoster } from '../../src/types.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { NOW, rosterOf, testMember } from './helpers.js';

let dir: string;
let store: StateStore;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'keysentry-team-'));
  store = createStateStore({ cwd: dir, cipher: createStateCipher(Buffer.alloc(32, 3)) });
});
afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

const ana = testMember('ana', 'admin');
const ben = testMember('ben', 'admin');
const cy = testMember('cy', 'admin');
const dee = testMember('dee', 'operator');

function genesis(threshold = 1, members = [ana, ben, dee]): SignedTeamRoster {
  let signed: SignedTeamRoster = { roster: rosterOf(members, { adminThreshold: threshold }), signatures: [] };
  const admins = members.filter(entry => entry.member.role === 'admin').slice(0, threshold);
  for (const admin of admins) signed = signRoster(signed, admin.member.id, admin.key);
  return signed;
}

describe('roster signatures', () => {
  test('a team of one signs its own first version, over the documented bytes', () => {
    const roster = createRoster({ now: NOW, admin: { id: 'ana', name: 'Ana', deviceKeys: [devicePublicKey(ana.key)] } });
    const signed = signRoster(roster, 'ana', ana.key);
    const result = verifyRoster(signed, null);
    expect(result).toMatchObject({ ok: true, signers: ['ana'] });
    expect(verifyDetached(ana.key.publicKeyDer, Buffer.from(TEAM_SIGNATURE_PREFIX + canonicalJson(roster)), Buffer.from(signed.signatures[0]!.sig, 'base64'))).toBe(true);
    expect(roster.teamId).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });

  test('version 1 needs adminThreshold distinct admins; one admin signing twice counts once', () => {
    const one = genesis(1, [ana, ben, dee]);
    const needsTwo: SignedTeamRoster = { roster: { ...one.roster, adminThreshold: 2 }, signatures: [] };
    const signedOnce = signRoster(needsTwo, 'ana', ana.key);
    expect(verifyRoster(signedOnce, null)).toEqual({ ok: false, reason: 'This change has 1 of the 2 admin signatures it needs.' });
    expect(() => signRoster(signedOnce, 'ana', ana.key)).toThrow(/already signed/);
    expect(verifyRoster(signRoster(signedOnce, 'ben', ben.key), null)).toMatchObject({ ok: true, signers: ['ana', 'ben'] });
  });

  test('an operator, a stranger or a mismatched key cannot sign', () => {
    const roster = rosterOf([ana, dee]);
    expect(verifyRoster(signRoster(roster, 'dee', dee.key), null)).toMatchObject({ ok: false, reason: expect.stringMatching(/not an admin/) });
    expect(verifyRoster(signRoster(roster, 'cy', cy.key), null)).toMatchObject({ ok: false, reason: expect.stringMatching(/not an admin/) });
    expect(verifyRoster(signRoster(roster, 'ana', ben.key), null)).toMatchObject({ ok: false, reason: expect.stringMatching(/device key that is not listed/) });
  });

  test('a document changed after signing is refused', () => {
    const signed = genesis();
    signed.roster.members[2]!.role = 'admin';
    expect(verifyRoster(signed, null)).toMatchObject({ ok: false, reason: expect.stringMatching(/changed after signing/) });
  });

  test('structural refusals: threshold above admins, duplicates, unknown fields, too many members', () => {
    const base = genesis().roster;
    const check = (roster: unknown) => verifyRoster({ roster, signatures: [] }, null);
    expect(check({ ...base, adminThreshold: 3 })).toMatchObject({ reason: 'The admin threshold is higher than the number of admins.' });
    expect(check({ ...base, members: [...base.members, { ...base.members[2]!, deviceKeys: [], passkeys: [] }] })).toMatchObject({ reason: 'Two members share the same id.' });
    expect(check({ ...base, members: [...base.members, { ...base.members[2]!, id: 'eve', passkeys: [] }] })).toMatchObject({ reason: 'A device key is listed more than once.' });
    expect(check({ ...base, members: [...base.members, { ...base.members[2]!, id: 'eve', deviceKeys: [] }] })).toMatchObject({ reason: 'A passkey is listed more than once.' });
    expect(check({ ...base, members: base.members.map(member => ({ ...member, email: 'same@example.com' })) })).toMatchObject({ reason: 'Two members share the same email.' });
    expect(check({ ...base, extra: true })).toMatchObject({ ok: false, reason: expect.stringMatching(/not a valid signed team roster/) });
    expect(check({ ...base, members: [{ ...base.members[0]!, unknown: 1 }] })).toMatchObject({ ok: false });
    expect(verifyRoster({ ...genesis(), extra: [] }, null)).toMatchObject({ ok: false });
    const many = Array.from({ length: 201 }, (_, index) => ({ id: `m${index}`, name: 'M', role: 'viewer', passkeys: [], deviceKeys: [] }));
    expect(check({ ...base, members: [base.members[0]!, ...many] })).toEqual({ ok: false, reason: 'A team can have at most 200 members.' });
    expect(check({ ...base, members: base.members.map(member => ({ ...member, role: 'viewer' })) })).toMatchObject({ reason: 'A team needs at least one admin.' });
    expect(check({ ...base, version: 2 })).toMatchObject({ reason: expect.stringMatching(/no previous hash/) });
    expect(check({ ...base, adminThreshold: 2, members: [{ ...base.members[0]!, deviceKeys: [] }, base.members[1]!, base.members[2]!] }))
      .toMatchObject({ reason: expect.stringMatching(/^Fewer admins have a device key/) });
  });
});

describe('roster chain', () => {
  test('each version extends the previous one, signed by the previous roster\'s admins', () => {
    const v1 = genesis();
    const v2 = signRoster(nextRoster(v1, { kind: 'add', member: { ...cy.member, role: 'operator' } }, NOW), 'ana', ana.key);
    expect(v2.roster).toMatchObject({ version: 2, prev: rosterHash(v1), teamId: v1.roster.teamId });
    expect(verifyRoster(v2, v1)).toMatchObject({ ok: true });
    expect(verifyRoster(v2, null)).toMatchObject({ ok: false, reason: 'Only version 1 of a roster can start a team.' });
  });

  test('rollback, fork, skipped version and another team are refused', () => {
    const v1 = genesis();
    const v2a = signRoster(nextRoster(v1, { kind: 'role', memberId: 'dee', role: 'viewer' }, NOW), 'ana', ana.key);
    const v2b = signRoster(nextRoster(v1, { kind: 'remove', memberId: 'dee' }, NOW), 'ana', ana.key);
    const v3b = signRoster(nextRoster(v2b, { kind: 'role', memberId: 'ben', role: 'operator' }, NOW), 'ana', ana.key);
    expect(verifyRoster(v1, v2a)).toMatchObject({ ok: false, reason: expect.stringMatching(/rollback/) });
    expect(verifyRoster(v2b, v2a)).toMatchObject({ ok: false, reason: expect.stringMatching(/rollback/) });
    expect(verifyRoster(v3b, v2a)).toMatchObject({ ok: false, reason: expect.stringMatching(/fork/) });
    expect(verifyRoster(v3b, v1)).toMatchObject({ ok: false, reason: expect.stringMatching(/skips a version/) });
    const other: SignedTeamRoster = signRoster({ ...v2a.roster, teamId: 'another-team-1' }, 'ana', ana.key);
    expect(verifyRoster(other, v1)).toMatchObject({ ok: false, reason: 'This roster belongs to a different team.' });
  });

  test('a removed admin cannot sign the next version', () => {
    const v1 = genesis(1, [ana, ben, dee]);
    const v2 = signRoster(nextRoster(v1, { kind: 'remove', memberId: 'ben' }, NOW), 'ben', ben.key);
    expect(verifyRoster(v2, v1)).toMatchObject({ ok: true }); // ben was still an admin of v1
    const v3 = signRoster(nextRoster(v2, { kind: 'role', memberId: 'dee', role: 'admin' }, NOW), 'ben', ben.key);
    expect(verifyRoster(v3, v2)).toMatchObject({ ok: false, reason: expect.stringMatching(/not an admin of the roster that authorizes/) });
  });

  test('a new admin cannot vote for their own addition, and the previous threshold applies', () => {
    const v1 = genesis(2, [ana, ben, dee]);
    const proposal = nextRoster(v1, { kind: 'add', member: cy.member }, NOW);
    const withNewAdmin = signRoster(signRoster(proposal, 'ana', ana.key), 'cy', cy.key);
    expect(verifyRoster(withNewAdmin, v1)).toMatchObject({ ok: false, reason: expect.stringMatching(/not an admin/) });
    expect(verifyRoster(signRoster(proposal, 'ana', ana.key), v1)).toEqual({ ok: false, reason: 'This change has 1 of the 2 admin signatures it needs.' });
    expect(verifyRoster(signRoster(signRoster(proposal, 'ana', ana.key), 'ben', ben.key), v1)).toMatchObject({ ok: true });
    // Lowering the threshold still needs the old threshold's signatures.
    const lower = signRoster(nextRoster(v1, { kind: 'threshold', adminThreshold: 1 }, NOW), 'ana', ana.key);
    expect(verifyRoster(lower, v1)).toMatchObject({ ok: false, reason: 'This change has 1 of the 2 admin signatures it needs.' });
  });

  test('changes that would leave no admin, or fewer admins than the threshold, are refused before signing', () => {
    const v1 = genesis(2, [ana, ben, dee]);
    expect(() => nextRoster(v1, { kind: 'remove', memberId: 'ben' }, NOW)).toThrow('The admin threshold is higher than the number of admins.');
    expect(() => nextRoster(v1, { kind: 'threshold', adminThreshold: 3 }, NOW)).toThrow(TeamError);
    expect(() => nextRoster(genesis(1, [ana, dee]), { kind: 'role', memberId: 'ana', role: 'operator' }, NOW)).toThrow('A team needs at least one admin.');
    expect(() => nextRoster(v1, { kind: 'add', member: { ...dee.member } }, NOW)).toThrow(/already on this team/);
    expect(() => nextRoster(v1, { kind: 'remove', memberId: 'nobody' }, NOW)).toThrow(/no member nobody/);
  });

  test('checkProposal accepts a partly signed proposal but not a bad signature', () => {
    const v1 = genesis(2, [ana, ben, dee]);
    const proposal = signRoster(nextRoster(v1, { kind: 'add', member: { ...cy.member, role: 'viewer' } }, NOW), 'ana', ana.key);
    expect(checkProposal(proposal, v1)).toMatchObject({ ok: true, signers: ['ana'], required: 2 });
    const tampered = structuredClone(proposal); tampered.roster.members.at(-1)!.role = 'admin';
    expect(checkProposal(tampered, v1)).toMatchObject({ ok: false });
    expect(checkProposal(v1, v1)).toMatchObject({ ok: false, reason: expect.stringMatching(/rollback/) });
  });

  test('lookups: passkeys by id and public key, device keys, emails, and role filters', () => {
    const roster = genesis(1, [ana, testMember('vic', 'viewer', { email: 'vic@example.com' }), dee]).roster;
    expect(memberForPasskey(roster, ana.credential)?.id).toBe('ana');
    expect(memberForPasskey(roster, { id: ana.credential.id, publicKeyCose: dee.credential.publicKeyCose })).toBeUndefined();
    expect(memberForDeviceKey(roster, dee.key.keyId)?.member.id).toBe('dee');
    expect(memberForDeviceKey(roster, cy.key.keyId)).toBeUndefined();
    expect(memberForEmail(roster, 'VIC@example.com')?.id).toBe('vic');
    expect(teamPasskeys(roster).map(passkey => passkey.id)).toHaveLength(3);
    expect(teamPasskeys(roster, 'operator').map(passkey => passkey.id)).toEqual([ana.credential.id, dee.credential.id]);
    expect(teamDeviceKeys(roster, 'operator').map(key => key.memberId)).toEqual(['ana', 'dee']);
    expect(teamDeviceKeys(roster, 'admin').map(key => key.keyId)).toEqual([ana.key.keyId]);
  });

  test('describeRosterChange lists the differences', () => {
    const v1 = genesis();
    const v2 = nextRoster(v1, { kind: 'add', member: { ...cy.member, role: 'operator' } }, NOW);
    expect(describeRosterChange(v1.roster, v2)).toEqual(['Add cy (CY) as operator.']);
    expect(describeRosterChange(v1.roster, nextRoster(v1, { kind: 'remove', memberId: 'dee' }, NOW))).toEqual(['Remove dee (operator).']);
  });
});

describe('first use on a new computer', () => {
  test('needs the right fingerprint', () => {
    const v1 = genesis();
    const hash = rosterHash(v1);
    expect(verifyFirstUse(v1, '0000000000000000')).toMatchObject({ ok: false, reason: expect.stringMatching(/fingerprint does not match/) });
    expect(verifyFirstUse(v1, fingerprint(hash))).toMatchObject({ ok: true });
    expect(verifyFirstUse(v1, hash.slice(0, 8))).toMatchObject({ ok: false });
  });

  test('a later version needs a valid signature from an admin still listed in it', () => {
    const v1 = genesis(1, [ana, ben, dee]);
    const byRemoved = signRoster(nextRoster(v1, { kind: 'remove', memberId: 'ben' }, NOW), 'ben', ben.key);
    expect(verifyFirstUse(byRemoved, rosterHash(byRemoved))).toMatchObject({ ok: false, reason: expect.stringMatching(/no signature from an admin listed in it/) });
    const byAna = signRoster(byRemoved, 'ana', ana.key);
    expect(verifyFirstUse(byAna, rosterHash(byAna))).toMatchObject({ ok: true, signers: ['ana'] });
    // A raised threshold was signed under the previous one; the fingerprint is what a new computer trusts.
    const raised = signRoster(nextRoster(v1, { kind: 'threshold', adminThreshold: 2 }, NOW), 'ana', ana.key);
    expect(verifyFirstUse(raised, rosterHash(raised))).toMatchObject({ ok: true });
    const forged = structuredClone(byAna); forged.signatures[1]!.sig = byRemoved.signatures[0]!.sig;
    expect(verifyFirstUse(forged, rosterHash(forged))).toMatchObject({ ok: false, reason: expect.stringMatching(/changed after signing/) });
  });
});

describe('saved roster', () => {
  test('applies a chain and refuses rollback and forks', async () => {
    const v1 = genesis();
    expect(await loadTeam(store)).toBeNull();
    expect(await applyRoster(store, v1)).toMatchObject({ status: 'applied' });
    expect(await applyRoster(store, v1)).toMatchObject({ status: 'unchanged' });
    const v2 = signRoster(nextRoster(v1, { kind: 'role', memberId: 'dee', role: 'viewer' }, NOW), 'ana', ana.key);
    const fork = signRoster(nextRoster(v1, { kind: 'remove', memberId: 'dee' }, NOW), 'ana', ana.key);
    await applyRoster(store, v2);
    await expect(applyRoster(store, v1)).rejects.toThrow(/rollback/);
    await expect(applyRoster(store, fork)).rejects.toThrow(/rollback|fork/);
    expect((await loadTeam(store))!.roster.roster.version).toBe(2);
    expect((await loadTeam(store))!.hash).toBe(rosterHash(v2));
  });

  test('a first roster from elsewhere needs a fingerprint; this computer\'s own version 1 does not', async () => {
    const v1 = genesis();
    const v2 = signRoster(nextRoster(v1, { kind: 'role', memberId: 'dee', role: 'viewer' }, NOW), 'ana', ana.key);
    await expect(applyRoster(store, v2)).rejects.toThrow('Only version 1 of a roster can start a team.');
    await expect(applyRoster(store, v2, { trust: { fingerprint: 'ffffffffffffffff' } })).rejects.toThrow(/fingerprint/);
    expect(await applyRoster(store, v2, { trust: { fingerprint: rosterHash(v2).slice(0, 16) } })).toMatchObject({ status: 'applied' });
  });

  test('restoring an older encrypted roster file is caught by the vault checkpoint', async () => {
    const vault = createFakeVault();
    const anchor = vaultTeamAnchor(vault, 'project-1', 'roster');
    const v1 = genesis();
    await applyRoster(store, v1, { anchor });
    await copyFile(rosterPath(store), join(dir, 'saved-v1'));
    const v2 = signRoster(nextRoster(v1, { kind: 'role', memberId: 'dee', role: 'viewer' }, NOW), 'ana', ana.key);
    await applyRoster(store, v2, { anchor });
    await copyFile(join(dir, 'saved-v1'), rosterPath(store));
    expect((await loadTeam(store))!.roster.roster.version).toBe(1); // without the checkpoint the old file looks valid
    await expect(loadTeam(store, { anchor })).rejects.toThrow(/rollback protection/);
    await rm(rosterPath(store));
    await expect(loadTeam(store, { anchor })).rejects.toThrow(/missing/);
    await expect(applyRoster(store, v1, { anchor, trust: { fingerprint: rosterHash(v1) } })).rejects.toThrow(/older/);
    expect(await applyRoster(store, v2, { anchor, trust: { fingerprint: rosterHash(v2) } })).toMatchObject({ status: 'applied' });
  });

  test('a damaged saved roster fails closed', async () => {
    await applyRoster(store, genesis());
    const raw = await store.readJson<{ v: 1; roster: SignedTeamRoster; hash: string }>('plan', rosterPath(store));
    await store.writeJson('plan', rosterPath(store), { ...raw!, hash: '0'.repeat(64) });
    await expect(loadTeam(store)).rejects.toThrow('The saved team roster could not be verified. Restore it with keysentry team apply.');
  });
});
