import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createStateCipher, createStateStore, type StateStore } from '../../src/core/store.js';
import {
  checkInvite, completeEnrollment, createInvite, describeRosterChange, enrollmentPath, INVITE_TTL_MS, listCandidates, memberForEmail, memberForSso,
  nextRoster, parseSignedRoster, removeCandidates, signRoster, verifyRoster,
} from '../../src/team/index.js';
import type { PasskeyCredential, SignedTeamRoster } from '../../src/types.js';
import { NOW, rosterOf, testMember } from './helpers.js';

let dir: string;
let store: StateStore;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'keysentry-team-sso-'));
  store = createStateStore({ cwd: dir, cipher: createStateCipher(Buffer.alloc(32, 7)) });
});
afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

const ISSUER = 'https://idp.example.test';
const ana = testMember('ana', 'admin', { email: 'ana@example.test' });
const ben = testMember('ben', 'operator', { email: 'ben@example.test' });

function signed(members = [ana, ben]): SignedTeamRoster {
  return signRoster({ roster: rosterOf(members), signatures: [] }, 'ana', ana.key);
}

describe('pinned single sign-on identity in the signed roster', () => {
  test('sso is optional, signed with the rest of the roster, and validated', () => {
    expect(verifyRoster(signed(), null)).toMatchObject({ ok: true });
    const next = nextRoster(signed(), { kind: 'sso', memberId: 'ben', sso: { issuer: ISSUER, subject: 'sub-ben' } }, NOW);
    expect(next.members.find(member => member.id === 'ben')?.sso).toEqual({ issuer: ISSUER, subject: 'sub-ben' });
    expect(describeRosterChange(signed().roster, next)).toEqual([`Pin the single sign-on identity of ben to issuer ${ISSUER}, subject sub-ben.`]);
    const applied = signRoster(next, 'ana', ana.key);
    expect(verifyRoster(applied, signed())).toMatchObject({ ok: true });
    // Changing the pin after signing breaks the signature.
    const tampered = structuredClone(applied);
    tampered.roster.members[1]!.sso!.subject = 'sub-mallory';
    expect(verifyRoster(tampered, signed())).toMatchObject({ ok: false, reason: expect.stringMatching(/changed after signing/) });
    const cleared = nextRoster(applied, { kind: 'sso', memberId: 'ben', sso: null }, NOW);
    expect(cleared.members[1]!.sso).toBeUndefined();
    expect(describeRosterChange(next, cleared)).toEqual(['Remove the pinned single sign-on identity of ben.']);
  });

  test('refuses a non-https issuer, an issuer with a query, a long or blank subject and a shared identity', () => {
    const base = signed();
    const withSso = (sso: unknown, member = 1) => {
      const copy = structuredClone(base) as unknown as { roster: { members: Record<string, unknown>[] } };
      copy.roster.members[member]!.sso = sso;
      return parseSignedRoster(copy);
    };
    expect(withSso({ issuer: ISSUER, subject: 'sub-ben' })).toMatchObject({ ok: true });
    for (const bad of [{ issuer: 'http://idp.example.test', subject: 's' }, { issuer: `${ISSUER}?tenant=1`, subject: 's' }, { issuer: ISSUER, subject: 'x'.repeat(256) },
      { issuer: ISSUER, subject: '' }, { issuer: ISSUER, subject: 'has space' }, { issuer: ISSUER, subject: 's', extra: true }]) {
      expect(withSso(bad)).toMatchObject({ ok: false });
    }
    const shared = structuredClone(base);
    shared.roster.members[0]!.sso = { issuer: ISSUER, subject: 'same' };
    shared.roster.members[1]!.sso = { issuer: ISSUER, subject: 'same' };
    expect(parseSignedRoster(shared)).toEqual({ ok: false, reason: 'Two members share the same single sign-on identity.' });
  });

  test('lookups: a pinned member is found by issuer and subject, never by email', () => {
    const roster = nextRoster(signed(), { kind: 'sso', memberId: 'ben', sso: { issuer: ISSUER, subject: 'sub-ben' } }, NOW);
    expect(memberForSso(roster, ISSUER, 'sub-ben')?.id).toBe('ben');
    expect(memberForSso(roster, ISSUER, 'sub-other')).toBeUndefined();
    expect(memberForSso(roster, 'https://other.example.test', 'sub-ben')).toBeUndefined();
    expect(memberForEmail(roster, 'ben@example.test')).toBeUndefined();
    expect(memberForEmail(roster, 'ANA@example.test')?.id).toBe('ana');
  });

  test('a passkey change adds the public credential once', () => {
    const credential: PasskeyCredential = { ...ana.credential, id: 'bmV3LXRlYW0tcGFzc2tleQ', label: 'Team dashboard passkey' };
    const next = nextRoster(signed(), { kind: 'passkey', memberId: 'ben', passkey: credential }, NOW);
    expect(next.members[1]!.passkeys.map(passkey => passkey.id)).toEqual([ben.credential.id, credential.id]);
    expect(describeRosterChange(signed().roster, next)).toEqual(['Change the device keys or passkeys of ben.']);
    const applied = signRoster(next, 'ana', ana.key);
    expect(() => nextRoster(applied, { kind: 'passkey', memberId: 'ana', passkey: credential }, NOW)).toThrow(/already on the team roster/);
    expect(() => nextRoster(applied, { kind: 'passkey', memberId: 'zed', passkey: credential }, NOW)).toThrow(/no member zed/);
  });
});

describe('passkey enrollment invitations', () => {
  const ORIGIN = 'https://keysentry.example.test';
  const credential: PasskeyCredential = { ...ben.credential, id: 'ZW5yb2xsZWQtY3JlZGVudGlhbA', rpId: 'keysentry.example.test', origins: [ORIGIN] };

  test('a valid invitation is checked, used once, and produces a pending candidate; the token is stored only as a hash', async () => {
    const invite = await createInvite(store, { memberId: 'ben', origin: ORIGIN, now: NOW });
    expect(invite.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(invite.expiresAt).toBe(new Date(NOW.getTime() + INVITE_TTL_MS).toISOString());
    const saved = JSON.stringify(await store.readJson('passkeys', enrollmentPath(store)));
    expect(saved).not.toContain(invite.token);
    expect(await readFile(enrollmentPath(store), 'utf8')).not.toContain(invite.token);
    expect(await checkInvite(store, invite.token, ORIGIN, NOW)).toEqual({ memberId: 'ben', expiresAt: invite.expiresAt });
    const candidate = await completeEnrollment(store, { token: invite.token, origin: ORIGIN, memberId: 'ben', credential, aaguid: '00000000000000000000000000000000', now: NOW });
    expect(candidate).toMatchObject({ memberId: 'ben', aaguid: null, credential: { id: credential.id } });
    expect(await listCandidates(store)).toHaveLength(1);
    // Reuse is refused, both at the check and at the completion.
    await expect(checkInvite(store, invite.token, ORIGIN, NOW)).rejects.toMatchObject({ reason: 'used', message: expect.stringMatching(/already been used/) });
    await expect(completeEnrollment(store, { token: invite.token, origin: ORIGIN, memberId: 'ben', credential: { ...credential, id: 'b3RoZXI' }, aaguid: null, now: NOW }))
      .rejects.toMatchObject({ reason: 'used' });
    expect(await removeCandidates(store, [credential.id])).toBe(1);
    expect(await listCandidates(store)).toEqual([]);
  });

  test('expired, unknown, malformed, other-origin and other-member invitations are refused', async () => {
    const invite = await createInvite(store, { memberId: 'ben', origin: ORIGIN, now: NOW });
    const later = new Date(NOW.getTime() + INVITE_TTL_MS);
    await expect(checkInvite(store, invite.token, ORIGIN, later)).rejects.toMatchObject({ reason: 'expired', message: expect.stringMatching(/expired/) });
    await expect(checkInvite(store, 'A'.repeat(43), ORIGIN, NOW)).rejects.toMatchObject({ reason: 'invalid' });
    await expect(checkInvite(store, 'short', ORIGIN, NOW)).rejects.toMatchObject({ reason: 'invalid' });
    await expect(checkInvite(store, invite.token, 'https://other.example.test', NOW)).rejects.toMatchObject({ reason: 'origin' });
    await expect(completeEnrollment(store, { token: invite.token, origin: ORIGIN, memberId: 'ana', credential, aaguid: null, now: NOW }))
      .rejects.toMatchObject({ reason: 'member', message: 'This enrollment link was made for another team member.' });
    // The refused attempts did not use the invitation up.
    expect(await checkInvite(store, invite.token, ORIGIN, NOW)).toMatchObject({ memberId: 'ben' });
    expect(await listCandidates(store)).toEqual([]);
  });

  test('a duplicate candidate and an invalid credential are refused; a real AAGUID is kept', async () => {
    const first = await createInvite(store, { memberId: 'ben', origin: ORIGIN, now: NOW });
    await completeEnrollment(store, { token: first.token, origin: ORIGIN, memberId: 'ben', credential, aaguid: 'ad'.repeat(16), now: NOW });
    expect((await listCandidates(store))[0]!.aaguid).toBe('ad'.repeat(16));
    const second = await createInvite(store, { memberId: 'ben', origin: ORIGIN, now: NOW });
    await expect(completeEnrollment(store, { token: second.token, origin: ORIGIN, memberId: 'ben', credential, aaguid: null, now: NOW })).rejects.toMatchObject({ reason: 'duplicate' });
    await expect(completeEnrollment(store, { token: second.token, origin: ORIGIN, memberId: 'ben', credential: { ...credential, id: 'not base64url!' }, aaguid: null, now: NOW }))
      .rejects.toMatchObject({ reason: 'invalid' });
  });

  test('a token the output would mask is drawn again', async () => {
    let calls = 0;
    const invite = await createInvite(store, { memberId: 'ben', origin: ORIGIN, now: NOW, printable: () => ++calls > 2 });
    expect(calls).toBe(3);
    expect(await checkInvite(store, invite.token, ORIGIN, NOW)).toMatchObject({ memberId: 'ben' });
  });
});
