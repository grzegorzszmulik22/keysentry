import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createStateCipher, createStateStore, type StateStore } from '../../src/core/store.js';
import {
  candidateCard, candidateFingerprint, checkInvite, completeEnrollment, describeRosterChange, enrollmentPath, INVITE_TTL_MS, listCandidates, memberForEmail,
  memberForSso, nextRoster, parseCandidateCard, parseSignedRoster, removeCandidates, signInvite, signRoster, verifyRoster,
} from '../../src/team/index.js';
import { generateDeviceKey } from '../../src/security/index.js';
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

describe('passkey enrollment invitations, signed on an admin\'s computer (review H3)', () => {
  const ORIGIN = 'https://keysentry.example.test';
  const credential: PasskeyCredential = { ...ben.credential, id: 'ZW5yb2xsZWQtY3JlZGVudGlhbA', rpId: 'keysentry.example.test', origins: [ORIGIN] };
  const roster = (members = [ana, ben]) => signed(members).roster;
  const context = (now = NOW, members = [ana, ben]) => ({ roster: roster(members), origin: ORIGIN, now });
  const payload = (token: string) => JSON.parse(Buffer.from(token.split('.')[0]!, 'base64url').toString('utf8')) as Record<string, unknown>;

  test('an admin-signed invitation is checked against the roster, used once, and produces a pending candidate; the server keeps only a nonce hash', async () => {
    const invite = signInvite({ memberId: 'ben', origin: ORIGIN, now: NOW, signer: ana.key });
    expect(invite.token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{86}$/);
    expect(invite.expiresAt).toBe(new Date(NOW.getTime() + INVITE_TTL_MS).toISOString());
    expect(payload(invite.token)).toEqual({ v: 1, member: 'ben', origin: ORIGIN, exp: invite.expiresAt, nonce: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/), keyId: ana.key.keyId });
    // Nothing is stored where the invitation is signed or checked.
    expect(await checkInvite(store, invite.token, context())).toEqual({ memberId: 'ben', expiresAt: invite.expiresAt });
    expect(await store.readJson('passkeys', enrollmentPath(store))).toBeNull();
    const candidate = await completeEnrollment(store, { token: invite.token, roster: roster(), origin: ORIGIN, memberId: 'ben', credential,
      aaguid: '00000000000000000000000000000000', now: NOW });
    expect(candidate).toMatchObject({ memberId: 'ben', aaguid: null, credential: { id: credential.id } });
    expect(await listCandidates(store)).toHaveLength(1);
    const saved = await readFile(enrollmentPath(store), 'utf8');
    expect(saved).not.toContain(invite.token);
    expect(JSON.stringify(await store.readJson('passkeys', enrollmentPath(store)))).not.toContain(payload(invite.token).nonce as string);
    // Reuse is refused, both at the check and at the completion.
    await expect(checkInvite(store, invite.token, context())).rejects.toMatchObject({ reason: 'used', message: expect.stringMatching(/already been used/) });
    await expect(completeEnrollment(store, { token: invite.token, roster: roster(), origin: ORIGIN, memberId: 'ben', credential: { ...credential, id: 'b3RoZXI' },
      aaguid: null, now: NOW })).rejects.toMatchObject({ reason: 'used' });
    expect(await removeCandidates(store, [credential.id])).toBe(1);
    expect(await listCandidates(store)).toEqual([]);
  });

  test('refuses links not signed by a current admin, altered, re-encoded, expired, too far ahead, for another origin or member, or for someone who left', async () => {
    const invite = signInvite({ memberId: 'ben', origin: ORIGIN, now: NOW, signer: ana.key });
    const notAdmin = /not signed by a current team admin/;
    await expect(checkInvite(store, signInvite({ memberId: 'ben', origin: ORIGIN, now: NOW, signer: ben.key }).token, context()))
      .rejects.toMatchObject({ reason: 'invalid', message: expect.stringMatching(notAdmin) });
    await expect(checkInvite(store, signInvite({ memberId: 'ben', origin: ORIGIN, now: NOW, signer: generateDeviceKey() }).token, context()))
      .rejects.toMatchObject({ reason: 'invalid', message: expect.stringMatching(notAdmin) });
    // Ana demoted to operator: her old links stop working.
    const demoted = structuredClone(signed()); demoted.roster.members[0]!.role = 'operator'; demoted.roster.members[1]!.role = 'admin';
    await expect(checkInvite(store, invite.token, { roster: demoted.roster, origin: ORIGIN, now: NOW })).rejects.toMatchObject({ reason: 'invalid' });
    const [body, sig] = invite.token.split('.') as [string, string];
    const altered = Buffer.from(JSON.stringify({ ...payload(invite.token), member: 'ana' })).toString('base64url');
    await expect(checkInvite(store, `${altered}.${sig}`, context())).rejects.toMatchObject({ reason: 'invalid' });
    const respaced = Buffer.from(JSON.stringify(payload(invite.token), null, 1)).toString('base64url');
    await expect(checkInvite(store, `${respaced}.${sig}`, context())).rejects.toMatchObject({ reason: 'invalid' });
    for (const bad of ['A'.repeat(43), 'short', `${body}.${'A'.repeat(86)}`, `${body}.${sig}=`, `${body}..${sig}`]) {
      await expect(checkInvite(store, bad, context())).rejects.toMatchObject({ reason: 'invalid' });
    }
    await expect(checkInvite(store, invite.token, context(new Date(NOW.getTime() + INVITE_TTL_MS)))).rejects.toMatchObject({ reason: 'expired', message: expect.stringMatching(/expired/) });
    const ahead = signInvite({ memberId: 'ben', origin: ORIGIN, now: new Date(NOW.getTime() + 60 * 60_000), signer: ana.key });
    await expect(checkInvite(store, ahead.token, context())).rejects.toMatchObject({ reason: 'invalid' });
    await expect(checkInvite(store, invite.token, { ...context(), origin: 'https://other.example.test' })).rejects.toMatchObject({ reason: 'origin' });
    await expect(checkInvite(store, invite.token, context(NOW, [ana]))).rejects.toMatchObject({ reason: 'member' });
    await expect(completeEnrollment(store, { token: invite.token, roster: roster(), origin: ORIGIN, memberId: 'ana', credential, aaguid: null, now: NOW }))
      .rejects.toMatchObject({ reason: 'member', message: 'This enrollment link was made for another team member.' });
    // The refused attempts did not use the invitation up.
    expect(await checkInvite(store, invite.token, context())).toMatchObject({ memberId: 'ben' });
    expect(await listCandidates(store)).toEqual([]);
  });

  test('a duplicate candidate (same id or same public key) and an invalid credential are refused; a reported AAGUID is kept as a hint', async () => {
    const first = signInvite({ memberId: 'ben', origin: ORIGIN, now: NOW, signer: ana.key });
    await completeEnrollment(store, { token: first.token, roster: roster(), origin: ORIGIN, memberId: 'ben', credential, aaguid: 'ad'.repeat(16), now: NOW });
    expect((await listCandidates(store))[0]!.aaguid).toBe('ad'.repeat(16));
    const second = signInvite({ memberId: 'ben', origin: ORIGIN, now: NOW, signer: ana.key });
    const again = (input: PasskeyCredential) => completeEnrollment(store, { token: second.token, roster: roster(), origin: ORIGIN, memberId: 'ben', credential: input, aaguid: null, now: NOW });
    await expect(again(credential)).rejects.toMatchObject({ reason: 'duplicate' });
    await expect(again({ ...credential, id: 'c2FtZS1rZXk' })).rejects.toMatchObject({ reason: 'duplicate' });
    await expect(again({ ...credential, id: 'not base64url!' })).rejects.toMatchObject({ reason: 'invalid' });
  });

  test('a link the output would mask is signed again', async () => {
    let calls = 0;
    const invite = signInvite({ memberId: 'ben', origin: ORIGIN, now: NOW, signer: ana.key, printable: () => ++calls > 2 });
    expect(calls).toBe(3);
    expect(await checkInvite(store, invite.token, context())).toMatchObject({ memberId: 'ben' });
  });

  test('candidate cards carry public data only, parse strictly, and show a comparable fingerprint', async () => {
    const invite = signInvite({ memberId: 'ben', origin: ORIGIN, now: NOW, signer: ana.key });
    await completeEnrollment(store, { token: invite.token, roster: roster(), origin: ORIGIN, memberId: 'ben', credential, aaguid: null, now: NOW });
    const card = candidateCard(await listCandidates(store));
    expect(card).toMatchObject({ v: 1, kind: 'keysentry-passkey-candidates', candidates: [{ memberId: 'ben', credential: { id: credential.id, origins: [ORIGIN] } }] });
    expect(parseCandidateCard(JSON.parse(JSON.stringify(card)))).toEqual(card.candidates);
    expect(candidateFingerprint(card.candidates[0]!)).toMatch(/^(?:[a-f0-9]{4}-){7}[a-f0-9]{4}$/);
    expect(() => parseCandidateCard({ ...card, extra: true })).toThrow(/passkey card is not valid/);
    expect(() => parseCandidateCard({ ...card, candidates: [] })).toThrow(/passkey card is not valid/);
    expect(() => parseCandidateCard({ ...card, candidates: [card.candidates[0], card.candidates[0]] })).toThrow(/same passkey twice/);
  });

  test('a saved state from before signed invitations keeps its candidates and drops its stored invitations', async () => {
    const candidate = { memberId: 'ben', credential, createdAt: NOW.toISOString(), aaguid: null };
    await store.writeJson('passkeys', enrollmentPath(store), { v: 1, invites: [{ tokenHash: 'a'.repeat(64) }], candidates: [candidate] });
    expect(await listCandidates(store)).toEqual([candidate]);
  });
});
