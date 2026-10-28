// Passkeys for the team dashboard's public host. An admin's own computer signs an invitation with the admin's device
// key: `{ member, origin, exp, nonce }` travels in the link's fragment, never in a request log, and the team server
// verifies it against the current roster's admins. The server needs no admin key: it checks the signature, the expiry
// and its own origin, and keeps only the hash of each used nonce (single use). A valid invitation turns into a pending
// candidate: the member's *public* credential, verified by the WebAuthn ceremony. A candidate grants nothing; it is
// exported as a candidate card and becomes usable only after admins sign it into the roster on their own computers
// (`keysentry team add-passkey <member> --card <file>`), which the server then applies like any computer.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { join } from 'node:path';
import { z } from 'zod';
import type { StateStore } from '../core/store.js';
import { canonicalJson, signDetached, verifyDetached, type DeviceKey } from '../security/index.js';
import type { PasskeyCredential, TeamRoster } from '../types.js';
import { serialized, TeamError } from './roster.js';
import { isoDate, keyIdFor, memberIdPattern, passkeySchema, sha256Hex } from './schema.js';

/** How long an invitation link works. */
export const INVITE_TTL_MS = 15 * 60_000;
/** The signing computer's clock may run ahead of the server's by this much. */
const CLOCK_SKEW_MS = 5 * 60_000;
const MAX_USED = 500;
const MAX_CANDIDATES = 200;
/** Used invitations are remembered until they expire, plus this long so a reused link gets a specific answer. */
const KEEP_USED_MS = 24 * 60 * 60_000;
const INVITE_PREFIX = 'keysentry-enroll-invite:v1\n';
const TOKEN = /^([A-Za-z0-9_-]{16,2048})\.([A-Za-z0-9_-]{86})$/;

export interface EnrollmentCandidate {
  memberId: string;
  /** The public credential only: id, COSE public key, algorithm, RP ID and origin. */
  credential: PasskeyCredential;
  createdAt: string;
  /**
   * Authenticator model id (hex) when a non-zero one was reported. With `none` attestation the authenticator reports
   * it and nothing verifies it, so it is a hint, not an identity.
   */
  aaguid: string | null;
}

interface UsedInvite { nonceHash: string; memberId: string; expiresAt: string; usedAt: string }
interface EnrollmentState { v: 2; used: UsedInvite[]; candidates: EnrollmentCandidate[] }

const candidateSchema = z.object({
  memberId: z.string().regex(memberIdPattern), credential: passkeySchema, createdAt: isoDate, aaguid: z.string().regex(/^[a-f0-9]{32}$/).nullable(),
}).strict();
const stateSchema = z.object({
  v: z.literal(2),
  used: z.array(z.object({ nonceHash: sha256Hex, memberId: z.string().regex(memberIdPattern), expiresAt: isoDate, usedAt: isoDate }).strict()).max(MAX_USED),
  candidates: z.array(candidateSchema).max(MAX_CANDIDATES),
}).strict();
/** Before signed invitations, invitations were stored here; they are no longer valid, but waiting candidates are kept. */
const legacySchema = z.object({ v: z.literal(1), invites: z.array(z.unknown()), candidates: z.array(candidateSchema).max(MAX_CANDIDATES) }).strict();

const payloadSchema = z.object({
  v: z.literal(1),
  member: z.string().regex(memberIdPattern),
  origin: z.string().min(1).max(512),
  exp: isoDate,
  nonce: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  keyId: z.string().regex(/^[a-f0-9]{16}$/),
}).strict();
type InvitePayload = z.infer<typeof payloadSchema>;

/** Fixed, value-free refusals. The link itself never appears in a message, log or audit event. */
export class EnrollmentError extends TeamError {
  constructor(message: string, readonly reason: 'invalid' | 'expired' | 'used' | 'origin' | 'member' | 'full' | 'duplicate' | 'state') {
    super(message);
    this.name = 'EnrollmentError';
  }
}

const INVALID = 'This enrollment link is not valid. Ask a team admin for a new one (keysentry team invite).';
const EXPIRED = 'This enrollment link has expired. Ask a team admin for a new one (keysentry team invite).';
const USED = 'This enrollment link has already been used. Ask a team admin for a new one if you need another passkey.';

export function enrollmentPath(store: Pick<StateStore, 'paths'>): string { return join(store.paths.dir, 'team-enrollment.json'); }

function hashNonce(nonce: string): string {
  return createHash('sha256').update(`keysentry-enrollment:v1\n${nonce}`, 'utf8').digest('hex');
}
function sameHash(a: string, b: string): boolean {
  return a.length === b.length && timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}
function base64url(value: string): Buffer | null {
  const bytes = Buffer.from(value, 'base64url');
  return bytes.toString('base64url') === value ? bytes : null;
}

async function load(store: StateStore): Promise<EnrollmentState> {
  const raw = await store.readJson('passkeys', enrollmentPath(store));
  if (raw === null) return { v: 2, used: [], candidates: [] };
  const parsed = stateSchema.safeParse(raw);
  if (parsed.success) return parsed.data as EnrollmentState;
  const legacy = legacySchema.safeParse(raw);
  if (legacy.success) return { v: 2, used: [], candidates: legacy.data.candidates as EnrollmentCandidate[] };
  throw new EnrollmentError('The saved passkey enrollments could not be read.', 'state');
}

function prune(state: EnrollmentState, now: Date): void {
  state.used = state.used.filter(entry => Date.parse(entry.expiresAt) + KEEP_USED_MS > now.getTime());
}

/**
 * Sign an invitation on an admin's own computer. Returns the token for the link's fragment (`<origin>/enroll#<token>`).
 * Nothing is stored: the team server checks the signature against the roster and remembers the nonce once used.
 */
export function signInvite(input: { memberId: string; origin: string; now: Date; signer: Pick<DeviceKey, 'keyId' | 'publicKeyDer' | 'privateKeyDer'>; ttlMs?: number;
  printable?: (token: string) => boolean }): { token: string; expiresAt: string } {
  if (!memberIdPattern.test(input.memberId)) throw new EnrollmentError('Choose a member on the team roster.', 'member');
  if (keyIdFor(input.signer.publicKeyDer) !== input.signer.keyId) throw new TypeError('Device key ID does not match its public key.');
  const ttl = Math.min(input.ttlMs ?? INVITE_TTL_MS, INVITE_TTL_MS);
  const expiresAt = new Date(input.now.getTime() + ttl).toISOString();
  const make = () => {
    const payload: InvitePayload = { v: 1, member: input.memberId, origin: input.origin, exp: expiresAt, nonce: randomBytes(32).toString('base64url'), keyId: input.signer.keyId };
    const body = canonicalJson(payload);
    const sig = signDetached(input.signer.privateKeyDer, Buffer.from(INVITE_PREFIX + body, 'utf8'));
    return `${Buffer.from(body, 'utf8').toString('base64url')}.${sig.toString('base64url')}`;
  };
  // A random nonce could, rarely, make the link look like a key to the output redactor; sign again so it prints whole.
  let token = make();
  for (let attempt = 0; attempt < 20 && input.printable && !input.printable(token); attempt++) token = make();
  return { token, expiresAt };
}

interface CheckedInvite { memberId: string; expiresAt: string; nonceHash: string; signerId: string }

/** Verify an invitation's signature (a current admin's device key), its origin, its expiry and its member. */
export function verifyInvite(token: unknown, context: { roster: Pick<TeamRoster, 'members'>; origin: string; now: Date }): CheckedInvite {
  if (typeof token !== 'string') throw new EnrollmentError(INVALID, 'invalid');
  const match = TOKEN.exec(token);
  if (!match) throw new EnrollmentError(INVALID, 'invalid');
  const body = base64url(match[1]!);
  const sig = base64url(match[2]!);
  if (!body || !sig || sig.length !== 64) throw new EnrollmentError(INVALID, 'invalid');
  let payload: InvitePayload;
  try {
    const parsed = payloadSchema.safeParse(JSON.parse(body.toString('utf8')));
    if (!parsed.success || canonicalJson(parsed.data) !== body.toString('utf8')) throw new Error();
    payload = parsed.data;
  } catch { throw new EnrollmentError(INVALID, 'invalid'); }
  const signer = context.roster.members.find(member => member.role === 'admin' && member.deviceKeys.some(key => key.keyId === payload.keyId));
  const key = signer?.deviceKeys.find(entry => entry.keyId === payload.keyId);
  if (!signer || !key || !verifyDetached(Buffer.from(key.publicKeyDer, 'base64'), Buffer.from(INVITE_PREFIX + body.toString('utf8'), 'utf8'), sig)) {
    throw new EnrollmentError('This enrollment link was not signed by a current team admin. Ask a team admin for a new one (keysentry team invite).', 'invalid');
  }
  const expires = Date.parse(payload.exp);
  if (expires <= context.now.getTime()) throw new EnrollmentError(EXPIRED, 'expired');
  if (expires > context.now.getTime() + INVITE_TTL_MS + CLOCK_SKEW_MS) throw new EnrollmentError(INVALID, 'invalid');
  if (payload.origin !== context.origin) throw new EnrollmentError('This enrollment link was made for another dashboard address. Ask a team admin for a link to this one.', 'origin');
  if (!context.roster.members.some(member => member.id === payload.member)) {
    throw new EnrollmentError('This enrollment link is for someone who is no longer on the team roster.', 'member');
  }
  return { memberId: payload.member, expiresAt: payload.exp, nonceHash: hashNonce(payload.nonce), signerId: signer.id };
}

function unused(state: EnrollmentState, invite: CheckedInvite): void {
  if (state.used.some(entry => sameHash(entry.nonceHash, invite.nonceHash))) throw new EnrollmentError(USED, 'used');
}

/** Check an invitation without using it up (the page asks before the browser prompt). */
export function checkInvite(store: StateStore, token: unknown, context: { roster: Pick<TeamRoster, 'members'>; origin: string; now: Date }): Promise<{ memberId: string; expiresAt: string }> {
  return serialized(enrollmentPath(store), async () => {
    const invite = verifyInvite(token, context);
    unused(await load(store), invite);
    return { memberId: invite.memberId, expiresAt: invite.expiresAt };
  });
}

/**
 * Use the invitation (single use: its nonce hash is remembered) and keep the verified public credential as a pending
 * candidate for the invited member. `memberId` is what the ceremony was started for; a credential for anyone else is refused.
 */
export function completeEnrollment(store: StateStore, input: { token: unknown; roster: Pick<TeamRoster, 'members'>; origin: string; memberId: string; credential: PasskeyCredential;
  aaguid: string | null; now: Date }): Promise<EnrollmentCandidate> {
  return serialized(enrollmentPath(store), async () => {
    const state = await load(store);
    prune(state, input.now);
    const invite = verifyInvite(input.token, { roster: input.roster, origin: input.origin, now: input.now });
    unused(state, invite);
    if (invite.memberId !== input.memberId) throw new EnrollmentError('This enrollment link was made for another team member.', 'member');
    if (!passkeySchema.safeParse(input.credential).success) throw new EnrollmentError('The passkey could not be verified. Try again with a new link.', 'invalid');
    if (state.candidates.some(candidate => candidate.credential.id === input.credential.id || candidate.credential.publicKeyCose === input.credential.publicKeyCose)) {
      throw new EnrollmentError('This passkey is already waiting for an admin.', 'duplicate');
    }
    if (state.candidates.length >= MAX_CANDIDATES) throw new EnrollmentError('There are too many passkeys waiting for an admin. Ask an admin to review them first.', 'full');
    if (state.used.length >= MAX_USED) throw new EnrollmentError('Too many enrollment links were used recently. Try again tomorrow.', 'full');
    state.used.push({ nonceHash: invite.nonceHash, memberId: invite.memberId, expiresAt: invite.expiresAt, usedAt: input.now.toISOString() });
    const candidate: EnrollmentCandidate = { memberId: invite.memberId, credential: structuredClone(input.credential), createdAt: input.now.toISOString(),
      aaguid: input.aaguid && /^[a-f0-9]{32}$/.test(input.aaguid) && !/^0+$/.test(input.aaguid) ? input.aaguid : null };
    state.candidates.push(candidate);
    await store.writeJson('passkeys', enrollmentPath(store), state);
    return structuredClone(candidate);
  });
}

/** Pending candidates (public data only), oldest first. */
export function listCandidates(store: StateStore): Promise<EnrollmentCandidate[]> {
  return serialized(enrollmentPath(store), async () => structuredClone((await load(store)).candidates));
}

/** Drop candidates whose credential is already on the roster (or was rejected); returns how many were removed. */
export function removeCandidates(store: StateStore, credentialIds: readonly string[]): Promise<number> {
  const ids = new Set(credentialIds);
  return serialized(enrollmentPath(store), async () => {
    const state = await load(store);
    const before = state.candidates.length;
    state.candidates = state.candidates.filter(candidate => !ids.has(candidate.credential.id));
    if (state.candidates.length !== before) await store.writeJson('passkeys', enrollmentPath(store), state);
    return before - state.candidates.length;
  });
}

// ---------------------------------------------------------------------------------------------- candidate cards
/** Public data only: what `team passkeys pending -o` writes on the server and `team add-passkey --card` reads on an admin's computer. */
export interface CandidateCard { v: 1; kind: 'keysentry-passkey-candidates'; candidates: EnrollmentCandidate[] }

const cardSchema = z.object({ v: z.literal(1), kind: z.literal('keysentry-passkey-candidates'), candidates: z.array(candidateSchema).min(1).max(MAX_CANDIDATES) }).strict();

export function candidateCard(candidates: readonly EnrollmentCandidate[]): CandidateCard {
  return { v: 1, kind: 'keysentry-passkey-candidates', candidates: structuredClone([...candidates]) };
}

/** Parse a candidate card (untrusted file contents) into its candidates, or refuse with a fixed message. */
export function parseCandidateCard(input: unknown): EnrollmentCandidate[] {
  const parsed = cardSchema.safeParse(input);
  if (!parsed.success) throw new TeamError('The passkey card is not valid. Export it again with keysentry team passkeys pending -o <file> on the team dashboard host.');
  const ids = parsed.data.candidates.map(candidate => candidate.credential.id);
  if (new Set(ids).size !== ids.length) throw new TeamError('The passkey card lists the same passkey twice.');
  return parsed.data.candidates as EnrollmentCandidate[];
}

/** A short, comparable fingerprint of a candidate's public key (shown on both computers before it is added). */
export function candidateFingerprint(candidate: Pick<EnrollmentCandidate, 'credential'>): string {
  return createHash('sha256').update(candidate.credential.publicKeyCose, 'utf8').digest('hex').slice(0, 32).match(/.{4}/g)!.join('-');
}
