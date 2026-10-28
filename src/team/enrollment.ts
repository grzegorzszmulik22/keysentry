// Passkeys for the team dashboard's public host. An admin's terminal creates a single-use invitation (stored only as
// a hash, bound to one member and one origin, 15 minutes). The team dashboard turns a valid invitation into a pending
// candidate: the member's *public* credential, verified by the WebAuthn ceremony. A candidate grants nothing; it is
// usable only after admins sign it into the roster (`keysentry team add-passkey`).
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { join } from 'node:path';
import { z } from 'zod';
import type { StateStore } from '../core/store.js';
import type { PasskeyCredential } from '../types.js';
import { serialized, TeamError } from './roster.js';
import { isoDate, memberIdPattern, passkeySchema, sha256Hex } from './schema.js';

/** How long an invitation link works. */
export const INVITE_TTL_MS = 15 * 60_000;
const MAX_INVITES = 200;
const MAX_CANDIDATES = 200;
/** Used and expired invitations are kept this long so a reused link gets a specific answer, then dropped. */
const KEEP_USED_MS = 24 * 60 * 60_000;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;

export interface EnrollmentCandidate {
  memberId: string;
  /** The public credential only: id, COSE public key, algorithm, RP ID and origin. */
  credential: PasskeyCredential;
  createdAt: string;
  /** Authenticator model id (hex) when the authenticator reported a non-zero one. */
  aaguid: string | null;
}

interface StoredInvite { tokenHash: string; memberId: string; origin: string; createdAt: string; expiresAt: string; usedAt?: string }
interface EnrollmentState { v: 1; invites: StoredInvite[]; candidates: EnrollmentCandidate[] }

const stateSchema = z.object({
  v: z.literal(1),
  invites: z.array(z.object({
    tokenHash: sha256Hex, memberId: z.string().regex(memberIdPattern), origin: z.string().max(512), createdAt: isoDate, expiresAt: isoDate, usedAt: isoDate.optional(),
  }).strict()).max(MAX_INVITES),
  candidates: z.array(z.object({
    memberId: z.string().regex(memberIdPattern), credential: passkeySchema, createdAt: isoDate, aaguid: z.string().regex(/^[a-f0-9]{32}$/).nullable(),
  }).strict()).max(MAX_CANDIDATES),
}).strict();

/** Fixed, value-free refusals. The token itself never appears in a message, log or audit event. */
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

function hashToken(token: string): string {
  return createHash('sha256').update(`keysentry-enrollment:v1\n${token}`, 'utf8').digest('hex');
}
function sameHash(a: string, b: string): boolean {
  return a.length === b.length && timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

async function load(store: StateStore): Promise<EnrollmentState> {
  const raw = await store.readJson('passkeys', enrollmentPath(store));
  if (raw === null) return { v: 1, invites: [], candidates: [] };
  const parsed = stateSchema.safeParse(raw);
  if (!parsed.success) throw new EnrollmentError('The saved passkey enrollments could not be read.', 'state');
  return parsed.data as EnrollmentState;
}

function prune(state: EnrollmentState, now: Date): void {
  const cutoff = now.getTime() - KEEP_USED_MS;
  state.invites = state.invites.filter(invite => Date.parse(invite.usedAt ?? invite.expiresAt) > cutoff);
}

/** Create a single-use invitation. Returns the token, which only the caller sees; the state keeps its hash. */
export function createInvite(store: StateStore, input: { memberId: string; origin: string; now: Date; ttlMs?: number; printable?: (token: string) => boolean }):
  Promise<{ token: string; expiresAt: string }> {
  if (!memberIdPattern.test(input.memberId)) throw new EnrollmentError('Choose a member on the team roster.', 'member');
  const ttl = input.ttlMs ?? INVITE_TTL_MS;
  return serialized(enrollmentPath(store), async () => {
    const state = await load(store);
    prune(state, input.now);
    if (state.invites.length >= MAX_INVITES) throw new EnrollmentError('There are too many open enrollment links. Wait for some to expire, then try again.', 'full');
    // A random token could, rarely, look like a key to the output redactor; draw again so the printed link is whole.
    let token = randomBytes(32).toString('base64url');
    for (let attempt = 0; attempt < 20 && input.printable && !input.printable(token); attempt++) token = randomBytes(32).toString('base64url');
    const expiresAt = new Date(input.now.getTime() + ttl).toISOString();
    state.invites.push({ tokenHash: hashToken(token), memberId: input.memberId, origin: input.origin, createdAt: input.now.toISOString(), expiresAt });
    await store.writeJson('passkeys', enrollmentPath(store), state);
    return { token, expiresAt };
  });
}

function find(state: EnrollmentState, token: unknown, origin: string, now: Date): StoredInvite {
  if (typeof token !== 'string' || !TOKEN.test(token)) throw new EnrollmentError(INVALID, 'invalid');
  const digest = hashToken(token);
  const invite = state.invites.find(candidate => sameHash(candidate.tokenHash, digest));
  if (!invite) throw new EnrollmentError(INVALID, 'invalid');
  if (invite.usedAt) throw new EnrollmentError(USED, 'used');
  if (Date.parse(invite.expiresAt) <= now.getTime()) throw new EnrollmentError(EXPIRED, 'expired');
  if (invite.origin !== origin) throw new EnrollmentError('This enrollment link was made for another dashboard address. Ask a team admin for a link to this one.', 'origin');
  return invite;
}

/** Check an invitation without using it up (the page asks before the browser prompt). */
export function checkInvite(store: StateStore, token: unknown, origin: string, now: Date): Promise<{ memberId: string; expiresAt: string }> {
  return serialized(enrollmentPath(store), async () => {
    const invite = find(await load(store), token, origin, now);
    return { memberId: invite.memberId, expiresAt: invite.expiresAt };
  });
}

/**
 * Use the invitation (single use) and keep the verified public credential as a pending candidate for the invited
 * member. `memberId` is what the ceremony was started for; a credential for anyone else is refused.
 */
export function completeEnrollment(store: StateStore, input: { token: unknown; origin: string; memberId: string; credential: PasskeyCredential; aaguid: string | null; now: Date }):
  Promise<EnrollmentCandidate> {
  return serialized(enrollmentPath(store), async () => {
    const state = await load(store);
    const invite = find(state, input.token, input.origin, input.now);
    if (invite.memberId !== input.memberId) throw new EnrollmentError('This enrollment link was made for another team member.', 'member');
    if (!passkeySchema.safeParse(input.credential).success) throw new EnrollmentError('The passkey could not be verified. Try again with a new link.', 'invalid');
    if (state.candidates.some(candidate => candidate.credential.id === input.credential.id)) throw new EnrollmentError('This passkey is already waiting for an admin.', 'duplicate');
    if (state.candidates.length >= MAX_CANDIDATES) throw new EnrollmentError('There are too many passkeys waiting for an admin. Ask an admin to review them first.', 'full');
    invite.usedAt = input.now.toISOString();
    const candidate: EnrollmentCandidate = { memberId: invite.memberId, credential: structuredClone(input.credential), createdAt: input.now.toISOString(),
      aaguid: input.aaguid && /^[a-f0-9]{32}$/.test(input.aaguid) && !/^0+$/.test(input.aaguid) ? input.aaguid : null };
    state.candidates.push(candidate);
    prune(state, input.now);
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
