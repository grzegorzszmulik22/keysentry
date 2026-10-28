// Strict shapes for the signed team roster. Every check here is structural; signatures live in signature.ts.
import { createHash, createPublicKey } from 'node:crypto';
import { z } from 'zod';
import type { SignedTeamRoster, TeamMember, TeamRole } from '../types.js';

export const MAX_MEMBERS = 200;
export const MAX_PASSKEYS_PER_MEMBER = 10;
export const MAX_DEVICE_KEYS_PER_MEMBER = 10;
export const MAX_SIGNATURES = 400;
/** Roster and policy files are small; anything larger is refused before parsing. */
export const MAX_TEAM_FILE_BYTES = 1024 * 1024;

export const ROLE_RANK: Readonly<Record<TeamRole, number>> = { viewer: 0, operator: 1, admin: 2 };
export const memberIdPattern = /^[a-z][a-z0-9_-]{0,31}$/;
export const teamIdPattern = /^[A-Za-z0-9_-]{8,64}$/;
export const channelIdPattern = /^[A-Za-z0-9_-]{1,64}$/;

const printable = (max: number) => z.string().min(1).max(max).refine(value => !/[\u0000-\u001f\u007f-\u009f]/.test(value) && value.trim() === value);
const base64url = z.string().min(1).max(65536).regex(/^[A-Za-z0-9_-]+$/)
  .refine(value => Buffer.from(value, 'base64url').toString('base64url') === value);
export const isoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/).refine(value => Number.isFinite(Date.parse(value)));
export const sha256Hex = z.string().regex(/^[a-f0-9]{64}$/);
export const emailSchema = z.string().max(254)
  .regex(/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/);

function webOrigin(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.origin !== value || url.username || url.password) return false;
    return url.protocol === 'https:' || (url.protocol === 'http:' && url.hostname === 'localhost');
  } catch { return false; }
}

export function keyIdFor(publicKeyDer: Buffer): string {
  return createHash('sha256').update(publicKeyDer).digest('hex').slice(0, 16);
}

export const deviceKeySchema = z.object({ keyId: z.string().regex(/^[a-f0-9]{16}$/), publicKeyDer: z.string().min(1).max(4096) }).strict()
  .refine(entry => {
    try {
      const der = Buffer.from(entry.publicKeyDer, 'base64');
      return der.toString('base64') === entry.publicKeyDer
        && createPublicKey({ key: der, format: 'der', type: 'spki' }).asymmetricKeyType === 'ed25519'
        && keyIdFor(der) === entry.keyId;
    } catch { return false; }
  });

export const passkeySchema = z.object({
  id: base64url, publicKeyCose: base64url, alg: z.union([z.literal(-7), z.literal(-8), z.literal(-257)]),
  signCount: z.number().int().min(0).max(0xffffffff), backupEligible: z.boolean(),
  rpId: printable(253), origins: z.array(z.string().max(2048).refine(webOrigin)).min(1).max(20), label: printable(80),
  createdAt: z.string().max(64).refine(value => Number.isFinite(Date.parse(value))),
}).strict();

export const memberSchema = z.object({
  id: z.string().regex(memberIdPattern),
  name: printable(80),
  role: z.enum(['viewer', 'operator', 'admin']),
  email: emailSchema.optional(),
  passkeys: z.array(passkeySchema).max(MAX_PASSKEYS_PER_MEMBER),
  deviceKeys: z.array(deviceKeySchema).max(MAX_DEVICE_KEYS_PER_MEMBER),
  notify: z.object({
    channels: z.array(z.string().regex(channelIdPattern)).max(50).refine(values => new Set(values).size === values.length),
    minSeverity: z.enum(['info', 'warning', 'urgent']),
  }).strict().optional(),
}).strict();

export const rosterSchema = z.object({
  v: z.literal(1),
  teamId: z.string().regex(teamIdPattern),
  version: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  prev: sha256Hex.nullable(),
  updatedAt: isoDate,
  members: z.array(memberSchema).min(1).max(MAX_MEMBERS),
  adminThreshold: z.number().int().min(1).max(MAX_MEMBERS),
}).strict();

export const signatureSchema = z.object({
  memberId: z.string().regex(memberIdPattern),
  keyId: z.string().regex(/^[a-f0-9]{16}$/),
  sig: z.string().regex(/^[A-Za-z0-9+/]{86}==$/),
}).strict();

export const signedRosterSchema = z.object({
  roster: rosterSchema,
  signatures: z.array(signatureSchema).max(MAX_SIGNATURES),
}).strict();

/** The public half of a member's identity, exported by `keysentry team card` and imported by `team add --card`. */
export interface MemberCard { v: 1; kind: 'keysentry-member-card'; deviceKeys: TeamMember['deviceKeys']; passkeys: TeamMember['passkeys'] }
export const memberCardSchema = z.object({
  v: z.literal(1), kind: z.literal('keysentry-member-card'),
  deviceKeys: z.array(deviceKeySchema).min(1).max(MAX_DEVICE_KEYS_PER_MEMBER),
  passkeys: z.array(passkeySchema).max(MAX_PASSKEYS_PER_MEMBER),
}).strict();

/** Rules zod cannot express per field. Returns a fixed, value-free reason, or null. */
export function rosterProblem(roster: z.infer<typeof rosterSchema>): string | null {
  if ((roster.version === 1) !== (roster.prev === null)) return 'Version 1 of a roster has no previous hash, and every later version has one.';
  const ids = roster.members.map(member => member.id);
  if (new Set(ids).size !== ids.length) return 'Two members share the same id.';
  const keyIds = roster.members.flatMap(member => member.deviceKeys.map(key => key.keyId));
  if (new Set(keyIds).size !== keyIds.length) return 'A device key is listed more than once.';
  const passkeyIds = roster.members.flatMap(member => member.passkeys.map(passkey => passkey.id));
  if (new Set(passkeyIds).size !== passkeyIds.length) return 'A passkey is listed more than once.';
  const emails = roster.members.flatMap(member => member.email === undefined ? [] : [member.email]);
  if (new Set(emails).size !== emails.length) return 'Two members share the same email.';
  const admins = roster.members.filter(member => member.role === 'admin');
  if (!admins.length) return 'A team needs at least one admin.';
  if (roster.adminThreshold > admins.length) return 'The admin threshold is higher than the number of admins.';
  if (roster.adminThreshold > admins.filter(member => member.deviceKeys.length > 0).length) {
    return 'Fewer admins have a device key than the admin threshold needs, so no later change could be signed.';
  }
  return null;
}

/** Parse untrusted input into a structurally valid signed roster, or return why not. */
export function parseSignedRoster(input: unknown): { ok: true; value: SignedTeamRoster } | { ok: false; reason: string } {
  const members = (input as { roster?: { members?: unknown } } | null)?.roster?.members;
  if (Array.isArray(members) && members.length > MAX_MEMBERS) return { ok: false, reason: `A team can have at most ${MAX_MEMBERS} members.` };
  const parsed = signedRosterSchema.safeParse(input);
  if (!parsed.success) return { ok: false, reason: 'The roster is not a valid signed team roster (wrong type, unknown field, or invalid value).' };
  const problem = rosterProblem(parsed.data.roster);
  if (problem) return { ok: false, reason: problem };
  const seen = new Set<string>();
  for (const signature of parsed.data.signatures) {
    const key = `${signature.memberId}:${signature.keyId}`;
    if (seen.has(key)) return { ok: false, reason: 'The roster carries the same signature twice.' };
    seen.add(key);
  }
  return { ok: true, value: parsed.data as SignedTeamRoster };
}
