import type { TeamMember, TeamRole } from '../../types.js';
import { fail } from './errors.js';
import type { VerifiedIdentity } from './id-token.js';

const ROLES: readonly TeamRole[] = ['viewer', 'operator', 'admin'];

export function roleRank(role: TeamRole): number {
  return ROLES.indexOf(role);
}

export function isTeamRole(value: unknown): value is TeamRole {
  return typeof value === 'string' && (ROLES as readonly string[]).includes(value);
}

export function normalizeEmail(value: string): string {
  return value.toLowerCase();
}

/** True when the member's pinned single sign-on identity is exactly this issuer and subject. */
export function pinnedTo(member: Pick<TeamMember, 'sso'>, issuer: string, subject: string): boolean {
  const sso = member.sso;
  return !!sso && typeof sso === 'object' && sso.issuer === issuer && sso.subject === subject;
}

/**
 * Map a verified identity to exactly one roster member.
 *
 * - A member with a pinned `sso` identity matches only that exact (`iss`, `sub`) pair. OIDC Core §5.7: only the
 *   issuer and subject together are stable; providers may reassign an email address.
 * - A member without `sso` matches by verified email, as before.
 * - A verified email that belongs to a member pinned to another subject is refused (`identity-mismatch`): a
 *   reassigned address cannot sign in as that member.
 */
export function memberForIdentity(identity: VerifiedIdentity, members: readonly TeamMember[]): TeamMember {
  const valid = members.filter(member => member && isTeamRole(member.role));
  const pinned = valid.filter(member => pinnedTo(member, identity.issuer, identity.subject));
  if (pinned.length > 1) return fail('not-member');
  if (pinned.length === 1) return pinned[0]!;
  if (identity.email === undefined) return fail('email-missing');
  if (identity.emailVerified !== true) return fail('email-unverified');
  const email = normalizeEmail(identity.email);
  const matches = valid.filter(member => typeof member.email === 'string' && normalizeEmail(member.email) === email);
  if (matches.length !== 1) return fail('not-member');
  if (matches[0]!.sso !== undefined) return fail('identity-mismatch');
  return matches[0]!;
}
