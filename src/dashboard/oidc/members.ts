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

/**
 * Map a verified identity to exactly one roster member by verified email. No verified email, no member, or an
 * ambiguous match (two members with one address) gives no session.
 */
export function memberForIdentity(identity: VerifiedIdentity, members: readonly TeamMember[]): TeamMember {
  if (identity.email === undefined) return fail('email-missing');
  if (identity.emailVerified !== true) return fail('email-unverified');
  const email = normalizeEmail(identity.email);
  const matches = members.filter(member => typeof member.email === 'string' && normalizeEmail(member.email) === email && isTeamRole(member.role));
  if (matches.length !== 1) return fail('not-member');
  return matches[0]!;
}
