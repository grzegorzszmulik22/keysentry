export {
  TeamError, rosterHash, rosterFingerprint, hasRole, devicePublicKey, createRoster, nextRoster, signRoster, verifyRoster, verifyFirstUse,
  memberForPasskey, memberForDeviceKey, memberForEmail, memberForSso, teamPasskeys, teamDeviceKeys, vaultTeamAnchor, loadTeam, applyRoster,
  describeRosterChange, rosterPath, checkProposal,
} from './roster.js';
export type { NewMember, RosterChange, RosterVerification, TeamAnchor, LoadedTeam, ApplyRosterOptions } from './roster.js';
export { TEAM_SIGNATURE_PREFIX, documentHash, fingerprint, fingerprintMatches, signTeamDocument, verifyTeamSignatures } from './signature.js';
export type { SignatureCheck } from './signature.js';
export { MAX_MEMBERS, ROLE_RANK, parseSignedRoster, memberCardSchema } from './schema.js';
export type { MemberCard } from './schema.js';
export { routeChannels, createRoutedDispatcher } from './routing.js';
export type { RoutedSendResult } from './routing.js';
export { INVITE_TTL_MS, EnrollmentError, createInvite, checkInvite, completeEnrollment, listCandidates, removeCandidates, enrollmentPath } from './enrollment.js';
export type { EnrollmentCandidate } from './enrollment.js';
