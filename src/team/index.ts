export {
  TeamError, rosterHash, rosterFingerprint, hasRole, devicePublicKey, createRoster, nextRoster, signRoster, verifyRoster, verifyFirstUse,
  memberForPasskey, memberForDeviceKey, memberForEmail, memberForSso, teamPasskeys, teamDeviceKeys, vaultTeamAnchor, loadTeam, applyRoster,
  describeRosterChange, rosterPath, checkProposal, exclusiveChannels, adminsNeeded, noSpareAdminWarning,
} from './roster.js';
export type { NewMember, RosterChange, RosterVerification, RosterRules, TeamAnchor, LoadedTeam, ApplyRosterOptions } from './roster.js';
export { TEAM_SIGNATURE_PREFIX, documentHash, fingerprint, fingerprintMatches, signTeamDocument, verifyTeamSignatures } from './signature.js';
export type { SignatureCheck } from './signature.js';
export { MAX_MEMBERS, ROLE_RANK, parseSignedRoster, memberCardSchema, foldEmail, asciiEmail, canonicalSignature } from './schema.js';
export type { MemberCard } from './schema.js';
export { routeChannels, createRoutedDispatcher } from './routing.js';
export type { RoutedSendResult } from './routing.js';
export {
  INVITE_TTL_MS, EnrollmentError, signInvite, verifyInvite, checkInvite, completeEnrollment, listCandidates, removeCandidates, enrollmentPath,
  candidateCard, parseCandidateCard, candidateFingerprint,
} from './enrollment.js';
export type { EnrollmentCandidate, CandidateCard } from './enrollment.js';
