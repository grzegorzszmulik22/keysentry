/**
 * Why a single sign-on attempt was refused. Reasons are fixed labels: they are safe to put in the audit log and
 * never carry a token, claim value, upstream body or URL.
 */
export type OidcFailure =
  | 'configuration'
  | 'unavailable'
  | 'token-response'
  | 'provider-error'
  | 'state'
  | 'malformed'
  | 'algorithm'
  | 'unknown-key'
  | 'signature'
  | 'issuer'
  | 'audience'
  | 'authorized-party'
  | 'expired'
  | 'not-yet-valid'
  | 'stale'
  | 'nonce'
  | 'subject'
  | 'email-missing'
  | 'email-unverified'
  | 'not-member'
  | 'roster-unavailable';

const VERIFY = 'The sign-in could not be verified. Sign in again, or ask a team admin to check the identity provider settings.';
const EMAIL = 'Your identity provider did not confirm a verified email address for this account, so it cannot be matched to a team member.';

/** Calm, fixed user-facing text for each refusal. */
export const OIDC_MESSAGES: Readonly<Record<OidcFailure, string>> = Object.freeze({
  configuration: 'The sign-in settings do not match what the identity provider publishes. Ask a team admin to check the issuer, client and host settings.',
  unavailable: 'The identity provider could not be reached. Try signing in again in a moment.',
  'token-response': 'The identity provider did not complete the sign-in. Sign in again.',
  'provider-error': 'The identity provider did not complete the sign-in. Sign in again.',
  state: 'This sign-in has expired or was already used. Sign in again.',
  malformed: VERIFY,
  algorithm: VERIFY,
  'unknown-key': VERIFY,
  signature: VERIFY,
  issuer: VERIFY,
  audience: VERIFY,
  'authorized-party': VERIFY,
  expired: VERIFY,
  'not-yet-valid': VERIFY,
  stale: VERIFY,
  nonce: VERIFY,
  subject: VERIFY,
  'email-missing': EMAIL,
  'email-unverified': EMAIL,
  'not-member': 'This account is not on the team roster. Ask a team admin to add your email address.',
  'roster-unavailable': 'The team roster could not be read, so nobody can sign in right now. Ask a team admin to check keysentry.',
});

export class OidcError extends Error {
  constructor(readonly reason: OidcFailure) {
    super(OIDC_MESSAGES[reason]);
    this.name = 'OidcError';
  }
}

export function fail(reason: OidcFailure): never {
  throw new OidcError(reason);
}
