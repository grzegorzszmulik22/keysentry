import type { ProviderId } from '../types.js';

const AWS_ACCESS_KEY_ID = /^(?:AKIA|ASIA)[A-Z0-9]{16}$/;
const TWILIO_KEY_SID = /^SK[0-9a-fA-F]{32}$/;

/**
 * Public key identifiers that journals and reports keep in their typed key-reference fields so a later finish, grace
 * revocation or undo can name the key: AWS access key ids and Twilio API key SIDs. Their secrets, and every freeform
 * text, stay masked.
 */
export function isPublicKeyId(value: string, provider?: ProviderId): boolean {
  if (provider === 'aws') return AWS_ACCESS_KEY_ID.test(value);
  if (provider === 'twilio') return TWILIO_KEY_SID.test(value);
  if (provider !== undefined) return false;
  return AWS_ACCESS_KEY_ID.test(value) || TWILIO_KEY_SID.test(value);
}

/** Providers whose key references are public identifiers (see isPublicKeyId). */
export function hasPublicKeyIds(provider: ProviderId): boolean {
  return provider === 'aws' || provider === 'twilio';
}
