// One signature scheme for every team document (roster and policy): Ed25519 by an admin's device key over
// `keysentry-team:v1\n` + canonical JSON of the document. The signed wrapper is hashed for the version chain.
import { createHash } from 'node:crypto';
import { canonicalJson, signDetached, verifyDetached, type DeviceKey } from '../security/index.js';
import type { TeamRoster, TeamSignature } from '../types.js';
import { keyIdFor } from './schema.js';

export const TEAM_SIGNATURE_PREFIX = 'keysentry-team:v1\n';

export function signedBytes(document: unknown): Buffer {
  return Buffer.from(TEAM_SIGNATURE_PREFIX + canonicalJson(document), 'utf8');
}

/** sha256 hex of the canonical JSON of a signed document (its `prev` link for the next version). */
export function documentHash(signed: unknown): string {
  return createHash('sha256').update(canonicalJson(signed), 'utf8').digest('hex');
}

/** Short, human-comparable form of a document hash, e.g. "3f9a-12c4-77d0-ab18". */
export function fingerprint(hash: string): string {
  return hash.slice(0, 16).match(/.{4}/g)!.join('-');
}

/** True when `value` (dashes and case ignored, at least 16 hex characters) is a prefix of `hash`. */
export function fingerprintMatches(hash: string, value: string): boolean {
  const clean = value.replaceAll('-', '').toLowerCase();
  return /^[a-f0-9]{16,64}$/.test(clean) && hash.startsWith(clean);
}

export function signTeamDocument(document: unknown, memberId: string, key: DeviceKey): TeamSignature {
  if (keyIdFor(key.publicKeyDer) !== key.keyId) throw new TypeError('Device key ID does not match its public key.');
  return { memberId, keyId: key.keyId, sig: signDetached(key.privateKeyDer, signedBytes(document)).toString('base64') };
}

export type SignatureCheck = { ok: true; signers: string[] } | { ok: false; reason: string; signers?: string[] };

/**
 * Every signature must verify and come from an admin of `authority` (the roster that authorizes the change) with a
 * device key listed for that admin; distinct admins must reach `threshold`. A member signing twice counts once.
 */
export function verifyTeamSignatures(document: unknown, signatures: readonly TeamSignature[], authority: TeamRoster, threshold: number): SignatureCheck {
  const bytes = signedBytes(document);
  const signers = new Set<string>();
  for (const signature of signatures) {
    const member = authority.members.find(candidate => candidate.id === signature.memberId);
    if (!member || member.role !== 'admin') {
      return { ok: false, reason: 'A signature is from someone who is not an admin of the roster that authorizes this change.' };
    }
    const key = member.deviceKeys.find(candidate => candidate.keyId === signature.keyId);
    if (!key) return { ok: false, reason: 'A signature uses a device key that is not listed for that admin.' };
    const sig = Buffer.from(signature.sig, 'base64');
    if (sig.length !== 64 || !verifyDetached(Buffer.from(key.publicKeyDer, 'base64'), bytes, sig)) {
      return { ok: false, reason: 'A signature does not match the document. It may have been changed after signing.' };
    }
    signers.add(member.id);
  }
  if (signers.size < threshold) {
    return { ok: false, reason: `This change has ${signers.size} of the ${threshold} admin signatures it needs.`, signers: [...signers] };
  }
  return { ok: true, signers: [...signers] };
}
