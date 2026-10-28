import { createHash } from 'node:crypto';
import { generateDeviceKey, signDetached, type DeviceKey } from '../../src/security/index.js';
import { devicePublicKey } from '../../src/team/index.js';
import type { PasskeyCredential, TeamMember, TeamRole, TeamRoster } from '../../src/types.js';

export const NOW = new Date('2026-10-28T10:00:00.000Z');

export interface TestMember { member: TeamMember; key: DeviceKey; passkey: DeviceKey; credential: PasskeyCredential }

let counter = 0;
/** A member with one device key and one Ed25519 passkey for `origin`. */
export function testMember(id: string, role: TeamRole, options: { origin?: string; rpId?: string; email?: string } = {}): TestMember {
  const key = generateDeviceKey();
  const passkey = generateDeviceKey();
  const origin = options.origin ?? 'https://watcher.example.org';
  const cose = Buffer.concat([Buffer.from('a4010103272006215820', 'hex'), passkey.publicKeyDer.subarray(-32)]);
  const credential: PasskeyCredential = {
    id: Buffer.from(`credential-${id}-${++counter}`).toString('base64url'), publicKeyCose: cose.toString('base64url'), alg: -8, signCount: 0,
    backupEligible: false, rpId: options.rpId ?? new URL(origin).hostname, origins: [origin], label: `${id} laptop`, createdAt: NOW.toISOString(),
  };
  const member: TeamMember = { id, name: id.toUpperCase(), role, ...(options.email ? { email: options.email } : {}), passkeys: [credential], deviceKeys: [devicePublicKey(key)] };
  return { member, key, passkey, credential };
}

export function rosterOf(members: TestMember[], options: Partial<Pick<TeamRoster, 'adminThreshold' | 'teamId' | 'version' | 'prev'>> = {}): TeamRoster {
  return { v: 1, teamId: options.teamId ?? 'team-test-0001', version: options.version ?? 1, prev: options.prev ?? null, updatedAt: NOW.toISOString(),
    members: members.map(entry => structuredClone(entry.member)), adminThreshold: options.adminThreshold ?? 1 };
}

/** A WebAuthn assertion over `challenge` by the member's passkey (Ed25519, user verified). */
export function assertionFor(entry: TestMember, challenge: string, count = 0, origin = entry.credential.origins[0]!) {
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin }));
  const authenticatorData = Buffer.alloc(37);
  createHash('sha256').update(entry.credential.rpId).digest().copy(authenticatorData);
  authenticatorData[32] = 5;
  authenticatorData.writeUInt32BE(count, 33);
  const signature = signDetached(entry.passkey.privateKeyDer, Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJSON).digest()]));
  return { credentialId: entry.credential.id, clientDataJSON, authenticatorData, signature };
}
