import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import type { PasskeyCredential } from '../../../src/types.js';

/** Small definite-length CBOR encoder for the COSE key only. */
function cbor(value: number | Buffer | Map<number, unknown>): Buffer {
  const head = (major: number, size: number) => size < 24 ? Buffer.from([(major << 5) | size]) : Buffer.from([(major << 5) | 24, size]);
  if (typeof value === 'number') return head(value < 0 ? 1 : 0, value < 0 ? -1 - value : value);
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  return Buffer.concat([head(5, value.size), ...[...value].flatMap(([key, item]) => [cbor(key), cbor(item as Parameters<typeof cbor>[0])])]);
}

/** A real P-256 passkey for the team dashboard's RP ID (the public host), with synthetic WebAuthn bytes. */
export function createTeamAuthenticator(rpId: string) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const cose = cbor(new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')]]));
  const id = randomBytes(32).toString('base64url');
  let counter = 0;
  const hash = (data: Buffer | string) => createHash('sha256').update(data).digest();
  return {
    id,
    credential(origins: string[], credentialRpId = rpId): PasskeyCredential {
      return { id, publicKeyCose: cose.toString('base64url'), alg: -7, signCount: 0, backupEligible: false,
        rpId: credentialRpId, origins: [...origins], label: 'Team passkey', createdAt: '2026-10-28T00:00:00.000Z' };
    },
    assertionHeader(challenge: string, origin: string): string {
      const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin, crossOrigin: false }));
      const authenticatorData = Buffer.alloc(37);
      hash(rpId).copy(authenticatorData);
      authenticatorData[32] = 1 | 4;
      authenticatorData.writeUInt32BE(++counter, 33);
      const signature = sign('sha256', Buffer.concat([authenticatorData, hash(clientData)]), { key: privateKey, dsaEncoding: 'der' });
      return Buffer.from(JSON.stringify({ id, rawId: id, type: 'public-key', response: {
        clientDataJSON: clientData.toString('base64url'), authenticatorData: authenticatorData.toString('base64url'),
        signature: signature.toString('base64url'), userHandle: null,
      } })).toString('base64url');
    },
  };
}
