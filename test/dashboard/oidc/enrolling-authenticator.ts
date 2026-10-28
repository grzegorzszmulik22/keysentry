import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';

type Cbor = number | string | Buffer | Map<number | string, Cbor>;

/** Definite-length CBOR for the shapes WebAuthn registration uses: small ints, text, bytes and maps. */
function cbor(value: Cbor): Buffer {
  const head = (major: number, size: number) => size < 24 ? Buffer.from([(major << 5) | size])
    : size < 256 ? Buffer.from([(major << 5) | 24, size]) : Buffer.from([(major << 5) | 25, size >> 8, size & 0xff]);
  if (typeof value === 'number') return head(value < 0 ? 1 : 0, value < 0 ? -1 - value : value);
  if (typeof value === 'string') { const bytes = Buffer.from(value, 'utf8'); return Buffer.concat([head(3, bytes.length), bytes]); }
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  return Buffer.concat([head(5, value.size), ...[...value].flatMap(([key, item]) => [cbor(key), cbor(item)])]);
}

const hash = (data: Buffer | string) => createHash('sha256').update(data).digest();

/**
 * A P-256 passkey that can register on the team dashboard (`none` attestation, user verified) and then assert, the
 * way a browser and platform authenticator would. `aaguid` is reported in the attested credential data.
 */
export function createEnrollingAuthenticator(rpId: string, options: { aaguid?: Buffer; uv?: boolean } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const cose = cbor(new Map<number, Cbor>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')]]));
  const rawId = randomBytes(32);
  const id = rawId.toString('base64url');
  const aaguid = options.aaguid ?? Buffer.alloc(16);
  let counter = 0;
  return {
    id,
    /** The public credential as the roster stores it (for member cards). */
    credential(origins: string[]): import('../../../src/types.js').PasskeyCredential {
      return { id, publicKeyCose: cose.toString('base64url'), alg: -7, signCount: 0, backupEligible: false, rpId, origins: [...origins],
        label: 'Team passkey', createdAt: '2026-10-28T00:00:00.000Z' };
    },
    /** The JSON the enrollment page posts to /enroll/finish (without the token). */
    register(challenge: string, origin: string, registerRpId = rpId): { clientDataJSON: string; attestationObject: string } {
      const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin, crossOrigin: false }));
      const flags = 0x01 | (options.uv === false ? 0 : 0x04) | 0x40;
      const count = Buffer.alloc(4);
      const length = Buffer.from([rawId.length >> 8, rawId.length & 0xff]);
      const authData = Buffer.concat([hash(registerRpId), Buffer.from([flags]), count, aaguid, length, rawId, cose]);
      const attestation = cbor(new Map<string, Cbor>([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
      return { clientDataJSON: clientData.toString('base64url'), attestationObject: attestation.toString('base64url') };
    },
    /** The X-Passkey-Assertion header value for a dashboard change. */
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
