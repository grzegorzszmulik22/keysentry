import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import type { PasskeyCredential } from '../../../src/types.js';

export interface RegistrationWire {
  id: string;
  rawId: string;
  type: 'public-key';
  response: { clientDataJSON: string; attestationObject: string };
}
export interface AssertionWire {
  id: string;
  rawId: string;
  type: 'public-key';
  response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle: null };
}
interface CeremonyOptions { uv?: boolean; signCount?: number }

/** Small definite-length CBOR encoder used only to build synthetic authenticators. */
function cbor(value: number | string | Buffer | Map<number | string, unknown>): Buffer {
  function head(major: number, size: number): Buffer {
    if (size < 24) return Buffer.from([(major << 5) | size]);
    if (size < 256) return Buffer.from([(major << 5) | 24, size]);
    const result = Buffer.alloc(3);
    result[0] = (major << 5) | 25;
    result.writeUInt16BE(size, 1);
    return result;
  }
  if (typeof value === 'number') return head(value < 0 ? 1 : 0, value < 0 ? -1 - value : value);
  if (typeof value === 'string') { const bytes = Buffer.from(value); return Buffer.concat([head(3, bytes.length), bytes]); }
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  const entries = [...value].flatMap(([key, item]) => [cbor(key), cbor(item as Parameters<typeof cbor>[0])]);
  return Buffer.concat([head(5, value.size), ...entries]);
}

/** A real P-256 signing key with synthetic WebAuthn bytes; no browser or device calls. */
export function createFakeAuthenticator() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const cose = cbor(new Map<number, unknown>([
    [1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')],
  ]));
  const credentialId = randomBytes(32);
  const id = credentialId.toString('base64url');
  let counter = 0;
  const hash = (data: Buffer | string) => createHash('sha256').update(data).digest();
  const client = (type: string, challenge: string, origin: string) => Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  function authData(flags: number, count: number): Buffer {
    const result = Buffer.alloc(37);
    hash('localhost').copy(result);
    result[32] = flags;
    result.writeUInt32BE(count, 33);
    return result;
  }
  function assertion(challenge: string, origin: string, opts: CeremonyOptions = {}): AssertionWire {
    const count = opts.signCount ?? ++counter;
    const data = client('webauthn.get', challenge, origin);
    const authenticator = authData(1 | (opts.uv === false ? 0 : 4), count);
    const signature = sign('sha256', Buffer.concat([authenticator, hash(data)]), { key: privateKey, dsaEncoding: 'der' });
    return { id, rawId: id, type: 'public-key', response: {
      clientDataJSON: data.toString('base64url'), authenticatorData: authenticator.toString('base64url'),
      signature: signature.toString('base64url'), userHandle: null,
    } };
  }
  return {
    id,
    credential(origins = ['http://localhost']): PasskeyCredential {
      return { id, publicKeyCose: cose.toString('base64url'), alg: -7, signCount: 0, backupEligible: false,
        rpId: 'localhost', origins: [...origins], label: 'Test passkey', createdAt: '2026-10-27T00:00:00.000Z' };
    },
    registration(challenge: string, origin: string, opts: CeremonyOptions = {}): RegistrationWire {
      const length = Buffer.alloc(2);
      length.writeUInt16BE(credentialId.length);
      const authenticator = Buffer.concat([authData(0x41 | (opts.uv === false ? 0 : 4), opts.signCount ?? 0), Buffer.alloc(16), length, credentialId, cose]);
      const attestation = cbor(new Map<string, unknown>([['fmt', 'none'], ['attStmt', new Map()], ['authData', authenticator]]));
      return { id, rawId: id, type: 'public-key', response: {
        clientDataJSON: client('webauthn.create', challenge, origin).toString('base64url'), attestationObject: attestation.toString('base64url'),
      } };
    },
    assertion,
    assertionHeader(challenge: string, origin: string, opts: CeremonyOptions = {}): string {
      return Buffer.from(JSON.stringify(assertion(challenge, origin, opts))).toString('base64url');
    },
  };
}
