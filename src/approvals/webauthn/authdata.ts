import { decodeCborFirst } from './cbor.js';

/** Internal parse errors contain only fixed field descriptions, never input data. */
export class AuthDataError extends Error {
  constructor(reason: string) { super(reason); this.name = 'AuthDataError'; }
}

export interface AuthData {
  rpIdHash: Buffer;
  flags: { up: boolean; uv: boolean; be: boolean; bs: boolean; at: boolean; ed: boolean };
  signCount: number;
  credential?: { aaguid: Buffer; id: Buffer; publicKeyCose: Buffer };
}

export function parseAuthData(buf: Buffer): AuthData {
  if (!Buffer.isBuffer(buf) || buf.length < 37 || buf.length > 65536) {
    throw new AuthDataError('authenticatorData has an invalid length');
  }
  const bits = buf[32]!;
  const flags = {
    up: (bits & 1) !== 0, uv: (bits & 4) !== 0, be: (bits & 8) !== 0,
    bs: (bits & 16) !== 0, at: (bits & 64) !== 0, ed: (bits & 128) !== 0,
  };
  const result: AuthData = { rpIdHash: Buffer.from(buf.subarray(0, 32)), flags, signCount: buf.readUInt32BE(33) };
  let offset = 37;
  if (flags.at) {
    if (buf.length < 55) throw new AuthDataError('attested credential data is truncated');
    const idLength = buf.readUInt16BE(53);
    if (idLength < 1 || idLength > 1023) throw new AuthDataError('credential id length must be between 1 and 1023 bytes');
    const keyStart = 55 + idLength;
    if (keyStart >= buf.length) throw new AuthDataError('attested credential id or key is truncated');
    const decoded = decodeCborFirst(buf.subarray(keyStart));
    if (!(decoded.value instanceof Map) || [...decoded.value.keys()].some((k: unknown) => typeof k !== 'number')) {
      throw new AuthDataError('credential public key must be a COSE map');
    }
    offset = keyStart + decoded.bytesRead;
    result.credential = {
      aaguid: Buffer.from(buf.subarray(37, 53)), id: Buffer.from(buf.subarray(55, keyStart)),
      publicKeyCose: Buffer.from(buf.subarray(keyStart, offset)),
    };
  }
  if (flags.ed) {
    const decoded = decodeCborFirst(buf.subarray(offset));
    if (!(decoded.value instanceof Map) || [...decoded.value.keys()].some((k: unknown) => typeof k !== 'string')) {
      throw new AuthDataError('authenticator extensions must be a text-keyed map');
    }
    offset += decoded.bytesRead;
  }
  if (offset !== buf.length) throw new AuthDataError('authenticatorData has unexpected trailing bytes');
  return result;
}
