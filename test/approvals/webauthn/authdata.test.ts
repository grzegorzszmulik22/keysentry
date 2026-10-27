import { describe, expect, test } from 'vitest';
import { parseAuthData } from '../../../src/approvals/webauthn/authdata.js';
import { decodeCbor } from '../../../src/approvals/webauthn/cbor.js';
import { encode, hex, registrationAuthData, vector } from './helpers.js';

describe('authenticator data', () => {
  test('reads the fixed header, unsigned big-endian counter and flags', () => {
    const data = hex(vector().authentication.authenticatorData!);
    data.writeUInt32BE(0xfedcba98, 33);
    expect(parseAuthData(data)).toEqual({
      rpIdHash: hex('bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5'),
      flags: { up: true, uv: false, be: true, bs: true, at: false, ed: false }, signCount: 0xfedcba98,
    });
  });

  test('delimits a credential key separately from extension CBOR', () => {
    const data = registrationAuthData();
    data[32] = data[32]! | 0x80;
    const result = parseAuthData(Buffer.concat([data, encode(new Map([['example', true]]))]));
    expect(result.credential!.id).toEqual(hex(vector().registration.credential_id!));
    expect(result.credential!.aaguid).toEqual(hex(vector().registration.aaguid!));
    expect(decodeCbor(result.credential!.publicKeyCose)).toBeInstanceOf(Map);
    expect(result.flags.ed).toBe(true);
  });

  test('accepts extensions without an attested credential', () => {
    const header = hex(vector().authentication.authenticatorData!);
    header[32] = header[32]! | 0x80;
    expect(parseAuthData(Buffer.concat([header, encode(new Map([['test', 1]]))])).credential).toBeUndefined();
  });

  test.each([0, 1, 32, 36])('rejects a truncated fixed header of %i bytes', (length) => {
    expect(() => parseAuthData(Buffer.alloc(length))).toThrow();
  });

  test('rejects every truncated attested credential structure', () => {
    const data = registrationAuthData();
    for (let i = 37; i < data.length; i++) expect(() => parseAuthData(data.subarray(0, i)), `length ${i}`).toThrow();
  });

  test('rejects absent, non-map, malformed or extra extension data', () => {
    const data = hex(vector().authentication.authenticatorData!);
    data[32] = data[32]! | 0x80;
    for (const suffix of [Buffer.alloc(0), encode(1), hex('bf'), hex('a000')]) {
      expect(() => parseAuthData(Buffer.concat([data, suffix]))).toThrow();
    }
    const header = hex(vector().authentication.authenticatorData!);
    expect(() => parseAuthData(Buffer.concat([header, hex('a0')]))).toThrow();
  });

  test('rejects non-map credential keys and out-of-bounds credential ids', () => {
    const data = registrationAuthData();
    expect(() => parseAuthData(Buffer.concat([data.subarray(0, 87), encode(0)]))).toThrow();
    for (const size of [0, 1024, 65535]) {
      const malformed = Buffer.from(data);
      malformed.writeUInt16BE(size, 53);
      expect(() => parseAuthData(malformed)).toThrow();
    }
  });

  test('caps authenticator data size before parsing', () => {
    expect(() => parseAuthData(Buffer.alloc(65537))).toThrow();
  });
});
