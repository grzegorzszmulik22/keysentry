import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { describe, expect, test } from 'vitest';
import { CborError, decodeCbor, decodeCborFirst } from '../../../src/approvals/webauthn/cbor.js';

const hex = (value: string): Buffer => Buffer.from(value.replaceAll(' ', ''), 'hex');

function nestedArrays(depth: number): Buffer {
  return Buffer.concat([Buffer.alloc(depth, 0x81), hex('00')]);
}

const fixtures = JSON.parse(readFileSync(new URL('../../fixtures/webauthn/vectors.json', import.meta.url), 'utf8')) as {
  vectors: Record<string, { registration: { attestationObject: string } }>;
};
const attestations = Object.entries(fixtures.vectors).map(([name, vector]) => ({
  name,
  bytes: hex(vector.registration.attestationObject),
}));

describe('decodeCbor', () => {
  test.each([
    ['00', 0], ['17', 23], ['1818', 24], ['18ff', 255], ['190100', 256],
    ['19ffff', 65_535], ['1a00010000', 65_536], ['1affffffff', 4_294_967_295],
    ['1b0000000100000000', 4_294_967_296], ['1b001fffffffffffff', Number.MAX_SAFE_INTEGER],
    ['20', -1], ['37', -24], ['3818', -25], ['38ff', -256], ['390100', -257],
    ['3b001ffffffffffffe', Number.MIN_SAFE_INTEGER], ['f4', false], ['f5', true], ['f6', null],
  ])('decodes the supported scalar %s', (encoded, value) => {
    expect(decodeCbor(hex(encoded as string))).toBe(value);
  });

  test('decodes byte strings, UTF-8 text, arrays and integer/text Map keys', () => {
    expect(decodeCbor(hex('430001ff'))).toEqual(hex('0001ff'));
    expect(decodeCbor(hex('60'))).toBe('');
    expect(decodeCbor(hex('66 c3a9 f09f9491'))).toBe('é🔑');
    expect(decodeCbor(hex('84 00 20 f5 f6'))).toEqual([0, -1, true, null]);
    expect(decodeCbor(hex('a3 01 02 6131 03 20 04'))).toEqual(new Map<unknown, unknown>([[1, 2], ['1', 3], [-1, 4]]));
    expect(decodeCbor(hex('a0'))).toEqual(new Map());
  });

  test('preserves a UTF-8 BOM and keeps different text keys distinct', () => {
    expect(decodeCbor(hex('63efbbbf'))).toBe('\ufeff');
    expect(decodeCbor(hex('a2 60 00 63efbbbf 01'))).toEqual(new Map([['', 0], ['\ufeff', 1]]));
    expect(decodeCbor(hex('a2 62c3a9 00 6365cc81 01'))).toEqual(new Map([['é', 0], ['e\u0301', 1]]));
    expect(decodeCbor(hex('a1 695f5f70726f746f5f5f 00'))).toEqual(new Map([['__proto__', 0]]));
  });

  test.each([
    '', '18', '19ff', '1affff', '1b00000000', '38', '41', '61', '8200', 'a100',
    '5802ff', '7802ff', '9a00010000', 'ba00010000',
  ])('rejects truncated input %s as CborError', (encoded) => {
    expect(() => decodeCbor(hex(encoded))).toThrow(CborError);
  });

  test.each([
    '1800', '1817', '190018', '1900ff', '1a00000100', '1a0000ffff', '1b0000000000010000',
    '3800', '3900ff', '3a00000100', '3b00000000ffffffff',
    '5800', '590017', '5a000000ff', '5b000000000000ffff', '590000', '5a00000000', '5b0000000000000000',
    '7800', '790017', '7a000000ff', '7b000000000000ffff', '790000', '7a00000000', '7b0000000000000000',
    '9800', '990018', '9a000000ff', '9b000000000000ffff', '990000', '9a00000000', '9b0000000000000000',
    'b800', 'b90018', 'ba000000ff', 'bb000000000000ffff', 'b90000', 'ba00000000', 'bb0000000000000000',
  ])('rejects nonminimal integer or length encoding %s', (encoded) => {
    expect(() => decodeCbor(hex(encoded))).toThrow(CborError);
  });

  test.each([
    '1c', '1d', '1e', '1f', '3f', '5f40ff', '7f60ff', '9f00ff', 'bf0000ff',
    'c000', 'd81800', 'f0', 'f7', 'f814', 'f820', 'f90000', 'fa00000000',
    'fb0000000000000000', 'fc', 'fd', 'fe', 'ff',
  ])('rejects indefinite lengths, tags and unsupported simple values %s', (encoded) => {
    expect(() => decodeCbor(hex(encoded))).toThrow(CborError);
  });

  test.each([
    '6180', '61c0', '62c0af', '62c180', '62c2ff', '62e282', '63eda080',
    '64f0808080', '64f4908080', '64f5808080', '61ff',
  ])('rejects invalid UTF-8 %s', (encoded) => {
    expect(() => decodeCbor(hex(encoded))).toThrow(CborError);
  });

  test.each([
    '1b0020000000000000', '1bffffffffffffffff', '3b001fffffffffffff', '3bffffffffffffffff',
    'a1 1b0020000000000000 00', 'a1 3b001fffffffffffff 00',
  ])('rejects unsafe integers in values and map keys %s', (encoded) => {
    expect(() => decodeCbor(hex(encoded))).toThrow(CborError);
  });

  test.each(['a200000001', 'a220002001', 'a2616100616101', 'a263efbbbf0063efbbbf01'])('rejects duplicate map keys %s', (encoded) => {
    expect(() => decodeCbor(hex(encoded))).toThrow(CborError);
  });

  test.each(['a14000', 'a18000', 'a1a000', 'a1f400', 'a1f500', 'a1f600'])('rejects unsupported map keys %s', (encoded) => {
    expect(() => decodeCbor(hex(encoded))).toThrow(CborError);
  });

  test('rejects trailing input after one complete value', () => {
    expect(() => decodeCbor(hex('0000'))).toThrow(CborError);
    expect(() => decodeCbor(hex('a10102ff'))).toThrow(CborError);
  });

  test('accepts 16 nesting edges and rejects the 17th', () => {
    expect(() => decodeCbor(nestedArrays(16))).not.toThrow();
    expect(() => decodeCbor(nestedArrays(17))).toThrow(CborError);
    expect(() => decodeCbor(hex('00'), { maxDepth: 0 })).not.toThrow();
    expect(() => decodeCbor(hex('80'), { maxDepth: 0 })).not.toThrow();
    expect(() => decodeCbor(hex('8100'), { maxDepth: 0 })).toThrow(CborError);
    expect(() => decodeCbor(nestedArrays(2), { maxDepth: 1 })).toThrow(CborError);
  });

  test('counts containers, keys and values within the exact item limit', () => {
    const atLimit = Buffer.concat([hex('9903ff'), Buffer.alloc(1_023)]);
    const overLimit = Buffer.concat([hex('990400'), Buffer.alloc(1_024)]);
    expect(decodeCbor(atLimit)).toHaveLength(1_023);
    expect(() => decodeCbor(overLimit)).toThrow(CborError);
    expect(decodeCbor(hex('a201000200'), { maxItems: 5 })).toEqual(new Map([[1, 0], [2, 0]]));
    expect(() => decodeCbor(hex('a201000200'), { maxItems: 4 })).toThrow(CborError);
    expect(decodeCbor(hex('80'), { maxItems: 1 })).toEqual([]);
    expect(decodeCbor(hex('8100'), { maxItems: 2 })).toEqual([0]);
    expect(() => decodeCbor(hex('8100'), { maxItems: 1 })).toThrow(CborError);
  });

  test('accepts exactly 64 KiB and rejects larger input in both APIs', () => {
    const atLimit = Buffer.concat([hex('59fffd'), Buffer.alloc(65_533)]);
    expect(decodeCbor(atLimit)).toEqual(Buffer.alloc(65_533));
    expect(decodeCborFirst(atLimit).bytesRead).toBe(65_536);
    const overLimit = Buffer.concat([hex('59fffe'), Buffer.alloc(65_534)]);
    expect(() => decodeCbor(overLimit)).toThrow(CborError);
    expect(() => decodeCborFirst(overLimit)).toThrow(CborError);
    expect(() => decodeCborFirst(Buffer.alloc(65_537))).toThrow(CborError);
  });

  test.each([
    '5affffffff', '7affffffff', '9affffffff', 'baffffffff',
    '5b001fffffffffffff', '7b001fffffffffffff', '9b001fffffffffffff', 'bb001fffffffffffff',
    '5bffffffffffffffff', '7bffffffffffffffff', '9bffffffffffffffff', 'bbffffffffffffffff',
  ])('rejects enormous declared lengths without allocating or looping %s', (encoded) => {
    expect(() => decodeCbor(hex(encoded))).toThrow(CborError);
  });

  test.each([
    { maxDepth: -1 }, { maxDepth: 17 }, { maxDepth: 1.5 }, { maxDepth: Number.NaN }, { maxDepth: Infinity },
    { maxItems: 0 }, { maxItems: -1 }, { maxItems: 1_025 }, { maxItems: 1.5 }, { maxItems: Number.NaN }, { maxItems: Infinity },
  ])('rejects invalid or expanded security limits %j', (opts) => {
    expect(() => decodeCbor(hex('00'), opts)).toThrow(CborError);
    expect(() => decodeCborFirst(hex('00'), opts)).toThrow(CborError);
  });

  test('rejects invalid input with a static error that does not reflect its bytes', () => {
    const marker = Buffer.from('private-cbor-test-marker');
    const bytes = Buffer.concat([hex('7818'), marker, hex('ff')]);
    try {
      decodeCbor(bytes);
      expect.fail('Expected CBOR rejection.');
    } catch (error) {
      expect(error).toBeInstanceOf(CborError);
      expect((error as Error).name).toBe('CborError');
      expect((error as Error).message).not.toContain(marker.toString());
      expect((error as Error).message).not.toContain(marker.toString('hex'));
    }
    expect(() => decodeCbor(new Uint8Array([0]) as Buffer)).toThrow(CborError);
  });

  test.each(attestations)('decodes the real attestationObject $name', ({ bytes }) => {
    const decoded = decodeCbor(bytes) as Map<string, unknown>;
    expect(decoded).toBeInstanceOf(Map);
    expect(typeof decoded.get('fmt')).toBe('string');
    expect(decoded.get('attStmt')).toBeInstanceOf(Map);
    expect(Buffer.isBuffer(decoded.get('authData'))).toBe(true);
  });

  test('survives 10,000 random inputs and 2,000 real-object mutations within five seconds', () => {
    let state = 0x6e624eb7;
    const random = (): number => {
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      return state >>> 0;
    };
    const check = (bytes: Buffer): void => {
      for (const decode of [decodeCbor, decodeCborFirst]) {
        try {
          decode(bytes);
        } catch (error) {
          if (!(error instanceof CborError)) throw error;
        }
      }
    };
    const started = performance.now();
    for (let i = 0; i < 10_000; i++) {
      const bytes = Buffer.alloc(random() % 257);
      for (let j = 0; j < bytes.length; j++) bytes[j] = random() & 0xff;
      check(bytes);
    }
    for (let i = 0; i < 2_000; i++) {
      const source = attestations[random() % attestations.length]!.bytes;
      let bytes = Buffer.from(source);
      switch (i % 4) {
        case 0:
          bytes[random() % bytes.length]! ^= 1 << (random() % 8);
          break;
        case 1:
          bytes = bytes.subarray(0, random() % bytes.length);
          break;
        case 2:
          bytes = Buffer.concat([bytes, Buffer.from([random() & 0xff])]);
          break;
        default:
          bytes[random() % bytes.length] = random() & 0xff;
      }
      check(bytes);
    }
    expect(performance.now() - started).toBeLessThan(5_000);
  });
});

describe('decodeCborFirst', () => {
  test('delimits one complete value for a following CBOR extension map', () => {
    const bytes = hex('a10102a16178f5');
    expect(decodeCborFirst(bytes)).toEqual({ value: new Map([[1, 2]]), bytesRead: 3 });
    expect(decodeCbor(bytes.subarray(3))).toEqual(new Map([['x', true]]));
    expect(decodeCborFirst(hex('00ff'))).toEqual({ value: 0, bytesRead: 1 });
  });

  test('uses the same depth and item limits as full decoding', () => {
    expect(() => decodeCborFirst(nestedArrays(17))).toThrow(CborError);
    expect(() => decodeCborFirst(hex('8100'), { maxDepth: 0 })).toThrow(CborError);
    expect(() => decodeCborFirst(hex('a201000200'), { maxItems: 4 })).toThrow(CborError);
  });
});
