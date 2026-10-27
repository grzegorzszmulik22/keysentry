import { describe, expect, it } from 'vitest';
import { canonicalJson } from '../../src/security/index.js';

describe('canonicalJson', () => {
  it('sorts keys at every depth and drops whitespace', () => {
    expect(canonicalJson({ b: 1, a: [2, { d: 1, c: 2 }] })).toBe('{"a":[2,{"c":2,"d":1}],"b":1}');
  });

  it('drops undefined object members but keeps null', () => {
    expect(canonicalJson({ a: undefined, b: null, c: 'x' })).toBe('{"b":null,"c":"x"}');
  });

  it('is independent of insertion order', () => {
    const a = { z: { y: 1, x: [1, 2] }, m: 'q' };
    const b = { m: 'q', z: { x: [1, 2], y: 1 } };
    expect(canonicalJson(a)).toBe(canonicalJson(b));
  });

  it('escapes strings like JSON.stringify', () => {
    expect(canonicalJson({ s: 'a"b\n ' })).toBe(`{"s":${JSON.stringify('a"b\n ')}}`);
  });

  it('throws on non-finite numbers', () => {
    expect(() => canonicalJson({ a: Number.NaN })).toThrow(TypeError);
    expect(() => canonicalJson([Number.POSITIVE_INFINITY])).toThrow(TypeError);
  });

  it('throws on values JSON cannot represent', () => {
    expect(() => canonicalJson({ a: () => 1 })).toThrow(TypeError);
    expect(() => canonicalJson({ a: 1n })).toThrow(TypeError);
  });
});
