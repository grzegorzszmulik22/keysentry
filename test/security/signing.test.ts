import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { deviceKeyFromPrivate, generateDeviceKey, signDetached, verifyDetached } from '../../src/security/index.js';

describe('Ed25519 device keys', () => {
  it('signs and verifies', () => {
    const k = generateDeviceKey();
    const data = Buffer.from('keysentry-audit-checkpoint:v1:50:abc');
    const sig = signDetached(k.privateKeyDer, data);
    expect(sig.length).toBe(64);
    expect(verifyDetached(k.publicKeyDer, data, sig)).toBe(true);
  });

  it('rejects a flipped bit in the data or the signature', () => {
    const k = generateDeviceKey();
    const data = Buffer.from('hello');
    const sig = signDetached(k.privateKeyDer, data);
    const badData = Buffer.from(data);
    badData[0] ^= 1;
    const badSig = Buffer.from(sig);
    badSig[10] ^= 1;
    expect(verifyDetached(k.publicKeyDer, badData, sig)).toBe(false);
    expect(verifyDetached(k.publicKeyDer, data, badSig)).toBe(false);
  });

  it('rejects another key and malformed input without throwing', () => {
    const a = generateDeviceKey();
    const b = generateDeviceKey();
    const data = Buffer.from('x');
    const sig = signDetached(a.privateKeyDer, data);
    expect(verifyDetached(b.publicKeyDer, data, sig)).toBe(false);
    expect(verifyDetached(Buffer.from('not a key'), data, sig)).toBe(false);
    expect(verifyDetached(a.publicKeyDer, data, Buffer.alloc(3))).toBe(false);
  });

  it('derives the same public key and keyId from the private DER', () => {
    const k = generateDeviceKey();
    const again = deviceKeyFromPrivate(k.privateKeyDer);
    expect(again.publicKeyDer.equals(k.publicKeyDer)).toBe(true);
    expect(again.keyId).toBe(k.keyId);
    expect(k.keyId).toBe(createHash('sha256').update(k.publicKeyDer).digest('hex').slice(0, 16));
  });
});
