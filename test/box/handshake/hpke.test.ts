import { createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DecryptError } from '../../../src/security/index.js';
import { generateBoxKeyPair, openAsBox, sealToBox } from '../../../src/box/handshake/hpke.js';

vi.mock('node:crypto', async (importOriginal) => {
  const original = await importOriginal<typeof import('node:crypto')>();
  return { ...original, generateKeyPairSync: vi.fn(original.generateKeyPairSync) };
});

afterEach(() => vi.mocked(generateKeyPairSync).mockClear());

const plaintext = Buffer.from('keysentry test bundle', 'utf8');
const info = 'session-128-bits|attested-box-hash';

describe('box hybrid encryption', () => {
  it('round-trips with a raw public key and uses the specified versioned wire format', () => {
    const box = generateBoxKeyPair();
    const sealed = sealToBox(box.publicKeyRaw, plaintext, info);
    expect(box.publicKeyRaw.length).toBe(32);
    expect(sealed.subarray(0, 5)).toEqual(Buffer.from('4b53423101', 'hex'));
    expect(sealed.length).toBe(53 + plaintext.length);
    expect(openAsBox(box.privateKey, sealed, info)).toEqual(plaintext);
    expect(sealed.includes(plaintext)).toBe(false);
  });

  it('accepts PKCS8 DER private keys and empty plaintext', () => {
    const box = generateBoxKeyPair();
    const privateDer = box.privateKey.export({ type: 'pkcs8', format: 'der' });
    const sealed = sealToBox(box.publicKeyRaw, Buffer.alloc(0), info);
    expect(sealed.length).toBe(53);
    expect(openAsBox(privateDer, sealed, info)).toEqual(Buffer.alloc(0));
  });

  it('generates a fresh ephemeral public key for each message', () => {
    const box = generateBoxKeyPair();
    const first = sealToBox(box.publicKeyRaw, plaintext, info);
    const second = sealToBox(box.publicKeyRaw, plaintext, info);
    expect(first.subarray(5, 37)).not.toEqual(second.subarray(5, 37));
    expect(openAsBox(box.privateKey, second, info)).toEqual(plaintext);
  });

  it('rejects a change to every individual byte of a sealed bundle', () => {
    const box = generateBoxKeyPair();
    const sealed = sealToBox(box.publicKeyRaw, plaintext, info);
    for (let index = 0; index < sealed.length; index += 1) {
      const tampered = Buffer.from(sealed);
      tampered[index] = tampered[index]! ^ 1;
      expect(() => openAsBox(box.privateKey, tampered, info), `wire byte ${index}`).toThrow(DecryptError);
    }
  });

  it('rejects a different recipient or session binding without reflecting secrets', () => {
    const box = generateBoxKeyPair();
    const otherBox = generateBoxKeyPair();
    const sealed = sealToBox(box.publicKeyRaw, plaintext, info);
    for (const attempt of [
      () => openAsBox(otherBox.privateKey, sealed, info),
      () => openAsBox(box.privateKey, sealed, info + '-changed'),
    ]) {
      let error: unknown;
      try { attempt(); } catch (caught) { error = caught; }
      expect(error).toBeInstanceOf(DecryptError);
      expect(String(error)).not.toContain(plaintext.toString());
      expect(String(error)).not.toContain(box.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex'));
    }
  });

  it('rejects truncated, extended and malformed bundles', () => {
    const box = generateBoxKeyPair();
    const sealed = sealToBox(box.publicKeyRaw, plaintext, info);
    for (const bad of [Buffer.alloc(0), sealed.subarray(0, 52), sealed.subarray(0, -1), Buffer.concat([sealed, Buffer.of(0)])]) {
      expect(() => openAsBox(box.privateKey, bad, info)).toThrow(DecryptError);
    }
    expect(() => openAsBox(box.privateKey, 'invalid' as unknown as Buffer, info)).toThrow(DecryptError);
  });

  it.each([Buffer.alloc(32), Buffer.concat([Buffer.of(1), Buffer.alloc(31)])])('refuses low-order X25519 peer keys', (peer) => {
    expect(() => sealToBox(peer, plaintext, info)).toThrow();
    const box = generateBoxKeyPair();
    const sealed = sealToBox(box.publicKeyRaw, plaintext, info);
    peer.copy(sealed, 5);
    expect(() => openAsBox(box.privateKey, sealed, info)).toThrow(DecryptError);
  });

  it('validates public keys, plaintext and info before encrypting', () => {
    const box = generateBoxKeyPair();
    for (const key of [Buffer.alloc(0), Buffer.alloc(31), Buffer.alloc(33), 'invalid' as unknown as Buffer]) {
      expect(() => sealToBox(key, plaintext, info)).toThrow(TypeError);
    }
    expect(() => sealToBox(box.publicKeyRaw, 'invalid' as unknown as Buffer, info)).toThrow(TypeError);
    expect(() => sealToBox(box.publicKeyRaw, plaintext, undefined as unknown as string)).toThrow(TypeError);
  });

  it('refuses invalid, public-only or non-X25519 private keys', () => {
    const box = generateBoxKeyPair();
    const sealed = sealToBox(box.publicKeyRaw, plaintext, info);
    const ed = generateKeyPairSync('ed25519');
    for (const key of [Buffer.from('invalid'), ed.privateKey, createPublicKey(box.privateKey)]) {
      expect(() => openAsBox(key, sealed, info)).toThrow(DecryptError);
    }
    expect(() => openAsBox(box.privateKey, sealed, undefined as unknown as string)).toThrow(DecryptError);
  });

  it('matches the fixed X25519/HKDF/AES-GCM known-answer vector in both directions', () => {
    // Generated once on 2026-10-27 using RFC 7748 section 6.1 Alice (ephemeral)
    // and Bob (box) private keys with a standalone Node crypto calculation.
    // Checked independently: reverse ECDH, HMAC Extract/Expand versus hkdfSync,
    // and AES-GCM decryption. The literal expected bytes do not use our code.
    // info='vector-session|box-key-hash'; plaintext='keysentry test bundle'.
    const pkcs8Prefix = '302e020100300506032b656e04220420';
    const ephemeralPrivate = createPrivateKey({ format: 'der', type: 'pkcs8', key: Buffer.from(pkcs8Prefix +
      '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex') });
    const boxPrivate = createPrivateKey({ format: 'der', type: 'pkcs8', key: Buffer.from(pkcs8Prefix +
      '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb', 'hex') });
    const boxPublicRaw = Buffer.from('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f', 'hex');
    const expected = Buffer.from(
      '4b534231018520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a' +
      '382785a8aadeaf7841264262ab47274a555bc9b41a460f67a3335d09fe38eb7934701034b0', 'hex');
    vi.mocked(generateKeyPairSync).mockReturnValueOnce({ privateKey: ephemeralPrivate, publicKey: createPublicKey(ephemeralPrivate) });
    expect(sealToBox(boxPublicRaw, plaintext, 'vector-session|box-key-hash')).toEqual(expected);
    expect(openAsBox(boxPrivate, expected, 'vector-session|box-key-hash')).toEqual(plaintext);
  });
});
