import { createPublicKey, sign, verify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verifyCertificateChain } from '../../../src/box/attestation/pki.js';
import { createEmulatorPki } from '../src/emulator/pki.js';

describe('emulator PKI', () => {
  it.each(['2026-10-27T12:00:00Z', '2056-10-27T12:00:00Z'])('generates a complete local trust path valid at %s', date => {
    const now = new Date(date);
    const pki = createEmulatorPki(now);
    const key = verifyCertificateChain(pki.chain, now, pki.root);
    const payload = Buffer.from('emulator attestation payload');
    const signature = sign('RSA-SHA256', payload, pki.privateKey);
    expect(verify('RSA-SHA256', payload, key, signature)).toBe(true);
    expect(verify('RSA-SHA256', payload, createPublicKey({ key: pki.jwks[0]!, format: 'jwk' }), signature)).toBe(true);
    expect(pki.jwks[0]?.kid).toBe(pki.kid);
    expect(pki.chain).toHaveLength(3);
  });

  it('rejects an invalid clock before generating a certificate', () => {
    expect(() => createEmulatorPki(new Date(NaN))).toThrow('Invalid emulator clock.');
  });
});
