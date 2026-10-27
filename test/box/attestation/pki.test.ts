import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { CONFIDENTIAL_SPACE_ROOT_SHA256, verifyCertificateChain } from '../../../src/box/attestation/pki.js';
import { createTokenFactory, TEST_NOW } from './helpers.js';

describe('Confidential Space PKI chain', () => {
  const factory = createTokenFactory();

  it('accepts a generated leaf to intermediate to pinned test root chain', () => {
    const key = verifyCertificateChain(factory.x5c, TEST_NOW, factory.root);
    expect(key.export({ format: 'jwk' }).n).toBe(factory.jwk.n);
  });

  it('pins the real Confidential Space root fixture by SHA-256', () => {
    const root = new X509Certificate(readFileSync(new URL('../../fixtures/box/confidential-space-root.crt', import.meta.url)));
    expect(createHash('sha256').update(root.raw).digest('hex')).toBe(CONFIDENTIAL_SPACE_ROOT_SHA256);
    expect(root.ca).toBe(true);
    expect(root.verify(root.publicKey)).toBe(true);
  });

  it('refuses a generated test root when no root override is supplied', () => {
    expect(() => verifyCertificateChain(factory.x5c, TEST_NOW)).toThrow();
  });

  it('refuses a foreign supplied root', () => {
    const foreign = createTokenFactory();
    expect(() => verifyCertificateChain(factory.x5c, TEST_NOW, foreign.root)).toThrow();
  });

  it.each([
    { label: 'null', x5c: null },
    { label: 'empty chain', x5c: [] },
    { label: 'two certificates', x5c: factory.x5c.slice(0, 2) },
    { label: 'four certificates', x5c: [...factory.x5c, factory.x5c[0]] },
    { label: 'invalid DER', x5c: ['not a certificate', ...factory.x5c.slice(1)] },
    { label: 'newline in base64', x5c: [factory.x5c[0] + '\n', ...factory.x5c.slice(1)] },
    { label: 'truncated base64', x5c: [factory.x5c[0]!.slice(0, -1), ...factory.x5c.slice(1)] },
  ])('refuses malformed certificate chains: $label', ({ x5c }) => {
    expect(() => verifyCertificateChain(x5c, TEST_NOW, factory.root)).toThrow();
  });

  it('refuses a three-certificate chain with the intermediate and root reordered', () => {
    const reordered = [factory.x5c[0], factory.x5c[2], factory.x5c[1]];
    expect(reordered).toHaveLength(3);
    expect(() => verifyCertificateChain(reordered, TEST_NOW, factory.root)).toThrow();
  });

  it('refuses a certificate outside its validity interval', () => {
    expect(() => verifyCertificateChain(factory.x5c, new Date('2031-01-01T00:00:00Z'), factory.root)).toThrow();
    expect(() => verifyCertificateChain(factory.x5c, new Date('2024-01-01T00:00:00Z'), factory.root)).toThrow();
    expect(() => verifyCertificateChain(factory.x5c, new Date(NaN), factory.root)).toThrow();
  });

  it.each([
    { leafRawValidFrom: '269927120000Z' },
    { leafRawValidTo: '269927120000Z' },
  ])('refuses a signed certificate whose ASN.1 validity cannot be parsed %#', options => {
    const invalid = createTokenFactory(options);
    const leaf = new X509Certificate(Buffer.from(invalid.x5c[0]!, 'base64'));
    const intermediate = new X509Certificate(Buffer.from(invalid.x5c[1]!, 'base64'));
    expect(leaf.verify(intermediate.publicKey)).toBe(true);
    const parsed = Date.parse(options.leafRawValidFrom ? leaf.validFrom : leaf.validTo);
    expect(Number.isNaN(parsed)).toBe(true);
    expect(() => verifyCertificateChain(invalid.x5c, TEST_NOW, invalid.root)).toThrow();
  });

  it.each([
    { rootValidTo: new Date('2026-10-26T00:00:00Z') },
    { rootValidFrom: new Date('2026-10-28T00:00:00Z') },
    { intermediateValidTo: new Date('2026-10-26T00:00:00Z') },
    { intermediateValidFrom: new Date('2026-10-28T00:00:00Z') },
  ])('checks every certificate validity interval %#', options => {
    const invalid = createTokenFactory(options);
    expect(() => verifyCertificateChain(invalid.x5c, TEST_NOW, invalid.root)).toThrow();
  });

  it('refuses bytes appended to a DER certificate', () => {
    const appended = Buffer.concat([Buffer.from(factory.x5c[0]!, 'base64'), Buffer.from([0])]).toString('base64');
    expect(() => verifyCertificateChain([appended, ...factory.x5c.slice(1)], TEST_NOW, factory.root)).toThrow();
  });

  it('refuses an intermediate that is not a CA', () => {
    const invalid = createTokenFactory({ intermediateCa: false });
    expect(() => verifyCertificateChain(invalid.x5c, TEST_NOW, invalid.root)).toThrow();
  });

  it('refuses a root that is not a CA', () => {
    const invalid = createTokenFactory({ rootCa: false });
    expect(() => verifyCertificateChain(invalid.x5c, TEST_NOW, invalid.root)).toThrow();
  });

  it('refuses a chain with a forged intermediate signature', () => {
    const invalid = createTokenFactory({ brokenIntermediateSignature: true });
    expect(() => verifyCertificateChain(invalid.x5c, TEST_NOW, invalid.root)).toThrow();
  });

  it('refuses a chain with a forged leaf signature', () => {
    const invalid = createTokenFactory({ brokenLeafSignature: true });
    expect(() => verifyCertificateChain(invalid.x5c, TEST_NOW, invalid.root)).toThrow();
  });

  it('refuses a root whose self signature cannot be verified', () => {
    const invalid = createTokenFactory({ brokenRootSignature: true });
    expect(() => verifyCertificateChain(invalid.x5c, TEST_NOW, invalid.root)).toThrow();
  });

  it('refuses an RSA leaf smaller than 2048 bits', () => {
    const invalid = createTokenFactory({ leafModulusLength: 1024 });
    expect(() => verifyCertificateChain(invalid.x5c, TEST_NOW, invalid.root)).toThrow();
  });

  it('refuses an RSA leaf whose exponent is not 65537', () => {
    const invalid = createTokenFactory({ leafExponent: 3 });
    expect(() => verifyCertificateChain(invalid.x5c, TEST_NOW, invalid.root)).toThrow();
  });
});
