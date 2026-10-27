import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { FakeHttp, json, text } from '../../helpers/fake-http.js';
import { CONFIDENTIAL_SPACE_JWKS_URL, createJwksFetcher, jwkPublicKey, parseJwks } from '../../../src/box/attestation/jwks.js';

const publicKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey;
const key = { ...publicKey.export({ format: 'jwk' }), kid: 'test-key', alg: 'RS256', use: 'sig' };

function fixture() {
  return JSON.parse(readFileSync(new URL('../../fixtures/box/google-jwks-2026-10-27.json', import.meta.url), 'utf8'));
}

describe('attestation JWK validation', () => {
  it('imports the recorded real Google keys as RSA-2048 with exponent 65537', () => {
    const keys = parseJwks(fixture());
    expect(keys).toHaveLength(2);
    for (const jwk of keys) {
      const imported = jwkPublicKey(jwk);
      expect(imported.asymmetricKeyType).toBe('rsa');
      expect(imported.asymmetricKeyDetails).toMatchObject({ modulusLength: 2048, publicExponent: 65537n });
    }
  });

  it.each([
    ['wrong key type', { ...key, kty: 'EC' }],
    ['wrong signing algorithm', { ...key, alg: 'HS256' }],
    ['wrong key use', { ...key, use: 'enc' }],
    ['wrong key operations', { ...key, key_ops: ['sign'] }],
    ['wrong exponent', { ...key, e: 'Aw' }],
    ['padded modulus', { ...key, n: `${key.n}=` }],
    ['invalid modulus alphabet', { ...key, n: `${key.n}+` }],
    ['private key material', { ...key, d: 'private-data' }],
    ['missing modulus', { ...key, n: undefined }],
    ['empty modulus', { ...key, n: '' }],
    ['small RSA key', { ...generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ format: 'jwk' }), kid: 'small' }],
  ])('refuses %s', (_name, jwk) => {
    expect(() => jwkPublicKey(jwk)).toThrow('Attestation signing key is invalid.');
  });

  it.each([null, [], {}, { keys: null }, { keys: [] }, { keys: [null] }, { keys: [{ ...key, kid: '' }] }, { keys: [key, key] }].map((value) => ({ value })))('refuses malformed or ambiguous key sets %#', ({ value }) => {
    expect(() => parseJwks(value)).toThrow('Attestation key set is invalid.');
  });
});

describe('attestation JWKS cache', () => {
  it('fetches only through the injected client and caches max-age until its exact expiry', async () => {
    let now = new Date('2026-10-27T12:00:00Z');
    const http = new FakeHttp().on('GET', /^https:\/\/www\.googleapis\.com\//, () => json(200, { keys: [key] }, { 'Cache-Control': 'public, max-age=60, must-revalidate' }));
    const fetchKeys = createJwksFetcher(http, { now: () => now });
    expect((await fetchKeys())[0]?.kid).toBe('test-key');
    now = new Date(now.getTime() + 59_999);
    await fetchKeys();
    expect(http.calls).toHaveLength(1);
    expect(http.calls[0]).toEqual({ method: 'GET', url: CONFIDENTIAL_SPACE_JWKS_URL });
    now = new Date(now.getTime() + 1);
    await fetchKeys();
    expect(http.calls).toHaveLength(2);
  });

  it('caps server max-age at 24 hours', async () => {
    let milliseconds = 0;
    const http = new FakeHttp().on('GET', /.*/, () => json(200, { keys: [key] }, { 'cache-control': 'max-age=999999999' }));
    const fetchKeys = createJwksFetcher(http, { now: () => new Date(milliseconds) });
    await fetchKeys();
    milliseconds = 86_399_999;
    await fetchKeys();
    expect(http.calls).toHaveLength(1);
    milliseconds = 86_400_000;
    await fetchKeys();
    expect(http.calls).toHaveLength(2);
  });

  it.each(['', 'max-age=invalid', 'max-age=-10', 'max-age=10.5', 'no-store, max-age=300', 'no-cache, max-age=300', 'max-age=30, max-age=600'])('does not cache absent, invalid or restricted policy %s', async (cacheControl) => {
    const http = new FakeHttp().on('GET', /.*/, () => json(200, { keys: [key] }, { 'cache-control': cacheControl }));
    const fetchKeys = createJwksFetcher(http);
    await fetchKeys();
    await fetchKeys();
    expect(http.calls).toHaveLength(2);
  });

  it('subtracts the response Age from max-age', async () => {
    let milliseconds = 0;
    const http = new FakeHttp().on('GET', /.*/, () => json(200, { keys: [key] }, { 'cache-control': 'max-age=60', age: '59' }));
    const fetchKeys = createJwksFetcher(http, { now: () => new Date(milliseconds) });
    await fetchKeys();
    milliseconds = 999;
    await fetchKeys();
    expect(http.calls).toHaveLength(1);
    milliseconds = 1000;
    await fetchKeys();
    expect(http.calls).toHaveLength(2);
  });

  it('force-refreshes a still-cached key set for unknown-kid rotation', async () => {
    let requests = 0;
    const http = new FakeHttp().on('GET', /.*/, () => json(200, { keys: [{ ...key, kid: ++requests === 1 ? 'old-key' : 'new-key' }] }, { 'cache-control': 'max-age=3600' }));
    const fetchKeys = createJwksFetcher(http);
    expect((await fetchKeys())[0]?.kid).toBe('old-key');
    expect((await fetchKeys(true))[0]?.kid).toBe('new-key');
    expect((await fetchKeys())[0]?.kid).toBe('new-key');
    expect(http.calls).toHaveLength(2);
  });

  it('does not let callers change the cached public keys', async () => {
    const http = new FakeHttp().on('GET', /.*/, () => json(200, { keys: [key] }, { 'cache-control': 'max-age=3600' }));
    const fetchKeys = createJwksFetcher(http);
    (await fetchKeys())[0]!.kid = 'changed';
    expect((await fetchKeys())[0]?.kid).toBe('test-key');
  });

  it('coalesces concurrent initial fetches', async () => {
    const http = new FakeHttp().on('GET', /.*/, async () => json(200, { keys: [key] }, { 'cache-control': 'max-age=3600' }));
    const fetchKeys = createJwksFetcher(http);
    await Promise.all([fetchKeys(), fetchKeys()]);
    expect(http.calls).toHaveLength(1);
  });

  it.each([
    () => json(503, { error: 'do not echo remote body' }),
    () => text(200, 'do not echo invalid JSON'),
    () => json(200, { keys: [{ ...key, e: 'Aw' }] }),
  ])('reports HTTP, JSON or invalid-key failures without response content %#', async (response) => {
    const http = new FakeHttp().on('GET', /.*/, response);
    await expect(createJwksFetcher(http)()).rejects.toThrow('Attestation signing keys could not be fetched.');
  });

  it('never returns expired keys after a fetch failure', async () => {
    let requests = 0;
    let milliseconds = 0;
    const http = new FakeHttp().on('GET', /.*/, () => ++requests === 1 ? json(200, { keys: [key] }, { 'cache-control': 'max-age=1' }) : json(503, {}));
    const fetchKeys = createJwksFetcher(http, { now: () => new Date(milliseconds) });
    await fetchKeys();
    milliseconds = 1000;
    await expect(fetchKeys()).rejects.toThrow('Attestation signing keys could not be fetched.');
    await expect(fetchKeys()).rejects.toThrow('Attestation signing keys could not be fetched.');
    expect(http.calls).toHaveLength(3);
  });
});
