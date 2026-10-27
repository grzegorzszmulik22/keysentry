import { describe, expect, it } from 'vitest';
import { FakeHttp, json } from '../../helpers/fake-http.js';
import { crc32c, exchangeForAccessToken, kmsDecrypt, kmsEncrypt } from '../../../src/box/seal/index.js';

const audience = '//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/box/providers/attestation';
const keyName = 'projects/keysentry/locations/global/keyRings/box/cryptoKeys/tokens';

describe('CRC32C Castagnoli', () => {
  it.each([
    ['empty', Buffer.alloc(0), 0],
    ['standard check', Buffer.from('123456789'), 0xe3069283],
    ['RFC 3720 zero bytes', Buffer.alloc(32), 0x8a9136aa],
    ['RFC 3720 ones', Buffer.alloc(32, 0xff), 0x62a8ab43],
    ['RFC 3720 incrementing', Buffer.from(Array.from({ length: 32 }, (_, i) => i)), 0x46dd794e],
    ['RFC 3720 decrementing', Buffer.from(Array.from({ length: 32 }, (_, i) => 31 - i)), 0x113fdb5c],
  ])('%s', (_name, bytes, expected) => {
    expect(crc32c(bytes)).toBe(expected);
  });
});

describe('STS exchange', () => {
  it('sends the documented JSON exchange without Authorization', async () => {
    const http = new FakeHttp().on('POST', /^https:\/\/sts\.googleapis\.com\/v1\/token$/, (req) => {
      expect(req.headers).toEqual({ 'Content-Type': 'application/json' });
      expect(JSON.parse(req.body!)).toEqual({
        grantType: 'urn:ietf:params:oauth:grant-type:token-exchange', audience,
        scope: 'https://www.googleapis.com/auth/cloud-platform',
        requestedTokenType: 'urn:ietf:params:oauth:token-type:access_token',
        subjectToken: 'subject.jwt.token', subjectTokenType: 'urn:ietf:params:oauth:token-type:jwt',
      });
      return json(200, { access_token: 'access-token', token_type: 'Bearer', expires_in: 3600 });
    });
    expect(await exchangeForAccessToken(http, { audience, subjectToken: 'subject.jwt.token' })).toBe('access-token');
  });

  it.each([
    { access_token: 'access-token', token_type: 'Basic', expires_in: 3600 },
    { access_token: 'access\r\nInjected: yes', token_type: 'Bearer', expires_in: 3600 },
    { access_token: 'access-token', token_type: 'Bearer', expires_in: 0 },
    { access_token: 'a'.repeat(12 * 1024 + 1), token_type: 'Bearer', expires_in: 3600 },
  ])('rejects invalid STS success response %#', async (response) => {
    const http = new FakeHttp().on('POST', /.*/, () => json(200, response));
    await expect(exchangeForAccessToken(http, { audience, subjectToken: 'subject.jwt.token' })).rejects.toThrow(/STS.*response/i);
  });

  it('does not expose an upstream failure body or thrown request error', async () => {
    const http = new FakeHttp().on('POST', /.*/, () => json(403, { error: 'planted-private-subject' }));
    const rejected = exchangeForAccessToken(http, { audience, subjectToken: 'subject.jwt.token' });
    await expect(rejected).rejects.toThrow(/attestation.*policy/i);
    await expect(rejected).rejects.not.toThrow('planted-private-subject');
    const thrown = exchangeForAccessToken({ request: async () => { throw new Error('planted-private-subject'); } }, { audience, subjectToken: 'subject.jwt.token' });
    await expect(thrown).rejects.not.toThrow('planted-private-subject');
  });
});

describe('KMS REST integrity', () => {
  const data = Buffer.from('123456789');
  const aad = Buffer.from('123456789');
  const cipher = Buffer.from('123456789');

  it('encrypts with base64 fields, both request checksums, and verified response checksums', async () => {
    const http = new FakeHttp().on('POST', /:encrypt$/, (req) => {
      expect(req.url).toBe(`https://cloudkms.googleapis.com/v1/${keyName}:encrypt`);
      expect(req.headers?.Authorization).toBe('Bearer access-token');
      expect(JSON.parse(req.body!)).toEqual({ plaintext: 'MTIzNDU2Nzg5', additionalAuthenticatedData: 'MTIzNDU2Nzg5',
        plaintextCrc32c: '3808858755', additionalAuthenticatedDataCrc32c: '3808858755' });
      return json(200, { ciphertext: cipher.toString('base64'), ciphertextCrc32c: '3808858755',
        verifiedPlaintextCrc32c: true, verifiedAdditionalAuthenticatedDataCrc32c: true });
    });
    expect((await kmsEncrypt(http, 'access-token', keyName, data, aad)).equals(cipher)).toBe(true);
  });

  it('decrypts with base64 ciphertext/AAD and checks plaintext CRC32C', async () => {
    const http = new FakeHttp().on('POST', /:decrypt$/, (req) => {
      expect(req.url).toBe(`https://cloudkms.googleapis.com/v1/${keyName}:decrypt`);
      expect(JSON.parse(req.body!)).toEqual({ ciphertext: 'MTIzNDU2Nzg5', additionalAuthenticatedData: 'MTIzNDU2Nzg5',
        ciphertextCrc32c: '3808858755', additionalAuthenticatedDataCrc32c: '3808858755' });
      return json(200, { plaintext: 'MTIzNDU2Nzg5', plaintextCrc32c: '3808858755', usedPrimary: true, protectionLevel: 'SOFTWARE' });
    });
    expect((await kmsDecrypt(http, 'access-token', keyName, cipher, aad)).equals(data)).toBe(true);
  });

  it.each([
    { ciphertextCrc32c: '0' }, { ciphertextCrc32c: undefined },
    { verifiedPlaintextCrc32c: false }, { verifiedAdditionalAuthenticatedDataCrc32c: false },
    { ciphertext: 'not base64' },
  ])('refuses encrypt integrity failure %#', async (patch) => {
    const http = new FakeHttp().on('POST', /.*/, () => json(200, { ciphertext: 'MTIzNDU2Nzg5', ciphertextCrc32c: '3808858755',
      verifiedPlaintextCrc32c: true, verifiedAdditionalAuthenticatedDataCrc32c: true, ...patch }));
    await expect(kmsEncrypt(http, 'access-token', keyName, data, aad)).rejects.toThrow(/KMS.*integrity/i);
  });

  it.each(['0', undefined, '-1', '4294967296', 'NaN'])('refuses decrypt CRC32C %s', async (checksum) => {
    const http = new FakeHttp().on('POST', /.*/, () => json(200, { plaintext: 'MTIzNDU2Nzg5', plaintextCrc32c: checksum }));
    await expect(kmsDecrypt(http, 'access-token', keyName, cipher, aad)).rejects.toThrow(/KMS.*integrity/i);
  });

  it('does not expose KMS error bodies or thrown errors', async () => {
    const http = new FakeHttp().on('POST', /.*/, () => json(403, { error: 'planted-private-key' }));
    const rejected = kmsDecrypt(http, 'access-token', keyName, cipher, aad);
    await expect(rejected).rejects.toThrow(/KMS.*policy/i);
    await expect(rejected).rejects.not.toThrow('planted-private-key');
    const thrown = kmsEncrypt({ request: async () => { throw new Error('planted-private-key'); } }, 'access-token', keyName, data, aad);
    await expect(thrown).rejects.not.toThrow('planted-private-key');
  });

  it('rejects a key name that could change the destination before HTTP', async () => {
    const http = new FakeHttp();
    await expect(kmsEncrypt(http, 'access-token', `${keyName}?secret=bad`, data, aad)).rejects.toThrow(/key name/i);
    expect(http.calls).toHaveLength(0);
  });
});
