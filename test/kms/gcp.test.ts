import { randomBytes, verify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { crc32c } from '../../src/box/seal/kms.js';
import { createGcpKmsWrapper } from '../../src/kms/index.js';
import { FakeHttp, json } from '../helpers/fake-http.js';
import { credentialSource, failure, fakeGcpKms, GCP_KEY, now, secretFree } from './fakes.js';

const settings = { provider: 'gcp-kms', keyName: GCP_KEY } as const;
const CONTEXT = 'keysentry-state:v1:0123456789abcdef';

describe('Google Cloud KMS key wrapper', () => {
  it('signs an RS256 JWT bearer grant and calls cryptoKeys.encrypt with the context as AAD and CRC32C fields', async () => {
    const fake = fakeGcpKms();
    const wrapper = createGcpKmsWrapper(settings, { http: fake.http, credentials: credentialSource({ GOOGLE_SERVICE_ACCOUNT_KEY: fake.serviceAccountJson }), now });
    expect(wrapper.keyRef).toBe(GCP_KEY);
    const dataKey = randomBytes(32);
    const wrapped = await wrapper.wrap(dataKey, CONTEXT);

    const [token, encrypt] = fake.http.calls;
    expect(token!.method).toBe('POST');
    expect(token!.url).toBe('https://oauth2.googleapis.com/token');
    expect(token!.headers).toEqual({ 'Content-Type': 'application/x-www-form-urlencoded' });
    const form = new URLSearchParams(token!.body);
    expect([...form.keys()]).toEqual(['grant_type', 'assertion']);
    expect(form.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:jwt-bearer');
    const [head, claims, signature] = form.get('assertion')!.split('.');
    expect(JSON.parse(Buffer.from(head!, 'base64url').toString())).toEqual({ alg: 'RS256', typ: 'JWT', kid: 'abc123def456' });
    const iat = Math.floor(now().getTime() / 1000);
    expect(JSON.parse(Buffer.from(claims!, 'base64url').toString())).toEqual({
      iss: 'keysentry@acme-prod-123.iam.gserviceaccount.com', scope: 'https://www.googleapis.com/auth/cloudkms',
      aud: 'https://oauth2.googleapis.com/token', iat, exp: iat + 3600,
    });
    expect(verify('sha256', Buffer.from(`${head}.${claims}`), fake.publicKey, Buffer.from(signature!, 'base64url'))).toBe(true);

    expect(encrypt!.url).toBe(`https://cloudkms.googleapis.com/v1/${GCP_KEY}:encrypt`);
    expect(encrypt!.headers).toEqual({ 'Content-Type': 'application/json', Authorization: 'Bearer ya29.issued-1' });
    const aad = Buffer.from(CONTEXT);
    expect(JSON.parse(encrypt!.body!)).toEqual({
      plaintext: dataKey.toString('base64'), additionalAuthenticatedData: aad.toString('base64'),
      plaintextCrc32c: String(crc32c(dataKey)), additionalAuthenticatedDataCrc32c: String(crc32c(aad)),
    });
    expect(JSON.parse(wrapped.toString()).version).toBe(`${GCP_KEY}/cryptoKeyVersions/1`);

    const unwrapped = await wrapper.unwrap(wrapped, CONTEXT);
    expect(unwrapped.equals(dataKey)).toBe(true);
    const decrypt = fake.http.calls.at(-1)!;
    expect(decrypt.url).toBe(`https://cloudkms.googleapis.com/v1/${GCP_KEY}:decrypt`);
    const body = JSON.parse(decrypt.body!);
    expect(Object.keys(body).sort()).toEqual(['additionalAuthenticatedData', 'additionalAuthenticatedDataCrc32c', 'ciphertext', 'ciphertextCrc32c']);
    expect(body.ciphertextCrc32c).toBe(String(crc32c(Buffer.from(body.ciphertext, 'base64'))));
  });

  it('caches the token per role and uses a supplied access token without a token request', async () => {
    const fake = fakeGcpKms();
    const wrapper = createGcpKmsWrapper(settings, { http: fake.http, credentials: credentialSource({ GOOGLE_SERVICE_ACCOUNT_KEY: Buffer.from(fake.serviceAccountJson).toString('base64') }), now });
    await wrapper.wrap(randomBytes(32), CONTEXT);
    await wrapper.wrap(randomBytes(32), CONTEXT);
    expect(fake.state.tokensIssued).toBe(1);

    const direct = fakeGcpKms();
    const viaToken = createGcpKmsWrapper(settings, { http: direct.http, credentials: credentialSource({ GOOGLE_OAUTH_ACCESS_TOKEN: 'direct-access-token-planted' }), now });
    const wrapped = await viaToken.wrap(randomBytes(32), CONTEXT);
    await viaToken.unwrap(wrapped, CONTEXT);
    expect(direct.http.callsTo('POST', /oauth2/)).toHaveLength(0);
    expect(direct.http.calls[0]!.headers!.Authorization).toBe('Bearer direct-access-token-planted');
  });

  it('refuses a wrong context, a tampered ciphertext, a disabled version and a bad checksum', async () => {
    const fake = fakeGcpKms();
    const SECRETS = ['direct-access-token-planted'];
    const wrapper = createGcpKmsWrapper(settings, { http: fake.http, credentials: credentialSource({ GOOGLE_OAUTH_ACCESS_TOKEN: SECRETS[0]! }), now });
    const wrapped = await wrapper.wrap(randomBytes(32), CONTEXT);
    const wrong = await failure(wrapper.unwrap(wrapped, 'keysentry-state:v1:fedcba9876543210'));
    expect(wrong.code).toBe('rejected');
    const envelope = JSON.parse(wrapped.toString());
    const blob = Buffer.from(envelope.ciphertext, 'base64'); blob[5]! ^= 0xff;
    const tampered = await failure(wrapper.unwrap(Buffer.from(JSON.stringify({ ...envelope, ciphertext: blob.toString('base64') })), CONTEXT));
    expect(tampered.code).toBe('rejected');
    fake.state.disabled = true;
    const disabled = await failure(wrapper.unwrap(wrapped, CONTEXT));
    expect(disabled.code).toBe('key-unavailable');
    for (const error of [wrong, tampered, disabled]) expect(secretFree(error, SECRETS)).toBe(true);

    const corrupt = new FakeHttp().on('POST', /:encrypt$/, () => json(200, { name: `${GCP_KEY}/cryptoKeyVersions/1`, ciphertext: 'AAAA',
      ciphertextCrc32c: '1', verifiedPlaintextCrc32c: true, verifiedAdditionalAuthenticatedDataCrc32c: true }));
    const corruptWrapper = createGcpKmsWrapper(settings, { http: corrupt, credentials: credentialSource({ GOOGLE_OAUTH_ACCESS_TOKEN: SECRETS[0]! }), now });
    expect((await failure(corruptWrapper.wrap(randomBytes(32), CONTEXT))).code).toBe('invalid-response');
    const unverified = new FakeHttp().on('POST', /:encrypt$/, () => json(200, { name: `${GCP_KEY}/cryptoKeyVersions/1`, ciphertext: 'AAAA',
      ciphertextCrc32c: String(crc32c(Buffer.from('AAAA', 'base64'))), verifiedPlaintextCrc32c: false, verifiedAdditionalAuthenticatedDataCrc32c: true }));
    expect((await failure(createGcpKmsWrapper(settings, { http: unverified, credentials: credentialSource({ GOOGLE_OAUTH_ACCESS_TOKEN: SECRETS[0]! }), now })
      .wrap(randomBytes(32), CONTEXT))).code).toBe('invalid-response');
  });

  it('refuses refused sign-ins, foreign token endpoints and missing credentials without echoing them', async () => {
    const fake = fakeGcpKms();
    fake.state.tokenStatus = 400;
    const refused = await failure(createGcpKmsWrapper(settings, { http: fake.http, credentials: credentialSource({ GOOGLE_SERVICE_ACCOUNT_KEY: fake.serviceAccountJson }), now })
      .wrap(randomBytes(32), CONTEXT));
    expect(refused.code).toBe('denied');
    const privateKey = JSON.parse(fake.serviceAccountJson).private_key as string;
    expect(secretFree(refused, [privateKey.slice(40, 80)])).toBe(true);

    const foreign = JSON.stringify({ ...JSON.parse(fake.serviceAccountJson), token_uri: 'https://evil.example/token' });
    const http = new FakeHttp();
    const foreignError = await failure(createGcpKmsWrapper(settings, { http, credentials: credentialSource({ GOOGLE_SERVICE_ACCOUNT_KEY: foreign }), now }).wrap(randomBytes(32), CONTEXT));
    expect(foreignError.code).toBe('credentials');
    expect(http.calls).toHaveLength(0);
    const missing = await failure(createGcpKmsWrapper(settings, { http, credentials: credentialSource({}), now }).wrap(randomBytes(32), CONTEXT));
    expect(missing.code).toBe('credentials');
    const garbage = await failure(createGcpKmsWrapper(settings, { http, credentials: credentialSource({ GOOGLE_SERVICE_ACCOUNT_KEY: '{"type":"service_account","private_key":"planted-not-a-key"}' }), now }).wrap(randomBytes(32), CONTEXT));
    expect(garbage.code).toBe('credentials');
    expect(secretFree(garbage, ['planted-not-a-key'])).toBe(true);
    expect(http.calls).toHaveLength(0);
  });
});
