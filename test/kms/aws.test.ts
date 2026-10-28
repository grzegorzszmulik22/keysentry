import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createAwsKmsWrapper, KmsError } from '../../src/kms/index.js';
import { FakeHttp, json } from '../helpers/fake-http.js';
import { credentialSource, failure, fakeAwsKms, now, secretFree } from './fakes.js';

const KEY_ARN = 'arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab';
const settings = { provider: 'aws-kms', keyId: KEY_ARN, region: 'us-east-1' } as const;
const CONTEXT = 'keysentry-state:v1:0123456789abcdef';
const SECRETS = ['AKIAEXAMPLEPLANTED01', 'aws-secret-planted-value', 'session-token-planted'];
const credentials = () => credentialSource({ AWS_ACCESS_KEY_ID: SECRETS[0]!, AWS_SECRET_ACCESS_KEY: SECRETS[1]!, AWS_SESSION_TOKEN: SECRETS[2]! });

describe('AWS KMS key wrapper', () => {
  it('wraps with a SigV4-signed TrentService.Encrypt that binds the encryption context', async () => {
    const fake = fakeAwsKms();
    const wrapper = createAwsKmsWrapper(settings, { http: fake.http, credentials: credentials(), now });
    expect(wrapper.provider).toBe('aws-kms');
    expect(wrapper.keyRef).toBe(KEY_ARN);
    const dataKey = randomBytes(32);
    const wrapped = await wrapper.wrap(dataKey, CONTEXT);
    expect(fake.http.calls).toHaveLength(1);
    const call = fake.http.calls[0]!;
    expect(call.method).toBe('POST');
    expect(call.url).toBe('https://kms.us-east-1.amazonaws.com/');
    expect(call.headers).toMatchObject({
      'content-type': 'application/x-amz-json-1.1', 'x-amz-target': 'TrentService.Encrypt', host: 'kms.us-east-1.amazonaws.com',
      'x-amz-date': '20261028T120000Z', 'x-amz-security-token': SECRETS[2],
    });
    expect(call.headers!.authorization).toMatch(new RegExp('^AWS4-HMAC-SHA256 Credential=AKIAEXAMPLEPLANTED01/20261028/us-east-1/kms/aws4_request, '
      + 'SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=[0-9a-f]{64}$'));
    expect(JSON.parse(call.body!)).toEqual({ KeyId: KEY_ARN, Plaintext: dataKey.toString('base64'), EncryptionContext: { keysentry: CONTEXT } });
    // The opaque bytes never contain the data key.
    expect(wrapped.includes(dataKey)).toBe(false);
    expect(wrapped.toString()).not.toContain(dataKey.toString('base64'));

    const unwrapped = await wrapper.unwrap(wrapped, CONTEXT);
    expect(unwrapped.equals(dataKey)).toBe(true);
    const decrypt = fake.http.calls[1]!;
    expect(decrypt.headers!['x-amz-target']).toBe('TrentService.Decrypt');
    const decryptBody = JSON.parse(decrypt.body!);
    expect(Object.keys(decryptBody).sort()).toEqual(['CiphertextBlob', 'EncryptionContext', 'KeyId']);
    expect(decryptBody.KeyId).toBe(KEY_ARN);
    expect(decryptBody.EncryptionContext).toEqual({ keysentry: CONTEXT });
  });

  it('uses write-role credentials to wrap and read-role credentials to unwrap', async () => {
    const fake = fakeAwsKms();
    const source = credentialSource({ 'AWS_ACCESS_KEY_ID@write': 'AKIAWRITEPLANTED0001', 'AWS_SECRET_ACCESS_KEY@write': 'write-secret',
      'AWS_ACCESS_KEY_ID@read': 'AKIAREADPLANTED00001', 'AWS_SECRET_ACCESS_KEY@read': 'read-secret' });
    const wrapper = createAwsKmsWrapper(settings, { http: fake.http, credentials: source, now });
    const wrapped = await wrapper.wrap(randomBytes(32), CONTEXT);
    await wrapper.unwrap(wrapped, CONTEXT);
    expect(fake.http.calls[0]!.headers!.authorization).toContain('Credential=AKIAWRITEPLANTED0001/');
    expect(fake.http.calls[1]!.headers!.authorization).toContain('Credential=AKIAREADPLANTED00001/');
    expect(source.lookups.filter(item => item.name === 'AWS_ACCESS_KEY_ID').map(item => item.role)).toEqual(['write', 'read']);
  });

  it('refuses a different context, a tampered ciphertext and a damaged envelope', async () => {
    const fake = fakeAwsKms();
    const wrapper = createAwsKmsWrapper(settings, { http: fake.http, credentials: credentials(), now });
    const wrapped = await wrapper.wrap(randomBytes(32), CONTEXT);
    const wrongContext = await failure(wrapper.unwrap(wrapped, 'keysentry-state:v1:fedcba9876543210'));
    expect(wrongContext).toBeInstanceOf(KmsError);
    expect(wrongContext.code).toBe('rejected');

    const envelope = JSON.parse(wrapped.toString());
    const blob = Buffer.from(envelope.ciphertext, 'base64'); blob[blob.length - 1]! ^= 1;
    const tampered = await failure(wrapper.unwrap(Buffer.from(JSON.stringify({ ...envelope, ciphertext: blob.toString('base64') })), CONTEXT));
    expect(tampered.code).toBe('rejected');

    const calls = fake.http.calls.length;
    expect((await failure(wrapper.unwrap(Buffer.from('{"v":1,"key":"x"}'), CONTEXT))).code).toBe('damaged');
    // A key ARN outside the configured key is refused before any request.
    const foreign = Buffer.from(JSON.stringify({ ...envelope, key: 'arn:aws:kms:us-east-1:999999999999:key/other' }));
    expect((await failure(wrapper.unwrap(foreign, CONTEXT))).code).toBe('rejected');
    expect(fake.http.calls.length).toBe(calls);
    for (const error of [wrongContext, tampered]) expect(secretFree(error, SECRETS)).toBe(true);
  });

  it('decrypts an alias-wrapped key with the key ARN AWS reported, and refuses a key from another account', async () => {
    const alias = { ...settings, keyId: 'arn:aws:kms:us-east-1:111122223333:alias/keysentry' };
    const fake = fakeAwsKms();
    const wrapper = createAwsKmsWrapper(alias, { http: fake.http, credentials: credentials(), now });
    expect(wrapper.keyRef).toBe(alias.keyId);
    const wrapped = await wrapper.wrap(randomBytes(32), CONTEXT);
    expect(JSON.parse(fake.http.calls[0]!.body!).KeyId).toBe(alias.keyId);
    await wrapper.unwrap(wrapped, CONTEXT);
    expect(JSON.parse(fake.http.calls[1]!.body!).KeyId).toBe(KEY_ARN);

    fake.state.keyArn = 'arn:aws:kms:us-east-1:999999999999:key/1234abcd-12ab-34cd-56ef-1234567890ab';
    expect((await failure(wrapper.wrap(randomBytes(32), CONTEXT))).code).toBe('invalid-response');
  });

  it('explains a disabled key, refused credentials, an outage and missing credentials without echoing anything', async () => {
    const fake = fakeAwsKms();
    const wrapper = createAwsKmsWrapper(settings, { http: fake.http, credentials: credentials(), now });
    const wrapped = await wrapper.wrap(randomBytes(32), CONTEXT);
    fake.state.disabled = true;
    const disabled = await failure(wrapper.unwrap(wrapped, CONTEXT));
    expect(disabled.code).toBe('key-unavailable');
    expect(disabled.message).toContain('missing, disabled or scheduled for deletion');
    fake.state.disabled = false; fake.state.down = true;
    const down = await failure(wrapper.unwrap(wrapped, CONTEXT));
    expect(down.code).toBe('unreachable');

    const denied = new FakeHttp().on('POST', /amazonaws/, () => json(400, { __type: 'AccessDeniedException', message: 'upstream-secret-detail' }));
    const deniedError = await failure(createAwsKmsWrapper(settings, { http: denied, credentials: credentials(), now }).wrap(randomBytes(32), CONTEXT));
    expect(deniedError.code).toBe('denied');
    const outage = new FakeHttp().on('POST', /amazonaws/, () => json(500, { __type: 'KMSInternalException' }));
    expect((await failure(createAwsKmsWrapper(settings, { http: outage, credentials: credentials(), now }).wrap(randomBytes(32), CONTEXT))).code).toBe('unavailable');

    const empty = new FakeHttp();
    const missing = await failure(createAwsKmsWrapper(settings, { http: empty, credentials: credentialSource({}), now }).wrap(randomBytes(32), CONTEXT));
    expect(missing.code).toBe('credentials');
    expect(missing.message).toContain('AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY');
    expect(empty.calls).toHaveLength(0);
    for (const error of [disabled, down, deniedError, missing]) expect(secretFree(error, SECRETS)).toBe(true);
  });

  it('refuses unsupported configuration before any request', () => {
    const deps = { http: new FakeHttp(), credentials: credentials(), now };
    expect(() => createAwsKmsWrapper({ ...settings, region: 'eu-west-1' }, deps)).toThrow(/different region/);
    expect(() => createAwsKmsWrapper({ ...settings, keyId: 'arn:aws-cn:kms:cn-north-1:111122223333:key/abc', region: 'cn-north-1' }, deps)).toThrow(/aws and aws-us-gov/);
  });
});
