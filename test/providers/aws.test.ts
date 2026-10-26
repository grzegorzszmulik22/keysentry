import { randomBytes } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { awsProvider } from '../../src/providers/aws.js';
import { signAwsRequest } from '../../src/providers/aws-sigv4.js';
import type { ProviderContext } from '../../src/types.js';
import { FakeHttp, silentLogger, text } from '../helpers/fake-http.js';

const now = new Date('2025-01-02T03:04:05Z');
const secret = () => randomBytes(30).toString('base64');
const accessId = () => `AKIA${randomBytes(8).toString('hex').toUpperCase()}`;
const context = (http: FakeHttp, siblingVars?: Record<string, string>): ProviderContext => ({
  http, siblingVars, credentials: {}, log: silentLogger,
});
async function expectAwsFailure(action: Promise<unknown>): Promise<void> {
  const error = await action.then(() => null, (failure: unknown) => failure);
  expect(error instanceof Error).toBe(true);
  expect(String(error).includes('AWS')).toBe(true);
}
const identityXml = '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
  + '<GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/test</Arn><UserId>AIDAEXAMPLE</UserId>'
  + '<Account>123456789012</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>request-id</RequestId>'
  + '</ResponseMetadata></GetCallerIdentityResponse>';

afterEach(() => vi.useRealTimers());

describe('AWS provider', () => {
  it('verifies through signed STS POST form in us-east-1, including the session token', async () => {
    vi.useFakeTimers().setSystemTime(now);
    const value = secret();
    const id = accessId();
    const token = randomBytes(48).toString('base64');
    const http = new FakeHttp().on('POST', /^https:\/\/sts\.amazonaws\.com\/$/, () => text(200, identityXml));

    const result = await awsProvider.verify(value, context(http, { AWS_ACCESS_KEY_ID: id, AWS_SESSION_TOKEN: token }));

    expect(result.ok).toBe(true);
    expect(result.status).toBe(200);
    expect(result.identity === 'arn:aws:iam::123456789012:user/test').toBe(true);
    expect(http.calls.length).toBe(1);
    const request = http.calls[0]!;
    expect(request.method).toBe('POST');
    expect(request.url).toBe('https://sts.amazonaws.com/');
    expect(request.body).toBe('Action=GetCallerIdentity&Version=2011-06-15');
    expect(request.headers?.['content-type']).toBe('application/x-www-form-urlencoded; charset=utf-8');
    expect(request.headers?.['x-amz-date']).toBe('20250102T030405Z');
    expect(request.headers?.['x-amz-security-token'] === token).toBe(true);
    expect(request.headers?.authorization?.includes(`Credential=${id}/20250102/us-east-1/sts/aws4_request`)).toBe(true);
    expect(request.headers?.authorization?.includes('SignedHeaders=content-type;host;x-amz-date;x-amz-security-token,')).toBe(true);
    expect(request.url.includes(value)).toBe(false);
  });

  it.each([401, 403])('returns failed verification for STS HTTP %i without upstream details', async (status) => {
    const value = secret();
    const http = new FakeHttp().on('POST', /^https:\/\/sts\.amazonaws\.com\/$/, () => text(status,
      `<ErrorResponse><Error><Code>InvalidClientTokenId</Code><Message>${value}</Message></Error></ErrorResponse>`));
    const result = await awsProvider.verify(value, context(http, { AWS_ACCESS_KEY_ID: accessId() }));
    expect(result.ok).toBe(false);
    expect(result.status).toBe(status);
    expect(JSON.stringify(result).includes(value)).toBe(false);
    expect(result.error).toBeTruthy();
  });

  it('fails verification without a sibling access ID before sending any request', async () => {
    const http = new FakeHttp();
    const result = await awsProvider.verify(secret(), context(http));
    expect(result.ok).toBe(false);
    expect(result.error).toBeTruthy();
    expect(http.calls.length).toBe(0);
  });

  it('sanitizes transport failures in verification', async () => {
    const value = secret();
    const http = new FakeHttp().on('POST', /^https:\/\/sts\.amazonaws\.com\/$/, () => { throw new Error(value); });
    const result = await awsProvider.verify(value, context(http, { AWS_ACCESS_KEY_ID: accessId() }));
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result).includes(value)).toBe(false);
    expect(result.error).toBeTruthy();
  });

  it.each(['<broken>', '<GetCallerIdentityResponse><GetCallerIdentityResult/></GetCallerIdentityResponse>'])('rejects malformed or incomplete identity XML', async (body) => {
    const http = new FakeHttp().on('POST', /^https:\/\/sts\.amazonaws\.com\/$/, () => text(200, body));
    const result = await awsProvider.verify(secret(), context(http, { AWS_ACCESS_KEY_ID: accessId() }));
    expect(result.ok).toBe(false);
    expect(result.error).toBeTruthy();
  });

  it('creates an IAM key with the old pair and preserves a suffixed companion name', async () => {
    vi.useFakeTimers().setSystemTime(now);
    const oldValue = secret();
    const oldId = accessId();
    const newValue = secret();
    const newId = accessId();
    const body = '<CreateAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
      + '<CreateAccessKeyResult><AccessKey><UserName>test</UserName>'
      + `<AccessKeyId>${newId}</AccessKeyId><Status>Active</Status><SecretAccessKey>${newValue}</SecretAccessKey>`
      + '<CreateDate>2025-01-02T03:04:05Z</CreateDate></AccessKey></CreateAccessKeyResult>'
      + '<ResponseMetadata><RequestId>request-id</RequestId></ResponseMetadata></CreateAccessKeyResponse>';
    const http = new FakeHttp().on('POST', /^https:\/\/iam\.amazonaws\.com\/$/, () => text(200, body));

    const result = await awsProvider.rotate!(oldValue, context(http, { DEPLOY_AWS_ACCESS_KEY_ID: oldId }));

    expect(result.newValue === newValue).toBe(true);
    expect(result.oldKeyRef === oldId).toBe(true);
    expect(result.newKeyRef === newId).toBe(true);
    expect(result.oldRevoked).toBe(false);
    expect(Object.keys(result.companions ?? {})).toEqual(['DEPLOY_AWS_ACCESS_KEY_ID']);
    expect(result.companions?.DEPLOY_AWS_ACCESS_KEY_ID === newId).toBe(true);
    expect(http.calls.length).toBe(1);
    const request = http.calls[0]!;
    expect(request.body).toBe('Action=CreateAccessKey&Version=2010-05-08');
    expect(new URLSearchParams(request.body).has('UserName')).toBe(false);
    expect(request.headers?.['x-amz-security-token'] === undefined).toBe(true);
    const expected = signAwsRequest({ method: 'POST', url: 'https://iam.amazonaws.com/',
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' }, body: request.body },
    { accessKeyId: oldId, secretAccessKey: oldValue }, { region: 'us-east-1', service: 'iam', now });
    expect(request.headers?.authorization === expected.headers?.authorization).toBe(true);
    expect(request.url.includes(oldValue)).toBe(false);
    expect(request.url.includes(newValue)).toBe(false);
  });

  it('refuses automatic rotation of a temporary pair before creating an unusable long-lived key', async () => {
    const http = new FakeHttp();
    const ctx = context(http, {
      DEPLOY_AWS_ACCESS_KEY_ID: accessId(), DEPLOY_AWS_SESSION_TOKEN: randomBytes(48).toString('base64'),
    });
    const error = await awsProvider.rotate!(secret(), ctx).then(() => null, (failure: unknown) => failure);
    expect(error instanceof Error).toBe(true);
    expect(http.calls.length).toBe(0);
  });

  it.each(['old', 'new', 'malformed'] as const)('rejects success XML with an unsafe %s access ID', async (kind) => {
    const oldValue = secret();
    const newValue = secret();
    const unsafeId = kind === 'old' ? oldValue : kind === 'new' ? newValue : 'not-an-aws-access-id';
    const http = new FakeHttp().on('POST', /^https:\/\/iam\.amazonaws\.com\/$/, () => text(200,
      `<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><AccessKeyId>${unsafeId}</AccessKeyId>`
      + `<SecretAccessKey>${newValue}</SecretAccessKey></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>`));
    const error = await awsProvider.rotate!(oldValue, context(http, { AWS_ACCESS_KEY_ID: accessId() }))
      .then(() => null, (failure: unknown) => failure);
    expect(error instanceof Error).toBe(true);
    expect(String(error).includes(oldValue)).toBe(false);
    expect(String(error).includes(newValue)).toBe(false);
  });

  it('refuses a secret stored in the access ID sibling before it can become an old key reference', async () => {
    const value = secret();
    const http = new FakeHttp();
    const error = await awsProvider.rotate!(value, context(http, { AWS_ACCESS_KEY_ID: value }))
      .then(() => null, (failure: unknown) => failure);
    expect(error instanceof Error).toBe(true);
    expect(String(error).includes(value)).toBe(false);
    expect(http.calls.length).toBe(0);
  });

  it('uses the canonical access ID companion when it is present', async () => {
    const oldId = accessId();
    const newId = accessId();
    const newValue = secret();
    const http = new FakeHttp().on('POST', /^https:\/\/iam\.amazonaws\.com\/$/, () => text(200,
      `<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><AccessKeyId>${newId}</AccessKeyId>`
      + `<SecretAccessKey>${newValue}</SecretAccessKey></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>`));
    const result = await awsProvider.rotate!(secret(), context(http, { OTHER_ACCESS_KEY_ID: accessId(), AWS_ACCESS_KEY_ID: oldId }));
    expect(result.oldKeyRef === oldId).toBe(true);
    expect(Object.keys(result.companions ?? {})).toEqual(['AWS_ACCESS_KEY_ID']);
  });

  it('revokes by form body signed only with the new sibling credentials', async () => {
    vi.useFakeTimers().setSystemTime(now);
    const oldId = accessId();
    const newId = accessId();
    const newValue = secret();
    const unusedOldValue = secret();
    const token = randomBytes(48).toString('base64');
    const http = new FakeHttp().on('POST', /^https:\/\/iam\.amazonaws\.com\/$/, () => text(200,
      '<DeleteAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ResponseMetadata>'
      + '<RequestId>request-id</RequestId></ResponseMetadata></DeleteAccessKeyResponse>'));
    const ctx = context(http, { CUSTOM_ACCESS_KEY_ID: newId, CUSTOM_SECRET_ACCESS_KEY: newValue, CUSTOM_SESSION_TOKEN: token });
    ctx.credentials.AWS_SECRET_ACCESS_KEY = unusedOldValue;

    await awsProvider.revoke!(oldId, ctx);

    expect(http.calls.length).toBe(1);
    const request = http.calls[0]!;
    const parameters = new URLSearchParams(request.body);
    expect(parameters.get('Action')).toBe('DeleteAccessKey');
    expect(parameters.get('Version')).toBe('2010-05-08');
    expect(parameters.get('AccessKeyId') === oldId).toBe(true);
    expect(parameters.has('UserName')).toBe(false);
    const expected = signAwsRequest({ method: 'POST', url: 'https://iam.amazonaws.com/',
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' }, body: request.body },
    { accessKeyId: newId, secretAccessKey: newValue, sessionToken: token }, { region: 'us-east-1', service: 'iam', now });
    expect(request.headers?.authorization === expected.headers?.authorization).toBe(true);
    expect(request.headers?.authorization?.includes(`Credential=${newId}/20250102/us-east-1/iam/aws4_request`)).toBe(true);
    expect(request.url.includes(oldId)).toBe(false);
    expect(request.url.includes(newValue)).toBe(false);
  });

  it('refuses revoke when the current sibling secret is missing, without using admin credentials', async () => {
    const http = new FakeHttp();
    const ctx = context(http, { AWS_ACCESS_KEY_ID: accessId() });
    ctx.credentials.AWS_SECRET_ACCESS_KEY = secret();
    await expectAwsFailure(awsProvider.revoke!(accessId(), ctx));
    expect(http.calls.length).toBe(0);
  });

  it('does not mix a suffixed access ID with a different sibling secret', async () => {
    const http = new FakeHttp();
    await expectAwsFailure(awsProvider.revoke!(accessId(), context(http, {
      ONE_ACCESS_KEY_ID: accessId(), TWO_SECRET_ACCESS_KEY: secret(),
    })));
    expect(http.calls.length).toBe(0);
  });

  it.each(['rotate', 'revoke'] as const)('sanitizes %s upstream errors', async (operation) => {
    const value = secret();
    const http = new FakeHttp().on('POST', /^https:\/\/iam\.amazonaws\.com\/$/, () => text(500,
      `<ErrorResponse><Error><Message>${value}</Message></Error></ErrorResponse>`));
    const ctx = context(http, { AWS_ACCESS_KEY_ID: accessId(), AWS_SECRET_ACCESS_KEY: value });
    const error = await (operation === 'rotate' ? awsProvider.rotate!(value, ctx) : awsProvider.revoke!(accessId(), ctx))
      .then(() => null, (failure: unknown) => failure);
    expect(error instanceof Error).toBe(true);
    expect(String(error).includes(value)).toBe(false);
    expect(String(error).includes('500')).toBe(true);
  });

  it.each(['rotate', 'revoke'] as const)('sanitizes %s transport exceptions', async (operation) => {
    const value = secret();
    const http = new FakeHttp().on('POST', /^https:\/\/iam\.amazonaws\.com\/$/, () => { throw new Error(value); });
    const ctx = context(http, { AWS_ACCESS_KEY_ID: accessId(), AWS_SECRET_ACCESS_KEY: value });
    const error = await (operation === 'rotate' ? awsProvider.rotate!(value, ctx) : awsProvider.revoke!(accessId(), ctx))
      .then(() => null, (failure: unknown) => failure);
    expect(error instanceof Error).toBe(true);
    expect(String(error).includes(value)).toBe(false);
  });

  it.each(['<broken>', '<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey/></CreateAccessKeyResult></CreateAccessKeyResponse>'])('rejects malformed or incomplete creation XML without leaking its contents', async (body) => {
    const value = secret();
    const http = new FakeHttp().on('POST', /^https:\/\/iam\.amazonaws\.com\/$/, () => text(200, body));
    await expectAwsFailure(awsProvider.rotate!(value, context(http, { AWS_ACCESS_KEY_ID: accessId() })));
  });

  it('rejects an XML error response even when IAM returns HTTP 200', async () => {
    const http = new FakeHttp().on('POST', /^https:\/\/iam\.amazonaws\.com\/$/, () => text(200,
      '<ErrorResponse><Error><Message>denied</Message></Error></ErrorResponse>'));
    await expectAwsFailure(awsProvider.revoke!(accessId(), context(http, {
      AWS_ACCESS_KEY_ID: accessId(), AWS_SECRET_ACCESS_KEY: secret(),
    })));
  });
});
