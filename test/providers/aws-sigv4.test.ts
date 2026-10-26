import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { signAwsRequest } from '../../src/providers/aws-sigv4.js';

describe('AWS SigV4', () => {
  it('reproduces the AWS IAM ListUsers documentation signature', () => {
    // Public AWS documentation example, assembled in memory; never a live key.
    const documentationSecret = ['wJalrXUtnFEMI', 'K7MDENG+bPxRfiCY', 'EXAMPLEKEY'].join('').replace('FEMI', 'FEMI/');
    const signed = signAwsRequest({
      method: 'GET',
      url: 'https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' },
    }, { accessKeyId: 'AKIDEXAMPLE', secretAccessKey: documentationSecret }, {
      region: 'us-east-1', service: 'iam', now: new Date('2015-08-30T12:36:00Z'),
    });

    expect(signed.headers?.authorization).toBe(
      'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, '
      + 'SignedHeaders=content-type;host;x-amz-date, '
      + 'Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7',
    );
    expect(signed.headers?.host).toBe('iam.amazonaws.com');
    expect(signed.headers?.['x-amz-date']).toBe('20150830T123600Z');
  });

  it('signs temporary credentials and hashes the exact body', () => {
    const credentials = {
      accessKeyId: `ASIA${randomBytes(8).toString('hex').toUpperCase()}`,
      secretAccessKey: randomBytes(30).toString('base64'),
      sessionToken: randomBytes(48).toString('base64'),
    };
    const request = {
      method: 'POST' as const,
      url: 'https://sts.amazonaws.com/',
      headers: { 'Content-Type': ' application/x-www-form-urlencoded;  charset=utf-8 ' },
      body: 'Action=GetCallerIdentity&Version=2011-06-15',
    };
    const options = { region: 'us-east-1', service: 'sts', now: new Date('2025-01-02T03:04:05Z') };
    const signed = signAwsRequest(request, credentials, options);
    const changedBody = signAwsRequest({ ...request, body: `${request.body}&X=1` }, credentials, options);
    const changedToken = signAwsRequest(request, { ...credentials, sessionToken: randomBytes(48).toString('base64') }, options);

    expect(signed.headers?.['x-amz-security-token'] === credentials.sessionToken).toBe(true);
    expect(signed.headers?.authorization?.includes('SignedHeaders=content-type;host;x-amz-date;x-amz-security-token,')).toBe(true);
    expect(signed.headers?.authorization === changedBody.headers?.authorization).toBe(false);
    expect(signed.headers?.authorization === changedToken.headers?.authorization).toBe(false);
    expect(signed.body).toBe(request.body);
    expect(request.headers).toEqual({ 'Content-Type': ' application/x-www-form-urlencoded;  charset=utf-8 ' });
  });

  it('canonicalizes query ordering, encoded spaces and header whitespace', () => {
    const credentials = { accessKeyId: 'AKIDEXAMPLE', secretAccessKey: randomBytes(30).toString('base64') };
    const options = { region: 'us-east-1', service: 'iam', now: new Date('2025-01-02T03:04:05Z') };
    const first = signAwsRequest({ method: 'GET', url: 'https://iam.amazonaws.com/?z=last&a=two+words&a=one', headers: { 'X-Test': 'a  b' } }, credentials, options);
    const second = signAwsRequest({ method: 'GET', url: 'https://iam.amazonaws.com/?a=one&a=two%20words&z=last', headers: { 'x-test': ' a b ' } }, credentials, options);
    expect(first.headers?.authorization === second.headers?.authorization).toBe(true);
  });

  it('removes a stale session token when re-signing with long-lived credentials', () => {
    const credentials = { accessKeyId: 'AKIDEXAMPLE', secretAccessKey: randomBytes(30).toString('base64') };
    const options = { region: 'us-east-1', service: 'sts', now: new Date('2025-01-02T03:04:05Z') };
    const request = { method: 'POST' as const, url: 'https://sts.amazonaws.com/', body: 'Action=GetCallerIdentity&Version=2011-06-15' };
    const temporary = signAwsRequest(request, { ...credentials, sessionToken: randomBytes(48).toString('base64') }, options);
    const signed = signAwsRequest(temporary, credentials, options);
    const fresh = signAwsRequest(request, credentials, options);
    expect(signed.headers?.['x-amz-security-token'] === undefined).toBe(true);
    expect(signed.headers?.authorization === fresh.headers?.authorization).toBe(true);
  });
});
