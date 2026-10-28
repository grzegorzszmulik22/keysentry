import { createHash, createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AuditExportError, createS3Sink, s3BatchBody, s3ObjectKey, s3ObjectUrl, s3RequestOrigin } from '../../src/audit-export/index.js';
import { signAwsRequest } from '../../src/providers/aws-sigv4.js';
import type { HttpRequest } from '../../src/types.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { FakeHttp, text } from '../helpers/fake-http.js';
import { sampleRecord, unexpected } from './helpers.js';

const now = () => new Date('2026-10-28T12:34:56.000Z');
const ACCESS_KEY = 'AKIAEXPORTTEST0000001';
const SECRET_KEY = ['s3-secret', 'Kq9vX2mL7pR4tY8w', 'Zz'].join('/');
const aws = { kind: 's3' as const, id: 'lake', endpoint: 'https://s3.eu-west-1.amazonaws.com', bucket: 'audit-bucket', region: 'eu-west-1', prefix: 'keysentry-audit/' };
const minio = { kind: 's3' as const, id: 'lake', endpoint: 'https://minio.example.com/storage', bucket: 'audit.bucket', region: 'us-east-1', prefix: 'team/a/' };
const vault = (extra: Record<string, Buffer> = {}) => createFakeVault({
  'audit-export/lake/access-key-id': Buffer.from(ACCESS_KEY), 'audit-export/lake/secret-access-key': Buffer.from(SECRET_KEY), ...extra });

/** The source and log identity every object name carries (review M2). */
const LOG = { sourceId: 'src0', logId: '0123456789abcdef' };
const ID = { source: 'src0', log: '0123456789abcdef' };
const sha256 = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');
const hmac = (key: string | Buffer, value: string) => createHmac('sha256', key).update(value, 'utf8').digest();
/** Independent S3 SigV4 check: S3 encodes the path once and signs the x-amz-content-sha256 value as the payload hash. */
function expectedAuthorization(request: HttpRequest, secret: string, region: string): string {
  const url = new URL(request.url);
  const headers = Object.fromEntries(Object.entries(request.headers!).filter(([name]) => name !== 'authorization'));
  const names = Object.keys(headers).sort();
  const uri = url.pathname.split('/').map(segment => encodeURIComponent(segment).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)).join('/');
  const canonical = [request.method, uri, '', names.map(name => `${name}:${headers[name]!.trim()}\n`).join(''), names.join(';'), headers['x-amz-content-sha256']].join('\n');
  const amzDate = headers['x-amz-date']!;
  const scope = `${amzDate.slice(0, 8)}/${region}/s3/aws4_request`;
  const key = hmac(hmac(hmac(hmac(`AWS4${secret}`, amzDate.slice(0, 8)), region), 's3'), 'aws4_request');
  const signature = hmac(key, ['AWS4-HMAC-SHA256', amzDate, scope, sha256(canonical)].join('\n')).toString('hex');
  return `AWS4-HMAC-SHA256 Credential=${ACCESS_KEY}/${scope}, SignedHeaders=${names.join(';')}, Signature=${signature}`;
}

describe('S3-compatible export', () => {
  it('reuses a SigV4 helper that reproduces the AWS S3 PutObject documentation example', () => {
    // Public AWS documentation values ("Example: PUT Object"), assembled in memory; not a live key.
    const documentationSecret = ['wJalrXUtnFEMI', 'K7MDENG', 'bPxRfiCYEXAMPLEKEY'].join('/');
    const signed = signAwsRequest({ method: 'PUT', url: 'https://examplebucket.s3.amazonaws.com/test$file.text', body: 'Welcome to Amazon S3.',
      headers: { Date: 'Fri, 24 May 2013 00:00:00 GMT', 'x-amz-storage-class': 'REDUCED_REDUNDANCY',
        'x-amz-content-sha256': sha256('Welcome to Amazon S3.') } },
    { accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: documentationSecret }, { region: 'us-east-1', service: 's3', now: new Date('2013-05-24T00:00:00Z') });
    expect(signed.headers!['x-amz-content-sha256']).toBe('44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072');
    expect(signed.headers!.authorization).toBe('AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, '
      + 'SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, '
      + 'Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd');
  });

  it('names each object <prefix><yyyy>/<mm>/<dd>/<source>/<log>/<firstSeq>-<lastSeq>.jsonl from the first record (UTC)', () => {
    const batch = [sampleRecord(41, { at: '2026-03-04T23:59:59.000Z' }), sampleRecord(42, { at: '2026-03-05T00:00:01.000Z' })];
    expect(s3ObjectKey('keysentry-audit/', batch, ID)).toBe('keysentry-audit/2026/03/04/src0/0123456789abcdef/41-42.jsonl');
    expect(s3ObjectKey('', [sampleRecord(7)], ID)).toBe('2026/10/28/src0/0123456789abcdef/7-7.jsonl');
    // Two logs of one source never share a name, even for the same sequence numbers on the same day (review M2).
    expect(s3ObjectKey('', [sampleRecord(7)], { ...ID, log: 'fedcba9876543210' })).not.toBe(s3ObjectKey('', [sampleRecord(7)], ID));
    expect(() => s3ObjectKey('p/', [], ID)).toThrow(AuditExportError);
    expect(() => s3ObjectKey('p/', [sampleRecord(1)], { ...ID, log: '../x' })).toThrow('no usable identity');
  });

  it('refuses to store a batch without a log identity rather than name it ambiguously', async () => {
    const http = new FakeHttp().on('PUT', /amazonaws/, () => text(200, ''));
    const error = await createS3Sink(aws, { http, vault: vault(), now, sourceId: 'src0' }).deliver([sampleRecord(1)]).then(unexpected, (caught: unknown) => caught as AuditExportError);
    expect(error.message).toBe('The audit log has no usable identity, so it cannot be stored.');
    expect(http.calls).toHaveLength(0);
  });

  it('uses virtual-hosted URLs on AWS and path-style URLs for other services and dotted bucket names', () => {
    expect(s3ObjectUrl(aws, 'keysentry-audit/2026/10/28/1-2.jsonl')).toBe('https://audit-bucket.s3.eu-west-1.amazonaws.com/keysentry-audit/2026/10/28/1-2.jsonl');
    expect(s3RequestOrigin(aws)).toBe('https://audit-bucket.s3.eu-west-1.amazonaws.com');
    expect(s3ObjectUrl({ ...aws, bucket: 'audit.bucket' }, 'k.jsonl')).toBe('https://s3.eu-west-1.amazonaws.com/audit.bucket/k.jsonl');
    expect(s3ObjectUrl(minio, 'team/a/1-2.jsonl')).toBe('https://minio.example.com/storage/audit.bucket/team/a/1-2.jsonl');
    expect(s3RequestOrigin(minio)).toBe('https://minio.example.com');
    expect(() => s3ObjectUrl({ ...minio, prefix: 'a/../b/' }, 'a/../b/1-1.jsonl')).toThrow('must not contain');
  });

  it('PUTs one JSONL object per batch with SigV4, x-amz-content-sha256 and If-None-Match: *', async () => {
    const http = new FakeHttp().on('PUT', /audit-bucket\.s3\.eu-west-1\.amazonaws\.com/, () => text(200, ''));
    const batch = [sampleRecord(1), sampleRecord(2)];
    expect(await createS3Sink(aws, { http, vault: vault(), now, ...LOG }).deliver(batch)).toEqual({});
    const request = http.calls[0]!;
    expect(request.url).toBe('https://audit-bucket.s3.eu-west-1.amazonaws.com/keysentry-audit/2026/10/28/src0/0123456789abcdef/1-2.jsonl');
    expect(request.body).toBe(s3BatchBody(batch));
    expect(request.body!.split('\n')).toHaveLength(3);
    expect(JSON.parse(request.body!.split('\n')[0]!)).toEqual(batch[0]);
    expect(request.headers!['x-amz-content-sha256']).toBe(sha256(request.body!));
    expect(request.headers!['if-none-match']).toBe('*');
    expect(request.headers!['content-type']).toBe('application/x-ndjson');
    expect(request.headers!['x-amz-date']).toBe('20261028T123456Z');
    expect(request.headers!.authorization).toContain('SignedHeaders=content-type;host;if-none-match;x-amz-content-sha256;x-amz-date,');
    expect(request.headers!.authorization).toBe(expectedAuthorization(request, SECRET_KEY, 'eu-west-1'));
    expect(JSON.stringify(request)).not.toContain(SECRET_KEY);
  });

  it('signs a session token when one is stored', async () => {
    const http = new FakeHttp().on('PUT', /minio\.example\.com/, () => text(200, ''));
    await createS3Sink(minio, { http, vault: vault({ 'audit-export/lake/session-token': Buffer.from('session-token-value-1') }), now, ...LOG }).deliver([sampleRecord(3)]);
    const request = http.calls[0]!;
    expect(request.url).toBe('https://minio.example.com/storage/audit.bucket/team/a/2026/10/28/src0/0123456789abcdef/3-3.jsonl');
    expect(request.headers!['x-amz-security-token']).toBe('session-token-value-1');
    expect(request.headers!.authorization).toBe(expectedAuthorization(request, SECRET_KEY, 'us-east-1'));
  });

  it('treats 412 as already stored only when the existing object holds exactly this batch', async () => {
    const batch = [sampleRecord(1)];
    const same = new FakeHttp().on('PUT', /amazonaws/, () => text(412, '<Error/>')).on('GET', /amazonaws/, () => text(200, s3BatchBody(batch)));
    expect(await createS3Sink(aws, { http: same, vault: vault(), now, ...LOG }).deliver(batch)).toEqual({});
    const get = same.calls[1]!;
    expect(get.headers!['x-amz-content-sha256']).toBe(sha256(''));
    expect(get.headers!.authorization).toBe(expectedAuthorization(get, SECRET_KEY, 'eu-west-1'));

    const different = new FakeHttp().on('PUT', /amazonaws/, () => text(412, '')).on('GET', /amazonaws/, () => text(200, s3BatchBody([sampleRecord(9)])));
    await expect(createS3Sink(aws, { http: different, vault: vault(), now, ...LOG }).deliver(batch)).rejects.toThrow('Nothing was overwritten. Check that no other writer uses this S3 prefix.');

    const unreadable = new FakeHttp().on('PUT', /amazonaws/, () => text(412, '')).on('GET', /amazonaws/, () => text(403, 'AccessDenied'));
    const error = await createS3Sink(aws, { http: unreadable, vault: vault(), now, ...LOG }).deliver(batch).then(unexpected, (caught: unknown) => caught as AuditExportError);
    expect(error.message).toContain('could not read it to confirm');
    expect(error.retryable).toBe(false);
  });

  it('falls back from a service without conditional writes, and says so', async () => {
    let first = true;
    const http = new FakeHttp().on('PUT', /minio/, () => { const status = first ? 501 : 200; first = false; return text(status, ''); });
    const sink = createS3Sink(minio, { http, vault: vault(), now, ...LOG });
    const outcome = await sink.deliver([sampleRecord(1)]);
    expect(outcome.warnings?.[0]).toContain('does not support conditional writes');
    expect(http.calls.map(call => call.headers!['if-none-match'])).toEqual(['*', undefined]);
    expect(http.calls[1]!.headers!.authorization).toBe(expectedAuthorization(http.calls[1]!, SECRET_KEY, 'us-east-1'));
  });

  it('classifies failures with fixed text and never puts a credential in an error', async () => {
    for (const [status, retryable] of [[403, false], [400, false], [409, true], [500, true], [503, true], [429, true]] as const) {
      const http = new FakeHttp().on('PUT', /amazonaws/, () => text(status, `<Error><Message>${SECRET_KEY}</Message></Error>`));
      const error = await createS3Sink(aws, { http, vault: vault(), now, ...LOG }).deliver([sampleRecord(1)]).then(unexpected, (caught: unknown) => caught as AuditExportError);
      expect(error.message).toBe(`The storage service answered HTTP ${status}.`);
      expect(error.retryable).toBe(retryable);
    }
    const missing = await createS3Sink(aws, { http: new FakeHttp(), vault: createFakeVault(), now, ...LOG }).deliver([sampleRecord(1)]).then(unexpected, (caught: unknown) => caught as AuditExportError);
    expect(missing.message).toBe('Store the S3 credentials first: keysentry audit export secret lake access-key-id, then secret-access-key.');
    const malformed = await createS3Sink(aws, { http: new FakeHttp(), vault: vault({ 'audit-export/lake/secret-access-key': Buffer.from(`has space ${SECRET_KEY}`) }), now, ...LOG })
      .deliver([sampleRecord(1)]).then(unexpected, (caught: unknown) => caught as AuditExportError);
    expect(malformed.message).toBe('The stored S3 credentials have an unsupported format.');
  });

  it('previews the object name and size without credentials or network', () => {
    const preview = createS3Sink(aws, { http: new FakeHttp(), vault: createFakeVault(), now, ...LOG }).preview([sampleRecord(5), sampleRecord(6)]);
    expect(preview).toEqual({ location: 'audit-bucket/keysentry-audit/2026/10/28/src0/0123456789abcdef/5-6.jsonl', bytes: Buffer.byteLength(s3BatchBody([sampleRecord(5), sampleRecord(6)])) });
  });
});
