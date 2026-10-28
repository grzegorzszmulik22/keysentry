import { describe, expect, it } from 'vitest';
import { createAwsSecretsManagerHost, plainVariableName, type AwsSecretsManagerHostOptions } from '../../src/hosts/aws-secrets-manager.js';
import { signAwsRequest } from '../../src/providers/aws-sigv4.js';
import type { HttpRequest, ServiceRef } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const endpoint = 'https://secretsmanager.eu-west-1.amazonaws.com/';
const credentials = { accessKeyId: 'AKIDEXAMPLESECRETSMGR', secretAccessKey: 'test-aws-secret-access-key-value' };
const fixedNow = new Date('2026-10-28T10:00:00.000Z');
const arn = 'arn:aws:secretsmanager:eu-west-1:123456789012:secret:prod/api-AbCdEf';
const service: ServiceRef = {
  host: 'aws-secrets-manager', projectId: 'eu-west-1', projectName: 'eu-west-1', serviceId: arn, serviceName: 'prod/api',
  environmentId: '', environmentName: '',
};
const current = 'a1b2c3d4-0000-4000-8000-000000000001';
const newToken = 'a1b2c3d4-0000-4000-8000-0000000000ff';

function hostFor(http: FakeHttp, extra: Partial<AwsSecretsManagerHostOptions> = {}) {
  return createAwsSecretsManagerHost({
    region: 'eu-west-1', credentials, http, log: silentLogger, now: () => fixedNow, randomUUID: () => newToken, ...extra,
  });
}

const target = (req: HttpRequest) => req.headers?.['x-amz-target']?.replace('secretsmanager.', '');
const body = (req: HttpRequest) => JSON.parse(req.body ?? '{}') as Record<string, unknown>;

/** Route by X-Amz-Target; every call is a signed POST to the regional endpoint. */
function awsFake(handlers: Record<string, (req: HttpRequest) => ReturnType<typeof json>>) {
  return new FakeHttp().on('POST', /^https:\/\/secretsmanager\.eu-west-1\.amazonaws\.com\/$/, (req) => {
    const handler = handlers[target(req) ?? ''];
    return handler ? handler(req) : json(400, { __type: 'InvalidAction' });
  });
}

const described = (overrides: Record<string, unknown> = {}) => ({
  ARN: arn, Name: 'prod/api', VersionIdsToStages: { [current]: ['AWSCURRENT'], 'a1b2c3d4-0000-4000-8000-000000000000': ['AWSPREVIOUS'] },
  KmsKeyId: 'arn:aws:kms:eu-west-1:123456789012:key/k', Tags: [{ Key: 'team', Value: 'pay' }], ...overrides,
});

describe('AWS Secrets Manager host', () => {
  it('reports readable values, single-call writes and no deployments', () => {
    const host = hostFor(new FakeHttp());
    expect(host.id).toBe('aws-secrets-manager');
    expect(host.capabilities).toEqual({ readValues: true, batchWrite: true, redeploy: false });
  });

  it('validates the region and name filters', () => {
    expect(() => hostFor(new FakeHttp(), { region: 'eu-west-1.evil.example' })).toThrow(/region/);
    expect(() => hostFor(new FakeHttp(), { namePrefixes: ['!prod'] })).toThrow(/prefixes/);
  });

  it('signs JSON API calls with SigV4 for the secretsmanager service', async () => {
    const http = awsFake({ ListSecrets: () => json(200, { SecretList: [] }) });
    await hostFor(http).listServices();
    const call = http.calls[0]!;
    const expected = signAwsRequest({
      method: 'POST', url: endpoint,
      headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amz-target': 'secretsmanager.ListSecrets' },
      body: JSON.stringify({ MaxResults: 100 }),
    }, credentials, { region: 'eu-west-1', service: 'secretsmanager', now: fixedNow });
    expect(call).toEqual(expected);
    expect(call.headers?.authorization).toMatch(
      /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLESECRETSMGR\/20261028\/eu-west-1\/secretsmanager\/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=[0-9a-f]{64}$/,
    );
    expect(call.headers?.authorization).not.toContain(credentials.secretAccessKey);
  });

  it('lists secrets across NextToken pages, including an empty page, with name filters', async () => {
    const pages: Record<string, unknown>[] = [
      { SecretList: [{ ARN: arn, Name: 'prod/api' }], NextToken: 'token-1' },
      { SecretList: [], NextToken: 'token-2' },
      { SecretList: [{ ARN: `${arn}2`, Name: 'prod/worker' }, { ARN: `${arn}3`, Name: 'prod/old', DeletedDate: 1 }] },
    ];
    const http = awsFake({ ListSecrets: () => json(200, pages.shift()) });
    const refs = await hostFor(http, { namePrefixes: ['prod/'] }).listServices();
    expect(refs).toEqual([service, { ...service, serviceId: `${arn}2`, serviceName: 'prod/worker' }]);
    expect(http.calls.map(body)).toEqual([
      { MaxResults: 100, Filters: [{ Key: 'name', Values: ['prod/'] }] },
      { MaxResults: 100, Filters: [{ Key: 'name', Values: ['prod/'] }], NextToken: 'token-1' },
      { MaxResults: 100, Filters: [{ Key: 'name', Values: ['prod/'] }], NextToken: 'token-2' },
    ]);
  });

  it('stops when NextToken repeats', async () => {
    const http = awsFake({ ListSecrets: () => json(200, { SecretList: [], NextToken: 'same' }) });
    await expect(hostFor(http).listServices()).rejects.toThrow('AWS Secrets Manager pagination did not advance');
    expect(http.calls).toHaveLength(2);
  });

  it('describes configured secret ids instead of listing', async () => {
    const http = awsFake({ DescribeSecret: () => json(200, described()) });
    expect(await hostFor(http, { secretIds: ['prod/api'] }).listServices()).toEqual([service]);
    expect(http.calls.map(target)).toEqual(['DescribeSecret']);
    expect(body(http.calls[0]!)).toEqual({ SecretId: 'prod/api' });
  });

  it('maps JSON string keys to variables and keeps non-string values out', async () => {
    const http = awsFake({
      GetSecretValue: () => json(200, {
        ARN: arn, Name: 'prod/api', VersionId: current,
        SecretString: JSON.stringify({ OPENAI_API_KEY: 'test-openai-value', PORT: 5432, nested: { a: 1 }, EMPTY: '' }),
      }),
    });
    expect(await hostFor(http).readVariables(service)).toEqual([
      { name: 'OPENAI_API_KEY', value: 'test-openai-value', sealed: false },
      { name: 'EMPTY', value: '', sealed: false },
    ]);
    expect(body(http.calls[0]!)).toEqual({ SecretId: arn });
  });

  it('names a plain-string secret after the last segment of its name and seals binary secrets', async () => {
    expect(plainVariableName('prod/payments/STRIPE_SECRET_KEY')).toBe('STRIPE_SECRET_KEY');
    expect(plainVariableName('plain-name')).toBe('plain-name');
    expect(plainVariableName('ends-with/')).toBe('ends-with/');
    const plain = awsFake({ GetSecretValue: () => json(200, { ARN: arn, Name: 'prod/STRIPE_SECRET_KEY', VersionId: current, SecretString: 'test-stripe-value' }) });
    expect(await hostFor(plain).readVariables(service)).toEqual([{ name: 'STRIPE_SECRET_KEY', value: 'test-stripe-value', sealed: false }]);
    const binary = awsFake({ GetSecretValue: () => json(200, { ARN: arn, Name: 'prod/cert', VersionId: current, SecretBinary: 'AAEC' }) });
    expect(await hostFor(binary).readVariables(service)).toEqual([{ name: 'cert', sealed: true }]);
  });

  it('writes a new version and moves AWSCURRENT only from the version it read, keeping other keys', async () => {
    const original = '{\n  "OPENAI_API_KEY": "test-old-openai",\n  "PORT": 5432,\n  "flag": true,\n  "esc": "a\\/b"\n}';
    const http = awsFake({
      DescribeSecret: () => json(200, described()),
      GetSecretValue: () => json(200, { ARN: arn, Name: 'prod/api', VersionId: current, SecretString: original }),
      PutSecretValue: () => json(200, { ARN: arn, Name: 'prod/api', VersionId: newToken, VersionStages: ['KEYSENTRY_PENDING'] }),
      UpdateSecretVersionStage: () => json(200, { ARN: arn, Name: 'prod/api' }),
    });
    await hostFor(http).writeVariables(service, { OPENAI_API_KEY: 'test-new-openai', ADDED: 'test-added' }, { skipDeploy: true });

    expect(http.calls.map(target)).toEqual(['DescribeSecret', 'GetSecretValue', 'PutSecretValue', 'UpdateSecretVersionStage', 'UpdateSecretVersionStage']);
    expect(http.calls.map(body)).toEqual([
      { SecretId: arn },
      { SecretId: arn, VersionId: current },
      {
        SecretId: arn, ClientRequestToken: newToken, VersionStages: ['KEYSENTRY_PENDING'],
        SecretString: JSON.stringify({ OPENAI_API_KEY: 'test-new-openai', PORT: 5432, flag: true, esc: 'a/b', ADDED: 'test-added' }),
      },
      { SecretId: arn, VersionStage: 'AWSCURRENT', MoveToVersionId: newToken, RemoveFromVersionId: current },
      { SecretId: arn, VersionStage: 'KEYSENTRY_PENDING', RemoveFromVersionId: newToken },
    ]);
    expect(http.calls.every((call) => call.method === 'POST' && call.url === endpoint)).toBe(true);
  });

  it('fails without overwriting when AWSCURRENT moved concurrently, and removes its pending label', async () => {
    const http = awsFake({
      DescribeSecret: () => json(200, described()),
      GetSecretValue: () => json(200, { ARN: arn, Name: 'prod/api', VersionId: current, SecretString: '{"K":"test-old"}' }),
      PutSecretValue: () => json(200, { ARN: arn, VersionId: newToken }),
      UpdateSecretVersionStage: (req) => (body(req).VersionStage === 'AWSCURRENT'
        ? json(400, { __type: 'InvalidParameterException', message: 'planted-stage-marker test-new' })
        : json(200, { ARN: arn })),
    });
    const error = await hostFor(http).writeVariables(service, { K: 'test-new' }, { skipDeploy: true }).catch((caught: unknown) => caught);
    expect(String(error)).toMatch(/changed while keysentry was writing it/);
    expect(String(error)).not.toContain('planted-stage-marker');
    expect(String(error)).not.toContain('test-new');
    expect(body(http.calls[4]!)).toEqual({ SecretId: arn, VersionStage: 'KEYSENTRY_PENDING', RemoveFromVersionId: newToken });
  });

  it.each([
    ['a rotation in progress', described({ VersionIdsToStages: { [current]: ['AWSCURRENT'], 'a1b2c3d4-0000-4000-8000-0000000000aa': ['AWSPENDING'] } }), /rotation in progress/],
    ['a service-owned secret', described({ OwningService: 'rds' }), /managed by another AWS service/],
    ['a secret scheduled for deletion', described({ DeletedDate: 1_800_000_000 }), /scheduled for deletion/],
  ])('refuses %s before reading or writing values', async (_label, describe_, message) => {
    const http = awsFake({ DescribeSecret: () => json(200, describe_) });
    await expect(hostFor(http).writeVariables(service, { K: 'test-new' }, { skipDeploy: true })).rejects.toThrow(message);
    expect(http.calls.map(target)).toEqual(['DescribeSecret']);
  });

  it.each([
    ['a lossy number', '{"K":"test-old","N":1.0}', { K: 'test-new' }, /numbers or duplicate keys/],
    ['a duplicate key', '{"K":"test-old","K":"test-dup"}', { K: 'test-new' }, /numbers or duplicate keys/],
    ['a non-string target', '{"K":"test-old","N":5}', { N: 'test-new' }, /non-string value/],
    ['a second key on a plain secret', 'test-plain-old', { api: 'test-new', OTHER: 'x' }, /plain-text secret/],
    ['a different name on a plain secret', 'test-plain-old', { OTHER: 'test-new' }, /plain-text secret/],
    ['a JSON object into a plain secret', 'test-plain-old', { api: '{"a":"b"}' }, /would become a JSON/],
  ])('refuses %s before PutSecretValue', async (_label, secretString, vars, message) => {
    const http = awsFake({
      DescribeSecret: () => json(200, described()),
      GetSecretValue: () => json(200, { ARN: arn, Name: 'prod/api', VersionId: current, SecretString: secretString }),
    });
    await expect(hostFor(http).writeVariables(service, vars, { skipDeploy: true })).rejects.toThrow(message);
    expect(http.calls.map(target)).not.toContain('PutSecretValue');
  });

  it('writes a plain-string secret as its single value and skips unchanged writes', async () => {
    const http = awsFake({
      DescribeSecret: () => json(200, described()),
      GetSecretValue: () => json(200, { ARN: arn, Name: 'prod/api', VersionId: current, SecretString: 'test-plain-old' }),
      PutSecretValue: () => json(200, { ARN: arn, VersionId: newToken }),
      UpdateSecretVersionStage: () => json(200, { ARN: arn }),
    });
    await hostFor(http).writeVariables(service, { api: 'test-plain-new' }, { skipDeploy: true });
    expect(body(http.callsTo('POST', /./).find((call) => target(call) === 'PutSecretValue')!).SecretString).toBe('test-plain-new');

    const same = awsFake({
      DescribeSecret: () => json(200, described()),
      GetSecretValue: () => json(200, { ARN: arn, Name: 'prod/api', VersionId: current, SecretString: '{"K":"test-same"}' }),
    });
    await hostFor(same).writeVariables(service, { K: 'test-same' }, { skipDeploy: true });
    expect(same.calls.map(target)).toEqual(['DescribeSecret', 'GetSecretValue']);
  });

  it('rejects a read whose version differs from the current version it described', async () => {
    const http = awsFake({
      DescribeSecret: () => json(200, described()),
      GetSecretValue: () => json(200, { ARN: arn, Name: 'prod/api', VersionId: 'a1b2c3d4-0000-4000-8000-000000000999', SecretString: '{}' }),
    });
    await expect(hostFor(http).writeVariables(service, { K: 'test-new' }, { skipDeploy: true })).rejects.toThrow('AWS Secrets Manager returned an invalid response');
  });

  it.each(['http', 'transport', 'json'] as const)('sanitizes a %s failure', async (failure) => {
    const marker = 'test-planted-aws-marker';
    const http = new FakeHttp().on('POST', /./, () => {
      if (failure === 'transport') throw new Error(`${credentials.secretAccessKey} ${marker}`);
      return failure === 'http' ? json(400, { __type: 'AccessDeniedException', message: marker }) : text(200, `{${marker}`);
    });
    const error = await hostFor(http).readVariables(service).catch((caught: unknown) => caught);
    expect(String(error)).toMatch(/AWS Secrets Manager/);
    expect(String(error)).not.toContain(marker);
    expect(String(error)).not.toContain(credentials.secretAccessKey);
  });

  it('does not deploy', async () => {
    expect(await hostFor(new FakeHttp()).redeploy(service)).toBeNull();
    await expect(hostFor(new FakeHttp()).deploymentStatus(service, 'x')).rejects.toThrow(/does not create deployments/);
  });
});
