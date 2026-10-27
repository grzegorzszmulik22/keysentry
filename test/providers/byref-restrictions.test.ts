import { randomBytes } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { openrouterProvider } from '../../src/providers/openrouter.js';
import { openaiProvider } from '../../src/providers/openai.js';
import type { ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger } from '../helpers/fake-http.js';

const context = (http: FakeHttp): ProviderContext => ({ http, log: silentLogger, credentials: {
  OPENROUTER_PROVISIONING_KEY: `sk-or-v1-${randomBytes(32).toString('hex')}`,
  OPENAI_ADMIN_KEY: `sk-admin-${randomBytes(32).toString('hex')}`,
} });
const routerKey = { hash: 'old-hash', name: 'Production', disabled: false, limit: 15 };
const aiRef = 'proj_one/key_old/sa-key:svc_acct_old';
const aiKey = { id: 'key_old', scopes: ['api.responses.write'],
  owner: { type: 'service_account', service_account: { id: 'svc_acct_old' } } };
const now = Date.parse('2026-10-27T12:00:00.250Z');
const expiresAt = Date.parse('2026-10-28T12:00:00Z') / 1000;

afterEach(() => vi.restoreAllMocks());

describe('L3 replacement key restrictions', () => {
  it.each([
    { metadata: { limit_reset: 'monthly', include_byok_in_limit: true },
      expected: { limit_reset: 'monthly', include_byok_in_limit: true } },
    { metadata: { limitReset: 'weekly', includeByokInLimit: false },
      expected: { limit_reset: 'weekly', include_byok_in_limit: false } },
    { metadata: { limitReset: 'daily', include_byok_in_limit: true },
      expected: { limit_reset: 'daily', include_byok_in_limit: true } },
    { metadata: { limit_reset: null, include_byok_in_limit: false },
      expected: { limit_reset: null, include_byok_in_limit: false } },
    { metadata: { limit_reset: 'monthly', limitReset: 'monthly',
      include_byok_in_limit: false, includeByokInLimit: false },
      expected: { limit_reset: 'monthly', include_byok_in_limit: false } },
  ])('OpenRouter copies reset and BYOK settings to creation: $metadata', async ({ metadata, expected }) => {
    const value = `sk-or-v1-${randomBytes(32).toString('hex')}`;
    const http = new FakeHttp().on('GET', /\/keys\/old-hash$/, () => json(200, {
      data: { ...routerKey, ...metadata, label: 'masked', created_at: '2026-10-01T00:00:00Z',
        updated_at: '2026-10-02T00:00:00Z', limit_remaining: 13, usage: 2,
        usage_daily: 1, usage_weekly: 2, usage_monthly: 2,
        byok_usage: 1, byok_usage_daily: 1, byok_usage_weekly: 1, byok_usage_monthly: 1 },
    })).on('POST', /\/keys$/, () => json(201, { key: value, data: { hash: 'new-hash' } }));
    const result = await openrouterProvider.rotateByRef!('old-hash', context(http));
    expect(result.newValue === value).toBe(true);
    expect(http.calls.map(call => call.method)).toEqual(['GET', 'POST']);
    expect(JSON.parse(http.calls[1]!.body!)).toEqual({ name: 'Production', limit: 15, ...expected });
    expect(result.oldRevoked).toBe(false);
  });

  it.each([
    { limit_reset: 'yearly' }, { limit_reset: 60 }, { limit_reset: {} },
    { limitReset: '' }, { limitReset: true }, { include_byok_in_limit: null },
    { include_byok_in_limit: 'false' }, { includeByokInLimit: 1 },
    { limit_reset: 'monthly', limitReset: 'weekly' },
    { limit_reset: null, limitReset: 'monthly' },
    { include_byok_in_limit: false, includeByokInLimit: true },
    { expires_at: '2026-12-01T00:00:00Z' }, { permissions: ['read'] },
    { rate_limit: { requests: 10 } }, { future_policy: false },
  ])('OpenRouter requires guided rotation for unrepresentable metadata before mutation: %j', async metadata => {
    const http = new FakeHttp().on('GET', /\/keys\/old-hash$/, () => json(200, {
      data: { ...routerKey, ...metadata },
    })).on('POST', /\/keys$/, () => json(201, { key: 'unused', data: { hash: 'new-hash' } }));
    await expect(openrouterProvider.rotateByRef!('old-hash', context(http)))
      .rejects.toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(http.calls.map(call => call.method)).toEqual(['GET']);
  });

  it.each([0, null])('OpenRouter preserves zero and unlimited limits with recurring settings: %s', async limit => {
    const http = new FakeHttp().on('GET', /\/keys\/old-hash$/, () => json(200, {
      data: { ...routerKey, limit, limit_reset: 'monthly', include_byok_in_limit: false },
    })).on('POST', /\/keys$/, () => json(201, {
      key: `sk-or-v1-${randomBytes(32).toString('hex')}`, data: { hash: 'new-hash' },
    }));
    await openrouterProvider.rotateByRef!('old-hash', context(http));
    expect(JSON.parse(http.calls[1]!.body!)).toEqual({ name: 'Production', limit,
      limit_reset: 'monthly', include_byok_in_limit: false });
  });

  it('OpenRouter keeps unsupported policy values out of errors', async () => {
    const http = new FakeHttp();
    const ctx = context(http);
    const secret = ctx.credentials.OPENROUTER_PROVISIONING_KEY!;
    http.on('GET', /\/keys\/old-hash$/, () => json(200, { data: { ...routerKey, limit_reset: secret } }));
    const error: unknown = await openrouterProvider.rotateByRef!('old-hash', ctx).catch((failure: unknown) => failure);
    expect(error).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(String(error).includes(secret)).toBe(false);
    expect(http.calls.map(call => call.method)).toEqual(['GET']);
  });

  it('OpenAI carries forward remaining expiry when rotating by reference', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(now);
    const value = `sk-svcacct-${randomBytes(32).toString('hex')}`;
    const http = new FakeHttp().on('GET', /\/api_keys\/key_old$/, () => json(200, { ...aiKey, expires_at: expiresAt }))
      .on('POST', /\/service_accounts\/svc_acct_old\/api_keys$/, () => json(201, { id: 'key_new', value }));
    const result = await openaiProvider.rotateByRef!(aiRef, context(http));
    expect(result.newValue === value).toBe(true);
    const body = JSON.parse(http.calls[1]!.body!);
    expect(body.scopes).toEqual(['api.responses.write']);
    expect(body.expires_in_seconds).toBe(86_399);
    expect(Object.keys(body).sort()).toEqual(['expires_in_seconds', 'name', 'scopes']);
    expect(result.oldRevoked).toBe(false);
  });

  it('OpenAI retains expiry through value-based resolution too', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(now);
    const oldValue = `sk-svcacct-${randomBytes(32).toString('hex')}`;
    const http = new FakeHttp().on('GET', /\/organization\/projects\?limit=100$/, () => json(200, {
      data: [{ id: 'proj_one' }], has_more: false,
    })).on('GET', /\/proj_one\/api_keys\?limit=100$/, () => json(200, {
      data: [{ ...aiKey, expires_at: expiresAt, redacted_value: `${oldValue.slice(0, 12)}...${oldValue.slice(-4)}` }],
      has_more: false,
    })).on('POST', /\/service_accounts\/svc_acct_old\/api_keys$/, () => json(201, {
      id: 'key_new', value: `sk-svcacct-${randomBytes(32).toString('hex')}`,
    }));
    await openaiProvider.rotate!(oldValue, context(http));
    expect(JSON.parse(http.calls[2]!.body!).expires_in_seconds).toBe(86_399);
  });

  it.each([null, undefined])('OpenAI keeps keys without an expiry unchanged: %s', async expires_at => {
    const http = new FakeHttp().on('GET', /\/api_keys\/key_old$/, () => json(200, { ...aiKey, expires_at }))
      .on('POST', /\/service_accounts\/svc_acct_old\/api_keys$/, () => json(201, {
        id: 'key_new', value: `sk-svcacct-${randomBytes(32).toString('hex')}`,
      }));
    await openaiProvider.rotateByRef!(aiRef, context(http));
    expect(Object.keys(JSON.parse(http.calls[1]!.body!)).sort()).toEqual(['name', 'scopes']);
  });

  it.each([0, -1, now / 1000, Math.ceil(now / 1000), 1.5, '2026-10-28T12:00:00Z', {}, true,
    Number.MAX_SAFE_INTEGER + 1])('OpenAI refuses invalid, expired or unrepresentable expiry before mutation: %j', async expires_at => {
    vi.spyOn(Date, 'now').mockReturnValue(now);
    const http = new FakeHttp().on('GET', /\/api_keys\/key_old$/, () => json(200, { ...aiKey, expires_at }))
      .on('POST', /\/service_accounts\/svc_acct_old\/api_keys$/, () => json(201, { id: 'key_new', value: 'unused' }));
    await expect(openaiProvider.rotateByRef!(aiRef, context(http)))
      .rejects.toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED', provider: 'openai' });
    expect(http.calls.map(call => call.method)).toEqual(['GET']);
  });

  it.each([400, 404, 405, 422, 501])('OpenAI does not retry without expiry when creation rejects it (%s)', async status => {
    vi.spyOn(Date, 'now').mockReturnValue(now);
    const http = new FakeHttp().on('GET', /\/api_keys\/key_old$/, () => json(200, { ...aiKey, expires_at: expiresAt }))
      .on('POST', /\/service_accounts\/svc_acct_old\/api_keys$/, () => json(status, { error: { message: 'unsupported expiry' } }));
    await expect(openaiProvider.rotateByRef!(aiRef, context(http)))
      .rejects.toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(http.calls.map(call => call.method)).toEqual(['GET', 'POST']);
    expect(JSON.parse(http.calls[1]!.body!).expires_in_seconds).toBe(86_399);
  });
});
