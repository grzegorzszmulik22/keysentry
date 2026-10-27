import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { openrouterProvider } from '../../src/providers/openrouter.js';
import { openaiProvider } from '../../src/providers/openai.js';
import { resendProvider } from '../../src/providers/resend.js';
import { awsProvider } from '../../src/providers/aws.js';
import type { ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const context = (http: FakeHttp): ProviderContext => ({ http, log: silentLogger, credentials: {
  OPENROUTER_PROVISIONING_KEY: `sk-or-v1-${randomBytes(32).toString('hex')}`,
  OPENAI_ADMIN_KEY: `sk-admin-${randomBytes(32).toString('hex')}`,
  RESEND_ADMIN_KEY: `re_${randomBytes(24).toString('hex')}`,
} });

describe('rotation by provider reference', () => {
  it.each([17.25, 0, null])('OpenRouter reads metadata by hash and preserves name and limit %s', async limit => {
    const http = new FakeHttp();
    const ctx = context(http);
    const value = `sk-or-v1-${randomBytes(32).toString('hex')}`;
    http.on('GET', /^https:\/\/openrouter\.ai\/api\/v1\/keys\/old-hash$/, req => {
      expect(req.headers?.Authorization === `Bearer ${ctx.credentials.OPENROUTER_PROVISIONING_KEY}`).toBe(true);
      return json(200, { data: { hash: 'old-hash', name: 'Production worker', limit, disabled: false } });
    }).on('POST', /^https:\/\/openrouter\.ai\/api\/v1\/keys$/, req => {
      expect(req.headers?.Authorization === `Bearer ${ctx.credentials.OPENROUTER_PROVISIONING_KEY}`).toBe(true);
      expect(JSON.parse(req.body!)).toEqual({ name: 'Production worker', limit });
      return json(201, { key: value, data: { hash: 'new-hash' } });
    });
    const result = await openrouterProvider.rotateByRef!('old-hash', ctx);
    expect(result.newValue === value).toBe(true);
    expect({ ...result, newValue: '<value>' }).toEqual({ newValue: '<value>', oldKeyRef: 'old-hash', newKeyRef: 'new-hash', oldRevoked: false });
    expect(http.calls.map(req => req.method)).toEqual(['GET', 'POST']);
  });

  it.each([
    { disabled: true }, { disabled: undefined }, { hash: 'different-hash' }, { name: undefined },
    { name: '' }, { limit: undefined }, { limit: -1 }, { limit: '10' },
  ])('OpenRouter refuses unsafe or disabled metadata before creation: %j', async patch => {
    const http = new FakeHttp().on('GET', /\/keys\/old-hash$/, () => json(200, {
      data: { hash: 'old-hash', name: 'Production', limit: 10, disabled: false, ...patch },
    }));
    await expect(openrouterProvider.rotateByRef!('old-hash', context(http)))
      .rejects.toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(http.calls.every(req => req.method === 'GET')).toBe(true);
  });

  it('OpenRouter rejects secret-shaped refs and names without exposing them', async () => {
    const http = new FakeHttp();
    const ctx = context(http);
    const secret = ctx.credentials.OPENROUTER_PROVISIONING_KEY!;
    await expect(openrouterProvider.rotateByRef!(secret, ctx)).rejects.toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(http.calls).toHaveLength(0);
    http.on('GET', /\/keys\/old-hash$/, () => json(200, {
      data: { hash: 'old-hash', name: secret, limit: 10, disabled: false },
    }));
    const error = await openrouterProvider.rotateByRef!('old-hash', ctx).catch((failure: unknown) => failure);
    expect(error).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(String(error).includes(secret)).toBe(false);
    expect(http.calls.every(req => req.method === 'GET')).toBe(true);
  });

  it('OpenRouter refuses nonfinite JSON limits before creation', async () => {
    const http = new FakeHttp().on('GET', /\/keys\/old-hash$/, () => text(200,
      '{"data":{"hash":"old-hash","name":"Production","disabled":false,"limit":1e999}}'));
    await expect(openrouterProvider.rotateByRef!('old-hash', context(http)))
      .rejects.toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(http.calls.every(req => req.method === 'GET')).toBe(true);
  });

  it.each(['sa-key:', 'sa:'])('OpenAI creates a scoped key for the same service account (%s)', async suffix => {
    const http = new FakeHttp();
    const ctx = context(http);
    const value = `sk-svcacct-${randomBytes(32).toString('hex')}`;
    const ref = `proj_one/key_old/${suffix}svc_acct_old`;
    http.on('GET', /^https:\/\/api\.openai\.com\/v1\/organization\/projects\/proj_one\/api_keys\/key_old$/, req => {
      expect(req.headers?.Authorization === `Bearer ${ctx.credentials.OPENAI_ADMIN_KEY}`).toBe(true);
      return json(200, { id: 'key_old', scopes: ['api.models.read', 'api.responses.write'],
        owner: { type: 'service_account', service_account: { id: 'svc_acct_old' } } });
    }).on('POST', /^https:\/\/api\.openai\.com\/v1\/organization\/projects\/proj_one\/service_accounts\/svc_acct_old\/api_keys$/, req => {
      const body = JSON.parse(req.body!);
      expect(body.scopes).toEqual(['api.models.read', 'api.responses.write']);
      expect(Object.keys(body)).toEqual(['name', 'scopes']);
      expect(body.name).toMatch(/^keysentry-/);
      return json(200, { id: 'key_new', value });
    });
    const result = await openaiProvider.rotateByRef!(ref, ctx);
    expect(result.newValue === value).toBe(true);
    expect({ ...result, newValue: '<value>' }).toEqual({ newValue: '<value>', oldKeyRef: ref,
      newKeyRef: 'proj_one/key_new/sa-key:svc_acct_old', oldRevoked: false });
    expect(http.calls.map(req => req.method)).toEqual(['GET', 'POST']);
  });

  it.each(['proj_one/key_old', 'unknown', 'proj_one/key_old/user:someone', 'proj_one/key_old/sa-key:'])
    ('OpenAI refuses user or unknown reference %s before HTTP', async ref => {
      const http = new FakeHttp();
      await expect(openaiProvider.rotateByRef!(ref, context(http))).rejects.toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
      expect(http.calls).toHaveLength(0);
    });

  it.each([
    { id: 'key_other' }, { owner: { type: 'user', user: { id: 'user_one' } } },
    { owner: { type: 'service_account', service_account: { id: 'svc_acct_other' } } },
    { scopes: undefined }, { scopes: [] }, { scopes: [''] }, { scopes: ['api.responses.write\n'] },
  ])('OpenAI refuses missing scopes or mismatched ownership before mutation: %j', async patch => {
    const http = new FakeHttp().on('GET', /\/api_keys\/key_old$/, () => json(200, {
      id: 'key_old', scopes: ['api.responses.write'], owner: { type: 'service_account', service_account: { id: 'svc_acct_old' } }, ...patch,
    }));
    await expect(openaiProvider.rotateByRef!('proj_one/key_old/sa-key:svc_acct_old', context(http)))
      .rejects.toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(http.calls.every(req => req.method === 'GET')).toBe(true);
  });

  it('OpenAI does not retry scoped-create rejection with broader permissions', async () => {
    const http = new FakeHttp().on('GET', /\/api_keys\/key_old$/, () => json(200, {
      id: 'key_old', scopes: ['api.responses.write'], owner: { type: 'service_account', service_account: { id: 'svc_acct_old' } },
    })).on('POST', /\/service_accounts\/svc_acct_old\/api_keys$/, () => text(422, 'unsupported scopes'));
    await expect(openaiProvider.rotateByRef!('proj_one/key_old/sa-key:svc_acct_old', context(http)))
      .rejects.toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(http.calls.filter(req => req.method === 'POST')).toHaveLength(1);
  });

  it.each([resendProvider, awsProvider])('%s refuses unsupported reference rotation without mutation', async provider => {
    const http = new FakeHttp();
    const ctx = context(http);
    // AWS only has the current sibling pair; it is not a separate management identity.
    ctx.siblingVars = { AWS_ACCESS_KEY_ID: 'AKIA0000000000000000', AWS_SECRET_ACCESS_KEY: randomBytes(30).toString('base64') };
    await expect(provider.rotateByRef!('old-ref', ctx)).rejects.toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(http.calls).toHaveLength(0);
  });
});
