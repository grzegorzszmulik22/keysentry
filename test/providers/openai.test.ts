import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { OpenAIGuidedRotationRequiredError, openaiProvider } from '../../src/providers/openai.js';
import type { ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const secret = () => `sk-proj-${randomBytes(30).toString('hex')}`;
const context = (http: FakeHttp, admin = secret()): ProviderContext => ({
  http, credentials: { OPENAI_ADMIN_KEY: admin }, log: silentLogger,
});
const hint = (value: string) => `${value.slice(0, 12)}...${value.slice(-4)}`;
const projectsUrl = /^https:\/\/api\.openai\.com\/v1\/organization\/projects\?limit=100$/;
const keysUrl = /^https:\/\/api\.openai\.com\/v1\/organization\/projects\/proj_one\/api_keys\?limit=100$/;
function oneKey(http: FakeHttp, value: string, serviceAccount = true) {
  http.on('GET', projectsUrl, () => json(200, { object: 'list', data: [{ id: 'proj_one' }], has_more: false }));
  http.on('GET', keysUrl, () => json(200, { object: 'list', data: [{
    id: 'key_old', name: 'Production', redacted_value: hint(value), created_at: 1_700_000_000,
    owner: serviceAccount ? { type: 'service_account', service_account: { id: 'svc_acct_old', name: 'Worker' } }
      : { type: 'user', user: { id: 'user_old', email: 'owner@example.test' } },
  }], has_more: false }));
  return http;
}

describe('OpenAI provider', () => {
  it('verifies using the supplied key and treats restricted read permission as valid', async () => {
    for (const [status, ok] of [[200, true], [401, false], [403, true]] as const) {
      const value = secret();
      const http = new FakeHttp().on('GET', /^https:\/\/api\.openai\.com\/v1\/models$/, req => {
        expect(req.headers?.Authorization === `Bearer ${value}`).toBe(true);
        expect(req.body).toBeUndefined();
        expect(req.url.includes(value)).toBe(false);
        return json(status, { data: [], error: { message: value } });
      });
      const result = await openaiProvider.verify(value, context(http));
      expect(result.ok).toBe(ok);
      expect(result.status).toBe(status);
      expect(JSON.stringify(result).includes(value)).toBe(false);
      if (status === 403) expect(result.identity).toMatch(/limited|restricted/i);
    }
  });

  it('paginates projects and project keys and encodes service-account ownership in references', async () => {
    const admin = secret();
    const value = secret();
    const http = new FakeHttp()
      .on('GET', projectsUrl, () => json(200, { data: [{ id: 'proj_one' }], has_more: true, last_id: 'proj_one' }))
      .on('GET', /^https:\/\/api\.openai\.com\/v1\/organization\/projects\?limit=100&after=proj_one$/, () =>
        json(200, { data: [{ id: 'proj_two' }], has_more: false }))
      .on('GET', keysUrl, () => json(200, { data: [{ id: 'key_first', redacted_value: hint(value),
        owner: { type: 'service_account', service_account: { id: 'svc_acct_first' } } }], has_more: true, last_id: 'key_first' }))
      .on('GET', /^https:\/\/api\.openai\.com\/v1\/organization\/projects\/proj_one\/api_keys\?limit=100&after=key_first$/, () =>
        json(200, { data: [{ id: 'key_second', owner: { type: 'user', user: { id: 'user_second' } } }], has_more: false }))
      .on('GET', /^https:\/\/api\.openai\.com\/v1\/organization\/projects\/proj_two\/api_keys\?limit=100$/, () =>
        json(200, { data: [{ id: 'key_third', owner: { type: 'user', user: { id: 'user_third' } } }], has_more: false }));
    const keys = await openaiProvider.listKeys!(context(http, admin));
    expect(keys.map(key => key.keyRef)).toEqual([
      'proj_one/key_first/sa-key:svc_acct_first', 'proj_one/key_second', 'proj_two/key_third',
    ]);
    expect(http.calls.every(call => call.headers?.Authorization === `Bearer ${admin}`)).toBe(true);
    expect(http.calls.every(call => !call.url.includes(admin))).toBe(true);
    expect(JSON.stringify(keys).includes(value)).toBe(false);
  });

  it('resolves using both nonempty redacted prefix and suffix and refuses ambiguous matches', async () => {
    const value = secret();
    expect(await openaiProvider.resolveKeyRef!(value, context(oneKey(new FakeHttp(), value))))
      .toBe('proj_one/key_old/sa-key:svc_acct_old');
    const wrongSuffix = `${value.slice(0, -4)}zzzz`;
    expect(await openaiProvider.resolveKeyRef!(wrongSuffix, context(oneKey(new FakeHttp(), value)))).toBeNull();
    const wrongPrefix = `different-${value.slice(10)}`;
    expect(await openaiProvider.resolveKeyRef!(wrongPrefix, context(oneKey(new FakeHttp(), value)))).toBeNull();
    for (const redacted of ['...', `...${value.slice(-4)}`, `${value.slice(0, 12)}...`]) {
      const http = new FakeHttp().on('GET', projectsUrl, () => json(200, { data: [{ id: 'proj_one' }], has_more: false }))
        .on('GET', keysUrl, () => json(200, { data: [{ id: 'key_old', redacted_value: redacted }], has_more: false }));
      expect(await openaiProvider.resolveKeyRef!(value, context(http))).toBeNull();
    }
    const ambiguous = new FakeHttp().on('GET', projectsUrl, () => json(200, { data: [{ id: 'proj_one' }], has_more: false }))
      .on('GET', keysUrl, () => json(200, { data: [
        { id: 'key_one', redacted_value: hint(value) }, { id: 'key_two', redacted_value: hint(value) },
      ], has_more: false }));
    expect(await openaiProvider.resolveKeyRef!(value, context(ambiguous))).toBeNull();
  });

  it('creates a replacement key on the same service account and revokes only the old key', async () => {
    const value = secret();
    const newValue = secret();
    const admin = secret();
    const http = oneKey(new FakeHttp(), value).on('POST',
      /^https:\/\/api\.openai\.com\/v1\/organization\/projects\/proj_one\/service_accounts\/svc_acct_old\/api_keys$/, req => {
        expect(req.headers?.Authorization === `Bearer ${admin}`).toBe(true);
        expect(req.headers?.['Content-Type']).toBe('application/json');
        const body = JSON.parse(req.body!) as Record<string, unknown>;
        expect(Object.keys(body)).toEqual(['name']);
        expect(body.name).toMatch(/^keysentry-\d{4}-\d\d-\d\dT/);
        return json(200, { id: 'key_new', value: newValue });
      }).on('DELETE',
      /^https:\/\/api\.openai\.com\/v1\/organization\/projects\/proj_one\/api_keys\/key_old$/,
      () => json(200, { deleted: true }));
    const ctx = context(http, admin);
    const result = await openaiProvider.rotate!(value, ctx);
    expect(result.newValue === newValue).toBe(true);
    expect(result.oldKeyRef).toBe('proj_one/key_old/sa-key:svc_acct_old');
    expect(result.newKeyRef).toBe('proj_one/key_new/sa-key:svc_acct_old');
    expect(result.oldRevoked).toBe(false);
    expect(http.calls.some(call => call.method === 'DELETE')).toBe(false);
    await openaiProvider.revoke!(result.oldKeyRef!, ctx);
    expect(http.calls.filter(call => call.method === 'POST' || call.method === 'DELETE').map(call => call.url)).toEqual([
      'https://api.openai.com/v1/organization/projects/proj_one/service_accounts/svc_acct_old/api_keys',
      'https://api.openai.com/v1/organization/projects/proj_one/api_keys/key_old',
    ]);
  });

  it('requires guided rotation for user-owned keys without creating a service account', async () => {
    const value = secret();
    const newValue = secret();
    const admin = secret();
    const http = oneKey(new FakeHttp(), value, false).on('POST',
      /^https:\/\/api\.openai\.com\/v1\/organization\/projects\/proj_one\/service_accounts$/, req => {
        expect(req.headers?.Authorization === `Bearer ${admin}`).toBe(true);
        expect(req.headers?.['Content-Type']).toBe('application/json');
        expect(JSON.parse(req.body!).name).toMatch(/^keysentry-\d{4}-\d\d-\d\dT/);
        return json(200, { id: 'svc_acct_new', api_key: { id: 'key_new', value: newValue } });
      });
    let error: unknown;
    try { await openaiProvider.rotate!(value, context(http, admin)); } catch (cause) { error = cause; }
    expect(error instanceof OpenAIGuidedRotationRequiredError).toBe(true);
    expect(error).toMatchObject({ name: 'OpenAIGuidedRotationRequiredError', code: 'GUIDED_ROTATION_REQUIRED', provider: 'openai' });
    expect(String(error)).toMatch(/user|permission|guided/i);
    expect(String(error).includes(value)).toBe(false);
    expect(http.calls.every(call => call.method === 'GET')).toBe(true);
  });

  it('still resolves and revokes user-owned keys when rotation is guided', async () => {
    const value = secret();
    const http = oneKey(new FakeHttp(), value, false).on('DELETE',
      /^https:\/\/api\.openai\.com\/v1\/organization\/projects\/proj_one\/api_keys\/key_old$/,
      () => json(200, { deleted: true }));
    const ctx = context(http);
    const keyRef = await openaiProvider.resolveKeyRef!(value, ctx);
    expect(keyRef).toBe('proj_one/key_old');
    await openaiProvider.revoke!(keyRef!, ctx);
    expect(http.calls.filter(call => call.method === 'DELETE').map(call => call.url)).toEqual([
      'https://api.openai.com/v1/organization/projects/proj_one/api_keys/key_old',
    ]);
  });

  it('does not create a key when the old project cannot be resolved', async () => {
    const http = new FakeHttp().on('GET', projectsUrl, () => json(200, { data: [], has_more: false }));
    await expect(openaiProvider.rotate!(secret(), context(http))).rejects.toThrow(/resolve|project/i);
    expect(http.calls.every(call => call.method === 'GET')).toBe(true);
  });

  it('rejects malformed or unchanged replacement keys without exposing them', async () => {
    const value = secret();
    for (const replacement of [undefined, '', '   ', value]) {
      const http = oneKey(new FakeHttp(), value).on('POST', /\/service_accounts\/svc_acct_old\/api_keys$/,
        () => json(200, { id: 'key_new', value: replacement }));
      let message = '';
      try { await openaiProvider.rotate!(value, context(http)); } catch (error) { message = String(error); }
      expect(message).toMatch(/new service-account key/i);
      expect(message.includes(value)).toBe(false);
      expect(http.calls.filter(call => call.method === 'POST')).toHaveLength(1);
      expect(http.calls.some(call => call.method === 'DELETE')).toBe(false);
    }
  });

  it('revokes only the referenced key for new and legacy service-account refs and user refs', async () => {
    const admin = secret();
    const http = new FakeHttp()
      .on('DELETE', /^https:\/\/api\.openai\.com\/v1\/organization\/projects\/proj_one\/api_keys\/key_old$/, () => json(200, { deleted: true }))
      .on('DELETE', /^https:\/\/api\.openai\.com\/v1\/organization\/projects\/proj_one\/api_keys\/key_user$/, () => json(200, { deleted: true }));
    await openaiProvider.revoke!('proj_one/key_old/sa-key:svc_acct_old', context(http, admin));
    await openaiProvider.revoke!('proj_one/key_old/sa:svc_acct_old', context(http, admin));
    await openaiProvider.revoke!('proj_one/key_user', context(http, admin));
    expect(http.calls.length).toBe(3);
    expect(http.calls.every(call => /\/api_keys\/(?:key_old|key_user)$/.test(call.url))).toBe(true);
    expect(http.calls.every(call => call.headers?.Authorization === `Bearer ${admin}` && call.body === undefined)).toBe(true);
  });

  it('filters usage by key, groups models, follows pages, and estimates token cost including cache discounts', async () => {
    const http = new FakeHttp().on('GET', /^https:\/\/api\.openai\.com\/v1\/organization\/usage\/completions\?/, req => {
      const query = new URL(req.url).searchParams;
      expect(query.get('start_time')).toBe('1704067200');
      expect(query.get('end_time')).toBe('1704074400');
      expect(query.get('bucket_width')).toBe('1h');
      expect(query.get('api_key_ids')).toBe('key_old');
      expect(query.get('group_by')).toBe('model');
      return json(200, query.has('page') ? { data: [{ results: [{ model: 'gpt-4o-mini-2024-07-18',
        input_tokens: 1_000_000, output_tokens: 0, input_cached_tokens: 0, num_model_requests: 4 }] }], has_more: false }
        : { data: [{ results: [{ model: 'gpt-4o-mini', input_tokens: 1_000_000, output_tokens: 2_000_000,
          input_cached_tokens: 400_000, num_model_requests: 3 }] }], has_more: true, next_page: 'page_two' });
    });
    const sample = await openaiProvider.usage!('proj_one/key_old/sa:svc_acct_old', {
      from: new Date('2024-01-01T00:00:00Z'), to: new Date('2024-01-01T02:00:00Z'),
    }, context(http));
    expect(sample.keyRef).toBe('proj_one/key_old/sa:svc_acct_old');
    expect(sample.requests).toBe(7);
    expect(sample.costUsd).toBeCloseTo(1.47);
    expect(sample.byModel?.['gpt-4o-mini']).toBeCloseTo(1.32);
    expect(sample.byModel?.['gpt-4o-mini-2024-07-18']).toBeCloseTo(0.15);
    expect(new URL(http.calls[1]!.url).searchParams.get('page')).toBe('page_two');
  });

  it('sanitizes upstream errors, malformed responses and transport failures', async () => {
    const value = secret();
    for (const response of [json(500, { error: { message: value } }), text(200, value)]) {
      const http = new FakeHttp().on('GET', projectsUrl, () => response);
      let error: unknown;
      try { await openaiProvider.listKeys!(context(http)); } catch (cause) { error = cause; }
      expect(error instanceof Error).toBe(true);
      expect(String(error).includes(value)).toBe(false);
    }
    const http = new FakeHttp().on('GET', /^https:\/\/api\.openai\.com\/v1\/models$/, () => { throw new Error(value); });
    const result = await openaiProvider.verify(value, context(http));
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result).includes(value)).toBe(false);
  });

  it('does not expose secret-shaped upstream key names or identifiers', async () => {
    const value = secret();
    const http = new FakeHttp().on('GET', projectsUrl, () => json(200, { data: [{ id: 'proj_one' }], has_more: false }))
      .on('GET', keysUrl, () => json(200, { data: [{ id: 'key_safe', name: `Worker ${value}`, redacted_value: value }], has_more: false }));
    const listed = await openaiProvider.listKeys!(context(http));
    expect(JSON.stringify(listed).includes(value)).toBe(false);
    expect(listed[0]?.hint).toBeUndefined();
    const invalid = new FakeHttp().on('GET', projectsUrl, () => json(200, { data: [{ id: value }], has_more: false }));
    await expect(openaiProvider.listKeys!(context(invalid))).rejects.toThrow(/invalid/i);
    expect(invalid.calls.length).toBe(1);
  });

  it('estimates unpriced models at the highest rate for all tokens and warns once per model across pages', async () => {
    const warnings: { message: string; data?: Record<string, unknown> }[] = [];
    const http = new FakeHttp().on('GET', /^https:\/\/api\.openai\.com\/v1\/organization\/usage\/completions\?/, req =>
      json(200, new URL(req.url).searchParams.has('page')
        ? { data: [{ results: [
          { model: 'gpt-future', input_tokens: 500_000, input_cached_tokens: 500_000, output_tokens: 500_000, num_model_requests: 2 },
          { model: 'gpt-other', input_tokens: 0, output_tokens: 1_000_000, num_model_requests: 1 },
        ] }], has_more: false }
        : { data: [{ results: [
          { model: 'gpt-future', input_tokens: 1_000_000, input_cached_tokens: 400_000, output_tokens: 2_000_000, num_model_requests: 3 },
          { model: 'gpt-4o-mini', input_tokens: 1_000_000, output_tokens: 0, num_model_requests: 4 },
        ] }], has_more: true, next_page: 'page_two' }));
    const ctx = context(http);
    ctx.log = { ...silentLogger, warn: (message, data) => { warnings.push({ message, data }); } };
    const sample = await openaiProvider.usage!('proj_one/key_old/sa-key:svc_acct_old', {
      from: new Date('2024-01-01T00:00:00Z'), to: new Date('2024-01-01T01:00:00Z'),
    }, ctx);
    expect(sample.costUsd).toBeCloseTo(300.15);
    expect(sample.requests).toBe(10);
    expect(sample.byModel).toEqual({ 'gpt-future': 240, 'gpt-other': 60, 'gpt-4o-mini': 0.15 });
    expect(warnings).toHaveLength(2);
    for (const model of ['gpt-future', 'gpt-other']) {
      expect(warnings.filter(warning => JSON.stringify(warning).includes(model))).toHaveLength(1);
    }
  });

  it('sanitizes secret-shaped unpriced model names in usage and warnings', async () => {
    const admin = secret();
    const upstreamSecret = secret();
    const warnings: unknown[] = [];
    const http = new FakeHttp().on('GET', /\/usage\/completions\?/, () => json(200, {
      data: [{ results: [admin, upstreamSecret].map(model => ({ model, output_tokens: 1_000_000 })) }], has_more: false,
    }));
    const ctx = context(http, admin);
    ctx.log = { ...silentLogger, warn: (...args) => { warnings.push(args); } };
    const sample = await openaiProvider.usage!('proj_one/key_old', {
      from: new Date('2024-01-01T00:00:00Z'), to: new Date('2024-01-01T01:00:00Z'),
    }, ctx);
    expect(sample.costUsd).toBe(120);
    expect(sample.byModel).toEqual({ unknown: 120 });
    expect(warnings).toHaveLength(1);
    expect(JSON.stringify({ sample, warnings }).includes(admin)).toBe(false);
    expect(JSON.stringify({ sample, warnings }).includes(upstreamSecret)).toBe(false);
  });

  it('rejects invalid or looping cursors rather than silently returning incomplete key lists', async () => {
    for (const last_id of [undefined, 'proj_one']) {
      const http = new FakeHttp().on('GET', /^https:\/\/api\.openai\.com\/v1\/organization\/projects\?/, () =>
        json(200, { data: [], has_more: true, last_id }));
      await expect(openaiProvider.listKeys!(context(http))).rejects.toThrow(/pagination|cursor/i);
    }
  });
});
