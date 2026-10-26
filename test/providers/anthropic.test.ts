import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { anthropicProvider } from '../../src/providers/anthropic.js';
import type { ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const secret = () => `sk-ant-api03-${randomBytes(32).toString('hex')}`;
const context = (http: FakeHttp, admin = secret()): ProviderContext => ({
  http, credentials: { ANTHROPIC_ADMIN_KEY: admin }, log: silentLogger,
});

describe('anthropic provider', () => {
  it('verifies with the supplied key and Anthropic version header', async () => {
    const key = secret();
    const http = new FakeHttp().on('GET', /^https:\/\/api\.anthropic\.com\/v1\/models$/, req => {
      expect(req.headers?.['x-api-key'] === key).toBe(true);
      expect(req.headers?.['anthropic-version']).toBe('2023-06-01');
      return json(200, { data: [], has_more: false, first_id: null, last_id: null });
    });
    const result = await anthropicProvider.verify(key, context(http));
    expect(result.ok).toBe(true);
    expect(result.status).toBe(200);
    expect(JSON.stringify(result).includes(key)).toBe(false);
  });

  it.each([401, 403, 500])('handles verify status %s without returning upstream errors', async status => {
    const key = secret();
    const http = new FakeHttp().on('GET', /\/models$/, () => json(status, { error: { message: key } }));
    const result = await anthropicProvider.verify(key, context(http));
    expect(result.ok).toBe(status === 403);
    expect(result.status).toBe(status);
    if (status === 403) expect(result.identity).toMatch(/limited/i);
    expect(JSON.stringify(result).includes(key)).toBe(false);
  });

  it('lists active keys across pages and protects secret-bearing names and hints', async () => {
    const admin = secret();
    const unexpectedSecret = secret();
    const http = new FakeHttp().on('GET', /\/organizations\/api_keys\?/, req => {
      const url = new URL(req.url);
      expect(req.headers?.['x-api-key'] === admin).toBe(true);
      expect(req.headers?.['anthropic-version']).toBe('2023-06-01');
      expect(url.searchParams.get('limit')).toBe('100');
      expect(url.searchParams.get('status')).toBe('active');
      if (!url.searchParams.has('after_id')) return json(200, {
        data: [{ id: 'apikey_first', name: 'production', status: 'active', created_at: '2026-01-01T00:00:00Z', partial_key_hint: 'sk-ant-api03-alpha...1234' }],
        has_more: true, first_id: 'apikey_first', last_id: 'apikey_first',
      });
      expect(url.searchParams.get('after_id')).toBe('apikey_first');
      return json(200, {
        data: [{ id: 'apikey_second', name: unexpectedSecret, status: 'active', created_at: '2026-01-02T00:00:00Z', partial_key_hint: unexpectedSecret }],
        has_more: false, first_id: 'apikey_second', last_id: 'apikey_second',
      });
    });
    const keys = await anthropicProvider.listKeys!(context(http, admin));
    expect(keys.map(key => key.keyRef)).toEqual(['apikey_first', 'apikey_second']);
    expect(keys[0]?.name).toBe('production');
    expect(keys[0]?.hint).toBe('sk-ant-…1234');
    expect(JSON.stringify(keys).includes(unexpectedSecret)).toBe(false);
    expect(JSON.stringify(keys).includes(admin)).toBe(false);
    expect(http.calls.length).toBe(2);
  });

  it('matches both hint ends and returns null when more than one key matches', async () => {
    const key = secret();
    const prefix = key.slice(0, 20);
    const suffix = key.slice(-4);
    const http = new FakeHttp().on('GET', /\/organizations\/api_keys\?/, () => json(200, {
      data: [
        { id: 'apikey_wrong', partial_key_hint: `${prefix}...zzzz`, status: 'active' },
        { id: 'apikey_match', partial_key_hint: `${prefix}...${suffix}`, status: 'active' },
      ], has_more: false,
    }));
    expect(await anthropicProvider.resolveKeyRef!(key, context(http))).toBe('apikey_match');
    const ambiguous = new FakeHttp().on('GET', /\/organizations\/api_keys\?/, () => json(200, {
      data: [{ id: 'apikey_one', partial_key_hint: `${prefix}...${suffix}` }, { id: 'apikey_two', partial_key_hint: `${prefix}...${suffix}` }], has_more: false,
    }));
    expect(await anthropicProvider.resolveKeyRef!(key, context(ambiguous))).toBeNull();
  });

  it('rejects incomplete hints rather than matching a suffix alone', async () => {
    const key = secret();
    const http = new FakeHttp().on('GET', /\/organizations\/api_keys\?/, () => json(200, {
      data: [{ id: 'apikey_bad', partial_key_hint: `...${key.slice(-4)}` }], has_more: false,
    }));
    expect(await anthropicProvider.resolveKeyRef!(key, context(http))).toBeNull();
  });

  it('revokes and caps by posting inactive without transmitting a key value', async () => {
    const admin = secret();
    const http = new FakeHttp().on('POST', /^https:\/\/api\.anthropic\.com\/v1\/organizations\/api_keys\/apikey_one$/, req => {
      expect(req.headers?.['x-api-key'] === admin).toBe(true);
      expect(req.headers?.['content-type']).toBe('application/json');
      expect(JSON.parse(req.body ?? '{}')).toEqual({ status: 'inactive' });
      return json(200, { id: 'apikey_one', status: 'inactive' });
    });
    await anthropicProvider.revoke!('apikey_one', context(http, admin));
    await anthropicProvider.cap!('apikey_one', context(http, admin));
    expect(http.calls.length).toBe(2);
  });

  it('estimates paginated model spend from input, output and cached tokens', async () => {
    const admin = secret();
    const http = new FakeHttp().on('GET', /\/usage_report\/messages\?/, req => {
      const url = new URL(req.url);
      expect(req.headers?.['x-api-key'] === admin).toBe(true);
      expect(url.searchParams.get('starting_at')).toBe('2026-01-01T00:00:00.000Z');
      expect(url.searchParams.get('ending_at')).toBe('2026-01-01T02:00:00.000Z');
      expect(url.searchParams.get('bucket_width')).toBe('1h');
      expect(url.searchParams.getAll('api_key_ids[]')).toEqual(['apikey_one']);
      expect(url.searchParams.getAll('group_by[]')).toEqual(['model']);
      if (!url.searchParams.has('page')) return json(200, {
        data: [{ starting_at: '2026-01-01T00:00:00Z', ending_at: '2026-01-01T01:00:00Z', results: [{ model: 'claude-sonnet-4-20250514', uncached_input_tokens: 1_000_000, output_tokens: 1_000_000, cache_read_input_tokens: 1_000_000, cache_creation_input_tokens: 1_000_000 }] }],
        has_more: true, next_page: 'page_two',
      });
      expect(url.searchParams.get('page')).toBe('page_two');
      return json(200, {
        data: [{ starting_at: '2026-01-01T01:00:00Z', ending_at: '2026-01-01T02:00:00Z', results: [{ model: 'claude-3-5-haiku-20241022', uncached_input_tokens: 1_000_000, output_tokens: 1_000_000, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 }] }],
        has_more: false, next_page: null,
      });
    });
    const usage = await anthropicProvider.usage!('apikey_one', { from: new Date('2026-01-01T00:00:00Z'), to: new Date('2026-01-01T02:00:00Z') }, context(http, admin));
    expect(usage.costUsd).toBeCloseTo(26.85);
    expect(usage.byModel).toEqual({ 'claude-sonnet-4-20250514': 22.05, 'claude-3-5-haiku-20241022': 4.8 });
    expect(usage.keyRef).toBe('apikey_one');
    expect(http.calls.length).toBe(2);
  });

  it('fails safely on malformed JSON, transport errors and missing credentials', async () => {
    const key = secret();
    const badJson = new FakeHttp().on('GET', /\/organizations\/api_keys\?/, () => text(200, key));
    const throwing = new FakeHttp().on('GET', /\/organizations\/api_keys\?/, () => { throw new Error(key); });
    for (const http of [badJson, throwing]) {
      let message = '';
      try { await anthropicProvider.listKeys!(context(http)); } catch (error) { message = String(error); }
      expect(message.length > 0).toBe(true);
      expect(message.includes(key)).toBe(false);
    }
    await expect(anthropicProvider.listKeys!({ http: new FakeHttp(), credentials: {}, log: silentLogger })).rejects.toThrow(/ANTHROPIC_ADMIN_KEY/);
  });

  it('does not apply a related model price to an unknown model generation', async () => {
    const http = new FakeHttp().on('GET', /\/usage_report\/messages\?/, () => json(200, {
      data: [{ results: [{ model: 'claude-sonnet-4-unknown', uncached_input_tokens: 1_000_000, output_tokens: 0 }] }], has_more: false,
    }));
    await expect(anthropicProvider.usage!('apikey_one', {
      from: new Date('2026-01-01T00:00:00Z'), to: new Date('2026-01-01T01:00:00Z'),
    }, context(http))).rejects.toThrow(/price estimate/);
  });

  it('rejects malformed usage windows before issuing a request', async () => {
    const http = new FakeHttp();
    await expect(anthropicProvider.usage!('apikey_one', {
      from: new Date('2026-01-01T01:00:00Z'), to: new Date('2026-01-01T00:00:00Z'),
    }, context(http))).rejects.toThrow(/window/);
    expect(http.calls.length).toBe(0);
  });

  it.each(['keys', 'usage'])('rejects malformed %s pagination flags', async operation => {
    const http = new FakeHttp().on('GET', /\/organizations\//, () => json(200, {
      data: [], has_more: 'false', last_id: 'apikey_one', next_page: 'page_two',
    }));
    const call = operation === 'keys'
      ? anthropicProvider.listKeys!(context(http))
      : anthropicProvider.usage!('apikey_one', {
        from: new Date('2026-01-01T00:00:00Z'), to: new Date('2026-01-01T01:00:00Z'),
      }, context(http));
    await expect(call).rejects.toThrow(/pagination/);
  });

  it('never puts an echoed admin credential into a usage pagination URL', async () => {
    const admin = randomBytes(32).toString('base64url');
    const http = new FakeHttp().on('GET', /\/usage_report\/messages\?/, () => json(200, {
      data: [], has_more: true, next_page: admin,
    }));
    let message = '';
    try {
      await anthropicProvider.usage!('apikey_one', {
        from: new Date('2026-01-01T00:00:00Z'), to: new Date('2026-01-01T01:00:00Z'),
      }, context(http, admin));
    } catch (error) { message = String(error); }
    expect(message.length > 0).toBe(true);
    expect(message.includes(admin)).toBe(false);
    expect(http.calls.length).toBe(1);
    expect(http.calls.some(call => call.url.includes(admin))).toBe(false);
  });

  it('stops repeated pagination and rejects secret values passed as key refs', async () => {
    const http = new FakeHttp().on('GET', /\/organizations\/api_keys\?/, () => json(200, {
      data: [{ id: 'apikey_one', partial_key_hint: 'sk-ant-...1234' }], has_more: true, last_id: 'apikey_one',
    }));
    await expect(anthropicProvider.listKeys!(context(http))).rejects.toThrow(/pagination/i);
    expect(http.calls.length).toBe(2);
    const key = secret();
    const noCalls = new FakeHttp();
    let message = '';
    try { await anthropicProvider.revoke!(key, context(noCalls)); } catch (error) { message = String(error); }
    expect(message.length > 0).toBe(true);
    expect(message.includes(key)).toBe(false);
    expect(noCalls.calls.length).toBe(0);
  });

  it('offers guided rotation and explains that containment disables consumers', () => {
    expect(anthropicProvider.method).toBe('guided');
    expect(anthropicProvider.rotate).toBeUndefined();
    expect(anthropicProvider.guidance().url).toBe('https://console.anthropic.com/settings/keys');
    expect(anthropicProvider.guidance().steps.join(' ')).toMatch(/(break|interrupt|stop).*consumer/i);
  });
});
