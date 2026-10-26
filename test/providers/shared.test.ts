import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';
import { credential, ensureOk, matchHint, readJson, request, safeIdentity, verifyRead } from '../../src/providers/shared.js';

function context(http = new FakeHttp()): ProviderContext {
  return { http, credentials: {}, log: silentLogger };
}

describe('provider HTTP safety', () => {
  it('replaces transport and parse exceptions without retaining their secret or cause', async () => {
    const secret = randomBytes(32).toString('base64url');
    const http = new FakeHttp().on('GET', /^https:\/\/example\.test\/$/, () => { throw new Error(secret); });
    let error: unknown;
    try { await request(context(http), { method: 'GET', url: 'https://example.test/' }, 'example'); }
    catch (caught) { error = caught; }
    expect(error instanceof Error).toBe(true);
    expect(String(error).includes(secret)).toBe(false);
    expect((error as Error).cause).toBeUndefined();
    try { readJson(text(200, secret), 'example'); }
    catch (caught) { error = caught; }
    expect(String(error).includes(secret)).toBe(false);
    expect((error as Error).cause).toBeUndefined();
  });

  it('reports only the status on upstream HTTP errors', () => {
    const secret = randomBytes(32).toString('hex');
    try { ensureOk(json(500, { error: secret }), 'example'); }
    catch (error) {
      expect(String(error)).toContain('500');
      expect(String(error).includes(secret)).toBe(false);
      return;
    }
    throw new Error('Expected HTTP rejection');
  });

  it('refuses known or recognizable credentials in URLs before network dispatch', async () => {
    const secret = randomBytes(32).toString('base64');
    const otherSecret = `re_${randomBytes(32).toString('base64url')}`;
    for (const value of [secret, otherSecret]) {
      const http = new FakeHttp();
      const ctx = { ...context(http), credentials: { EXAMPLE_ADMIN_KEY: secret } };
      let rejected = false;
      try { await request(ctx, { method: 'DELETE', url: `https://example.test/keys/${encodeURIComponent(value)}` }, 'example'); }
      catch (error) {
        rejected = true;
        expect(String(error).includes(value)).toBe(false);
      }
      expect(rejected).toBe(true);
      expect(http.calls.length).toBe(0);
    }
  });

  it.each([
    [200, true, 'account'],
    [401, false, undefined],
    [403, true, 'example (limited)'],
    [500, false, undefined],
  ] as const)('maps read verification status %i safely', async (status, ok, identity) => {
    const secret = randomBytes(32).toString('base64url');
    const http = new FakeHttp().on('GET', /^https:\/\/example\.test\/$/, req => {
      expect(req.method).toBe('GET');
      expect(req.url).toBe('https://example.test/');
      expect(req.headers?.Authorization === `Bearer ${secret}`).toBe(true);
      expect(req.body).toBeUndefined();
      return json(status, { name: 'account', error: secret });
    });
    const result = await verifyRead(context(http), { method: 'GET', url: 'https://example.test/', headers: { Authorization: `Bearer ${secret}` } }, 'example', data => (data as { name: string }).name);
    expect(result).toEqual({ ok, identity, status, ...(ok ? {} : { error: `example verification failed (HTTP ${status})` }) });
    expect(JSON.stringify(result).includes(secret)).toBe(false);
  });

  it('rejects restricted responses when limited access is not sufficient', async () => {
    const http = new FakeHttp().on('GET', /.*/, () => json(403, {}));
    const result = await verifyRead(context(http), { method: 'GET', url: 'https://example.test/' }, 'example', () => 'account', false);
    expect(result.ok).toBe(false);
  });

  it('does not expose a reflected auth value in an identity', async () => {
    const secret = randomBytes(32).toString('base64url');
    const http = new FakeHttp().on('GET', /.*/, () => json(200, { name: secret }));
    const result = await verifyRead(context(http), { method: 'GET', url: 'https://example.test/', headers: { 'x-api-key': secret } }, 'example', data => (data as { name: string }).name);
    expect(result.identity).toBe('example');
    expect(safeIdentity(`account ${secret}`, 'account', [secret])).toBe('account');
  });

  it('omits recognizable key values reflected from unrelated provider metadata', () => {
    const secret = `sk-proj-${randomBytes(32).toString('base64url')}`;
    expect(safeIdentity(`account ${secret}`, 'account') === 'account').toBe(true);
    expect(safeIdentity('sk-proj-abc...wxyz', 'account')).toBe('sk-proj-abc...wxyz');
  });

  it('does not pass malformed success responses through verification', async () => {
    const http = new FakeHttp().on('GET', /.*/, () => text(200, '{'));
    const result = await verifyRead(context(http), { method: 'GET', url: 'https://example.test/' }, 'example', () => 'account');
    expect(result.ok).toBe(false);
    expect(result.error).toBe('example verification failed');
  });

  it('fails before making a request when a management credential is missing', () => {
    expect(() => credential(context(), 'EXAMPLE_ADMIN_KEY')).toThrow('Missing provider credential: EXAMPLE_ADMIN_KEY');
  });
});

describe('provider redacted hints', () => {
  it('requires matching prefixes and suffixes and rejects unredacted prefix-only hints', () => {
    const value = randomBytes(32).toString('hex');
    const prefix = value.slice(0, 6);
    const suffix = value.slice(-4);
    expect(matchHint(value, `${prefix}...${suffix}`)).toBe(true);
    expect(matchHint(value, `${prefix}…${suffix}`)).toBe(true);
    expect(matchHint(value, `${prefix}****${suffix}`)).toBe(true);
    expect(matchHint(value, `wrong...${suffix}`)).toBe(false);
    expect(matchHint(value, `${prefix}...wrong`)).toBe(false);
    expect(matchHint(value, `${prefix}...`)).toBe(false);
    expect(matchHint(value, `...${suffix}`)).toBe(false);
    expect(matchHint(value, prefix)).toBe(false);
  });
});
