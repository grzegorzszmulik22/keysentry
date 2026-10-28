import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { postmarkProvider } from '../../src/providers/postmark.js';
import type { ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const serverUrl = /^https:\/\/api\.postmarkapp\.com\/deliverystats$/;
const accountUrl = /^https:\/\/api\.postmarkapp\.com\/domains\?count=1&offset=0$/;

function setup() {
  const http = new FakeHttp();
  const value = randomUUID();
  const ctx: ProviderContext = { http, credentials: {}, log: silentLogger };
  return { http, value, ctx };
}

const leaks = (value: unknown, secret: string) => JSON.stringify(value).includes(secret);

describe('postmarkProvider', () => {
  it('verifies a server token with a server-level read that returns no tokens', async () => {
    const { http, value, ctx } = setup();
    http.on('GET', serverUrl, (req) => {
      expect(req.headers).toEqual({ Accept: 'application/json', 'X-Postmark-Server-Token': value });
      expect(req.body).toBeUndefined();
      return json(200, { InactiveMails: 0, Bounces: [{ Name: 'All', Count: 0 }] });
    });
    expect(await postmarkProvider.verify(value, ctx)).toEqual({ ok: true, status: 200, identity: 'Postmark server token' });
    expect(http.calls).toHaveLength(1);
  });

  it('falls back to an account-level read when the server endpoint rejects the token type', async () => {
    const { http, value, ctx } = setup();
    http.on('GET', serverUrl, () => json(401, { ErrorCode: 10, Message: value }))
      .on('GET', accountUrl, (req) => {
        expect(req.headers).toEqual({ Accept: 'application/json', 'X-Postmark-Account-Token': value });
        return json(200, { TotalCount: 0, Domains: [] });
      });
    expect(await postmarkProvider.verify(value, ctx)).toEqual({ ok: true, status: 200, identity: 'Postmark account token' });
    expect(http.calls).toHaveLength(2);
  });

  it('reports a token rejected by both endpoints as invalid', async () => {
    const { http, value, ctx } = setup();
    http.on('GET', serverUrl, () => json(401, { ErrorCode: 10, Message: value }))
      .on('GET', accountUrl, () => json(401, { ErrorCode: 10, Message: value }));
    const result = await postmarkProvider.verify(value, ctx);
    expect(result.ok).toBe(false);
    expect(result.status).toBe(401);
    expect(leaks(result, value)).toBe(false);
  });

  it('does not try the account endpoint after a non-authentication failure', async () => {
    const { http, value, ctx } = setup();
    http.on('GET', serverUrl, () => json(500, { Message: value }));
    const result = await postmarkProvider.verify(value, ctx);
    expect(result.ok).toBe(false);
    expect(result.status).toBe(500);
    expect(http.calls).toHaveLength(1);
  });

  it('sanitizes malformed responses and transport failures', async () => {
    for (const kind of ['text', 'shape', 'transport', 'account-shape'] as const) {
      const { http, value, ctx } = setup();
      http.on('GET', serverUrl, () => {
        if (kind === 'transport') throw new Error(value);
        if (kind === 'text') return text(200, value);
        if (kind === 'shape') return json(200, { ApiTokens: [value] });
        return json(401, {});
      }).on('GET', accountUrl, () => json(200, { Servers: [{ ApiTokens: [value] }] }));
      const result = await postmarkProvider.verify(value, ctx);
      expect(result.ok).toBe(false);
      expect(leaks(result, value)).toBe(false);
    }
  });

  it('is guided because Postmark documents no token create or delete API', () => {
    expect(postmarkProvider.id).toBe('postmark');
    expect(postmarkProvider.method).toBe('guided');
    expect(postmarkProvider.rotate).toBeUndefined();
    expect(postmarkProvider.revoke).toBeUndefined();
    const guidance = postmarkProvider.guidance();
    expect(guidance.url).toBe('https://account.postmarkapp.com/servers');
    expect(guidance.steps.join(' ')).toMatch(/Generate New/);
    expect(guidance.steps.join(' ')).toMatch(/account API token/i);
  });
});
