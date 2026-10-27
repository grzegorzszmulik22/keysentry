import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { openrouterProvider } from '../../src/providers/openrouter.js';
import type { ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger } from '../helpers/fake-http.js';

function setup() {
  const admin = `sk-or-v1-${randomBytes(32).toString('hex')}`;
  const http = new FakeHttp();
  const ctx: ProviderContext = { http, credentials: { OPENROUTER_PROVISIONING_KEY: admin }, log: silentLogger };
  return { admin, http, ctx };
}

describe('OpenRouter spending limits', () => {
  it.each([0, 17.25])('updates only the requested key limit to %s USD with management auth', async (limit) => {
    const { admin, http, ctx } = setup();
    expect(typeof openrouterProvider.setLimit).toBe('function');
    http.on('PATCH', /^https:\/\/openrouter\.ai\/api\/v1\/keys\/key-hash$/, (req) => {
      expect(req.headers?.Authorization === `Bearer ${admin}`).toBe(true);
      expect(req.headers?.['Content-Type']).toBe('application/json');
      expect(JSON.parse(req.body!)).toEqual({ limit });
      return json(200, { data: { hash: 'key-hash', limit } });
    });
    await openrouterProvider.setLimit('key-hash', limit, ctx);
    expect(http.calls.length).toBe(1);
  });

  it.each([-1, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('refuses invalid limit %s before HTTP', async (limit) => {
    const { http, ctx } = setup();
    await expect(openrouterProvider.setLimit('key-hash', limit, ctx)).rejects.toThrow('spending limit');
    expect(http.calls.length).toBe(0);
  });

  it('refuses malformed or secret key references without echoing them', async () => {
    const { admin, http, ctx } = setup();
    const value = `sk-or-v1-${randomBytes(32).toString('hex')}`;
    for (const ref of ['', '../another-key', 'hash?limit=0', admin, value]) {
      let message = '';
      try {
        await openrouterProvider.setLimit(ref, 10, ctx);
      } catch (error) {
        message = error instanceof Error ? error.message : String(error);
      }
      expect(message).toBe('OpenRouter returned an invalid key reference');
      expect(message.includes(admin)).toBe(false);
      expect(message.includes(value)).toBe(false);
    }
    expect(http.calls.length).toBe(0);
  });

  it('requires the management credential before HTTP', async () => {
    const { http, ctx } = setup();
    await expect(openrouterProvider.setLimit('key-hash', 10, { ...ctx, credentials: {} }))
      .rejects.toThrow('Missing provider credential: OPENROUTER_PROVISIONING_KEY');
    expect(http.calls.length).toBe(0);
  });

  it.each(['http', 'transport'] as const)('keeps %s failures free of credentials and provider bodies', async (kind) => {
    const { admin, http, ctx } = setup();
    const value = `sk-or-v1-${randomBytes(32).toString('hex')}`;
    http.on('PATCH', /\/keys\/key-hash$/, () => {
      if (kind === 'transport') throw new Error(`${admin} ${value}`);
      return json(403, { error: `${admin} ${value}` });
    });
    let message = '';
    try {
      await openrouterProvider.setLimit('key-hash', 10, ctx);
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toBe(kind === 'http' ? 'OpenRouter request failed (HTTP 403)' : 'OpenRouter request failed');
    expect(message.includes(admin)).toBe(false);
    expect(message.includes(value)).toBe(false);
  });
});
