import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createCanaryKey, openrouterProvider } from '../../src/providers/openrouter.js';
import type { ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

function setup() {
  const value = `sk-or-v1-${randomBytes(32).toString('hex')}`;
  const admin = `sk-or-v1-${randomBytes(32).toString('hex')}`;
  const http = new FakeHttp();
  const ctx: ProviderContext = { http, credentials: { OPENROUTER_PROVISIONING_KEY: admin }, log: silentLogger };
  return { value, admin, http, ctx };
}

function listed(hash: string, overrides: Record<string, unknown> = {}) {
  return { hash, name: 'production', label: 'sk-or-v1-aaa...bbbb', disabled: false, limit: 12, usage: 4.5, ...overrides };
}

async function errorMessage(operation: () => Promise<unknown>): Promise<string> {
  try {
    await operation();
    return '';
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

describe('OpenRouter provider', () => {
  it('verifies with the key itself and returns its label', async () => {
    const { value, admin, ctx, http } = setup();
    http.on('GET', /^https:\/\/openrouter\.ai\/api\/v1\/key$/, (req) => {
      expect(req.headers?.Authorization === `Bearer ${value}`).toBe(true);
      expect(req.headers?.Authorization === `Bearer ${admin}`).toBe(false);
      expect(req.body).toBeUndefined();
      return json(200, { data: { label: 'production key' } });
    });
    expect(await openrouterProvider.verify(value, ctx)).toEqual({ ok: true, status: 200, identity: 'production key' });
  });

  it.each([401, 403])('reports HTTP %i according to read-key verification rules', async (status) => {
    const { value, ctx, http } = setup();
    http.on('GET', /\/key$/, () => json(status, { error: { message: value } }));
    const result = await openrouterProvider.verify(value, ctx);
    expect(result.ok).toBe(status === 403);
    expect(result.status).toBe(status);
    if (status === 403) expect(result.identity).toMatch(/limit|restrict/i);
    expect(JSON.stringify(result).includes(value)).toBe(false);
  });

  it('sanitizes verify transport, JSON parse, and malicious identity failures', async () => {
    for (const kind of ['transport', 'parse', 'identity'] as const) {
      const { value, admin, ctx, http } = setup();
      http.on('GET', /\/key$/, () => {
        if (kind === 'transport') throw new Error(`${value} ${admin}`);
        if (kind === 'parse') return text(200, `${value} ${admin}`);
        return json(200, { data: { label: `${value} ${admin}` } });
      });
      const result = await openrouterProvider.verify(value, ctx);
      expect(result.ok).toBe(kind === 'identity');
      expect(JSON.stringify(result).includes(value)).toBe(false);
      expect(JSON.stringify(result).includes(admin)).toBe(false);
    }
  });

  it('lists all pages with admin auth and maps key metadata', async () => {
    const { ctx, http, admin } = setup();
    http.on('GET', /^https:\/\/openrouter\.ai\/api\/v1\/keys\?include_disabled=true$/, (req) => {
      expect(req.headers?.Authorization === `Bearer ${admin}`).toBe(true);
      return json(200, { data: Array.from({ length: 100 }, (_, i) => listed(`hash-${i}`)) });
    });
    http.on('GET', /^https:\/\/openrouter\.ai\/api\/v1\/keys\?include_disabled=true&offset=100$/, (req) => {
      expect(req.headers?.Authorization === `Bearer ${admin}`).toBe(true);
      return json(200, { data: [listed('last-hash', { name: 'last', disabled: true, limit: null, created_at: '2026-10-01T00:00:00Z' })] });
    });
    const keys = await openrouterProvider.listKeys!(ctx);
    expect(keys.length).toBe(101);
    expect(keys[100]).toEqual({ keyRef: 'last-hash', name: 'last', hint: 'sk-or-v1-aaa...bbbb', disabled: true, limitUsd: null, createdAt: '2026-10-01T00:00:00Z' });
  });

  it('resolves a key by the authenticated label rather than matching the value to a hint', async () => {
    const { value, ctx, http } = setup();
    http.on('GET', /\/key$/, () => json(200, { data: { label: 'opaque-label' } }));
    http.on('GET', /\/keys\?include_disabled=true$/, () => json(200, { data: [listed('other'), listed('old-hash', { label: 'opaque-label' })] }));
    expect(await openrouterProvider.resolveKeyRef!(value, ctx) === 'old-hash').toBe(true);
  });

  it('does not guess a key ref from ambiguous or missing labels', async () => {
    for (const labels of [['opaque-label', 'opaque-label'], ['other']]) {
      const { value, ctx, http } = setup();
      http.on('GET', /\/key$/, () => json(200, { data: { label: 'opaque-label' } }));
      http.on('GET', /\/keys\?include_disabled=true$/, () => json(200, { data: labels.map((label, i) => listed(`hash-${i}`, { label })) }));
      expect(await openrouterProvider.resolveKeyRef!(value, ctx) === null).toBe(true);
    }
  });

  it('creates a replacement with the old spending limit and leaves the old key active', async () => {
    const { value, ctx, http, admin } = setup();
    const nextValue = `sk-or-v1-${randomBytes(32).toString('hex')}`;
    http.on('GET', /\/key$/, (req) => {
      expect(req.headers?.Authorization === `Bearer ${value}`).toBe(true);
      return json(200, { data: { label: 'old-label' } });
    });
    http.on('GET', /\/keys\?include_disabled=true$/, () => json(200, { data: [listed('old-hash', { label: 'old-label', limit: 17.25 })] }));
    http.on('POST', /^https:\/\/openrouter\.ai\/api\/v1\/keys$/, (req) => {
      expect(req.headers?.Authorization === `Bearer ${admin}`).toBe(true);
      expect(req.headers?.['Content-Type']).toBe('application/json');
      const body = JSON.parse(req.body!);
      expect(body.name).toMatch(/^keysentry-/);
      expect(body.limit).toBe(17.25);
      expect(Object.keys(body).sort()).toEqual(['limit', 'name']);
      return json(200, { key: nextValue, data: { hash: 'new-hash' } });
    });
    const result = await openrouterProvider.rotate!(value, ctx);
    expect(result.newValue === nextValue).toBe(true);
    expect(result.oldKeyRef === 'old-hash').toBe(true);
    expect(result.newKeyRef === 'new-hash').toBe(true);
    expect(result.oldRevoked).toBe(false);
    expect(http.calls.some((req) => req.method === 'DELETE' || req.method === 'PATCH')).toBe(false);
  });

  it('keeps null limits unlimited and stops if the old key cannot be identified', async () => {
    for (const label of ['old-label', 'unmatched']) {
      const { value, ctx, http } = setup();
      http.on('GET', /\/key$/, () => json(200, { data: { label } }));
      http.on('GET', /\/keys\?include_disabled=true$/, () => json(200, { data: [listed('old-hash', { label: 'old-label', limit: null })] }));
      http.on('POST', /\/keys$/, (req) => {
        expect(JSON.parse(req.body!).limit).toBeNull();
        return json(200, { key: `sk-or-v1-${randomBytes(32).toString('hex')}`, data: { hash: 'new-hash' } });
      });
      if (label === 'old-label') {
        expect((await openrouterProvider.rotate!(value, ctx)).oldKeyRef === 'old-hash').toBe(true);
      } else {
        expect((await errorMessage(() => openrouterProvider.rotate!(value, ctx))).length > 0).toBe(true);
        expect(http.calls.some((req) => req.method === 'POST')).toBe(false);
      }
    }
  });

  it('creates a canary with a $0.01 limit', async () => {
    const { ctx, http, admin } = setup();
    const canaryValue = `sk-or-v1-${randomBytes(32).toString('hex')}`;
    http.on('POST', /^https:\/\/openrouter\.ai\/api\/v1\/keys$/, (req) => {
      expect(req.headers?.Authorization === `Bearer ${admin}`).toBe(true);
      expect(JSON.parse(req.body!)).toEqual({ name: 'fallback-key', limit: 0.01 });
      return json(201, { key: canaryValue, data: { hash: 'canary-hash' } });
    });
    const result = await createCanaryKey(ctx, 'fallback-key');
    expect(result.value === canaryValue).toBe(true);
    expect(result.keyRef === 'canary-hash').toBe(true);
  });

  it('revokes and caps the specified provider ref using management auth', async () => {
    const { ctx, http, admin } = setup();
    http.on('DELETE', /^https:\/\/openrouter\.ai\/api\/v1\/keys\/old-hash$/, (req) => {
      expect(req.headers?.Authorization === `Bearer ${admin}`).toBe(true);
      expect(req.body).toBeUndefined();
      return json(200, { deleted: true });
    });
    http.on('PATCH', /^https:\/\/openrouter\.ai\/api\/v1\/keys\/old-hash$/, (req) => {
      expect(req.headers?.Authorization === `Bearer ${admin}`).toBe(true);
      expect(JSON.parse(req.body!)).toEqual({ disabled: true });
      return json(200, { data: listed('old-hash', { disabled: true }) });
    });
    await openrouterProvider.revoke!('old-hash', ctx);
    await openrouterProvider.cap!('old-hash', ctx);
    expect(http.calls.map(({ method }) => method)).toEqual(['DELETE', 'PATCH']);
  });

  it('reports lifetime usage separately so the monitor can calculate deltas', async () => {
    const { ctx, http } = setup();
    http.on('GET', /\/keys\?include_disabled=true$/, () => json(200, { data: [listed('old-hash', { usage: 49.125 })] }));
    expect(await openrouterProvider.usage!('old-hash', { from: new Date('2026-10-25T00:00:00Z'), to: new Date('2026-10-26T00:00:00Z') }, ctx)).toEqual({
      keyRef: 'old-hash', from: '2026-10-25T00:00:00.000Z', to: '2026-10-26T00:00:00.000Z', costUsd: 0, cumulativeCostUsd: 49.125,
    });
  });

  it('does not report a missing or invalid usage counter as zero spend', async () => {
    for (const rows of [[], [listed('old-hash', { usage: -1 })], [listed('old-hash', { usage: '49' })]]) {
      const { ctx, http } = setup();
      http.on('GET', /\/keys\?include_disabled=true$/, () => json(200, { data: rows }));
      const message = await errorMessage(() => openrouterProvider.usage!('old-hash', { from: new Date(), to: new Date() }, ctx));
      expect(message.length > 0).toBe(true);
    }
  });

  it('sanitizes management HTTP, transport, and JSON failures', async () => {
    for (const kind of ['http', 'transport', 'parse'] as const) {
      const { value, admin, ctx, http } = setup();
      http.on('GET', /\/keys\?include_disabled=true$/, () => {
        if (kind === 'transport') throw new Error(`${value} ${admin}`);
        if (kind === 'parse') return text(200, `${value} ${admin}`);
        return json(401, { error: `${value} ${admin}` });
      });
      const message = await errorMessage(() => openrouterProvider.listKeys!(ctx));
      expect(message.length > 0).toBe(true);
      expect(message.includes(value)).toBe(false);
      expect(message.includes(admin)).toBe(false);
    }
  });

  it('validates management credentials and malformed key-creation payloads', async () => {
    const { ctx, http, admin } = setup();
    const missingCtx = { ...ctx, credentials: {} };
    expect((await errorMessage(() => createCanaryKey(missingCtx, 'fallback'))).length > 0).toBe(true);
    expect(http.calls.length).toBe(0);
    http.on('POST', /\/keys$/, () => json(200, { key: admin, data: {} }));
    const message = await errorMessage(() => createCanaryKey(ctx, 'fallback'));
    expect(message.length > 0).toBe(true);
    expect(message.includes(admin)).toBe(false);
  });

  it('rejects a full API key exposed as a provider reference before returning or using it', async () => {
    const { ctx, http } = setup();
    const unexpectedValue = `sk-or-v1-${randomBytes(32).toString('hex')}`;
    http.on('GET', /\/keys\?include_disabled=true$/, () => json(200, { data: [listed(unexpectedValue)] }));
    const message = await errorMessage(() => openrouterProvider.listKeys!(ctx));
    expect(message.length > 0).toBe(true);
    expect(message.includes(unexpectedValue)).toBe(false);
    const revokeMessage = await errorMessage(() => openrouterProvider.revoke!(unexpectedValue, ctx));
    expect(revokeMessage.length > 0).toBe(true);
    expect(http.calls.some((req) => req.method === 'DELETE')).toBe(false);
  });

  it('omits full key values echoed as list metadata', async () => {
    const { ctx, http } = setup();
    const unexpectedValue = `sk-or-v1-${randomBytes(32).toString('hex')}`;
    http.on('GET', /\/keys\?include_disabled=true$/, () => json(200, { data: [listed('hash', { name: unexpectedValue, label: unexpectedValue })] }));
    const keys = await openrouterProvider.listKeys!(ctx);
    expect(keys.length).toBe(1);
    expect(JSON.stringify(keys).includes(unexpectedValue)).toBe(false);
    expect(keys[0]?.name === undefined).toBe(true);
    expect(keys[0]?.hint === undefined).toBe(true);
  });
});
