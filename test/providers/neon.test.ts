import { randomBytes, randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { NeonGuidedRotationRequiredError, neonProvider } from '../../src/providers/neon.js';
import type { ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const apiKey = () => `napi_${randomBytes(32).toString('hex')}`;
const authUrl = /^https:\/\/console\.neon\.tech\/api\/v2\/auth$/;
const keysUrl = /^https:\/\/console\.neon\.tech\/api\/v2\/api_keys$/;
const keyUrl = (id: string | number) => new RegExp(`^https://console\\.neon\\.tech/api/v2/api_keys/${id}$`);

interface Setup { http: FakeHttp; ctx: ProviderContext; oldValue: string; admin: string; user: string }

function setup(): Setup {
  const http = new FakeHttp();
  const oldValue = apiKey();
  const admin = apiKey();
  return { http, oldValue, admin, user: randomUUID(), ctx: { http, credentials: { NEON_ADMIN_KEY: admin }, log: silentLogger } };
}

function authRoutes(s: Setup, old: Record<string, unknown> = {}, admin: Record<string, unknown> = {}) {
  s.http.on('GET', authUrl, (req) => {
    if (req.headers?.Authorization === `Bearer ${s.oldValue}`) {
      return json(200, { account_id: s.user, auth_method: 'api_key_user', auth_data: 'x', ...old });
    }
    expect(req.headers?.Authorization === `Bearer ${s.admin}`).toBe(true);
    return json(200, { account_id: s.user, auth_method: 'api_key_user', ...admin });
  });
}

async function rejection(operation: Promise<unknown>): Promise<unknown> {
  try {
    await operation;
  } catch (error) {
    return error;
  }
  return undefined;
}

const leaks = (value: unknown, ...secrets: string[]) => {
  const serialized = value instanceof Error ? `${value.name} ${value.message}` : JSON.stringify(value);
  return secrets.some(secret => serialized.includes(secret));
};

describe('neonProvider verify', () => {
  it('verifies any API key type through the auth details endpoint', async () => {
    for (const [method, identity] of [['api_key_user', 'Neon personal API key'], ['api_key_org', 'Neon organization API key'], [undefined, 'Neon API key']] as const) {
      const s = setup();
      s.http.on('GET', authUrl, (req) => {
        expect(req.headers?.Authorization === `Bearer ${s.oldValue}`).toBe(true);
        expect(req.body).toBeUndefined();
        return json(200, method ? { account_id: s.user, auth_method: method } : { account_id: s.user });
      });
      expect(await neonProvider.verify(s.oldValue, s.ctx)).toEqual({ ok: true, status: 200, identity });
    }
  });

  it('reports 401 as invalid and sanitizes malformed or failed responses', async () => {
    for (const kind of ['401', 'text', 'array', 'transport'] as const) {
      const s = setup();
      s.http.on('GET', authUrl, () => {
        if (kind === 'transport') throw new Error(s.oldValue);
        if (kind === 'text') return text(200, s.oldValue);
        if (kind === 'array') return json(200, [s.oldValue]);
        return json(401, { message: s.oldValue });
      });
      const result = await neonProvider.verify(s.oldValue, s.ctx);
      expect(result.ok).toBe(false);
      expect(leaks(result, s.oldValue, s.admin)).toBe(false);
    }
  });
});

describe('neonProvider rotate', () => {
  it('creates a personal key for the same user and leaves the old key to be deleted by hand', async () => {
    const s = setup();
    const newValue = apiKey();
    authRoutes(s);
    s.http.on('POST', keysUrl, (req) => {
      expect(req.headers?.Authorization === `Bearer ${s.admin}`).toBe(true);
      expect(req.headers?.['Content-Type']).toBe('application/json');
      const body = JSON.parse(req.body ?? '{}') as Record<string, unknown>;
      expect(Object.keys(body)).toEqual(['key_name']);
      expect(body.key_name).toMatch(/^keysentry-\d{4}-/);
      return json(200, { id: 1000001, key: newValue, name: body.key_name, created_at: '2026-10-28T00:00:00Z', created_by: s.user });
    });
    const result = await neonProvider.rotate!(s.oldValue, s.ctx);
    expect(result.newValue === newValue).toBe(true);
    expect(result.newKeyRef).toBe('1000001');
    expect(result.oldKeyRef).toBeNull();
    expect(result.oldRevoked).toBe(false);
    expect(result.notes).toMatch(/delete/i);
    expect(leaks(result.notes, newValue, s.oldValue)).toBe(false);
    expect(s.http.calls.map(call => call.method)).toEqual(['GET', 'GET', 'POST']);
  });

  it('requires guided rotation before any mutation when ownership cannot be preserved', async () => {
    const cases: [Record<string, unknown>, Record<string, unknown>][] = [
      [{ auth_method: 'api_key_org' }, {}],
      [{ auth_method: 'oauth' }, {}],
      [{ account_id: '' }, {}],
      [{ account_id: undefined }, {}],
      [{}, { account_id: randomUUID() }],
      [{}, { auth_method: 'api_key_org' }],
    ];
    for (const [old, admin] of cases) {
      const s = setup();
      authRoutes(s, old, admin);
      s.http.on('POST', keysUrl, () => json(200, { id: 1, key: apiKey() }));
      const error = await rejection(neonProvider.rotate!(s.oldValue, s.ctx));
      expect(error instanceof NeonGuidedRotationRequiredError).toBe(true);
      expect(error).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED', provider: 'neon' });
      expect(s.http.calls.every(call => call.method === 'GET')).toBe(true);
    }
  });

  it('requires guided rotation when the old key does not authenticate', async () => {
    for (const status of [401, 500]) {
      const s = setup();
      s.http.on('GET', authUrl, () => json(status, { message: s.admin }));
      const error = await rejection(neonProvider.rotate!(s.oldValue, s.ctx));
      expect(error).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
      expect(leaks(error, s.admin, s.oldValue)).toBe(false);
      expect(s.http.calls.every(call => call.method === 'GET')).toBe(true);
    }
  });

  it('keeps connection strings and the management key itself guided without a request', async () => {
    for (const value of ['postgresql://app:secretpw@ep-cool-name-123456.us-east-2.aws.neon.tech/db?sslmode=require', 'ADMIN']) {
      const s = setup();
      const old = value === 'ADMIN' ? s.admin : value;
      expect(await rejection(neonProvider.rotate!(old, s.ctx))).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
      expect(s.http.calls).toHaveLength(0);
    }
  });

  it('requires the management credential before any request', async () => {
    const s = setup();
    s.ctx.credentials = {};
    expect(String(await rejection(neonProvider.rotate!(s.oldValue, s.ctx)))).toMatch(/NEON_ADMIN_KEY/);
    expect(s.http.calls).toHaveLength(0);
  });

  it('rejects malformed creation responses without echoing values', async () => {
    const value = apiKey();
    for (const body of [{ id: 1 }, { key: value }, { id: 'x1', key: value }, { id: -1, key: value }, { id: 1.5, key: value }, { id: 2, key: '' }]) {
      const s = setup();
      authRoutes(s);
      s.http.on('POST', keysUrl, () => json(200, body));
      const error = await rejection(neonProvider.rotate!(s.oldValue, s.ctx));
      expect(error).toBeInstanceOf(Error);
      expect(error).not.toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
      expect(leaks(error, value, s.admin, s.oldValue)).toBe(false);
    }
  });

  it.each([400, 423, 503])('sanitizes HTTP %s creation failures', async (status) => {
    const s = setup();
    authRoutes(s);
    s.http.on('POST', keysUrl, () => json(status, { message: `${s.admin} ${s.oldValue}` }));
    const error = await rejection(neonProvider.rotate!(s.oldValue, s.ctx));
    expect(String(error)).toMatch(new RegExp(`HTTP ${status}`));
    expect(leaks(error, s.admin, s.oldValue)).toBe(false);
  });
});

describe('neonProvider by reference, revoke and list', () => {
  it('replaces a personal key by reference when it belongs to the management user', async () => {
    const s = setup();
    const newValue = apiKey();
    s.http.on('GET', keysUrl, (req) => {
      expect(req.headers?.Authorization === `Bearer ${s.admin}`).toBe(true);
      return json(200, [{ id: 41, name: 'ci' }, { id: 42, name: 'production', created_at: '2026-01-01T00:00:00Z' }]);
    }).on('POST', keysUrl, () => json(200, { id: 43, key: newValue }));
    const result = await neonProvider.rotateByRef!('42', s.ctx);
    expect(result.oldKeyRef).toBe('42');
    expect(result.newKeyRef).toBe('43');
    expect(result.newValue === newValue).toBe(true);

    for (const ref of ['44', 'x', '']) {
      const t = setup();
      t.http.on('GET', keysUrl, () => json(200, [{ id: 42, name: 'production' }]))
        .on('POST', keysUrl, () => json(200, { id: 43, key: apiKey() }));
      expect(await rejection(neonProvider.rotateByRef!(ref, t.ctx))).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
      expect(t.http.calls.every(call => call.method === 'GET')).toBe(true);
    }
  });

  it('revokes by numeric id and checks the revoked flag', async () => {
    const s = setup();
    s.http.on('DELETE', keyUrl(42), (req) => {
      expect(req.headers?.Authorization === `Bearer ${s.admin}`).toBe(true);
      expect(req.body).toBeUndefined();
      return json(200, { id: 42, name: 'production', revoked: true });
    });
    await neonProvider.revoke!('42', s.ctx);

    const t = setup();
    t.http.on('DELETE', keyUrl(42), () => json(200, { id: 42, revoked: false }));
    expect(await rejection(neonProvider.revoke!('42', t.ctx))).toBeInstanceOf(Error);

    const u = setup();
    for (const ref of ['abc', '1/2', u.oldValue]) expect(await rejection(neonProvider.revoke!(ref, u.ctx))).toBeInstanceOf(Error);
    expect(u.http.calls).toHaveLength(0);
  });

  it('sanitizes deletion failures', async () => {
    const s = setup();
    s.http.on('DELETE', keyUrl(42), () => json(404, { message: s.admin }));
    const error = await rejection(neonProvider.revoke!('42', s.ctx));
    expect(String(error)).toMatch(/HTTP 404/);
    expect(leaks(error, s.admin)).toBe(false);
  });

  it('lists the personal keys of the management user', async () => {
    const s = setup();
    s.http.on('GET', keysUrl, () => json(200, [
      { id: 1, name: 'one', created_at: '2026-01-01T00:00:00Z', last_used_at: null, created_by: { id: s.user, name: 'me' } },
      { id: 2, name: 'two' },
    ]));
    expect(await neonProvider.listKeys!(s.ctx)).toEqual([
      { keyRef: '1', name: 'one', createdAt: '2026-01-01T00:00:00Z' },
      { keyRef: '2', name: 'two' },
    ]);
  });

  it('identifies itself and gives console guidance for keys and passwords', () => {
    expect(neonProvider.id).toBe('neon');
    expect(neonProvider.method).toBe('auto');
    const guidance = neonProvider.guidance();
    expect(guidance.url).toBe('https://console.neon.tech/app/settings/api-keys');
    expect(guidance.steps.join(' ')).toMatch(/Reset password/);
  });
});
