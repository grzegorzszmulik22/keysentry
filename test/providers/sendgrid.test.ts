import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { SendGridGuidedRotationRequiredError, sendgridProvider } from '../../src/providers/sendgrid.js';
import type { ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const segment = (length: number) => randomBytes(length).toString('base64url').slice(0, length);
const keyId = () => segment(22);
const sgKey = (id = keyId()) => `SG.${id}.${segment(43)}`;
const idOf = (value: string) => value.split('.')[1]!;
const SCOPES = ['mail.send', 'alerts.read', 'templates.read'];

interface Setup { http: FakeHttp; ctx: ProviderContext; oldValue: string; oldId: string; admin: string }

function setup(): Setup {
  const http = new FakeHttp();
  const oldValue = sgKey();
  const admin = sgKey();
  return { http, oldValue, oldId: idOf(oldValue), admin, ctx: { http, credentials: { SENDGRID_ADMIN_KEY: admin }, log: silentLogger } };
}

const scopesUrl = /^https:\/\/api\.sendgrid\.com\/v3\/scopes$/;
const keyUrl = (id: string) => new RegExp(`^https://api\\.sendgrid\\.com/v3/api_keys/${id.replace(/[-]/g, '\\-')}$`);
const createUrl = /^https:\/\/api\.sendgrid\.com\/v3\/api_keys$/;

function rotationRoutes(s: Setup, opts: { scopes?: string[]; adminScopes?: string[] | null; createdScopes?: string[]; newValue?: string; newId?: string } = {}) {
  const scopes = opts.scopes ?? SCOPES;
  const newId = opts.newId ?? keyId();
  const newValue = opts.newValue ?? sgKey(newId);
  s.http
    .on('GET', scopesUrl, (req) => {
      expect(req.headers?.Authorization === `Bearer ${s.oldValue}`).toBe(true);
      return json(200, { scopes });
    })
    .on('GET', keyUrl(s.oldId), (req) => {
      expect(req.headers?.Authorization === `Bearer ${s.admin}`).toBe(true);
      const entry: Record<string, unknown> = { api_key_id: s.oldId, name: 'production' };
      if (opts.adminScopes !== null) entry.scopes = opts.adminScopes ?? [...scopes].reverse();
      return json(200, { result: [entry] });
    })
    .on('POST', createUrl, (req) => {
      const body = JSON.parse(req.body ?? '{}') as { name: string; scopes: string[] };
      return json(201, { api_key: newValue, api_key_id: newId, name: body.name, scopes: opts.createdScopes ?? body.scopes });
    });
  return { newId, newValue };
}

async function rejection(operation: Promise<unknown>): Promise<unknown> {
  try {
    await operation;
  } catch (error) {
    return error;
  }
  return undefined;
}

const leaks = (value: unknown, ...values: string[]) => {
  const serialized = value instanceof Error ? `${value.name} ${value.message}` : JSON.stringify(value);
  return values.some(secret => serialized.includes(secret));
};

describe('sendgridProvider verify', () => {
  it('verifies through the scopes endpoint with the key itself', async () => {
    const s = setup();
    s.http.on('GET', scopesUrl, (req) => {
      expect(req.headers?.Authorization === `Bearer ${s.oldValue}`).toBe(true);
      expect(req.body).toBeUndefined();
      return json(200, { scopes: SCOPES });
    });
    expect(await sendgridProvider.verify(s.oldValue, s.ctx)).toEqual({ ok: true, status: 200, identity: 'SendGrid API key' });
  });

  it('reports 401 as invalid and 403 as valid-but-limited without echoing bodies', async () => {
    for (const status of [401, 403]) {
      const s = setup();
      s.http.on('GET', scopesUrl, () => json(status, { errors: [{ message: s.oldValue }] }));
      const result = await sendgridProvider.verify(s.oldValue, s.ctx);
      expect(result.ok).toBe(status === 403);
      expect(result.status).toBe(status);
      expect(leaks(result, s.oldValue, s.admin)).toBe(false);
    }
  });

  it('sanitizes malformed and transport failures', async () => {
    for (const kind of ['parse', 'shape', 'transport'] as const) {
      const s = setup();
      s.http.on('GET', scopesUrl, () => {
        if (kind === 'transport') throw new Error(s.oldValue);
        return kind === 'parse' ? text(200, s.oldValue) : json(200, { scopes: 'all' });
      });
      const result = await sendgridProvider.verify(s.oldValue, s.ctx);
      expect(result.ok).toBe(false);
      expect(leaks(result, s.oldValue)).toBe(false);
    }
  });
});

describe('sendgridProvider rotate', () => {
  it('creates a replacement with exactly the old key scopes and keeps the old key active', async () => {
    const s = setup();
    const newId = keyId();
    const newValue = sgKey(newId);
    s.http.on('POST', createUrl, (req) => {
      expect(req.headers?.Authorization === `Bearer ${s.admin}`).toBe(true);
      expect(req.headers?.['Content-Type']).toBe('application/json');
      const body = JSON.parse(req.body ?? '{}') as Record<string, unknown>;
      expect(Object.keys(body).sort()).toEqual(['name', 'scopes']);
      expect(body.name).toMatch(/^keysentry-\d{4}-/);
      expect(body.scopes).toEqual(SCOPES);
      expect(req.body?.includes(s.oldValue)).toBe(false);
      return json(201, { api_key: newValue, api_key_id: newId, name: body.name, scopes: [...SCOPES].reverse() });
    });
    rotationRoutes(s);
    const result = await sendgridProvider.rotate!(s.oldValue, s.ctx);
    expect(result.newValue === newValue).toBe(true);
    expect(result.oldKeyRef === s.oldId).toBe(true);
    expect(result.newKeyRef === newId).toBe(true);
    expect(result.oldRevoked).toBe(false);
    expect(s.http.calls.map(call => call.method)).toEqual(['GET', 'GET', 'POST']);
  });

  it('accepts a single-object key description and one without listed scopes', async () => {
    for (const shape of ['object', 'no-scopes'] as const) {
      const s = setup();
      s.http.on('GET', keyUrl(s.oldId), () => json(200, shape === 'object'
        ? { api_key_id: s.oldId, name: 'production', scopes: SCOPES }
        : { result: [{ api_key_id: s.oldId, name: 'production' }] }));
      rotationRoutes(s);
      expect((await sendgridProvider.rotate!(s.oldValue, s.ctx)).oldKeyRef === s.oldId).toBe(true);
    }
  });

  it('requires guided rotation before any mutation when the old key or its scope cannot be confirmed', async () => {
    const cases: [string, (s: Setup) => void][] = [
      ['scopes 401', s => s.http.on('GET', scopesUrl, () => json(401, { errors: [{ message: s.admin }] }))],
      ['scopes empty', s => s.http.on('GET', scopesUrl, () => json(200, { scopes: [] }))],
      ['scopes malformed', s => s.http.on('GET', scopesUrl, () => json(200, { scopes: ['mail.send', 7] }))],
      ['scopes duplicated', s => s.http.on('GET', scopesUrl, () => json(200, { scopes: ['mail.send', 'mail.send'] }))],
      ['scopes text', s => s.http.on('GET', scopesUrl, () => text(200, s.oldValue))],
      ['not in account', s => s.http.on('GET', keyUrl(s.oldId), () => json(404, { errors: [] }))],
      ['admin 401', s => s.http.on('GET', keyUrl(s.oldId), () => json(401, { errors: [{ message: s.admin }] }))],
      ['wrong id', s => s.http.on('GET', keyUrl(s.oldId), () => json(200, { result: [{ api_key_id: keyId(), name: 'x' }] }))],
      ['two entries', s => s.http.on('GET', keyUrl(s.oldId), () => json(200, { result: [
        { api_key_id: s.oldId, name: 'a' }, { api_key_id: s.oldId, name: 'b' }] }))],
      ['scope mismatch', s => s.http.on('GET', keyUrl(s.oldId), () => json(200, { result: [
        { api_key_id: s.oldId, name: 'a', scopes: ['mail.send'] }] }))],
    ];
    for (const [, arrange] of cases) {
      const s = setup();
      arrange(s);
      rotationRoutes(s);
      const error = await rejection(sendgridProvider.rotate!(s.oldValue, s.ctx));
      expect(error instanceof SendGridGuidedRotationRequiredError).toBe(true);
      expect(error).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED', provider: 'sendgrid' });
      expect(leaks(error, s.oldValue, s.admin)).toBe(false);
      expect(s.http.calls.every(call => call.method === 'GET')).toBe(true);
    }
  });

  it('requires guided rotation without a request for unrecognized values or the management key', async () => {
    for (const mutate of [(s: Setup) => { s.oldValue = `SG.${segment(10)}`; }, (s: Setup) => { s.oldValue = s.admin; }]) {
      const s = setup();
      mutate(s);
      expect(await rejection(sendgridProvider.rotate!(s.oldValue, s.ctx))).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
      expect(s.http.calls).toHaveLength(0);
    }
  });

  it('requires the management credential before any request', async () => {
    const s = setup();
    s.ctx.credentials = {};
    expect(String(await rejection(sendgridProvider.rotate!(s.oldValue, s.ctx)))).toMatch(/SENDGRID_ADMIN_KEY/);
    expect(s.http.calls).toHaveLength(0);
  });

  it('deletes a replacement whose scopes differ from the request', async () => {
    const s = setup();
    const { newId } = rotationRoutes(s, { createdScopes: [...SCOPES, 'api_keys.create'] });
    s.http.on('DELETE', keyUrl(newId), (req) => {
      expect(req.headers?.Authorization === `Bearer ${s.admin}`).toBe(true);
      return text(204, '');
    });
    const error = await rejection(sendgridProvider.rotate!(s.oldValue, s.ctx));
    expect(String(error)).toMatch(/deleted/);
    expect(s.http.callsTo('DELETE', keyUrl(newId))).toHaveLength(1);

    const t = setup();
    const created = rotationRoutes(t, { createdScopes: ['mail.send'] });
    t.http.on('DELETE', keyUrl(created.newId), () => json(500, { errors: [{ message: t.admin }] }));
    const unremoved = await rejection(sendgridProvider.rotate!(t.oldValue, t.ctx));
    expect(String(unremoved)).toMatch(/SendGrid dashboard/);
    expect(leaks(unremoved, t.admin, created.newValue)).toBe(false);
  });

  it('rejects malformed creation responses without echoing values', async () => {
    const value = sgKey();
    for (const body of [{ api_key_id: keyId(), scopes: SCOPES }, { api_key: value, scopes: SCOPES },
      { api_key: value, api_key_id: 'bad/id', scopes: SCOPES }, { api_key: '', api_key_id: keyId(), scopes: SCOPES }]) {
      const s = setup();
      s.http.on('POST', createUrl, () => json(201, body));
      rotationRoutes(s);
      const error = await rejection(sendgridProvider.rotate!(s.oldValue, s.ctx));
      expect(error).toBeInstanceOf(Error);
      expect(leaks(error, value, s.oldValue, s.admin)).toBe(false);
    }
  });

  it.each([400, 403, 500])('sanitizes HTTP %s creation failures', async (status) => {
    const s = setup();
    s.http.on('POST', createUrl, () => json(status, { errors: [{ message: `${s.admin} ${s.oldValue}` }] }));
    rotationRoutes(s);
    const error = await rejection(sendgridProvider.rotate!(s.oldValue, s.ctx));
    expect(String(error)).toMatch(new RegExp(`HTTP ${status}`));
    expect(leaks(error, s.admin, s.oldValue)).toBe(false);
  });
});

describe('sendgridProvider by reference, revoke, resolve and list', () => {
  it('replaces a key by reference with the scopes the management API reports', async () => {
    const s = setup();
    const newId = keyId();
    s.http.on('GET', keyUrl(s.oldId), () => json(200, { result: [{ api_key_id: s.oldId, name: 'production', scopes: SCOPES }] }))
      .on('POST', createUrl, (req) => {
        expect(JSON.parse(req.body!).scopes).toEqual(SCOPES);
        return json(201, { api_key: sgKey(newId), api_key_id: newId, name: 'x', scopes: SCOPES });
      });
    const result = await sendgridProvider.rotateByRef!(s.oldId, s.ctx);
    expect(result.oldKeyRef === s.oldId).toBe(true);
    expect(result.newKeyRef === newId).toBe(true);
  });

  it('requires guided rotation by reference when scopes are unknown', async () => {
    for (const body of [{ result: [{ api_key_id: 'ID', name: 'x' }] }, { result: [{ api_key_id: 'ID', name: 'x', scopes: [] }] }]) {
      const s = setup();
      s.oldId = 'ID';
      s.http.on('GET', keyUrl('ID'), () => json(200, body));
      expect(await rejection(sendgridProvider.rotateByRef!('ID', s.ctx))).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
      expect(s.http.calls.every(call => call.method === 'GET')).toBe(true);
    }
    const t = setup();
    expect(await rejection(sendgridProvider.rotateByRef!(idOf(t.admin), t.ctx))).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(await rejection(sendgridProvider.rotateByRef!('bad/ref', t.ctx))).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(t.http.calls).toHaveLength(0);
  });

  it('revokes by id with the management key and refuses its own id or malformed refs', async () => {
    const s = setup();
    s.http.on('DELETE', keyUrl(s.oldId), (req) => {
      expect(req.headers?.Authorization === `Bearer ${s.admin}`).toBe(true);
      expect(req.body).toBeUndefined();
      return text(204, '');
    });
    await sendgridProvider.revoke!(s.oldId, s.ctx);
    for (const ref of [idOf(s.admin), 'bad/ref', 'bad ref', s.oldValue]) {
      expect(await rejection(sendgridProvider.revoke!(ref, s.ctx))).toBeInstanceOf(Error);
    }
    expect(s.http.calls).toHaveLength(1);
  });

  it('sanitizes deletion failures', async () => {
    const s = setup();
    s.http.on('DELETE', keyUrl(s.oldId), () => json(404, { errors: [{ message: s.admin }] }));
    const error = await rejection(sendgridProvider.revoke!(s.oldId, s.ctx));
    expect(String(error)).toMatch(/HTTP 404/);
    expect(leaks(error, s.admin)).toBe(false);
  });

  it('resolves the id embedded in a key only when the account confirms it', async () => {
    const s = setup();
    s.http.on('GET', keyUrl(s.oldId), () => json(200, { result: [{ api_key_id: s.oldId, name: 'production' }] }));
    expect(await sendgridProvider.resolveKeyRef!(s.oldValue, s.ctx) === s.oldId).toBe(true);

    const t = setup();
    t.http.on('GET', keyUrl(t.oldId), () => json(404, {}));
    expect(await sendgridProvider.resolveKeyRef!(t.oldValue, t.ctx)).toBeNull();
    expect(await sendgridProvider.resolveKeyRef!('not-a-key', t.ctx)).toBeNull();
  });

  it('lists keys visible to the management key', async () => {
    const s = setup();
    s.http.on('GET', createUrl, (req) => {
      expect(req.headers?.Authorization === `Bearer ${s.admin}`).toBe(true);
      return json(200, { result: [{ api_key_id: 'one', name: 'first' }, { api_key_id: 'two', name: 'second' }] });
    });
    expect(await sendgridProvider.listKeys!(s.ctx)).toEqual([{ keyRef: 'one', name: 'first' }, { keyRef: 'two', name: 'second' }]);
  });

  it('identifies itself and gives dashboard guidance', () => {
    expect(sendgridProvider.id).toBe('sendgrid');
    expect(sendgridProvider.method).toBe('auto');
    expect(sendgridProvider.guidance().url).toBe('https://app.sendgrid.com/settings/api_keys');
  });
});
