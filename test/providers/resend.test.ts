import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ResendGuidedRotationRequiredError, resendProvider } from '../../src/providers/resend.js';
import type { ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const secret = () => `re_${randomBytes(24).toString('hex')}`;
const context = (http: FakeHttp, admin = secret()): ProviderContext => ({
  http,
  credentials: { RESEND_ADMIN_KEY: admin },
  log: silentLogger,
});

const hint = (value: string) => `${value.slice(0, 7)}...${value.slice(-4)}`;
function rotationHttp(value: string, permission: 'full_access' | 'sending_access' = 'full_access', domainId: string | null = null) {
  return new FakeHttp()
    .on('GET', /^https:\/\/api\.resend\.com\/domains$/, request => {
      expect(request.headers?.Authorization === `Bearer ${value}`).toBe(true);
      return json(permission === 'sending_access' ? 403 : 200, { data: [] });
    })
    .on('GET', /^https:\/\/api\.resend\.com\/api-keys$/, () => json(200, { data: [{
      id: 'old-id', redacted_value: hint(value), permission, domain_id: domainId,
    }], has_more: false }));
}

async function failure(operation: Promise<unknown>): Promise<string> {
  try {
    await operation;
    return '';
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

describe('resendProvider', () => {
  it('verifies with the supplied key through the domains endpoint', async () => {
    const value = secret();
    const http = new FakeHttp().on('GET', /^https:\/\/api\.resend\.com\/domains$/, (request) => {
      expect(request.headers?.Authorization === `Bearer ${value}`).toBe(true);
      expect(request.body === undefined).toBe(true);
      return json(200, { data: [] });
    });

    const result = await resendProvider.verify(value, context(http));
    expect(result.ok).toBe(true);
    expect(result.status).toBe(200);
    expect(result.identity?.includes(value)).not.toBe(true);
    expect(http.calls.length).toBe(1);
  });

  it('rejects unauthorized keys without including provider error bodies', async () => {
    const value = secret();
    const http = new FakeHttp().on('GET', /\/domains$/, () => json(401, { message: value }));
    const result = await resendProvider.verify(value, context(http));
    expect(result.ok).toBe(false);
    expect(result.status).toBe(401);
    expect(JSON.stringify(result).includes(value)).toBe(false);
  });

  it('recognizes sending-only keys as valid but limited on a 403 read', async () => {
    const value = secret();
    const http = new FakeHttp().on('GET', /\/domains$/, () => json(403, { message: value }));
    const result = await resendProvider.verify(value, context(http));
    expect(result.ok).toBe(true);
    expect(result.status).toBe(403);
    expect(result.identity).toMatch(/limited/i);
    expect(JSON.stringify(result).includes(value)).toBe(false);
  });

  it('sanitizes transport exceptions during verification', async () => {
    const value = secret();
    const http = new FakeHttp().on('GET', /\/domains$/, () => { throw new Error(value); });
    const result = await resendProvider.verify(value, context(http));
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result).includes(value)).toBe(false);
  });

  it('sanitizes parse errors during verification', async () => {
    const value = secret();
    const http = new FakeHttp().on('GET', /\/domains$/, () => text(200, value));
    const result = await resendProvider.verify(value, context(http));
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result).includes(value)).toBe(false);
  });

  it('creates a full-access replacement with the admin key and leaves old deletion manual', async () => {
    const oldValue = secret();
    const newValue = secret();
    const admin = secret();
    const http = rotationHttp(oldValue).on('POST', /^https:\/\/api\.resend\.com\/api-keys$/, (request) => {
      expect(request.headers?.Authorization === `Bearer ${admin}`).toBe(true);
      expect(request.headers?.['Content-Type']).toBe('application/json');
      const body = JSON.parse(request.body ?? '{}') as Record<string, unknown>;
      expect(body.permission).toBe('full_access');
      expect(body.name).toMatch(/^keysentry-/);
      expect(Object.keys(body).sort()).toEqual(['name', 'permission']);
      expect(request.body?.includes(oldValue)).not.toBe(true);
      return json(201, { id: 'replacement-id', token: newValue });
    });

    const result = await resendProvider.rotate!(oldValue, context(http, admin));
    expect(result.newValue === newValue).toBe(true);
    expect(result.newKeyRef === 'replacement-id').toBe(true);
    expect(result.oldKeyRef === null).toBe(true);
    expect(result.oldRevoked).toBe(false);
    expect(result.notes).toMatch(/manually/i);
    expect(result.notes?.includes(oldValue)).not.toBe(true);
    expect(result.notes?.includes(newValue)).not.toBe(true);
    expect(http.calls.map(call => call.method)).toEqual(['GET', 'GET', 'POST']);
    expect(http.calls[1]?.headers?.Authorization === `Bearer ${admin}`).toBe(true);
  });

  it.each(['sending_access', 'full_access'] as const)('preserves %s and a detected domain restriction', async (permission) => {
    const oldValue = secret();
    const newValue = secret();
    const http = rotationHttp(oldValue, permission, 'domain_old').on('POST', /\/api-keys$/, request => {
      const body = JSON.parse(request.body!) as Record<string, unknown>;
      expect(body.permission).toBe(permission);
      expect(body.domain_id).toBe('domain_old');
      return json(201, { id: 'replacement-id', token: newValue });
    });
    const result = await resendProvider.rotate!(oldValue, context(http));
    expect(result.newValue === newValue).toBe(true);
    expect(http.calls.filter(call => call.method === 'POST')).toHaveLength(1);
  });

  it('preserves explicitly unrestricted sending access without adding domain access fields', async () => {
    const oldValue = secret();
    const newValue = secret();
    const http = rotationHttp(oldValue, 'sending_access').on('POST', /\/api-keys$/, request => {
      const body = JSON.parse(request.body!) as Record<string, unknown>;
      expect(body.permission).toBe('sending_access');
      expect(Object.hasOwn(body, 'domain_id')).toBe(false);
      return json(201, { id: 'replacement-id', token: newValue });
    });
    expect((await resendProvider.rotate!(oldValue, context(http))).newValue === newValue).toBe(true);
  });

  it.each(['sending_access', 'full_access'] as const)('requires guided rotation when %s domain scope is unknown or ambiguous', async (permission) => {
    const oldValue = secret();
    const matched = { id: 'old-id', redacted_value: hint(oldValue), permission, domain_id: 'domain_old' };
    for (const response of [
      json(200, { data: [{ id: 'old-id', name: 'old key' }] }),
      json(200, { data: [{ ...matched, domain_id: undefined }] }),
      json(200, { data: [{ ...matched, domain_id: '' }] }),
      json(200, { data: [{ ...matched, domain_id: oldValue }] }),
      json(200, { data: [{ ...matched, permission: 'unknown' }] }),
      json(200, { data: [{ ...matched, redacted_value: `...${oldValue.slice(-4)}` }] }),
      json(200, { data: [{ ...matched, redacted_value: `re_...${oldValue.slice(-1)}` }], has_more: false }),
      json(200, { data: [{ ...matched, redacted_value: `re_...${oldValue.slice(-4)}` }], has_more: false }),
      json(200, { data: [{ ...matched, redacted_value: `${oldValue.slice(0, 7)}...${oldValue.slice(-3)}` }], has_more: false }),
      json(200, { data: [matched, { ...matched, id: 'another-id' }] }),
      json(200, { data: [matched], has_more: true }),
      json(403, { message: oldValue }),
      text(200, oldValue),
    ]) {
      const http = new FakeHttp()
        .on('GET', /\/domains$/, () => json(permission === 'sending_access' ? 403 : 200, { data: [] }))
        .on('GET', /\/api-keys$/, () => response)
        .on('POST', /\/api-keys$/, () => json(201, { id: 'replacement-id', token: secret() }));
      let error: unknown;
      try { await resendProvider.rotate!(oldValue, context(http)); } catch (cause) { error = cause; }
      expect(error instanceof ResendGuidedRotationRequiredError).toBe(true);
      expect(error).toMatchObject({ name: 'ResendGuidedRotationRequiredError', code: 'GUIDED_ROTATION_REQUIRED', provider: 'resend' });
      expect(String(error).includes(oldValue)).toBe(false);
      expect(http.calls.every(call => call.method === 'GET')).toBe(true);
    }
  });

  it.each([401, 429, 500])('never creates a replacement when old-key verification returns HTTP %s', async (status) => {
    const oldValue = secret();
    const http = new FakeHttp().on('GET', /\/domains$/, () => json(status, { message: oldValue }))
      .on('POST', /\/api-keys$/, () => json(201, { id: 'replacement-id', token: secret() }));
    expect(await failure(resendProvider.rotate!(oldValue, context(http)))).toMatch(/verif/i);
    expect(http.calls.map(call => call.method)).toEqual(['GET']);
  });

  it('never creates a replacement when the old-key verification response is malformed', async () => {
    const oldValue = secret();
    for (const response of [text(200, oldValue), json(200, null), json(200, { data: 'invalid' })]) {
      const http = new FakeHttp().on('GET', /\/domains$/, () => response)
        .on('POST', /\/api-keys$/, () => json(201, { id: 'replacement-id', token: secret() }));
      expect(await failure(resendProvider.rotate!(oldValue, context(http)))).toMatch(/verif/i);
      expect(http.calls.map(call => call.method)).toEqual(['GET']);
    }
  });

  it('requires the management credential before creating a key', async () => {
    const http = new FakeHttp();
    const ctx = context(http);
    ctx.credentials = {};
    expect(await failure(resendProvider.rotate!(secret(), ctx))).toMatch(/RESEND_ADMIN_KEY/);
    expect(http.calls.length).toBe(0);
  });

  it.each([401, 403, 500])('sanitizes HTTP %s rotation failures', async (status) => {
    const admin = secret();
    const oldValue = secret();
    const http = rotationHttp(oldValue).on('POST', /\/api-keys$/, () => json(status, { message: admin }));
    const message = await failure(resendProvider.rotate!(oldValue, context(http, admin)));
    expect(message.length > 0).toBe(true);
    expect(message.includes(admin)).toBe(false);
  });

  it('sanitizes transport rotation failures', async () => {
    const admin = secret();
    const oldValue = secret();
    const http = rotationHttp(oldValue).on('POST', /\/api-keys$/, () => { throw new Error(admin); });
    const message = await failure(resendProvider.rotate!(oldValue, context(http, admin)));
    expect(message.length > 0).toBe(true);
    expect(message.includes(admin)).toBe(false);
  });

  it('sanitizes JSON parse failures after creation', async () => {
    const newValue = secret();
    const oldValue = secret();
    const http = rotationHttp(oldValue).on('POST', /\/api-keys$/, () => text(200, newValue));
    const message = await failure(resendProvider.rotate!(oldValue, context(http)));
    expect(message.length > 0).toBe(true);
    expect(message.includes(newValue)).toBe(false);
  });

  it.each([{ id: 'replacement-id' }, { token: '' }, { token: 'placeholder', id: '' }])(
    'rejects a malformed create response',
    async (response) => {
      const oldValue = secret();
      const http = rotationHttp(oldValue).on('POST', /\/api-keys$/, () => json(200, response));
      expect((await failure(resendProvider.rotate!(oldValue, context(http)))).length > 0).toBe(true);
    },
  );

  it('refuses to return a secret as a key reference', async () => {
    const value = secret();
    const oldValue = secret();
    const http = rotationHttp(oldValue).on('POST', /\/api-keys$/, () => json(200, { token: value, id: value }));
    const message = await failure(resendProvider.rotate!(oldValue, context(http)));
    expect(message.length > 0).toBe(true);
    expect(message.includes(value)).toBe(false);
  });

  it('rejects a creation id that echoes another configured credential', async () => {
    const otherCredential = randomBytes(32).toString('hex');
    const newValue = secret();
    const oldValue = secret();
    const http = rotationHttp(oldValue).on('POST', /\/api-keys$/, () =>
      json(201, { token: newValue, id: `key-${otherCredential}` }));
    const ctx = context(http);
    ctx.credentials.OTHER_ADMIN_KEY = otherCredential;
    const message = await failure(resendProvider.rotate!(oldValue, ctx));
    expect(message.length > 0).toBe(true);
    expect(message.includes(otherCredential)).toBe(false);
    expect(message.includes(newValue)).toBe(false);
  });

  it('rejects an unrelated full token returned as a creation id', async () => {
    const foreignToken = secret();
    const oldValue = secret();
    const http = rotationHttp(oldValue).on('POST', /\/api-keys$/, () =>
      json(201, { token: secret(), id: foreignToken }));
    const message = await failure(resendProvider.rotate!(oldValue, context(http)));
    expect(message.length > 0).toBe(true);
    expect(message.includes(foreignToken)).toBe(false);
  });

  it('rejects a foreign full token as a revocation ref before any HTTP call', async () => {
    const foreignToken = secret();
    const http = new FakeHttp().on('DELETE', /\/api-keys\/.+$/, () => json(200, { deleted: true }));
    const message = await failure(resendProvider.revoke!(foreignToken, context(http)));
    expect(message.length > 0).toBe(true);
    expect(message.includes(foreignToken)).toBe(false);
    expect(http.calls.length).toBe(0);
  });

  it.each(['bad/ref', 'bad?ref', 'bad#ref', 'bad ref', 'bad%ref'])('rejects malformed refs before HTTP', async (ref) => {
    const http = new FakeHttp().on('DELETE', /\/api-keys\/.+$/, () => json(200, { deleted: true }));
    const message = await failure(resendProvider.revoke!(ref, context(http)));
    expect(message.length > 0).toBe(true);
    expect(http.calls.length).toBe(0);
  });

  it('revokes a specific known key using the admin credential', async () => {
    const admin = secret();
    const http = new FakeHttp().on('DELETE', /^https:\/\/api\.resend\.com\/api-keys\/known-id$/, (request) => {
      expect(request.headers?.Authorization === `Bearer ${admin}`).toBe(true);
      expect(request.body === undefined).toBe(true);
      return json(200, { id: 'known-id' });
    });
    await resendProvider.revoke!('known-id', context(http, admin));
    expect(http.calls.length).toBe(1);
  });

  it('sanitizes deletion failure bodies', async () => {
    const admin = secret();
    const http = new FakeHttp().on('DELETE', /\/api-keys\/known-id$/, () => json(403, { error: admin }));
    const message = await failure(resendProvider.revoke!('known-id', context(http, admin)));
    expect(message.length > 0).toBe(true);
    expect(message.includes(admin)).toBe(false);
  });

  it('provides manual guidance for creating and retiring keys', () => {
    expect(resendProvider.id).toBe('resend');
    expect(resendProvider.method).toBe('auto');
    expect(resendProvider.guidance().url).toBe('https://resend.com/api-keys');
    expect(resendProvider.guidance().steps.join(' ')).toMatch(/delete/i);
  });
});
