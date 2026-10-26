import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { cloudflareProvider } from '../../src/providers/cloudflare.js';
import type { ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const verifyUrl = /^https:\/\/api\.cloudflare\.com\/client\/v4\/user\/tokens\/verify$/;
const rollUrl = /^https:\/\/api\.cloudflare\.com\/client\/v4\/user\/tokens\/token-id\/value$/;
const secret = (): string => randomBytes(32).toString('base64url');
const context = (http: FakeHttp, admin = secret()): ProviderContext => ({
  http,
  credentials: { CLOUDFLARE_ADMIN_TOKEN: admin },
  log: silentLogger,
});

async function failureMessage(action: Promise<unknown>): Promise<string> {
  try {
    await action;
    return '';
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

describe('cloudflareProvider', () => {
  it('verifies an active token using the token itself', async () => {
    const value = secret();
    const http = new FakeHttp().on('GET', verifyUrl, (req) => {
      expect(req.headers?.Authorization === `Bearer ${value}`).toBe(true);
      expect(req.body === undefined).toBe(true);
      return json(200, { success: true, result: { id: 'token-id', status: 'active' } });
    });

    const result = await cloudflareProvider.verify(value, context(http));
    expect(result.ok).toBe(true);
    expect(result.status).toBe(200);
    expect(result.identity === 'token-id').toBe(true);
    expect(http.calls.length).toBe(1);
    expect(cloudflareProvider.method).toBe('atomic-roll');
  });

  it.each([401, 403])('fails verification closed for HTTP %i', async (status) => {
    const value = secret();
    const http = new FakeHttp().on('GET', verifyUrl, () => json(status, { errors: [{ message: value }] }));
    const result = await cloudflareProvider.verify(value, context(http));
    expect(result.ok).toBe(false);
    expect(result.status).toBe(status);
    expect(JSON.stringify(result).includes(value)).toBe(false);
  });

  it.each([
    { success: true, result: { id: 'token-id', status: 'disabled' } },
    { success: true, result: { id: 'token-id', status: 'expired' } },
    { success: true, result: { id: 'token-id' } },
    { success: true, result: { status: 'active' } },
    { success: false, result: { id: 'token-id', status: 'active' } },
    { result: { id: 'token-id', status: 'active' } },
    null,
  ])('rejects inactive or malformed verification responses', async (body) => {
    const http = new FakeHttp().on('GET', verifyUrl, () => json(200, body));
    const result = await cloudflareProvider.verify(secret(), context(http));
    expect(result.ok).toBe(false);
    expect(result.status).toBe(200);
  });

  it('rolls the verified token with the admin credential and reports atomic revocation', async () => {
    const oldValue = secret();
    const newValue = secret();
    const admin = secret();
    const http = new FakeHttp()
      .on('GET', verifyUrl, (req) => {
        expect(req.headers?.Authorization === `Bearer ${oldValue}`).toBe(true);
        return json(200, { success: true, result: { id: 'token-id', status: 'active' } });
      })
      .on('PUT', rollUrl, (req) => {
        expect(req.headers?.Authorization === `Bearer ${admin}`).toBe(true);
        expect(req.body === undefined).toBe(true);
        return json(200, { success: true, result: newValue });
      });

    const result = await cloudflareProvider.rotate!(oldValue, context(http, admin));
    expect(result.newValue === newValue).toBe(true);
    expect(result.oldKeyRef === 'token-id').toBe(true);
    expect(result.newKeyRef === 'token-id').toBe(true);
    expect(result.oldRevoked).toBe(true);
    expect(http.calls.map(({ method }) => method)).toEqual(['GET', 'PUT']);
    expect(http.calls.some(({ url }) => [oldValue, newValue, admin].some((value) => url.includes(value)))).toBe(false);
  });

  it('does not roll a token whose verification is not active', async () => {
    const http = new FakeHttp().on('GET', verifyUrl, () =>
      json(200, { success: true, result: { id: 'token-id', status: 'disabled' } }));
    const message = await failureMessage(cloudflareProvider.rotate!(secret(), context(http)));
    expect(message.length > 0).toBe(true);
    expect(http.calls.map(({ method }) => method)).toEqual(['GET']);
  });

  it('requires an admin credential before rolling', async () => {
    const http = new FakeHttp().on('GET', verifyUrl, () =>
      json(200, { success: true, result: { id: 'token-id', status: 'active' } }));
    const ctx = context(http);
    ctx.credentials = {};
    const message = await failureMessage(cloudflareProvider.rotate!(secret(), ctx));
    expect(message.includes('CLOUDFLARE_ADMIN_TOKEN')).toBe(true);
    expect(http.calls.filter(({ method }) => method === 'PUT').length).toBe(0);
  });

  it.each([
    { success: true, result: '' },
    { success: true, result: { value: 'unexpected' } },
    { success: false, result: 'unexpected' },
    { result: 'unexpected' },
    null,
  ])('rejects malformed roll results', async (body) => {
    const http = new FakeHttp()
      .on('GET', verifyUrl, () => json(200, { success: true, result: { id: 'token-id', status: 'active' } }))
      .on('PUT', rollUrl, () => json(200, body));
    const message = await failureMessage(cloudflareProvider.rotate!(secret(), context(http)));
    expect(message.length > 0).toBe(true);
  });

  it('resolves the active token id without an admin credential', async () => {
    const http = new FakeHttp().on('GET', verifyUrl, () =>
      json(200, { success: true, result: { id: 'token-id', status: 'active' } }));
    const ctx = context(http);
    ctx.credentials = {};
    expect(await cloudflareProvider.resolveKeyRef!(secret(), ctx) === 'token-id').toBe(true);
  });

  it('does not resolve inactive tokens', async () => {
    const http = new FakeHttp().on('GET', verifyUrl, () =>
      json(200, { success: true, result: { id: 'token-id', status: 'disabled' } }));
    expect(await cloudflareProvider.resolveKeyRef!(secret(), context(http)) === null).toBe(true);
  });

  it('sanitizes verification transport failures', async () => {
    const value = secret();
    const http = new FakeHttp().on('GET', verifyUrl, () => { throw new Error(value); });
    const result = await cloudflareProvider.verify(value, context(http));
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result).includes(value)).toBe(false);
  });

  it('sanitizes verification JSON failures', async () => {
    const value = secret();
    const http = new FakeHttp().on('GET', verifyUrl, () => text(200, value));
    const result = await cloudflareProvider.verify(value, context(http));
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result).includes(value)).toBe(false);
  });

  it.each(['http', 'transport', 'parse'] as const)('sanitizes %s failures during rolling', async (kind) => {
    const admin = secret();
    const http = new FakeHttp()
      .on('GET', verifyUrl, () => json(200, { success: true, result: { id: 'token-id', status: 'active' } }))
      .on('PUT', rollUrl, () => {
        if (kind === 'transport') throw new Error(admin);
        if (kind === 'parse') return text(200, admin);
        return json(403, { errors: [{ message: admin }] });
      });
    const message = await failureMessage(cloudflareProvider.rotate!(secret(), context(http, admin)));
    expect(message.length > 0).toBe(true);
    expect(message.includes(admin)).toBe(false);
  });

  it('rejects verification ids that repeat a credential', async () => {
    const value = secret();
    const http = new FakeHttp().on('GET', verifyUrl, () =>
      json(200, { success: true, result: { id: value, status: 'active' } }));
    const result = await cloudflareProvider.verify(value, context(http));
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result).includes(value)).toBe(false);
  });

  it('provides token-roll guidance', () => {
    const guidance = cloudflareProvider.guidance();
    expect(guidance.url).toBe('https://dash.cloudflare.com/profile/api-tokens');
    expect(guidance.steps.join(' ')).toMatch(/old.*invalid|immediate|atomic/i);
  });
});
