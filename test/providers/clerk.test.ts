import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { clerkProvider } from '../../src/providers/clerk.js';
import type { ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const secret = (kind: 'live' | 'test' = 'live') => `sk_${kind}_${randomBytes(30).toString('hex').slice(0, 40)}`;
const context = (http: FakeHttp): ProviderContext => ({ http, credentials: {}, log: silentLogger });

describe('clerkProvider', () => {
  it('is guided: instance secret keys are managed in the Dashboard', () => {
    expect(clerkProvider.id).toBe('clerk');
    expect(clerkProvider.method).toBe('guided');
    expect(clerkProvider.rotate).toBeUndefined();
    expect(clerkProvider.revoke).toBeUndefined();
    const guidance = clerkProvider.guidance();
    expect(guidance.url).toBe('https://dashboard.clerk.com/last-active?path=api-keys');
    expect(guidance.steps.join(' ')).toMatch(/CLERK_SECRET_KEY/);
  });

  it.each([['live', 'Clerk production instance'], ['test', 'Clerk development instance']] as const)(
    'verifies an sk_%s key by reading the instance JWKS', async (kind, identity) => {
      const value = secret(kind);
      const http = new FakeHttp().on('GET', /.*/, (req) => {
        expect(req.url).toBe('https://api.clerk.com/v1/jwks');
        expect(req.headers?.Authorization === `Bearer ${value}`).toBe(true);
        expect(req.body).toBeUndefined();
        return json(200, { keys: [{ kty: 'RSA', kid: 'ins_123', use: 'sig', alg: 'RS256', n: 'abc', e: 'AQAB' }] });
      });
      expect(await clerkProvider.verify(value, context(http))).toEqual({ ok: true, status: 200, identity });
    });

  it('does not call the API for values that are not secret keys', async () => {
    const http = new FakeHttp();
    for (const value of [`whsec_${randomBytes(24).toString('base64')}`, `pk_live_${randomBytes(20).toString('hex')}`, 'sk_live_']) {
      expect(await clerkProvider.verify(value, context(http))).toEqual({ ok: true, identity: 'unverified' });
    }
    expect(http.calls).toHaveLength(0);
  });

  it.each([[401, false], [403, true], [422, false], [500, false]] as const)('maps HTTP %i to ok=%s without echoing the body', async (status, ok) => {
    const value = secret();
    const http = new FakeHttp().on('GET', /jwks$/, () => json(status, { errors: [{ code: 'authentication_invalid', message: value }] }));
    const result = await clerkProvider.verify(value, context(http));
    expect(result.ok).toBe(ok);
    expect(result.status).toBe(status);
    expect(JSON.stringify(result).includes(value)).toBe(false);
  });

  it('fails closed on transport errors and malformed responses', async () => {
    for (const respond of [() => { throw new Error('boom'); }, () => text(200, 'nope'), () => json(200, { keys: 'x' })]) {
      const value = secret('test');
      const http = new FakeHttp().on('GET', /jwks$/, () => respond());
      const result = await clerkProvider.verify(value, context(http));
      expect(result.ok).toBe(false);
      expect(JSON.stringify(result).includes(value)).toBe(false);
    }
  });
});
