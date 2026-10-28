import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { replicateProvider } from '../../src/providers/replicate.js';
import type { ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const token = () => `r8_${randomBytes(30).toString('hex').slice(0, 37)}`;
const context = (http: FakeHttp): ProviderContext => ({ http, credentials: {}, log: silentLogger });

describe('replicateProvider', () => {
  it('is guided: Replicate documents no token management API', () => {
    expect(replicateProvider.id).toBe('replicate');
    expect(replicateProvider.method).toBe('guided');
    expect(replicateProvider.rotate).toBeUndefined();
    expect(replicateProvider.revoke).toBeUndefined();
    expect(replicateProvider.guidance().url).toBe('https://replicate.com/account/api-tokens');
  });

  it('verifies with the account endpoint and reports the username', async () => {
    const value = token();
    const http = new FakeHttp().on('GET', /.*/, (req) => {
      expect(req.url).toBe('https://api.replicate.com/v1/account');
      expect(req.headers?.Authorization === `Bearer ${value}`).toBe(true);
      expect(req.body).toBeUndefined();
      return json(200, { type: 'organization', username: 'acme', name: 'Acme Inc', github_url: null });
    });
    expect(await replicateProvider.verify(value, context(http))).toEqual({ ok: true, status: 200, identity: 'acme' });
  });

  it('never reports a token-shaped username as identity', async () => {
    const value = token();
    for (const username of [value, token(), '', 42]) {
      const http = new FakeHttp().on('GET', /account$/, () => json(200, { type: 'user', username }));
      const result = await replicateProvider.verify(value, context(http));
      expect(result).toEqual({ ok: true, status: 200, identity: 'Replicate account' });
    }
  });

  it.each([[401, false], [403, true], [404, false], [500, false]] as const)('maps HTTP %i to ok=%s without echoing the body', async (status, ok) => {
    const value = token();
    const http = new FakeHttp().on('GET', /account$/, () => json(status, { detail: `Invalid token ${value}` }));
    const result = await replicateProvider.verify(value, context(http));
    expect(result.ok).toBe(ok);
    expect(result.status).toBe(status);
    expect(JSON.stringify(result).includes(value)).toBe(false);
  });

  it('fails closed on transport errors and malformed responses', async () => {
    for (const respond of [() => { throw new Error('boom'); }, () => text(200, 'nope'), () => json(200, [1, 2])]) {
      const value = token();
      const http = new FakeHttp().on('GET', /account$/, () => respond());
      const result = await replicateProvider.verify(value, context(http));
      expect(result.ok).toBe(false);
      expect(JSON.stringify(result).includes(value)).toBe(false);
    }
  });
});
