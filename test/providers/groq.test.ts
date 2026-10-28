import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { groqProvider } from '../../src/providers/groq.js';
import type { ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const key = () => `gsk_${randomBytes(39).toString('base64url').replace(/[-_]/g, 'A').slice(0, 52)}`;
const context = (http: FakeHttp): ProviderContext => ({ http, credentials: {}, log: silentLogger });

describe('groqProvider', () => {
  it('is guided: Groq documents no key management API', () => {
    expect(groqProvider.id).toBe('groq');
    expect(groqProvider.method).toBe('guided');
    expect(groqProvider.rotate).toBeUndefined();
    expect(groqProvider.revoke).toBeUndefined();
    const guidance = groqProvider.guidance();
    expect(guidance.url).toBe('https://console.groq.com/keys');
    expect(guidance.steps.length).toBeGreaterThan(1);
  });

  it('verifies by listing models with the key as a bearer token', async () => {
    const value = key();
    const http = new FakeHttp().on('GET', /.*/, (req) => {
      expect(req.url).toBe('https://api.groq.com/openai/v1/models');
      expect(req.headers?.Authorization === `Bearer ${value}`).toBe(true);
      expect(req.body).toBeUndefined();
      return json(200, { object: 'list', data: [{ id: 'llama-3.3-70b-versatile', object: 'model' }] });
    });
    expect(await groqProvider.verify(value, context(http))).toEqual({ ok: true, status: 200, identity: 'Groq API key' });
    expect(http.calls).toHaveLength(1);
  });

  it.each([[401, false], [403, true], [429, false], [500, false]] as const)('maps HTTP %i to ok=%s without echoing the body', async (status, ok) => {
    const value = key();
    const http = new FakeHttp().on('GET', /models$/, () => json(status, { error: { message: `Invalid API Key ${value}`, type: 'invalid_request_error' } }));
    const result = await groqProvider.verify(value, context(http));
    expect(result.ok).toBe(ok);
    expect(result.status).toBe(status);
    expect(JSON.stringify(result).includes(value)).toBe(false);
  });

  it('fails closed on transport errors and malformed responses', async () => {
    for (const respond of [() => { throw new Error('boom'); }, () => text(200, 'not json'), () => json(200, { data: 'x' })]) {
      const value = key();
      const http = new FakeHttp().on('GET', /models$/, () => { const response = respond(); return response; });
      const result = await groqProvider.verify(value, context(http));
      expect(result.ok).toBe(false);
      expect(JSON.stringify(result).includes(value)).toBe(false);
    }
  });
});
