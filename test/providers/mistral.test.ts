import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { MISTRAL_ADMIN_KEY, mistralProvider } from '../../src/providers/mistral.js';
import type { ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const key = () => Array.from(randomBytes(32), byte => ALPHABET[byte % ALPHABET.length]).join('');
const hidden = (value: string) => `${value.slice(0, 4)}...${value.slice(-4)}`;
const uuid = () => [8, 4, 4, 4, 12].map(n => randomBytes(n).toString('hex').slice(0, n)).join('-');
const LIST = /^https:\/\/api\.mistral\.ai\/v1\/admin\/api-keys\?limit=100&offset=(\d+)$/;

function context(http: FakeHttp, admin: string | null = key()): ProviderContext {
  return { http, credentials: admin === null ? {} : { [MISTRAL_ADMIN_KEY]: admin }, log: silentLogger };
}

function row(id: string, value: string, extra: Record<string, unknown> = {}) {
  return { key_id: id, hidden_key: hidden(value), key: null, name: 'backend', product: 'API', workspace_id: 'w1',
    created_at: '2026-09-01T10:00:00Z', expiration_date: null, can_delete: true, actions: {}, ...extra };
}

/** Pages of `pageSize` rows; the listing ends with an empty page. */
function listing(http: FakeHttp, admin: string, rows: unknown[], pageSize = 100) {
  return http.on('GET', LIST, (req, match) => {
    expect(req.headers?.['x-api-key'] === admin).toBe(true);
    expect(req.headers?.Authorization).toBeUndefined();
    const offset = Number(match[1]);
    return json(200, { keys: rows.slice(offset, offset + pageSize) });
  });
}

async function rejection(operation: Promise<unknown>): Promise<string> {
  try { await operation; } catch (error) { return error instanceof Error ? error.message : String(error); }
  throw new Error('expected rejection');
}

describe('mistralProvider', () => {
  it('stays guided: the Admin API cannot reproduce a key\'s Connector access scope', () => {
    expect(mistralProvider.id).toBe('mistral');
    expect(mistralProvider.method).toBe('guided');
    expect(mistralProvider.rotate).toBeUndefined();
    expect(typeof mistralProvider.revoke).toBe('function');
    expect(mistralProvider.guidance().url).toBe('https://console.mistral.ai/api-keys');
    expect(mistralProvider.guidance().steps.join(' ')).toMatch(/Connector access scope/);
  });

  it('verifies by listing models with the key as a bearer token', async () => {
    const value = key();
    const http = new FakeHttp().on('GET', /.*/, (req) => {
      expect(req.url).toBe('https://api.mistral.ai/v1/models');
      expect(req.headers?.Authorization === `Bearer ${value}`).toBe(true);
      expect(req.body).toBeUndefined();
      return json(200, { object: 'list', data: [{ id: 'mistral-small-latest' }] });
    });
    expect(await mistralProvider.verify(value, context(http, null))).toEqual({ ok: true, status: 200, identity: 'Mistral API key' });
  });

  it.each([[401, false], [403, true], [500, false]] as const)('maps verify HTTP %i to ok=%s without echoing the body', async (status, ok) => {
    const value = key();
    const http = new FakeHttp().on('GET', /models$/, () => json(status, { message: value }));
    const result = await mistralProvider.verify(value, context(http));
    expect(result).toMatchObject({ ok, status });
    expect(JSON.stringify(result).includes(value)).toBe(false);
  });

  it('fails verify closed on transport errors and malformed responses', async () => {
    for (const respond of [() => { throw new Error('boom'); }, () => text(200, 'x'), () => json(200, { data: {} })]) {
      const value = key();
      const result = await mistralProvider.verify(value, context(new FakeHttp().on('GET', /models$/, () => respond())));
      expect(result.ok).toBe(false);
      expect(JSON.stringify(result).includes(value)).toBe(false);
    }
  });

  it('resolves the old key by its masked first and last four characters across offset pages', async () => {
    const value = key();
    const admin = key();
    const id = uuid();
    const rows = [...Array.from({ length: 100 }, () => row(uuid(), key())), row(id, value)];
    const http = listing(new FakeHttp(), admin, rows);
    expect(await mistralProvider.resolveKeyRef!(value, context(http, admin))).toBe(id);
    expect(http.calls.map(call => call.url.replace('https://api.mistral.ai/v1', ''))).toEqual([
      '/admin/api-keys?limit=100&offset=0', '/admin/api-keys?limit=100&offset=100', '/admin/api-keys?limit=100&offset=101',
    ]);
    for (const call of http.calls) expect(call.url.includes(value.slice(-4))).toBe(false);
  });

  it('keeps paging when the server returns smaller pages than requested', async () => {
    const value = key();
    const admin = key();
    const id = uuid();
    const http = listing(new FakeHttp(), admin, [row(uuid(), key()), row(uuid(), key()), row(id, value)], 2);
    expect(await mistralProvider.resolveKeyRef!(value, context(http, admin))).toBe(id);
  });

  it('does not guess on ambiguous, partial or malformed hints', async () => {
    const value = key();
    const admin = key();
    for (const rows of [
      [row(uuid(), value), row(uuid(), value)],
      [row(uuid(), key(), { hidden_key: `...${value.slice(-4)}` })],
      [row(uuid(), key(), { hidden_key: `${value.slice(0, 4)}...${value.slice(-3)}` })],
      [row(uuid(), key(), { hidden_key: `${value.slice(0, 2)}...${value.slice(-4)}` })],
      [row(uuid(), key(), { hidden_key: null })],
    ]) {
      expect(await mistralProvider.resolveKeyRef!(value, context(listing(new FakeHttp(), admin, rows), admin))).toBeNull();
    }
  });

  it('returns null without requests when no admin key is configured, and null on API failures', async () => {
    const value = key();
    const empty = new FakeHttp();
    expect(await mistralProvider.resolveKeyRef!(value, context(empty, null))).toBeNull();
    expect(await mistralProvider.resolveKeyRef!(value, context(empty, '  '))).toBeNull();
    expect(empty.calls).toHaveLength(0);
    for (const response of [json(401, { detail: value }), text(200, 'x'), json(200, { keys: [{ key_id: value, hidden_key: hidden(value) }] })]) {
      const http = new FakeHttp().on('GET', LIST, () => response);
      expect(await mistralProvider.resolveKeyRef!(value, context(http))).toBeNull();
    }
  });

  it('lists keys without ever returning a plaintext key field', async () => {
    const admin = key();
    const first = key();
    const leaked = key();
    const id = uuid();
    const second = uuid();
    const http = listing(new FakeHttp(), admin, [row(id, first, { key: leaked }), row(second, key(), { name: admin, hidden_key: leaked })]);
    const keys = await mistralProvider.listKeys!(context(http, admin));
    expect(keys).toEqual([
      { keyRef: id, name: 'backend', hint: hidden(first), createdAt: '2026-09-01T10:00:00Z' },
      { keyRef: second, createdAt: '2026-09-01T10:00:00Z' },
    ]);
    expect(JSON.stringify(keys).includes(leaked)).toBe(false);
    expect(JSON.stringify(keys).includes(admin)).toBe(false);
  });

  it('requires the admin key for listing and revocation', async () => {
    const http = new FakeHttp();
    expect(await rejection(mistralProvider.listKeys!(context(http, null)))).toBe(`Missing provider credential: ${MISTRAL_ADMIN_KEY}`);
    expect(await rejection(mistralProvider.revoke!(uuid(), context(http, null)))).toBe(`Missing provider credential: ${MISTRAL_ADMIN_KEY}`);
    expect(http.calls).toHaveLength(0);
  });

  it('revokes with DELETE and the admin key header', async () => {
    const admin = key();
    const id = uuid();
    const http = new FakeHttp().on('DELETE', /.*/, (req) => {
      expect(req.url).toBe(`https://api.mistral.ai/v1/admin/api-keys/${id}`);
      expect(req.headers?.['x-api-key'] === admin).toBe(true);
      expect(req.body).toBeUndefined();
      return json(200, { detail: 'API key deleted successfully' });
    });
    await mistralProvider.revoke!(id, context(http, admin));
    expect(http.calls).toHaveLength(1);
  });

  it('refuses invalid references and reports failures with fixed text', async () => {
    const admin = key();
    const http = new FakeHttp().on('DELETE', /api-keys/, () => json(404, { detail: admin }));
    for (const ref of ['../x', 'a/b', admin]) {
      expect(await rejection(mistralProvider.revoke!(ref, context(http, admin)))).toBe('Mistral requires a valid API key reference');
    }
    expect(http.calls).toHaveLength(0);
    const message = await rejection(mistralProvider.revoke!(uuid(), context(http, admin)));
    expect(message).toBe('Mistral request failed (HTTP 404)');
    const failing = new FakeHttp().on('DELETE', /api-keys/, () => { throw new Error(admin); });
    expect(await rejection(mistralProvider.revoke!(uuid(), context(failing, admin)))).toBe('Mistral request failed');
  });
});
