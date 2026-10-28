import type { ProviderAdapter, ProviderContext, ProviderKeyInfo } from '../types.js';
import { credential, ensureOk, matchHint, readJson, request, safeIdentity, verifyRead } from './shared.js';

// Mistral's Admin API (Enterprise plans, preview) lists and deletes Workspace API keys
// (https://docs.mistral.ai/api/endpoint/beta/admin/api-keys). Its create endpoint cannot set or report a key's
// Connector access scope, so a replacement could differ from the exposed key: creation stays guided, while an
// identified old key can be revoked after the guided replacement. Details: notes/providers-b.md.

const API = 'https://api.mistral.ai/v1';
const PROVIDER = 'Mistral';
export const MISTRAL_ADMIN_KEY = 'MISTRAL_ADMIN_KEY';
const PAGE_SIZE = 100;
const MAX_PAGES = 100;
const KEY_ID = /^[A-Za-z0-9-]{8,64}$/;

type Row = Record<string, unknown>;

function record(value: unknown): Row | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Row : undefined;
}

function secretValues(ctx: ProviderContext, extra: string[] = []): string[] {
  return [...Object.values(ctx.credentials).filter((value): value is string => typeof value === 'string'), ...extra];
}

function keyId(value: unknown, ctx: ProviderContext, extra: string[] = []): string {
  if (typeof value !== 'string' || !KEY_ID.test(value) || safeIdentity(value, '', secretValues(ctx, extra)) !== value) {
    throw new Error(`${PROVIDER} returned an invalid API key reference`);
  }
  return value;
}

/** The Admin API masks keys as the first and last four characters ("HQSx...Ug6Y"); require both ends. */
function matchesHiddenKey(value: string, hidden: unknown): boolean {
  if (typeof hidden !== 'string') return false;
  const parts = hidden.split(/\.{2,}|…|\*+/);
  return parts.length === 2 && /^[A-Za-z0-9]{4,}$/.test(parts[0]!) && /^[A-Za-z0-9]{4,}$/.test(parts[1]!)
    && matchHint(value, hidden);
}

function adminHeaders(admin: string): Record<string, string> {
  // The Admin API authentication guide documents x-api-key (the generated reference shows a bearer example).
  return { 'x-api-key': admin };
}

async function keyRows(ctx: ProviderContext, admin: string): Promise<Row[]> {
  const rows: Row[] = [];
  const seen = new Set<string>();
  for (let page = 0; page < MAX_PAGES; page++) {
    const response = await request(ctx, {
      method: 'GET', url: `${API}/admin/api-keys?limit=${PAGE_SIZE}&offset=${rows.length}`, headers: adminHeaders(admin),
    }, PROVIDER);
    ensureOk(response, PROVIDER);
    const keys = record(readJson<unknown>(response, PROVIDER))?.keys;
    if (!Array.isArray(keys)) throw new Error(`${PROVIDER} returned an invalid API key list`);
    let added = 0;
    for (const entry of keys) {
      const row = record(entry);
      if (!row) throw new Error(`${PROVIDER} returned an invalid API key list`);
      const id = keyId(row.key_id, ctx);
      if (seen.has(id)) continue;
      seen.add(id);
      rows.push(row);
      added++;
    }
    // Offset pagination has no cursor; an empty page or one that adds nothing new ends the listing.
    if (keys.length === 0 || added === 0) return rows;
  }
  throw new Error(`${PROVIDER} returned too many API key pages`);
}

export const mistralProvider: ProviderAdapter = {
  id: 'mistral',
  method: 'guided',

  verify(value, ctx) {
    return verifyRead(ctx, {
      method: 'GET',
      url: `${API}/models`,
      headers: { Authorization: `Bearer ${value}` },
    }, PROVIDER, (data) => {
      if (!Array.isArray(record(data)?.data)) throw new Error('Invalid Mistral models response');
      return 'Mistral API key';
    });
  },

  async resolveKeyRef(value, ctx) {
    const admin = ctx.credentials[MISTRAL_ADMIN_KEY];
    if (!admin?.trim()) return null;
    try {
      const matches = (await keyRows(ctx, admin)).filter(row => matchesHiddenKey(value, row.hidden_key));
      return matches.length === 1 ? keyId(matches[0]!.key_id, ctx, [value]) : null;
    } catch {
      // Guided rotation resolves the old key after a replacement was pasted; never fail that step here.
      ctx.log.warn('Mistral API key reference lookup failed.');
      return null;
    }
  },

  async listKeys(ctx): Promise<ProviderKeyInfo[]> {
    const admin = credential(ctx, MISTRAL_ADMIN_KEY);
    const secrets = secretValues(ctx);
    return (await keyRows(ctx, admin)).map((row) => {
      const name = safeIdentity(row.name, '', secrets);
      const hint = typeof row.hidden_key === 'string' && /^[A-Za-z0-9]{4,8}(?:\.{2,}|…|\*+)[A-Za-z0-9]{4,8}$/.test(row.hidden_key)
        ? row.hidden_key : '';
      const createdAt = typeof row.created_at === 'string' && !Number.isNaN(Date.parse(row.created_at)) ? row.created_at : undefined;
      return {
        keyRef: keyId(row.key_id, ctx),
        ...(name ? { name } : {}),
        ...(hint ? { hint } : {}),
        ...(createdAt ? { createdAt } : {}),
      };
    });
  },

  async revoke(ref, ctx) {
    const admin = credential(ctx, MISTRAL_ADMIN_KEY);
    let id: string;
    try { id = keyId(ref, ctx); } catch { throw new Error(`${PROVIDER} requires a valid API key reference`); }
    const response = await request(ctx, {
      method: 'DELETE', url: `${API}/admin/api-keys/${encodeURIComponent(id)}`, headers: adminHeaders(admin),
    }, PROVIDER);
    ensureOk(response, PROVIDER);
  },

  guidance() {
    return {
      url: 'https://console.mistral.ai/api-keys',
      steps: [
        'Create a replacement API key in the same Workspace with the same Connector access scope and an expiration no later than the exposed key\'s.',
        'Update every consumer and redeploy, then verify the replacement key.',
        `Delete the exposed key in Mistral; with ${MISTRAL_ADMIN_KEY} (an Enterprise Admin API key) keysentry can find and delete it after the grace period.`,
      ],
    };
  },
};
