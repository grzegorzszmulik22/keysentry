import type { ProviderAdapter, ProviderContext, ProviderKeyInfo, RotationResult } from '../types.js';
import { credential, ensureOk, readJson, request, safeIdentity, verifyRead } from './shared.js';

// Docs (accessed 2026-10-28): https://neon.com/docs/manage/api-keys,
// https://neon.com/docs/reference/api/api-keys/create-api-key, .../api-keys/list-api-keys, .../api-keys/revoke-api-key,
// https://neon.com/docs/reference/api/users/get-auth-details (GET /auth).
const API = 'https://console.neon.tech/api/v2';
const PROVIDER = 'Neon';
const KEY_ID = /^\d{1,20}$/;
const CONSOLE_URL = 'https://console.neon.tech/app/settings/api-keys';

export class NeonGuidedRotationRequiredError extends Error {
  readonly code = 'GUIDED_ROTATION_REQUIRED';
  readonly provider = 'neon';

  constructor(reason = 'Neon key ownership could not be confirmed') {
    super(`${reason}; use guided rotation.`);
    this.name = 'NeonGuidedRotationRequiredError';
  }
}

type Row = Record<string, unknown>;

function record(value: unknown): Row | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Row : undefined;
}

function adminKey(ctx: ProviderContext): string {
  return credential(ctx, 'NEON_ADMIN_KEY');
}

function auth(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

function keyId(value: unknown): string | null {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return String(value);
  if (typeof value === 'string' && KEY_ID.test(value)) return value;
  return null;
}

/** The personal-key owner, or null for organization/project keys and anything unexpected. */
async function personalOwner(token: string, ctx: ProviderContext): Promise<string | null> {
  const response = await request(ctx, { method: 'GET', url: `${API}/auth`, headers: auth(token) }, PROVIDER);
  if (response.status < 200 || response.status >= 300) return null;
  const data = record(readJson<unknown>(response, PROVIDER));
  const account = data?.account_id;
  return data?.auth_method === 'api_key_user' && typeof account === 'string' && account.trim().length > 0 ? account : null;
}

async function personalKeys(admin: string, ctx: ProviderContext): Promise<Row[]> {
  const response = await request(ctx, { method: 'GET', url: `${API}/api_keys`, headers: auth(admin) }, PROVIDER);
  ensureOk(response, PROVIDER);
  const rows = readJson<unknown>(response, PROVIDER);
  if (!Array.isArray(rows)) throw new Error(`${PROVIDER} returned an invalid key list`);
  return rows.map((entry) => {
    const row = record(entry);
    if (!row || keyId(row.id) === null) throw new Error(`${PROVIDER} returned an invalid key list`);
    return row;
  });
}

async function createKey(admin: string, ctx: ProviderContext, previous: string[]): Promise<{ value: string; id: string }> {
  const response = await request(ctx, {
    method: 'POST', url: `${API}/api_keys`,
    headers: { ...auth(admin), 'Content-Type': 'application/json' },
    body: JSON.stringify({ key_name: `keysentry-${new Date().toISOString()}` }),
  }, PROVIDER);
  ensureOk(response, PROVIDER);
  const data = record(readJson<unknown>(response, PROVIDER));
  const id = keyId(data?.id);
  const value = data?.key;
  if (id === null || typeof value !== 'string' || value.trim().length === 0 || previous.includes(value) || value === admin) {
    throw new Error('Neon returned an invalid API key creation response; check the Neon Console for an unused keysentry API key.');
  }
  return { value, id };
}

/**
 * API keys only. A connection-string role password can be reset (`reset_password`), but that invalidates every
 * other copy of the password (pooled and direct URLs, PG* variables) at once; those copies have different values,
 * so they are separate inventory clusters this adapter cannot see. Passwords therefore stay guided.
 */
export const neonProvider: ProviderAdapter = {
  id: 'neon',
  method: 'auto',

  verify(value, ctx) {
    return verifyRead(ctx, { method: 'GET', url: `${API}/auth`, headers: auth(value) }, PROVIDER, (data) => {
      const details = record(data);
      if (!details) throw new Error('invalid');
      if (details.auth_method === 'api_key_user') return 'Neon personal API key';
      if (details.auth_method === 'api_key_org') return 'Neon organization API key';
      return 'Neon API key';
    });
  },

  async rotate(oldValue, ctx): Promise<RotationResult> {
    if (oldValue.includes('://')) {
      throw new NeonGuidedRotationRequiredError('Neon role passwords are reset in the Neon Console, which ends every copy of the old password at once');
    }
    const admin = adminKey(ctx);
    if (oldValue === admin) throw new NeonGuidedRotationRequiredError('this is the management key keysentry uses');
    try {
      // Personal keys carry their user's access and have no other settings, so a personal key created by the same
      // user preserves owner and scope. Organization and project-scoped keys are created per organization/project
      // and stay guided.
      const owner = await personalOwner(oldValue, ctx);
      if (owner === null) throw new NeonGuidedRotationRequiredError('the old key is not a working Neon personal API key');
      if (await personalOwner(admin, ctx) !== owner) {
        throw new NeonGuidedRotationRequiredError('the old key and NEON_ADMIN_KEY belong to different Neon users');
      }
    } catch (error) {
      if (error instanceof NeonGuidedRotationRequiredError) throw error;
      throw new NeonGuidedRotationRequiredError();
    }
    const created = await createKey(admin, ctx, [oldValue]);
    return {
      newValue: created.value,
      oldKeyRef: null,
      newKeyRef: created.id,
      oldRevoked: false,
      notes: `Neon does not expose any part of existing key values, so the previous key cannot be identified automatically. After every consumer uses the replacement and verification succeeds, delete the previous key at ${CONSOLE_URL}.`,
    };
  },

  async rotateByRef(keyRef, ctx): Promise<RotationResult> {
    const admin = adminKey(ctx);
    try {
      if (typeof keyRef !== 'string' || !KEY_ID.test(keyRef)) throw new Error('invalid');
      // The list contains only the management user's personal keys: a match proves the same owner.
      if (!(await personalKeys(admin, ctx)).some((row) => keyId(row.id) === keyRef)) throw new Error('not listed');
    } catch {
      throw new NeonGuidedRotationRequiredError('that key is not a personal key of the NEON_ADMIN_KEY user');
    }
    const created = await createKey(admin, ctx, []);
    return { newValue: created.value, oldKeyRef: keyRef, newKeyRef: created.id, oldRevoked: false };
  },

  async revoke(keyRef, ctx) {
    const admin = adminKey(ctx);
    if (typeof keyRef !== 'string' || !KEY_ID.test(keyRef)) throw new Error('Neon requires a numeric API key id');
    const response = await request(ctx, { method: 'DELETE', url: `${API}/api_keys/${keyRef}`, headers: auth(admin) }, PROVIDER);
    ensureOk(response, PROVIDER);
    let data: Row | undefined;
    try {
      data = record(response.json<unknown>());
    } catch {
      data = undefined;
    }
    if (data?.revoked === false) throw new Error(`${PROVIDER} did not revoke the API key`);
  },

  async listKeys(ctx): Promise<ProviderKeyInfo[]> {
    const known = Object.values(ctx.credentials).filter((value): value is string => typeof value === 'string');
    return (await personalKeys(adminKey(ctx), ctx)).map((row) => {
      const name = safeIdentity(row.name, '', known);
      const createdAt = typeof row.created_at === 'string' && !Number.isNaN(Date.parse(row.created_at)) ? row.created_at : undefined;
      return { keyRef: keyId(row.id)!, ...(name ? { name } : {}), ...(createdAt ? { createdAt } : {}) };
    });
  },

  guidance() {
    return {
      url: CONSOLE_URL,
      steps: [
        'For an API key: create a replacement of the same kind (personal, organization, or project-scoped for the same project) and update every consumer.',
        'Verify the replacement, then revoke the exposed key in the same API keys list.',
        'For a database connection string: open the branch in the Neon Console, choose Roles, and Reset password. The old password stops working at once, so update every variable that contains it (pooled and direct URLs, PGPASSWORD) and redeploy right away.',
      ],
    };
  },
};
