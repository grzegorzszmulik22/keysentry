import type { HttpResponse, ProviderAdapter, ProviderContext, ProviderKeyInfo, RotationResult } from '../types.js';
import { credential, ensureOk, readJson, request, safeIdentity, verifyRead } from './shared.js';

// Docs (accessed 2026-10-28): https://www.twilio.com/docs/sendgrid/api-reference/api-keys/create-api-keys,
// .../api-keys/retrieve-an-existing-api-key, .../api-keys/retrieve-all-api-keys-belonging-to-the-authenticated-user,
// .../api-keys/delete-api-keys, .../api-key-permissions/retrieve-a-list-of-scopes-for-which-this-user-has-access.
const API = 'https://api.sendgrid.com/v3';
const PROVIDER = 'SendGrid';
/** `SG.<key id>.<secret>`; the middle segment is used as a candidate id only after the account confirms it. */
const KEY = /^SG\.([A-Za-z0-9_-]{16,})\.([A-Za-z0-9_-]{16,})$/;
const REF = /^[A-Za-z0-9_-]{1,128}$/;
const SCOPE = /^[A-Za-z0-9_.:-]{1,128}$/;

export class SendGridGuidedRotationRequiredError extends Error {
  readonly code = 'GUIDED_ROTATION_REQUIRED';
  readonly provider = 'sendgrid';

  constructor(reason = 'SendGrid key ownership or scopes could not be confirmed') {
    super(`${reason}; use guided rotation.`);
    this.name = 'SendGridGuidedRotationRequiredError';
  }
}

type Row = Record<string, unknown>;

function record(value: unknown): Row | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Row : undefined;
}

function embeddedId(value: string): string | null {
  return KEY.exec(value)?.[1] ?? null;
}

function adminKey(ctx: ProviderContext): string {
  return credential(ctx, 'SENDGRID_ADMIN_KEY');
}

function auth(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

function secrets(ctx: ProviderContext, extra: string[] = []): string[] {
  return [...Object.values(ctx.credentials).filter((value): value is string => typeof value === 'string'), ...extra];
}

/** A non-empty list of distinct, plain scope names, or null. */
function scopeList(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length === 0) return null;
  if (!value.every((scope) => typeof scope === 'string' && SCOPE.test(scope))) return null;
  return new Set(value).size === value.length ? [...value as string[]] : null;
}

function sameScopes(left: string[], right: string[]): boolean {
  const set = new Set(left);
  return left.length === right.length && right.every((scope) => set.has(scope));
}

/** The documented response is `{ result: [ { api_key_id, name, scopes } ] }`; a bare object is accepted too. */
async function describeKey(id: string, admin: string, ctx: ProviderContext): Promise<{ scopes: string[] | null } | null> {
  const response = await request(ctx, { method: 'GET', url: `${API}/api_keys/${id}`, headers: auth(admin) }, PROVIDER);
  if (response.status === 404) return null;
  ensureOk(response, PROVIDER);
  const data = record(readJson<unknown>(response, PROVIDER));
  const entries: unknown[] = Array.isArray(data?.result) ? data.result : data ? [data] : [];
  const matches = entries.map(record).filter((entry): entry is Row => entry?.api_key_id === id);
  if (matches.length !== 1) throw new Error(`${PROVIDER} returned an invalid API key description`);
  const listed = matches[0]!.scopes;
  if (listed === undefined) return { scopes: null };
  const scopes = scopeList(listed);
  if (!scopes) throw new Error(`${PROVIDER} returned an invalid API key description`);
  return { scopes };
}

async function oldKey(oldValue: string, admin: string, ctx: ProviderContext): Promise<{ id: string; scopes: string[] }> {
  const id = embeddedId(oldValue);
  if (!id) throw new SendGridGuidedRotationRequiredError('the value is not a recognized SendGrid API key');
  if (oldValue === admin || id === embeddedId(admin)) {
    throw new SendGridGuidedRotationRequiredError('this is the management key keysentry uses');
  }
  try {
    // The scopes endpoint returns every scope of the key that calls it, so the old key states its own scope.
    const response = await request(ctx, { method: 'GET', url: `${API}/scopes`, headers: auth(oldValue) }, PROVIDER);
    if (response.status < 200 || response.status >= 300) throw new SendGridGuidedRotationRequiredError('the old SendGrid key did not report its scopes');
    const scopes = scopeList(record(readJson<unknown>(response, PROVIDER))?.scopes);
    if (!scopes) throw new SendGridGuidedRotationRequiredError('the old SendGrid key did not report its scopes');
    // Creating with the management key places the replacement in the management key's account. Only proceed when
    // that account knows the old key's id, so a subuser's key is never replaced by a parent-account key.
    const described = await describeKey(id, admin, ctx);
    if (!described) throw new SendGridGuidedRotationRequiredError('the old SendGrid key is not in the management key account');
    if (described.scopes && !sameScopes(described.scopes, scopes)) {
      throw new SendGridGuidedRotationRequiredError('SendGrid reported different scopes for the old key');
    }
    return { id, scopes };
  } catch (error) {
    if (error instanceof SendGridGuidedRotationRequiredError) throw error;
    throw new SendGridGuidedRotationRequiredError();
  }
}

async function removeUnusable(id: string, admin: string, ctx: ProviderContext): Promise<never> {
  let removed = false;
  try {
    const response: HttpResponse = await request(ctx, { method: 'DELETE', url: `${API}/api_keys/${id}`, headers: auth(admin) }, PROVIDER);
    removed = response.status >= 200 && response.status < 300;
  } catch {
    removed = false;
  }
  throw new Error(removed
    ? 'SendGrid returned an unusable or differently scoped replacement key; it was deleted and no consumer was changed.'
    : 'SendGrid returned an unusable or differently scoped replacement key and it could not be deleted; delete the newest keysentry API key in the SendGrid dashboard.');
}

async function createKey(scopes: string[], admin: string, ctx: ProviderContext, previous: string[]): Promise<{ value: string; id: string }> {
  // Scopes are always explicit: SendGrid gives a key created without scopes Full Access.
  const response = await request(ctx, {
    method: 'POST', url: `${API}/api_keys`,
    headers: { ...auth(admin), 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: `keysentry-${new Date().toISOString()}`, scopes }),
  }, PROVIDER);
  ensureOk(response, PROVIDER);
  const data = record(readJson<unknown>(response, PROVIDER));
  const value = data?.api_key;
  const id = data?.api_key_id;
  const known = secrets(ctx, [...previous, ...(typeof value === 'string' && value ? [value] : [])]);
  if (typeof id !== 'string' || !REF.test(id) || safeIdentity(id, '', known) !== id) {
    throw new Error('SendGrid returned an invalid API key creation response; check the SendGrid dashboard for an unused keysentry API key.');
  }
  const returned = scopeList(data?.scopes);
  if (typeof value !== 'string' || value.trim().length === 0 || previous.includes(value) || value === admin
    || !returned || !sameScopes(returned, scopes)) {
    return removeUnusable(id, admin, ctx);
  }
  return { value, id };
}

function reference(keyRef: unknown, admin: string): string {
  if (typeof keyRef !== 'string' || !REF.test(keyRef)) throw new Error('SendGrid requires a valid API key id');
  if (keyRef === embeddedId(admin)) throw new Error('SendGrid will not change the management key keysentry uses');
  return keyRef;
}

export const sendgridProvider: ProviderAdapter = {
  id: 'sendgrid',
  method: 'auto',

  verify(value, ctx) {
    return verifyRead(ctx, { method: 'GET', url: `${API}/scopes`, headers: auth(value) }, PROVIDER, (data) => {
      if (!Array.isArray(record(data)?.scopes)) throw new Error('invalid');
      return 'SendGrid API key';
    });
  },

  async resolveKeyRef(value, ctx) {
    const id = embeddedId(value);
    if (!id) return null;
    return (await describeKey(id, adminKey(ctx), ctx)) ? id : null;
  },

  async rotate(oldValue, ctx): Promise<RotationResult> {
    const admin = adminKey(ctx);
    const previous = await oldKey(oldValue, admin, ctx);
    const created = await createKey(previous.scopes, admin, ctx, [oldValue]);
    return { newValue: created.value, oldKeyRef: previous.id, newKeyRef: created.id, oldRevoked: false };
  },

  async rotateByRef(keyRef, ctx): Promise<RotationResult> {
    const admin = adminKey(ctx);
    let scopes: string[];
    try {
      const ref = reference(keyRef, admin);
      const described = await describeKey(ref, admin, ctx);
      if (!described?.scopes) throw new Error('unknown scopes');
      scopes = described.scopes;
    } catch {
      throw new SendGridGuidedRotationRequiredError('SendGrid did not report the scopes of that key');
    }
    const created = await createKey(scopes, admin, ctx, []);
    return { newValue: created.value, oldKeyRef: keyRef, newKeyRef: created.id, oldRevoked: false };
  },

  async revoke(keyRef, ctx) {
    const admin = adminKey(ctx);
    const ref = reference(keyRef, admin);
    const response = await request(ctx, { method: 'DELETE', url: `${API}/api_keys/${ref}`, headers: auth(admin) }, PROVIDER);
    ensureOk(response, PROVIDER);
  },

  async listKeys(ctx): Promise<ProviderKeyInfo[]> {
    const response = await request(ctx, { method: 'GET', url: `${API}/api_keys`, headers: auth(adminKey(ctx)) }, PROVIDER);
    ensureOk(response, PROVIDER);
    const rows = record(readJson<unknown>(response, PROVIDER))?.result;
    if (!Array.isArray(rows)) throw new Error(`${PROVIDER} returned an invalid key list`);
    return rows.map((entry) => {
      const row = record(entry);
      if (!row || typeof row.api_key_id !== 'string' || !REF.test(row.api_key_id)) throw new Error(`${PROVIDER} returned an invalid key list`);
      const name = safeIdentity(row.name, '', secrets(ctx));
      return { keyRef: row.api_key_id, ...(name ? { name } : {}) };
    });
  },

  guidance() {
    return {
      url: 'https://app.sendgrid.com/settings/api_keys',
      steps: [
        'Create a replacement API key with the same permissions (scopes) as the exposed key; billing keys cannot be combined with other permissions.',
        'Update every consumer and redeploy, then verify the key and application mail delivery.',
        'Delete the exposed API key after the replacement works everywhere. For automatic rotation, configure SENDGRID_ADMIN_KEY with API key create, read and delete permissions in the same account or subuser.',
      ],
    };
  },
};
