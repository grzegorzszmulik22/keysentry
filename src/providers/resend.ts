import type { ProviderAdapter, ProviderContext } from '../types.js';
import { credential, ensureOk, matchHint, mutationRequest, readJson, request, safeIdentity, verifyRead } from './shared.js';

const API_URL = 'https://api.resend.com';

export class ResendGuidedRotationRequiredError extends Error {
  readonly code = 'GUIDED_ROTATION_REQUIRED';
  readonly provider = 'resend';

  constructor() {
    super('Resend key permissions and domain restriction could not be determined safely; use guided rotation.');
    this.name = 'ResendGuidedRotationRequiredError';
  }
}

type Row = Record<string, unknown>;
interface KeyScope { permission: 'full_access' | 'sending_access'; domainId?: string }

function object(value: unknown): value is Row {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function matchesKey(value: string, hint: unknown): boolean {
  if (typeof hint !== 'string') return false;
  if (hint === value) return true;
  const parts = hint.split(/\.{2,}|\u2026|\*+/);
  return parts.length === 2 && /^re_[A-Za-z0-9_-]{4,}$/.test(parts[0]!)
    && /^[A-Za-z0-9_-]{4,}$/.test(parts[1]!) && matchHint(value, hint);
}

function reference(value: unknown, ctx: ProviderContext, extraSecrets: string[] = []): string {
  const secrets = [...Object.values(ctx.credentials).filter((item): item is string => typeof item === 'string'), ...extraSecrets];
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || safeIdentity(value, '', secrets) !== value) {
    throw new Error('resend requires a valid API key reference');
  }
  return value;
}

function verify(value: string, ctx: ProviderContext) {
  return verifyRead(ctx, {
    method: 'GET',
    url: `${API_URL}/domains`,
    headers: { Authorization: `Bearer ${value}` },
  }, 'resend', data => {
    if (!object(data) || !Array.isArray(data.data)) throw new Error('Invalid Resend domains response');
    return 'Resend API key';
  });
}

async function keyScope(oldValue: string, admin: string, ctx: ProviderContext): Promise<KeyScope> {
  const verified = await verify(oldValue, ctx);
  if (!verified.ok) throw new ResendGuidedRotationRequiredError();
  const permission = verified.status === 403 ? 'sending_access' : 'full_access';
  try {
    const response = await request(ctx, {
      method: 'GET', url: `${API_URL}/api-keys`, headers: { Authorization: `Bearer ${admin}` },
    }, 'resend');
    ensureOk(response, 'resend');
    const data = readJson<unknown>(response, 'resend');
    if (!object(data) || !Array.isArray(data.data)
      || (data.has_more !== undefined && data.has_more !== false)) throw new ResendGuidedRotationRequiredError();
    // Current Resend key lists do not identify the old value. Only explicit,
    // uniquely matched scope metadata can make this safe if the API supplies it;
    // missing hints or an omitted domain_id never prove unrestricted access.
    const matches = data.data.filter((key): key is Row => object(key) && matchesKey(oldValue, key.redacted_value));
    const key = matches.length === 1 ? matches[0] : undefined;
    if (!key || (key.permission !== undefined && key.permission !== permission)
      || !Object.hasOwn(key, 'domain_id')) throw new ResendGuidedRotationRequiredError();
    if (key.domain_id === null) return { permission };
    return { permission, domainId: reference(key.domain_id, ctx, [oldValue]) };
  } catch {
    throw new ResendGuidedRotationRequiredError();
  }
}

/** Resend does not expose enough of existing key values to identify the old key. */
export const resendProvider: ProviderAdapter = {
  id: 'resend',
  method: 'auto',

  verify,

  async rotateByRef() {
    // The documented list API does not expose permission or domain_id. An id
    // alone cannot prove the old key's restrictions, even with a full-access key.
    throw new ResendGuidedRotationRequiredError();
  },

  async rotate(oldValue, ctx) {
    const admin = credential(ctx, 'RESEND_ADMIN_KEY');
    const scope = await keyScope(oldValue, admin, ctx);
    const response = await mutationRequest(ctx, {
      method: 'POST',
      url: `${API_URL}/api-keys`,
      headers: { Authorization: `Bearer ${admin}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: `keysentry-${new Date().toISOString()}`, permission: scope.permission,
        ...(scope.domainId === undefined ? {} : { domain_id: scope.domainId }) }),
    }, 'resend');
    ensureOk(response, 'resend');
    const data = readJson<{ token?: unknown; id?: unknown } | null>(response, 'resend');
    const token = data?.token;
    if (typeof token !== 'string' || !token.trim()) {
      throw new Error('resend returned an invalid API key creation response');
    }
    const id = reference(data?.id, ctx, [oldValue, token]);
    return {
      newValue: token,
      oldKeyRef: null,
      newKeyRef: id,
      oldRevoked: false,
      notes: 'The previous Resend API key cannot be identified automatically. After all consumers use the replacement and verification succeeds, manually delete the previous key at https://resend.com/api-keys.',
    };
  },

  async revoke(keyRef, ctx) {
    const admin = credential(ctx, 'RESEND_ADMIN_KEY');
    const id = reference(keyRef, ctx);
    const response = await request(ctx, {
      method: 'DELETE',
      url: `${API_URL}/api-keys/${encodeURIComponent(id)}`,
      headers: { Authorization: `Bearer ${admin}` },
    }, 'resend');
    ensureOk(response, 'resend');
  },

  guidance() {
    return {
      url: 'https://resend.com/api-keys',
      steps: [
        'Create a replacement API key with the same permission and domain restriction as the previous key.',
        'Update every consumer and verify the replacement key.',
        'After verification succeeds, delete the previous key manually; Resend does not expose hints that identify its value.',
      ],
    };
  },
};
