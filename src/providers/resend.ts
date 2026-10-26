import type { ProviderAdapter, ProviderContext } from '../types.js';
import { credential, ensureOk, readJson, request, safeIdentity, verifyRead } from './shared.js';

const API_URL = 'https://api.resend.com';

function reference(value: unknown, ctx: ProviderContext, extraSecrets: string[] = []): string {
  const secrets = [...Object.values(ctx.credentials).filter((item): item is string => typeof item === 'string'), ...extraSecrets];
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || safeIdentity(value, '', secrets) !== value) {
    throw new Error('resend requires a valid API key reference');
  }
  return value;
}

/** Resend does not expose enough of existing key values to identify the old key. */
export const resendProvider: ProviderAdapter = {
  id: 'resend',
  method: 'auto',

  async verify(value, ctx) {
    return verifyRead(ctx, {
      method: 'GET',
      url: `${API_URL}/domains`,
      headers: { Authorization: `Bearer ${value}` },
    }, 'resend', () => 'Resend API key');
  },

  async rotate(oldValue, ctx) {
    const admin = credential(ctx, 'RESEND_ADMIN_KEY');
    const response = await request(ctx, {
      method: 'POST',
      url: `${API_URL}/api-keys`,
      headers: { Authorization: `Bearer ${admin}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: `keysentry-${new Date().toISOString()}`, permission: 'full_access' }),
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
        'Create a replacement API key with the permissions required by its consumers.',
        'Update every consumer and verify the replacement key.',
        'After verification succeeds, delete the previous key manually; Resend does not expose hints that identify its value.',
      ],
    };
  },
};
