import type { ProviderAdapter, ProviderContext, VerifyResult } from '../types.js';
import { credential, ensureOk, mutationRequest, ProviderMutationUncertainError, readJson, request } from './shared.js';

const API = 'https://api.cloudflare.com/client/v4';
const PROVIDER = 'cloudflare';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function tokenId(data: unknown, secrets: string[]): string | null {
  if (!isRecord(data) || data.success !== true || !isRecord(data.result)) return null;
  const { id, status } = data.result;
  if (status !== 'active' || typeof id !== 'string' || id.trim().length === 0) return null;
  if (secrets.some((value) => value.length > 0 && id.includes(value))) return null;
  return id;
}

async function inspectToken(value: string, ctx: ProviderContext): Promise<{ verification: VerifyResult; id: string | null }> {
  let status: number | undefined;
  try {
    const response = await request(ctx, {
      method: 'GET',
      url: `${API}/user/tokens/verify`,
      headers: { Authorization: `Bearer ${value}` },
    }, PROVIDER);
    status = response.status;
    if (response.status < 200 || response.status >= 300) {
      return { verification: { ok: false, status, error: `cloudflare verification failed (HTTP ${status})` }, id: null };
    }
    const id = tokenId(readJson<unknown>(response, PROVIDER), [value, ...Object.values(ctx.credentials).filter((item): item is string => typeof item === 'string')]);
    if (!id) {
      return { verification: { ok: false, status, error: 'cloudflare token is not active or its identity is unavailable' }, id: null };
    }
    return { verification: { ok: true, status, identity: id }, id };
  } catch {
    return { verification: { ok: false, status, error: 'cloudflare verification request failed' }, id: null };
  }
}

export const cloudflareProvider: ProviderAdapter = {
  id: PROVIDER,
  method: 'atomic-roll',

  async verify(value, ctx) {
    return (await inspectToken(value, ctx)).verification;
  },

  async resolveKeyRef(value, ctx) {
    return (await inspectToken(value, ctx)).id;
  },

  async rotate(oldValue, ctx) {
    const admin = credential(ctx, 'CLOUDFLARE_ADMIN_TOKEN');
    const { id } = await inspectToken(oldValue, ctx);
    if (!id) throw new Error('cloudflare cannot roll a token without an active verified identity');

    const response = await mutationRequest(ctx, {
      method: 'PUT',
      url: `${API}/user/tokens/${encodeURIComponent(id)}/value`,
      headers: { Authorization: `Bearer ${admin}` },
    }, PROVIDER, { atomic: true });
    ensureOk(response, PROVIDER);
    let data: unknown;
    try {
      data = response.json<unknown>();
    } catch {
      data = undefined;
    }
    if (!isRecord(data) || data.success !== true || typeof data.result !== 'string' || data.result.trim().length === 0) {
      throw new ProviderMutationUncertainError('cloudflare returned an invalid token-roll response; the old token may already be invalid', true);
    }
    return {
      newValue: data.result,
      oldKeyRef: id,
      newKeyRef: id,
      oldRevoked: true,
      notes: 'Cloudflare rolls tokens atomically; the old token is already invalid. Update and redeploy every consumer immediately.',
    };
  },

  guidance() {
    return {
      url: 'https://dash.cloudflare.com/profile/api-tokens',
      steps: [
        'Choose the token in API Tokens and roll it, preserving its permissions.',
        'Rolling is atomic and immediately invalidates the old value. Update every consumer and redeploy immediately.',
        'For automatic rotation, configure CLOUDFLARE_ADMIN_TOKEN with API Tokens Write permission.',
      ],
    };
  },
};
