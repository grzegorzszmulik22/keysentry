import type { ProviderAdapter, ProviderContext, ProviderKeyInfo, RotationResult } from '../types.js';
import { credential, ensureOk, mutationRequest, ProviderMutationUncertainError, readJson, request, safeIdentity, verifyRead } from './shared.js';

const BASE = 'https://openrouter.ai/api/v1';
const PROVIDER = 'OpenRouter';
const PAGE_SIZE = 100;

class OpenRouterGuidedRotationRequiredError extends Error {
  readonly code = 'GUIDED_ROTATION_REQUIRED';

  constructor() {
    super('OpenRouter key metadata could not be preserved safely; use guided rotation.');
    this.name = 'OpenRouterGuidedRotationRequiredError';
  }
}

type Row = Record<string, unknown>;
interface KeyRestrictions {
  limit_reset?: 'daily' | 'weekly' | 'monthly' | null;
  include_byok_in_limit?: boolean;
}

// Only these management fields are understood. A new field could constrain the
// old key, so reference rotation must stop until it can reproduce that policy.
const KNOWN_KEY_FIELDS = new Set([
  'hash', 'label', 'name', 'disabled', 'limit', 'limit_remaining',
  'created_at', 'updated_at', 'usage', 'usage_daily', 'usage_weekly', 'usage_monthly',
  'byok_usage', 'byok_usage_daily', 'byok_usage_weekly', 'byok_usage_monthly',
  'limit_reset', 'limitReset', 'include_byok_in_limit', 'includeByokInLimit',
]);

function restrictionAlias(row: Row, snake: string, camel: string): unknown {
  if (Object.hasOwn(row, snake) && Object.hasOwn(row, camel) && row[snake] !== row[camel]) {
    throw new OpenRouterGuidedRotationRequiredError();
  }
  return Object.hasOwn(row, snake) ? row[snake] : row[camel];
}

function keyRestrictions(row: Row): KeyRestrictions {
  if (Object.keys(row).some(field => !KNOWN_KEY_FIELDS.has(field))) {
    throw new OpenRouterGuidedRotationRequiredError();
  }
  const restrictions: KeyRestrictions = {};
  const reset = restrictionAlias(row, 'limit_reset', 'limitReset');
  if (reset !== undefined) {
    if (reset !== null && reset !== 'daily' && reset !== 'weekly' && reset !== 'monthly') {
      throw new OpenRouterGuidedRotationRequiredError();
    }
    restrictions.limit_reset = reset;
  }
  const byok = restrictionAlias(row, 'include_byok_in_limit', 'includeByokInLimit');
  if (byok !== undefined) {
    if (typeof byok !== 'boolean') throw new OpenRouterGuidedRotationRequiredError();
    restrictions.include_byok_in_limit = byok;
  }
  return restrictions;
}

function record(value: unknown): Row | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Row : undefined;
}

function secretValues(ctx: ProviderContext, extra: string[] = []): string[] {
  return [...Object.values(ctx.credentials).filter((value): value is string => typeof value === 'string'), ...extra];
}

function keyRef(value: unknown, ctx: ProviderContext, extra: string[] = []): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)
      || safeIdentity(value, '', secretValues(ctx, extra)) !== value) {
    throw new Error(`${PROVIDER} returned an invalid key reference`);
  }
  return value;
}

function headers(ctx: ProviderContext): Record<string, string> {
  return { Authorization: `Bearer ${credential(ctx, 'OPENROUTER_PROVISIONING_KEY')}`, 'Content-Type': 'application/json' };
}

async function keyRows(ctx: ProviderContext): Promise<Row[]> {
  const auth = headers(ctx);
  const rows: Row[] = [];
  const seen = new Set<string>();
  let offset = 0;
  while (true) {
    // Include disabled keys so a capped key or exhausted canary remains observable.
    const query = `?include_disabled=true${offset === 0 ? '' : `&offset=${offset}`}`;
    const response = await request(ctx, { method: 'GET', url: `${BASE}/keys${query}`, headers: auth }, PROVIDER);
    ensureOk(response, PROVIDER);
    const payload = record(readJson<unknown>(response, PROVIDER));
    if (!Array.isArray(payload?.data)) throw new Error(`${PROVIDER} returned an invalid key list`);
    for (const entry of payload.data) {
      const row = record(entry);
      if (!row) throw new Error(`${PROVIDER} returned an invalid key list`);
      const ref = keyRef(row.hash, ctx);
      if (seen.has(ref)) throw new Error(`${PROVIDER} returned duplicate key references`);
      seen.add(ref);
      rows.push(row);
    }
    if (payload.data.length < PAGE_SIZE) return rows;
    offset += payload.data.length;
  }
}

async function oldKey(value: string, ctx: ProviderContext): Promise<Row | null> {
  const response = await request(ctx, { method: 'GET', url: `${BASE}/key`, headers: { Authorization: `Bearer ${value}` } }, PROVIDER);
  if (response.status === 401 || response.status === 403) return null;
  ensureOk(response, PROVIDER);
  const payload = record(readJson<unknown>(response, PROVIDER));
  const label = record(payload?.data)?.label;
  if (typeof label !== 'string' || label.length === 0) return null;
  const matches = (await keyRows(ctx)).filter((row) => row.label === label);
  return matches.length === 1 ? matches[0]! : null;
}

async function createKey(ctx: ProviderContext, name: string, limit: number | null | undefined,
  restrictions: KeyRestrictions = {}): Promise<{ value: string; keyRef: string }> {
  const body: { name: string; limit?: number | null } & KeyRestrictions = { name, ...restrictions };
  if (limit !== undefined) body.limit = limit;
  const response = await mutationRequest(ctx, { method: 'POST', url: `${BASE}/keys`, headers: headers(ctx), body: JSON.stringify(body) }, PROVIDER);
  ensureOk(response, PROVIDER);
  let payload: Row | undefined;
  try {
    payload = record(response.json<unknown>());
  } catch {
    payload = undefined;
  }
  if (typeof payload?.key !== 'string' || payload.key.length === 0) {
    throw new ProviderMutationUncertainError(`${PROVIDER} returned an invalid new key; check the provider console for an unused keysentry key.`);
  }
  return { value: payload.key, keyRef: keyRef(record(payload.data)?.hash, ctx, [payload.key]) };
}

/** Create a decoy key whose maximum provider spend is one cent. */
export function createCanaryKey(ctx: ProviderContext, name: string): Promise<{ value: string; keyRef: string }> {
  return createKey(ctx, name, 0.01);
}

export interface OpenRouterAdapter extends ProviderAdapter {
  /** Set a hard spending limit after the caller has approved the mutation. */
  setLimit(keyRef: string, limitUsd: number, ctx: ProviderContext): Promise<void>;
}

export const openrouterProvider: OpenRouterAdapter = {
  id: 'openrouter',
  method: 'auto',

  verify(value, ctx) {
    return verifyRead(ctx, { method: 'GET', url: `${BASE}/key`, headers: { Authorization: `Bearer ${value}` } }, PROVIDER, (payload) => {
      const label = record(record(payload)?.data)?.label;
      return safeIdentity(label, 'OpenRouter key', secretValues(ctx, [value]));
    });
  },

  async resolveKeyRef(value, ctx) {
    const row = await oldKey(value, ctx);
    return row ? keyRef(row.hash, ctx, [value]) : null;
  },

  async listKeys(ctx): Promise<ProviderKeyInfo[]> {
    return (await keyRows(ctx)).map((row) => {
      const secrets = secretValues(ctx);
      const name = safeIdentity(row.name, '', secrets);
      const hint = safeIdentity(row.label, '', secrets);
      const createdAt = typeof row.created_at === 'string' && !Number.isNaN(Date.parse(row.created_at)) ? row.created_at : undefined;
      const limit = row.limit;
      if (limit !== undefined && limit !== null && (typeof limit !== 'number' || !Number.isFinite(limit) || limit < 0)) {
        throw new Error(`${PROVIDER} returned an invalid spending limit`);
      }
      return {
        keyRef: keyRef(row.hash, ctx),
        ...(name ? { name } : {}),
        ...(hint ? { hint } : {}),
        ...(createdAt ? { createdAt } : {}),
        ...(typeof row.disabled === 'boolean' ? { disabled: row.disabled } : {}),
        ...(limit !== undefined ? { limitUsd: limit as number | null } : {}),
      };
    });
  },

  async rotate(value, ctx): Promise<RotationResult> {
    credential(ctx, 'OPENROUTER_PROVISIONING_KEY');
    const previous = await oldKey(value, ctx);
    if (!previous) throw new Error(`${PROVIDER} could not identify the old key; no replacement was created`);
    const previousRef = keyRef(previous.hash, ctx, [value]);
    const limit = previous.limit;
    if (limit !== undefined && limit !== null && (typeof limit !== 'number' || !Number.isFinite(limit) || limit < 0)) {
      throw new Error(`${PROVIDER} returned an invalid spending limit`);
    }
    const created = await createKey(ctx, `keysentry-${new Date().toISOString()}`, limit as number | null | undefined);
    return { newValue: created.value, oldKeyRef: previousRef, newKeyRef: created.keyRef, oldRevoked: false };
  },

  async rotateByRef(ref, ctx): Promise<RotationResult> {
    let previousRef: string;
    try {
      previousRef = keyRef(ref, ctx);
    } catch {
      throw new OpenRouterGuidedRotationRequiredError();
    }
    const response = await request(ctx, {
      method: 'GET', url: `${BASE}/keys/${encodeURIComponent(previousRef)}`, headers: headers(ctx),
    }, PROVIDER);
    ensureOk(response, PROVIDER);
    const previous = record(record(readJson<unknown>(response, PROVIDER))?.data);
    if (!previous || previous.hash !== previousRef || previous.disabled !== false
      || typeof previous.name !== 'string' || !previous.name.trim()
      || safeIdentity(previous.name, '', secretValues(ctx)) !== previous.name
      || (previous.limit !== null && (typeof previous.limit !== 'number'
        || !Number.isFinite(previous.limit) || previous.limit < 0))) {
      throw new OpenRouterGuidedRotationRequiredError();
    }
    const created = await createKey(ctx, previous.name, previous.limit as number | null, keyRestrictions(previous));
    return { newValue: created.value, oldKeyRef: previousRef, newKeyRef: created.keyRef, oldRevoked: false };
  },

  async revoke(ref, ctx) {
    const response = await request(ctx, { method: 'DELETE', url: `${BASE}/keys/${encodeURIComponent(keyRef(ref, ctx))}`, headers: headers(ctx) }, PROVIDER);
    ensureOk(response, PROVIDER);
  },

  async cap(ref, ctx) {
    const response = await request(ctx, { method: 'PATCH', url: `${BASE}/keys/${encodeURIComponent(keyRef(ref, ctx))}`, headers: headers(ctx), body: JSON.stringify({ disabled: true }) }, PROVIDER);
    ensureOk(response, PROVIDER);
  },

  async setLimit(ref, limitUsd, ctx) {
    if (!Number.isFinite(limitUsd) || limitUsd < 0) {
      throw new Error(`${PROVIDER} spending limit must be a finite, non-negative number`);
    }
    const response = await request(ctx, {
      method: 'PATCH', url: `${BASE}/keys/${encodeURIComponent(keyRef(ref, ctx))}`,
      headers: headers(ctx), body: JSON.stringify({ limit: limitUsd }),
    }, PROVIDER);
    ensureOk(response, PROVIDER);
  },

  async usage(ref, window, ctx) {
    keyRef(ref, ctx);
    const row = (await keyRows(ctx)).find((entry) => entry.hash === ref);
    if (!row || typeof row.usage !== 'number' || !Number.isFinite(row.usage) || row.usage < 0) {
      throw new Error(`${PROVIDER} did not return a valid cumulative usage counter`);
    }
    return { keyRef: ref, from: window.from.toISOString(), to: window.to.toISOString(), costUsd: 0, cumulativeCostUsd: row.usage };
  },

  guidance() {
    return { url: 'https://openrouter.ai/settings/keys', steps: ['Create a new key with the same spending limit.', 'Update every consumer and verify the replacement key.', 'Delete the old key after its consumers have redeployed.'] };
  },
};
