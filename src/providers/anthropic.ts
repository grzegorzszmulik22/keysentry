import type { HttpRequest, ProviderAdapter, ProviderContext, ProviderKeyInfo, UsageSample } from '../types.js';
import { credential, ensureOk, matchHint, readJson, request, safeIdentity, verifyRead } from './shared.js';

const BASE_URL = 'https://api.anthropic.com/v1';
const VERSION = '2023-06-01';

interface ModelPrice {
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
  cacheWriteOneHour: number;
}

/** Estimated USD per million tokens. Update when models or pricing change; excludes batch discounts and tiers. */
export const ANTHROPIC_MODEL_PRICES: Record<string, ModelPrice> = {
  'claude-sonnet-4': { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75, cacheWriteOneHour: 6 },
  'claude-3-7-sonnet': { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75, cacheWriteOneHour: 6 },
  'claude-3-5-sonnet': { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75, cacheWriteOneHour: 6 },
  'claude-opus-4': { input: 15, output: 75, cacheRead: 1.5, cacheWrite: 18.75, cacheWriteOneHour: 30 },
  'claude-3-opus': { input: 15, output: 75, cacheRead: 1.5, cacheWrite: 18.75, cacheWriteOneHour: 30 },
  'claude-3-5-haiku': { input: 0.8, output: 4, cacheRead: 0.08, cacheWrite: 1, cacheWriteOneHour: 1.6 },
  'claude-haiku-4-5': { input: 1, output: 5, cacheRead: 0.1, cacheWrite: 1.25, cacheWriteOneHour: 2 },
  'claude-3-haiku': { input: 0.25, output: 1.25, cacheRead: 0.03, cacheWrite: 0.3, cacheWriteOneHour: 0.5 },
};

type JsonObject = Record<string, unknown>;

function object(value: unknown): JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('anthropic: invalid API response');
  return value as JsonObject;
}

function containsCredential(value: string, ctx: ProviderContext): boolean {
  return Object.values(ctx.credentials).some(secret => typeof secret === 'string' && secret.length > 0 && value.includes(secret));
}

function reference(value: unknown, ctx: ProviderContext): string {
  if (typeof value !== 'string' || !/^apikey_[A-Za-z0-9_-]{1,128}$/.test(value)
    || value.includes('sk-') || containsCredential(value, ctx)) {
    throw new Error('anthropic: invalid API key reference');
  }
  return value;
}

function hasMore(data: JsonObject): boolean {
  if (data.has_more === undefined) return false;
  if (typeof data.has_more !== 'boolean') throw new Error('anthropic: invalid pagination flag');
  return data.has_more;
}

function headers(ctx: ProviderContext): Record<string, string> {
  return {
    'x-api-key': credential(ctx, 'ANTHROPIC_ADMIN_KEY'),
    'anthropic-version': VERSION,
    'content-type': 'application/json',
  };
}

async function get(ctx: ProviderContext, url: URL): Promise<JsonObject> {
  const response = await request(ctx, { method: 'GET', url: url.toString(), headers: headers(ctx) }, 'anthropic');
  ensureOk(response, 'anthropic');
  return object(readJson<unknown>(response, 'anthropic'));
}

async function keys(ctx: ProviderContext): Promise<JsonObject[]> {
  const entries: JsonObject[] = [];
  const seen = new Set<string>();
  let after: string | undefined;
  while (true) {
    const url = new URL(`${BASE_URL}/organizations/api_keys`);
    url.searchParams.set('limit', '100');
    url.searchParams.set('status', 'active');
    if (after) url.searchParams.set('after_id', after);
    const data = await get(ctx, url);
    if (!Array.isArray(data.data)) throw new Error('anthropic: invalid API key list');
    for (const entry of data.data) {
      const key = object(entry);
      reference(key.id, ctx);
      if (key.status === undefined || key.status === 'active') entries.push(key);
    }
    if (!hasMore(data)) break;
    const cursor = reference(data.last_id, ctx);
    if (seen.has(cursor)) throw new Error('anthropic: repeated API key pagination cursor');
    seen.add(cursor);
    after = cursor;
  }
  return entries;
}

function hint(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const split = value.split(/\.{3}|…/);
  const prefix = split[0];
  const suffix = split[1];
  if (split.length !== 2 || !prefix || !suffix) return undefined;
  return `${prefix.slice(0, 7)}…${suffix.slice(-4)}`;
}

async function listKeys(ctx: ProviderContext): Promise<ProviderKeyInfo[]> {
  const secrets = Object.values(ctx.credentials).filter((value): value is string => typeof value === 'string');
  return (await keys(ctx)).map(key => {
    const keyRef = reference(key.id, ctx);
    const name = safeIdentity(
      typeof key.name === 'string' && /sk-[A-Za-z0-9_-]{12,}/.test(key.name) ? undefined : key.name,
      'Anthropic API key', secrets,
    );
    const result: ProviderKeyInfo = { keyRef, name, disabled: false };
    const partialHint = hint(key.partial_key_hint);
    if (partialHint) result.hint = partialHint;
    if (typeof key.created_at === 'string' && Number.isFinite(Date.parse(key.created_at))) {
      result.createdAt = new Date(key.created_at).toISOString();
    }
    return result;
  });
}

async function resolveKeyRef(value: string, ctx: ProviderContext): Promise<string | null> {
  const matches = (await keys(ctx)).filter(key => typeof key.partial_key_hint === 'string' && matchHint(value, key.partial_key_hint));
  return matches.length === 1 ? reference(matches[0]!.id, ctx) : null;
}

async function revoke(keyRef: string, ctx: ProviderContext): Promise<void> {
  const id = reference(keyRef, ctx);
  const response = await request(ctx, {
    method: 'POST', url: `${BASE_URL}/organizations/api_keys/${encodeURIComponent(id)}`,
    headers: headers(ctx), body: JSON.stringify({ status: 'inactive' }),
  }, 'anthropic');
  ensureOk(response, 'anthropic');
}

function tokens(value: unknown): number {
  if (value === undefined || value === null) return 0;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) throw new Error('anthropic: invalid usage token count');
  return value;
}

function modelPrice(model: unknown, ctx: ProviderContext): { model: string; price: ModelPrice; fallback: boolean } {
  const secrets = Object.values(ctx.credentials).filter((value): value is string => typeof value === 'string' && value.length > 0);
  if (typeof model !== 'string' || !/^claude-[a-z0-9][a-z0-9._-]{0,127}$/.test(model)
    || safeIdentity(model, '', secrets) !== model) {
    throw new Error('anthropic: missing or invalid usage model');
  }
  const entry = Object.entries(ANTHROPIC_MODEL_PRICES)
    .sort(([left], [right]) => right.length - left.length)
    .find(([name]) => model === name || model === `${name}-latest`
      || (model.startsWith(`${name}-`) && /^\d{8}$/.test(model.slice(name.length + 1))));
  if (entry) return { model, price: entry[1], fallback: false };
  // Apply the single highest rate to every token category, including discounted cache tokens.
  const rate = Math.max(...Object.values(ANTHROPIC_MODEL_PRICES).flatMap(price => Object.values(price)));
  return {
    model,
    price: { input: rate, output: rate, cacheRead: rate, cacheWrite: rate, cacheWriteOneHour: rate },
    fallback: true,
  };
}

function estimate(result: JsonObject, price: ModelPrice): number {
  const cache = result.cache_creation === undefined || result.cache_creation === null ? undefined : object(result.cache_creation);
  const oneHour = cache ? tokens(cache.ephemeral_1h_input_tokens) : 0;
  const cacheWrite = tokens(result.cache_creation_input_tokens);
  const fiveMinute = cache && cache.ephemeral_5m_input_tokens !== undefined
    ? tokens(cache.ephemeral_5m_input_tokens)
    : Math.max(0, cacheWrite - oneHour);
  return (
    tokens(result.uncached_input_tokens ?? result.input_tokens) * price.input
    + tokens(result.output_tokens) * price.output
    + tokens(result.cache_read_input_tokens) * price.cacheRead
    + fiveMinute * price.cacheWrite
    + oneHour * price.cacheWriteOneHour
  ) / 1_000_000;
}

async function usage(keyRef: string, window: { from: Date; to: Date }, ctx: ProviderContext): Promise<UsageSample> {
  const id = reference(keyRef, ctx);
  if (!Number.isFinite(window.from.getTime()) || !Number.isFinite(window.to.getTime()) || window.from >= window.to) {
    throw new Error('anthropic: invalid usage window');
  }
  const from = window.from.toISOString();
  const to = window.to.toISOString();
  const byModel: Record<string, number> = {};
  const seen = new Set<string>();
  const warnedModels = new Set<string>();
  let page: string | undefined;
  while (true) {
    const url = new URL(`${BASE_URL}/organizations/usage_report/messages`);
    url.searchParams.set('starting_at', from);
    url.searchParams.set('ending_at', to);
    url.searchParams.set('bucket_width', '1h');
    url.searchParams.set('api_key_ids[]', id);
    url.searchParams.set('group_by[]', 'model');
    if (page) url.searchParams.set('page', page);
    const data = await get(ctx, url);
    if (!Array.isArray(data.data)) throw new Error('anthropic: invalid usage response');
    for (const bucketValue of data.data) {
      const bucket = object(bucketValue);
      if (!Array.isArray(bucket.results)) throw new Error('anthropic: invalid usage bucket');
      for (const resultValue of bucket.results) {
        const result = object(resultValue);
        const { model, price, fallback } = modelPrice(result.model, ctx);
        if (fallback && !warnedModels.has(model)) {
          ctx.log.warn('anthropic: unknown usage model; estimating every token at the highest table rate', { model });
          warnedModels.add(model);
        }
        byModel[model] = (byModel[model] ?? 0) + estimate(result, price);
      }
    }
    if (!hasMore(data)) break;
    if (typeof data.next_page !== 'string' || !/^[A-Za-z0-9+/=_-]{1,512}$/.test(data.next_page)
      || data.next_page.includes('sk-') || containsCredential(data.next_page, ctx) || seen.has(data.next_page)) {
      throw new Error('anthropic: invalid or repeated usage pagination cursor');
    }
    seen.add(data.next_page);
    page = data.next_page;
  }
  return { keyRef: id, from, to, costUsd: Object.values(byModel).reduce((sum, amount) => sum + amount, 0), byModel };
}

export const anthropicProvider: ProviderAdapter = {
  id: 'anthropic',
  method: 'guided',
  verify(value, ctx) {
    const req: HttpRequest = {
      method: 'GET', url: `${BASE_URL}/models`,
      headers: { 'x-api-key': value, 'anthropic-version': VERSION },
    };
    return verifyRead(ctx, req, 'anthropic', () => 'Anthropic API key');
  },
  listKeys,
  resolveKeyRef,
  revoke,
  // Containment disables the key immediately and interrupts every consumer using it.
  cap: revoke,
  usage,
  guidance() {
    return {
      url: 'https://platform.claude.com/settings/keys',
      steps: [
        'Create a replacement API key in the Anthropic Console.',
        'Update every consumer, redeploy, and verify the replacement before disabling the old key.',
        'Containment disables the key immediately and interrupts every consumer using it.',
        'Usage cost is an estimate from ANTHROPIC_MODEL_PRICES; unknown models use its highest rate for every token category. Update the table for current pricing and models.',
      ],
    };
  },
};
