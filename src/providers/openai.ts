import type {
  HttpRequest, ProviderAdapter, ProviderContext, ProviderKeyInfo, RotationResult, UsageSample,
} from '../types.js';
import { credential, ensureOk, matchHint, readJson, request, safeIdentity, verifyRead } from './shared.js';

const BASE = 'https://api.openai.com/v1';
const PROVIDER = 'OpenAI';

/** Automatic rotation must preserve both ownership and explicit per-key permissions. */
export class OpenAIGuidedRotationRequiredError extends Error {
  readonly code = 'GUIDED_ROTATION_REQUIRED';
  readonly provider = 'openai';

  constructor() {
    super('OpenAI key ownership or permissions cannot be preserved safely; use guided rotation.');
    this.name = 'OpenAIGuidedRotationRequiredError';
  }
}

export interface OpenAIModelPrice {
  inputPerMillionUsd: number;
  outputPerMillionUsd: number;
  cachedInputPerMillionUsd?: number;
}

/** Editable estimates, not billing data. Dated model variants inherit their base model's rates.
 * Unpriced models use the table's highest rate for every token category.
 * Audio, image, batch and fine-tuning prices are not included. Update these rates before relying on estimates.
 */
export const OPENAI_MODEL_PRICES: Record<string, OpenAIModelPrice> = {
  'gpt-4o': { inputPerMillionUsd: 2.5, outputPerMillionUsd: 10, cachedInputPerMillionUsd: 1.25 },
  'gpt-4o-mini': { inputPerMillionUsd: 0.15, outputPerMillionUsd: 0.6, cachedInputPerMillionUsd: 0.075 },
  'gpt-4.1': { inputPerMillionUsd: 2, outputPerMillionUsd: 8, cachedInputPerMillionUsd: 0.5 },
  'gpt-4.1-mini': { inputPerMillionUsd: 0.4, outputPerMillionUsd: 1.6, cachedInputPerMillionUsd: 0.1 },
  'gpt-4.1-nano': { inputPerMillionUsd: 0.1, outputPerMillionUsd: 0.4, cachedInputPerMillionUsd: 0.025 },
  'gpt-4-turbo': { inputPerMillionUsd: 10, outputPerMillionUsd: 30 },
  'gpt-4': { inputPerMillionUsd: 30, outputPerMillionUsd: 60 },
  'gpt-3.5-turbo': { inputPerMillionUsd: 0.5, outputPerMillionUsd: 1.5 },
  o1: { inputPerMillionUsd: 15, outputPerMillionUsd: 60, cachedInputPerMillionUsd: 7.5 },
  'o1-mini': { inputPerMillionUsd: 3, outputPerMillionUsd: 12, cachedInputPerMillionUsd: 1.5 },
  o3: { inputPerMillionUsd: 2, outputPerMillionUsd: 8, cachedInputPerMillionUsd: 0.5 },
  'o3-mini': { inputPerMillionUsd: 1.1, outputPerMillionUsd: 4.4, cachedInputPerMillionUsd: 0.55 },
  'o4-mini': { inputPerMillionUsd: 1.1, outputPerMillionUsd: 4.4, cachedInputPerMillionUsd: 0.275 },
};

type Row = Record<string, unknown>;
interface Page { data: unknown[]; has_more?: boolean; last_id?: unknown; next_page?: unknown }
interface KeyRecord { info: ProviderKeyInfo; rawHint?: string; scopes: unknown }
interface KeyRef { projectId: string; keyId: string; serviceAccountId?: string }

function object(value: unknown): value is Row {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function knownSecrets(ctx: ProviderContext, extra: string[] = []): string[] {
  return [...Object.values(ctx.credentials).filter((value): value is string => typeof value === 'string'), ...extra];
}

function safeLabel(value: unknown, fallback: string, ctx: ProviderContext, extra: string[] = []): string {
  if (typeof value === 'string' && /sk-[A-Za-z0-9_-]{12,}/.test(value)) return fallback;
  return safeIdentity(value, fallback, knownSecrets(ctx, extra));
}

function referenceId(value: unknown, ctx: ProviderContext, extra: string[] = []): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,200}$/.test(value)
    || safeLabel(value, '', ctx, extra) !== value) {
    throw new Error('OpenAI returned an invalid identifier.');
  }
  return value;
}

function parseRef(value: string, ctx: ProviderContext): KeyRef {
  const parts = value.split('/');
  // sa-key explicitly denotes key-only revocation. Legacy sa refs remain readable,
  // but must also revoke only their key: the account may now own a replacement.
  const account = parts.length === 3 ? /^(?:sa-key:|sa:)(.+)$/.exec(parts[2]!) : null;
  if ((parts.length !== 2 && parts.length !== 3) || (parts.length === 3 && !account)) {
    throw new Error('Invalid OpenAI key reference.');
  }
  const projectId = referenceId(parts[0], ctx);
  const keyId = referenceId(parts[1], ctx);
  const serviceAccountId = account ? referenceId(account[1], ctx) : undefined;
  return { projectId, keyId, serviceAccountId };
}

function headers(ctx: ProviderContext): Record<string, string> {
  return { Authorization: `Bearer ${credential(ctx, 'OPENAI_ADMIN_KEY')}` };
}

async function adminJson(ctx: ProviderContext, req: HttpRequest): Promise<unknown> {
  const response = await request(ctx, { ...req, headers: { ...headers(ctx), ...req.headers } }, PROVIDER);
  ensureOk(response, PROVIDER);
  return readJson<unknown>(response, PROVIDER);
}

async function pages(ctx: ProviderContext, path: string, params: URLSearchParams, cursorField: 'after' | 'page' = 'after'): Promise<unknown[]> {
  const rows: unknown[] = [];
  const seen = new Set<string>();
  for (;;) {
    const data = await adminJson(ctx, { method: 'GET', url: `${BASE}${path}?${params.toString()}` });
    if (!object(data) || !Array.isArray(data.data)) throw new Error('OpenAI returned an invalid list response.');
    const page = data as unknown as Page;
    rows.push(...page.data);
    if (page.has_more !== undefined && typeof page.has_more !== 'boolean') {
      throw new Error('OpenAI returned invalid pagination.');
    }
    if (!page.has_more) return rows;
    const cursor = cursorField === 'page' ? page.next_page : page.last_id;
    if (typeof cursor !== 'string' || cursor.length === 0 || cursor.length > 1024
      || safeLabel(cursor, '', ctx) !== cursor || seen.has(cursor)) {
      throw new Error('OpenAI returned invalid pagination cursor.');
    }
    seen.add(cursor);
    params.set(cursorField, cursor);
  }
}

function createdAt(value: unknown): string | undefined {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return undefined;
  const date = new Date(value * 1000);
  return Number.isFinite(date.getTime()) ? date.toISOString() : undefined;
}

function publicHint(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const parts = value.split(/\.\.\.|\u2026/);
  if (parts.length !== 2 || !parts[0] || !parts[1] || parts[1].length < 4) return undefined;
  return `${parts[0].slice(0, 7)}\u2026${parts[1].slice(-4)}`;
}

async function keyRecords(ctx: ProviderContext): Promise<KeyRecord[]> {
  const projects = await pages(ctx, '/organization/projects', new URLSearchParams({ limit: '100' }));
  const records: KeyRecord[] = [];
  const seenRefs = new Set<string>();
  for (const project of projects) {
    if (!object(project)) throw new Error('OpenAI returned an invalid project.');
    const projectId = referenceId(project.id, ctx);
    const keys = await pages(ctx, `/organization/projects/${encodeURIComponent(projectId)}/api_keys`, new URLSearchParams({ limit: '100' }));
    for (const key of keys) {
      if (!object(key)) throw new Error('OpenAI returned an invalid API key record.');
      const keyId = referenceId(key.id, ctx);
      const owner = object(key.owner) ? key.owner : undefined;
      let keyRef = `${projectId}/${keyId}`;
      if (owner?.type === 'service_account') {
        const account = object(owner.service_account) ? owner.service_account : undefined;
        const accountId = referenceId(account?.id, ctx);
        keyRef += `/sa-key:${accountId}`;
      }
      if (seenRefs.has(keyRef)) continue;
      seenRefs.add(keyRef);
      records.push({
        info: {
          keyRef,
          ...(typeof key.name === 'string' ? { name: safeLabel(key.name, 'OpenAI project key', ctx) } : {}),
          ...(publicHint(key.redacted_value) ? { hint: publicHint(key.redacted_value)! } : {}),
          ...(createdAt(key.created_at) ? { createdAt: createdAt(key.created_at)! } : {}),
        },
        ...(typeof key.redacted_value === 'string' ? { rawHint: key.redacted_value } : {}),
        scopes: key.scopes,
      });
    }
  }
  return records;
}

async function resolveKey(value: string, ctx: ProviderContext): Promise<KeyRecord | undefined> {
  const matches = (await keyRecords(ctx)).filter(key => key.rawHint !== undefined && matchHint(value, key.rawHint));
  return matches.length === 1 ? matches[0] : undefined;
}

async function resolveKeyRef(value: string, ctx: ProviderContext): Promise<string | null> {
  return (await resolveKey(value, ctx))?.info.keyRef ?? null;
}

async function rotate(oldValue: string, ctx: ProviderContext): Promise<RotationResult> {
  const oldKey = await resolveKey(oldValue, ctx);
  if (!oldKey) throw new Error('OpenAI key could not be resolved to a project; create a key through the dashboard.');
  const oldKeyRef = oldKey.info.keyRef;
  const { projectId, serviceAccountId } = parseRef(oldKeyRef, ctx);
  if (!serviceAccountId) throw new OpenAIGuidedRotationRequiredError();
  const scopes = oldKey.scopes;
  // Missing scopes do not prove unrestricted access. Empty/default scope semantics
  // are ambiguous, so only explicit, representable permissions permit creation.
  if (!Array.isArray(scopes) || scopes.length === 0 || scopes.some(scope => typeof scope !== 'string'
    || scope.length === 0 || /[\s\u0000-\u001f\u007f]/.test(scope)
    || safeLabel(scope, '', ctx, [oldValue]) !== scope)) {
    throw new OpenAIGuidedRotationRequiredError();
  }
  const accountPath = `${BASE}/organization/projects/${encodeURIComponent(projectId)}/service_accounts`;
  const response = await request(ctx, {
    method: 'POST', url: `${accountPath}/${encodeURIComponent(serviceAccountId)}/api_keys`,
    headers: { ...headers(ctx), 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: `keysentry-${new Date().toISOString()}`, scopes }),
  }, PROVIDER);
  // A rejected scoped request must never be retried with broader default permissions.
  if ([400, 404, 405, 422, 501].includes(response.status)) throw new OpenAIGuidedRotationRequiredError();
  ensureOk(response, PROVIDER);
  const data = readJson<unknown>(response, PROVIDER);
  const key = object(data) ? data : undefined;
  if (!object(key) || typeof key.value !== 'string'
    || key.value.trim().length === 0 || key.value === oldValue) {
    throw new Error('OpenAI did not return a new service-account key.');
  }
  const newValue = key.value;
  const keyId = referenceId(key.id, ctx, [oldValue, newValue]);
  return { newValue, oldKeyRef, newKeyRef: `${projectId}/${keyId}/sa-key:${serviceAccountId}`, oldRevoked: false };
}

async function revoke(keyRef: string, ctx: ProviderContext): Promise<void> {
  const { projectId, keyId } = parseRef(keyRef, ctx);
  const response = await request(ctx, {
    method: 'DELETE', url: `${BASE}/organization/projects/${encodeURIComponent(projectId)}/api_keys/${encodeURIComponent(keyId)}`, headers: headers(ctx),
  }, PROVIDER);
  ensureOk(response, PROVIDER);
}

function count(value: unknown): number {
  if (value === undefined || value === null) return 0;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) throw new Error('OpenAI returned an invalid usage counter.');
  return value;
}

function priceFor(model: string): OpenAIModelPrice | undefined {
  const name = Object.keys(OPENAI_MODEL_PRICES).sort((a, b) => b.length - a.length)
    .find(base => model === base || new RegExp(`^${base.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}-\\d{4}-\\d{2}-\\d{2}$`).test(model));
  return name ? OPENAI_MODEL_PRICES[name] : undefined;
}

async function usage(keyRef: string, window: { from: Date; to: Date }, ctx: ProviderContext): Promise<UsageSample> {
  const { keyId } = parseRef(keyRef, ctx);
  const start = window.from.getTime();
  const end = window.to.getTime();
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) throw new Error('Invalid OpenAI usage window.');
  const buckets = await pages(ctx, '/organization/usage/completions', new URLSearchParams({
    start_time: String(Math.floor(start / 1000)), end_time: String(Math.floor(end / 1000)), bucket_width: '1h',
    api_key_ids: keyId, group_by: 'model',
  }), 'page');
  let costUsd = 0;
  let requests = 0;
  const byModel: Record<string, number> = Object.create(null) as Record<string, number>;
  const warnedModels = new Set<string>();
  for (const bucket of buckets) {
    if (!object(bucket) || !Array.isArray(bucket.results)) throw new Error('OpenAI returned invalid usage buckets.');
    for (const row of bucket.results) {
      if (!object(row)) throw new Error('OpenAI returned invalid usage results.');
      const model = safeLabel(row.model, 'unknown', ctx);
      const input = count(row.input_tokens);
      const output = count(row.output_tokens);
      const cached = Math.min(input, count(row.input_cached_tokens));
      requests += count(row.num_model_requests);
      let price = priceFor(model);
      if (!price) {
        const rate = Math.max(...Object.values(OPENAI_MODEL_PRICES).flatMap(entry => [
          entry.inputPerMillionUsd, entry.outputPerMillionUsd, entry.cachedInputPerMillionUsd ?? entry.inputPerMillionUsd,
        ]));
        price = { inputPerMillionUsd: rate, outputPerMillionUsd: rate, cachedInputPerMillionUsd: rate };
        if (!warnedModels.has(model)) {
          ctx.log.warn('OpenAI usage model has no price estimate; using the highest table rate.', { model, ratePerMillionUsd: rate });
          warnedModels.add(model);
        }
      }
      const cost = ((input - cached) * price.inputPerMillionUsd
        + cached * (price.cachedInputPerMillionUsd ?? price.inputPerMillionUsd)
        + output * price.outputPerMillionUsd) / 1_000_000;
      costUsd += cost;
      byModel[model] = (byModel[model] ?? 0) + cost;
    }
  }
  return { keyRef, from: window.from.toISOString(), to: window.to.toISOString(), costUsd, requests, byModel };
}

export const openaiProvider: ProviderAdapter = {
  id: 'openai', method: 'auto',
  verify: (value, ctx) => verifyRead(ctx, {
    method: 'GET', url: `${BASE}/models`, headers: { Authorization: `Bearer ${value}` },
  }, PROVIDER, () => 'OpenAI API key'),
  rotate,
  revoke,
  resolveKeyRef,
  listKeys: async ctx => (await keyRecords(ctx)).map(key => key.info),
  usage,
  guidance: () => ({
    url: 'https://platform.openai.com/api-keys',
    steps: [
      'Select the same project and create a replacement API key with the same owner and permissions as the previous key.',
      'Update every consumer, redeploy, and verify the new key before deleting the old key.',
      'Automatic rotation needs OPENAI_ADMIN_KEY and explicit scopes that can be copied to a new key in the same service account; otherwise use guided rotation.',
      'Usage cost is an estimate from OPENAI_MODEL_PRICES; update the table for current models and pricing.',
    ],
  }),
};
