import type { HttpRequest, HttpResponse, ProviderContext, VerifyResult } from '../types.js';

function protectedValues(ctx: ProviderContext, req: HttpRequest): string[] {
  return [
    ...Object.values(ctx.credentials),
    ...Object.entries(req.headers ?? {}).flatMap(([name, value]) =>
      /^(?:authorization|x-api-key|apikey|x-amz-security-token)$/i.test(name)
        ? [value, value.replace(/^Bearer\s+/i, '')] : []),
  ].filter((value): value is string => typeof value === 'string' && value.length > 0);
}

function assertSafeUrl(ctx: ProviderContext, req: HttpRequest): void {
  // Check decoded URLs too: escaping a credential does not make it safe to put
  // in a path or query. Provider references and pagination cursors are public.
  const url = decodeURIComponent(req.url);
  if (safeIdentity(url, '', protectedValues(ctx, req)) !== url) throw new Error();
}

/** Do not preserve upstream errors: clients can include request headers/bodies in them. */
export async function request(ctx: ProviderContext, req: HttpRequest, provider: string): Promise<HttpResponse> {
  try {
    assertSafeUrl(ctx, req);
    return await ctx.http.request(req);
  } catch {
    throw new Error(`${provider} request failed`);
  }
}

/**
 * siblingVars entries under this prefix are other planned forms of the credential being rolled (the engine adds them
 * when one atomic roll changes several inventoried forms, such as an Upstash REST token and a Redis URL of the same
 * database). An atomic-roll adapter returns each one's new value as a companion under the same name, including a form
 * the roll left unchanged, and omits it only when its new value is unknown. The engine strips these names before
 * writing companions.
 */
export const PLANNED_FORM_PREFIX = 'keysentry:planned-form:';

/**
 * A provider change (a key creation, reset or roll) may have happened, but its outcome is unknown: the request got no
 * answer, the provider failed with a server error, or it answered without a usable result. The rotation engine then
 * records a possible stray key (or, for an atomic roll, a possibly dead old credential) and reports the step as needing
 * attention, never as "nothing changed". The message is fixed text. `keyRef` names the possible stray key when known.
 */
export class ProviderMutationUncertainError extends Error {
  readonly code = 'MUTATION_UNCERTAIN';

  constructor(message: string, readonly atomic = false, readonly keyRef: string | null = null) {
    super(message);
    this.name = 'ProviderMutationUncertainError';
  }
}

/**
 * Send the request that creates, resets or rolls a credential. No answer, or a 5xx answer, leaves the outcome unknown
 * and raises ProviderMutationUncertainError; every other response (including 4xx refusals) is returned as usual.
 */
export async function mutationRequest(ctx: ProviderContext, req: HttpRequest, provider: string,
  options: { atomic?: boolean } = {}): Promise<HttpResponse> {
  try {
    assertSafeUrl(ctx, req);
  } catch {
    throw new Error(`${provider} request failed`);
  }
  const outcome = options.atomic
    ? 'the change may already have happened and the old credential may already be invalid. Check it in the provider console.'
    : 'a replacement key may already exist. Check the provider console for an unused keysentry key.';
  let response: HttpResponse;
  try {
    response = await ctx.http.request(req);
  } catch {
    throw new ProviderMutationUncertainError(`${provider} request failed (no answer); ${outcome}`, options.atomic === true);
  }
  // 501 Not Implemented is a definite refusal of the method, so nothing was changed.
  if (response.status >= 500 && response.status !== 501) {
    throw new ProviderMutationUncertainError(`${provider} request failed (HTTP ${response.status}); ${outcome}`, options.atomic === true);
  }
  return response;
}

export function ensureOk(response: HttpResponse, provider: string): void {
  if (response.status < 200 || response.status >= 300) {
    throw new Error(`${provider} request failed (HTTP ${response.status})`);
  }
}

export function readJson<T = unknown>(response: HttpResponse, provider: string): T {
  try {
    return response.json<T>();
  } catch {
    throw new Error(`${provider} returned an invalid response`);
  }
}

export function credential(ctx: ProviderContext, name: string): string {
  const value = ctx.credentials[name];
  if (!value?.trim()) throw new Error(`Missing provider credential: ${name}`);
  return value;
}

export function safeIdentity(value: unknown, fallback: string, secrets: string[] = []): string {
  if (typeof value !== 'string' || !value.trim()) return fallback;
  if (secrets.some(secret => secret.length > 0 && value.includes(secret))) return fallback;
  // Provider-controlled names and labels occasionally contain credentials. Keep
  // partial hints, but refuse recognizable complete secrets even when unrelated
  // to the credential used for this call.
  if (/(?:sk-(?:proj-|svcacct-|or-v1-|ant-[a-z0-9-]*-)?[A-Za-z0-9_-]{20,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|whsec_[A-Za-z0-9]{16,}|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{16,}|xox[baprs]-[A-Za-z0-9-]{12,}|re_[A-Za-z0-9_-]{20,}|sb_secret_[A-Za-z0-9_-]{16,}|SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|https:\/\/hooks\.slack\.com\/services\/)/.test(value)) return fallback;
  return value;
}

export async function verifyRead(
  ctx: ProviderContext,
  req: HttpRequest,
  provider: string,
  identify: (data: unknown) => string | undefined,
  limited = true,
): Promise<VerifyResult> {
  let status: number | undefined;
  try {
    const response = await request(ctx, req, provider);
    status = response.status;
    if (status === 403 && limited) return { ok: true, identity: `${provider} (limited)`, status };
    if (status < 200 || status >= 300) {
      return { ok: false, status, error: `${provider} verification failed (HTTP ${status})` };
    }
    const data = readJson(response, provider);
    return { ok: true, identity: safeIdentity(identify(data), provider, protectedValues(ctx, req)), status };
  } catch {
    return { ok: false, status, error: `${provider} verification failed` };
  }
}

/** Match both visible ends, so a common provider prefix alone cannot identify a key. */
export function matchHint(value: string, hint: string): boolean {
  const parts = hint.split(/\.{2,}|…|\*+/);
  if (parts.length !== 2) return value === hint;
  const [prefix, suffix] = parts;
  return !!prefix && !!suffix && value.length >= prefix.length + suffix.length
    && value.startsWith(prefix) && value.endsWith(suffix);
}
