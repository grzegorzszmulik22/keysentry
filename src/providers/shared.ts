import type { HttpRequest, HttpResponse, ProviderContext, VerifyResult } from '../types.js';

function protectedValues(ctx: ProviderContext, req: HttpRequest): string[] {
  return [
    ...Object.values(ctx.credentials),
    ...Object.entries(req.headers ?? {}).flatMap(([name, value]) =>
      /^(?:authorization|x-api-key|apikey|x-amz-security-token)$/i.test(name)
        ? [value, value.replace(/^Bearer\s+/i, '')] : []),
  ].filter((value): value is string => typeof value === 'string' && value.length > 0);
}

/** Do not preserve upstream errors: clients can include request headers/bodies in them. */
export async function request(ctx: ProviderContext, req: HttpRequest, provider: string): Promise<HttpResponse> {
  try {
    // Check decoded URLs too: escaping a credential does not make it safe to put
    // in a path or query. Provider references and pagination cursors are public.
    const url = decodeURIComponent(req.url);
    if (safeIdentity(url, '', protectedValues(ctx, req)) !== url) throw new Error();
    return await ctx.http.request(req);
  } catch {
    throw new Error(`${provider} request failed`);
  }
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
