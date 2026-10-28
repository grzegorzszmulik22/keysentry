import type { HttpRequest, ProviderAdapter, ProviderContext, VerifyResult } from '../types.js';
import { readJson, request } from './shared.js';

// Docs (accessed 2026-10-28): https://postmarkapp.com/developer/api/overview,
// https://postmarkapp.com/developer/api/bounce-api (GET /deliverystats), https://postmarkapp.com/developer/api/domains-api
// (GET /domains), https://postmarkapp.com/support/article/1293-how-to-cycle-a-server-api-token,
// https://postmarkapp.com/support/article/1212-can-you-have-more-than-one-account-api-token-at-a-time.
// No API creates, regenerates or deletes server or account tokens, so rotation stays guided.
const API = 'https://api.postmarkapp.com';
const PROVIDER = 'Postmark';

type Row = Record<string, unknown>;

function record(value: unknown): Row | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Row : undefined;
}

/**
 * Both reads avoid endpoints whose responses list ApiTokens (GET /server, GET /servers). Postmark answers HTTP 401
 * (ErrorCode 10) for a missing or invalid token and for the wrong token type, so a 401 from the server endpoint is
 * followed by one account-endpoint attempt.
 */
async function attempt(ctx: ProviderContext, req: HttpRequest, identity: string,
  valid: (data: Row) => boolean): Promise<VerifyResult> {
  let status: number | undefined;
  try {
    const response = await request(ctx, req, PROVIDER);
    status = response.status;
    if (status < 200 || status >= 300) return { ok: false, status, error: `${PROVIDER} verification failed (HTTP ${status})` };
    const data = record(readJson<unknown>(response, PROVIDER));
    if (!data || !valid(data)) return { ok: false, status, error: `${PROVIDER} verification failed` };
    return { ok: true, status, identity };
  } catch {
    return { ok: false, ...(status === undefined ? {} : { status }), error: `${PROVIDER} verification failed` };
  }
}

export const postmarkProvider: ProviderAdapter = {
  id: 'postmark',
  method: 'guided',

  async verify(value, ctx) {
    const server = await attempt(ctx, {
      method: 'GET', url: `${API}/deliverystats`, headers: { Accept: 'application/json', 'X-Postmark-Server-Token': value },
    }, 'Postmark server token', (data) => typeof data.InactiveMails === 'number' && Array.isArray(data.Bounces));
    if (server.ok || server.status !== 401) return server;
    return attempt(ctx, {
      method: 'GET', url: `${API}/domains?count=1&offset=0`, headers: { Accept: 'application/json', 'X-Postmark-Account-Token': value },
    }, 'Postmark account token', (data) => typeof data.TotalCount === 'number' && Array.isArray(data.Domains));
  },

  guidance() {
    return {
      url: 'https://account.postmarkapp.com/servers',
      steps: [
        'For a server token: open the server, choose API Tokens, select Generate New, and keep the existing token until consumers are updated.',
        'For an account API token: open Account > API Tokens and generate another token (at most three exist at once); existing account tokens stay valid.',
        'Update every consumer and redeploy, verify the new token sends or reads as expected, then delete the exposed token in the same API Tokens tab.',
      ],
    };
  },
};
