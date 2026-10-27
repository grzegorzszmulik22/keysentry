import type { HttpClient, HttpResponse } from '../../types.js';

export interface TokenExchangeInput {
  /** Workload identity provider resource audience, from the sealed box config. */
  audience: string;
  /** The launcher's default OIDC token (audience https://sts.googleapis.com). */
  subjectToken: string;
}

export function assertAudience(audience: string): void {
  if (typeof audience !== 'string' || audience.length > 1024 ||
      !/^\/\/iam\.googleapis\.com\/projects\/\d+\/locations\/global\/workloadIdentityPools\/[A-Za-z0-9_-]+\/providers\/[A-Za-z0-9_-]+$/.test(audience)) {
    throw new Error('The box workload identity audience is invalid.');
  }
}

/** No token caching: each key operation uses the launcher's current attestation. */
export async function exchangeForAccessToken(http: HttpClient, input: TokenExchangeInput): Promise<string> {
  assertAudience(input.audience);
  if (typeof input.subjectToken !== 'string' || input.subjectToken.length === 0 || input.subjectToken.length > 128 * 1024 || /\s/.test(input.subjectToken)) {
    throw new Error('The box attestation token is invalid.');
  }
  let response: HttpResponse;
  try {
    response = await http.request({
      method: 'POST', url: 'https://sts.googleapis.com/v1/token', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grantType: 'urn:ietf:params:oauth:grant-type:token-exchange', audience: input.audience,
        scope: 'https://www.googleapis.com/auth/cloud-platform',
        requestedTokenType: 'urn:ietf:params:oauth:token-type:access_token',
        subjectToken: input.subjectToken, subjectTokenType: 'urn:ietf:params:oauth:token-type:jwt',
      }),
    });
  } catch { throw new Error('Could not exchange box attestation with STS. Check the connection and key-release policy.'); }
  if (response.status < 200 || response.status >= 300) {
    throw new Error('STS refused the box attestation exchange. Check the workload identity audience and key-release policy.');
  }
  try {
    const body = response.json<{ access_token?: unknown; token_type?: unknown; expires_in?: unknown }>();
    if (!body || typeof body.access_token !== 'string' || body.access_token.length > 12 * 1024 ||
        !/^[A-Za-z0-9._~+\/-]+=*$/.test(body.access_token) || body.token_type !== 'Bearer' ||
        typeof body.expires_in !== 'number' || !Number.isSafeInteger(body.expires_in) || body.expires_in <= 0) throw new Error();
    return body.access_token;
  } catch { throw new Error('STS returned an invalid access token response.'); }
}
