import type { HttpClient } from '../../types.js';
import { fail, OidcError } from './errors.js';
import { requestJson } from './fetch.js';

export type IdTokenAlg = 'RS256' | 'ES256';
export const SUPPORTED_ALGS: readonly IdTokenAlg[] = Object.freeze(['RS256', 'ES256']);

/** The validated subset of the provider's discovery document that keysentry uses. */
export interface OidcProviderMetadata {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  /** The provider's ID token algorithms that keysentry also accepts (RS256, ES256). */
  signingAlgs: IdTokenAlg[];
  /** Published methods, or the OpenID default `client_secret_basic` when omitted. */
  tokenAuthMethods: string[];
  /** RFC 9207: when true, the authorization response must carry an `iss` parameter. */
  issParameterSupported: boolean;
}

const MAX_URL = 2048;
const MAX_DOCUMENT = 256 * 1024;

function plain(value: string): boolean {
  return value.length > 0 && value.length <= MAX_URL && !/[\s\u0000-\u001f\u007f]/.test(value);
}

/**
 * Accept an issuer exactly as written (it is compared byte for byte later): https, a host, no credentials,
 * query or fragment. Throws a configuration refusal otherwise.
 */
export function checkIssuer(issuer: unknown): string {
  if (typeof issuer !== 'string' || !plain(issuer) || issuer.includes('?') || issuer.includes('#')) return fail('configuration');
  let url: URL;
  try { url = new URL(issuer); } catch { return fail('configuration'); }
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password) return fail('configuration');
  return issuer;
}

/** OpenID Connect Discovery 1.0 §4.1: drop one terminating slash, then append the well-known path. */
export function discoveryUrl(issuer: string): string {
  checkIssuer(issuer);
  return `${issuer.endsWith('/') ? issuer.slice(0, -1) : issuer}/.well-known/openid-configuration`;
}

/** Endpoints must be https without credentials or fragments; a query is allowed (RFC 6749 §3.1, §3.2). */
function endpoint(value: unknown): string {
  if (typeof value !== 'string' || !plain(value) || value.includes('#')) return fail('configuration');
  let url: URL;
  try { url = new URL(value); } catch { return fail('configuration'); }
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password) return fail('configuration');
  return url.href;
}

function strings(value: unknown, required: boolean): string[] | undefined {
  if (value === undefined && !required) return undefined;
  if (!Array.isArray(value) || value.length === 0 || value.length > 100 || !value.every(item => typeof item === 'string' && item.length > 0 && item.length <= 200)) {
    return fail('configuration');
  }
  return [...value] as string[];
}

export function hostOf(url: string): string {
  return new URL(url).hostname.toLowerCase().replace(/\.$/, '');
}

/** Validate a parsed discovery document against the configured issuer (Discovery §3, §4.3; RFC 8414; RFC 9207). */
export function parseProviderMetadata(issuer: string, document: Record<string, unknown>): OidcProviderMetadata {
  if (typeof document.issuer !== 'string' || document.issuer !== issuer) return fail('configuration');
  const responseTypes = strings(document.response_types_supported, true)!;
  strings(document.subject_types_supported, true);
  const algs = strings(document.id_token_signing_alg_values_supported, true)!;
  const grants = strings(document.grant_types_supported, false);
  const challenges = strings(document.code_challenge_methods_supported, false);
  const methods = strings(document.token_endpoint_auth_methods_supported, false) ?? ['client_secret_basic'];
  if (!responseTypes.includes('code')) return fail('configuration');
  if (grants && !grants.includes('authorization_code')) return fail('configuration');
  // Providers that publish their PKCE methods must offer S256; keysentry always sends S256.
  if (challenges && !challenges.includes('S256')) return fail('configuration');
  const signingAlgs = SUPPORTED_ALGS.filter(alg => algs.includes(alg));
  if (signingAlgs.length === 0) return fail('configuration');
  const iss = document.authorization_response_iss_parameter_supported;
  if (iss !== undefined && typeof iss !== 'boolean') return fail('configuration');
  return {
    issuer,
    authorizationEndpoint: endpoint(document.authorization_endpoint),
    tokenEndpoint: endpoint(document.token_endpoint),
    jwksUri: endpoint(document.jwks_uri),
    signingAlgs,
    tokenAuthMethods: methods,
    issParameterSupported: iss === true,
  };
}

/** Fetch and validate the discovery document through the injected client. */
export async function discover(http: HttpClient, issuer: string): Promise<OidcProviderMetadata> {
  try {
    const { body } = await requestJson(http, { method: 'GET', url: discoveryUrl(issuer), headers: { Accept: 'application/json' } }, MAX_DOCUMENT);
    return parseProviderMetadata(issuer, body);
  } catch (error) {
    if (error instanceof OidcError) throw error;
    return fail('configuration');
  }
}
