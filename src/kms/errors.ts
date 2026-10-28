import { CliError } from '../cli/errors.js';
import type { KmsProviderId } from '../types.js';

/**
 * Why a KMS operation did not complete. Every message is fixed text built from these codes and the provider label;
 * no upstream body, token, key, value or credential-bearing URL ever reaches it.
 */
export type KmsFailure =
  | 'config' | 'credentials' | 'blocked' | 'unreachable' | 'unavailable' | 'denied' | 'key-unavailable'
  | 'unsupported' | 'rejected' | 'invalid-response' | 'damaged' | 'wrong-key' | 'mismatch' | 'not-wrapped' | 'read-only'
  | 'network' | 'busy';

/** Extends CliError so its fixed message crosses the CLI error boundary unchanged. */
export class KmsError extends CliError {
  constructor(readonly code: KmsFailure, message: string) {
    super(message);
    this.name = 'KmsError';
  }
}

export const PROVIDER_LABELS: Readonly<Record<KmsProviderId, string>> = Object.freeze({
  'aws-kms': 'AWS KMS',
  'gcp-kms': 'Google Cloud KMS',
  'azure-key-vault': 'Azure Key Vault',
  'vault-transit': 'Vault Transit',
});

export function unreachable(provider: KmsProviderId): KmsError {
  return new KmsError('unreachable', `Could not reach ${PROVIDER_LABELS[provider]}. Check the connection and any proxy settings.`);
}

/**
 * The proxy, CA or team-policy network settings refuse every request (a fail-closed transport), so the KMS was never
 * contacted. `reason` is the transport's own fixed message, which names the setting and never its value.
 */
export function networkRefused(provider: KmsProviderId, reason: string): KmsError {
  return new KmsError('network', `${PROVIDER_LABELS[provider]} was not contacted because the network settings cannot be used: ${reason}`);
}

export function blocked(provider: KmsProviderId): KmsError {
  return new KmsError('blocked', `The ${PROVIDER_LABELS[provider]} address is not on keysentry's list of allowed hosts. Check the kms settings in keysentry.yaml.`);
}

export function invalidResponse(provider: KmsProviderId): KmsError {
  return new KmsError('invalid-response', `${PROVIDER_LABELS[provider]} returned a response keysentry could not verify. Nothing was changed.`);
}

export function damaged(provider: KmsProviderId): KmsError {
  return new KmsError('damaged', `The wrapped state key is damaged or was changed, so ${PROVIDER_LABELS[provider]} was not asked to unwrap it. Restore the vault entry from a backup.`);
}

export function rejected(provider: KmsProviderId): KmsError {
  return new KmsError('rejected', `${PROVIDER_LABELS[provider]} could not unwrap the state key with this key for this project. The wrapped copy was made with another key or project, or it was changed.`);
}

/** Map an HTTP status (and a provider error code, never its message) to a fixed explanation. */
export function failureFor(provider: KmsProviderId, status: number, operation: 'wrap' | 'unwrap' | 'token' | 'describe', code?: string): KmsError {
  const label = PROVIDER_LABELS[provider];
  if (operation === 'token') {
    if (status === 400 || status === 401 || status === 403) {
      return new KmsError('denied', `The sign-in for ${label} was refused. Check the credentials keysentry uses for it.`);
    }
    if (status === 429 || status >= 500) return new KmsError('unavailable', `The sign-in service for ${label} is unavailable right now. Try again shortly.`);
    return new KmsError('denied', `The sign-in for ${label} did not succeed. Check the credentials keysentry uses for it.`);
  }
  const keyGone = new KmsError('key-unavailable', `${label} reports that the key is missing, disabled or scheduled for deletion. Restore or re-enable the key; keysentry did not create a new one.`);
  const unusable = new KmsError('unsupported', `The ${label} key cannot wrap keys this way. Use a symmetric encryption key (AWS, Google Cloud, Vault Transit) or an RSA key (Azure Key Vault).`);
  switch (code) {
    case 'DisabledException': case 'NotFoundException': case 'KMSInvalidStateException': case 'KeyUnavailableException':
    case 'KeyNotFound': case 'KeyDisabled': case 'FAILED_PRECONDITION': case 'NOT_FOUND':
      return keyGone;
    case 'InvalidKeyUsageException':
      return unusable;
    case 'AccessDeniedException': case 'UnrecognizedClientException': case 'InvalidSignatureException': case 'ExpiredTokenException':
    case 'IncompleteSignatureException': case 'MissingAuthenticationTokenException': case 'PERMISSION_DENIED': case 'UNAUTHENTICATED': case 'Forbidden': case 'Unauthorized':
      return new KmsError('denied', `${label} refused the request. Check that the credentials are valid and allowed to use this key.`);
    case 'InvalidCiphertextException': case 'IncorrectKeyException':
      return rejected(provider);
    default: break;
  }
  if (status === 401 || status === 403) return new KmsError('denied', `${label} refused the request. Check that the credentials are valid and allowed to use this key.`);
  if (status === 404 || status === 410) return keyGone;
  if (status === 429 || status >= 500) return new KmsError('unavailable', `${label} is unavailable right now. Try again shortly.`);
  if (operation === 'unwrap') return rejected(provider);
  return new KmsError('unsupported', `${label} did not accept the request. Check the key settings and that the key can wrap keys.`);
}

export function missingCredentials(provider: KmsProviderId, names: string): KmsError {
  return new KmsError('credentials', `${PROVIDER_LABELS[provider]} needs ${names}. Provide them through the keysentry vault or the environment.`);
}
