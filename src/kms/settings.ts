import type { ConfigSettings } from '../cli/config.js';
import { createGuardedHttp } from '../net/index.js';
import type { EgressRule, HttpClient, Logger, NetworkReceipt } from '../types.js';

export type KmsSettings = NonNullable<ConfigSettings['kms']>;
export type AwsKmsSettings = Extract<KmsSettings, { provider: 'aws-kms' }>;
export type GcpKmsSettings = Extract<KmsSettings, { provider: 'gcp-kms' }>;
export type AzureKeyVaultSettings = Extract<KmsSettings, { provider: 'azure-key-vault' }>;
export type VaultTransitSettings = Extract<KmsSettings, { provider: 'vault-transit' }>;

/** Credential names each provider reads through the CredentialSource (vault first, then the environment). */
export const KMS_CREDENTIAL_NAMES: readonly string[] = Object.freeze([
  'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
  'GOOGLE_OAUTH_ACCESS_TOKEN', 'GOOGLE_SERVICE_ACCOUNT_KEY',
  'AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET',
  'VAULT_TOKEN',
]);

/** Exactly the hosts the configured KMS needs; nothing else is reachable through `createKmsHttp`. */
export function kmsEgressRules(settings: KmsSettings): EgressRule[] {
  switch (settings.provider) {
    case 'aws-kms':
      return [{ host: `kms.${settings.region}.amazonaws.com`, owner: 'kms', purpose: 'AWS KMS key you configured (wraps the state key)' }];
    case 'gcp-kms':
      return [
        { host: 'cloudkms.googleapis.com', owner: 'kms', purpose: 'Google Cloud KMS key you configured (wraps the state key)' },
        { host: 'oauth2.googleapis.com', owner: 'kms', purpose: 'Google sign-in for the KMS key you configured' },
      ];
    case 'azure-key-vault':
      return [
        { host: new URL(settings.vaultUrl).hostname.toLowerCase(), owner: 'user', purpose: 'Azure Key Vault key you configured (wraps the state key)' },
        { host: 'login.microsoftonline.com', owner: 'kms', purpose: 'Microsoft sign-in for the Key Vault key you configured' },
      ];
    case 'vault-transit':
      return [{ host: new URL(settings.address).hostname.toLowerCase(), owner: 'user', purpose: 'Vault Transit key you configured (wraps the state key)' }];
  }
}

/** A guarded client limited to the KMS hosts. Redirects are refused: no KMS call this module makes should redirect. */
export function createKmsHttp(transport: HttpClient, settings: KmsSettings, options: { receipt?: NetworkReceipt; log?: Logger; now?: () => Date } = {}): HttpClient {
  return createGuardedHttp(transport, { rules: kmsEgressRules(settings), maxRedirects: 0,
    ...(options.receipt ? { receipt: options.receipt } : {}), ...(options.log ? { log: options.log } : {}), ...(options.now ? { now: options.now } : {}) });
}
