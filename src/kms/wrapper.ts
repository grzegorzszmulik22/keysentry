import type { KeyWrapper, KmsProviderId } from '../types.js';
import { awsKeyVersion, createAwsKmsWrapper } from './aws.js';
import { azureKeyVersion, createAzureKeyVaultWrapper } from './azure.js';
import { createGcpKmsWrapper, gcpKeyVersion } from './gcp.js';
import type { KmsSettings } from './settings.js';
import type { KeyWrapperDeps } from './shared.js';
import { createVaultTransitWrapper, vaultKeyVersion } from './vault-transit.js';

/** One adapter per provider. Construction does no I/O; credentials are read on each operation. */
export function createKeyWrapper(config: KmsSettings, deps: KeyWrapperDeps): KeyWrapper {
  switch (config.provider) {
    case 'aws-kms': return createAwsKmsWrapper(config, deps);
    case 'gcp-kms': return createGcpKmsWrapper(config, deps);
    case 'azure-key-vault': return createAzureKeyVaultWrapper(config, deps);
    case 'vault-transit': return createVaultTransitWrapper(config, deps);
  }
}

/** The non-secret key version a wrapped blob names (AWS key ARN, Cloud KMS version, Key Vault version, Transit vN). */
export function wrappedKeyVersion(provider: KmsProviderId, wrapped: Buffer): string | undefined {
  switch (provider) {
    case 'aws-kms': return awsKeyVersion(wrapped);
    case 'gcp-kms': return gcpKeyVersion(wrapped);
    case 'azure-key-vault': return azureKeyVersion(wrapped);
    case 'vault-transit': return vaultKeyVersion(wrapped);
  }
}
