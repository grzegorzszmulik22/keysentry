export { createKeyWrapper, wrappedKeyVersion } from './wrapper.js';
export { createAwsKmsWrapper } from './aws.js';
export { createGcpKmsWrapper, serviceAccountAssertion, GOOGLE_KMS_SCOPE, GOOGLE_TOKEN_URL } from './gcp.js';
export { createAzureKeyVaultWrapper, AZURE_KEYS_API_VERSION, AZURE_VAULT_SCOPE } from './azure.js';
export { createVaultTransitWrapper } from './vault-transit.js';
export { createKmsHttp, kmsEgressRules, KMS_CREDENTIAL_NAMES } from './settings.js';
export type { KmsSettings, AwsKmsSettings, GcpKmsSettings, AzureKeyVaultSettings, VaultTransitSettings } from './settings.js';
export type { KeyWrapperDeps } from './shared.js';
export { unwrapDeploymentStateKey, type DeploymentStateKeyOptions } from './watcher.js';
export { KmsError, PROVIDER_LABELS, type KmsFailure } from './errors.js';
export {
  stateKeyContext, plainStateKeyName, wrappedStateKeyName, encodeWrappedStateKey, decodeWrappedStateKey,
  encodeWatcherWrappedStateKey, decodeWatcherWrappedStateKey, unwrapStateKey, wrapStateKey, loadProjectStateKey,
  migrateStateKey, rotateStateKey, stateKeyStatus, wrapWatcherStateKey, unwrapWatcherStateKey,
} from './state-key.js';
export type {
  WrappedStateKey, LoadStateKeyOptions, MigrateStateKeyOptions, MigrationPoint, MigrationResult, RotationResult, StateKeyStatus,
} from './state-key.js';
