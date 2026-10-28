import { KMS_CREDENTIAL_NAMES } from '../kms/index.js';
import { OIDC_CLIENT_SECRET_NAME } from '../dashboard/oidc/index.js';
import { CREDENTIAL_NAMES } from '../vault/index.js';

/**
 * Names `vault set`, `vault remove` and `vault status` accept in addition to CREDENTIAL_NAMES: the KMS credentials
 * for the state key and the team dashboard's OIDC client secret. They are deliberately not CREDENTIAL_NAMES:
 * loadConfig does not read them, `vault import-env` does not copy them, the watcher deployment does not export them
 * unless a command asks, and the watcher keeps protecting application variables with these names (for example an
 * app's own AWS_ACCESS_KEY_ID).
 */
export const VAULT_ONLY_CREDENTIAL_NAMES: readonly string[] = Object.freeze(
  [...new Set([...KMS_CREDENTIAL_NAMES, OIDC_CLIENT_SECRET_NAME])].filter(name => !CREDENTIAL_NAMES.includes(name)));

/** Every name the vault commands accept. */
export const VAULT_SET_NAMES: readonly string[] = Object.freeze([...CREDENTIAL_NAMES, ...VAULT_ONLY_CREDENTIAL_NAMES]);

export function acceptedCredentialName(name: string): boolean {
  return VAULT_SET_NAMES.includes(name);
}
