import type { CredentialSource, TokenRole, Vault } from '../types.js';
import { PROVIDER_CREDENTIALS } from '../providers/index.js';
import { HOST_CREDENTIALS } from '../hosts/credentials.js';
import { validateVaultName } from './names.js';

/**
 * keysentry's own credentials: host tokens, the proxy credential (`username:password` for network.proxy, see
 * src/net/transport.ts) and provider management credentials. loadConfig reads every one of them, `vault import-env`
 * copies them, and the watcher never treats an application variable with one of these names as a key to rotate.
 */
export const CREDENTIAL_NAMES: readonly string[] = Object.freeze([...new Set([
  ...Object.values(HOST_CREDENTIALS).flat(),
  'KEYSENTRY_PROXY_AUTH',
  ...Object.values(PROVIDER_CREDENTIALS).flat(),
])]);

export function credentialVaultName(name: string, role: TokenRole): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new TypeError('Credential names must be environment variable names.');
  if (role !== 'read' && role !== 'write') throw new TypeError('The credential role must be read or write.');
  const vaultName = `cred/${name}${role === 'read' ? '@read' : ''}`;
  validateVaultName(vaultName);
  return vaultName;
}

export function createCredentialSource(vault: Vault, env: NodeJS.ProcessEnv): CredentialSource {
  return {
    async get(name, role) {
      const candidates = role === 'read' ? [credentialVaultName(name, 'read'), credentialVaultName(name, 'write')] : [credentialVaultName(name, role)];
      for (const candidate of candidates) {
        const value = await vault.get(candidate);
        if (value !== null) {
          try { return { value: value.toString('utf8'), source: vault.backend === 'env' ? 'env' : 'vault' }; }
          finally { value.fill(0); }
        }
      }
      const value = env[name];
      return value ? { value, source: 'env' } : null;
    },
  };
}

export async function importFromEnv(vault: Vault, env: NodeJS.ProcessEnv, names: readonly string[] = CREDENTIAL_NAMES): Promise<string[]> {
  const imported: string[] = [];
  for (const name of new Set(names)) {
    const vaultName = credentialVaultName(name, 'write');
    const value = env[name];
    if (!value) continue;
    const bytes = Buffer.from(value);
    try { await vault.set(vaultName, bytes); imported.push(name); }
    finally { bytes.fill(0); }
  }
  return imported;
}
