import type { Vault } from '../../types.js';
import { VaultReadOnlyError } from '../errors.js';
import { validateVaultName } from '../names.js';
import { CREDENTIAL_NAMES } from '../credentials.js';
import { createMemoryVault } from './memory.js';

/** The environment name is also used in actionable missing-key errors. */
export function environmentVariableForName(name: string): string {
  validateVaultName(name);
  if (name.startsWith('cred/')) {
    const credential = name.slice(5);
    return credential.endsWith('@read') ? `${credential.slice(0, -5)}_READ` : credential;
  }
  if (name.endsWith('key/state')) return 'KEYSENTRY_STATE_KEY';
  if (name.endsWith('key/fingerprint')) return 'KEYSENTRY_FINGERPRINT_KEY';
  if (name === 'key/device-ed25519') return 'KEYSENTRY_DEVICE_KEY';
  return `KEYSENTRY_VAULT_${name.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`;
}

const inFlight = (name: string) => /^project\/[^/]+\/inflight\/.+/.test(name);

export function createEnvVault(env: NodeJS.ProcessEnv): Vault {
  const transient = createMemoryVault();
  const seen = new Set<string>();
  return {
    backend: 'env',
    weakness: 'Keys come from environment variables, which other programs started by the same user can read.',
    async get(name) {
      validateVaultName(name);
      if (inFlight(name)) return transient.get(name);
      const variable = environmentVariableForName(name);
      const value = env[variable];
      if (!value) return null;
      seen.add(name);
      const encoded = name.endsWith('key/state') || name.endsWith('key/fingerprint') || name === 'key/device-ed25519';
      return Buffer.from(value, encoded ? 'base64' : 'utf8');
    },
    async set(name, value) {
      validateVaultName(name);
      if (inFlight(name)) return transient.set(name, value);
      throw new VaultReadOnlyError(`The environment vault is read-only. Set ${environmentVariableForName(name)} instead.`);
    },
    async delete(name) {
      validateVaultName(name);
      if (inFlight(name)) return transient.delete(name);
      throw new VaultReadOnlyError(`The environment vault is read-only. Remove ${environmentVariableForName(name)} from the environment instead.`);
    },
    async list(prefix = '') {
      if (prefix) validateVaultName(prefix);
      const names = new Set([...seen, ...await transient.list()]);
      // Generic environment names cannot be reversed losslessly. Include credentials and
      // canonical key names; project-specific aliases are included once accessed.
      for (const variable of CREDENTIAL_NAMES) {
        if (env[variable]) names.add(`cred/${variable}`);
        if (env[`${variable}_READ`]) names.add(`cred/${variable}@read`);
      }
      if (env.KEYSENTRY_STATE_KEY) names.add('key/state');
      if (env.KEYSENTRY_FINGERPRINT_KEY) names.add('key/fingerprint');
      if (env.KEYSENTRY_DEVICE_KEY) names.add('key/device-ed25519');
      return [...names].filter(name => name.startsWith(prefix)
        && (inFlight(name) || Boolean(env[environmentVariableForName(name)]))).sort();
    },
  };
}
