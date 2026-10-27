import type { Vault } from '../../types.js';
import { validateVaultName } from '../names.js';

export function createMemoryVault(): Vault {
  const items = new Map<string, Buffer>();
  return {
    backend: 'memory',
    async get(name) {
      validateVaultName(name);
      const value = items.get(name);
      return value === undefined ? null : Buffer.from(value);
    },
    async set(name, value) {
      validateVaultName(name);
      const copy = Buffer.from(value);
      items.get(name)?.fill(0);
      items.set(name, copy);
    },
    async delete(name) {
      validateVaultName(name);
      items.get(name)?.fill(0);
      return items.delete(name);
    },
    async list(prefix = '') {
      if (prefix) validateVaultName(prefix);
      return [...items.keys()].filter(name => name.startsWith(prefix)).sort();
    },
  };
}
