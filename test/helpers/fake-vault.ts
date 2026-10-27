// In-memory Vault for tests (owned by the orchestrator).
import type { Vault } from '../../src/types.js';

export function createFakeVault(seed: Record<string, Buffer> = {}): Vault & { dump(): Map<string, Buffer> } {
  const items = new Map<string, Buffer>(Object.entries(seed).map(([k, v]) => [k, Buffer.from(v)]));
  return {
    backend: 'memory',
    async get(name) {
      const v = items.get(name);
      return v ? Buffer.from(v) : null;
    },
    async set(name, value) {
      items.set(name, Buffer.from(value));
    },
    async delete(name) {
      return items.delete(name);
    },
    async list(prefix = '') {
      return [...items.keys()].filter((k) => k.startsWith(prefix)).sort();
    },
    dump() {
      return items;
    },
  };
}
