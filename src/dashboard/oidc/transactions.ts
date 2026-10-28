import { randomBytes } from 'node:crypto';

/** One browser's sign-in in progress. The id travels only in an HttpOnly cookie; the rest stays in memory. */
export interface LoginTransaction {
  id: string;
  state: string;
  nonce: string;
  verifier: string;
  expires: number;
}

/**
 * Short-lived, single-use sign-in transactions. Memory is bounded: when full, the oldest pending sign-in is
 * dropped (that browser simply signs in again). Rate limiting of anonymous traffic belongs to the TLS proxy.
 */
export function createLoginTransactions(options: { now?: () => number; lifetimeMs?: number; max?: number } = {}) {
  const now = options.now ?? Date.now;
  const lifetimeMs = options.lifetimeMs ?? 600_000;
  const max = options.max ?? 1000;
  const pending = new Map<string, LoginTransaction>();
  function prune(): void {
    const time = now();
    for (const [id, entry] of pending) if (time >= entry.expires) pending.delete(id);
  }
  return {
    lifetimeMs,
    create(request: { state: string; nonce: string; verifier: string }): LoginTransaction {
      prune();
      while (pending.size >= max) pending.delete(pending.keys().next().value!);
      const entry: LoginTransaction = { id: randomBytes(32).toString('base64url'), ...request, expires: now() + lifetimeMs };
      pending.set(entry.id, entry);
      return { ...entry };
    },
    /** Remove and return the transaction; a second call, an unknown id or an expired entry returns null. */
    take(id: string | undefined): LoginTransaction | null {
      if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(id)) return null;
      const entry = pending.get(id);
      pending.delete(id);
      if (!entry || now() >= entry.expires) return null;
      return entry;
    },
    get size(): number { prune(); return pending.size; },
    clear(): void { pending.clear(); },
  };
}

export type LoginTransactions = ReturnType<typeof createLoginTransactions>;
