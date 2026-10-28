import { createHash } from 'node:crypto';
import { canonicalJson } from '../../security/index.js';
import type { TeamRole } from '../../types.js';
import { DashboardError } from './security.js';

/**
 * Handler context. The local dashboard passes only `session`. Team mode adds the signed-in roster member and, for
 * mutating routes, the id of the member's own passkey that confirmed this exact request.
 */
export interface DashboardRequestContext {
  session: string;
  member?: { id: string; role: TeamRole };
  passkey?: string;
}

export interface DashboardApi {
  [route: string]: {
    method: 'GET' | 'POST';
    /** True for changes and explicit secret reveals. Disarm may be declared false. */
    mutating: boolean;
    handler(body: unknown, ctx: DashboardRequestContext): Promise<unknown>;
  };
}

export function bodyDigest(body: unknown): string {
  try { return createHash('sha256').update(canonicalJson(body)).digest('hex'); }
  catch { throw new DashboardError(400, 'Send a valid JSON body.'); }
}

export function apiRoute(api: DashboardApi, name: string): DashboardApi[string] | undefined {
  return Object.hasOwn(api, name) ? api[name] : undefined;
}

export function validateApi(api: DashboardApi): void {
  for (const [name, route] of Object.entries(api)) {
    if (!/^[a-z][a-z0-9-]*(?:\/[a-z][a-z0-9-]*)*$/.test(name) || name === 'session' || name === 'passkey' || name.startsWith('passkey/') ||
        !route || !['GET', 'POST'].includes(route.method) || typeof route.mutating !== 'boolean' || typeof route.handler !== 'function' ||
        (route.method === 'GET' && route.mutating)) {
      throw new Error('Configure dashboard routes with valid methods and mutation flags.');
    }
  }
}
