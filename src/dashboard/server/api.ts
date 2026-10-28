import { createHash } from 'node:crypto';
import { canonicalJson } from '../../security/index.js';
import type { TeamRole } from '../../types.js';
import { DashboardError } from './security.js';

/**
 * Handler context. The local dashboard passes only `session`. Team mode adds the signed-in roster member and, for
 * passkey-confirmed routes, the id of the member's own passkey that confirmed this exact request.
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
    /**
     * Team dashboard only: also confirm a non-mutating POST with the member's own passkey. Disarm uses it, so an
     * identity provider session alone cannot turn autopilot off (review M3); the local dashboard still needs no passkey.
     */
    teamPasskey?: boolean;
    handler(body: unknown, ctx: DashboardRequestContext): Promise<unknown>;
  };
}

/**
 * A change was accepted but has not run yet (a team request still collecting approvals). The server answers 202 with
 * `body` instead of 200, so no client can mistake it for the change itself.
 */
export class DashboardAccepted {
  constructor(readonly body: unknown) {}
}

/** Does this route need the member's passkey on the team dashboard? */
export function needsTeamPasskey(route: DashboardApi[string]): boolean {
  return route.mutating || (route.method === 'POST' && route.teamPasskey === true);
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
        (route.method === 'GET' && route.mutating) || (route.teamPasskey !== undefined && (typeof route.teamPasskey !== 'boolean' || route.method !== 'POST'))) {
      throw new Error('Configure dashboard routes with valid methods and mutation flags.');
    }
  }
}
