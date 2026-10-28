import { isIP } from 'node:net';
import type { AuditEvent } from '../../types.js';
import type { TeamAuthEvent } from '../server/team-server.js';
import { checkIssuer } from './discovery.js';

/** Vault credential name for a confidential client's secret (`keysentry vault set KEYSENTRY_OIDC_CLIENT_SECRET`). */
export const OIDC_CLIENT_SECRET_NAME = 'KEYSENTRY_OIDC_CLIENT_SECRET';
export const DEFAULT_TEAM_LISTEN = '127.0.0.1:8484';

export interface TeamUiOptions {
  publicOrigin: string;
  issuer: string;
  clientId: string;
  publicClient: boolean;
  /** Extra provider hosts for the token and key endpoints, lowercase. */
  hosts: string[];
  listen: { host: string; port: number };
}

const HOST = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

export function parsePublicOrigin(value: unknown): string {
  const message = 'Use --public-origin with the https address members open, for example https://keysentry.example.com.';
  if (typeof value !== 'string' || value.length > 512) throw new Error(message);
  let url: URL;
  try { url = new URL(value); } catch { throw new Error(message); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/' || value.includes('?') || value.includes('#')
    || !HOST.test(url.hostname) || isIP(url.hostname) !== 0) throw new Error(message);
  return url.origin;
}

export function parseListen(value: unknown): { host: string; port: number } {
  const message = 'Use --listen with an interface and port, for example 127.0.0.1:8484 or [::1]:8484.';
  const match = typeof value === 'string' ? /^(?:\[([0-9A-Fa-f:.]+)\]|([A-Za-z0-9.-]{1,253})):(\d{1,5})$/.exec(value) : null;
  if (!match) throw new Error(message);
  const host = match[1] ?? match[2]!;
  const port = Number(match[3]);
  if (port < 1 || port > 65535 || (match[1] !== undefined && isIP(host) !== 6)) throw new Error(message);
  return { host, port };
}

/** Validate `keysentry ui --team` options. No secret is ever accepted here: it comes from the vault. */
export function parseTeamUiOptions(input: { publicOrigin?: unknown; oidcIssuer?: unknown; oidcClientId?: unknown; oidcPublicClient?: unknown; oidcHost?: unknown; listen?: unknown }): TeamUiOptions {
  const publicOrigin = parsePublicOrigin(input.publicOrigin);
  let issuer: string;
  try { issuer = checkIssuer(input.oidcIssuer); } catch { throw new Error('Use --oidc-issuer with your identity provider’s https issuer URL, exactly as it publishes it.'); }
  const clientId = input.oidcClientId;
  if (typeof clientId !== 'string' || !/^[\x21-\x7e]{1,512}$/.test(clientId)) throw new Error('Use --oidc-client-id with the client id registered for keysentry.');
  const raw = input.oidcHost === undefined ? [] : input.oidcHost;
  if (!Array.isArray(raw) || raw.length > 10) throw new Error('Name at most ten extra identity provider hosts.');
  const hosts = raw.map(host => {
    const value = typeof host === 'string' ? host.toLowerCase().replace(/\.$/, '') : '';
    if (!HOST.test(value) || isIP(value) !== 0) throw new Error('Use --oidc-host with a host name such as oauth2.example.com.');
    return value;
  });
  return { publicOrigin, issuer, clientId, publicClient: input.oidcPublicClient === true, hosts: [...new Set(hosts)], listen: parseListen(input.listen ?? DEFAULT_TEAM_LISTEN) };
}

/** Value-free audit entries for sign-in events. */
export function teamAuditEvent(event: TeamAuthEvent): AuditEvent {
  switch (event.kind) {
    case 'sign-in': return { kind: 'team-sign-in', summary: 'A team member signed in to the dashboard.', data: { memberId: event.memberId, role: event.role } };
    case 'sign-in-refused': return { kind: 'team-sign-in-refused', summary: 'A dashboard sign-in was refused.',
      data: { reason: event.reason, ...(event.suppressed ? { suppressedBefore: event.suppressed } : {}) } };
    case 'sign-out': return { kind: 'team-sign-out', summary: 'A team member signed out of the dashboard.', data: { memberId: event.memberId } };
    case 'session-ended': return { kind: 'team-session-ended', summary: 'A dashboard session ended after a roster change.', data: { memberId: event.memberId } };
  }
}
