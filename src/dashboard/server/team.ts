import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import type { StateStore } from '../../core/store.js';
import type { PasskeyCredential, TeamMember, TeamRole } from '../../types.js';
import type { PasskeyStore } from './passkey-gate.js';
import { DashboardError } from './security.js';

/** `__Host-` cookies are Secure, Path=/ and host-only, so a sibling subdomain cannot set or shadow them. */
export const TEAM_SESSION_COOKIE = '__Host-ks_session';
export const TEAM_SIGN_IN_COOKIE = '__Host-ks_oidc';
export const TEAM_PASSKEY_NOTICE = 'Ask a team admin to add your passkey to the team roster, then reload this page.';

export interface TeamSession {
  id: string;
  csrf: string;
  memberId: string;
  /** The verified, normalized email that signed in (null when a pinned identity matched without one). */
  email: string | null;
  /** The identity provider's issuer and subject for this sign-in. Pinned members must keep matching them. */
  issuer: string;
  subject: string;
  created: number;
  lastSeen: number;
}

/** Read exactly one cookie value; duplicates or malformed values count as none. */
export function readCookie(header: string | undefined, name: string): string | undefined {
  const prefix = `${name}=`;
  const values = (header ?? '').split(';').map(part => part.trim()).filter(part => part.startsWith(prefix));
  if (values.length !== 1) return undefined;
  const value = values[0]!.slice(prefix.length);
  return /^[A-Za-z0-9_-]{43}$/.test(value) ? value : undefined;
}

/** In-memory team sessions with idle and absolute lifetimes; nothing is written to disk. */
export function createTeamSessions(opts: { idleMs: number; absoluteMs: number; max?: number; now?: () => number }) {
  const now = opts.now ?? Date.now;
  const max = opts.max ?? 500;
  const sessions = new Map<string, TeamSession>();
  const live = (session: TeamSession, time: number) => time < session.lastSeen + opts.idleMs && time < session.created + opts.absoluteMs;
  function prune(): void {
    const time = now();
    for (const [id, session] of sessions) if (!live(session, time)) sessions.delete(id);
  }
  return {
    create(member: { memberId: string; email: string | null; issuer: string; subject: string }): TeamSession {
      prune();
      while (sessions.size >= max) sessions.delete(sessions.keys().next().value!);
      const time = now();
      const session: TeamSession = { id: randomBytes(32).toString('base64url'), csrf: randomBytes(32).toString('base64url'), ...member, created: time, lastSeen: time };
      sessions.set(session.id, session);
      return { ...session };
    },
    /** Returns the session and refreshes its idle timer; expired sessions are removed. */
    authenticate(cookie: string | undefined): TeamSession | null {
      const id = readCookie(cookie, TEAM_SESSION_COOKIE);
      if (!id) return null;
      const session = sessions.get(id);
      if (!session) return null;
      const time = now();
      if (!live(session, time)) { sessions.delete(id); return null; }
      session.lastSeen = time;
      return { ...session };
    },
    remove(id: string): void { sessions.delete(id); },
    get size(): number { prune(); return sessions.size; },
    clear(): void { sessions.clear(); },
  };
}

/**
 * Minimum role per dashboard route. GET routes default to viewer, POST routes to operator. Mutating routes never
 * drop below operator, whatever an override says. The defaults keep policy-widening and secret-handling routes
 * (arming more keys, settings, notification channels, vault entries, reveal) for admins.
 */
export const TEAM_ROUTE_ROLES: Readonly<Record<string, TeamRole>> = Object.freeze({
  'rotate/preview': 'viewer',
  timeline: 'viewer',
  card: 'viewer',
  'notifications/verify': 'viewer',
  'autopilot/arm': 'admin',
  'settings/update': 'admin',
  'notifications/add': 'admin',
  'notifications/remove': 'admin',
  'vault/store': 'admin',
  'vault/remove': 'admin',
  reveal: 'admin',
});

const RANK: Readonly<Record<TeamRole, number>> = { viewer: 0, operator: 1, admin: 2 };

export function requiredRole(name: string, route: { method: 'GET' | 'POST'; mutating: boolean }, overrides: Readonly<Record<string, TeamRole>> = {}): TeamRole {
  const table: Record<string, TeamRole> = { ...TEAM_ROUTE_ROLES, ...overrides };
  const role = Object.hasOwn(table, name) && Object.hasOwn(RANK, table[name]!) ? table[name]! : route.method === 'GET' ? 'viewer' : 'operator';
  return route.mutating && role === 'viewer' ? 'operator' : role;
}

export function allows(role: TeamRole, required: TeamRole): boolean {
  return Object.hasOwn(RANK, role) && RANK[role] >= RANK[required];
}

/** Sign counters for roster passkeys. The roster is signed, so counters live beside it. */
export interface PasskeyCounterStore {
  read(credentialId: string): Promise<number | null>;
  write(credentialId: string, signCount: number): Promise<void>;
}

function validCounter(value: unknown): value is number {
  return Number.isInteger(value) && (value as number) >= 0 && (value as number) <= 0xffffffff;
}

export function createMemoryPasskeyCounters(): PasskeyCounterStore {
  const counters = new Map<string, number>();
  return {
    async read(id) { return counters.get(id) ?? null; },
    async write(id, signCount) { if (!validCounter(signCount)) throw new Error('Invalid passkey counter.'); counters.set(id, signCount); },
  };
}

/** Counters in encrypted project state (`team-passkey-counters.json`), bound to that path by the store. */
export function createStatePasskeyCounters(store: Pick<StateStore, 'paths' | 'readJson' | 'writeJson'>): PasskeyCounterStore {
  const path = join(store.paths.dir, 'team-passkey-counters.json');
  let queue: Promise<unknown> = Promise.resolve();
  const serial = <T>(fn: () => Promise<T>): Promise<T> => { const next = queue.then(fn, fn); queue = next.catch(() => undefined); return next; };
  async function load(): Promise<Record<string, number>> {
    const raw = await store.readJson<{ v?: unknown; counters?: unknown }>('passkeys', path);
    if (raw === null) return {};
    const counters = raw && typeof raw === 'object' && raw.v === 1 && raw.counters && typeof raw.counters === 'object' && !Array.isArray(raw.counters)
      ? raw.counters as Record<string, unknown> : null;
    if (!counters || Object.keys(counters).length > 2000 || !Object.entries(counters).every(([id, n]) => /^[A-Za-z0-9_-]{1,1400}$/.test(id) && validCounter(n))) {
      throw new Error('The team passkey counters could not be read.');
    }
    return { ...counters } as Record<string, number>;
  }
  return {
    read: id => serial(async () => { const counters = await load(); return Object.hasOwn(counters, id) ? counters[id]! : null; }),
    write: (id, signCount) => serial(async () => {
      if (!/^[A-Za-z0-9_-]{1,1400}$/.test(id) || !validCounter(signCount)) throw new Error('Invalid passkey counter.');
      const counters = await load();
      counters[id] = Math.max(signCount, counters[id] ?? 0);
      await store.writeJson('passkeys', path, { v: 1, counters });
    }),
  };
}

/** The usable passkeys of one member for this origin, with the stored counters applied. */
export function memberPasskeys(member: TeamMember, rpId: string, origin: string): PasskeyCredential[] {
  if (!Array.isArray(member.passkeys)) return [];
  return member.passkeys.filter(credential => credential && credential.rpId === rpId && Array.isArray(credential.origins) && credential.origins.includes(origin));
}

/**
 * A passkey store scoped to the signed-in member: the gate can only offer and accept that member's own
 * credentials. Adding passkeys is a signed roster change, never a dashboard action.
 */
export function memberPasskeyStore(member: TeamMember, rpId: string, origin: string, counters: PasskeyCounterStore): PasskeyStore {
  const own = memberPasskeys(member, rpId, origin);
  return {
    async list() {
      return Promise.all(own.map(async credential => {
        const stored = await counters.read(credential.id);
        return { ...structuredClone(credential), signCount: Math.max(credential.signCount, stored ?? 0) };
      }));
    },
    async add() { throw new DashboardError(409, TEAM_PASSKEY_NOTICE); },
    async update(credential) {
      if (!own.some(item => item.id === credential.id)) throw new DashboardError(403, 'Use a fresh passkey to continue.');
      await counters.write(credential.id, credential.signCount);
    },
  };
}
