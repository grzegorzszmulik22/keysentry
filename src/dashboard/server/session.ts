import { randomBytes, timingSafeEqual } from 'node:crypto';

export interface DashboardSession { id: string; csrf: string }

/** Compare opaque tokens without accepting alternate encodings or duplicate cookies. */
export function sameToken(actual: string | undefined, expected: string): boolean {
  if (actual === undefined || actual.length !== expected.length || !/^[A-Za-z0-9_-]+$/.test(actual)) return false;
  return timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
}

/** One dashboard launch grants one browser session; nothing is persisted to disk. */
export function createSession(opts: { idleMs: number; now?: () => number; port: () => number }) {
  const now = opts.now ?? Date.now;
  const token = randomBytes(32).toString('base64url');
  const tokenExpires = now() + 120_000;
  let consumed = false;
  let active: (DashboardSession & { expires: number }) | null = null;
  return {
    token,
    get cookieName(): string { return `ks_session_${opts.port()}`; },
    exchange(value: string): DashboardSession | null {
      if (consumed || now() >= tokenExpires || !sameToken(value, token)) return null;
      consumed = true;
      active = { id: randomBytes(32).toString('base64url'), csrf: randomBytes(32).toString('base64url'), expires: now() + opts.idleMs };
      return { id: active.id, csrf: active.csrf };
    },
    authenticate(cookie: string | undefined): DashboardSession | null {
      if (!active) return null;
      if (now() >= active.expires) { active = null; return null; }
      const prefix = `${this.cookieName}=`;
      const values = (cookie ?? '').split(';').map(s => s.trim()).filter(s => s.startsWith(prefix));
      if (values.length !== 1 || !sameToken(values[0]!.slice(prefix.length), active.id)) return null;
      active.expires = now() + opts.idleMs;
      return { id: active.id, csrf: active.csrf };
    },
    clear(): void { consumed = true; active = null; },
  };
}
