import { createHash, randomBytes } from 'node:crypto';
import { verifyAssertion, verifyRegistration } from '../../../src/approvals/webauthn/index.js';
import type { PasskeyCredential } from '../../../src/types.js';
import { keyedLock, Lru } from './lock.js';
import type { Storage } from './storage.js';

export interface Account {
  id: string;
  plan: 'free' | 'paid';
  credential: PasskeyCredential;
  createdAt: string;
  customerId?: string;
  subscriptionId?: string;
}
export interface AccountSession { id: string; accountId: string; csrf: string }
export interface AccountsOptions {
  storage: Storage;
  origin: string;
  rpId?: string;
  now?: () => number;
  challengeTtlMs?: number;
  /** Sliding idle expiry. Default 30 minutes. */
  sessionIdleMs?: number;
  /** Absolute lifetime from sign-in. Default 12 hours. */
  sessionMaxAgeMs?: number;
  /** A new sign-in beyond this evicts the account's oldest session. Default 8. */
  maxSessionsPerAccount?: number;
  /** Pending ceremonies per client address; a new one evicts that client's oldest. Default 16. */
  maxChallengesPerClient?: number;
  /** Pending ceremonies in total; a new one evicts the oldest. Default 20,000. */
  maxChallenges?: number;
  /** Boxes (pending or active) a paid account may hold. Default 1. */
  boxQuota?: number;
}
interface Ceremony { challenge: string; expires: number; kind: 'registration' | 'assertion'; accountId?: string; client: string }
export interface RegisterAccountInput { challengeId: string; clientDataJSON: Buffer; attestationObject: Buffer }
export interface SignInInput {
  accountId: string; challengeId: string; credentialId: string;
  clientDataJSON: Buffer; authenticatorData: Buffer; signature: Buffer;
}
export interface AccountLogin { account: Account; session: AccountSession; cookie: string }
interface StoredSession { v: 1; accountId: string; csrf: string; createdAt: number; lastSeen: number }
interface SessionIndex { v: 1; sessions: { hash: string; createdAt: number }[] }
interface BoxOwner { accountId: string; state?: 'pending' | 'active'; since?: string }
interface AccountBoxes { v: 1; boxes: Record<string, 'pending' | 'active'> }

/** Refusals the HTTP layer maps to fixed responses: 402 unpaid, 403 quota, 409 name taken. */
export class AccountRefusal extends Error {
  constructor(readonly status: 402 | 403 | 409) {
    super(status === 402 ? 'A paid plan is required to create a box.'
      : status === 403 ? 'This account has reached its box limit.' : 'That box name is taken.');
    this.name = 'AccountRefusal';
  }
}

const token = () => randomBytes(32).toString('base64url');
const hashOf = (value: string) => createHash('sha256').update(value).digest('hex');
const TOUCH_MS = 60_000;
function fail(): never { throw new Error('Account request could not be verified.'); }
function id(value: string): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(value)) fail();
  return value;
}
function originConfig(origin: string, rpId?: string) {
  try {
    const url = new URL(origin);
    if (url.origin !== origin || url.username || url.password || url.search || url.hash) fail();
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) fail();
    const relyingParty = rpId ?? url.hostname;
    if (!relyingParty || (url.hostname !== relyingParty && !url.hostname.endsWith(`.${relyingParty}`))) fail();
    return { secure: url.protocol === 'https:', rpId: relyingParty };
  } catch { throw new Error('Account origin must be HTTPS or a loopback HTTP origin.'); }
}
function bounded(value: number | undefined, fallback: number, min: number, max: number): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < min || result > max) throw new Error('Invalid account settings.');
  return result;
}
function validSession(value: unknown): value is StoredSession {
  const v = value as StoredSession | null;
  return !!v && typeof v === 'object' && v.v === 1 && typeof v.accountId === 'string' && typeof v.csrf === 'string'
    && /^[A-Za-z0-9_-]{43}$/.test(v.csrf) && Number.isSafeInteger(v.createdAt) && Number.isSafeInteger(v.lastSeen);
}

/**
 * Passkey credentials are public metadata. Sessions are stored by SHA-256 of their id (never the id), capped per
 * account, with idle and absolute expiry. Challenges stay in memory: a two-minute ceremony needs no durability.
 */
export function createAccounts(opts: AccountsOptions) {
  const config = originConfig(opts.origin, opts.rpId);
  const { storage } = opts;
  const now = opts.now ?? Date.now;
  const challengeTtlMs = bounded(opts.challengeTtlMs, 120_000, 1, 600_000);
  const sessionIdleMs = bounded(opts.sessionIdleMs, 30 * 60_000, 1, 86_400_000);
  const sessionMaxAgeMs = bounded(opts.sessionMaxAgeMs, 12 * 3_600_000, 1, 7 * 86_400_000);
  const maxSessions = bounded(opts.maxSessionsPerAccount, 8, 1, 64);
  const maxPerClient = bounded(opts.maxChallengesPerClient, 16, 1, 1024);
  const maxChallenges = bounded(opts.maxChallenges, 20_000, 1, 1_000_000);
  const boxQuota = bounded(opts.boxQuota, 1, 0, 1000);
  // `__Host-` binds the cookie to this exact host over HTTPS, so a sibling subdomain cannot plant or shadow it.
  const COOKIE = config.secure ? '__Host-ks_control_session' : 'ks_control_session';
  const attributes = `Path=/; HttpOnly; SameSite=Strict${config.secure ? '; Secure' : ''}`;

  const challenges = new Map<string, Ceremony>();
  const byClient = new Map<string, string[]>();
  const sessions = new Lru<string, StoredSession>(10_000);
  const lock = keyedLock();
  // Lock order: the account lock may take a session lock, never the reverse.
  const accountLock = <T>(fn: () => Promise<T>) => lock('accounts', fn);
  const sessionLock = <T>(hash: string, fn: () => Promise<T>) => lock(`session:${hash}`, fn);

  function dropChallenge(challengeId: string): void {
    const ceremony = challenges.get(challengeId);
    if (!ceremony) return;
    challenges.delete(challengeId);
    const ids = byClient.get(ceremony.client)?.filter(item => item !== challengeId) ?? [];
    if (ids.length) byClient.set(ceremony.client, ids); else byClient.delete(ceremony.client);
  }
  function begin(kind: Ceremony['kind'], client: string | undefined, accountId?: string) {
    // Insertion order is expiry order (one TTL), so expired ceremonies are all at the front.
    for (const [key, value] of challenges) { if (value.expires > now()) break; dropChallenge(key); }
    const owner = typeof client === 'string' && client.length > 0 ? client.slice(0, 80) : 'local';
    while ((byClient.get(owner)?.length ?? 0) >= maxPerClient) dropChallenge(byClient.get(owner)![0]!);
    while (challenges.size >= maxChallenges) dropChallenge(challenges.keys().next().value as string);
    const ceremonyId = token(); const challenge = token();
    challenges.set(ceremonyId, { challenge, kind, accountId, client: owner, expires: now() + challengeTtlMs });
    byClient.set(owner, [...(byClient.get(owner) ?? []), ceremonyId]);
    return { id: ceremonyId, challenge, rpId: config.rpId };
  }
  function consume(challengeId: string, kind: Ceremony['kind'], accountId?: string): Ceremony {
    const value = typeof challengeId === 'string' ? challenges.get(challengeId) : undefined;
    if (value) dropChallenge(challengeId);
    if (!value || value.expires <= now() || value.kind !== kind || value.accountId !== accountId) fail();
    return value;
  }
  async function get(accountId: string): Promise<Account | null> { return storage.get<Account>(`accounts/${id(accountId)}`); }
  function live(session: StoredSession): boolean {
    return now() < session.lastSeen + sessionIdleMs && now() < session.createdAt + sessionMaxAgeMs;
  }
  async function removeSession(hash: string): Promise<void> {
    await sessionLock(hash, async () => { sessions.delete(hash); await storage.delete(`sessions/${hash}`); });
  }
  async function readSessionIndex(accountId: string): Promise<SessionIndex> {
    const index = await storage.get<SessionIndex>(`account-sessions/${accountId}`);
    if (!index) return { v: 1, sessions: [] };
    if (index.v !== 1 || !Array.isArray(index.sessions)) throw new Error('Account storage is unavailable.');
    return index;
  }
  /** Runs under the account lock. Evicted sessions are deleted before the new one exists. */
  async function createSession(account: Account, written?: string[]): Promise<AccountLogin> {
    const index = await readSessionIndex(account.id);
    const ordered = index.sessions.filter(entry => typeof entry?.hash === 'string' && /^[a-f0-9]{64}$/.test(entry.hash))
      .sort((a, b) => a.createdAt - b.createdAt);
    const keep = ordered.filter(entry => now() < entry.createdAt + sessionMaxAgeMs).slice(-(maxSessions - 1));
    for (const entry of ordered) if (!keep.includes(entry)) await removeSession(entry.hash);
    const sessionId = token(), hash = hashOf(sessionId);
    const stored: StoredSession = { v: 1, accountId: account.id, csrf: token(), createdAt: now(), lastSeen: now() };
    await storage.put(`sessions/${hash}`, stored); written?.push(`sessions/${hash}`);
    await storage.put(`account-sessions/${account.id}`, { v: 1, sessions: [...keep, { hash, createdAt: stored.createdAt }] });
    written?.push(`account-sessions/${account.id}`);
    sessions.set(hash, stored);
    return { account, session: { id: sessionId, accountId: account.id, csrf: stored.csrf }, cookie: `${COOKIE}=${sessionId}; ${attributes}` };
  }
  function cookieId(cookie: string | undefined): string | null {
    if (typeof cookie !== 'string' || cookie.length > 8192) return null;
    const matches = cookie.split(';').map(part => part.trim()).filter(part => part.startsWith(`${COOKIE}=`));
    if (matches.length !== 1) return null;
    const value = matches[0]!.slice(COOKIE.length + 1);
    return /^[A-Za-z0-9_-]{43}$/.test(value) && Buffer.from(value, 'base64url').toString('base64url') === value ? value : null;
  }
  async function owner(boxId: string): Promise<BoxOwner | null> {
    const record = await storage.get<BoxOwner>(`box-owners/${id(boxId)}`);
    return record && typeof record.accountId === 'string' ? record : null;
  }
  async function boxes(accountId: string): Promise<AccountBoxes> {
    const record = await storage.get<AccountBoxes>(`account-boxes/${accountId}`);
    if (!record) return { v: 1, boxes: {} };
    if (record.v !== 1 || !record.boxes || typeof record.boxes !== 'object') throw new Error('Account storage is unavailable.');
    return record;
  }

  return {
    cookieName: COOKIE,
    /** Set-Cookie value that removes the session cookie with matching attributes. */
    clearCookie: `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${config.secure ? '; Secure' : ''}`,
    registrationChallenge(client?: string) { return begin('registration', client); },
    async register(input: RegisterAccountInput): Promise<AccountLogin> {
      const ceremony = consume(input.challengeId, 'registration');
      return accountLock(async () => {
        let credential: PasskeyCredential;
        try {
          if (!Buffer.isBuffer(input.attestationObject) || input.attestationObject.length > 64 * 1024) fail();
          credential = verifyRegistration({ ...input, expectedChallenge: Buffer.from(ceremony.challenge, 'base64url'), expectedOrigins: [opts.origin], rpId: config.rpId, requireUserVerification: true });
        } catch { return fail(); }
        const credentialKey = `credentials/${hashOf(credential.id)}`;
        if (await storage.get(credentialKey)) fail();
        const account: Account = { id: token(), credential: { ...credential, createdAt: new Date(now()).toISOString() }, plan: 'free', createdAt: new Date(now()).toISOString() };
        // Every record is rolled back if any write fails, so a refused registration never burns the passkey.
        const written: string[] = [];
        try {
          await storage.put(`accounts/${account.id}`, account); written.push(`accounts/${account.id}`);
          await storage.put(credentialKey, { accountId: account.id }); written.push(credentialKey);
          return await createSession(account, written);
        } catch {
          for (const key of written.reverse()) await storage.delete(key).catch(() => undefined);
          for (const key of written) if (key.startsWith('sessions/')) sessions.delete(key.slice(9));
          return fail();
        }
      });
    },
    async assertionChallenge(accountId: string, client?: string) {
      const account = await get(accountId); if (!account) fail();
      return { ...begin('assertion', client, accountId), credentialId: account.credential.id };
    },
    async signIn(input: SignInInput): Promise<AccountLogin> {
      const ceremony = consume(input.challengeId, 'assertion', input.accountId);
      return accountLock(async () => {
        const account = await get(input.accountId); if (!account || account.credential.id !== input.credentialId) fail();
        let result: ReturnType<typeof verifyAssertion>;
        try {
          result = verifyAssertion({ ...input, credential: account.credential, expectedChallenge: Buffer.from(ceremony.challenge, 'base64url'), expectedOrigins: [opts.origin], requireUserVerification: true });
        } catch { return fail(); }
        if (result.cloneWarning) fail();
        account.credential.signCount = result.signCount;
        await storage.put(`accounts/${account.id}`, account);
        return createSession(account);
      });
    },
    /** True when the cookie's session is in memory, so checking it costs no storage read. */
    cachedSession(cookie: string | undefined): boolean {
      const value = cookieId(cookie);
      return value !== null && sessions.has(hashOf(value));
    },
    async authenticate(cookie: string | undefined): Promise<AccountSession | null> {
      const value = cookieId(cookie); if (!value) return null;
      const hash = hashOf(value);
      let session = sessions.get(hash);
      if (!session) {
        session = await sessionLock(hash, async () => {
          const stored = await storage.get<unknown>(`sessions/${hash}`);
          if (!validSession(stored)) return undefined;
          sessions.set(hash, stored);
          return stored;
        });
        if (!session) return null;
      }
      if (!live(session)) { await removeSession(hash); return null; }
      if (now() - session.lastSeen >= TOUCH_MS) {
        const touched = await sessionLock(hash, async () => {
          const stored = await storage.get<unknown>(`sessions/${hash}`);
          if (!validSession(stored) || !live(stored)) { sessions.delete(hash); return false; }
          stored.lastSeen = now();
          await storage.put(`sessions/${hash}`, stored);
          sessions.set(hash, stored);
          return true;
        });
        if (!touched) return null;
      }
      return { id: value, accountId: session.accountId, csrf: session.csrf };
    },
    async clearSession(cookie: string | undefined): Promise<void> {
      const value = cookieId(cookie); if (!value) return;
      const hash = hashOf(value);
      const stored = await storage.get<unknown>(`sessions/${hash}`);
      await removeSession(hash);
      if (!validSession(stored)) return;
      await accountLock(async () => {
        const index = await readSessionIndex(stored.accountId);
        await storage.put(`account-sessions/${stored.accountId}`, { v: 1, sessions: index.sessions.filter(entry => entry.hash !== hash) });
      });
    },
    get,
    /**
     * H1: holds the name for this account before any Compute call. Refuses an unpaid account (402), an account at
     * its quota (403) and a name another account holds (409). Retrying a name this account already reserved is allowed.
     */
    async reserveBox(accountId: string, boxId: string): Promise<void> {
      return accountLock(async () => {
        const account = await get(accountId); if (!account) fail();
        if (account.plan !== 'paid') throw new AccountRefusal(402);
        const current = await owner(boxId);
        if (current && (current.accountId !== accountId || current.state !== 'pending')) throw new AccountRefusal(409);
        const held = await boxes(accountId);
        if (Object.keys(held.boxes).filter(name => name !== boxId).length >= boxQuota) throw new AccountRefusal(403);
        await storage.put(`box-owners/${boxId}`, { accountId, state: 'pending', since: new Date(now()).toISOString() });
        await storage.put(`account-boxes/${accountId}`, { v: 1, boxes: { ...held.boxes, [boxId]: 'pending' } });
      });
    },
    async confirmBox(accountId: string, boxId: string): Promise<void> {
      return accountLock(async () => {
        const current = await owner(boxId);
        if (!current || current.accountId !== accountId) fail();
        await storage.put(`box-owners/${boxId}`, { accountId, state: 'active', since: new Date(now()).toISOString() });
        const held = await boxes(accountId);
        await storage.put(`account-boxes/${accountId}`, { v: 1, boxes: { ...held.boxes, [boxId]: 'active' } });
      });
    },
    /** Rolls back a pending reservation after a failed provision. An active box is never released here. */
    async releaseBox(accountId: string, boxId: string): Promise<void> {
      return accountLock(async () => {
        const current = await owner(boxId);
        if (!current || current.accountId !== accountId || current.state !== 'pending') return;
        const held = await boxes(accountId);
        const { [boxId]: _released, ...rest } = held.boxes;
        if (Object.keys(rest).length) await storage.put(`account-boxes/${accountId}`, { v: 1, boxes: rest });
        else await storage.delete(`account-boxes/${accountId}`);
        await storage.delete(`box-owners/${boxId}`);
      });
    },
    /** Records an active box without plan or quota checks: for trusted local composition only, never a route. */
    async addBox(accountId: string, boxId: string): Promise<void> {
      return accountLock(async () => {
        if (!await get(accountId)) fail();
        const current = await owner(boxId);
        if (current && current.accountId !== accountId) fail();
        await storage.put(`box-owners/${boxId}`, { accountId, state: 'active', since: new Date(now()).toISOString() });
        const held = await boxes(accountId);
        await storage.put(`account-boxes/${accountId}`, { v: 1, boxes: { ...held.boxes, [boxId]: 'active' } });
      });
    },
    async ownsBox(accountId: string, boxId: string): Promise<boolean> {
      const current = await owner(boxId);
      return current?.accountId === accountId && current.state !== 'pending';
    },
    /** The owning account of an active box, or null. */
    async boxOwner(boxId: string): Promise<string | null> {
      const current = await owner(boxId);
      return current && current.state !== 'pending' ? current.accountId : null;
    },
    async setPlan(accountId: string, plan: Account['plan'], billing?: { customerId?: string; subscriptionId?: string }): Promise<void> {
      return accountLock(async () => {
        const account = await get(accountId); if (!account || (plan !== 'free' && plan !== 'paid')) fail();
        account.plan = plan;
        if (billing?.customerId !== undefined) account.customerId = id(billing.customerId);
        if (billing?.subscriptionId !== undefined) account.subscriptionId = id(billing.subscriptionId);
        await storage.put(`accounts/${account.id}`, account);
      });
    },
  };
}
export type Accounts = ReturnType<typeof createAccounts>;
