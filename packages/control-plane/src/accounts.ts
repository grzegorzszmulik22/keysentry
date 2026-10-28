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
  /** How long a box's relay access decision (`boxAccess`) is kept in memory. Default 30 seconds. */
  boxAccessCacheMs?: number;
}
interface Ceremony { challenge: string; expires: number; kind: 'registration' | 'assertion'; accountId?: string; client: string }
/**
 * A box as the owner's page shows it: `pending` while it is created or checked, `active`, `suspended` when the account
 * has no paid plan (no relay access, a stop is requested), `stopped` after a stop while the plan is paid again.
 */
export type BoxState = 'pending' | 'active' | 'suspended' | 'stopped';
/** What the web page shows: the plan and the account's boxes, never billing identifiers. */
export interface AccountOverview {
  accountId: string;
  plan: 'free' | 'paid';
  boxes: { name: string; state: BoxState }[];
  boxQuota: number;
}
/** Relay access for a box credential: its owner pays (`allowed`), does not (`suspended`), or it has no active owner. */
export type BoxAccess = 'allowed' | 'suspended' | 'none';
/** A pending reservation no request in this process is provisioning: reconciliation asks Compute about it. */
export interface PendingBox { accountId: string; reservation: string; deviceKey?: string; ageMs: number }
/** What Compute said about a pending reservation's instance: ours, absent, or an instance that is not this reservation's. */
export type BoxSettlement = 'present' | 'absent' | 'foreign';
export interface RegisterAccountInput { challengeId: string; clientDataJSON: Buffer; attestationObject: Buffer }
export interface SignInInput {
  /** Omitted for a discoverable-credential sign-in: the credential id names the account. */
  accountId?: string; challengeId: string; credentialId: string;
  clientDataJSON: Buffer; authenticatorData: Buffer; signature: Buffer;
}
export interface AccountLogin { account: Account; session: AccountSession; cookie: string }
interface StoredSession { v: 1; accountId: string; csrf: string; createdAt: number; lastSeen: number }
interface SessionIndex { v: 1; sessions: { hash: string; createdAt: number }[] }
interface BoxOwner {
  accountId: string;
  state?: 'pending' | 'active';
  since?: string;
  /** Pending only: this reservation's id, so reconciliation never settles a newer reservation of the same name. */
  reservation?: string;
  /** Pending only: the enrollment key sent to Compute; reconciliation recognises this reservation's instance by it. */
  deviceKey?: string;
  /** Pending only: the Compute call ended without a definite answer. */
  uncertain?: true;
  /** Active only: a stop was requested through Compute; the owner's page offers to start it. */
  stopped?: true;
}
interface AccountBoxes { v: 1; boxes: Record<string, 'pending' | 'active'> }
/** Index records, so the minute sweep finds work without listing every box. */
const RECONCILE = 'box-reconcile/';
const STOPS = 'box-stops/';

/** Refusals the HTTP layer maps to fixed responses: 402 unpaid, 403 quota or not the owner, 409 name taken or pending. */
export class AccountRefusal extends Error {
  /** `pending`: the name is this account's reservation that is still being created or checked. */
  constructor(readonly status: 402 | 403 | 409, readonly pending = false) {
    super(status === 402 ? 'A paid plan is required to create a box.'
      : status === 403 ? 'This account has reached its box limit.'
      : pending ? 'That box is still being created or checked.' : 'That box name is taken.');
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
  const accessCacheMs = bounded(opts.boxAccessCacheMs, 30_000, 0, 300_000);
  // `__Host-` binds the cookie to this exact host over HTTPS, so a sibling subdomain cannot plant or shadow it.
  const COOKIE = config.secure ? '__Host-ks_control_session' : 'ks_control_session';
  const attributes = `Path=/; HttpOnly; SameSite=Strict${config.secure ? '; Secure' : ''}`;

  const challenges = new Map<string, Ceremony>();
  const byClient = new Map<string, string[]>();
  const sessions = new Lru<string, StoredSession>(10_000);
  // N1: names whose provisioning call is running in this process, with the reserving account. Reconciliation never
  // touches them. The request's own confirm, release or hold ends it before any storage access, so a storage failure
  // there cannot leave a name in flight for the life of the process.
  const inFlight = new Map<string, string>();
  const landed = (accountId: string, boxId: string) => { if (inFlight.get(boxId) === accountId) inFlight.delete(boxId); };
  // Relay access per box, dropped on every write this process makes to the box or to any plan.
  const access = new Lru<string, { value: BoxAccess; until: number }>(10_000);
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
    // A registration ceremony carries the id the new account will have; the page uses its bytes as the passkey's user
    // handle. Lower-case hex: an id in a Cloud Storage URL can never look like a provider key to the egress guard.
    challenges.set(ceremonyId, { challenge, kind, accountId: kind === 'registration' ? randomBytes(32).toString('hex') : accountId, client: owner, expires: now() + challengeTtlMs });
    byClient.set(owner, [...(byClient.get(owner) ?? []), ceremonyId]);
    return { id: ceremonyId, challenge, rpId: config.rpId };
  }
  function consume(challengeId: string, kind: Ceremony['kind'], accountId?: string): Ceremony {
    const value = typeof challengeId === 'string' ? challenges.get(challengeId) : undefined;
    if (value) dropChallenge(challengeId);
    if (!value || value.expires <= now() || value.kind !== kind || (kind === 'assertion' && value.accountId !== accountId)) fail();
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
  const iso = () => new Date(now()).toISOString();
  async function writeOwner(boxId: string, record: BoxOwner): Promise<void> {
    await storage.put(`box-owners/${boxId}`, record);
    access.delete(boxId);
  }
  async function hold(accountId: string, boxId: string, state: 'pending' | 'active' | null): Promise<void> {
    const held = await boxes(accountId);
    if (state !== null && held.boxes[boxId] === state) return;
    const { [boxId]: _previous, ...rest } = held.boxes;
    const next = state === null ? rest : { ...rest, [boxId]: state };
    if (Object.keys(next).length) await storage.put(`account-boxes/${accountId}`, { v: 1, boxes: next });
    else await storage.delete(`account-boxes/${accountId}`);
  }
  /** Runs under the account lock. A box confirmed for an account that is no longer paid is suspended at once. */
  async function activate(account: Account, boxId: string): Promise<void> {
    if (account.plan !== 'paid') await storage.put(`${STOPS}${boxId}`, { v: 1 });
    await writeOwner(boxId, { accountId: account.id, state: 'active', since: iso() });
    await hold(account.id, boxId, 'active');
    await storage.delete(`${RECONCILE}${boxId}`);
  }
  /** Runs under the account lock: removes a pending reservation; the index entry goes last. */
  async function removePending(accountId: string, boxId: string): Promise<void> {
    await hold(accountId, boxId, null);
    await storage.delete(`box-owners/${boxId}`);
    access.delete(boxId);
    await storage.delete(`${RECONCILE}${boxId}`);
  }
  const reservationOf = (record: BoxOwner) => record.reservation ?? record.since ?? '';

  return {
    cookieName: COOKIE,
    /** Set-Cookie value that removes the session cookie with matching attributes. */
    clearCookie: `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${config.secure ? '; Secure' : ''}`,
    /** `userId` is the new account id's 32 bytes (base64url): the page passes them as the passkey's user handle. */
    registrationChallenge(client?: string) {
      const ceremony = begin('registration', client);
      return { ...ceremony, userId: Buffer.from(challenges.get(ceremony.id)!.accountId!, 'hex').toString('base64url') };
    },
    async register(input: RegisterAccountInput): Promise<AccountLogin> {
      const ceremony = consume(input.challengeId, 'registration');
      return accountLock(async () => {
        let credential: PasskeyCredential;
        try {
          if (!Buffer.isBuffer(input.attestationObject) || input.attestationObject.length > 64 * 1024) fail();
          credential = verifyRegistration({ ...input, expectedChallenge: Buffer.from(ceremony.challenge, 'base64url'), expectedOrigins: [opts.origin], rpId: config.rpId, requireUserVerification: true });
        } catch { return fail(); }
        const credentialKey = `credentials/${hashOf(credential.id)}`;
        if (await storage.get(credentialKey) || await get(ceremony.accountId ?? '-')) fail();
        const account: Account = { id: ceremony.accountId ?? token(), credential: { ...credential, createdAt: new Date(now()).toISOString() }, plan: 'free', createdAt: new Date(now()).toISOString() };
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
    /**
     * With an account id: a challenge for that account's passkey. Without one: a discoverable-credential challenge,
     * where the browser offers the user's keysentry passkeys and the credential id names the account.
     */
    async assertionChallenge(accountId?: string, client?: string) {
      if (accountId === undefined) return begin('assertion', client);
      const account = await get(accountId); if (!account) fail();
      return { ...begin('assertion', client, accountId), credentialId: account.credential.id };
    },
    async signIn(input: SignInInput): Promise<AccountLogin> {
      const ceremony = consume(input.challengeId, 'assertion', input.accountId);
      return accountLock(async () => {
        let accountId = input.accountId;
        if (accountId === undefined) {
          if (typeof input.credentialId !== 'string' || input.credentialId.length === 0 || input.credentialId.length > 1400) fail();
          const index = await storage.get<{ accountId?: unknown }>(`credentials/${hashOf(input.credentialId)}`);
          if (typeof index?.accountId !== 'string') fail();
          accountId = index.accountId;
        }
        const account = await get(accountId); if (!account || account.credential.id !== input.credentialId) fail();
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
    /** Plan and boxes for the signed-in page. */
    async overview(accountId: string): Promise<AccountOverview> {
      const account = await get(accountId); if (!account) fail();
      const paid = account.plan === 'paid';
      const held = await boxes(account.id);
      const list: AccountOverview['boxes'] = [];
      for (const [name, state] of Object.entries(held.boxes)) {
        if (state === 'pending') list.push({ name, state });
        else if (state === 'active') list.push({ name, state: !paid ? 'suspended' : (await owner(name))?.stopped ? 'stopped' : 'active' });
      }
      list.sort((a, b) => a.name.localeCompare(b.name));
      return { accountId: account.id, plan: paid ? 'paid' : 'free', boxes: list, boxQuota };
    },
    /**
     * H1/N1: holds the name for this account before any Compute call. Refuses an unpaid account (402), an account at
     * its quota (403, pending reservations count) and any name already held (409): another account's, an active box,
     * or this account's reservation that is still in flight or awaiting reconciliation (`pending` set). `deviceKey` is
     * kept with the reservation so reconciliation can recognise the instance it creates.
     */
    async reserveBox(accountId: string, boxId: string, deviceKey?: string): Promise<void> {
      return accountLock(async () => {
        if (deviceKey !== undefined && (typeof deviceKey !== 'string' || !/^[A-Za-z0-9+/]{1,128}={0,2}$/.test(deviceKey))) fail();
        const account = await get(accountId); if (!account) fail();
        if (account.plan !== 'paid') throw new AccountRefusal(402);
        const current = await owner(boxId);
        if (current) throw new AccountRefusal(409, current.accountId === accountId && current.state === 'pending');
        const held = await boxes(accountId);
        if (Object.keys(held.boxes).length >= boxQuota) throw new AccountRefusal(403);
        // The index entry first: a crash after it leaves an entry the sweep drops, never a reservation it cannot find.
        await storage.put(`${RECONCILE}${boxId}`, { v: 1 });
        await writeOwner(boxId, { accountId, state: 'pending', since: iso(), reservation: randomBytes(12).toString('hex'), ...(deviceKey ? { deviceKey } : {}) });
        await hold(accountId, boxId, 'pending');
        inFlight.set(boxId, accountId);
      });
    },
    /**
     * Compute accepted the instance. Idempotent: an active box stays as it is, and a reservation that is gone is
     * recorded again (the instance exists; an owner record keeps it from being orphaned).
     */
    async confirmBox(accountId: string, boxId: string): Promise<void> {
      return accountLock(async () => {
        landed(accountId, boxId);
        const account = await get(accountId); if (!account) fail();
        const current = await owner(boxId);
        if (current && current.accountId !== accountId) fail();
        if (current?.state === 'active') {
          await hold(accountId, boxId, 'active');
          await storage.delete(`${RECONCILE}${boxId}`);
          return;
        }
        await activate(account, boxId);
      });
    },
    /** Rolls back a pending reservation after a definite refusal from Compute. An active box is never released here. */
    async releaseBox(accountId: string, boxId: string): Promise<void> {
      return accountLock(async () => {
        landed(accountId, boxId);
        const current = await owner(boxId);
        if (!current || current.accountId !== accountId || current.state !== 'pending') return;
        await removePending(accountId, boxId);
      });
    },
    /** N1: the Compute call had no definite outcome (409, timeout, anything unknown). The name stays held. */
    async holdBox(accountId: string, boxId: string): Promise<void> {
      return accountLock(async () => {
        landed(accountId, boxId);
        const current = await owner(boxId);
        if (!current || current.accountId !== accountId || current.state !== 'pending') return;
        await writeOwner(boxId, { ...current, uncertain: true });
      });
    },
    /** Names with a pending reservation (`reconcile`) or a stop to request (`stops`), for the minute sweep. */
    async boxQueue(kind: 'reconcile' | 'stops'): Promise<string[]> {
      const prefix = kind === 'reconcile' ? RECONCILE : STOPS;
      return (await storage.list(prefix)).map(key => key.slice(prefix.length));
    },
    /**
     * A reservation reconciliation may check with Compute: pending and not being provisioned in this process.
     * An index entry whose reservation is gone or already active is tidied here.
     */
    async pendingBox(boxId: string): Promise<PendingBox | null> {
      return accountLock(async () => {
        const current = await owner(boxId);
        if (!current || current.state !== 'pending') {
          if (current) await hold(current.accountId, boxId, 'active');
          await storage.delete(`${RECONCILE}${boxId}`);
          return null;
        }
        if (inFlight.has(boxId)) return null;
        const since = Date.parse(current.since ?? '');
        return { accountId: current.accountId, reservation: reservationOf(current), ...(current.deviceKey ? { deviceKey: current.deviceKey } : {}),
          ageMs: Number.isFinite(since) ? Math.max(0, now() - since) : Number.MAX_SAFE_INTEGER };
      });
    },
    /** Applies reconciliation's answer, only to the same reservation and only while nothing is provisioning it. */
    async settleBox(boxId: string, reservation: string, outcome: BoxSettlement): Promise<boolean> {
      return accountLock(async () => {
        const current = await owner(boxId);
        if (!current || current.state !== 'pending' || inFlight.has(boxId) || reservationOf(current) !== reservation) return false;
        if (outcome === 'present') {
          const account = await get(current.accountId); if (!account) fail();
          await activate(account, boxId);
        } else await removePending(current.accountId, boxId);
        return true;
      });
    },
    /** Records an active box without plan or quota checks: for trusted local composition only, never a route. */
    async addBox(accountId: string, boxId: string): Promise<void> {
      return accountLock(async () => {
        if (!await get(accountId)) fail();
        const current = await owner(boxId);
        if (current && current.accountId !== accountId) fail();
        await writeOwner(boxId, { accountId, state: 'active', since: iso() });
        await hold(accountId, boxId, 'active');
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
    /**
     * Downgrade: a box credential works only while the box's account is paid. Checked on every relay request; kept
     * in memory for `boxAccessCacheMs` and dropped whenever this process changes the box or a plan.
     */
    async boxAccess(boxId: string): Promise<BoxAccess> {
      const cached = access.get(boxId);
      if (cached && now() < cached.until) return cached.value;
      if (typeof boxId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(boxId)) return 'none';
      let value: BoxAccess = 'none';
      const current = await owner(boxId);
      if (current && current.state !== 'pending') value = (await get(current.accountId))?.plan === 'paid' ? 'allowed' : 'suspended';
      access.set(boxId, { value, until: now() + accessCacheMs });
      return value;
    },
    /** True when a stop should still be requested for this box (active, account unpaid); otherwise drops the entry. */
    async stopDue(boxId: string): Promise<boolean> {
      return accountLock(async () => {
        const current = await owner(boxId);
        if (current && current.state === 'active' && (await get(current.accountId))?.plan !== 'paid') return true;
        await storage.delete(`${STOPS}${boxId}`);
        return false;
      });
    },
    /** Compute accepted the stop (or the instance is gone): the page offers to start it once the plan is paid. */
    async markStopped(boxId: string): Promise<void> {
      return accountLock(async () => {
        const current = await owner(boxId);
        if (current?.state === 'active' && !current.stopped) await writeOwner(boxId, { ...current, stopped: true });
        await storage.delete(`${STOPS}${boxId}`);
      });
    },
    /** A start request from the owner's page: 402 without the paid plan, 403 unless this account's active box. */
    async startTarget(accountId: string, boxId: string): Promise<void> {
      const account = await get(accountId); if (!account) fail();
      if (account.plan !== 'paid') throw new AccountRefusal(402);
      const current = await owner(boxId);
      if (!current || current.accountId !== accountId || current.state !== 'active') throw new AccountRefusal(403);
    },
    async markStarted(boxId: string): Promise<void> {
      return accountLock(async () => {
        const current = await owner(boxId);
        if (current?.state === 'active' && current.stopped) {
          const { stopped: _stopped, ...rest } = current;
          await writeOwner(boxId, rest);
        }
      });
    },
    /**
     * Downgrade (paid to free): the account's active boxes are suspended (`boxAccess`) and a stop is queued for each
     * (written before the plan, so a crash never loses one). Upgrade: queued stops that were not sent are dropped. No
     * box record or data is deleted.
     */
    async setPlan(accountId: string, plan: Account['plan'], billing?: { customerId?: string; subscriptionId?: string }): Promise<void> {
      return accountLock(async () => {
        const account = await get(accountId); if (!account || (plan !== 'free' && plan !== 'paid')) fail();
        const previous = account.plan;
        account.plan = plan;
        if (billing?.customerId !== undefined) account.customerId = id(billing.customerId);
        if (billing?.subscriptionId !== undefined) account.subscriptionId = id(billing.subscriptionId);
        const active = Object.entries((await boxes(account.id)).boxes).filter(([, state]) => state === 'active').map(([name]) => name);
        if (previous === 'paid' && plan !== 'paid') for (const name of active) await storage.put(`${STOPS}${name}`, { v: 1 });
        await storage.put(`accounts/${account.id}`, account);
        access.clear();
        if (plan === 'paid' && previous !== 'paid') for (const name of active) await storage.delete(`${STOPS}${name}`);
      });
    },
  };
}
export type Accounts = ReturnType<typeof createAccounts>;
