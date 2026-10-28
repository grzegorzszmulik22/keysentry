import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { verifyAssertion, verifyRegistration } from '../../../src/approvals/webauthn/index.js';
import type { PasskeyCredential } from '../../../src/types.js';
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
  sessionIdleMs?: number;
}
interface Ceremony { challenge: string; expires: number; kind: 'registration' | 'assertion'; accountId?: string }
export interface RegisterAccountInput { challengeId: string; clientDataJSON: Buffer; attestationObject: Buffer }
export interface SignInInput {
  accountId: string; challengeId: string; credentialId: string;
  clientDataJSON: Buffer; authenticatorData: Buffer; signature: Buffer;
}
export interface AccountLogin { account: Account; session: AccountSession; cookie: string }

const COOKIE = 'ks_control_session';
const token = () => randomBytes(32).toString('base64url');
function fail(): never { throw new Error('Account request could not be verified.'); }
function id(value: string): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(value)) fail();
  return value;
}
function same(actual: string | undefined, expected: string): boolean {
  return typeof actual === 'string' && /^[A-Za-z0-9_-]+$/.test(actual)
    && actual.length === expected.length && timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
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

/** Passkey credentials are public metadata. Session and challenge tokens stay in memory. */
export function createAccounts(opts: AccountsOptions) {
  const config = originConfig(opts.origin, opts.rpId);
  const now = opts.now ?? Date.now;
  const challengeTtlMs = opts.challengeTtlMs ?? 120_000;
  const sessionIdleMs = opts.sessionIdleMs ?? 30 * 60_000;
  if (!Number.isSafeInteger(challengeTtlMs) || challengeTtlMs <= 0 || challengeTtlMs > 600_000
    || !Number.isSafeInteger(sessionIdleMs) || sessionIdleMs <= 0 || sessionIdleMs > 86_400_000) throw new Error('Invalid account expiry settings.');
  const challenges = new Map<string, Ceremony>();
  const sessions = new Map<string, AccountSession & { expires: number }>();
  let tail: Promise<unknown> = Promise.resolve();
  function serial<T>(fn: () => Promise<T>): Promise<T> {
    const result = tail.then(fn); tail = result.then(() => undefined, () => undefined); return result;
  }
  function begin(kind: Ceremony['kind'], accountId?: string) {
    for (const [key, value] of challenges) if (value.expires <= now()) challenges.delete(key);
    if (challenges.size >= 4096) throw new Error('Please try again later.');
    const ceremonyId = token(); const challenge = token();
    challenges.set(ceremonyId, { challenge, kind, accountId, expires: now() + challengeTtlMs });
    return { id: ceremonyId, challenge, rpId: config.rpId };
  }
  function consume(challengeId: string, kind: Ceremony['kind'], accountId?: string): Ceremony {
    const value = challenges.get(challengeId); challenges.delete(challengeId);
    if (!value || value.expires <= now() || value.kind !== kind || value.accountId !== accountId) fail();
    return value;
  }
  async function get(accountId: string): Promise<Account | null> { return opts.storage.get<Account>(`accounts/${id(accountId)}`); }
  function login(account: Account): AccountLogin {
    for (const [key, value] of sessions) if (value.expires <= now()) sessions.delete(key);
    if (sessions.size >= 4096) throw new Error('Please try again later.');
    const session = { id: token(), accountId: account.id, csrf: token() };
    sessions.set(session.id, { ...session, expires: now() + sessionIdleMs });
    return { account, session, cookie: `${COOKIE}=${session.id}; Path=/; HttpOnly; SameSite=Strict${config.secure ? '; Secure' : ''}` };
  }
  function cookieId(cookie: string | undefined): string | null {
    const matches = (cookie ?? '').split(';').map(part => part.trim()).filter(part => part.startsWith(`${COOKIE}=`));
    if (matches.length !== 1) return null;
    const value = matches[0]!.slice(COOKIE.length + 1);
    return /^[A-Za-z0-9_-]{43}$/.test(value) && Buffer.from(value, 'base64url').toString('base64url') === value ? value : null;
  }
  return {
    cookieName: COOKIE,
    registrationChallenge() { return begin('registration'); },
    async register(input: RegisterAccountInput): Promise<AccountLogin> {
      const ceremony = consume(input.challengeId, 'registration');
      return serial(async () => {
        let credential: PasskeyCredential;
        try {
          if (!Buffer.isBuffer(input.attestationObject) || input.attestationObject.length > 64 * 1024) fail();
          credential = verifyRegistration({ ...input, expectedChallenge: Buffer.from(ceremony.challenge, 'base64url'), expectedOrigins: [opts.origin], rpId: config.rpId, requireUserVerification: true });
        } catch { return fail(); }
        const credentialKey = `credentials/${createHash('sha256').update(credential.id).digest('hex')}`;
        if (await opts.storage.get(credentialKey)) fail();
        const account: Account = { id: token(), credential: { ...credential, createdAt: new Date(now()).toISOString() }, plan: 'free', createdAt: new Date(now()).toISOString() };
        await opts.storage.put(`accounts/${account.id}`, account);
        await opts.storage.put(credentialKey, { accountId: account.id });
        return login(account);
      });
    },
    async assertionChallenge(accountId: string) {
      const account = await get(accountId); if (!account) fail();
      return { ...begin('assertion', accountId), credentialId: account.credential.id };
    },
    async signIn(input: SignInInput): Promise<AccountLogin> {
      const ceremony = consume(input.challengeId, 'assertion', input.accountId);
      return serial(async () => {
        const account = await get(input.accountId); if (!account || account.credential.id !== input.credentialId) fail();
        let result: ReturnType<typeof verifyAssertion>;
        try {
          result = verifyAssertion({ ...input, credential: account.credential, expectedChallenge: Buffer.from(ceremony.challenge, 'base64url'), expectedOrigins: [opts.origin], requireUserVerification: true });
        } catch { return fail(); }
        if (result.cloneWarning) fail();
        account.credential.signCount = result.signCount;
        await opts.storage.put(`accounts/${account.id}`, account);
        return login(account);
      });
    },
    authenticate(cookie: string | undefined): AccountSession | null {
      const value = cookieId(cookie); if (!value) return null;
      const session = sessions.get(value); if (!session) return null;
      if (session.expires <= now()) { sessions.delete(value); return null; }
      if (!same(value, session.id)) return null;
      session.expires = now() + sessionIdleMs;
      return { id: session.id, accountId: session.accountId, csrf: session.csrf };
    },
    clearSession(cookie: string | undefined): void { const value = cookieId(cookie); if (value) sessions.delete(value); },
    get,
    async addBox(accountId: string, boxId: string): Promise<void> {
      return serial(async () => {
        if (!await get(accountId)) fail();
        const key = `box-owners/${id(boxId)}`;
        const owner = await opts.storage.get<{ accountId: string }>(key);
        if (owner && owner.accountId !== accountId) fail();
        await opts.storage.put(key, { accountId });
      });
    },
    async ownsBox(accountId: string, boxId: string): Promise<boolean> {
      const owner = await opts.storage.get<{ accountId: string }>(`box-owners/${id(boxId)}`);
      return owner?.accountId === accountId;
    },
    async setPlan(accountId: string, plan: Account['plan'], billing?: { customerId?: string; subscriptionId?: string }): Promise<void> {
      return serial(async () => {
        const account = await get(accountId); if (!account || (plan !== 'free' && plan !== 'paid')) fail();
        account.plan = plan;
        if (billing?.customerId !== undefined) account.customerId = id(billing.customerId);
        if (billing?.subscriptionId !== undefined) account.subscriptionId = id(billing.subscriptionId);
        await opts.storage.put(`accounts/${account.id}`, account);
      });
    },
  };
}
export type Accounts = ReturnType<typeof createAccounts>;
