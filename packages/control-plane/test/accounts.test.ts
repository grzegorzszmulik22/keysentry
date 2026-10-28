import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { encode } from '../../../test/approvals/webauthn/helpers.js';
import { createAccounts } from '../src/accounts.js';

function memory() {
  const data = new Map<string, unknown>();
  return {
    async get<T>(key: string): Promise<T | null> { return structuredClone(data.get(key) as T ?? null); },
    async put(key: string, value: unknown) { data.set(key, structuredClone(value)); },
    async delete(key: string) { data.delete(key); },
    async list(prefix: string) { return [...data.keys()].filter(key => key.startsWith(prefix)); },
  };
}
function authenticator() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const credentialId = randomBytes(16);
  const cose = encode(new Map<number, unknown>([[1, 1], [3, -8], [-1, 6], [-2, Buffer.from(publicKey.export({ format: 'jwk' }).x!, 'base64url')]]));
  function client(challenge: string, type: string, origin = 'https://control.example') {
    return Buffer.from(JSON.stringify({ type, challenge, origin }));
  }
  return {
    id: credentialId.toString('base64url'),
    registration(challenge: string, origin?: string) {
      const count = Buffer.alloc(4);
      const length = Buffer.alloc(2); length.writeUInt16BE(credentialId.length);
      const auth = Buffer.concat([createHash('sha256').update('control.example').digest(), Buffer.from([0x45]), count, Buffer.alloc(16), length, credentialId, cose]);
      return { clientDataJSON: client(challenge, 'webauthn.create', origin), attestationObject: encode(new Map<string, unknown>([['fmt', 'none'], ['attStmt', new Map()], ['authData', auth]])) };
    },
    assertion(challenge: string, counter = 1, origin?: string) {
      const clientDataJSON = client(challenge, 'webauthn.get', origin);
      const count = Buffer.alloc(4); count.writeUInt32BE(counter);
      const authenticatorData = Buffer.concat([createHash('sha256').update('control.example').digest(), Buffer.from([5]), count]);
      const signature = sign(null, Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJSON).digest()]), privateKey);
      return { clientDataJSON, authenticatorData, signature };
    },
  };
}
function setup() {
  let now = 1_000_000;
  const storage = memory();
  const accounts = createAccounts({ storage, origin: 'https://control.example', now: () => now, sessionIdleMs: 60_000 });
  return { accounts, storage, advance(ms: number) { now += ms; } };
}
async function signup(ctx = setup()) {
  const auth = authenticator();
  const challenge = ctx.accounts.registrationChallenge();
  const result = await ctx.accounts.register({ challengeId: challenge.id, ...auth.registration(challenge.challenge) });
  return { ...ctx, auth, ...result };
}

describe('passkey accounts', () => {
  test('verified registration creates an account and a private strict cookie session', async () => {
    const ctx = await signup();
    expect(ctx.account.plan).toBe('free');
    expect(ctx.account.credential.id).toBe(ctx.auth.id);
    expect(ctx.cookie).toContain('Path=/; HttpOnly; SameSite=Strict; Secure');
    expect(ctx.cookie).toMatch(/^__Host-ks_control_session=[A-Za-z0-9_-]{43}; /);
    expect((await ctx.accounts.authenticate(ctx.cookie))?.accountId).toBe(ctx.account.id);
    expect((await ctx.accounts.authenticate(ctx.cookie))?.csrf).toHaveLength(43);
    expect(await ctx.accounts.get(ctx.account.id)).toEqual(ctx.account);
  });
  test('registration rejects wrong origins and consumes the challenge after a failed attempt', async () => {
    const { accounts } = setup(); const auth = authenticator(); const challenge = accounts.registrationChallenge();
    await expect(accounts.register({ challengeId: challenge.id, ...auth.registration(challenge.challenge, 'https://other.example') })).rejects.toThrow();
    await expect(accounts.register({ challengeId: challenge.id, ...auth.registration(challenge.challenge) })).rejects.toThrow();
  });
  test('a registration challenge is single-use under concurrent completion attempts', async () => {
    const { accounts } = setup(); const auth = authenticator(); const challenge = accounts.registrationChallenge();
    const input = { challengeId: challenge.id, ...auth.registration(challenge.challenge) };
    const results = await Promise.allSettled([accounts.register(input), accounts.register(input)]);
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
  });
  test('an expired registration challenge cannot create an account', async () => {
    const ctx = setup(); const auth = authenticator(); const challenge = ctx.accounts.registrationChallenge(); ctx.advance(120_000);
    await expect(ctx.accounts.register({ challengeId: challenge.id, ...auth.registration(challenge.challenge) })).rejects.toThrow();
  });
  test('the same credential cannot register a second account', async () => {
    const ctx = await signup(); const challenge = ctx.accounts.registrationChallenge();
    await expect(ctx.accounts.register({ challengeId: challenge.id, ...ctx.auth.registration(challenge.challenge) })).rejects.toThrow();
  });
  test('registration requires authenticator user verification', async () => {
    const { accounts } = setup(); const auth = authenticator(); const challenge = accounts.registrationChallenge();
    const registration = auth.registration(challenge.challenge);
    // The signed attestation object is CBOR with one 32-byte rpId hash; clear UV at its following flags byte.
    const hash = createHash('sha256').update('control.example').digest();
    const offset = registration.attestationObject.indexOf(hash);
    registration.attestationObject[offset + 32] = 0x41;
    await expect(accounts.register({ challengeId: challenge.id, ...registration })).rejects.toThrow();
  });
  test('sign-in verifies a new assertion and rejects assertion replay and counter regression', async () => {
    const ctx = await signup(); const challenge = await ctx.accounts.assertionChallenge(ctx.account.id);
    const input = { accountId: ctx.account.id, challengeId: challenge.id, credentialId: ctx.auth.id, ...ctx.auth.assertion(challenge.challenge) };
    const signed = await ctx.accounts.signIn(input);
    expect(signed.account.credential.signCount).toBe(1);
    expect((await ctx.accounts.authenticate(signed.cookie))?.accountId).toBe(ctx.account.id);
    await expect(ctx.accounts.signIn(input)).rejects.toThrow();
    const next = await ctx.accounts.assertionChallenge(ctx.account.id);
    await expect(ctx.accounts.signIn({ ...input, challengeId: next.id, ...ctx.auth.assertion(next.challenge, 1) })).rejects.toThrow();
  });
  test('sign-in rejects a credential from a different account', async () => {
    const ctx = await signup(); const second = await signup(ctx); const challenge = await ctx.accounts.assertionChallenge(ctx.account.id);
    await expect(ctx.accounts.signIn({ accountId: ctx.account.id, challengeId: challenge.id, credentialId: second.auth.id, ...second.auth.assertion(challenge.challenge) })).rejects.toThrow();
  });
  test('an invalid signature consumes its sign-in challenge without issuing a session', async () => {
    const ctx = await signup(); const challenge = await ctx.accounts.assertionChallenge(ctx.account.id);
    const input = { accountId: ctx.account.id, challengeId: challenge.id, credentialId: ctx.auth.id, ...ctx.auth.assertion(challenge.challenge) };
    const signature = Buffer.from(input.signature); signature[0] = signature[0]! ^ 1;
    await expect(ctx.accounts.signIn({ ...input, signature })).rejects.toThrow();
    await expect(ctx.accounts.signIn(input)).rejects.toThrow();
    expect((await ctx.accounts.get(ctx.account.id))?.credential.signCount).toBe(0);
  });
  test('an expired sign-in challenge cannot issue a session', async () => {
    const ctx = await signup(); const challenge = await ctx.accounts.assertionChallenge(ctx.account.id); ctx.advance(120_000);
    await expect(ctx.accounts.signIn({ accountId: ctx.account.id, challengeId: challenge.id, credentialId: ctx.auth.id, ...ctx.auth.assertion(challenge.challenge) })).rejects.toThrow();
  });
  test('duplicate cookies, idle expiry and cleared sessions cannot authenticate', async () => {
    const ctx = await signup(); const pair = ctx.cookie.split(';')[0]!;
    expect(await ctx.accounts.authenticate(`${pair}; ${pair}`)).toBeNull();
    ctx.advance(60_000); expect(await ctx.accounts.authenticate(pair)).toBeNull();
    const second = await signup(ctx); await ctx.accounts.clearSession(second.cookie); expect(await ctx.accounts.authenticate(second.cookie)).toBeNull();
  });
  test('account ownership cannot be reassigned or accessed by another account', async () => {
    const ctx = await signup(); const second = await signup(ctx);
    await ctx.accounts.addBox(ctx.account.id, 'box-one');
    expect(await ctx.accounts.ownsBox(ctx.account.id, 'box-one')).toBe(true);
    expect(await ctx.accounts.ownsBox(second.account.id, 'box-one')).toBe(false);
    await expect(ctx.accounts.addBox(second.account.id, 'box-one')).rejects.toThrow();
    await expect(ctx.accounts.addBox('missing', 'box-two')).rejects.toThrow();
  });
  test('HTTP sessions are permitted only on loopback and omit Secure there', () => {
    expect(() => createAccounts({ storage: memory(), origin: 'http://remote.example' })).toThrow();
    const local = createAccounts({ storage: memory(), origin: 'http://127.0.0.1:1234' });
    expect(local.cookieName).toBe('ks_control_session');
    expect(local.clearCookie).not.toContain('Secure');
  });
});

describe('M1 and L4: durable, bounded sessions and challenges', () => {
  async function signIn(ctx: Awaited<ReturnType<typeof signup>>) {
    const challenge = await ctx.accounts.assertionChallenge(ctx.account.id);
    return ctx.accounts.signIn({ accountId: ctx.account.id, challengeId: challenge.id, credentialId: ctx.auth.id, ...ctx.auth.assertion(challenge.challenge, ++counter) });
  }
  let counter = 0;
  test('sessions are stored by hash only and survive a restart on the same storage', async () => {
    const ctx = await signup();
    const id = ctx.session.id;
    for (const key of await ctx.storage.list('')) expect(JSON.stringify(await ctx.storage.get(key))).not.toContain(id);
    expect(await ctx.storage.list('sessions/')).toEqual([`sessions/${createHash('sha256').update(id).digest('hex')}`]);
    const restarted = createAccounts({ storage: ctx.storage, origin: 'https://control.example', now: () => 1_000_000 });
    expect(await restarted.authenticate(ctx.cookie)).toEqual({ id, accountId: ctx.account.id, csrf: ctx.session.csrf });
    expect(restarted.cachedSession(ctx.cookie)).toBe(true);
  });
  test('a sign-in beyond the per-account cap evicts that account\'s oldest session only', async () => {
    let now = 1_000_000;
    const storage = memory();
    const accounts = createAccounts({ storage, origin: 'https://control.example', now: () => now, maxSessionsPerAccount: 2 });
    const ctx = await signup({ accounts, storage, advance: (ms: number) => { now += ms; } });
    const other = await signup({ accounts, storage, advance: (ms: number) => { now += ms; } });
    now += 1; const second = await signIn(ctx);
    now += 1; const third = await signIn(ctx);
    expect(await accounts.authenticate(ctx.cookie)).toBeNull();
    expect(await accounts.authenticate(second.cookie)).not.toBeNull();
    expect(await accounts.authenticate(third.cookie)).not.toBeNull();
    expect(await accounts.authenticate(other.cookie)).not.toBeNull();
    expect((await storage.list('sessions/')).length).toBe(3);
  });
  test('activity extends the idle expiry but never the absolute lifetime', async () => {
    let now = 1_000_000;
    const storage = memory();
    const accounts = createAccounts({ storage, origin: 'https://control.example', now: () => now, sessionIdleMs: 120_000, sessionMaxAgeMs: 300_000 });
    const ctx = await signup({ accounts, storage, advance: (ms: number) => { now += ms; } });
    for (let i = 0; i < 4; i++) { now += 70_000; expect(await accounts.authenticate(ctx.cookie)).not.toBeNull(); }
    now += 30_000;
    expect(await accounts.authenticate(ctx.cookie)).toBeNull();
    expect(await storage.list('sessions/')).toEqual([]);
  });
  test('a full ceremony table evicts that client\'s oldest challenge, not other clients\'', async () => {
    const ctx = await signup();
    const first = ctx.accounts.registrationChallenge('203.0.113.9');
    for (let i = 0; i < 16; i++) ctx.accounts.registrationChallenge('203.0.113.9');
    const other = await ctx.accounts.assertionChallenge(ctx.account.id, '198.51.100.7');
    const auth = authenticator();
    await expect(ctx.accounts.register({ challengeId: first.id, ...auth.registration(first.challenge) })).rejects.toThrow();
    const signed = await ctx.accounts.signIn({ accountId: ctx.account.id, challengeId: other.id, credentialId: ctx.auth.id, ...ctx.auth.assertion(other.challenge, 5) });
    expect(signed.session.accountId).toBe(ctx.account.id);
  });
  test('a registration whose session cannot be stored writes nothing and the passkey can register later', async () => {
    const inner = memory();
    let refuse = true;
    const storage = { ...inner, async put(key: string, value: unknown) { if (refuse && key.startsWith('account-sessions/')) throw new Error('unavailable'); return inner.put(key, value); } };
    const accounts = createAccounts({ storage, origin: 'https://control.example', now: () => 1_000_000 });
    const auth = authenticator();
    const attempt = () => { const challenge = accounts.registrationChallenge(); return accounts.register({ challengeId: challenge.id, ...auth.registration(challenge.challenge) }); };
    await expect(attempt()).rejects.toThrow();
    expect(await inner.list('')).toEqual([]);
    refuse = false;
    await expect(attempt()).resolves.toHaveProperty('account');
  });
  test('clearing a session removes it from storage and from the account index', async () => {
    const ctx = await signup();
    await ctx.accounts.clearSession(ctx.cookie);
    expect(await ctx.storage.list('sessions/')).toEqual([]);
    expect(await ctx.storage.get(`account-sessions/${ctx.account.id}`)).toEqual({ v: 1, sessions: [] });
  });
});

describe('H1: box reservations', () => {
  async function paid(ctx: Awaited<ReturnType<typeof signup>>) { await ctx.accounts.setPlan(ctx.account.id, 'paid'); }
  test('a free account cannot reserve; a paid one reserves, confirms and owns its box', async () => {
    const ctx = await signup();
    await expect(ctx.accounts.reserveBox(ctx.account.id, 'box-one')).rejects.toMatchObject({ status: 402 });
    expect(await ctx.storage.list('box-owners/')).toEqual([]);
    await paid(ctx);
    await ctx.accounts.reserveBox(ctx.account.id, 'box-one');
    expect(await ctx.accounts.ownsBox(ctx.account.id, 'box-one')).toBe(false);
    expect(await ctx.accounts.boxOwner('box-one')).toBeNull();
    await ctx.accounts.confirmBox(ctx.account.id, 'box-one');
    expect(await ctx.accounts.ownsBox(ctx.account.id, 'box-one')).toBe(true);
    expect(await ctx.accounts.boxOwner('box-one')).toBe(ctx.account.id);
  });
  test('the quota counts pending and active boxes, a held name is refused to others, and release frees both', async () => {
    const ctx = await signup(); const other = await signup(ctx);
    await paid(ctx); await paid(other);
    await ctx.accounts.reserveBox(ctx.account.id, 'box-one');
    await expect(ctx.accounts.reserveBox(ctx.account.id, 'box-two')).rejects.toMatchObject({ status: 403 });
    await expect(ctx.accounts.reserveBox(other.account.id, 'box-one')).rejects.toMatchObject({ status: 409 });
    await ctx.accounts.reserveBox(ctx.account.id, 'box-one');
    await ctx.accounts.releaseBox(ctx.account.id, 'box-one');
    await other.accounts.reserveBox(other.account.id, 'box-one');
    await ctx.accounts.reserveBox(ctx.account.id, 'box-two');
    await other.accounts.confirmBox(other.account.id, 'box-one');
    await other.accounts.releaseBox(other.account.id, 'box-one');
    expect(await ctx.accounts.ownsBox(other.account.id, 'box-one')).toBe(true);
  });
  test('the quota is configurable', async () => {
    const storage = memory();
    const accounts = createAccounts({ storage, origin: 'https://control.example', now: () => 1_000_000, boxQuota: 2 });
    const ctx = await signup({ accounts, storage, advance: () => undefined });
    await paid(ctx);
    await accounts.reserveBox(ctx.account.id, 'box-one'); await accounts.reserveBox(ctx.account.id, 'box-two');
    await expect(accounts.reserveBox(ctx.account.id, 'box-three')).rejects.toMatchObject({ status: 403 });
  });
});
