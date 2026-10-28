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
    await expect(ctx.accounts.reserveBox(other.account.id, 'box-one')).rejects.toMatchObject({ status: 409, pending: false });
    // N1: a reservation still in flight is never reserved again, not even by its own account.
    await expect(ctx.accounts.reserveBox(ctx.account.id, 'box-one')).rejects.toMatchObject({ status: 409, pending: true });
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

describe('N1: reservations in flight, uncertain outcomes and reconciliation', () => {
  const key = generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  async function paidAccount(boxQuota = 1) {
    let now = 1_000_000;
    const storage = memory();
    const accounts = createAccounts({ storage, origin: 'https://control.example', now: () => now, boxQuota });
    const ctx = await signup({ accounts, storage, advance(ms: number) { now += ms; } });
    await accounts.setPlan(ctx.account.id, 'paid');
    return ctx;
  }
  test('confirmBox is idempotent, and records an instance whose reservation record is gone', async () => {
    const ctx = await paidAccount(2);
    await ctx.accounts.reserveBox(ctx.account.id, 'box-one', key);
    await ctx.accounts.confirmBox(ctx.account.id, 'box-one');
    await ctx.accounts.confirmBox(ctx.account.id, 'box-one');
    expect((await ctx.accounts.overview(ctx.account.id)).boxes).toEqual([{ name: 'box-one', state: 'active' }]);
    expect(await ctx.storage.list('box-reconcile/')).toEqual([]);
    await ctx.accounts.reserveBox(ctx.account.id, 'box-two', key);
    await ctx.storage.delete('box-owners/box-two');
    await ctx.accounts.confirmBox(ctx.account.id, 'box-two');
    expect(await ctx.accounts.ownsBox(ctx.account.id, 'box-two')).toBe(true);
    const other = await signup(ctx);
    await expect(ctx.accounts.confirmBox(other.account.id, 'box-two')).rejects.toThrow('Account request could not be verified.');
  });
  test('a held reservation is offered to reconciliation only when nothing in this process provisions it', async () => {
    const ctx = await paidAccount();
    await ctx.accounts.reserveBox(ctx.account.id, 'box-one', key);
    expect(await ctx.accounts.pendingBox('box-one')).toBeNull();
    expect(await ctx.accounts.boxQueue('reconcile')).toEqual(['box-one']);
    await ctx.accounts.holdBox(ctx.account.id, 'box-one');
    ctx.advance(5_000);
    const pending = await ctx.accounts.pendingBox('box-one');
    expect(pending).toEqual({ accountId: ctx.account.id, reservation: expect.stringMatching(/^[a-f0-9]{24}$/), deviceKey: key, ageMs: 5_000 });
    await expect(ctx.accounts.reserveBox(ctx.account.id, 'box-one', key)).rejects.toMatchObject({ status: 409, pending: true });
    await expect(ctx.accounts.reserveBox(ctx.account.id, 'box-two', key)).rejects.toMatchObject({ status: 403 });
    expect(await ctx.accounts.settleBox('box-one', 'f'.repeat(24), 'present')).toBe(false);
    expect(await ctx.accounts.settleBox('box-one', pending!.reservation, 'present')).toBe(true);
    expect(await ctx.accounts.ownsBox(ctx.account.id, 'box-one')).toBe(true);
    expect(await ctx.accounts.boxQueue('reconcile')).toEqual([]);
    expect(await ctx.accounts.settleBox('box-one', pending!.reservation, 'absent')).toBe(false);
    expect(await ctx.accounts.ownsBox(ctx.account.id, 'box-one')).toBe(true);
  });
  test.each(['absent', 'foreign'] as const)('settling %s frees the name and the quota slot, and an older answer never settles a newer reservation', async outcome => {
    const ctx = await paidAccount();
    await ctx.accounts.reserveBox(ctx.account.id, 'box-one', key);
    await ctx.accounts.holdBox(ctx.account.id, 'box-one');
    const old = (await ctx.accounts.pendingBox('box-one'))!;
    expect(await ctx.accounts.settleBox('box-one', old.reservation, outcome)).toBe(true);
    expect(await ctx.accounts.overview(ctx.account.id)).toMatchObject({ boxes: [] });
    expect(await ctx.storage.list('box-')).toEqual([]);
    await ctx.accounts.reserveBox(ctx.account.id, 'box-one', key);
    await ctx.accounts.holdBox(ctx.account.id, 'box-one');
    expect(await ctx.accounts.settleBox('box-one', old.reservation, outcome)).toBe(false);
    expect((await ctx.accounts.overview(ctx.account.id)).boxes).toEqual([{ name: 'box-one', state: 'pending' }]);
  });
  test('a definite refusal releases; an active box is never released or held', async () => {
    const ctx = await paidAccount();
    await ctx.accounts.reserveBox(ctx.account.id, 'box-one', key);
    await ctx.accounts.releaseBox(ctx.account.id, 'box-one');
    expect(await ctx.storage.list('box-')).toEqual([]);
    await ctx.accounts.reserveBox(ctx.account.id, 'box-one', key);
    await ctx.accounts.confirmBox(ctx.account.id, 'box-one');
    await ctx.accounts.releaseBox(ctx.account.id, 'box-one');
    await ctx.accounts.holdBox(ctx.account.id, 'box-one');
    expect(await ctx.accounts.ownsBox(ctx.account.id, 'box-one')).toBe(true);
    expect(await ctx.accounts.pendingBox('box-one')).toBeNull();
  });
  test('the sweep index drops entries whose reservation is gone, and repairs one already active', async () => {
    const ctx = await paidAccount();
    await ctx.storage.put('box-reconcile/ghost-box', { v: 1 });
    expect(await ctx.accounts.pendingBox('ghost-box')).toBeNull();
    await ctx.accounts.reserveBox(ctx.account.id, 'box-one', key);
    // A crash between writing the active owner record and the rest of confirmBox.
    await ctx.storage.put('box-owners/box-one', { accountId: ctx.account.id, state: 'active', since: new Date(0).toISOString() });
    expect(await ctx.accounts.pendingBox('box-one')).toBeNull();
    expect(await ctx.accounts.boxQueue('reconcile')).toEqual([]);
    expect((await ctx.accounts.overview(ctx.account.id)).boxes).toEqual([{ name: 'box-one', state: 'active' }]);
  });
  test('refuses a device key that is not base64', async () => {
    const ctx = await paidAccount();
    for (const bad of ['not a key', 'a'.repeat(200), 'x\ny']) await expect(ctx.accounts.reserveBox(ctx.account.id, 'box-one', bad)).rejects.toThrow('Account request could not be verified.');
    expect(await ctx.storage.list('box-')).toEqual([]);
  });
});

describe('downgrade: suspension, stops and resuming', () => {
  async function withBox(boxAccessCacheMs?: number) {
    let now = 1_000_000;
    const storage = memory();
    const accounts = createAccounts({ storage, origin: 'https://control.example', now: () => now, ...(boxAccessCacheMs === undefined ? {} : { boxAccessCacheMs }) });
    const ctx = await signup({ accounts, storage, advance(ms: number) { now += ms; } });
    await accounts.setPlan(ctx.account.id, 'paid');
    await accounts.reserveBox(ctx.account.id, 'box-one');
    expect(await accounts.boxAccess('box-one')).toBe('none');
    await accounts.confirmBox(ctx.account.id, 'box-one');
    return ctx;
  }
  test('an unpaid account\'s boxes lose relay access and get a queued stop; paying again restores access and offers a start', async () => {
    const ctx = await withBox();
    expect(await ctx.accounts.boxAccess('box-one')).toBe('allowed');
    await ctx.accounts.setPlan(ctx.account.id, 'free');
    expect(await ctx.accounts.boxAccess('box-one')).toBe('suspended');
    expect(await ctx.accounts.ownsBox(ctx.account.id, 'box-one')).toBe(true);
    expect((await ctx.accounts.overview(ctx.account.id)).boxes).toEqual([{ name: 'box-one', state: 'suspended' }]);
    expect(await ctx.accounts.boxQueue('stops')).toEqual(['box-one']);
    expect(await ctx.accounts.stopDue('box-one')).toBe(true);
    await expect(ctx.accounts.startTarget(ctx.account.id, 'box-one')).rejects.toMatchObject({ status: 402 });
    await ctx.accounts.markStopped('box-one');
    expect(await ctx.accounts.boxQueue('stops')).toEqual([]);
    await ctx.accounts.setPlan(ctx.account.id, 'paid');
    expect(await ctx.accounts.boxAccess('box-one')).toBe('allowed');
    expect((await ctx.accounts.overview(ctx.account.id)).boxes).toEqual([{ name: 'box-one', state: 'stopped' }]);
    await ctx.accounts.startTarget(ctx.account.id, 'box-one');
    await ctx.accounts.markStarted('box-one');
    expect((await ctx.accounts.overview(ctx.account.id)).boxes).toEqual([{ name: 'box-one', state: 'active' }]);
    expect(await ctx.storage.get('box-owners/box-one')).toMatchObject({ accountId: ctx.account.id, state: 'active' });
  });
  test('a plan that comes back before the stop is sent drops the queued stop', async () => {
    const ctx = await withBox();
    await ctx.accounts.setPlan(ctx.account.id, 'free');
    await ctx.accounts.setPlan(ctx.account.id, 'paid');
    expect(await ctx.accounts.boxQueue('stops')).toEqual([]);
    await ctx.storage.put('box-stops/box-one', { v: 1 });
    expect(await ctx.accounts.stopDue('box-one')).toBe(false);
    expect(await ctx.accounts.boxQueue('stops')).toEqual([]);
    expect((await ctx.accounts.overview(ctx.account.id)).boxes).toEqual([{ name: 'box-one', state: 'active' }]);
  });
  test('only the owner\'s active box can be started', async () => {
    const ctx = await withBox();
    const other = await signup(ctx);
    await ctx.accounts.setPlan(other.account.id, 'paid');
    await expect(ctx.accounts.startTarget(other.account.id, 'box-one')).rejects.toMatchObject({ status: 403 });
    await expect(ctx.accounts.startTarget(ctx.account.id, 'missing-box')).rejects.toMatchObject({ status: 403 });
    await ctx.accounts.reserveBox(other.account.id, 'box-two');
    await expect(ctx.accounts.startTarget(other.account.id, 'box-two')).rejects.toMatchObject({ status: 403 });
  });
  test('access decisions are cached for boxAccessCacheMs; this process\'s own writes drop them at once', async () => {
    const ctx = await withBox(30_000);
    expect(await ctx.accounts.boxAccess('box-one')).toBe('allowed');
    // Another instance (a rollout) changes the plan behind this one's back.
    await ctx.storage.put(`accounts/${ctx.account.id}`, { ...await ctx.storage.get<object>(`accounts/${ctx.account.id}`), plan: 'free' });
    expect(await ctx.accounts.boxAccess('box-one')).toBe('allowed');
    ctx.advance(30_000);
    expect(await ctx.accounts.boxAccess('box-one')).toBe('suspended');
    await ctx.accounts.setPlan(ctx.account.id, 'paid');
    expect(await ctx.accounts.boxAccess('box-one')).toBe('allowed');
    expect(await ctx.accounts.boxAccess('Not a box!')).toBe('none');
    expect(await ctx.accounts.boxAccess('unknown-box')).toBe('none');
  });
});

describe('web page sign-in and overview', () => {
  test('registration uses the user handle the challenge announced as the account id', async () => {
    const ctx = setup(); const auth = authenticator();
    const challenge = ctx.accounts.registrationChallenge();
    expect(challenge.userId).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const result = await ctx.accounts.register({ challengeId: challenge.id, ...auth.registration(challenge.challenge) });
    expect(result.account.id).toMatch(/^[a-f0-9]{64}$/);
    expect(Buffer.from(challenge.userId, 'base64url').toString('hex')).toBe(result.account.id);
  });
  test('a discoverable passkey signs in without an account id; the credential names the account', async () => {
    const ctx = await signup(); await signup(ctx);
    const challenge = await ctx.accounts.assertionChallenge(undefined, '203.0.113.9');
    expect(challenge).not.toHaveProperty('credentialId');
    const signed = await ctx.accounts.signIn({ challengeId: challenge.id, credentialId: ctx.auth.id, ...ctx.auth.assertion(challenge.challenge) });
    expect(signed.account.id).toBe(ctx.account.id);
    expect((await ctx.accounts.authenticate(signed.cookie))?.accountId).toBe(ctx.account.id);
  });
  test('a discoverable sign-in refuses an unknown credential, a wrong key and a challenge bound to another mode', async () => {
    const ctx = await signup(); const stranger = authenticator();
    let challenge = await ctx.accounts.assertionChallenge(undefined);
    await expect(ctx.accounts.signIn({ challengeId: challenge.id, credentialId: stranger.id, ...stranger.assertion(challenge.challenge) })).rejects.toThrow('Account request could not be verified.');
    challenge = await ctx.accounts.assertionChallenge(undefined);
    await expect(ctx.accounts.signIn({ challengeId: challenge.id, credentialId: ctx.auth.id, ...stranger.assertion(challenge.challenge) })).rejects.toThrow();
    // A discoverable challenge cannot finish an account-bound sign-in, and the reverse.
    challenge = await ctx.accounts.assertionChallenge(undefined);
    await expect(ctx.accounts.signIn({ accountId: ctx.account.id, challengeId: challenge.id, credentialId: ctx.auth.id, ...ctx.auth.assertion(challenge.challenge, 2) })).rejects.toThrow();
    const bound = await ctx.accounts.assertionChallenge(ctx.account.id);
    await expect(ctx.accounts.signIn({ challengeId: bound.id, credentialId: ctx.auth.id, ...ctx.auth.assertion(bound.challenge, 3) })).rejects.toThrow();
    expect(await ctx.storage.list('sessions/')).toHaveLength(1);
  });
  test('the overview shows the plan, the quota and the boxes with their state, and nothing about billing', async () => {
    const ctx = await signup();
    expect(await ctx.accounts.overview(ctx.account.id)).toEqual({ accountId: ctx.account.id, plan: 'free', boxes: [], boxQuota: 1 });
    await ctx.accounts.setPlan(ctx.account.id, 'paid', { customerId: 'cus_one', subscriptionId: 'sub_one' });
    await ctx.accounts.reserveBox(ctx.account.id, 'box-one');
    const overview = await ctx.accounts.overview(ctx.account.id);
    expect(overview).toEqual({ accountId: ctx.account.id, plan: 'paid', boxes: [{ name: 'box-one', state: 'pending' }], boxQuota: 1 });
    expect(JSON.stringify(overview)).not.toMatch(/cus_|sub_/);
    await ctx.accounts.confirmBox(ctx.account.id, 'box-one');
    expect((await ctx.accounts.overview(ctx.account.id)).boxes).toEqual([{ name: 'box-one', state: 'active' }]);
    await expect(ctx.accounts.overview('missing-account')).rejects.toThrow('Account request could not be verified.');
  });
});
