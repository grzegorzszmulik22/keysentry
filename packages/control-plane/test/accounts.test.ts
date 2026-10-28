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
    expect(ctx.accounts.authenticate(ctx.cookie)?.accountId).toBe(ctx.account.id);
    expect(ctx.accounts.authenticate(ctx.cookie)?.csrf).toHaveLength(43);
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
    expect(ctx.accounts.authenticate(signed.cookie)?.accountId).toBe(ctx.account.id);
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
    expect(ctx.accounts.authenticate(`${pair}; ${pair}`)).toBeNull();
    ctx.advance(60_000); expect(ctx.accounts.authenticate(pair)).toBeNull();
    const second = await signup(ctx); ctx.accounts.clearSession(second.cookie); expect(ctx.accounts.authenticate(second.cookie)).toBeNull();
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
    expect(() => createAccounts({ storage: memory(), origin: 'http://127.0.0.1:1234' })).not.toThrow();
  });
});
