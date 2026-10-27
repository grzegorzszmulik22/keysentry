import { describe, expect, it } from 'vitest';
import type { PasskeyCredential } from '../../../src/types.js';
import { createPasskeyGate, type PasskeyStore } from '../../../src/dashboard/server/passkey-gate.js';
import { createFakeAuthenticator } from '../helpers/fake-authenticator.js';

const origin = 'http://localhost:43210';
const digest = 'a'.repeat(64);
function setup(initial: PasskeyCredential[] = []) {
  let now = 1000;
  const credentials = initial.map(c => structuredClone(c));
  const store: PasskeyStore = {
    async list() { return structuredClone(credentials); },
    async add(c) { credentials.push(structuredClone(c)); },
    async update(c) { credentials.splice(credentials.findIndex(item => item.id === c.id), 1, structuredClone(c)); },
  };
  const gate = createPasskeyGate({ passkeys: store, origin, now: () => now });
  return { gate, credentials, store, advance: (ms: number) => { now += ms; } };
}

describe('dashboard passkey gate', () => {
  it('exposes no registration ceremony and directs an empty store to the terminal', async () => {
    const { gate, credentials } = setup();
    expect(gate).not.toHaveProperty('registrationOptions');
    expect(gate).not.toHaveProperty('registrationFinish');
    const expected = { status: 403, message: 'Register a passkey with keysentry passkey register in your terminal, then reload this page.' };
    await expect(gate.challenge('session', 'rotate', digest)).rejects.toMatchObject(expected);
    await expect(gate.verify('session', 'rotate', digest, undefined)).rejects.toMatchObject(expected);
    expect(credentials).toHaveLength(0);
  });

  it('verifies a real P-256 assertion and persists its counter', async () => {
    const auth = createFakeAuthenticator();
    const { gate, credentials } = setup([auth.credential()]);
    const options = await gate.challenge('session', 'rotate', digest);
    expect(options).toMatchObject({ rpId: 'localhost', userVerification: 'required', allowCredentials: [{ id: auth.id, type: 'public-key' }] });
    await gate.verify('session', 'rotate', digest, auth.assertionHeader(options.challenge, origin));
    expect(credentials[0]?.signCount).toBe(1);
  });

  it.each(['session', 'route', 'digest'])('binds assertions to the exact %s', async field => {
    const auth = createFakeAuthenticator();
    const { gate } = setup([auth.credential()]);
    const options = await gate.challenge('session', 'rotate', digest);
    await expect(gate.verify(field === 'session' ? 'other' : 'session', field === 'route' ? 'other' : 'rotate',
      field === 'digest' ? 'b'.repeat(64) : digest, auth.assertionHeader(options.challenge, origin))).rejects.toMatchObject({ status: 403 });
  });

  it('refuses a missing proof and consumes a successful proof once, including concurrent calls', async () => {
    const auth = createFakeAuthenticator();
    const { gate } = setup([auth.credential()]);
    await expect(gate.verify('session', 'rotate', digest, undefined)).rejects.toMatchObject({ status: 403 });
    const options = await gate.challenge('session', 'rotate', digest);
    const header = auth.assertionHeader(options.challenge, origin);
    const results = await Promise.allSettled([gate.verify('session', 'rotate', digest, header), gate.verify('session', 'rotate', digest, header)]);
    expect(results.map(r => r.status).sort()).toEqual(['fulfilled', 'rejected']);
  });

  it('expires assertions exactly at two minutes', async () => {
    const auth = createFakeAuthenticator();
    const { gate, advance } = setup([auth.credential()]);
    const options = await gate.challenge('session', 'rotate', digest);
    advance(120_000);
    await expect(gate.verify('session', 'rotate', digest, auth.assertionHeader(options.challenge, origin))).rejects.toMatchObject({ status: 403 });
  });

  it('rechecks assertion expiry after slow credential storage', async () => {
    const auth = createFakeAuthenticator();
    const state = setup([auth.credential()]);
    const options = await state.gate.challenge('session', 'rotate', digest);
    const list = state.store.list;
    state.store.list = async () => { state.advance(120_000); return list(); };
    await expect(state.gate.verify('session', 'rotate', digest, auth.assertionHeader(options.challenge, origin))).rejects.toMatchObject({ status: 403 });
    expect(state.credentials[0]?.signCount).toBe(0);
  });

  it('consumes a submitted proof even if credential storage fails', async () => {
    const auth = createFakeAuthenticator();
    const state = setup([auth.credential()]);
    const options = await state.gate.challenge('session', 'rotate', digest);
    const header = auth.assertionHeader(options.challenge, origin);
    const list = state.store.list;
    state.store.list = async () => { throw new Error('Storage is unavailable.'); };
    await expect(state.gate.verify('session', 'rotate', digest, header)).rejects.toThrow('Storage is unavailable.');
    state.store.list = list;
    await expect(state.gate.verify('session', 'rotate', digest, header)).rejects.toMatchObject({ status: 403 });
    expect(state.credentials[0]?.signCount).toBe(0);
  });

  it.each(['uv', 'origin', 'signature', 'counter'])('refuses an invalid %s and never updates a counter', async field => {
    const auth = createFakeAuthenticator();
    const { gate, credentials } = setup([auth.credential()]);
    const options = await gate.challenge('session', 'rotate', digest);
    const wire = auth.assertion(options.challenge, field === 'origin' ? 'http://localhost:1' : origin,
      { uv: field !== 'uv', signCount: field === 'counter' ? 0 : 1 });
    if (field === 'signature') wire.response.signature = Buffer.alloc(64, 1).toString('base64url');
    if (field === 'counter') credentials[0]!.signCount = 1;
    await expect(gate.verify('session', 'rotate', digest, Buffer.from(JSON.stringify(wire)).toString('base64url'))).rejects.toMatchObject({ status: 403 });
    expect(credentials[0]?.signCount).toBe(field === 'counter' ? 1 : 0);
  });

  it('rejects unknown credentials and malformed base64url without echoing the input', async () => {
    const auth = createFakeAuthenticator();
    const other = createFakeAuthenticator();
    const { gate } = setup([auth.credential()]);
    const options = await gate.challenge('session', 'rotate', digest);
    await expect(gate.verify('session', 'rotate', digest, other.assertionHeader(options.challenge, origin))).rejects.toMatchObject({ status: 403 });
    await expect(gate.verify('session', 'rotate', digest, 'planted-private-value!')).rejects.toThrow(/^Use a fresh passkey to continue\.$/);
  });

  it('does not widen a non-localhost registered origin or RP', async () => {
    const auth = createFakeAuthenticator();
    const credential = auth.credential(['https://example.org']);
    const { gate } = setup([credential]);
    await expect(gate.challenge('session', 'rotate', digest)).rejects.toMatchObject({ status: 403 });
    const other = setup([{ ...auth.credential(), rpId: 'example.org' }]);
    await expect(other.gate.challenge('session', 'rotate', digest)).rejects.toMatchObject({ status: 403 });
  });

  it('bounds pending challenges and prunes expired entries', async () => {
    const auth = createFakeAuthenticator();
    const state = setup([auth.credential()]);
    for (let i = 0; i < 100; i++) await state.gate.challenge('session', 'rotate', digest);
    await expect(state.gate.challenge('session', 'rotate', digest)).rejects.toMatchObject({ status: 429 });
    state.advance(120_000);
    await expect(state.gate.challenge('session', 'rotate', digest)).resolves.toHaveProperty('challenge');
  });

  it('rejects invalid action descriptions and invalid configured origins', async () => {
    const { gate, store } = setup();
    await expect(gate.challenge('session', 'rotate', 'not-a-digest')).rejects.toMatchObject({ status: 400 });
    await expect(gate.challenge('session', '/api/rotate', digest)).rejects.toMatchObject({ status: 400 });
    expect(() => createPasskeyGate({ passkeys: store, origin: 'https://elsewhere.example' })).toThrow('Dashboard origin must be http://localhost with a port.');
  });
});
