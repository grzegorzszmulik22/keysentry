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
  it('registers a UV passkey with localhost origins and consumes enrollment once', async () => {
    const auth = createFakeAuthenticator();
    const { gate, credentials } = setup();
    const options = await gate.registrationOptions('session');
    expect(options.rp.id).toBe('localhost');
    expect(options.authenticatorSelection.userVerification).toBe('required');
    const response = auth.registration(options.challenge, origin);
    await gate.registrationFinish('session', response);
    expect(credentials[0]).toMatchObject({ id: auth.id, rpId: 'localhost', origins: [origin, 'http://localhost'] });
    await expect(gate.registrationFinish('session', response)).rejects.toMatchObject({ status: 403 });
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

  it.each(['assertion', 'registration'])('rechecks %s expiry after slow credential storage', async ceremony => {
    const auth = createFakeAuthenticator();
    const state = setup(ceremony === 'assertion' ? [auth.credential()] : []);
    const options = ceremony === 'assertion' ? await state.gate.challenge('session', 'rotate', digest) : await state.gate.registrationOptions('session');
    const list = state.store.list;
    state.store.list = async () => { state.advance(120_000); return list(); };
    const action = ceremony === 'assertion'
      ? state.gate.verify('session', 'rotate', digest, auth.assertionHeader(options.challenge, origin))
      : state.gate.registrationFinish('session', auth.registration(options.challenge, origin));
    await expect(action).rejects.toMatchObject({ status: 403 });
    expect(state.credentials[0]?.signCount ?? 0).toBe(0);
    if (ceremony === 'registration') expect(state.credentials).toHaveLength(0);
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

  it('refuses enrollment without UV, on wrong session, after expiry or changed credential set', async () => {
    const auth = createFakeAuthenticator();
    const state = setup();
    let options = await state.gate.registrationOptions('session');
    await expect(state.gate.registrationFinish('other', auth.registration(options.challenge, origin))).rejects.toMatchObject({ status: 403 });
    options = await state.gate.registrationOptions('session');
    await expect(state.gate.registrationFinish('session', auth.registration(options.challenge, origin, { uv: false }))).rejects.toMatchObject({ status: 403 });
    options = await state.gate.registrationOptions('session');
    state.advance(120_000);
    await expect(state.gate.registrationFinish('session', auth.registration(options.challenge, origin))).rejects.toMatchObject({ status: 403 });
    options = await state.gate.registrationOptions('session');
    state.credentials.push(createFakeAuthenticator().credential());
    await expect(state.gate.registrationFinish('session', auth.registration(options.challenge, origin))).rejects.toMatchObject({ status: 403 });
  });

  it('rejects duplicate enrollment and ID substitution', async () => {
    const auth = createFakeAuthenticator();
    const { gate } = setup([auth.credential()]);
    let proof = await gate.challenge('session', 'passkey/register/options', digest);
    await gate.verify('session', 'passkey/register/options', digest, auth.assertionHeader(proof.challenge, origin));
    let options = await gate.registrationOptions('session');
    await expect(gate.registrationFinish('session', auth.registration(options.challenge, origin))).rejects.toMatchObject({ status: 409 });
    proof = await gate.challenge('session', 'passkey/register/options', digest);
    await gate.verify('session', 'passkey/register/options', digest, auth.assertionHeader(proof.challenge, origin));
    options = await gate.registrationOptions('session');
    const wire = createFakeAuthenticator().registration(options.challenge, origin);
    wire.id = auth.id; wire.rawId = auth.id;
    await expect(gate.registrationFinish('session', wire)).rejects.toMatchObject({ status: 403 });
  });

  it('checks existing-passkey enrollment authorization atomically with issuing options', async () => {
    const auth = createFakeAuthenticator();
    const state = setup();
    // The transport could have observed an empty store before another request added a key.
    state.credentials.push(auth.credential());
    await expect(state.gate.registrationOptions('session')).rejects.toMatchObject({ status: 403 });
    const proof = await state.gate.challenge('session', 'passkey/register/options', digest);
    await state.gate.verify('session', 'passkey/register/options', digest, auth.assertionHeader(proof.challenge, origin));
    await expect(state.gate.registrationOptions('session')).resolves.toHaveProperty('challenge');
    await expect(state.gate.registrationOptions('session')).rejects.toMatchObject({ status: 403 });
  });

  it('does not extend the original proof lifetime when granting enrollment options', async () => {
    const auth = createFakeAuthenticator();
    const state = setup([auth.credential()]);
    const proof = await state.gate.challenge('session', 'passkey/register/options', digest);
    state.advance(119_000);
    await state.gate.verify('session', 'passkey/register/options', digest, auth.assertionHeader(proof.challenge, origin));
    state.advance(1000);
    await expect(state.gate.registrationOptions('session')).rejects.toMatchObject({ status: 403 });
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
