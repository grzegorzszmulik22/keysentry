// @vitest-environment happy-dom
import { webcrypto } from 'node:crypto';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { configureSession, postWithPasskey } from '../../../src/dashboard/client/api.js';

// Decision 5 (notes/integration-phase6.md): the client uses the RP ID the server sends (team mode: the public host).
const b64 = (value: string) => Buffer.from(value).toString('base64url');
const bytes = (value: string) => new TextEncoder().encode(value).buffer;
const assertion = () => ({ id: b64('credential'), rawId: bytes('credential'), type: 'public-key', response: { clientDataJSON: bytes('client'), authenticatorData: bytes('auth'), signature: bytes('signature'), userHandle: null } });
const reply = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });

beforeEach(() => { configureSession({ csrf: 'session-csrf', readOnly: false, passkeys: 1 }); vi.stubGlobal('crypto', webcrypto); });
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

async function rpIdFor(challenge: Record<string, unknown>): Promise<string | undefined> {
  let rpId: string | undefined;
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: vi.fn(async (options: { publicKey: { rpId?: string } }) => { rpId = options.publicKey.rpId; return assertion(); }) } });
  vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(reply({ challenge: b64('challenge'), allowCredentials: [], ...challenge })).mockResolvedValueOnce(reply({ ok: true })));
  await postWithPasskey('rotate', {});
  return rpId;
}

it('uses the team host the server names as the WebAuthn RP ID', async () => {
  expect(await rpIdFor({ rpId: 'keysentry.example.com' })).toBe('keysentry.example.com');
});

it('keeps localhost for the local dashboard and for a missing or malformed RP ID', async () => {
  expect(await rpIdFor({ rpId: 'localhost' })).toBe('localhost');
  expect(await rpIdFor({})).toBe('localhost');
  expect(await rpIdFor({ rpId: 'evil.example/path' })).toBe('localhost');
  expect(await rpIdFor({ rpId: 42 })).toBe('localhost');
});

it('a team change still waiting for approvals (202) is reported as recorded, not as done or failed (review C1)', async () => {
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: vi.fn(async () => assertion()) } });
  const text = 'Your approval was recorded: 1 of 2 team approvals so far. It runs when the last of them approves it on the Approvals screen.';
  vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(reply({ challenge: b64('challenge'), allowCredentials: [], rpId: 'keysentry.example.com' }))
    .mockResolvedValueOnce(new Response(JSON.stringify({ teamRequest: 'recorded', id: 'team-1', approvals: 1, required: 2, text }), { status: 202, headers: { 'Content-Type': 'application/json' } })));
  const pending = postWithPasskey('rotate/execute', { planId: 'p', planHash: 'h' });
  await expect(pending).rejects.toMatchObject({ name: 'TeamRequestRecorded', message: text, approvals: 1, required: 2 });
  // A plain 200 is the change itself.
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: vi.fn(async () => assertion()) } });
  vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(reply({ challenge: b64('challenge'), allowCredentials: [] })).mockResolvedValueOnce(reply({ teamRequest: 'recorded' })));
  await expect(postWithPasskey('rotate/execute', {})).resolves.toEqual({ teamRequest: 'recorded' });
});
