// @vitest-environment happy-dom
import { afterEach, expect, it, vi } from 'vitest';
import { startEnrollment } from '../../../src/dashboard/client/enroll.js';

// An admin-signed invitation: base64url payload, a dot, and the 86-character signature (review H3).
const token = `${'T'.repeat(120)}.${'S'.repeat(86)}`;
const reply = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const tick = async () => { for (let i = 0; i < 10; i++) await new Promise(resolve => setTimeout(resolve, 0)); };
const options = { member: { id: 'ben', name: 'Ben' }, publicKey: { rp: { id: 'keysentry.example.test', name: 'keysentry' }, user: { id: 'dXNlcg', name: 'ben', displayName: 'Ben' },
  challenge: 'Y2hhbGxlbmdl', pubKeyCredParams: [{ type: 'public-key', alg: -7 }], timeout: 120000, attestation: 'none',
  authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' }, excludeCredentials: [] } };

function page() {
  document.body.innerHTML = '<button id="enroll-start" type="button" disabled>Create passkey</button><p id="enroll-status"></p>';
  return { button: document.getElementById('enroll-start') as HTMLButtonElement, status: document.getElementById('enroll-status')! };
}
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); document.body.replaceChildren(); history.replaceState(null, '', '/'); });

it('takes the token from the fragment, removes it from the address bar, and posts the attestation', async () => {
  history.replaceState(null, '', `/enroll#${token}`);
  const fetcher = vi.fn().mockImplementation(async (path: string) => reply(path === '/enroll/options' ? options : { enrolled: true, credentialId: 'Y3JlZA', fingerprint: '0123-4567-89ab-cdef-0123-4567-89ab-cdef' }));
  vi.stubGlobal('fetch', fetcher);
  const create = vi.fn().mockResolvedValue({ response: { clientDataJSON: new TextEncoder().encode('client').buffer, attestationObject: new TextEncoder().encode('attest').buffer } });
  Object.defineProperty(navigator, 'credentials', { value: { create }, configurable: true });
  const { button, status } = page();
  await startEnrollment();
  expect(location.hash).toBe('');
  expect(location.pathname).toBe('/enroll');
  expect(status.textContent).toContain('This link adds a passkey for Ben.');
  expect(button.disabled).toBe(false);
  button.click(); await tick();
  expect(create).toHaveBeenCalledWith({ publicKey: expect.objectContaining({ rp: { id: 'keysentry.example.test', name: 'keysentry' }, attestation: 'none' }) });
  const finish = fetcher.mock.calls.find(([path]) => path === '/enroll/finish')!;
  expect(JSON.parse(finish[1].body)).toEqual({ token, clientDataJSON: 'Y2xpZW50', attestationObject: 'YXR0ZXN0' });
  expect(status.textContent).toBe('Passkey created. It works after a team admin adds it to the roster. Give them this credential id: Y3JlZA (fingerprint 0123-4567-89ab-cdef-0123-4567-89ab-cdef)');
  expect(button.disabled).toBe(true);
});

it('shows the server refusal for a used or expired link, and nothing without a token', async () => {
  history.replaceState(null, '', `/enroll#${token}`);
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(reply({ error: 'This enrollment link has expired. Ask a team admin for a new one (keysentry team invite).' }, 410)));
  const first = page();
  await startEnrollment();
  expect(first.status.textContent).toBe('This enrollment link has expired. Ask a team admin for a new one (keysentry team invite).');
  expect(first.button.disabled).toBe(true);
  history.replaceState(null, '', '/enroll');
  const second = page();
  await startEnrollment();
  expect(second.status.textContent).toBe('This enrollment link is not complete. Open the full link a team admin sent you.');
  // The old 43-character random token is not an invitation any more.
  history.replaceState(null, '', `/enroll#${'T'.repeat(43)}`);
  const third = page();
  await startEnrollment();
  expect(third.status.textContent).toBe('This enrollment link is not complete. Open the full link a team admin sent you.');
});
