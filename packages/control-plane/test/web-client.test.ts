// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { UI_ASSETS } from '../src/ui-assets.js';

// The package typecheck has no DOM library (Node code); happy-dom provides these at run time.
interface PageNode {
  hidden: boolean; textContent: string | null; value: string; disabled: boolean; id: string;
  click(): void; getAttribute(name: string): string | null; hasAttribute(name: string): boolean; querySelectorAll(selector: string): Iterable<PageNode>;
}
declare const document: {
  getElementById(id: string): PageNode; body: { innerHTML: string; replaceChildren(): void }; activeElement: unknown; querySelector(selector: string): unknown;
};
declare const window: { history: { replaceState(data: null, unused: string, url: string): void }; location: { search: string; assign(url: string): void }; navigator: object };

interface Sent { method: string; path: string; headers: Record<string, string>; body: unknown }
type Reply = { status: number; body: unknown };
const DEVICE_KEY = 'MCowBQYDK2VwAyEA' + 'A'.repeat(43) + '=';
const CSRF = 'C'.repeat(43);
const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const buffer = (text: string) => { const bytes = new TextEncoder().encode(text); return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength); };

let sent: Sent[];
let routes: Map<string, Reply | ((body: unknown) => Reply)>;
let credentials: { create: ReturnType<typeof vi.fn>; get: ReturnType<typeof vi.fn> };
let assign: ReturnType<typeof vi.fn>;

function route(method: string, path: string, reply: Reply | ((body: unknown) => Reply)) { routes.set(`${method} ${path}`, reply); }
function account(plan: 'free' | 'paid', boxes: { name: string; state: string }[] = [], boxQuota = 1) {
  route('GET', '/session', { status: 200, body: { accountId: 'acct', csrf: CSRF } });
  route('GET', '/account', { status: 200, body: { accountId: 'acct', plan, boxes, boxQuota } });
}
function el(id: string): PageNode { return document.getElementById(id); }
function status(): string { return el('status').textContent ?? ''; }
async function boot(path = '/') {
  window.history.replaceState(null, '', path);
  const html = UI_ASSETS['/']!.body;
  document.body.innerHTML = html.slice(html.indexOf('<body>') + 6, html.indexOf('</body>'));
  new Function(UI_ASSETS['/app/app.js']!.body)();
  await vi.waitFor(() => expect(el('sign-in').disabled).toBe(false));
}
async function click(id: string) {
  el(id).click();
  await vi.waitFor(() => expect(el('sign-in').disabled).toBe(false));
}

beforeEach(() => {
  sent = []; routes = new Map();
  vi.stubGlobal('fetch', vi.fn(async (path: string, init: RequestInit = {}) => {
    const headers = Object.fromEntries(Object.entries((init.headers ?? {}) as Record<string, string>).map(([key, value]) => [key.toLowerCase(), value]));
    const body = typeof init.body === 'string' ? JSON.parse(init.body) as unknown : undefined;
    sent.push({ method: init.method ?? 'GET', path, headers, body });
    expect(init.credentials).toBe('same-origin');
    const handler = routes.get(`${init.method ?? 'GET'} ${path}`);
    const reply = typeof handler === 'function' ? handler(body) : handler ?? { status: 404, body: { error: 'Not found.' } };
    return new Response(JSON.stringify(reply.body), { status: reply.status, headers: { 'content-type': 'application/json' } });
  }));
  credentials = { create: vi.fn(), get: vi.fn() };
  Object.defineProperty(window.navigator, 'credentials', { configurable: true, value: credentials });
  vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {});
  assign = vi.fn();
  vi.spyOn(window.location, 'assign').mockImplementation(assign as never);
});
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); document.body.replaceChildren(); });

describe('cloud box account page', () => {
  it('shows the passkey choices when nobody is signed in', async () => {
    route('GET', '/session', { status: 401, body: { error: 'Sign in to continue.' } });
    await boot();
    expect(el('view-signed-out').hidden).toBe(false);
    expect(el('view-signed-in').hidden).toBe(true);
    expect(el('sign-out').hidden).toBe(true);
    expect(sent.map(item => `${item.method} ${item.path}`)).toEqual(['GET /session']);
  });

  it('creates an account with a discoverable passkey that requires user verification', async () => {
    route('GET', '/session', { status: 401, body: {} });
    const userId = b64url(new Uint8Array(32).fill(7));
    route('POST', '/auth/register/challenge', { status: 200, body: { id: 'ceremony', challenge: b64url(new Uint8Array([1, 2, 3])), rpId: 'control.example', userId } });
    route('POST', '/auth/register/finish', () => { account('free'); return { status: 200, body: { account: { id: userId }, csrf: CSRF } }; });
    credentials.create.mockResolvedValue({ id: 'cred', response: { clientDataJSON: buffer('client-data'), attestationObject: buffer('attestation') } });
    await boot();
    await click('sign-up');
    const options = credentials.create.mock.calls[0]![0].publicKey;
    expect(options.rp).toEqual({ id: 'control.example', name: 'keysentry' });
    expect(Array.from(options.user.id as Uint8Array)).toEqual(Array(32).fill(7));
    expect(Array.from(options.challenge as Uint8Array)).toEqual([1, 2, 3]);
    expect(options.authenticatorSelection).toEqual({ residentKey: 'required', requireResidentKey: true, userVerification: 'required' });
    expect(options.attestation).toBe('none');
    expect(options.pubKeyCredParams.map((param: { alg: number }) => param.alg)).toEqual([-8, -7, -257]);
    expect(sent.find(item => item.path === '/auth/register/finish')!.body).toEqual({
      challengeId: 'ceremony', clientDataJSON: Buffer.from('client-data').toString('base64url'), attestationObject: Buffer.from('attestation').toString('base64url'),
    });
    expect(el('view-signed-in').hidden).toBe(false);
    expect(el('plan-text').textContent).toBe('Free. Creating a box needs the paid plan.');
    expect(el('checkout').hidden).toBe(false);
    expect(el('create-panel').hidden).toBe(true);
    expect(status()).toBe('Account created. You are signed in.');
    expect(document.activeElement).toBe(el('account-title'));
  });

  it('signs in without naming an account and says so calmly when the passkey prompt is dismissed', async () => {
    route('GET', '/session', { status: 401, body: {} });
    route('POST', '/auth/login/challenge', { status: 200, body: { id: 'ceremony', challenge: b64url(new Uint8Array([9])), rpId: 'control.example' } });
    credentials.get.mockRejectedValueOnce(new DOMException('planted detail', 'NotAllowedError'));
    await boot();
    await click('sign-in');
    expect(status()).toBe('You were not signed in. You can try again.');
    expect(status()).not.toContain('planted');
    credentials.get.mockResolvedValue({ id: 'cred-id', response: { clientDataJSON: buffer('c'), authenticatorData: buffer('a'), signature: buffer('s') } });
    route('POST', '/auth/login/finish', () => { account('paid'); return { status: 200, body: { account: { id: 'acct' }, csrf: CSRF } }; });
    await click('sign-in');
    const options = credentials.get.mock.calls[1]![0].publicKey;
    expect(options.allowCredentials).toBeUndefined();
    expect(options.userVerification).toBe('required');
    expect(options.rpId).toBe('control.example');
    expect(sent.filter(item => item.path === '/auth/login/challenge').map(item => item.body)).toEqual([{}, {}]);
    expect(sent.find(item => item.path === '/auth/login/finish')!.body).toEqual({ challengeId: 'ceremony', credentialId: 'cred-id',
      clientDataJSON: Buffer.from('c').toString('base64url'), authenticatorData: Buffer.from('a').toString('base64url'), signature: Buffer.from('s').toString('base64url') });
    expect(status()).toBe('Signed in.');
    expect(el('view-signed-in').hidden).toBe(false);
  });

  it('tells the user when the browser has no passkey support', async () => {
    route('GET', '/session', { status: 401, body: {} });
    vi.stubGlobal('PublicKeyCredential', undefined);
    await boot();
    await click('sign-up');
    expect(status()).toMatch(/^This browser cannot use passkeys\./);
    expect(sent.map(item => item.path)).toEqual(['/session']);
  });

  it('starts Stripe Checkout with the CSRF token and goes only to checkout.stripe.com', async () => {
    account('free');
    route('POST', '/billing/checkout', { status: 200, body: { url: 'https://checkout.stripe.com/c/pay/cs_test_1' } });
    await boot();
    await click('checkout');
    const request = sent.find(item => item.path === '/billing/checkout')!;
    expect(request.headers['x-csrf-token']).toBe(CSRF);
    expect(request.body).toEqual({});
    expect(assign).toHaveBeenCalledWith('https://checkout.stripe.com/c/pay/cs_test_1');

    route('POST', '/billing/checkout', { status: 200, body: { url: 'https://evil.example/pay' } });
    await click('checkout');
    expect(assign).toHaveBeenCalledTimes(1);
    expect(status()).toBe('Checkout could not be started. Try again in a minute.');
    route('POST', '/billing/checkout', { status: 503, body: { error: 'Billing is temporarily unavailable.' } });
    await click('checkout');
    expect(status()).toBe('Billing is temporarily unavailable.');
  });

  it('explains the result of a returning checkout and cleans the address', async () => {
    account('free');
    await boot('/?checkout=done');
    expect(status()).toMatch(/^Thank you\. Your plan changes to paid as soon as Stripe confirms the payment/);
    expect(window.location.search).toBe('');
    await boot('/?checkout=cancelled');
    expect(status()).toBe('Checkout was cancelled. Nothing was charged.');
  });

  it('creates a box from a name and the pasted device key, checking both first', async () => {
    account('paid');
    await boot();
    expect(el('create-panel').hidden).toBe(false);
    expect(el('plan-text').textContent).toBe('Paid. This account can run up to 1 box.');
    const name = el('box-name'), key = el('device-key');

    name.value = 'Bad Name';
    await click('create');
    expect(el('create-error').textContent).toMatch(/^Use lowercase letters/);
    expect(name.getAttribute('aria-invalid')).toBe('true');
    expect(name.getAttribute('aria-describedby')).toBe('box-name-help create-error');
    expect(document.activeElement).toBe(name);

    name.value = 'web-box'; key.value = 'not a key';
    await click('create');
    expect(el('create-error').textContent).toMatch(/^This is not a device public key/);
    expect(key.getAttribute('aria-invalid')).toBe('true');
    expect(name.hasAttribute('aria-invalid')).toBe(false);
    expect(sent.some(item => item.path === '/boxes')).toBe(false);

    route('POST', '/boxes', () => { account('paid', [{ name: 'web-box', state: 'active' }]); return { status: 201, body: { boxId: 'web-box' } }; });
    key.value = `  ${DEVICE_KEY.slice(0, 30)}\n${DEVICE_KEY.slice(30)}  `;
    await click('create');
    const request = sent.find(item => item.path === '/boxes')!;
    expect(request.body).toEqual({ name: 'web-box', deviceKey: DEVICE_KEY });
    expect(request.headers['x-csrf-token']).toBe(CSRF);
    expect(status()).toBe('Box web-box is being created.');
    expect([...el('boxes-list').querySelectorAll('li')].map(item => item.textContent)).toEqual(['web-boxCreated']);
    expect(el('create-panel').hidden).toBe(true);
    expect(el('create-unavailable').textContent).toBe('This account has reached its limit of 1 box.');
  });

  it('shows the server\'s fixed refusal next to the field it concerns', async () => {
    account('paid', [], 2);
    route('POST', '/boxes', { status: 409, body: { error: 'That box name is taken.' } });
    await boot();
    el('box-name').value = 'taken-box';
    el('device-key').value = DEVICE_KEY;
    await click('create');
    expect(el('create-error').textContent).toBe('That box name is taken.');
    expect(el('box-name').getAttribute('aria-invalid')).toBe('true');
  });

  it('renders server values as text, never as markup', async () => {
    route('GET', '/session', { status: 200, body: { accountId: 'acct', csrf: CSRF } });
    route('GET', '/account', { status: 200, body: { accountId: 'acct', plan: 'paid', boxQuota: 3,
      boxes: [{ name: '<img src=x onerror=alert(1)>', state: 'active' }, { name: 'ok-box', state: 'pending' }] } });
    route('POST', '/boxes', { status: 400, body: { error: '<img src=x onerror=alert(1)>' } });
    await boot();
    expect([...el('boxes-list').querySelectorAll('li')].map(item => item.textContent)).toEqual([
      'ok-boxBeing createdkeysentry is creating this box or checking whether it was created. Reload this page in a few minutes.']);
    el('box-name').value = 'new-box';
    el('device-key').value = DEVICE_KEY;
    await click('create');
    expect(el('create-error').textContent).toBe('<img src=x onerror=alert(1)>');
    expect(document.querySelector('img')).toBeNull();
  });

  it('says a box is being checked when Compute gave no definite answer (202)', async () => {
    account('paid');
    route('POST', '/boxes', () => { account('paid', [{ name: 'web-box', state: 'pending' }]); return { status: 202, body: { boxId: 'web-box', state: 'pending' } }; });
    await boot();
    el('box-name').value = 'web-box';
    el('device-key').value = DEVICE_KEY;
    await click('create');
    expect(status()).toBe('Box web-box is being checked. Its state shows here within a few minutes.');
    expect(el('create-error').hidden).toBe(true);
    expect([...el('boxes-list').querySelectorAll('.box-state')].map(item => item.textContent)).toEqual(['Being created']);
  });

  it('says plainly that a box is suspended when the plan ended, and offers no start until the plan is paid', async () => {
    account('free', [{ name: 'held-box', state: 'suspended' }]);
    await boot();
    const [item] = [...el('boxes-list').querySelectorAll('li')];
    expect([...item!.querySelectorAll('.box-state')].map(node => node.textContent)).toEqual(['Suspended']);
    expect([...item!.querySelectorAll('.box-note')].map(node => node.textContent)).toEqual([
      'The paid plan ended, so this box was stopped and cannot reach keysentry. Nothing on it was deleted. Start the paid plan again, then start the box here.']);
    expect([...item!.querySelectorAll('button')]).toEqual([]);
    expect(el('checkout').hidden).toBe(false);
  });

  it('starts a stopped box with the CSRF token and shows the server\'s refusal as text', async () => {
    account('paid', [{ name: 'held-box', state: 'stopped' }]);
    route('POST', '/boxes/held-box/start', { status: 502, body: { error: 'The box could not be started. Try again in a few minutes.' } });
    await boot();
    const start = () => [...el('boxes-list').querySelectorAll('.box-start')][0]!;
    expect(start().getAttribute('aria-label')).toBe('Start box held-box');
    start().click();
    await vi.waitFor(() => expect(status()).toBe('The box could not be started. Try again in a few minutes.'));
    route('POST', '/boxes/held-box/start', () => { account('paid', [{ name: 'held-box', state: 'active' }]); return { status: 202, body: { boxId: 'held-box', state: 'starting' } }; });
    start().click();
    await vi.waitFor(() => expect(status()).toBe('Box held-box is starting.'));
    const request = sent.filter(item => item.path === '/boxes/held-box/start').at(-1)!;
    expect(request).toMatchObject({ method: 'POST', body: {} });
    expect(request.headers['x-csrf-token']).toBe(CSRF);
    expect([...el('boxes-list').querySelectorAll('.box-state')].map(item => item.textContent)).toEqual(['Created']);
    expect([...el('boxes-list').querySelectorAll('.box-start')]).toEqual([]);
  });

  it('signs out with the CSRF token', async () => {
    account('paid');
    route('DELETE', '/session', { status: 200, body: { ok: true } });
    await boot();
    await click('sign-out');
    expect(sent.find(item => item.method === 'DELETE')!.headers['x-csrf-token']).toBe(CSRF);
    expect(el('view-signed-out').hidden).toBe(false);
    expect(status()).toBe('Signed out.');
  });

  it('says when the server cannot be reached', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('planted network detail'); }));
    await boot();
    expect(status()).toBe('The keysentry server could not be reached. Check your connection and try again.');
  });
});
