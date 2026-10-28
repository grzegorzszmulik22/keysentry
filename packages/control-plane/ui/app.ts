// keysentry cloud box account page. Served as /app/app.js under a strict CSP (script-src 'self', Trusted Types):
// no inline script, no HTML strings, only textContent and DOM nodes. Every request goes to this origin.
'use strict';

interface ApiResult { status: number; data: Record<string, unknown> }
type BoxState = 'pending' | 'active' | 'suspended' | 'stopped';
interface BoxView { name: string; state: BoxState }
const BOX_STATES: readonly string[] = ['pending', 'active', 'suspended', 'stopped'];
const STATE_TEXT: Record<BoxState, string> = { pending: 'Being created', active: 'Created', suspended: 'Suspended', stopped: 'Stopped' };
const STATE_NOTE: Partial<Record<BoxState, string>> = {
  pending: 'keysentry is creating this box or checking whether it was created. Reload this page in a few minutes.',
  suspended: 'The paid plan ended, so this box was stopped and cannot reach keysentry. Nothing on it was deleted. Start the paid plan again, then start the box here.',
  stopped: 'This box was stopped when the paid plan ended. Start it to run the watcher again.',
};
type View = 'loading' | 'signed-out' | 'signed-in';

const BOX_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
// Ed25519 public key in SubjectPublicKeyInfo DER, base64: what `keysentry box card` prints.
const DEVICE_KEY = /^MCowBQYDK2VwAyEA[A-Za-z0-9+/]{43}=$/;
const OFFLINE = 'The keysentry server could not be reached. Check your connection and try again.';

let csrf = '';
let busy = false;

function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`The page is missing #${id}.`);
  return element as T;
}

function announce(text: string): void {
  byId('status').textContent = text;
}

function show(view: View, focus = false): void {
  byId('view-loading').hidden = view !== 'loading';
  byId('view-signed-out').hidden = view !== 'signed-out';
  byId('view-signed-in').hidden = view !== 'signed-in';
  byId('sign-out').hidden = view !== 'signed-in';
  if (focus) byId(view === 'signed-in' ? 'account-title' : view === 'signed-out' ? 'signed-out-title' : 'loading-title').focus();
}

function setBusy(value: boolean): void {
  busy = value;
  for (const id of ['sign-up', 'sign-in', 'checkout', 'create', 'sign-out']) (byId<HTMLButtonElement>(id)).disabled = value;
  for (const button of document.querySelectorAll<HTMLButtonElement>('.box-start')) button.disabled = value;
  byId('main').setAttribute('aria-busy', value ? 'true' : 'false');
}

async function api(path: string, method: 'GET' | 'POST' | 'DELETE' = 'GET', body?: unknown, withCsrf = false): Promise<ApiResult> {
  const headers: Record<string, string> = { accept: 'application/json' };
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (withCsrf) headers['x-csrf-token'] = csrf;
  let response: Response;
  try {
    response = await fetch(path, {
      method, headers, credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  } catch {
    return { status: 0, data: {} };
  }
  let data: Record<string, unknown> = {};
  try {
    const parsed: unknown = await response.json();
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) data = parsed as Record<string, unknown>;
  } catch {
    data = {};
  }
  return { status: response.status, data };
}

/** The server's fixed error text, or a plain fallback. Server errors never carry upstream detail. */
function failure(result: ApiResult, fallback: string): string {
  if (result.status === 0) return OFFLINE;
  return typeof result.data.error === 'string' && result.data.error.length <= 200 ? result.data.error : fallback;
}

function text(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 && value.length <= 4096 ? value : null;
}

function fromBase64url(value: string): Uint8Array<ArrayBuffer> {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function toBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function passkeysAvailable(): boolean {
  return typeof window.PublicKeyCredential === 'function' && typeof navigator.credentials?.create === 'function';
}

async function signUp(): Promise<void> {
  if (!passkeysAvailable()) { announce('This browser cannot use passkeys. Try a current version of Chrome, Edge, Firefox or Safari.'); return; }
  const start = await api('/auth/register/challenge', 'POST', {});
  const challengeId = text(start.data.id), challenge = text(start.data.challenge), rpId = text(start.data.rpId), userId = text(start.data.userId);
  if (start.status !== 200 || !challengeId || !challenge || !rpId || !userId) { announce(failure(start, 'Sign-up could not start. Try again.')); return; }
  let credential: Credential | null;
  try {
    credential = await navigator.credentials.create({ publicKey: {
      rp: { id: rpId, name: 'keysentry' },
      user: { id: fromBase64url(userId), name: 'keysentry cloud box', displayName: 'keysentry cloud box' },
      challenge: fromBase64url(challenge),
      pubKeyCredParams: [{ type: 'public-key', alg: -8 }, { type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
      attestation: 'none',
      timeout: 120_000,
    } });
  } catch {
    announce('No passkey was created. You can try again.');
    return;
  }
  const response = (credential as PublicKeyCredential | null)?.response as AuthenticatorAttestationResponse | undefined;
  if (!response?.attestationObject) { announce('No passkey was created. You can try again.'); return; }
  const finish = await api('/auth/register/finish', 'POST', {
    challengeId, clientDataJSON: toBase64url(response.clientDataJSON), attestationObject: toBase64url(response.attestationObject),
  });
  if (finish.status !== 200) { announce(failure(finish, 'The passkey could not be registered. Try again.')); return; }
  csrf = text(finish.data.csrf) ?? '';
  await load(true);
  announce('Account created. You are signed in.');
}

async function signIn(): Promise<void> {
  if (!passkeysAvailable()) { announce('This browser cannot use passkeys. Try a current version of Chrome, Edge, Firefox or Safari.'); return; }
  const start = await api('/auth/login/challenge', 'POST', {});
  const challengeId = text(start.data.id), challenge = text(start.data.challenge), rpId = text(start.data.rpId);
  if (start.status !== 200 || !challengeId || !challenge || !rpId) { announce(failure(start, 'Sign-in could not start. Try again.')); return; }
  let credential: Credential | null;
  try {
    credential = await navigator.credentials.get({ publicKey: { challenge: fromBase64url(challenge), rpId, userVerification: 'required', timeout: 120_000 } });
  } catch {
    announce('You were not signed in. You can try again.');
    return;
  }
  const passkey = credential as PublicKeyCredential | null;
  const response = passkey?.response as AuthenticatorAssertionResponse | undefined;
  if (!passkey || !response?.signature) { announce('You were not signed in. You can try again.'); return; }
  const finish = await api('/auth/login/finish', 'POST', {
    challengeId, credentialId: passkey.id, clientDataJSON: toBase64url(response.clientDataJSON),
    authenticatorData: toBase64url(response.authenticatorData), signature: toBase64url(response.signature),
  });
  if (finish.status !== 200) { announce(failure(finish, 'Sign-in could not be verified. Try again.')); return; }
  csrf = text(finish.data.csrf) ?? '';
  await load(true);
  announce('Signed in.');
}

async function signOut(): Promise<void> {
  const result = await api('/session', 'DELETE', undefined, true);
  if (result.status !== 200 && result.status !== 401) { announce(failure(result, 'You could not be signed out. Try again.')); return; }
  csrf = '';
  show('signed-out', true);
  announce('Signed out.');
}

function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}

function renderBoxes(boxes: BoxView[]): void {
  const list = byId<HTMLUListElement>('boxes-list');
  list.replaceChildren(...boxes.map(box => {
    const item = document.createElement('li');
    const name = document.createElement('span');
    name.className = 'box-name';
    name.textContent = box.name;
    const state = document.createElement('span');
    state.className = 'box-state';
    state.dataset.state = box.state;
    state.textContent = STATE_TEXT[box.state];
    item.append(name, state);
    const note = STATE_NOTE[box.state];
    if (note) {
      const text = document.createElement('p');
      text.className = 'box-note';
      text.textContent = note;
      item.append(text);
    }
    if (box.state === 'stopped') {
      const start = document.createElement('button');
      start.type = 'button';
      start.className = 'button secondary box-start';
      start.textContent = 'Start box';
      start.setAttribute('aria-label', `Start box ${box.name}`);
      start.addEventListener('click', guarded(() => startBox(box.name)));
      item.append(start);
    }
    return item;
  }));
  list.hidden = boxes.length === 0;
  byId('boxes-empty').hidden = boxes.length > 0;
}

function render(data: Record<string, unknown>): boolean {
  const plan = data.plan === 'paid' ? 'paid' : data.plan === 'free' ? 'free' : null;
  const quota = typeof data.boxQuota === 'number' && Number.isSafeInteger(data.boxQuota) && data.boxQuota >= 0 ? data.boxQuota : null;
  if (!plan || quota === null || !Array.isArray(data.boxes)) return false;
  const boxes: BoxView[] = data.boxes.flatMap((box: unknown) => {
    const record = box as Record<string, unknown> | null;
    return record && typeof record.name === 'string' && BOX_NAME.test(record.name) && typeof record.state === 'string' && BOX_STATES.includes(record.state)
      ? [{ name: record.name, state: record.state as BoxState }] : [];
  });
  byId('plan-text').textContent = plan === 'paid'
    ? `Paid. This account can run up to ${plural(quota, 'box', 'boxes')}.`
    : 'Free. Creating a box needs the paid plan.';
  byId('checkout').hidden = plan === 'paid';
  byId('checkout-text').hidden = plan === 'paid';
  renderBoxes(boxes);
  const canCreate = plan === 'paid' && boxes.length < quota;
  byId('create-panel').hidden = !canCreate;
  const unavailable = byId('create-unavailable');
  unavailable.hidden = plan !== 'paid' || canCreate;
  unavailable.textContent = plan === 'paid' && !canCreate ? `This account has reached its limit of ${plural(quota, 'box', 'boxes')}.` : '';
  return true;
}

async function load(focus = false): Promise<void> {
  const session = await api('/session');
  if (session.status === 401) { csrf = ''; show('signed-out', focus); return; }
  if (session.status !== 200) { show('signed-out', focus); announce(failure(session, 'Your account could not be loaded. Try again.')); return; }
  csrf = text(session.data.csrf) ?? '';
  const account = await api('/account');
  if (account.status !== 200 || !render(account.data)) {
    show('signed-out', focus);
    announce(failure(account, 'Your account could not be loaded. Try again.'));
    return;
  }
  show('signed-in', focus);
}

async function startCheckout(): Promise<void> {
  const result = await api('/billing/checkout', 'POST', {}, true);
  const url = text(result.data.url);
  let target: URL | null = null;
  try { target = url ? new URL(url) : null; } catch { target = null; }
  if (result.status !== 200 || !target || target.protocol !== 'https:' || target.hostname !== 'checkout.stripe.com') {
    announce(failure(result, 'Checkout could not be started. Try again in a minute.'));
    return;
  }
  announce('Opening Stripe Checkout.');
  window.location.assign(target.href);
}

function fieldError(field: HTMLInputElement | HTMLTextAreaElement | null, message: string): void {
  const error = byId('create-error');
  for (const id of ['box-name', 'device-key']) {
    const input = byId<HTMLInputElement | HTMLTextAreaElement>(id);
    input.removeAttribute('aria-invalid');
    input.setAttribute('aria-describedby', `${id}-help`);
  }
  error.textContent = message;
  error.hidden = message === '';
  const target = field ?? byId<HTMLInputElement>('box-name');
  if (message) {
    target.setAttribute('aria-invalid', 'true');
    target.setAttribute('aria-describedby', `${target.id}-help create-error`);
    target.focus();
  }
}

async function createBox(): Promise<void> {
  const nameInput = byId<HTMLInputElement>('box-name');
  const keyInput = byId<HTMLTextAreaElement>('device-key');
  const name = nameInput.value.trim();
  const deviceKey = keyInput.value.replace(/\s+/g, '');
  if (!BOX_NAME.test(name) || name.startsWith('gcp-')) {
    fieldError(nameInput, 'Use lowercase letters, digits and hyphens, starting with a letter, up to 63 characters.');
    return;
  }
  if (!DEVICE_KEY.test(deviceKey)) {
    fieldError(keyInput, 'This is not a device public key. Copy the whole key that keysentry box card prints.');
    return;
  }
  fieldError(null, '');
  const result = await api('/boxes', 'POST', { name, deviceKey }, true);
  if (result.status !== 201 && result.status !== 202) {
    fieldError(result.status === 409 ? nameInput : result.status === 400 ? keyInput : null, failure(result, 'The box could not be created. Try again.'));
    return;
  }
  byId<HTMLFormElement>('create-form').reset();
  await load();
  // 202: Compute gave no definite answer; the name stays held while keysentry checks whether the box exists.
  announce(result.status === 201 ? `Box ${name} is being created.` : `Box ${name} is being checked. Its state shows here within a few minutes.`);
}

async function startBox(name: string): Promise<void> {
  const result = await api('/boxes/' + encodeURIComponent(name) + '/start', 'POST', {}, true);
  if (result.status !== 202) { announce(failure(result, 'The box could not be started. Try again in a few minutes.')); return; }
  await load();
  announce(`Box ${name} is starting.`);
}

function guarded(action: () => Promise<void>): () => void {
  return () => {
    if (busy) return;
    setBusy(true);
    void action().catch(() => announce('Something went wrong on this page. Reload it and try again.')).finally(() => setBusy(false));
  };
}

async function boot(): Promise<void> {
  byId('sign-up').addEventListener('click', guarded(signUp));
  byId('sign-in').addEventListener('click', guarded(signIn));
  byId('sign-out').addEventListener('click', guarded(signOut));
  byId('checkout').addEventListener('click', guarded(startCheckout));
  byId('create-form').addEventListener('submit', event => { event.preventDefault(); guarded(createBox)(); });
  const returned = new URLSearchParams(window.location.search).get('checkout');
  if (returned !== null) window.history.replaceState(null, '', '/');
  setBusy(true);
  try { await load(); } finally { setBusy(false); }
  if (returned === 'done') announce('Thank you. Your plan changes to paid as soon as Stripe confirms the payment, usually within a minute. Reload this page to see it.');
  else if (returned === 'cancelled') announce('Checkout was cancelled. Nothing was charged.');
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => { void boot(); });
else void boot();
