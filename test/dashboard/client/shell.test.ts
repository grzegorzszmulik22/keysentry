// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash, webcrypto } from 'node:crypto';
import { boot } from '../../../src/dashboard/client/main.js';
import { createRouter } from '../../../src/dashboard/client/router.js';
import { canonicalBody, configureSession, get, post, postWithPasskey } from '../../../src/dashboard/client/api.js';
import { button, confirmAction, disposeComponents, emptyState, keyTag, maskedValue, notice, table } from '../../../src/dashboard/client/components.js';

const session = { csrf: 'session-csrf', readOnly: false, passkeys: 1 };
const b64 = (value: string) => Buffer.from(value).toString('base64url');
const bytes = (value: string) => new TextEncoder().encode(value).buffer;
const assertion = () => ({ id: b64('credential'), rawId: bytes('credential'), type: 'public-key', response: { clientDataJSON: bytes('client'), authenticatorData: bytes('auth'), signature: bytes('signature'), userHandle: null } });
const reply = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const tick = async () => { await new Promise(resolve => setTimeout(resolve, 0)); };
// Waits for the reveal to finish instead of a fixed number of ticks, which was too few on slow CI runners.
const shown = (component: Element) => vi.waitFor(() => expect(component.querySelector('[role="status"]')?.textContent).toBe('Value shown'));

beforeEach(() => {
  document.body.replaceChildren();
  history.replaceState(null, '', '/');
  configureSession(session);
  vi.stubGlobal('crypto', webcrypto);
});
afterEach(async () => {
  if (typeof disposeComponents === 'function') disposeComponents(document.body);
  document.body.replaceChildren();
  vi.useRealTimers();
  // Screens registered at boot start their own requests; let them settle against this test's fetch stub before the
  // next test installs its own, so no late request consumes another test's queued responses.
  for (let i = 0; i < 5; i++) await new Promise(resolve => setTimeout(resolve, 0));
  vi.unstubAllGlobals(); vi.restoreAllMocks();
});

describe('dashboard shell and routing', () => {
  it('fetches the session, renders navigation and placeholder screens', async () => {
    const fetcher = vi.fn().mockResolvedValue(reply(session)); vi.stubGlobal('fetch', fetcher);
    const root = document.createElement('div'); document.body.append(root);
    const app = await boot(root);
    expect(fetcher.mock.calls[0]?.[0]).toBe('/api/session');
    expect(root.querySelector('header')?.textContent).toContain('What keysentry can access');
    expect(root.querySelector('header')?.textContent).toContain('Network');
    expect(root.querySelector('nav')?.getAttribute('aria-label')).toBe('Main navigation');
    expect(root.querySelector('h1')?.textContent).toBe('Overview');
    app.router.navigate('keys'); await tick();
    expect(root.querySelector('h1')?.textContent).toBe('Your keys');
    expect(document.activeElement).toBe(root.querySelector('h1'));
    expect(root.querySelector('a[aria-current="page"]')?.textContent).toBe('Keys');
    app.destroy();
  });

  it('states read-only mode without offering browser passkey registration', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(reply({ ...session, readOnly: true, passkeys: 0 })));
    const root = document.createElement('div'); document.body.append(root);
    const app = await boot(root);
    expect(root.textContent).toContain('Read-only');
    expect(root.textContent).toContain('To make changes, run keysentry ui in your own terminal.');
    expect([...root.querySelectorAll('button')].some(b => b.textContent === 'Register passkey')).toBe(false);
    app.destroy();
  });

  it.each([false, true])('directs zero-passkey sessions to the terminal under the heading (readOnly=%s)', async readOnly => {
    const fetcher = vi.fn().mockResolvedValue(reply({ ...session, readOnly, passkeys: 0 }));
    vi.stubGlobal('fetch', fetcher);
    const root = document.createElement('div'); document.body.append(root);
    const app = await boot(root);
    const message = 'Register a passkey with keysentry passkey register in your terminal, then reload this page.';
    expect(root.querySelector('h1')?.nextElementSibling?.textContent).toContain(message);
    expect([...root.querySelectorAll('button')].some(control => /register passkey/i.test(control.textContent ?? ''))).toBe(false);
    expect(fetcher.mock.calls.some(call => String(call[0]).includes('passkey/register/'))).toBe(false);
    app.destroy();
  });

  it('lets the skip link focus content without changing the route', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(reply(session)));
    const root = document.createElement('div'); document.body.append(root);
    const app = await boot(root);
    root.querySelector<HTMLAnchorElement>('.skip-link')!.click(); await tick();
    expect(root.querySelector('h1')?.textContent).toBe('Overview');
    expect(document.activeElement).toBe(root.querySelector('h1')); app.destroy();
  });

  it('registers screens, focuses their heading and renders an unknown-route invitation', async () => {
    const outlet = document.createElement('main'); document.body.append(outlet);
    const router = createRouter(outlet);
    router.register('example', { title: 'Example', render: () => { const p = document.createElement('p'); p.textContent = 'Content'; return p; } });
    router.start(); router.navigate('example'); await tick();
    expect(outlet.querySelector('h1')?.textContent).toBe('Example');
    expect(document.activeElement).toBe(outlet.querySelector('h1'));
    router.navigate('missing'); await tick();
    expect(outlet.textContent).toContain('Page not found');
    expect(outlet.querySelector('button')?.textContent).toBe('Open overview');
    router.stop();
  });

  it('does not let an older asynchronous screen replace the latest navigation', async () => {
    const outlet = document.createElement('main'); document.body.append(outlet);
    let finish!: (node: HTMLElement) => void;
    const router = createRouter(outlet, { slow: { title: 'Slow', render: () => new Promise<HTMLElement>(resolve => { finish = resolve; }) }, fast: { title: 'Fast', render: () => document.createElement('p') } });
    router.start(); router.navigate('slow'); await tick(); router.navigate('fast'); await tick();
    finish(document.createElement('p')); await tick();
    expect(outlet.querySelector('h1')?.textContent).toBe('Fast'); router.stop();
  });

  it('disposes masked components in a stale asynchronous document fragment', async () => {
    const outlet = document.createElement('main'); document.body.append(outlet);
    let finish!: (node: DocumentFragment) => void;
    const component = maskedValue(); const fragment = document.createDocumentFragment(); fragment.append(component);
    const router = createRouter(outlet, { slow: { title: 'Slow', render: () => new Promise<DocumentFragment>(resolve => { finish = resolve; }) }, fast: { title: 'Fast', render: () => document.createElement('p') } });
    await router.start(); router.navigate('slow'); await tick(); router.navigate('fast'); await tick();
    finish(fragment); await tick();
    expect(component.querySelector('button')).toBeNull();
    expect(outlet.querySelector('h1')?.textContent).toBe('Fast'); router.stop();
  });
});

describe('dashboard API client', () => {
  it('uses same-origin credentials, CSRF and canonical JSON on posts', async () => {
    const fetcher = vi.fn().mockImplementation(async () => reply({ ok: true })); vi.stubGlobal('fetch', fetcher);
    await get('keys'); await post('/api/refresh', { z: 1, a: { d: true, c: null } });
    expect(fetcher.mock.calls[0]?.[0]).toBe('/api/keys');
    expect(fetcher.mock.calls[0]?.[1]).toMatchObject({ credentials: 'same-origin', method: 'GET' });
    expect(fetcher.mock.calls[1]?.[1]).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': session.csrf, 'Content-Type': 'application/json' }, body: '{"a":{"c":null,"d":true},"z":1}' });
  });

  it('binds the passkey to the exact route and a frozen canonical body', async () => {
    const body = { z: 2, a: 1 };
    const credentials = { get: vi.fn(async options => { expect(options.publicKey.challenge).toBeInstanceOf(Uint8Array); expect(options.publicKey.userVerification).toBe('required'); body.z = 9; return assertion(); }) };
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: credentials });
    const fetcher = vi.fn().mockResolvedValueOnce(reply({ challenge: b64('challenge'), rpId: 'localhost', userVerification: 'required', allowCredentials: [{ type: 'public-key', id: b64('credential') }] })).mockResolvedValueOnce(reply({ ok: true })); vi.stubGlobal('fetch', fetcher);
    await postWithPasskey('rotate', body);
    const challengeBody = JSON.parse(fetcher.mock.calls[0]?.[1].body);
    expect(challengeBody.route).toBe('rotate');
    expect(challengeBody.bodyDigest).toBe(createHash('sha256').update('{"a":1,"z":2}').digest('hex'));
    expect(fetcher.mock.calls[1]?.[1].body).toBe('{"a":1,"z":2}');
    const wire = JSON.parse(Buffer.from(fetcher.mock.calls[1]?.[1].headers['X-Passkey-Assertion'], 'base64url').toString());
    expect(wire.response.signature).toBe(b64('signature')); expect(wire.response.userHandle).toBeNull();
  });

  it('uses a terminal-registered credential ID longer than the old vault-name limit', async () => {
    const rawId = new Uint8Array(1023).fill(17).buffer;
    const id = Buffer.from(rawId).toString('base64url');
    const credentials = { get: vi.fn(async options => {
      expect(new Uint8Array(options.publicKey.allowCredentials[0].id)).toEqual(new Uint8Array(rawId));
      return { ...assertion(), id, rawId };
    }) };
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: credentials });
    const fetcher = vi.fn().mockResolvedValueOnce(reply({ challenge: b64('challenge'), allowCredentials: [{ type: 'public-key', id }] })).mockResolvedValueOnce(reply({ done: true }));
    vi.stubGlobal('fetch', fetcher);
    await expect(postWithPasskey('rotate', {})).resolves.toEqual({ done: true });
    const wire = JSON.parse(Buffer.from(fetcher.mock.calls[1]?.[1].headers['X-Passkey-Assertion'], 'base64url').toString());
    expect(wire.id).toBe(id); expect(wire.rawId).toBe(id);
  });

  it('never sends the action when the passkey prompt is cancelled', async () => {
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: vi.fn(async () => null) } });
    const fetcher = vi.fn().mockResolvedValue(reply({ challenge: b64('challenge'), rpId: 'localhost' })); vi.stubGlobal('fetch', fetcher);
    await expect(postWithPasskey('rotate', {})).rejects.toThrow('Passkey verification was not completed.');
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('refuses mutations in read-only mode before making a request', async () => {
    configureSession({ ...session, readOnly: true }); const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
    await expect(postWithPasskey('rotate', {})).rejects.toThrow('Changes are unavailable in this session.');
    expect(fetcher).not.toHaveBeenCalled();
  });

  it.each([false, true])('directs changes without a passkey to terminal registration before requesting credentials (readOnly=%s)', async readOnly => {
    configureSession({ ...session, readOnly, passkeys: 0 });
    const credentials = { get: vi.fn(), create: vi.fn() };
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: credentials });
    const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
    await expect(postWithPasskey('rotate', {})).rejects.toThrow('Register a passkey with keysentry passkey register in your terminal, then reload this page.');
    expect(fetcher).not.toHaveBeenCalled();
    expect(credentials.get).not.toHaveBeenCalled(); expect(credentials.create).not.toHaveBeenCalled();
  });

  it('does not display an API error body or credential error message', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(reply({ error: 'planted secret value' }, 400)));
    await expect(post('rotate', {})).rejects.toThrow('The request could not be completed. Try again.');
  });

  it('rejects external and malformed routes and unsupported bodies locally', async () => {
    const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
    await expect(get('https://elsewhere.test')).rejects.toThrow();
    await expect(post('../rotate', {})).rejects.toThrow();
    expect(() => canonicalBody({ value: NaN })).toThrow('The request contains an unsupported value.');
    expect(canonicalBody({ b: undefined, a: [undefined, null] })).toBe('{"a":[null,null]}');
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe('dashboard components', () => {
  it('renders key tags and notices as text and opens tags by keyboard-native button', () => {
    const open = vi.fn(); const tag = keyTag({ provider: '<img>', hint: 'sk-…abcd', state: 'In git history', copies: 3, ageDays: 41 }, open); document.body.append(tag);
    expect(tag.tagName).toBe('BUTTON'); expect(tag.querySelector('img')).toBeNull(); expect(tag.textContent).toContain('3 places'); tag.click(); expect(open).toHaveBeenCalledOnce();
    const block = notice('attention', 'Review this key', '<script>value</script>'); expect(block.textContent).toContain('<script>value</script>'); expect(block.querySelector('script')).toBeNull(); expect(block.textContent).toContain('Needs attention');
  });

  it('renders accessible tables and empty-state actions', () => {
    const data = table(['Provider', 'State'], [['OpenAI', '<img>']], 'Your keys');
    expect(data.querySelector('caption')?.textContent).toBe('Your keys'); expect(data.querySelectorAll('th[scope="col"]')).toHaveLength(2); expect(data.querySelector('td img')).toBeNull();
    const action = vi.fn(); const empty = emptyState('No platforms connected yet.', { label: 'Connect platform', onClick: action }); empty.querySelector('button')?.click(); expect(action).toHaveBeenCalledOnce();
    expect(button('Rotate 3 keys').type).toBe('button');
  });

  it('repeats the exact changes in a dialog and restores focus', async () => {
    const trigger = button('Rotate'); document.body.append(trigger); trigger.focus();
    const result = confirmAction({ title: 'Rotate 3 keys', changes: ['Write the new key to 2 services.', 'The old key stays valid for 15 minutes.'], button: 'Rotate 3 keys' });
    const dialog = document.querySelector('dialog')!; expect([...dialog.querySelectorAll('li')].map(li => li.textContent)).toEqual(['Write the new key to 2 services.', 'The old key stays valid for 15 minutes.']);
    [...dialog.querySelectorAll('button')].find(b => b.textContent === 'Rotate 3 keys')!.click();
    await expect(result).resolves.toBe(true); expect(document.activeElement).toBe(trigger); expect(document.querySelector('dialog')).toBeNull();
  });

  it('resolves false when a confirmation is cancelled', async () => {
    const result = confirmAction({ title: 'Rotate', changes: ['Write the new key.'], button: 'Rotate key' });
    document.querySelector('dialog')?.dispatchEvent(new Event('cancel', { cancelable: true })); await expect(result).resolves.toBe(false);
  });

  it('keeps values hidden until confirmation and passkey, then hides them again', async () => {
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: vi.fn(async () => assertion()) } });
    const fetcher = vi.fn().mockResolvedValueOnce(reply({ challenge: b64('challenge'), rpId: 'localhost' })).mockResolvedValueOnce(reply({ value: 'explicit-reveal-only' })); vi.stubGlobal('fetch', fetcher);
    const component = maskedValue({ route: 'keys/reveal', body: { id: 'key-id' } }); document.body.append(component);
    expect(component.textContent).toContain('Hidden'); expect(fetcher).not.toHaveBeenCalled(); component.querySelector('button')!.click();
    expect(fetcher).not.toHaveBeenCalled(); [...document.querySelectorAll('dialog button')].find(b => b.textContent === 'Reveal value')!.click(); await shown(component);
    expect(component.textContent).toContain('explicit-reveal-only'); [...component.querySelectorAll('button')].find(b => b.textContent === 'Hide')!.click(); expect(component.textContent).not.toContain('explicit-reveal-only'); expect(component.textContent).toContain('Hidden');
  });

  it('announces only reveal state while the value stays outside live regions', async () => {
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: vi.fn(async () => assertion()) } });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(reply({ challenge: b64('challenge'), rpId: 'localhost' })).mockResolvedValueOnce(reply({ value: 'private-revealed-value' })));
    const component = maskedValue(); document.body.append(component);
    const output = component.querySelector('.masked-value-output')!;
    expect(output.closest('[aria-live]:not([aria-live="off"]), [role="status"], [role="alert"], [role="log"]')).toBeNull();
    component.querySelector('button')!.click();
    [...document.querySelectorAll('dialog button')].find(control => control.textContent === 'Reveal value')!.click();
    await vi.waitFor(() => expect(output.textContent).toBe('private-revealed-value'));
    expect(component.querySelector('[role="status"]')?.textContent).toBe('Value shown');
    expect(output.closest('[aria-live]:not([aria-live="off"]), [role="status"], [role="alert"], [role="log"]')).toBeNull();
    [...component.querySelectorAll('button')].find(control => control.textContent === 'Hide')!.click();
    expect(component.querySelector('[role="status"]')?.textContent).toBe('Value hidden');
    expect(component.textContent).not.toContain('private-revealed-value');
  });

  it('clears a copied value 30 seconds after the most recent copy', async () => {
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: vi.fn(async () => assertion()) } });
    let clipboard = '';
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: vi.fn(async value => { clipboard = value; }), readText: vi.fn(async () => clipboard) } });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(reply({ challenge: b64('challenge'), rpId: 'localhost' })).mockResolvedValueOnce(reply({ value: 'copy-only-value' })));
    const component = maskedValue(); document.body.append(component); component.querySelector('button')!.click();
    [...document.querySelectorAll('dialog button')].find(b => b.textContent === 'Reveal value')!.click(); await shown(component);
    vi.useFakeTimers(); const copy = [...component.querySelectorAll('button')].find(b => b.textContent === 'Copy')!;
    copy.click(); await vi.waitFor(() => expect(component.textContent).toContain('Copied.')); await vi.advanceTimersByTimeAsync(20_000); copy.click(); await vi.waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledTimes(2)); await vi.waitFor(() => expect(component.textContent).toContain('Copied.'));
    await vi.advanceTimersByTimeAsync(10_000); expect(clipboard).toBe('copy-only-value');
    await vi.advanceTimersByTimeAsync(20_000); await vi.waitFor(() => expect(clipboard).toBe(''));
  });

  it('keeps a newer clipboard value when the clear timer runs', async () => {
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: vi.fn(async () => assertion()) } });
    let clipboard = '';
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: vi.fn(async value => { clipboard = value; }), readText: vi.fn(async () => clipboard) } });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(reply({ challenge: b64('challenge'), rpId: 'localhost' })).mockResolvedValueOnce(reply({ value: 'copy-only-value' })));
    const component = maskedValue(); document.body.append(component); component.querySelector('button')!.click();
    [...document.querySelectorAll('dialog button')].find(b => b.textContent === 'Reveal value')!.click(); await shown(component);
    vi.useFakeTimers(); [...component.querySelectorAll('button')].find(b => b.textContent === 'Copy')!.click(); await vi.waitFor(() => expect(component.textContent).toContain('Copied.')); clipboard = 'another clipboard value';
    await vi.advanceTimersByTimeAsync(30_000); expect(clipboard).toBe('another clipboard value');
  });

  it('keeps the previous clear timer if a repeat copy fails', async () => {
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: vi.fn(async () => assertion()) } });
    let clipboard = '';
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: vi.fn().mockImplementationOnce(async value => { clipboard = value; }).mockRejectedValueOnce(new Error('permission')).mockImplementation(async value => { clipboard = value; }), readText: vi.fn(async () => clipboard) } });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(reply({ challenge: b64('challenge'), rpId: 'localhost' })).mockResolvedValueOnce(reply({ value: 'copy-only-value' })));
    const component = maskedValue(); document.body.append(component); component.querySelector('button')!.click();
    [...document.querySelectorAll('dialog button')].find(b => b.textContent === 'Reveal value')!.click(); await shown(component);
    vi.useFakeTimers(); const copy = [...component.querySelectorAll('button')].find(b => b.textContent === 'Copy')!;
    copy.click(); await vi.waitFor(() => expect(component.textContent).toContain('Copied.')); await vi.advanceTimersByTimeAsync(20_000); copy.click(); await vi.waitFor(() => expect(component.textContent).toContain('Copy was unavailable.'));
    await vi.advanceTimersByTimeAsync(10_000); await vi.waitFor(() => expect(clipboard).toBe(''));
  });

  it('clears a visible value when leaving a route even if the old DOM is retained', async () => {
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: vi.fn(async () => assertion()) } });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(reply({ challenge: b64('challenge'), rpId: 'localhost' })).mockResolvedValueOnce(reply({ value: 'reveal-value' })));
    const component = maskedValue(); const outlet = document.createElement('main'); document.body.append(outlet);
    const router = createRouter(outlet, { home: { title: 'Home', render: () => component }, other: { title: 'Other', render: () => document.createElement('p') } }); router.start(); await tick(); component.querySelector('button')!.click();
    [...document.querySelectorAll('dialog button')].find(b => b.textContent === 'Reveal value')!.click(); await shown(component);
    expect(component.textContent).toContain('reveal-value'); router.navigate('other'); await tick();
    expect(component.textContent).not.toContain('reveal-value'); expect(component.textContent).toContain('Hidden'); router.stop();
  });

  it('ignores an in-flight reveal result after its route is removed', async () => {
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: vi.fn(async () => assertion()) } });
    let complete!: (value: Response) => void;
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(reply({ challenge: b64('challenge'), rpId: 'localhost' })).mockImplementationOnce(() => new Promise<Response>(resolve => { complete = resolve; })));
    const component = maskedValue(); const outlet = document.createElement('main'); document.body.append(outlet);
    const router = createRouter(outlet, { home: { title: 'Home', render: () => component }, other: { title: 'Other', render: () => document.createElement('p') } }); router.start(); await tick(); component.querySelector('button')!.click();
    [...document.querySelectorAll('dialog button')].find(b => b.textContent === 'Reveal value')!.click(); await tick(); await tick();
    router.navigate('other'); await tick(); complete(reply({ value: 'late-reveal-value' })); await tick();
    expect(component.textContent).not.toContain('late-reveal-value'); expect(component.textContent).toContain('Hidden'); router.stop();
  });

  it('hides a revealed value on pagehide before history can restore the page', async () => {
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: vi.fn(async () => assertion()) } });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(reply({ challenge: b64('challenge'), rpId: 'localhost' })).mockResolvedValueOnce(reply({ value: 'reveal-value' })));
    const component = maskedValue(); document.body.append(component); component.querySelector('button')!.click();
    [...document.querySelectorAll('dialog button')].find(b => b.textContent === 'Reveal value')!.click(); await shown(component);
    expect(component.textContent).toContain('reveal-value'); window.dispatchEvent(new Event('pagehide'));
    expect(component.textContent).not.toContain('reveal-value'); expect(component.textContent).toContain('Hidden');
  });

  it('closes a pending reveal confirmation on router stop without requesting a passkey', async () => {
    const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
    const component = maskedValue(); const outlet = document.createElement('main'); document.body.append(outlet);
    const router = createRouter(outlet, { home: { title: 'Home', render: () => component } }); await router.start();
    component.querySelector('button')!.click(); expect(document.querySelector('dialog')).not.toBeNull();
    router.stop(); await tick();
    expect(document.querySelector('dialog')).toBeNull(); expect(component.textContent).toContain('Hidden'); expect(fetcher).not.toHaveBeenCalled();
  });

  it('prevents repeated reveal clicks from opening multiple confirmations', async () => {
    const component = maskedValue(); document.body.append(component);
    const reveal = component.querySelector('button')!; reveal.click(); reveal.click();
    expect(document.querySelectorAll('dialog')).toHaveLength(1);
    document.querySelector('dialog')!.dispatchEvent(new Event('cancel', { cancelable: true })); await tick();
    expect(reveal.disabled).toBe(false);
  });
});
