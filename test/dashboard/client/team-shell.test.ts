// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { boot } from '../../../src/dashboard/client/main.js';
import { configureSession, fetchSession, postWithPasskey } from '../../../src/dashboard/client/api.js';
import { renderAccount } from '../../../src/dashboard/client/screens/account.js';
import { disposeComponents } from '../../../src/dashboard/client/components.js';

const reply = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const tick = async () => { await new Promise(resolve => setTimeout(resolve, 0)); };
const team = { csrf: 'team-csrf', readOnly: false, passkeys: 1, team: true, member: { id: 'ben', name: 'Ben', role: 'operator' },
  identity: { issuer: 'https://idp.example.test', subject: 'sub-ben', pinned: false } } as const;

beforeEach(() => { document.body.replaceChildren(); history.replaceState(null, '', '/'); });
afterEach(async () => {
  disposeComponents(document.body); document.body.replaceChildren();
  for (let i = 0; i < 5; i++) await tick();
  vi.unstubAllGlobals(); vi.restoreAllMocks();
});

describe('team dashboard shell', () => {
  it('keeps the team session fields, shows who is signed in, and signs out through /auth/logout', async () => {
    const fetcher = vi.fn().mockImplementation(async (url: string) => reply(url === '/api/session' ? team : url === '/auth/logout' ? { signedOut: true } : {}));
    vi.stubGlobal('fetch', fetcher);
    const assign = vi.spyOn(window.location, 'assign').mockImplementation(() => {});
    expect(await fetchSession()).toEqual(team);
    const root = document.createElement('div'); document.body.append(root);
    const app = await boot(root);
    const header = root.querySelector('header')!;
    expect(header.textContent).toContain('Signed in as Ben (operator)');
    expect(header.querySelector('a[href="#/account"]')?.textContent).toBe('Account');
    [...header.querySelectorAll('button')].find(item => item.textContent === 'Sign out')!.click();
    await tick();
    expect(fetcher).toHaveBeenCalledWith('/auth/logout', expect.objectContaining({ method: 'POST', headers: { 'X-CSRF-Token': 'team-csrf' } }));
    expect(assign).toHaveBeenCalledWith('/');
    app.destroy();
  });

  it('tells a viewer and a member without a passkey what to ask an admin for', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => reply({ ...team, readOnly: true, passkeys: 0, member: { ...team.member, role: 'viewer' } })));
    const root = document.createElement('div'); document.body.append(root);
    const app = await boot(root);
    expect(root.textContent).toContain('You are signed in as a viewer. Ask a team admin for the operator role to make changes.');
    app.destroy();
    vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => reply({ ...team, passkeys: 0 })));
    const other = document.createElement('div'); document.body.append(other);
    const second = await boot(other);
    expect(other.textContent).toContain('Ask a team admin to add your passkey to the team roster, then reload this page.');
    configureSession({ ...team, passkeys: 0 });
    await expect(postWithPasskey('rotate', {})).rejects.toThrow('Ask a team admin to add your passkey to the team roster, then reload this page.');
    second.destroy();
  });

  it('the account page shows the issuer and subject to pin, or that they are pinned', () => {
    const page = renderAccount({ ...team });
    expect(page.textContent).toContain('Signed in as Ben (ben).');
    expect([...page.querySelectorAll('code')].map(node => node.textContent)).toEqual(['https://idp.example.test', 'sub-ben']);
    expect(page.textContent).toContain('keysentry team sso ben --issuer https://idp.example.test --subject sub-ben');
    expect(renderAccount({ ...team, identity: { ...team.identity, pinned: true } }).textContent).toContain('Identity pinned');
    expect(renderAccount({ csrf: 'x', readOnly: false, passkeys: 1 }).textContent).toContain('Local dashboard');
  });
});

describe('team dashboard review fixes', () => {
  it('shows an admin the passkeys waiting for the roster and offers their card for download (H3)', async () => {
    const card = { v: 1, kind: 'keysentry-passkey-candidates', candidates: [{ memberId: 'ben', credential: { id: 'Y3JlZA' } }] };
    vi.stubGlobal('fetch', vi.fn().mockImplementation(async (url: string) => reply(url === '/api/team/candidates'
      ? { pending: [{ memberId: 'ben', credentialId: 'Y3JlZA', createdAt: '2026-10-28T10:00:00.000Z', fingerprint: '0123-4567-89ab-cdef-0123-4567-89ab-cdef' }], card } : {})));
    configureSession({ ...team, member: { ...team.member, role: 'admin' } });
    const page = renderAccount({ ...team, member: { ...team.member, role: 'admin' } });
    document.body.append(page);
    await vi.waitFor(() => expect(page.textContent).toContain('0123-4567-89ab-cdef-0123-4567-89ab-cdef'));
    expect(page.textContent).toContain('keysentry team add-passkey <member> --card <file>');
    const created = vi.fn(() => 'blob:card'); const revoked = vi.fn();
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: created, revokeObjectURL: revoked }));
    [...page.querySelectorAll('button')].find(item => item.textContent === 'Download passkey card')!.click();
    expect(created).toHaveBeenCalledTimes(1);
    // Operators do not see the list.
    expect(renderAccount({ ...team }).textContent).not.toContain('Passkeys waiting for an admin');
  });
});
