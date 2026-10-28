import { request as httpRequest, type IncomingHttpHeaders } from 'node:http';
import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createOidcClient } from '../../../src/dashboard/oidc/index.js';
import {
  createMemoryPasskeyCounters, startDashboard, type DashboardApi, type PasskeyCounterStore, type TeamAuthEvent,
} from '../../../src/dashboard/server/index.js';
import { canonicalJson } from '../../../src/security/index.js';
import type { TeamMember } from '../../../src/types.js';
import {
  ACCESS_TOKEN, CLIENT_ID, CLIENT_SECRET, createFakeIdp, ISSUER, PUBLIC_HOST, PUBLIC_ORIGIN, REDIRECT_URI, rsaKey, type FakeUser,
} from './fake-idp.js';
import { createTeamAuthenticator } from './team-authenticator.js';

interface Reply { status: number; headers: IncomingHttpHeaders; text: string; json: any }
const running: { close(): Promise<void> }[] = [];
afterEach(async () => { await Promise.all(running.splice(0).map(d => d.close())); });

const T0 = Date.parse('2026-10-28T12:00:00Z');
const ana = createTeamAuthenticator(PUBLIC_HOST);
const bo = createTeamAuthenticator(PUBLIC_HOST);
const localKey = createTeamAuthenticator('localhost');
const users: Record<string, FakeUser> = {
  ana: { sub: 'sub-ana', email: 'Ana@Example.test', email_verified: true },
  bo: { sub: 'sub-bo', email: 'bo@example.test', email_verified: true },
  vic: { sub: 'sub-vic', email: 'vic@example.test', email_verified: true },
  adi: { sub: 'sub-adi', email: 'adi@example.test', email_verified: true },
  eve: { sub: 'sub-eve', email: 'eve@example.test', email_verified: true },
  unverified: { sub: 'sub-ana2', email: 'ana@example.test', email_verified: false },
  stringly: { sub: 'sub-ana3', email: 'ana@example.test', email_verified: 'true' },
  noemail: { sub: 'sub-x' },
};
function roster(): TeamMember[] {
  return [
    { id: 'ana', name: 'Ana', role: 'operator', email: 'ana@example.test', deviceKeys: [],
      passkeys: [ana.credential([PUBLIC_ORIGIN]), localKey.credential(['http://localhost'])] },
    { id: 'bo', name: 'Bo', role: 'operator', email: 'bo@example.test', deviceKeys: [], passkeys: [bo.credential([PUBLIC_ORIGIN])] },
    { id: 'vic', name: 'Vic', role: 'viewer', email: 'vic@example.test', deviceKeys: [], passkeys: [] },
    { id: 'adi', name: 'Adi', role: 'admin', email: 'adi@example.test', deviceKeys: [], passkeys: [] },
    { id: 'nomail', name: 'No mail', role: 'admin', deviceKeys: [], passkeys: [] },
  ];
}

async function startTeam(extra: { readOnly?: boolean; idleMs?: number; absoluteMs?: number; counters?: PasskeyCounterStore; members?: () => Promise<TeamMember[]> } = {}) {
  let now = T0;
  const idp = createFakeIdp({ now: () => now });
  const members = roster();
  const events: TeamAuthEvent[] = [];
  const handlers = { read: vi.fn(async () => ({ count: 2 })), write: vi.fn(async () => ({ done: true })) };
  const api: DashboardApi = {
    keys: { method: 'GET', mutating: false, handler: handlers.read },
    rotate: { method: 'POST', mutating: true, handler: handlers.write },
    'rotate/preview': { method: 'POST', mutating: false, handler: handlers.read },
    'autopilot/disarm': { method: 'POST', mutating: false, handler: handlers.write },
    'autopilot/arm': { method: 'POST', mutating: true, handler: handlers.write },
  };
  const counters = extra.counters ?? createMemoryPasskeyCounters();
  const oidc = createOidcClient({ issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, http: idp.http, clientSecret: async () => CLIENT_SECRET, now: () => now });
  const dashboard = await startDashboard({ api, readOnly: extra.readOnly ?? false, idleMs: extra.idleMs, now: () => now, team: {
    publicOrigin: PUBLIC_ORIGIN, listen: { host: '127.0.0.1', port: 0 }, oidc, absoluteMs: extra.absoluteMs,
    members: extra.members ?? (async () => structuredClone(members)), passkeyCounters: counters, onAuthEvent: event => { events.push(event); },
  } });
  running.push(dashboard);
  const replies: Reply[] = [];
  function req(path: string, opts: { method?: string; headers?: Record<string, string>; body?: string } = {}): Promise<Reply> {
    return new Promise((resolve, reject) => {
      const request = httpRequest({ hostname: '127.0.0.1', port: dashboard.port, path, method: opts.method ?? 'GET', headers: { Host: PUBLIC_HOST, ...opts.headers } }, res => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', chunk => { text += chunk; });
        res.on('end', () => { let json: any; try { json = JSON.parse(text); } catch { /* HTML */ } const reply = { status: res.statusCode!, headers: res.headers, text, json }; replies.push(reply); resolve(reply); });
      });
      request.on('error', reject);
      request.end(opts.body);
    });
  }
  const cookie = (reply: Reply, name: string) => (reply.headers['set-cookie'] ?? []).find(value => value.startsWith(`${name}=`));
  /** Login redirect, provider round trip, and the cross-site redirect back. */
  async function callbackFor(user: FakeUser, extraParams: Record<string, string> = {}) {
    const login = await req('/auth/login', { headers: { 'Sec-Fetch-Site': 'same-origin' } });
    expect(login.status).toBe(303);
    const signInCookie = cookie(login, '__Host-ks_oidc')!.split(';')[0]!;
    const query = idp.authorize(login.headers.location!, user, extraParams);
    return { login, signInCookie, path: `/auth/callback?${query}` };
  }
  async function signIn(user: FakeUser) {
    const flow = await callbackFor(user);
    const callback = await req(flow.path, { headers: { Cookie: flow.signInCookie, 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document' } });
    const sessionCookie = cookie(callback, '__Host-ks_session');
    if (callback.status !== 200 || !sessionCookie) return { callback, flow, auth: null };
    const auth = { cookie: sessionCookie.split(';')[0]!, csrf: '' };
    auth.csrf = (await req('/api/session', { headers: { Cookie: auth.cookie } })).json.csrf;
    return { callback, flow, auth };
  }
  function post(path: string, auth: { cookie: string; csrf: string }, body: unknown = {}, headers: Record<string, string> = {}) {
    return req(path, { method: 'POST', body: JSON.stringify(body), headers: { Cookie: auth.cookie, Origin: PUBLIC_ORIGIN, 'X-CSRF-Token': auth.csrf, 'Content-Type': 'application/json', ...headers } });
  }
  return { dashboard, idp, members, events, handlers, counters, replies, req, post, signIn, callbackFor, cookie, advance(ms: number) { now += ms; } };
}

const digest = (body: unknown) => createHash('sha256').update(canonicalJson(body)).digest('hex');

describe('team dashboard sign-in', () => {
  it('signs a roster member in with the code flow, Secure cookies and no tokens anywhere in responses', async () => {
    const t = await startTeam();
    expect(t.dashboard.url).toBe(`${PUBLIC_ORIGIN}/`);
    const start = await t.req('/');
    expect(start.status).toBe(200); expect(start.text).toContain('href="/auth/login"');
    const { callback, flow, auth } = await t.signIn(users.ana!);
    const location = new URL(flow.login.headers.location!);
    expect(location.origin + location.pathname).toBe(`${ISSUER}/authorize`);
    expect(location.searchParams.get('redirect_uri')).toBe(REDIRECT_URI);
    expect(t.cookie(flow.login, '__Host-ks_oidc')).toMatch(/^__Host-ks_oidc=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=600$/);
    expect(callback.status).toBe(200);
    expect(callback.text).toContain('<meta http-equiv="refresh" content="0;url=/">');
    expect(t.cookie(callback, '__Host-ks_session')).toMatch(/^__Host-ks_session=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Strict$/);
    expect(t.cookie(callback, '__Host-ks_oidc')).toBe('__Host-ks_oidc=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0');
    expect(callback.headers['strict-transport-security']).toBe('max-age=31536000');
    expect(callback.headers['content-security-policy']).toContain("default-src 'none'");
    const session = await t.req('/api/session', { headers: { Cookie: auth!.cookie } });
    expect(session.json).toEqual({ csrf: auth!.csrf, readOnly: false, passkeys: 1, team: true, member: { id: 'ana', name: 'Ana', role: 'operator' },
      identity: { issuer: ISSUER, subject: 'sub-ana', pinned: false } });
    expect((await t.req('/', { headers: { Cookie: auth!.cookie } })).text).toContain('/app/main.js');
    expect((await t.req('/api/keys', { headers: { Cookie: auth!.cookie } })).json).toEqual({ count: 2 });
    expect(t.events).toEqual([{ kind: 'sign-in', memberId: 'ana', role: 'operator' }]);
    const code = new URLSearchParams(flow.path.split('?')[1]).get('code')!;
    const idToken = t.idp.state.issued[0]!;
    expect(idToken.split('.')).toHaveLength(3);
    for (const reply of t.replies) {
      const all = reply.text + JSON.stringify(reply.headers);
      for (const secret of [ACCESS_TOKEN, 'refresh-planted-value', CLIENT_SECRET, code, idToken, idToken.split('.')[2]!]) expect(all).not.toContain(secret);
    }
    expect(JSON.stringify(t.events)).not.toContain('example.test');
  });

  it('refuses a replayed callback, a missing sign-in cookie and a mismatched state', async () => {
    const t = await startTeam();
    const { flow, auth } = await t.signIn(users.ana!);
    expect(auth).not.toBeNull();
    const replay = await t.req(flow.path, { headers: { Cookie: flow.signInCookie } });
    expect(replay.status).toBe(400); expect(replay.text).toContain('This sign-in has expired or was already used.');
    const second = await t.callbackFor(users.ana!);
    expect((await t.req(second.path)).status).toBe(400);
    // A forged state consumes the transaction, so the genuine callback after it fails too.
    const third = await t.callbackFor(users.ana!);
    const wrongState = third.path.replace(/state=[^&]+/, 'state=forged-state');
    expect((await t.req(wrongState, { headers: { Cookie: third.signInCookie } })).status).toBe(400);
    expect((await t.req(third.path, { headers: { Cookie: third.signInCookie } })).status).toBe(400);
    // One browser's sign-in cookie cannot complete another browser's callback (login CSRF).
    const otherBrowser = await t.callbackFor(users.ana!);
    expect((await t.req(otherBrowser.path, { headers: { Cookie: second.signInCookie } })).status).toBe(400);
    expect(t.idp.state.tokenRequests).toHaveLength(1);
    expect(t.events.filter(event => event.kind === 'sign-in-refused')).toEqual(Array(5).fill({ kind: 'sign-in-refused', reason: 'state' }));
  });

  it('reports at most ten anonymous refusals a minute and counts the rest', async () => {
    const t = await startTeam();
    for (let i = 0; i < 14; i++) expect((await t.req('/auth/callback?code=x&state=y')).status).toBe(400);
    expect(t.events).toHaveLength(10);
    t.advance(60_000);
    expect((await t.req('/auth/callback?code=x&state=y')).status).toBe(400);
    expect(t.events.at(-1)).toEqual({ kind: 'sign-in-refused', reason: 'state', suppressed: 4 });
    expect((await t.signIn(users.ana!)).auth).not.toBeNull();
    expect(t.events.at(-1)).toEqual({ kind: 'sign-in', memberId: 'ana', role: 'operator' });
  });

  it('expires the sign-in cookie after ten minutes', async () => {
    const t = await startTeam();
    const flow = await t.callbackFor(users.ana!);
    t.advance(600_000);
    expect((await t.req(flow.path, { headers: { Cookie: flow.signInCookie } })).status).toBe(400);
  });

  it.each<[string, Record<string, unknown>, Record<string, unknown>, string]>([
    ['a wrong issuer', { iss: 'https://evil.example.test' }, {}, 'issuer'],
    ['a wrong audience', { aud: 'another-client' }, {}, 'audience'],
    ['an expired token', { exp: Math.floor(T0 / 1000) - 120 }, {}, 'expired'],
    ['a token from the future', { iat: Math.floor(T0 / 1000) + 3600, exp: Math.floor(T0 / 1000) + 7200 }, {}, 'not-yet-valid'],
    ['a token not valid yet', { nbf: Math.floor(T0 / 1000) + 3600 }, {}, 'not-yet-valid'],
    ['a bad nonce', { nonce: 'nonce-from-another-sign-in' }, {}, 'nonce'],
    ['alg none', {}, { alg: 'none' }, 'algorithm'],
    ['HS256', {}, { alg: 'HS256' }, 'algorithm'],
  ])('refuses %s with no session', async (_name, claims, header, reason) => {
    const t = await startTeam();
    t.idp.state.claims = base => ({ ...base, ...claims });
    t.idp.state.header = base => ({ ...base, ...header });
    const { callback, auth } = await t.signIn(users.ana!);
    expect(auth).toBeNull();
    expect(callback.status).toBe(401);
    expect(callback.text).toContain('The sign-in could not be verified.');
    expect(t.cookie(callback, '__Host-ks_session')).toBeUndefined();
    expect(t.events).toEqual([{ kind: 'sign-in-refused', reason }]);
  });

  it('refreshes the provider keys once for an unknown kid and refuses keys it still cannot find', async () => {
    const t = await startTeam();
    expect((await t.signIn(users.ana!)).auth).not.toBeNull();
    expect(t.idp.jwksFetches()).toBe(1);
    const rotated = rsaKey('k2');
    t.idp.state.published = [rotated]; t.idp.state.signer = rotated;
    expect((await t.signIn(users.ana!)).auth).not.toBeNull();
    expect(t.idp.jwksFetches()).toBe(2);
    expect((await t.signIn(users.ana!)).auth).not.toBeNull();
    expect(t.idp.jwksFetches()).toBe(2);
    t.advance(11_000);
    t.idp.state.signer = rsaKey('k9');
    const refused = await t.signIn(users.ana!);
    expect(refused.auth).toBeNull();
    expect(t.idp.jwksFetches()).toBe(3);
    expect(t.events.at(-1)).toEqual({ kind: 'sign-in-refused', reason: 'unknown-key' });
  });

  it.each<[string, string, string]>([
    ['unverified', 'email-unverified', 'did not confirm a verified email address'],
    ['stringly', 'email-unverified', 'did not confirm a verified email address'],
    ['noemail', 'email-missing', 'did not confirm a verified email address'],
    ['eve', 'not-member', 'This account is not on the team roster.'],
  ])('refuses the %s identity', async (who, reason, text) => {
    const t = await startTeam();
    const { callback, auth } = await t.signIn(users[who]!);
    expect(auth).toBeNull(); expect(callback.status).toBe(403); expect(callback.text).toContain(text);
    expect(t.events).toEqual([{ kind: 'sign-in-refused', reason }]);
  });

  it('refuses provider errors and duplicate parameters without echoing them', async () => {
    const t = await startTeam();
    const flow = await t.callbackFor(users.ana!);
    const state = new URLSearchParams(flow.path.split('?')[1]).get('state')!;
    const error = await t.req(`/auth/callback?error=access_denied&error_description=planted-provider-text&state=${state}`, { headers: { Cookie: flow.signInCookie } });
    expect(error.status).toBe(401); expect(error.text).not.toContain('planted-provider-text');
    const again = await t.callbackFor(users.ana!);
    expect((await t.req(`${again.path}&code=second`, { headers: { Cookie: again.signInCookie } })).status).toBe(401);
    expect(t.events.map(event => event.kind === 'sign-in-refused' && event.reason)).toEqual(['provider-error', 'provider-error']);
  });

  it('fails closed when the roster cannot be read', async () => {
    let fail = false;
    const members = roster();
    const t = await startTeam({ members: async () => { if (fail) throw new Error('planted roster failure'); return structuredClone(members); } });
    const { auth } = await t.signIn(users.ana!);
    fail = true;
    const read = await t.req('/api/keys', { headers: { Cookie: auth!.cookie } });
    expect(read.status).toBe(500); expect(read.text).not.toContain('planted');
    const second = await t.signIn(users.ana!);
    expect(second.callback.status).toBe(503); expect(second.auth).toBeNull();
    expect(t.handlers.read).not.toHaveBeenCalled();
  });
});

describe('team dashboard boundary', () => {
  it('checks Host, Origin, CSRF and Fetch Metadata against the public origin', async () => {
    const t = await startTeam();
    const { auth } = await t.signIn(users.ana!);
    for (const Host of ['127.0.0.1', `localhost:${t.dashboard.port}`, 'evil.example.test', 'KEYSENTRY.example.test', `${PUBLIC_HOST}:443`]) {
      expect((await t.req('/api/keys', { headers: { Host, Cookie: auth!.cookie } })).status).toBe(403);
    }
    expect((await t.req('/api/keys', { headers: { Host: 'evil.example.test', 'X-Forwarded-Host': PUBLIC_HOST, Cookie: auth!.cookie } })).status).toBe(403);
    expect((await t.post('/api/autopilot/disarm', auth!, {}, { Origin: `http://${PUBLIC_HOST}` })).status).toBe(403);
    expect((await t.post('/api/autopilot/disarm', auth!, {}, { Origin: 'https://evil.example.test' })).status).toBe(403);
    expect((await t.post('/api/autopilot/disarm', auth!, {}, { 'X-CSRF-Token': 'x'.repeat(43) })).status).toBe(403);
    expect((await t.req('/api/keys', { headers: { Cookie: auth!.cookie, 'Sec-Fetch-Site': 'cross-site' } })).status).toBe(403);
    expect((await t.req('/auth/login', { headers: { 'Sec-Fetch-Site': 'cross-site' } })).status).toBe(403);
    expect((await t.req('/', { headers: { 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'no-cors', 'Sec-Fetch-Dest': 'image' } })).status).toBe(403);
    expect((await t.req('/', { headers: { 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document' } })).status).toBe(200);
    expect(t.handlers.write).not.toHaveBeenCalled();
    expect((await t.post('/api/autopilot/disarm', auth!)).status).toBe(200);
  });

  it('disables the one-time link and any query entry in team mode', async () => {
    const t = await startTeam();
    for (const path of [`/?t=${'a'.repeat(43)}`, '/?x=1', '/api/keys?x=1']) {
      const reply = await t.req(path);
      expect(reply.status).toBe(404); expect(reply.headers['set-cookie']).toBeUndefined();
    }
    expect((await t.req('/api/session')).status).toBe(401);
    expect((await t.req('/app/main.js')).status).toBe(401);
  });

  it('ends sessions after the idle and absolute lifetimes, and on sign-out', async () => {
    const t = await startTeam({ idleMs: 60_000, absoluteMs: 150_000 });
    const first = (await t.signIn(users.ana!)).auth!;
    t.advance(59_000); expect((await t.req('/api/keys', { headers: { Cookie: first.cookie } })).status).toBe(200);
    t.advance(59_000); expect((await t.req('/api/keys', { headers: { Cookie: first.cookie } })).status).toBe(200);
    t.advance(33_000); expect((await t.req('/api/keys', { headers: { Cookie: first.cookie } })).status).toBe(401);
    const second = (await t.signIn(users.ana!)).auth!;
    t.advance(60_000); expect((await t.req('/api/keys', { headers: { Cookie: second.cookie } })).status).toBe(401);
    const third = (await t.signIn(users.ana!)).auth!;
    expect((await t.post('/auth/logout', { ...third, csrf: 'y'.repeat(43) })).status).toBe(403);
    const out = await t.post('/auth/logout', third);
    expect(out.status).toBe(200); expect(out.headers['set-cookie']).toEqual(['__Host-ks_session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0']);
    expect((await t.req('/api/keys', { headers: { Cookie: third.cookie } })).status).toBe(401);
    expect(t.events.filter(event => event.kind === 'sign-out')).toEqual([{ kind: 'sign-out', memberId: 'ana' }]);
  });

  it('ends a session when the member leaves the roster or their email changes, and applies role changes at once', async () => {
    const t = await startTeam();
    const { auth } = await t.signIn(users.ana!);
    t.members[0]!.role = 'viewer';
    expect((await t.post('/api/autopilot/disarm', auth!)).status).toBe(403);
    t.members[0]!.role = 'operator';
    expect((await t.post('/api/autopilot/disarm', auth!)).status).toBe(200);
    t.members[0]!.email = 'ana.new@example.test';
    expect((await t.req('/api/keys', { headers: { Cookie: auth!.cookie } })).status).toBe(401);
    expect(t.events.at(-1)).toEqual({ kind: 'session-ended', memberId: 'ana', reason: 'roster' });
    const bo = (await t.signIn(users.bo!)).auth!;
    t.members.splice(1, 1);
    expect((await t.req('/', { headers: { Cookie: bo.cookie } })).text).toContain('href="/auth/login"');
  });
});

describe('team dashboard roles and passkeys', () => {
  it('gives viewers a read-only dashboard', async () => {
    const t = await startTeam();
    const { auth } = await t.signIn(users.vic!);
    expect((await t.req('/api/session', { headers: { Cookie: auth!.cookie } })).json).toMatchObject({ readOnly: true, passkeys: 0, member: { id: 'vic', role: 'viewer' } });
    expect((await t.req('/api/keys', { headers: { Cookie: auth!.cookie } })).status).toBe(200);
    expect((await t.post('/api/rotate/preview', auth!)).status).toBe(200);
    for (const [path, body] of [['/api/autopilot/disarm', {}], ['/api/rotate', {}], ['/api/autopilot/arm', {}], ['/api/passkey/challenge', { route: 'rotate', bodyDigest: 'a'.repeat(64) }]] as const) {
      const reply = await t.post(path, auth!, body);
      expect(reply.status).toBe(403);
      expect(reply.json).toEqual({ error: 'Your team role can read this dashboard but not make changes.' });
    }
    expect(t.handlers.write).not.toHaveBeenCalled();
  });

  it("requires the operator's own passkey for every change; the identity provider alone approves nothing", async () => {
    const t = await startTeam();
    const { auth } = await t.signIn(users.ana!);
    const body = { clusterIds: ['c1'] };
    expect((await t.post('/api/rotate', auth!, body)).status).toBe(403);
    const options = await t.post('/api/passkey/challenge', auth!, { route: 'rotate', bodyDigest: digest(body) });
    expect(options.status).toBe(200);
    expect(options.json).toMatchObject({ rpId: PUBLIC_HOST, userVerification: 'required', allowCredentials: [{ id: ana.id, type: 'public-key' }] });
    // Another operator's real passkey over Ana's challenge is not accepted, and burns the challenge.
    expect((await t.post('/api/rotate', auth!, body, { 'X-Passkey-Assertion': bo.assertionHeader(options.json.challenge, PUBLIC_ORIGIN) })).status).toBe(403);
    expect((await t.post('/api/rotate', auth!, body, { 'X-Passkey-Assertion': ana.assertionHeader(options.json.challenge, PUBLIC_ORIGIN) })).status).toBe(403);
    // A localhost passkey of the same member is neither offered nor accepted on the team origin.
    const local = await t.post('/api/passkey/challenge', auth!, { route: 'rotate', bodyDigest: digest(body) });
    expect((await t.post('/api/rotate', auth!, body, { 'X-Passkey-Assertion': localKey.assertionHeader(local.json.challenge, PUBLIC_ORIGIN) })).status).toBe(403);
    const fresh = await t.post('/api/passkey/challenge', auth!, { route: 'rotate', bodyDigest: digest(body) });
    const wrongOrigin = ana.assertionHeader(fresh.json.challenge, 'https://evil.example.test');
    expect((await t.post('/api/rotate', auth!, body, { 'X-Passkey-Assertion': wrongOrigin })).status).toBe(403);
    expect(t.handlers.write).not.toHaveBeenCalled();
    const good = await t.post('/api/passkey/challenge', auth!, { route: 'rotate', bodyDigest: digest(body) });
    const header = ana.assertionHeader(good.json.challenge, PUBLIC_ORIGIN);
    expect((await t.post('/api/rotate', auth!, body, { 'X-Passkey-Assertion': header })).status).toBe(200);
    expect(t.handlers.write).toHaveBeenCalledExactlyOnceWith(body, { session: expect.any(String), member: { id: 'ana', role: 'operator' }, passkey: ana.id });
    expect(await t.counters.read(ana.id)).toBeGreaterThan(0);
    expect((await t.post('/api/rotate', auth!, body, { 'X-Passkey-Assertion': header })).status).toBe(403);
    expect(t.handlers.write).toHaveBeenCalledTimes(1);
  });

  it("does not let one member's session use another member's challenge", async () => {
    const t = await startTeam();
    const anaAuth = (await t.signIn(users.ana!)).auth!;
    const boAuth = (await t.signIn(users.bo!)).auth!;
    const body = { clusterIds: ['c1'] };
    const options = await t.post('/api/passkey/challenge', anaAuth, { route: 'rotate', bodyDigest: digest(body) });
    expect((await t.post('/api/rotate', boAuth, body, { 'X-Passkey-Assertion': bo.assertionHeader(options.json.challenge, PUBLIC_ORIGIN) })).status).toBe(403);
    expect((await t.post('/api/rotate', boAuth, body, { 'X-Passkey-Assertion': ana.assertionHeader(options.json.challenge, PUBLIC_ORIGIN) })).status).toBe(403);
    expect(t.handlers.write).not.toHaveBeenCalled();
  });

  it('keeps policy-widening routes for admins and tells members without a passkey to ask an admin', async () => {
    const t = await startTeam();
    const operator = (await t.signIn(users.ana!)).auth!;
    expect((await t.post('/api/autopilot/arm', operator)).json).toEqual({ error: 'Your team role does not allow this action.' });
    expect((await t.post('/api/passkey/challenge', operator, { route: 'autopilot/arm', bodyDigest: digest({}) })).status).toBe(403);
    const admin = (await t.signIn(users.adi!)).auth!;
    const reply = await t.post('/api/passkey/challenge', admin, { route: 'autopilot/arm', bodyDigest: digest({}) });
    expect(reply.status).toBe(403);
    expect(reply.json).toEqual({ error: 'Ask a team admin to add your passkey to the team roster, then reload this page.' });
    expect((await t.post('/api/autopilot/arm', admin)).status).toBe(403);
    expect(t.handlers.write).not.toHaveBeenCalled();
  });

  it('refuses changes in a read-only team dashboard even with a passkey', async () => {
    const t = await startTeam({ readOnly: true });
    const { auth } = await t.signIn(users.ana!);
    expect((await t.req('/api/session', { headers: { Cookie: auth!.cookie } })).json.readOnly).toBe(true);
    for (const path of ['/api/rotate', '/api/passkey/challenge']) {
      expect((await t.post(path, auth!, { route: 'rotate', bodyDigest: 'a'.repeat(64) })).json).toEqual({ error: 'This dashboard was started read-only. Changes are unavailable.' });
    }
  });
});

describe('team dashboard configuration', () => {
  it('refuses an http or IP public origin and a redirect URI elsewhere', async () => {
    const idp = createFakeIdp({ now: () => T0 });
    const oidc = createOidcClient({ issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, http: idp.http });
    const base = { members: async () => [], passkeyCounters: createMemoryPasskeyCounters(), listen: { host: '127.0.0.1', port: 0 }, oidc };
    for (const publicOrigin of ['http://keysentry.example.test', 'https://keysentry.example.test/', 'https://127.0.0.1', 'https://keysentry.example.test/app']) {
      await expect(startDashboard({ api: {}, readOnly: false, team: { ...base, publicOrigin } })).rejects.toThrow('https origin');
    }
    const elsewhere = createOidcClient({ issuer: ISSUER, clientId: CLIENT_ID, redirectUri: 'https://other.example.test/auth/callback', http: idp.http });
    await expect(startDashboard({ api: {}, readOnly: false, team: { ...base, oidc: elsewhere, publicOrigin: PUBLIC_ORIGIN } })).rejects.toThrow('redirect');
    await expect(startDashboard({ api: {}, readOnly: false, team: { ...base, publicOrigin: PUBLIC_ORIGIN, listen: { host: '', port: 0 } } })).rejects.toThrow('interface');
  });

  it('leaves the local dashboard unchanged: one-time link, no sign-in routes', async () => {
    const local = await startDashboard({ api: {}, readOnly: false });
    running.push(local);
    expect(local.url).toMatch(new RegExp(`^http://localhost:${local.port}/\\?t=[A-Za-z0-9_-]{43}$`));
    const reply = await new Promise<number>((resolve, reject) => {
      const request = httpRequest({ hostname: '127.0.0.1', port: local.port, path: '/auth/login', headers: { Host: `localhost:${local.port}` } }, res => { res.resume(); resolve(res.statusCode!); });
      request.on('error', reject); request.end();
    });
    expect(reply).toBe(401);
  });
});
