// Team dashboard: single sign-on pinned to (iss, sub), and passkey enrollment for the public host.
import { request as httpRequest, type IncomingHttpHeaders } from 'node:http';
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { enrollmentHooks } from '../../../src/cli/phase3.js';
import { createStateCipher, createStateStore } from '../../../src/core/store.js';
import { createOidcClient, memberForIdentity } from '../../../src/dashboard/oidc/index.js';
import { createMemoryPasskeyCounters, startDashboard, type DashboardApi } from '../../../src/dashboard/server/index.js';
import { canonicalJson } from '../../../src/security/index.js';
import { createInvite, INVITE_TTL_MS, listCandidates } from '../../../src/team/index.js';
import type { AuditEvent, TeamMember } from '../../../src/types.js';
import { CLIENT_ID, CLIENT_SECRET, createFakeIdp, ISSUER, PUBLIC_HOST, PUBLIC_ORIGIN, REDIRECT_URI, type FakeUser } from './fake-idp.js';
import { createEnrollingAuthenticator } from './enrolling-authenticator.js';

interface Reply { status: number; headers: IncomingHttpHeaders; text: string; json: any }
const running: { close(): Promise<void> }[] = [];
const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(running.splice(0).map(d => d.close()));
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

const T0 = Date.parse('2026-10-28T12:00:00Z');
const digest = (body: unknown) => createHash('sha256').update(canonicalJson(body)).digest('hex');

function roster(): TeamMember[] {
  return [
    { id: 'ana', name: 'Ana', role: 'admin', email: 'ana@example.test', sso: { issuer: ISSUER, subject: 'sub-ana' }, deviceKeys: [], passkeys: [] },
    { id: 'ben', name: 'Ben', role: 'operator', email: 'ben@example.test', deviceKeys: [], passkeys: [] },
    { id: 'vic', name: 'Vic', role: 'viewer', email: 'vic@example.test', deviceKeys: [], passkeys: [] },
  ];
}

async function startTeam(extra: { enrollment?: boolean } = {}) {
  let now = T0;
  const idp = createFakeIdp({ now: () => now });
  const members = roster();
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-team-gov-')); dirs.push(cwd);
  const store = createStateStore({ cwd, cipher: createStateCipher(Buffer.alloc(32, 9)) });
  const audit: AuditEvent[] = [];
  const handlers = { write: vi.fn(async () => ({ done: true })) };
  const api: DashboardApi = { rotate: { method: 'POST', mutating: true, handler: handlers.write } };
  const oidc = createOidcClient({ issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, http: idp.http, clientSecret: async () => CLIENT_SECRET, now: () => now });
  const rt = { store, now: () => new Date(now), audit: { append: async (event: AuditEvent) => { audit.push(event); }, checkpoint: async () => {}, verify: async () => ({ ok: true, entries: 0, checkpoints: 0 }) } };
  const dashboard = await startDashboard({ api, readOnly: false, now: () => now, team: {
    publicOrigin: PUBLIC_ORIGIN, listen: { host: '127.0.0.1', port: 0 }, oidc,
    members: async () => structuredClone(members), passkeyCounters: createMemoryPasskeyCounters(),
    ...(extra.enrollment === false ? {} : { enrollment: enrollmentHooks(rt, PUBLIC_ORIGIN, { diagnostic: () => {} }) }),
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
  async function signIn(user: FakeUser) {
    const login = await req('/auth/login', { headers: { 'Sec-Fetch-Site': 'same-origin' } });
    const signInCookie = cookie(login, '__Host-ks_oidc')!.split(';')[0]!;
    const query = idp.authorize(login.headers.location!, user);
    const callback = await req(`/auth/callback?${query}`, { headers: { Cookie: signInCookie, 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document' } });
    const session = cookie(callback, '__Host-ks_session');
    if (callback.status !== 200 || !session) return { callback, auth: null };
    const auth = { cookie: session.split(';')[0]!, csrf: '' };
    auth.csrf = (await req('/api/session', { headers: { Cookie: auth.cookie } })).json.csrf;
    return { callback, auth };
  }
  const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
    req(path, { method: 'POST', body: JSON.stringify(body), headers: { Origin: PUBLIC_ORIGIN, 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin', ...headers } });
  const authed = (path: string, auth: { cookie: string; csrf: string }, body: unknown, headers: Record<string, string> = {}) =>
    post(path, body, { Cookie: auth.cookie, 'X-CSRF-Token': auth.csrf, ...headers });
  return { dashboard, idp, members, store, audit, handlers, replies, req, post, authed, signIn, advance(ms: number) { now += ms; }, now: () => now };
}

describe('single sign-on pinned to issuer and subject', () => {
  const identity = (subject: string, email?: string, emailVerified = true) => ({ issuer: ISSUER, subject, ...(email ? { email } : {}), emailVerified });

  it('maps a pinned member by (iss, sub) only, and unpinned members by verified email', () => {
    const members = roster();
    expect(memberForIdentity(identity('sub-ana'), members).id).toBe('ana');
    expect(memberForIdentity(identity('sub-ana', 'someone-else@example.test', false), members).id).toBe('ana');
    // A reassigned address: same email, another subject.
    expect(() => memberForIdentity(identity('sub-new-owner', 'ana@example.test'), members)).toThrow(expect.objectContaining({ reason: 'identity-mismatch' }));
    expect(() => memberForIdentity({ ...identity('sub-ana'), issuer: 'https://other-idp.example.test' }, members)).toThrow(expect.objectContaining({ reason: 'email-missing' }));
    expect(memberForIdentity(identity('sub-anything', 'BEN@example.test'), members).id).toBe('ben');
    expect(() => memberForIdentity(identity('sub-ben', 'ben@example.test', false), members)).toThrow(expect.objectContaining({ reason: 'email-unverified' }));
  });

  it('signs a pinned member in, refuses a reassigned email, shows (iss, sub) on the account page and ends the session when the pin changes', async () => {
    const t = await startTeam();
    const { auth } = await t.signIn({ sub: 'sub-ana', email: 'ana@example.test', email_verified: true });
    const session = await t.req('/api/session', { headers: { Cookie: auth!.cookie } });
    expect(session.json).toMatchObject({ team: true, member: { id: 'ana', role: 'admin' }, identity: { issuer: ISSUER, subject: 'sub-ana', pinned: true } });

    const reassigned = await t.signIn({ sub: 'sub-new-owner', email: 'ana@example.test', email_verified: true });
    expect(reassigned.auth).toBeNull();
    expect(reassigned.callback.status).toBe(403);
    expect(reassigned.callback.text).toContain('does not match the identity pinned for that team member');

    // Ben signs in by email; his account page offers the exact pin command.
    const ben = await t.signIn({ sub: 'sub-ben', email: 'ben@example.test', email_verified: true });
    expect((await t.req('/api/session', { headers: { Cookie: ben.auth!.cookie } })).json.identity).toEqual({ issuer: ISSUER, subject: 'sub-ben', pinned: false });
    // An admin pins Ben to another subject: his email-based session ends on the next request.
    t.members[1]!.sso = { issuer: ISSUER, subject: 'sub-ben-new' };
    expect((await t.req('/api/session', { headers: { Cookie: ben.auth!.cookie } })).status).toBe(401);
    // Pinned to the subject he signed in with, a fresh session works.
    t.members[1]!.sso = { issuer: ISSUER, subject: 'sub-ben' };
    const again = await t.signIn({ sub: 'sub-ben', email: 'ben@example.test', email_verified: true });
    expect((await t.req('/api/session', { headers: { Cookie: again.auth!.cookie } })).json.identity.pinned).toBe(true);
    for (const reply of t.replies) expect(reply.text).not.toMatch(/access-token-planted|client-secret-planted/);
  });
});

describe('passkey enrollment for the team dashboard host', () => {
  it('serves /enroll with credential creation allowed only there, and turns a valid link into an inert candidate', async () => {
    const t = await startTeam();
    const page = await t.req('/enroll', { headers: { 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document' } });
    expect(page.status).toBe(200);
    expect(page.headers['permissions-policy']).toBe('publickey-credentials-create=(self), publickey-credentials-get=()');
    expect(page.text).toContain('src="/enroll/app.js"');
    expect((await t.req('/enroll/app.js')).text).toContain('/enroll/options');
    // Every other page still blocks credential creation.
    expect((await t.req('/')).headers['permissions-policy']).toBe('publickey-credentials-get=(self), publickey-credentials-create=()');

    const { token } = await createInvite(t.store, { memberId: 'ben', origin: PUBLIC_ORIGIN, now: new Date(t.now()) });
    const options = await t.post('/enroll/options', { token });
    expect(options.status).toBe(200);
    expect(options.json.member).toEqual({ id: 'ben', name: 'Ben' });
    expect(options.json.publicKey).toMatchObject({ rp: { id: PUBLIC_HOST }, attestation: 'none', authenticatorSelection: { userVerification: 'required' } });
    const authenticator = createEnrollingAuthenticator(PUBLIC_HOST, { aaguid: Buffer.alloc(16, 0xab) });
    const finished = await t.post('/enroll/finish', { token, ...authenticator.register(options.json.publicKey.challenge, PUBLIC_ORIGIN) });
    expect(finished.status).toBe(200);
    expect(finished.json).toEqual({ enrolled: true, member: 'ben', credentialId: authenticator.id, next: `Ask a team admin to run: keysentry team add-passkey ben ${authenticator.id}` });
    const [candidate] = await listCandidates(t.store);
    expect(candidate).toMatchObject({ memberId: 'ben', aaguid: 'ab'.repeat(16), credential: { id: authenticator.id, rpId: PUBLIC_HOST, origins: [PUBLIC_ORIGIN] } });
    expect(t.audit.map(event => event.kind)).toContain('team:passkey-enrolled');
    // The token never comes back in any response.
    for (const reply of t.replies) expect(reply.text).not.toContain(token);

    // A second use of the link is refused.
    expect(await t.post('/enroll/options', { token })).toMatchObject({ status: 409, json: { error: expect.stringMatching(/already been used/) } });

    // The candidate is inert: Ben has no passkey for this dashboard until the signed roster lists it.
    const ben = await t.signIn({ sub: 'sub-ben', email: 'ben@example.test', email_verified: true });
    expect((await t.req('/api/session', { headers: { Cookie: ben.auth!.cookie } })).json.passkeys).toBe(0);
    const body = { plan: 'p1' };
    const refused = await t.authed('/api/passkey/challenge', ben.auth!, { route: 'rotate', bodyDigest: digest(body) });
    expect(refused).toMatchObject({ status: 403, json: { error: 'Ask a team admin to add your passkey to the team roster, then reload this page.' } });
    expect(t.handlers.write).not.toHaveBeenCalled();

    // Admins add it to the roster (here, the verified roster the dashboard reads); now it confirms Ben's change.
    t.members[1]!.passkeys.push(candidate!.credential);
    const challenge = await t.authed('/api/passkey/challenge', ben.auth!, { route: 'rotate', bodyDigest: digest(body) });
    expect(challenge.status).toBe(200);
    const change = await t.authed('/api/rotate', ben.auth!, body, { 'X-Passkey-Assertion': authenticator.assertionHeader(challenge.json.challenge, PUBLIC_ORIGIN) });
    expect(change.status).toBe(200);
    expect(t.handlers.write).toHaveBeenCalledTimes(1);
  });

  it('refuses expired, unknown, other-origin and other-member links, a failed ceremony and a wrong RP ID', async () => {
    const t = await startTeam();
    const expired = await createInvite(t.store, { memberId: 'ben', origin: PUBLIC_ORIGIN, now: new Date(t.now() - INVITE_TTL_MS - 1) });
    expect(await t.post('/enroll/options', { token: expired.token })).toMatchObject({ status: 410, json: { error: expect.stringMatching(/expired/) } });
    expect((await t.post('/enroll/options', { token: 'A'.repeat(43) })).status).toBe(403);
    expect((await t.post('/enroll/options', { token: 'not-a-token' })).status).toBe(400);
    const elsewhere = await createInvite(t.store, { memberId: 'ben', origin: 'https://other.example.test', now: new Date(t.now()) });
    expect((await t.post('/enroll/options', { token: elsewhere.token })).status).toBe(403);
    const gone = await createInvite(t.store, { memberId: 'zed', origin: PUBLIC_ORIGIN, now: new Date(t.now()) });
    expect(await t.post('/enroll/options', { token: gone.token })).toMatchObject({ status: 403, json: { error: expect.stringMatching(/no longer on the team roster/) } });

    const valid = await createInvite(t.store, { memberId: 'ben', origin: PUBLIC_ORIGIN, now: new Date(t.now()) });
    // Finishing without a started ceremony is refused, and does not use the link.
    const authenticator = createEnrollingAuthenticator(PUBLIC_HOST);
    expect((await t.post('/enroll/finish', { token: valid.token, ...authenticator.register('AAAA', PUBLIC_ORIGIN) })).status).toBe(409);
    // A credential for another RP ID (a localhost passkey) fails verification; the ceremony must start again.
    const options = await t.post('/enroll/options', { token: valid.token });
    const wrong = await t.post('/enroll/finish', { token: valid.token, ...authenticator.register(options.json.publicKey.challenge, PUBLIC_ORIGIN, 'localhost') });
    expect(wrong).toMatchObject({ status: 400, json: { error: expect.stringMatching(/could not be verified/) } });
    expect((await t.post('/enroll/finish', { token: valid.token, ...authenticator.register(options.json.publicKey.challenge, PUBLIC_ORIGIN) })).status).toBe(409);
    // Without user verification the passkey is refused.
    const again = await t.post('/enroll/options', { token: valid.token });
    const noUv = createEnrollingAuthenticator(PUBLIC_HOST, { uv: false });
    expect((await t.post('/enroll/finish', { token: valid.token, ...noUv.register(again.json.publicKey.challenge, PUBLIC_ORIGIN) })).status).toBe(400);
    // Cross-site and wrong-Origin posts are refused before the token is looked at.
    expect((await t.post('/enroll/options', { token: valid.token }, { Origin: 'https://evil.example' })).status).toBe(403);
    expect((await t.post('/enroll/options', { token: valid.token }, { 'Sec-Fetch-Site': 'cross-site' })).status).toBe(403);
    expect(await listCandidates(t.store)).toEqual([]);
  });

  it('rate-limits enrollment requests', async () => {
    const t = await startTeam();
    const statuses: number[] = [];
    for (let i = 0; i < 31; i++) statuses.push((await t.post('/enroll/options', { token: 'B'.repeat(43) })).status);
    expect(statuses.slice(0, 30).every(status => status === 403)).toBe(true);
    expect(statuses[30]).toBe(429);
    t.advance(60_000);
    expect((await t.post('/enroll/options', { token: 'B'.repeat(43) })).status).toBe(403);
  });

  it('does not exist without enrollment hooks, nor on the local dashboard', async () => {
    const t = await startTeam({ enrollment: false });
    expect((await t.req('/enroll')).status).toBe(404);
    const local = await startDashboard({ api: {}, readOnly: false });
    running.push(local);
    const reply = await new Promise<Reply>((resolve, reject) => {
      const request = httpRequest({ hostname: '127.0.0.1', port: local.port, path: '/enroll', headers: { Host: `localhost:${local.port}` } }, res => {
        let text = ''; res.setEncoding('utf8'); res.on('data', chunk => { text += chunk; });
        res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, text, json: JSON.parse(text) }));
      });
      request.on('error', reject); request.end();
    });
    expect(reply.status).toBe(404);
    expect(reply.json.error).toMatch(/only on the team dashboard/);
    expect(reply.headers['permissions-policy']).toBe('publickey-credentials-get=(self), publickey-credentials-create=()');
  });
});
