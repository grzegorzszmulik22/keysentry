import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { isIP } from 'node:net';
import { decodeCbor, parseAuthData, verifyRegistration } from '../../approvals/webauthn/index.js';
import type { PasskeyCredential, TeamMember, TeamRole } from '../../types.js';
import { ASSETS } from '../generated/assets.js';
import type { OidcClient } from '../oidc/client.js';
import { OIDC_MESSAGES, OidcError, type OidcFailure } from '../oidc/errors.js';
import { isTeamRole, memberForIdentity, normalizeEmail, pinnedTo } from '../oidc/members.js';
import { candidateFingerprint } from '../../team/enrollment.js';
import { createLoginTransactions } from '../oidc/transactions.js';
import { apiRoute, bodyDigest, DashboardAccepted, needsTeamPasskey, validateApi } from './api.js';
import { createPasskeyGate, PasskeyGateError, type PasskeyStore } from './passkey-gate.js';
import { CSP, DashboardError, json, operationalError, readJson, securityHeaders } from './security.js';
import type { DashboardOptions } from './server.js';
import { sameToken } from './session.js';
import {
  allows, createTeamSessions, memberPasskeys, memberPasskeyStore, readCookie, requiredRole,
  TEAM_PASSKEY_NOTICE, TEAM_SESSION_COOKIE, TEAM_SIGN_IN_COOKIE, type PasskeyCounterStore, type TeamSession,
} from './team.js';

/** Value-free sign-in events for the audit log. */
export type TeamAuthEvent =
  | { kind: 'sign-in'; memberId: string; role: TeamRole }
  /** Anonymous traffic can cause refusals, so at most ten are reported per minute; `suppressed` counts the rest. */
  | { kind: 'sign-in-refused'; reason: OidcFailure; suppressed?: number }
  | { kind: 'sign-out'; memberId: string }
  | { kind: 'session-ended'; memberId: string; reason: 'roster' };

export interface TeamDashboardOptions {
  /** The https origin members open, e.g. https://keysentry.example.com. Also the passkey RP ID host. */
  publicOrigin: string;
  /** The interface behind the team's TLS-terminating proxy. */
  listen: { host: string; port: number };
  /** Its redirect URI must be `${publicOrigin}/auth/callback`. */
  oidc: OidcClient;
  /** Current roster members (from the verified signed roster). Read on every request; failures deny. */
  members(): Promise<TeamMember[]>;
  passkeyCounters: PasskeyCounterStore;
  /** Absolute session lifetime (default 8 hours). The idle lifetime is `DashboardOptions.idleMs` (default 30 minutes). */
  absoluteMs?: number;
  maxSessions?: number;
  /** Minimum roles per route on top of `TEAM_ROUTE_ROLES`; mutating routes never drop below operator. */
  routeRoles?: Readonly<Record<string, TeamRole>>;
  onAuthEvent?: (event: TeamAuthEvent) => void | Promise<void>;
  /**
   * Passkey enrollment for this public host (`/enroll`). Without it the route does not exist. The hooks check and use
   * single-use invitations created by an admin's terminal; they throw `DashboardError` with fixed text to refuse.
   */
  enrollment?: TeamEnrollmentHooks;
}

/** Invitation checks for `/enroll`, backed by encrypted project state (src/team/enrollment.ts). */
export interface TeamEnrollmentHooks {
  /** The member a valid, unexpired, unused invitation for this origin was made for. */
  check(token: string): Promise<{ memberId: string }>;
  /** Use the invitation once and keep the verified public credential as a pending candidate. Grants nothing. */
  complete(input: { token: string; memberId: string; credential: PasskeyCredential; aaguid: string | null }): Promise<void>;
  onEvent?: (event: { kind: 'passkey-enrolled'; memberId: string } | { kind: 'enrollment-refused' }) => void | Promise<void>;
}

/** Permissions-Policy for the enrollment page only: it may create a credential, and nothing else may. */
const ENROLL_PERMISSIONS = 'publickey-credentials-create=(self), publickey-credentials-get=()';
const ENROLL_PAGE = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>Add a passkey · keysentry</title><script type="module" src="/enroll/app.js"></script></head><body><main><h1>Add a passkey for the team dashboard</h1><p id="enroll-intro">This page creates a passkey for this dashboard. It grants nothing by itself: a team admin adds it to the signed team roster.</p><button id="enroll-start" type="button" disabled>Create passkey</button><p id="enroll-status" role="status" aria-live="polite">Checking your enrollment link.</p></main><noscript>Enable JavaScript to add a passkey.</noscript></body></html>';
const ENROLL_LIMIT = 30;
const CEREMONY_MS = 5 * 60_000;
const tokenDigest = (token: string) => createHash('sha256').update(`keysentry-enroll-ceremony\n${token}`).digest('hex');

const NOT_AVAILABLE = 'This page is not available.';
const SIGN_IN_AGAIN = 'Sign in again to continue.';
const WRONG_SITE = 'Send this request from the team dashboard.';
const READ_ONLY = 'This dashboard was started read-only. Changes are unavailable.';
const VIEWER = 'Your team role can read this dashboard but not make changes.';
const ROLE = 'Your team role does not allow this action.';

const escapeHtml = (text: string) => text.replace(/[&<>"']/g, character => `&#${character.charCodeAt(0)};`);
function page(title: string, body: string, head = ''): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">${head}<title>keysentry</title></head><body><main><h1>${escapeHtml(title)}</h1>${body}</main></body></html>`;
}
const START_PAGE = page('keysentry', '<p>Sign in with your team’s identity provider to open the dashboard.</p><p><a href="/auth/login">Sign in</a></p>');
// The session cookie is SameSite=Strict, so the first request after the provider's cross-site redirect would not
// carry it. A same-origin refresh from this page does.
const SIGNED_IN_PAGE = page('Signed in', '<p>You are signed in.</p><p><a href="/">Open the dashboard</a></p>', '<meta http-equiv="refresh" content="0;url=/">');
const refusedPage = (message: string) => page('Sign-in not completed', `<p>${escapeHtml(message)}</p><p><a href="/auth/login">Sign in again</a></p>`);

function html(res: ServerResponse, status: number, body: string): void {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(body);
}

function rawRefusal(status: string, message: string): string {
  return `HTTP/1.1 ${status}\r\nContent-Security-Policy: ${CSP}\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCache-Control: no-store\r\nX-Frame-Options: DENY\r\nCross-Origin-Resource-Policy: same-origin\r\nCross-Origin-Opener-Policy: same-origin\r\nPermissions-Policy: publickey-credentials-get=(self), publickey-credentials-create=()\r\nStrict-Transport-Security: max-age=31536000\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n${JSON.stringify({ error: message })}`;
}

function checkPublicOrigin(value: string): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error('Use the team dashboard’s https origin, for example https://keysentry.example.com.'); }
  if (url.protocol !== 'https:' || url.origin !== value || !url.hostname || isIP(url.hostname.replace(/^\[|\]$/g, '')) !== 0) {
    throw new Error('Use the team dashboard’s https origin, for example https://keysentry.example.com.');
  }
  return url;
}

const refusalStatus = (reason: OidcFailure): number =>
  reason === 'state' ? 400 : reason === 'unavailable' || reason === 'roster-unavailable' ? 503
    : reason === 'not-member' || reason === 'email-missing' || reason === 'email-unverified' || reason === 'identity-mismatch' ? 403
      : reason === 'configuration' ? 500 : 401;

export async function startTeamDashboard(opts: DashboardOptions, team: TeamDashboardOptions): Promise<{ url: string; port: number; close(): Promise<void> }> {
  validateApi(opts.api);
  const publicUrl = checkPublicOrigin(team.publicOrigin);
  const origin = publicUrl.origin;
  const publicHost = publicUrl.host;
  const rpId = publicUrl.hostname;
  if (!team.oidc || team.oidc.redirectUri !== `${origin}/auth/callback`) throw new Error('Register the OIDC redirect address as the public origin followed by /auth/callback.');
  if (typeof team.members !== 'function' || !team.passkeyCounters || typeof team.passkeyCounters.read !== 'function' || typeof team.passkeyCounters.write !== 'function') {
    throw new Error('Connect the team roster and passkey counters before starting the team dashboard.');
  }
  const { host, port: listenPort } = team.listen ?? {};
  if (typeof host !== 'string' || !host || host.length > 255 || !Number.isInteger(listenPort) || listenPort < 0 || listenPort > 65535) {
    throw new Error('Choose the interface and port the team dashboard listens on.');
  }
  const idleMs = opts.idleMs ?? 30 * 60_000;
  const absoluteMs = team.absoluteMs ?? 8 * 60 * 60_000;
  for (const value of [idleMs, absoluteMs]) {
    if (!Number.isFinite(value) || value <= 0 || value > 2_147_483_647) throw new Error('Choose positive team session lifetimes.');
  }
  const now = opts.now ?? Date.now;
  const sessions = createTeamSessions({ idleMs, absoluteMs, max: team.maxSessions, now });
  const transactions = createLoginTransactions({ now });
  const noStore: PasskeyStore = {
    list: async () => [],
    add: async () => { throw new DashboardError(409, TEAM_PASSKEY_NOTICE); },
    update: async () => { throw new DashboardError(409, TEAM_PASSKEY_NOTICE); },
  };
  const gate = createPasskeyGate({ passkeys: noStore, origin, rpId, noPasskeyMessage: TEAM_PASSKEY_NOTICE, now });
  const clearSignIn = `${TEAM_SIGN_IN_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`;
  const clearSession = `${TEAM_SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`;

  const refusals = { windowStart: Number.NEGATIVE_INFINITY, count: 0, suppressed: 0 };
  function emit(event: TeamAuthEvent): void {
    if (event.kind === 'sign-in-refused') {
      const time = now();
      if (time - refusals.windowStart >= 60_000) { refusals.windowStart = time; refusals.count = 0; }
      if (refusals.count >= 10) { refusals.suppressed++; return; }
      refusals.count++;
      if (refusals.suppressed > 0) { event = { ...event, suppressed: refusals.suppressed }; refusals.suppressed = 0; }
    }
    try { void Promise.resolve(team.onAuthEvent?.(event)).catch(() => {}); } catch { /* Reporting never changes a response. */ }
  }
  function report(errorClass: string): void {
    try { opts.onError?.(errorClass); } catch { /* Reporting must not interrupt the fixed response. */ }
  }

  // ---------------------------------------------------------------------------------------------- passkey enrollment
  // The invitation token travels in the URL fragment (never sent with the page request, never in a log) and is posted
  // by the page. Each check returns a ceremony bound to the invited member; the verified public credential becomes a
  // pending candidate that only a signed roster change can make usable.
  const ceremonies = new Map<string, { challenge: Buffer; memberId: string; expires: number }>();
  const enrollWindow = { start: Number.NEGATIVE_INFINITY, count: 0 };
  function enrollEvent(event: Parameters<NonNullable<TeamEnrollmentHooks['onEvent']>>[0]): void {
    try { void Promise.resolve(team.enrollment?.onEvent?.(event)).catch(() => {}); } catch { /* Reporting never changes a response. */ }
  }
  function enrollRate(): void {
    const time = now();
    if (time - enrollWindow.start >= 60_000) { enrollWindow.start = time; enrollWindow.count = 0; }
    if (++enrollWindow.count > ENROLL_LIMIT) throw new DashboardError(429, 'Too many enrollment attempts. Wait a minute, then try again.');
  }
  function enrollToken(input: unknown): string {
    const token = (input as { token?: unknown } | null)?.token;
    // A signed invitation: base64url payload, a dot, and the admin's base64url signature (src/team/enrollment.ts).
    if (typeof token !== 'string' || token.length > 2200 || !/^[A-Za-z0-9_-]{16,2048}\.[A-Za-z0-9_-]{86}$/.test(token)) {
      throw new DashboardError(400, 'This enrollment link is not valid. Ask a team admin for a new one (keysentry team invite).');
    }
    return token;
  }
  function decodeField(value: unknown, maxBytes: number): Buffer {
    if (typeof value !== 'string' || !value.length || value.length > Math.ceil(maxBytes * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) {
      throw new DashboardError(400, 'The passkey could not be verified. Open your enrollment link again.');
    }
    const bytes = Buffer.from(value, 'base64url');
    if (bytes.length > maxBytes || bytes.toString('base64url') !== value) throw new DashboardError(400, 'The passkey could not be verified. Open your enrollment link again.');
    return bytes;
  }
  async function enrollMember(memberId: string): Promise<TeamMember> {
    let members: TeamMember[];
    try { members = await team.members(); } catch { throw new DashboardError(503, 'The team roster could not be read. Try again in a moment.'); }
    const matches = Array.isArray(members) ? members.filter(member => member && member.id === memberId && isTeamRole(member.role)) : [];
    if (matches.length !== 1) throw new DashboardError(403, 'This enrollment link is for someone who is no longer on the team roster.');
    return matches[0]!;
  }
  async function enroll(req: IncomingMessage, res: ServerResponse, path: string): Promise<void> {
    const hooks = team.enrollment;
    if (!hooks) throw new DashboardError(404, NOT_AVAILABLE);
    if (req.method === 'GET' && path === '/enroll') {
      res.setHeader('Permissions-Policy', ENROLL_PERMISSIONS);
      html(res, 200, ENROLL_PAGE); return;
    }
    if (req.method === 'GET' && path === '/enroll/app.js') {
      const asset = ASSETS['/app/enroll.js'];
      if (!asset) throw new DashboardError(404, NOT_AVAILABLE);
      res.writeHead(200, { 'Content-Type': asset.type }); res.end(asset.body); return;
    }
    if (path !== '/enroll/options' && path !== '/enroll/finish') throw new DashboardError(404, NOT_AVAILABLE);
    if (req.method !== 'POST') throw new DashboardError(405, 'Use POST for this request.');
    const site = req.headers['sec-fetch-site'];
    if (site !== undefined && site !== 'same-origin') throw new DashboardError(403, WRONG_SITE);
    enrollRate();
    const body = await readJson(req) as Record<string, unknown> | null;
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new DashboardError(400, 'Send a valid enrollment request.');
    try {
      const token = enrollToken(body);
      const key = tokenDigest(token);
      if (path === '/enroll/options') {
        if (Object.keys(body).length !== 1) throw new DashboardError(400, 'Send a valid enrollment request.');
        const { memberId } = await hooks.check(token);
        const member = await enrollMember(memberId);
        const time = now();
        for (const [id, entry] of ceremonies) if (entry.expires <= time) ceremonies.delete(id);
        if (!ceremonies.has(key) && ceremonies.size >= 100) throw new DashboardError(429, 'Too many enrollments are in progress. Try again in a few minutes.');
        const challenge = randomBytes(32);
        ceremonies.set(key, { challenge, memberId, expires: time + CEREMONY_MS });
        json(res, 200, { member: { id: member.id, name: member.name }, publicKey: {
          rp: { id: rpId, name: 'keysentry' }, user: { id: randomBytes(32).toString('base64url'), name: member.id, displayName: member.name },
          challenge: challenge.toString('base64url'), pubKeyCredParams: [-8, -7, -257].map(alg => ({ type: 'public-key', alg })), timeout: 120_000,
          attestation: 'none', authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
          excludeCredentials: (Array.isArray(member.passkeys) ? member.passkeys : []).filter(credential => credential?.rpId === rpId).map(credential => ({ type: 'public-key', id: credential.id })),
        } });
        return;
      }
      const fields = ['token', 'clientDataJSON', 'attestationObject'];
      if (Object.keys(body).length !== fields.length || Object.keys(body).some(name => !fields.includes(name))) throw new DashboardError(400, 'Send a valid enrollment request.');
      // One ceremony per check: a failed verification needs a fresh start from the page.
      const ceremony = ceremonies.get(key);
      ceremonies.delete(key);
      if (!ceremony || ceremony.expires <= now()) throw new DashboardError(409, 'This enrollment step expired. Open your enrollment link again.');
      const clientDataJSON = decodeField(body.clientDataJSON, 8192);
      const attestationObject = decodeField(body.attestationObject, 32 * 1024);
      let credential: PasskeyCredential;
      let aaguid: string | null = null;
      try {
        credential = verifyRegistration({ clientDataJSON, attestationObject, expectedChallenge: ceremony.challenge, expectedOrigins: [origin], rpId, requireUserVerification: true });
        const decoded = decodeCbor(attestationObject);
        const authData = decoded instanceof Map ? decoded.get('authData') : undefined;
        const parsed = Buffer.isBuffer(authData) ? parseAuthData(authData) : undefined;
        if (parsed?.credential) aaguid = parsed.credential.aaguid.toString('hex');
      } catch { throw new DashboardError(400, 'The passkey could not be verified. Open your enrollment link again.'); }
      const member = await enrollMember(ceremony.memberId);
      if ((Array.isArray(member.passkeys) ? member.passkeys : []).some(existing => existing?.id === credential.id)) {
        throw new DashboardError(409, 'This passkey is already on the team roster.');
      }
      credential.origins = [origin];
      credential.label = 'Team dashboard passkey';
      credential.createdAt = new Date(now()).toISOString();
      await hooks.complete({ token, memberId: ceremony.memberId, credential, aaguid });
      enrollEvent({ kind: 'passkey-enrolled', memberId: ceremony.memberId });
      json(res, 200, { enrolled: true, member: ceremony.memberId, credentialId: credential.id,
        fingerprint: candidateFingerprint({ credential }),
        next: `Ask a team admin to add it: keysentry team passkeys pending -o <file> on the dashboard host, then keysentry team add-passkey ${ceremony.memberId} --card <file> on the admin's computer.` });
    } catch (error) {
      enrollEvent({ kind: 'enrollment-refused' });
      throw error;
    }
  }

  /** Forwarded headers are ignored: the proxy must pass the browser's Host through unchanged. */
  function checkHost(req: IncomingMessage): void {
    if (req.headers.host !== publicHost) throw new DashboardError(403, 'Open keysentry at its team address.');
  }
  /** Only top-level document navigations to `/` and the sign-in callback may arrive from another site. */
  function checkSite(req: IncomingMessage, navigation: boolean): void {
    const site = req.headers['sec-fetch-site'];
    if (site === undefined || site === 'same-origin' || site === 'none') return;
    if (navigation && (site === 'cross-site' || site === 'same-site')) {
      const mode = req.headers['sec-fetch-mode'];
      const dest = req.headers['sec-fetch-dest'];
      if ((mode === undefined || mode === 'navigate') && (dest === undefined || dest === 'document')) return;
    }
    throw new DashboardError(403, WRONG_SITE);
  }

  /** Authenticate the cookie, then re-check the member against the current roster on every request. */
  async function current(req: IncomingMessage, res: ServerResponse): Promise<{ session: TeamSession; member: TeamMember } | null> {
    const session = sessions.authenticate(req.headers.cookie);
    if (!session) return null;
    const members = await team.members();
    const matches = Array.isArray(members) ? members.filter(member => member && member.id === session.memberId) : [];
    const member = matches.length === 1 ? matches[0]! : undefined;
    // A pinned member must keep the exact issuer and subject; others must keep the verified email that signed in.
    const sameIdentity = member !== undefined && (member.sso !== undefined ? pinnedTo(member, session.issuer, session.subject)
      : typeof member.email === 'string' && session.email !== null && normalizeEmail(member.email) === session.email);
    if (!member || !sameIdentity || !isTeamRole(member.role)) {
      sessions.remove(session.id);
      res.setHeader('Set-Cookie', clearSession);
      emit({ kind: 'session-ended', memberId: session.memberId, reason: 'roster' });
      return null;
    }
    return { session, member };
  }

  async function login(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (await current(req, res)) { res.writeHead(303, { Location: '/' }); res.end(); return; }
    let authorization;
    try { authorization = await team.oidc.authorize(); }
    catch (error) {
      const reason: OidcFailure = error instanceof OidcError ? error.reason : 'unavailable';
      emit({ kind: 'sign-in-refused', reason });
      html(res, refusalStatus(reason), refusedPage(OIDC_MESSAGES[reason]));
      return;
    }
    const transaction = transactions.create({ state: authorization.state, nonce: authorization.nonce, verifier: authorization.verifier });
    // Lax so the provider's top-level redirect back carries it; HttpOnly, host-only and short-lived.
    res.setHeader('Set-Cookie', `${TEAM_SIGN_IN_COOKIE}=${transaction.id}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(transactions.lifetimeMs / 1000)}`);
    res.writeHead(303, { Location: authorization.url });
    res.end();
  }

  async function callback(req: IncomingMessage, res: ServerResponse, query: string): Promise<void> {
    const refuse = (reason: OidcFailure, cookies: string[] = [clearSignIn]) => {
      emit({ kind: 'sign-in-refused', reason });
      res.setHeader('Set-Cookie', cookies);
      html(res, refusalStatus(reason), refusedPage(OIDC_MESSAGES[reason]));
    };
    // Single use: the transaction is consumed before anything else is checked, whatever the outcome.
    const transaction = transactions.take(readCookie(req.headers.cookie, TEAM_SIGN_IN_COOKIE));
    if (!transaction) return refuse('state');
    if (query.length > 8192) return refuse('provider-error');
    const params = new URLSearchParams(query);
    for (const name of new Set(params.keys())) if (params.getAll(name).length !== 1) return refuse('provider-error');
    const value = (name: string) => params.get(name) ?? undefined;
    let member: TeamMember;
    let identity: Awaited<ReturnType<OidcClient['complete']>>;
    try {
      identity = await team.oidc.complete({ code: value('code'), state: value('state'), iss: value('iss'), error: value('error') }, transaction);
      let members: TeamMember[];
      try { members = await team.members(); } catch { return refuse('roster-unavailable'); }
      if (!Array.isArray(members)) return refuse('roster-unavailable');
      member = memberForIdentity(identity, members);
    } catch (error) {
      return refuse(error instanceof OidcError ? error.reason : 'unavailable');
    }
    const previous = sessions.authenticate(req.headers.cookie);
    if (previous) sessions.remove(previous.id);
    const email = identity.email !== undefined && identity.emailVerified === true ? normalizeEmail(identity.email) : null;
    const session = sessions.create({ memberId: member.id, email, issuer: identity.issuer, subject: identity.subject });
    res.setHeader('Set-Cookie', [clearSignIn, `${TEAM_SESSION_COOKIE}=${session.id}; Path=/; Secure; HttpOnly; SameSite=Strict`]);
    emit({ kind: 'sign-in', memberId: member.id, role: member.role });
    html(res, 200, SIGNED_IN_PAGE);
  }

  function logout(req: IncomingMessage, res: ServerResponse): void {
    req.resume();
    const session = sessions.authenticate(req.headers.cookie);
    if (session) {
      const csrf = req.headers['x-csrf-token'];
      if (typeof csrf !== 'string' || !sameToken(csrf, session.csrf)) throw new DashboardError(403, 'Reload the dashboard before signing out.');
      sessions.remove(session.id);
      emit({ kind: 'sign-out', memberId: session.memberId });
    }
    res.setHeader('Set-Cookie', clearSession);
    json(res, 200, { signedOut: true });
  }

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    securityHeaders(res);
    // Browsers only reach the team dashboard over the proxy's TLS; keep them there.
    res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    try {
      checkHost(req);
      const target = req.url ?? '';
      if (!target.startsWith('/') || target.startsWith('//') || target.includes('#')) throw new DashboardError(404, NOT_AVAILABLE);
      if (req.method !== 'GET' && req.method !== 'POST') throw new DashboardError(405, 'Use GET or POST for this request.');
      const mark = target.indexOf('?');
      const path = mark === -1 ? target : target.slice(0, mark);
      checkSite(req, req.method === 'GET' && (path === '/' || path === '/auth/callback' || path === '/enroll'));
      if (req.method === 'POST' && req.headers.origin !== origin) throw new DashboardError(403, WRONG_SITE);
      // Enrollment needs no session: the invitation is the authority, and the result grants nothing on its own.
      if (path === '/enroll' || path.startsWith('/enroll/')) {
        if (mark !== -1) throw new DashboardError(404, NOT_AVAILABLE);
        return await enroll(req, res, path);
      }
      if (path === '/auth/callback') {
        if (req.method !== 'GET') throw new DashboardError(405, 'Use GET for this request.');
        return await callback(req, res, mark === -1 ? '' : target.slice(mark + 1));
      }
      // The one-time link (`/?t=`) and every other query string are refused in team mode.
      if (mark !== -1) throw new DashboardError(404, NOT_AVAILABLE);
      if (path === '/auth/login') {
        if (req.method !== 'GET') throw new DashboardError(405, 'Use GET for this request.');
        return await login(req, res);
      }
      if (path === '/auth/logout') {
        if (req.method !== 'POST') throw new DashboardError(405, 'Use POST for this request.');
        return logout(req, res);
      }
      const signedIn = await current(req, res);
      if (req.method === 'GET' && path === '/' && !signedIn) { html(res, 200, START_PAGE); return; }
      if (!signedIn) throw new DashboardError(401, SIGN_IN_AGAIN);
      const { session, member } = signedIn;
      if (req.method === 'GET' && (path === '/' || path.startsWith('/app/'))) {
        const asset = Object.hasOwn(ASSETS, path) ? ASSETS[path] : undefined;
        if (!asset) throw new DashboardError(404, NOT_AVAILABLE);
        res.writeHead(200, { 'Content-Type': asset.type }); res.end(asset.body); return;
      }
      if (!path.startsWith('/api/')) throw new DashboardError(404, NOT_AVAILABLE);
      const name = path.slice('/api/'.length);
      const scoped = memberPasskeyStore(member, rpId, origin, team.passkeyCounters);
      if (name === 'session') {
        if (req.method !== 'GET') throw new DashboardError(405, 'Use GET for this request.');
        json(res, 200, {
          csrf: session.csrf, readOnly: opts.readOnly || member.role === 'viewer', passkeys: memberPasskeys(member, rpId, origin).length,
          team: true, member: { id: member.id, name: member.name, role: member.role },
          // Shown on the account page so an admin can pin it: keysentry team sso <member> --issuer ... --subject ...
          identity: { issuer: session.issuer, subject: session.subject, pinned: member.sso !== undefined },
        });
        return;
      }
      if (req.method === 'POST') {
        const csrf = req.headers['x-csrf-token'];
        if (typeof csrf !== 'string' || !sameToken(csrf, session.csrf)) throw new DashboardError(403, 'Reload the dashboard before making this change.');
      }
      const builtIn = name === 'passkey/challenge';
      const route = apiRoute(opts.api, name);
      if (!builtIn && !route) throw new DashboardError(404, 'This action is not available.');
      if (req.method !== (builtIn ? 'POST' : route!.method)) throw new DashboardError(405, 'Use the method provided for this action.');
      // The identity provider only says who someone is; the roster says what they may do.
      const needed = builtIn ? 'operator' : requiredRole(name, route!, team.routeRoles);
      if (!allows(member.role, needed)) throw new DashboardError(403, member.role === 'viewer' ? VIEWER : ROLE);
      // Disarm (a passkey-confirmed, non-mutating route) stays available on a read-only team dashboard.
      if (opts.readOnly && (builtIn ? false : route!.mutating)) throw new DashboardError(403, READ_ONLY);
      const body = req.method === 'POST' ? await readJson(req) : undefined;
      const proof = req.headers['x-passkey-assertion'];
      if (Array.isArray(proof)) throw new DashboardError(403, 'Confirm this action with your passkey.');
      if (builtIn) {
        const input = body as { route?: unknown; bodyDigest?: unknown } | null;
        if (!input || Array.isArray(input) || typeof input.route !== 'string' || typeof input.bodyDigest !== 'string' || !/^[0-9a-f]{64}$/.test(input.bodyDigest)) {
          throw new DashboardError(400, 'Choose an action and its JSON body digest.');
        }
        const action = apiRoute(opts.api, input.route);
        if (!action || action.method !== 'POST' || !needsTeamPasskey(action)) throw new DashboardError(400, 'Choose an action that requires a passkey.');
        if (opts.readOnly && action.mutating) throw new DashboardError(403, READ_ONLY);
        if (!allows(member.role, requiredRole(input.route, action, team.routeRoles))) throw new DashboardError(403, ROLE);
        json(res, 200, await gate.challenge(session.id, input.route, input.bodyDigest, scoped)); return;
      }
      // Every change, and disarm, needs this member's own passkey over this exact request; nobody else's credential is
      // offered or accepted. The identity provider session alone can only read (review M3).
      const passkey = needsTeamPasskey(route!) ? await gate.verify(session.id, name, bodyDigest(body), proof, scoped) : undefined;
      const result = await route!.handler(body, { session: session.id, member: { id: member.id, role: member.role }, ...(passkey ? { passkey } : {}) });
      // A team change still collecting approvals is accepted, not done (review C1).
      if (result instanceof DashboardAccepted) json(res, 202, result.body);
      else json(res, 200, result);
    } catch (error) {
      if (res.headersSent || res.destroyed) { res.destroy(); return; }
      if (error instanceof DashboardError || error instanceof PasskeyGateError) json(res, error.status, { error: error.message });
      else {
        const { status, errorClass } = operationalError(error);
        report(errorClass);
        if (status === 503) res.setHeader('Retry-After', '2');
        json(res, status, { error: 'The request could not be completed. Try again from keysentry.' });
      }
    }
  }

  let closed: Promise<void> | undefined;
  const server = createServer({ maxHeaderSize: 16 * 1024, headersTimeout: 10_000, requestTimeout: 10_000 }, (req, res) => { void handle(req, res); });
  const close = (): Promise<void> => {
    if (closed) return closed;
    sessions.clear();
    transactions.clear();
    closed = new Promise((resolve, reject) => {
      server.close(error => { if (error && (error as NodeJS.ErrnoException).code !== 'ERR_SERVER_NOT_RUNNING') reject(error); else resolve(); });
      server.closeAllConnections();
    });
    return closed;
  };
  const refuseExpectation = (req: IncomingMessage, res: ServerResponse) => {
    securityHeaders(res);
    try { checkHost(req); json(res, 417, { error: 'Send the request without an expectation header.' }); }
    catch (error) {
      if (error instanceof DashboardError) json(res, error.status, { error: error.message });
      else json(res, 500, { error: 'The request could not be completed. Try again from keysentry.' });
    }
    req.resume();
  };
  server.on('checkContinue', refuseExpectation);
  server.on('checkExpectation', refuseExpectation);
  server.on('connect', (_req, socket) => { socket.end(rawRefusal('405 Method Not Allowed', 'Use GET or POST for this request.')); });
  server.on('clientError', (_error, socket) => { if (socket.writable) socket.end(rawRefusal('400 Bad Request', 'Send a valid HTTP request.')); });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(listenPort, host, () => { server.off('error', reject); resolve(); });
  });
  const address = server.address();
  if (!address || typeof address === 'string') { await close(); throw new Error('The team dashboard could not start.'); }
  return { url: `${origin}/`, port: address.port, close };
}
