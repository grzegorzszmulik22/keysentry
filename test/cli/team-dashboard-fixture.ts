// Shared fixture for team dashboard tests: a project with one Railway service holding one OpenRouter key, driven through
// runCli and the team dashboard (OIDC sign-in against a fake identity provider, roster passkeys) like the e2e test.
import { request as httpRequest, type IncomingHttpHeaders } from 'node:http';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCli } from '../../src/cli/index.js';
import { createRuntime } from '../../src/cli/runtime.js';
import { createDashboardApi } from '../../src/cli/dashboard-api.js';
import { enrollmentHooks } from '../../src/cli/phase3.js';
import { createOidcClient } from '../../src/dashboard/oidc/index.js';
import { createStatePasskeyCounters, startDashboard } from '../../src/dashboard/server/index.js';
import { getProvider } from '../../src/providers/index.js';
import { canonicalJson, generateDeviceKey, type DeviceKey } from '../../src/security/index.js';
import { devicePublicKey, loadTeam } from '../../src/team/index.js';
import type { AuditEvent } from '../../src/types.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { CLIENT_ID, CLIENT_SECRET, createFakeIdp, ISSUER, PUBLIC_HOST, PUBLIC_ORIGIN, REDIRECT_URI, type FakeUser } from '../dashboard/oidc/fake-idp.js';
import { createEnrollingAuthenticator } from '../dashboard/oidc/enrolling-authenticator.js';

export { PUBLIC_HOST, PUBLIC_ORIGIN };
export interface Reply { status: number; headers: IncomingHttpHeaders; text: string; json: any }
export type Authenticator = ReturnType<typeof createEnrollingAuthenticator>;
export interface Member { key: DeviceKey; passkey: Authenticator }

const cleanups: (() => Promise<void>)[] = [];
export async function cleanup(): Promise<void> {
  for (const step of cleanups.splice(0).reverse()) await step().catch(() => undefined);
}

export const digest = (body: unknown) => createHash('sha256').update(canonicalJson(body)).digest('hex');

export function card(member: Pick<Member, 'key'> & Partial<Pick<Member, 'passkey'>>): string {
  return JSON.stringify({ v: 1, kind: 'keysentry-member-card', deviceKeys: [devicePublicKey(member.key)], passkeys: member.passkey ? [member.passkey.credential([PUBLIC_ORIGIN])] : [] });
}

/** A computer with its own vault, state and keysentry.yaml. `withKey` gives it the service and the OpenRouter key. */
export async function computer(options: { yaml?: string; grace?: () => Promise<'revoke' | 'defer' | 'undo'>; zeroGrace?: boolean; now?: () => Date } = {}) {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-team-dash-'));
  cleanups.push(() => rm(cwd, { recursive: true, force: true }));
  await writeFile(join(cwd, 'keysentry.yaml'), options.yaml ?? 'rotation:\n  graceSeconds: 0\n', { mode: 0o600 });
  const vault = createFakeVault();
  const inflight = createFakeInFlight();
  const host = new FakeHost('railway'); host.pendingPolls = 0;
  const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-0123456789abcdef');
  const original = provider.issue(); host.addService('api', { OPENROUTER_API_KEY: original.value });
  let auditPath = '';
  /** Every event in this computer's audit log, as written (the runtime adds the dashboard member to each). */
  const events = async (): Promise<AuditEvent[]> => {
    let text = '';
    try { text = await readFile(auditPath, 'utf8'); } catch { return []; }
    return text.split('\n').filter(Boolean).map(line => JSON.parse(line) as AuditEvent);
  };
  const runtime = async (env: NodeJS.ProcessEnv = {}) => {
    const rt = await createRuntime({ cwd, vault, inflight, userDir: join(cwd, '.user'), env, hosts: [host], providers: id => id === provider.id ? provider : getProvider(id),
      http: new FakeHttp(), log: silentLogger, feeds: [], sleep: async () => {}, stdinIsTTY: true, stdoutIsTTY: true, grace: options.grace ?? (async () => 'revoke'), ...(options.now ? { now: options.now } : {}) });
    if (options.zeroGrace !== false) rt.config.rotation.graceMs = 0;
    auditPath = rt.paths.audit;
    return rt;
  };
  async function cli(rt: Awaited<ReturnType<typeof runtime>>, args: string[]) {
    const output: string[] = []; const errors: string[] = [];
    const code = await runCli(args, { runtime: rt, output: line => output.push(line), error: line => errors.push(line), confirmAction: async () => true,
      stdinIsTTY: true, stdoutIsTTY: true, env: {} });
    return { code, output: output.join('\n'), errors: errors.join('\n') };
  }
  return { cwd, vault, host, provider, original, events, runtime, cli, path: (file: string) => join(cwd, file) };
}
export type Computer = Awaited<ReturnType<typeof computer>>;
export type Runtime = Awaited<ReturnType<Computer['runtime']>>;

/** A member's own computer key and a passkey for the team dashboard's host. */
export function member(): Member {
  return { key: generateDeviceKey(), passkey: createEnrollingAuthenticator(PUBLIC_HOST) };
}

export async function teamDashboard(rt: Runtime) {
  const idp = createFakeIdp({ now: () => Date.now() });
  const oidc = createOidcClient({ issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, http: idp.http, clientSecret: async () => CLIENT_SECRET });
  const dashboard = await startDashboard({ api: createDashboardApi(rt), readOnly: false, team: {
    publicOrigin: PUBLIC_ORIGIN, listen: { host: '127.0.0.1', port: 0 }, oidc,
    members: async () => (await loadTeam(rt.store, { anchor: rt.teamAnchors.roster }))!.roster.roster.members,
    passkeyCounters: createStatePasskeyCounters(rt.store), enrollment: enrollmentHooks(rt, PUBLIC_ORIGIN, { diagnostic: () => {} }),
  } });
  cleanups.push(() => dashboard.close());
  function req(path: string, opts: { method?: string; headers?: Record<string, string>; body?: string } = {}): Promise<Reply> {
    return new Promise((resolve, reject) => {
      const request = httpRequest({ hostname: '127.0.0.1', port: dashboard.port, path, method: opts.method ?? 'GET', headers: { Host: PUBLIC_HOST, ...opts.headers } }, res => {
        let text = ''; res.setEncoding('utf8'); res.on('data', chunk => { text += chunk; });
        res.on('end', () => { let json: any; try { json = JSON.parse(text); } catch { /* HTML */ } resolve({ status: res.statusCode!, headers: res.headers, text, json }); });
      });
      request.on('error', reject); request.end(opts.body);
    });
  }
  const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
    req(path, { method: 'POST', body: JSON.stringify(body), headers: { Origin: PUBLIC_ORIGIN, 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin', ...headers } });
  async function signIn(user: FakeUser) {
    const login = await req('/auth/login', { headers: { 'Sec-Fetch-Site': 'same-origin' } });
    const signInCookie = (login.headers['set-cookie'] ?? []).find(value => value.startsWith('__Host-ks_oidc='))!.split(';')[0]!;
    const callback = await req(`/auth/callback?${idp.authorize(login.headers.location!, user)}`, { headers: { Cookie: signInCookie, 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document' } });
    const session = (callback.headers['set-cookie'] ?? []).find(value => value.startsWith('__Host-ks_session='));
    if (!session) return null;
    const auth = { cookie: session.split(';')[0]!, csrf: '' };
    auth.csrf = (await req('/api/session', { headers: { Cookie: auth.cookie } })).json.csrf;
    return auth;
  }
  const get = (path: string, auth: { cookie: string }) => req(path, { headers: { Cookie: auth.cookie } });
  /** A passkey-confirmed request with the member's own roster passkey, exactly as the dashboard client sends it. */
  async function change(auth: { cookie: string; csrf: string }, authenticator: Authenticator, route: string, body: unknown) {
    const headers = { Cookie: auth.cookie, 'X-CSRF-Token': auth.csrf };
    const challenge = await post('/api/passkey/challenge', { route, bodyDigest: digest(body) }, headers);
    if (challenge.status !== 200) return challenge;
    return post(`/api/${route}`, body, { ...headers, 'X-Passkey-Assertion': authenticator.assertionHeader(challenge.json.challenge, PUBLIC_ORIGIN) });
  }
  /** A POST with only the identity provider session (no passkey). */
  const plain = (auth: { cookie: string; csrf: string }, route: string, body: unknown) => post(`/api/${route}`, body, { Cookie: auth.cookie, 'X-CSRF-Token': auth.csrf });
  /** The pending item for `predicate` on the Approvals screen. */
  async function pending(auth: { cookie: string }, predicate: (item: any) => boolean) {
    return ((await get('/api/approvals', auth)).json.pending as any[]).find(predicate);
  }
  return { req, post, signIn, get, change, plain, pending };
}
