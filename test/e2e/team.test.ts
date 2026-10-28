// The whole team flow through the CLI and the team dashboard: a roster with three operators and a viewer, a signed
// policy that narrows hosts and turns on offline mode, passkey enrollment for the public host, and a rotation that
// runs only after two different operators approved it.
import { request as httpRequest, type IncomingHttpHeaders } from 'node:http';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runCli } from '../../src/cli/index.js';
import { createRuntime } from '../../src/cli/runtime.js';
import { createDashboardApi } from '../../src/cli/dashboard-api.js';
import { enrollmentHooks } from '../../src/cli/phase3.js';
import { APPROVAL_PREFIX, createApprovalService } from '../../src/approvals/index.js';
import { createOidcClient } from '../../src/dashboard/oidc/index.js';
import { createStatePasskeyCounters, startDashboard } from '../../src/dashboard/server/index.js';
import { createMonitorState } from '../../src/monitor/index.js';
import { getProvider } from '../../src/providers/index.js';
import { canonicalJson, generateDeviceKey, signDetached, type DeviceKey } from '../../src/security/index.js';
import { devicePublicKey, loadTeam } from '../../src/team/index.js';
import { deviceKey } from '../../src/vault/keys.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { CLIENT_ID, CLIENT_SECRET, createFakeIdp, ISSUER, PUBLIC_HOST, PUBLIC_ORIGIN, REDIRECT_URI, type FakeUser } from '../dashboard/oidc/fake-idp.js';
import { createEnrollingAuthenticator } from '../dashboard/oidc/enrolling-authenticator.js';

interface Reply { status: number; headers: IncomingHttpHeaders; text: string; json: any }
const dirs: string[] = [];
const servers: { close(): Promise<void> }[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => server.close()));
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});
const digest = (body: unknown) => createHash('sha256').update(canonicalJson(body)).digest('hex');

async function fixture() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-team-e2e-')); dirs.push(cwd);
  // A notification webhook the team policy's network.allowHosts does not list.
  await writeFile(join(cwd, 'keysentry.yaml'), 'monitor:\n  webhooks:\n    - https://hooks.example.test/keysentry\n', { mode: 0o600 });
  const vault = createFakeVault();
  const inflight = createFakeInFlight();
  const host = new FakeHost('railway'); host.pendingPolls = 0;
  const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-0123456789abcdef');
  const original = provider.issue(); host.addService('api', { OPENROUTER_API_KEY: original.value });
  const runtime = async () => {
    const rt = await createRuntime({ cwd, vault, inflight, userDir: join(cwd, '.user'), env: {}, hosts: [host], providers: id => id === provider.id ? provider : getProvider(id),
      http: new FakeHttp(), log: silentLogger, feeds: [], sleep: async () => {}, stdinIsTTY: true, stdoutIsTTY: true, grace: async () => 'revoke' });
    rt.config.rotation.graceMs = 0;
    return rt;
  };
  async function cli(rt: Awaited<ReturnType<typeof runtime>>, args: string[]) {
    const output: string[] = []; const errors: string[] = [];
    const code = await runCli(args, { runtime: rt, output: line => output.push(line), error: line => errors.push(line), confirmAction: async () => true,
      stdinIsTTY: true, stdoutIsTTY: true, env: {} });
    return { code, output: output.join('\n'), errors: errors.join('\n') };
  }
  return { cwd, vault, host, provider, original, runtime, cli, path: (file: string) => join(cwd, file) };
}

function card(key: DeviceKey, passkey?: ReturnType<typeof createEnrollingAuthenticator>): string {
  return JSON.stringify({ v: 1, kind: 'keysentry-member-card', deviceKeys: [devicePublicKey(key)], passkeys: passkey ? [passkey.credential([PUBLIC_ORIGIN])] : [] });
}

async function teamDashboard(rt: Awaited<ReturnType<Awaited<ReturnType<typeof fixture>>['runtime']>>) {
  const idp = createFakeIdp({ now: () => Date.now() });
  const oidc = createOidcClient({ issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, http: idp.http, clientSecret: async () => CLIENT_SECRET });
  const dashboard = await startDashboard({ api: createDashboardApi(rt), readOnly: false, team: {
    publicOrigin: PUBLIC_ORIGIN, listen: { host: '127.0.0.1', port: 0 }, oidc,
    members: async () => (await loadTeam(rt.store, { anchor: rt.teamAnchors.roster }))!.roster.roster.members,
    passkeyCounters: createStatePasskeyCounters(rt.store), enrollment: enrollmentHooks(rt, PUBLIC_ORIGIN, { diagnostic: () => {} }),
  } });
  servers.push(dashboard);
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
    if (!session) return { callback, auth: null };
    const auth = { cookie: session.split(';')[0]!, csrf: '' };
    auth.csrf = (await req('/api/session', { headers: { Cookie: auth.cookie } })).json.csrf;
    return { callback, auth };
  }
  const get = (path: string, auth: { cookie: string }) => req(path, { headers: { Cookie: auth.cookie } });
  async function approve(auth: { cookie: string; csrf: string }, authenticator: ReturnType<typeof createEnrollingAuthenticator>, body: { id: string; reviewHash: string }) {
    const headers = { Cookie: auth.cookie, 'X-CSRF-Token': auth.csrf };
    const challenge = await post('/api/passkey/challenge', { route: 'approvals/approve', bodyDigest: digest(body) }, headers);
    if (challenge.status !== 200) return challenge;
    return post('/api/approvals/approve', body, { ...headers, 'X-Passkey-Assertion': authenticator.assertionHeader(challenge.json.challenge, PUBLIC_ORIGIN) });
  }
  return { req, post, signIn, get, approve };
}

describe('team mode end to end', () => {
  it('init, members, policy, enrollment, and a rotation approved by two of three operators through the CLI and the dashboard', async () => {
    const f = await fixture();
    const ben = { key: generateDeviceKey(), passkey: createEnrollingAuthenticator(PUBLIC_HOST) };
    const cy = { key: generateDeviceKey(), passkey: createEnrollingAuthenticator(PUBLIC_HOST) };
    const vic = { key: generateDeviceKey(), passkey: createEnrollingAuthenticator(PUBLIC_HOST) };

    // ---- Ana starts the team on this computer and adds members from their public cards.
    let rt = await f.runtime();
    expect(await f.cli(rt, ['team', 'init', '--id', 'ana', '--name', 'Ana', '--email', 'ana@example.test'])).toMatchObject({ code: 0 });
    await writeFile(f.path('ben.json'), card(ben.key));
    await writeFile(f.path('cy.json'), card(cy.key, cy.passkey));
    await writeFile(f.path('vic.json'), card(vic.key, vic.passkey));
    for (const [id, role] of [['ben', 'operator'], ['cy', 'operator'], ['vic', 'viewer']] as const) {
      const added = await f.cli(rt, ['team', 'add', id, '--role', role, '--card', `${id}.json`, '--email', `${id}@example.test`]);
      expect(added).toMatchObject({ code: 0, output: expect.stringMatching(/^Roster version \d applied/) });
    }

    // ---- A signed policy: two approvals, autopilot only on Vercel, offline, and a narrow egress list.
    await writeFile(f.path('team-policy.json'), JSON.stringify({ approvals: { required: 2, wideningAdmins: 1 }, autopilot: { allowedHosts: ['vercel'] },
      network: { offline: true, allowHosts: ['idp.example.test'] } }));
    expect(await f.cli(rt, ['policy', 'sign', 'team-policy.json', '--yes'])).toMatchObject({ code: 0, output: expect.stringMatching(/\(1 of 1 admin signatures\)/) });
    expect(await f.cli(rt, ['policy', 'apply', 'team-policy.json', '--yes'])).toMatchObject({ code: 0, output: expect.stringMatching(/team\.policyFile set to team-policy\.json/) });
    expect(await readFile(f.path('keysentry.yaml'), 'utf8')).toMatch(/team:\n {2}enabled: true\n {2}policyFile: team-policy\.json/);

    // ---- The next run works inside the policy: offline from the policy, the webhook host dropped, arming refused.
    rt = await f.runtime();
    expect(rt.network.feedMode).toEqual({ offline: true, source: 'policy' });
    expect(rt.teamPolicy?.approvals.required).toBe(2);
    expect(rt.config.settings.monitor.webhooks).toEqual([]);
    expect(rt.rules.some(rule => rule.host === 'hooks.example.test')).toBe(false);
    expect(rt.rawSettings.monitor.webhooks).toEqual(['https://hooks.example.test/keysentry']);
    expect(await f.cli(rt, ['team', 'verify'])).toMatchObject({ code: 0, output: expect.stringMatching(/Policy version 1 verified/) });
    expect(await f.cli(rt, ['drill'])).toMatchObject({ code: 0 });
    const arm = await f.cli(rt, ['arm']);
    expect(arm.code).toBe(1);
    expect(arm.errors).toContain('The team policy does not let autopilot change any host this project uses, so nothing can be armed.');
    expect(arm.errors).toContain('The team policy does not let autopilot change one of the hosts that use this key.');

    // ---- Two pending rotations proposed by the monitor.
    const inventory = await rt.inventory();
    const state = createMonitorState();
    for (const id of ['action-one', 'action-two']) {
      state.pendingActions.push({ id, createdAt: new Date().toISOString(), signalId: `signal-${id}`, action: 'rotate',
        clusterIds: inventory.clusters.map(cluster => cluster.id), status: 'pending' });
    }
    await rt.store.writeJson('monitor', rt.paths.monitor, state);

    // ---- Ana approves action-two at her terminal: recorded, not run, and the CLI says what is still needed.
    const recorded = await f.cli(rt, ['approve', 'action-two', '--yes']);
    expect(recorded.code).toBe(0);
    expect(recorded.output).toBe('Your approval was recorded: 1 of 2 team approvals so far. The action runs only after 2 different team members approve it. 1 more approval from a team operator or admin who has not approved yet.');
    expect(f.provider.keys.size).toBe(1);
    // The runtime itself refuses to run a monitor action without the met quorum, whoever calls it.
    const reviewTwo = await rt.reviewAction('action-two');
    await expect(rt.approve('action-two', { interactive: false, reviewHash: reviewTwo.reviewHash, prompt: async () => null }))
      .rejects.toThrow("This action needs the team's approvals first. Approve it with keysentry approve <id> or on the team dashboard.");
    expect(f.provider.keys.size).toBe(1);

    // ---- Ben adds a passkey for the dashboard host through a single-use link; it is inert until admins sign it in.
    const dashboard = await teamDashboard(rt);
    const invite = await f.cli(rt, ['team', 'invite', 'ben', '--origin', PUBLIC_ORIGIN]);
    expect(invite).toMatchObject({ code: 0, output: expect.stringContaining(`${PUBLIC_ORIGIN}/enroll#`) });
    const token = /\/enroll#([A-Za-z0-9_-]{43})/.exec(invite.output)![1]!;
    const options = await dashboard.post('/enroll/options', { token });
    expect(options.json.member).toEqual({ id: 'ben', name: 'ben' });
    expect((await dashboard.post('/enroll/finish', { token, ...ben.passkey.register(options.json.publicKey.challenge, PUBLIC_ORIGIN) })).status).toBe(200);
    expect((await dashboard.post('/enroll/options', { token })).status).toBe(409);
    const pending = await f.cli(rt, ['team', 'passkeys', 'pending']);
    expect(pending.output).toContain(ben.passkey.id);
    const benSession = await dashboard.signIn({ sub: 'sub-ben', email: 'ben@example.test', email_verified: true });
    expect((await dashboard.get('/api/session', benSession.auth!)).json.passkeys).toBe(0);
    expect((await f.cli(rt, ['team', 'add-passkey', 'cy', ben.passkey.id])).errors).toMatch(/enrolled from another member/);
    expect(await f.cli(rt, ['team', 'add-passkey', 'ben', ben.passkey.id])).toMatchObject({ code: 0, output: expect.stringMatching(/^Roster version 5 applied/) });
    expect((await f.cli(rt, ['team', 'passkeys', 'pending'])).output).toBe('No passkeys are waiting.');
    expect((await dashboard.get('/api/session', benSession.auth!)).json.passkeys).toBe(1);

    // ---- A non-member cannot sign in; the viewer can read but not approve.
    expect((await dashboard.signIn({ sub: 'sub-eve', email: 'eve@example.test', email_verified: true })).callback.status).toBe(403);
    const vicSession = await dashboard.signIn({ sub: 'sub-vic', email: 'vic@example.test', email_verified: true });
    const listed = await dashboard.get('/api/approvals', vicSession.auth!);
    expect(listed.status).toBe(200);
    const one = listed.json.pending.find((item: { id: string }) => item.id === 'action-one');
    const two = listed.json.pending.find((item: { id: string }) => item.id === 'action-two');
    expect(two.quorum).toEqual({ approvals: 1, required: 2 });
    expect(one.quorum).toBeUndefined();
    const viewer = await dashboard.approve(vicSession.auth!, vic.passkey, { id: 'action-one', reviewHash: one.reviewHash });
    expect(viewer.status).toBe(403);

    // ---- Ben approves action-one: recorded (1 of 2); approving again is refused; nothing has rotated.
    const first = await dashboard.approve(benSession.auth!, ben.passkey, { id: 'action-one', reviewHash: one.reviewHash });
    expect(first).toMatchObject({ status: 200, json: { result: 'recorded', approvals: 1, required: 2 } });
    expect(first.json.text).toMatch(/1 of 2 team approvals so far/);
    expect((await dashboard.get('/api/approvals', benSession.auth!)).json.pending.find((item: { id: string }) => item.id === 'action-one').quorum).toEqual({ approvals: 1, required: 2 });
    const twice = await dashboard.approve(benSession.auth!, ben.passkey, { id: 'action-one', reviewHash: one.reviewHash });
    expect(twice).toMatchObject({ status: 409, json: { error: 'This approval has already been used.' } });
    expect(f.provider.keys.size).toBe(1);
    expect(f.host.writes).toHaveLength(0);

    // ---- Cy approves: the quorum is met and the rotation runs.
    const cySession = await dashboard.signIn({ sub: 'sub-cy', email: 'cy@example.test', email_verified: true });
    const second = await dashboard.approve(cySession.auth!, cy.passkey, { id: 'action-one', reviewHash: one.reviewHash });
    expect(second.status).toBe(200);
    expect(second.json.result).not.toBe('recorded');
    expect(f.provider.keys.size).toBe(2);
    expect(f.host.writes).toHaveLength(1);

    // ---- Widening actions need admins: an operator's device approval is refused, an admin's counts.
    const quorum = rt.teamQuorum()!;
    const service = createApprovalService({ store: rt.store, audit: rt.audit, credentials: async () => [], deviceKeys: async () => [], rpId: 'localhost',
      origins: ['http://localhost'], quorum, now: rt.now });
    const request = await service.request({ id: 'arm-more-keys', kind: 'autopilot-arm', clusterIds: [] }, true);
    const sign = (key: DeviceKey) => {
      const data = { actionId: request.actionId, digest: request.digest, at: rt.now().toISOString() };
      return { ...data, keyId: key.keyId, sig: signDetached(key.privateKeyDer, Buffer.from(APPROVAL_PREFIX + canonicalJson(data))).toString('base64') };
    };
    await expect(service.approveWithDevice('arm-more-keys', sign(ben.key))).rejects.toThrow('This change needs approval from team admins.');
    const grant = await service.approveWithDevice('arm-more-keys', sign(await deviceKey(f.vault)));
    expect(grant.approvers?.map(approver => approver.memberId)).toEqual(['ana']);
  });

  it('pauses changes when the policy file is changed after signing, and when team mode is turned off under a roster', async () => {
    const f = await fixture();
    let rt = await f.runtime();
    expect((await f.cli(rt, ['team', 'init', '--id', 'ana'])).code).toBe(0);
    await writeFile(f.path('policy.json'), JSON.stringify({ approvals: { required: 1 } }));
    expect((await f.cli(rt, ['policy', 'sign', 'policy.json', '--yes'])).code).toBe(0);
    expect((await f.cli(rt, ['policy', 'apply', 'policy.json', '--yes'])).code).toBe(0);
    // Someone edits the signed policy file.
    const signed = JSON.parse(await readFile(f.path('policy.json'), 'utf8'));
    signed.policy.approvals.required = 1; signed.policy.network = { offline: false };
    await writeFile(f.path('policy.json'), JSON.stringify(signed));
    rt = await f.runtime();
    const rotate = await f.cli(rt, ['rotate', '--execute', '--yes']);
    expect(rotate.code).toBe(1);
    expect(rotate.errors).toMatch(/Changes are paused\. The team policy file is not valid: A signature does not match the document/);
    expect(f.provider.keys.size).toBe(1);
    expect((await f.cli(rt, ['doctor'])).output).toMatch(/fail: Team governance/);

    // Turning team mode off in keysentry.yaml does not fall back to single-user mode.
    await writeFile(f.path('keysentry.yaml'), 'team:\n  enabled: false\n');
    rt = await f.runtime();
    const off = await f.cli(rt, ['rotate', '--execute', '--yes']);
    expect(off.errors).toMatch(/This project has a team roster, but team\.enabled is false/);
  });
});
