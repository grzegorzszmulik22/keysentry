import { afterEach, expect, test, vi } from 'vitest';
import { Command } from 'commander';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { registerPhase3Commands, type Phase3CommandsOptions } from '../../../src/cli/phase3.js';
import { createRuntime } from '../../../src/cli/runtime.js';
import type { DashboardOptions } from '../../../src/dashboard/server/index.js';
import { devicePublicKey } from '../../../src/team/index.js';
import type { TeamMember } from '../../../src/types.js';
import { createFakeVault } from '../../helpers/fake-vault.js';
import { FakeHttp, json, silentLogger } from '../../helpers/fake-http.js';

const started = vi.hoisted(() => ({ options: [] as DashboardOptions[] }));
vi.mock('../../../src/dashboard/server/index.js', async importOriginal => ({
  ...await importOriginal<typeof import('../../../src/dashboard/server/index.js')>(),
  startDashboard: async (options: DashboardOptions) => {
    started.options.push(options);
    return { url: options.team ? `${options.team.publicOrigin}/` : `http://localhost:34567/?t=${'a'.repeat(43)}`, port: 8484, async close() {} };
  },
}));

const dirs: string[] = [];
afterEach(async () => { started.options.length = 0; for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });

const discovery = {
  issuer: 'https://idp.example.test', authorization_endpoint: 'https://idp.example.test/authorize', token_endpoint: 'https://idp.example.test/token',
  jwks_uri: 'https://idp.example.test/jwks', response_types_supported: ['code'], subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['RS256'],
};
const members: TeamMember[] = [{ id: 'ana', name: 'Ana', role: 'admin', email: 'ana@example.test', passkeys: [], deviceKeys: [] }];

async function setup(opts: { secret?: boolean; teamMembers?: Phase3CommandsOptions['teamMembers']; env?: NodeJS.ProcessEnv; discovery?: Record<string, unknown> } = {}) {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-oidc-ui-')); dirs.push(cwd);
  const http = new FakeHttp().on('GET', /^https:\/\/idp\.example\.test\/\.well-known\/openid-configuration$/, () => json(200, { ...discovery, ...opts.discovery }));
  const vault = createFakeVault(opts.secret === false ? {} : { 'cred/KEYSENTRY_OIDC_CLIENT_SECRET': Buffer.from('client-secret-planted-value') });
  const runtime = await createRuntime({ cwd, userDir: join(cwd, 'user'), vault, hosts: [], env: {}, http, log: silentLogger, stdinIsTTY: true, stdoutIsTTY: true });
  const output: string[] = [], diagnostics: string[] = [];
  // Commander keeps parsed option values on a command, so every run gets a fresh program.
  const run = (...args: string[]) => {
    const program = new Command().exitOverride();
    registerPhase3Commands(program, {
      getRuntime: async () => runtime, peekRuntime: () => runtime, cwd: () => cwd, firstRunSettings: () => ({ vault, userDir: join(cwd, 'user'), env: {} }),
      human: () => {}, emit: (_value, text) => { output.push(text ?? ''); }, diagnostic: text => { diagnostics.push(text); }, interactive: () => true, json: () => false,
      setExit: () => {}, env: opts.env ?? {}, teamMembers: 'teamMembers' in opts ? opts.teamMembers : async () => structuredClone(members),
    });
    return program.parseAsync(['node', 'keysentry', 'ui', ...args]);
  };
  return { runtime, http, output, diagnostics, run };
}
const team = ['--team', '--public-origin', 'https://keysentry.example.test', '--oidc-issuer', 'https://idp.example.test', '--oidc-client-id', 'keysentry'];

test('ui --team discovers the provider through the guarded client and starts team mode with vault secret', async () => {
  const s = await setup();
  await s.run(...team, '--listen', '0.0.0.0:9443');
  expect(s.http.calls.map(call => call.url)).toEqual(['https://idp.example.test/.well-known/openid-configuration']);
  const options = started.options[0]!;
  expect(options.readOnly).toBe(false);
  expect(options.passkeys).toBeUndefined();
  expect(options.team).toMatchObject({ publicOrigin: 'https://keysentry.example.test', listen: { host: '0.0.0.0', port: 9443 } });
  expect(options.team!.oidc.redirectUri).toBe('https://keysentry.example.test/auth/callback');
  expect(await options.team!.members()).toEqual(members);
  expect(s.output.join('\n')).toContain('Team dashboard: https://keysentry.example.test/');
  expect(s.output.join('\n') + s.diagnostics.join('\n')).not.toContain('client-secret-planted-value');
  await options.team!.onAuthEvent!({ kind: 'sign-in', memberId: 'ana', role: 'admin' });
});

test('ui --team is read-only for coding agents and refuses unsafe or incomplete settings', async () => {
  const agent = await setup({ env: { AI_AGENT: 'test-agent' } });
  await agent.run(...team);
  expect(started.options.at(-1)!.readOnly).toBe(true);
  const s = await setup();
  await expect(s.run('--public-origin', 'https://keysentry.example.test')).rejects.toThrow('together with --team');
  await expect(s.run(...team, '--print-url')).rejects.toThrow('no one-time link');
  await expect(s.run('--team', '--oidc-issuer', 'https://idp.example.test', '--oidc-client-id', 'k')).rejects.toThrow('--public-origin');
  await expect(s.run(...team.map(value => value === 'https://idp.example.test' ? 'http://idp.example.test' : value))).rejects.toThrow('--oidc-issuer');
  const noSecret = await setup({ secret: false });
  await expect(noSecret.run(...team)).rejects.toThrow('keysentry vault set KEYSENTRY_OIDC_CLIENT_SECRET');
  await noSecret.run(...team, '--oidc-public-client');
  const noRoster = await setup({ teamMembers: undefined });
  await expect(noRoster.run(...team)).rejects.toThrow('team init');
  const moved = await setup({ discovery: { token_endpoint: 'https://tokens.example.test/token' } });
  await expect(moved.run(...team)).rejects.toThrow('sign-in settings do not match');
  await moved.run(...team, '--oidc-host', 'tokens.example.test');
  const wrongIssuer = await setup({ discovery: { issuer: 'https://other.example.test' } });
  await expect(wrongIssuer.run(...team)).rejects.toThrow('sign-in settings do not match');
});

test('ui --team keeps single sign-on inside the team policy and offers passkey enrollment', async () => {
  const s = await setup();
  const policy = { v: 1, teamId: 'team-test-0001', version: 1, prev: null, updatedAt: '2026-10-28T00:00:00.000Z', autopilot: {},
    approvals: { required: 1, wideningAdmins: 1 }, network: { allowHosts: ['other.example.test'] }, notify: {}, rotation: {}, audit: {} } as const;
  Object.assign(s.runtime, { teamPolicy: structuredClone(policy) });
  await expect(s.run(...team)).rejects.toThrow("The team policy's network.allowHosts does not list idp.example.test, so single sign-on cannot reach the identity provider. Ask a team admin to add it to the policy.");
  expect(s.http.calls).toHaveLength(0);
  Object.assign(s.runtime, { teamPolicy: { ...structuredClone(policy), network: { allowHosts: ['idp.example.test'] } } });
  await s.run(...team);
  expect(started.options.at(-1)!.team!.enrollment).toMatchObject({ check: expect.any(Function), complete: expect.any(Function) });
});

test('ui --team refuses to start where the device key belongs to a team admin, and warns for another member (review H3)', async () => {
  const roster = (role: TeamMember['role']) => async (rt: Awaited<ReturnType<typeof createRuntime>>) => {
    const key = await rt.signingKey();
    try { return [...structuredClone(members), { id: 'srv', name: 'Server', role, passkeys: [], deviceKeys: [devicePublicKey(key)] }]; }
    finally { key.privateKeyDer.fill(0); }
  };
  const admin = await setup({ teamMembers: roster('admin') });
  await expect(admin.run(...team)).rejects.toThrow(/This computer's device key belongs to team admin srv, so the team dashboard will not start here/);
  expect(started.options).toHaveLength(0);
  expect(admin.http.calls).toHaveLength(0);
  const operator = await setup({ teamMembers: roster('operator') });
  await operator.run(...team);
  expect(started.options).toHaveLength(1);
  expect(operator.diagnostics.join('\n')).toContain('This computer\'s device key belongs to team member srv (operator): anyone with a terminal here can approve as srv.');
});
