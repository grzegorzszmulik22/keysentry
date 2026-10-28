import { afterEach, describe, expect, test } from 'vitest';
import { Command } from 'commander';
import { randomBytes } from 'node:crypto';
import { access, copyFile, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parse } from 'yaml';
import { configSchema } from '../../src/cli/config.js';
import { registerTeamCommands, type TeamRuntime } from '../../src/cli/team.js';
import { createStateCipher, createStateStore } from '../../src/core/store.js';
import { assertHumanForMutation } from '../../src/safety/index.js';
import { loadTeam } from '../../src/team/index.js';
import type { AuditEvent } from '../../src/types.js';
import { deviceKey } from '../../src/vault/keys.js';
import { createFakeVault } from '../helpers/fake-vault.js';

const NOW = new Date('2026-10-28T10:00:00.000Z');
const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });

async function computer(name: string) {
  const cwd = await mkdtemp(join(tmpdir(), `keysentry-team-cli-${name}-`)); dirs.push(cwd);
  const vault = createFakeVault();
  const events: AuditEvent[] = [];
  const rt: TeamRuntime = {
    store: createStateStore({ cwd, cipher: createStateCipher(randomBytes(32)) }), vault, projectId: `project-${name}`,
    audit: { append: async event => { events.push(event); }, checkpoint: async () => {}, verify: async () => ({ ok: true, entries: events.length, checkpoints: 0 }) },
    signingKey: () => deviceKey(vault), config: { cwd, configPath: join(cwd, 'keysentry.yaml'), settings: configSchema.parse({}) }, now: () => NOW,
  };
  return { name, cwd, rt, events, path: (file: string) => join(cwd, file) };
}
type Computer = Awaited<ReturnType<typeof computer>>;

interface RunOptions { env?: NodeJS.ProcessEnv; tty?: boolean; json?: boolean; confirm?: boolean }
async function run(device: Computer, args: string[], options: RunOptions = {}) {
  const output: string[] = [], diagnostics: string[] = [];
  let exit = 0;
  let error: unknown;
  const program = new Command().exitOverride().configureOutput({ writeOut: () => {}, writeErr: () => {} });
  const env = options.env ?? {};
  registerTeamCommands(program, {
    getRuntime: async () => device.rt, env,
    human: action => assertHumanForMutation({ env, stdinIsTTY: options.tty ?? true, stdoutIsTTY: options.tty ?? true, action }),
    emit: (value, text) => output.push(options.json ? JSON.stringify(value) : text ?? JSON.stringify(value)),
    diagnostic: text => diagnostics.push(text), json: () => options.json === true, setExit: code => { exit = code; },
    confirm: async () => options.confirm ?? true,
  });
  try { await program.parseAsync(args, { from: 'user' }); } catch (caught) { error = caught; exit = 1; }
  return { output: output.join('\n'), diagnostics: diagnostics.join('\n'), exit, error, message: error instanceof Error ? error.message : '' };
}
const exists = (path: string) => access(path).then(() => true, () => false);

const MUTATING = [
  ['team', 'init'], ['team', 'add', 'bob', '--role', 'operator'], ['team', 'remove', 'bob'], ['team', 'role', 'bob', 'admin'],
  ['team', 'threshold', '2'], ['team', 'notify', 'bob', '--clear'], ['team', 'sign', 'proposal.json'], ['team', 'apply', 'roster.json', '--fingerprint', 'a'.repeat(16)],
  ['policy', 'sign', 'policy.json'], ['policy', 'apply', 'policy.json'],
  ['team', 'sso', 'bob', '--clear'], ['team', 'invite', 'bob', '--origin', 'https://keysentry.example.com'], ['team', 'add-passkey', 'bob', 'Y3JlZA'],
];

describe('team and policy commands refuse agents and non-terminals', () => {
  test.each(MUTATING)('%s %s refuses an AI agent and a non-terminal before touching anything', async (...args) => {
    const device = await computer('agent');
    await writeFile(device.path('proposal.json'), '{}'); await writeFile(device.path('roster.json'), '{}'); await writeFile(device.path('policy.json'), '{}');
    const agent = await run(device, args, { env: { CLAUDE_CODE_CHILD_SESSION: '1' } });
    expect(agent.exit).toBe(1);
    expect(agent.message).toMatch(/^keysentry won't .+ when an AI coding agent runs it \(detected: Claude Code\)/);
    const piped = await run(device, args, { tty: false });
    expect(piped.message).toMatch(/needs you at an interactive terminal\.$/);
    expect(await exists(join(device.rt.store.paths.dir, 'team-roster.json'))).toBe(false);
    expect(await exists(device.rt.config.configPath)).toBe(false);
    expect(device.events).toEqual([]);
    expect(await device.rt.vault.list()).toEqual([]);
  });

  test('read-only commands stay available to anyone', async () => {
    const device = await computer('reader');
    const env = { CODEX_SANDBOX: 'seatbelt' };
    expect(await run(device, ['team', 'list'], { env, tty: false })).toMatchObject({ exit: 0, output: 'This project has no team. Run keysentry team init to start one.' });
    expect(await run(device, ['policy', 'show'], { env, tty: false })).toMatchObject({ exit: 0, output: expect.stringMatching(/^No team policy is in use/) });
    expect(await run(device, ['team', 'verify'], { env, tty: false })).toMatchObject({ exit: 0 });
    const card = await run(device, ['team', 'card'], { env, tty: false });
    expect(JSON.parse(card.output)).toMatchObject({ v: 1, kind: 'keysentry-member-card', deviceKeys: [{ keyId: expect.stringMatching(/^[a-f0-9]{16}$/) }], passkeys: [] });
    expect(card.output).not.toMatch(/PRIVATE|privateKey/i);
  });
});

describe('a team across three computers', () => {
  test('init, add, raise the threshold, propose, sign elsewhere, apply everywhere', async () => {
    const ana = await computer('ana'); const ben = await computer('ben'); const cy = await computer('cy');

    // Ana starts the team; team mode is switched on in her keysentry.yaml.
    const init = await run(ana, ['team', 'init', '--id', 'ana', '--name', 'Ana', '--email', 'Ana@Example.com']);
    expect(init).toMatchObject({ exit: 0, output: expect.stringMatching(/You \(ana\) are its first admin\. Roster fingerprint: [a-f0-9]{4}-/) });
    expect(parse(await readFile(ana.rt.config.configPath, 'utf8'))).toEqual({ team: { enabled: true } });
    expect(ana.rt.config.settings.team.enabled).toBe(true);
    expect((await run(ana, ['team', 'init'])).message).toMatch(/already has a team/);
    expect(ana.events.map(event => event.kind)).toEqual(['team:init']);

    // Ben and Cy send public member cards; with a threshold of 1, Ana's own signature applies each change.
    await run(ben, ['team', 'card', '-o', 'ben.json']);
    await run(cy, ['team', 'card', '-o', 'cy.json']);
    await copyFile(ben.path('ben.json'), ana.path('ben.json'));
    await copyFile(cy.path('cy.json'), ana.path('cy.json'));
    expect(await run(ana, ['team', 'add', 'ben', '--role', 'admin', '--card', 'ben.json'])).toMatchObject({ exit: 0, output: expect.stringMatching(/^Roster version 2 applied/) });
    expect(await run(ana, ['team', 'threshold', '2'])).toMatchObject({ exit: 0, output: expect.stringMatching(/^Roster version 3 applied/) });

    // Ben's computer joins with the exported roster and the fingerprint Ana reads out.
    await run(ana, ['team', 'export', '-o', 'roster-v3.json']);
    await copyFile(ana.path('roster-v3.json'), ben.path('roster-v3.json'));
    const listed = JSON.parse((await run(ana, ['team', 'list'], { json: true })).output);
    expect(listed).toMatchObject({ version: 3, adminThreshold: 2, members: [{ id: 'ana', role: 'admin', email: 'ana@example.com' }, { id: 'ben', role: 'admin' }] });
    expect((await run(ben, ['team', 'apply', 'roster-v3.json'])).message).toMatch(/no team roster yet/);
    expect((await run(ben, ['team', 'apply', 'roster-v3.json', '--fingerprint', '0000-0000-0000-0000'])).message).toMatch(/fingerprint does not match/);
    expect(await run(ben, ['team', 'apply', 'roster-v3.json', '--fingerprint', listed.fingerprint])).toMatchObject({ exit: 0, output: expect.stringMatching(/Roster version 3 applied/) });

    // Now changes need two admins: Ana's change becomes a proposal file with her signature.
    const proposed = await run(ana, ['team', 'add', 'cy', '--role', 'operator', '--card', 'cy.json', '--notify', 'ops', '--min-severity', 'warning', '-o', 'add-cy.json']);
    expect(proposed.output).toMatch(/with your signature \(1 of 2\)/);
    expect(proposed.diagnostics).toContain('Add cy (cy) as operator.');
    expect((await loadTeam(ana.rt.store))!.roster.roster.version).toBe(3);
    expect((await run(ana, ['team', 'apply', 'add-cy.json'])).message).toBe('This change has 1 of the 2 admin signatures it needs.');

    // Ben reviews and signs on his own computer; declining changes nothing.
    await copyFile(ana.path('add-cy.json'), ben.path('add-cy.json'));
    expect(await run(ben, ['team', 'sign', 'add-cy.json'], { confirm: false })).toMatchObject({ output: 'Not signed. Nothing changed.' });
    const signed = await run(ben, ['team', 'sign', 'add-cy.json']);
    expect(signed).toMatchObject({ exit: 0, output: expect.stringMatching(/\(2 of 2 admin signatures\)\. It has enough signatures/) });
    expect((await run(ben, ['team', 'sign', 'add-cy.json'])).message).toMatch(/already signed/);

    // Applied on both computers; the same file again is a no-op; an older roster is refused.
    await copyFile(ben.path('add-cy.json'), ana.path('add-cy.json'));
    expect(await run(ana, ['team', 'apply', 'add-cy.json'])).toMatchObject({ exit: 0, output: expect.stringMatching(/^Roster version 4 applied/) });
    expect(await run(ben, ['team', 'apply', 'add-cy.json'])).toMatchObject({ exit: 0, output: expect.stringMatching(/^Roster version 4 applied/) });
    expect(await run(ana, ['team', 'apply', 'add-cy.json'])).toMatchObject({ output: 'Roster version 4 is already in use.' });
    expect((await run(ana, ['team', 'apply', 'roster-v3.json'])).message).toMatch(/rollback protection/);
    expect(ana.events.map(event => event.kind)).toEqual(['team:init', 'team:roster-applied', 'team:roster-applied', 'team:roster-proposed', 'team:roster-applied']);

    // An operator's computer cannot sign roster changes.
    await run(ana, ['team', 'export', '-o', 'roster-v4.json']);
    await copyFile(ana.path('roster-v4.json'), cy.path('roster-v4.json'));
    const fp = JSON.parse((await run(ana, ['team', 'list'], { json: true })).output).fingerprint as string;
    expect((await run(cy, ['team', 'apply', 'roster-v4.json', '--fingerprint', fp])).exit).toBe(0);
    expect(await run(cy, ['team', 'list'])).toMatchObject({ output: expect.stringMatching(/cy +operator .*ops \(warning\+\)/) });
    expect((await run(cy, ['team', 'role', 'cy', 'admin', '-o', 'x.json'])).message).toMatch(/does not belong to an admin of the current roster/);

    // Policy: Ana drafts and signs, Ben signs, Ana applies; team.policyFile is set for her.
    await writeFile(ana.path('policy.json'), JSON.stringify({ approvals: { required: 2, wideningAdmins: 2 }, autopilot: { maxServicesPerWave: 3 } }));
    const first = await run(ana, ['policy', 'sign', 'policy.json']);
    expect(first).toMatchObject({ exit: 0, output: expect.stringMatching(/Signed policy version 1 \(1 of 2 admin signatures\)/) });
    expect(first.diagnostics).toContain('  Autopilot changes at most 3 services per wave.');
    expect((await run(ana, ['policy', 'apply', 'policy.json'])).message).toBe('This change has 1 of the 2 admin signatures it needs.');
    await copyFile(ana.path('policy.json'), ben.path('policy.json'));
    expect((await run(ben, ['policy', 'sign', 'policy.json'])).output).toMatch(/\(2 of 2 admin signatures\)/);
    await copyFile(ben.path('policy.json'), ana.path('policy.json'));
    expect(await run(ana, ['policy', 'apply', 'policy.json'])).toMatchObject({ exit: 0, output: expect.stringMatching(/Applied team policy version 1 .* team.policyFile set to policy.json/) });
    expect(parse(await readFile(ana.rt.config.configPath, 'utf8'))).toEqual({ team: { enabled: true, policyFile: 'policy.json' } });
    expect(await run(ana, ['policy', 'show'])).toMatchObject({ exit: 0, output: expect.stringMatching(/Approvals: 2 operators or admins; policy-widening changes: 2 admins\./) });
    expect(await run(ana, ['policy', 'verify'])).toMatchObject({ exit: 0, output: expect.stringMatching(/Policy version 1 verified/) });

    // A tampered policy file stops changes until it is fixed, and says why.
    const tampered = JSON.parse(await readFile(ana.path('policy.json'), 'utf8'));
    tampered.policy.approvals.required = 1;
    await writeFile(ana.path('policy.json'), JSON.stringify(tampered));
    const verify = await run(ana, ['policy', 'verify']);
    expect(verify.exit).toBe(1);
    expect(verify.output).toMatch(/Changes are paused: The team policy file is not valid: A signature does not match the document/);
    expect((await run(ana, ['team', 'verify'])).exit).toBe(1);
  });

  test('sso pins a subject as a roster change; invite prints a single-use link only an admin can make', async () => {
    const ana = await computer('ana-sso'); const ben = await computer('ben-sso');
    await run(ana, ['team', 'init', '--id', 'ana', '--email', 'ana@example.com']);
    await run(ben, ['team', 'card', '-o', 'ben.json']);
    await copyFile(ben.path('ben.json'), ana.path('ben.json'));
    expect((await run(ana, ['team', 'add', 'ben', '--role', 'operator', '--card', 'ben.json', '--email', 'ben@example.com'])).exit).toBe(0);

    const pinned = await run(ana, ['team', 'sso', 'ben', '--issuer', 'https://idp.example.com', '--subject', 'sub-ben-123']);
    expect(pinned).toMatchObject({ exit: 0, output: expect.stringMatching(/^Roster version 3 applied/) });
    expect(pinned.diagnostics).toContain('Pin the single sign-on identity of ben to issuer https://idp.example.com, subject sub-ben-123.');
    const listed = JSON.parse((await run(ana, ['team', 'list'], { json: true })).output);
    expect(listed.members[1]).toMatchObject({ id: 'ben', email: 'ben@example.com', sso: { issuer: 'https://idp.example.com', subject: 'sub-ben-123' } });
    expect((await run(ana, ['team', 'sso', 'ben', '--issuer', 'http://idp.example.com', '--subject', 's'])).message).toMatch(/^Use --issuer with the provider/);
    expect((await run(ana, ['team', 'sso', 'ben', '--issuer', 'https://idp.example.com'])).message).toMatch(/^Use --issuer with the provider/);
    expect((await run(ana, ['team', 'sso', 'ben'])).message).toBe('Use --issuer with --subject, or --clear.');
    expect(await run(ana, ['team', 'sso', 'ben', '--clear'])).toMatchObject({ exit: 0, diagnostics: 'Remove the pinned single sign-on identity of ben.' });

    const invite = await run(ana, ['team', 'invite', 'ben', '--origin', 'https://keysentry.example.com']);
    expect(invite.exit).toBe(0);
    const link = /https:\/\/keysentry\.example\.com\/enroll#([A-Za-z0-9_-]{43})/.exec(invite.output);
    expect(link).not.toBeNull();
    expect(invite.output).toMatch(/works once, until 2026-10-28T10:15:00\.000Z/);
    // The audit event names the member, never the token.
    expect(ana.events.at(-1)).toEqual({ kind: 'team:invite', summary: 'A passkey enrollment link was created.', data: { memberId: 'ben' } });
    expect(JSON.stringify(ana.events)).not.toContain(link![1]);
    expect((await run(ana, ['team', 'invite', 'zed', '--origin', 'https://keysentry.example.com'])).message).toBe('There is no member zed on this team.');
    expect((await run(ana, ['team', 'invite', 'ben', '--origin', 'http://keysentry.example.com'])).message).toMatch(/^Use --origin with the team dashboard/);
    expect((await run(ana, ['team', 'invite', 'ben', '--origin', 'https://keysentry.example.com/enroll'])).message).toMatch(/^Use --origin/);
    expect(await run(ana, ['team', 'passkeys', 'pending'])).toMatchObject({ exit: 0, output: 'No passkeys are waiting.' });
    expect((await run(ana, ['team', 'add-passkey', 'ben', 'Y3JlZA'])).message).toBe('No pending passkey has that credential id. Run keysentry team passkeys pending.');

    // Ben's computer (not an admin) cannot invite.
    await run(ana, ['team', 'export', '-o', 'roster.json']);
    await copyFile(ana.path('roster.json'), ben.path('roster.json'));
    const fp = JSON.parse((await run(ana, ['team', 'list'], { json: true })).output).fingerprint as string;
    expect((await run(ben, ['team', 'apply', 'roster.json', '--fingerprint', fp])).exit).toBe(0);
    expect((await run(ben, ['team', 'invite', 'ben', '--origin', 'https://keysentry.example.com'])).message).toMatch(/does not belong to an admin/);
  });

  test('team verify reports team mode without a roster', async () => {
    const device = await computer('solo');
    device.rt.config.settings = configSchema.parse({ team: { enabled: true } });
    const result = await run(device, ['team', 'verify']);
    expect(result.exit).toBe(1);
    expect(result.output).toMatch(/Changes are paused: Team mode is on in keysentry.yaml, but this project has no team roster/);
  });

  test('invalid arguments are refused with fixed messages', async () => {
    const device = await computer('args');
    await run(device, ['team', 'init', '--id', 'ana']);
    expect((await run(device, ['team', 'add', 'bob', '--role', 'owner'])).message).toBe('Use a role of viewer, operator or admin.');
    expect((await run(device, ['team', 'add', 'Bob!', '--role', 'viewer'])).message).toMatch(/Member ids use lowercase letters/);
    expect((await run(device, ['team', 'threshold', 'two'])).message).toBe('Use a whole number of admins, at least 1.');
    expect((await run(device, ['team', 'threshold', '2'])).message).toBe('The admin threshold is higher than the number of admins.');
    expect((await run(device, ['team', 'notify', 'ana'])).message).toBe('Use either --channels (with --min-severity) or --clear.');
    expect((await run(device, ['team', 'add', 'bob', '--role', 'viewer', '--email', 'not-an-email'])).message).toBe('Use a valid email address.');
    await writeFile(device.path('card.json'), JSON.stringify({ v: 1, kind: 'keysentry-member-card', deviceKeys: [], passkeys: [] }));
    expect((await run(device, ['team', 'add', 'bob', '--role', 'operator', '--card', 'card.json'])).message).toMatch(/member card is not valid/);
    expect((await run(device, ['team', 'add', 'bob', '--role', 'operator', '--card', 'missing.json'])).message).toBe('The member card was not found.');
    expect(await run(device, ['team', 'add', 'vic', '--role', 'viewer', '--email', 'vic@example.com'])).toMatchObject({ exit: 0 });
  });
});
