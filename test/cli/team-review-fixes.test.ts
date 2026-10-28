// Fix round for the team-mode review, CLI side: roster and policy changes need the policy's widening admins (H1),
// enrollment works with no admin key on the team server (H3), removing a member keeps their channels member-owned (M5),
// deployed watchers are reminded about (M6), emails fold ASCII only (L4), and authenticator ids are labelled (L5).
import { afterEach, describe, expect, test } from 'vitest';
import { Command } from 'commander';
import { randomBytes } from 'node:crypto';
import { copyFile, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parse } from 'yaml';
import { configSchema } from '../../src/cli/config.js';
import { registerTeamCommands, type TeamRuntime } from '../../src/cli/team.js';
import { createStateCipher, createStateStore } from '../../src/core/store.js';
import { assertHumanForMutation } from '../../src/safety/index.js';
import { completeEnrollment, loadTeam, routeChannels, signInvite, verifyInvite } from '../../src/team/index.js';
import type { AuditEvent, PasskeyCredential } from '../../src/types.js';
import { deviceKey } from '../../src/vault/keys.js';
import { createFakeVault } from '../helpers/fake-vault.js';

const NOW = new Date('2026-10-28T10:00:00.000Z');
const ORIGIN = 'https://keysentry.example.com';
const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });

async function computer(name: string, yaml?: string) {
  const cwd = await mkdtemp(join(tmpdir(), `keysentry-team-fix-${name}-`)); dirs.push(cwd);
  const vault = createFakeVault();
  const events: AuditEvent[] = [];
  const configPath = join(cwd, 'keysentry.yaml');
  if (yaml) await writeFile(configPath, yaml);
  const rt: TeamRuntime = {
    store: createStateStore({ cwd, cipher: createStateCipher(randomBytes(32)) }), vault, projectId: `project-${name}`,
    audit: { append: async event => { events.push(event); }, checkpoint: async () => {}, verify: async () => ({ ok: true, entries: events.length, checkpoints: 0 }) },
    signingKey: () => deviceKey(vault), config: { cwd, configPath, settings: configSchema.parse(yaml ? parse(yaml) : {}) }, now: () => NOW,
  };
  return { name, cwd, rt, events, vault, path: (file: string) => join(cwd, file) };
}
type Computer = Awaited<ReturnType<typeof computer>>;

async function run(device: Computer, args: string[]) {
  const output: string[] = [], diagnostics: string[] = [];
  let error: unknown;
  const program = new Command().exitOverride().configureOutput({ writeOut: () => {}, writeErr: () => {} });
  registerTeamCommands(program, {
    getRuntime: async () => device.rt, env: {},
    human: action => assertHumanForMutation({ env: {}, stdinIsTTY: true, stdoutIsTTY: true, action }),
    emit: (value, text) => output.push(text ?? JSON.stringify(value)), diagnostic: text => diagnostics.push(text), json: () => false, setExit: () => {},
    confirm: async () => true,
  });
  try { await program.parseAsync(args, { from: 'user' }); } catch (caught) { error = caught; }
  return { output: output.join('\n'), diagnostics: diagnostics.join('\n'), exit: error ? 1 : 0, message: error instanceof Error ? error.message : '' };
}

/** Ana's computer and Bea's computer, both admins, both with the roster; returns the roster fingerprint. */
async function twoAdmins() {
  const ana = await computer('ana'); const bea = await computer('bea');
  await run(ana, ['team', 'init', '--id', 'ana']);
  await run(bea, ['team', 'card', '-o', 'bea.json']);
  await copyFile(bea.path('bea.json'), ana.path('bea.json'));
  expect((await run(ana, ['team', 'add', 'bea', '--role', 'admin', '--card', 'bea.json'])).exit).toBe(0);
  await run(ana, ['team', 'export', '-o', 'roster.json']);
  await copyFile(ana.path('roster.json'), bea.path('roster.json'));
  const fingerprint = (await run(ana, ['team', 'list'])).output.match(/fingerprint ((?:[a-f0-9]{4}-){7}[a-f0-9]{4})/)![1]!;
  expect((await run(bea, ['team', 'apply', 'roster.json', '--fingerprint', fingerprint])).exit).toBe(0);
  return { ana, bea };
}

/** Sign a policy draft on Ana's computer, countersign on Bea's when `both`, and apply it on both. */
async function policy(ana: Computer, bea: Computer, draft: unknown, file: string, both = true) {
  await writeFile(ana.path(file), JSON.stringify(draft));
  expect((await run(ana, ['policy', 'sign', file])).exit).toBe(0);
  if (both) {
    await copyFile(ana.path(file), bea.path(file));
    expect((await run(bea, ['policy', 'sign', file])).exit).toBe(0);
    await copyFile(bea.path(file), ana.path(file));
  }
  const applied = await run(ana, ['policy', 'apply', file]);
  if (applied.exit === 0) {
    await copyFile(ana.path(file), bea.path(file));
    expect((await run(bea, ['policy', 'apply', file])).exit).toBe(0);
  }
  return applied;
}

describe('the policy\'s wideningAdmins binds roster and policy changes (H1)', () => {
  test('a member change needs two admins under a policy that asks for two; one admin\'s change becomes a proposal', async () => {
    const { ana, bea } = await twoAdmins();
    expect((await policy(ana, bea, { approvals: { required: 2, wideningAdmins: 2 } }, 'policy.json', false)).exit).toBe(0);
    expect((await run(ana, ['team', 'list'])).output).toContain('Admin signatures needed for roster and policy changes: 2 (the team policy\'s approvals.wideningAdmins; the roster\'s threshold is 1)');
    const sock = await computer('sock');
    await run(sock, ['team', 'card', '-o', 'sock.json']);
    await copyFile(sock.path('sock.json'), ana.path('sock.json'));
    const added = await run(ana, ['team', 'add', 'sock', '--role', 'operator', '--card', 'sock.json', '-o', 'add-sock.json']);
    expect(added).toMatchObject({ exit: 0, output: expect.stringMatching(/\(1 of 2\)\. The team policy asks for that many admins \(approvals\.wideningAdmins\) for roster changes\./) });
    expect((await loadTeam(ana.rt.store))!.roster.roster.version).toBe(2);
    expect((await run(ana, ['team', 'apply', 'add-sock.json'])).message).toBe('This change has 1 of the 2 admin signatures it needs.');
    await copyFile(ana.path('add-sock.json'), bea.path('add-sock.json'));
    expect((await run(bea, ['team', 'sign', 'add-sock.json'])).output).toMatch(/\(2 of 2 admin signatures\)/);
    await copyFile(bea.path('add-sock.json'), ana.path('add-sock.json'));
    expect(await run(ana, ['team', 'apply', 'add-sock.json'])).toMatchObject({ exit: 0, output: expect.stringMatching(/^Roster version 3 applied/) });
  });

  test('a new policy version needs the applied policy\'s widening admins; the rules cannot be relaxed by one admin', async () => {
    const { ana, bea } = await twoAdmins();
    expect((await policy(ana, bea, { approvals: { required: 2, wideningAdmins: 2 } }, 'policy.json', false)).exit).toBe(0);
    await writeFile(ana.path('weaker.json'), JSON.stringify({ approvals: { required: 1, wideningAdmins: 1 } }));
    expect((await run(ana, ['policy', 'sign', 'weaker.json'])).output).toMatch(/\(1 of 2 admin signatures\)\. The policy in force asks for that many admins/);
    expect((await run(ana, ['policy', 'apply', 'weaker.json'])).message)
      .toBe('This change has 1 of the 2 admin signatures it needs. The policy in force asks for that many admins (approvals.wideningAdmins) before its rules can change.');
    await copyFile(ana.path('weaker.json'), bea.path('weaker.json'));
    await run(bea, ['policy', 'sign', 'weaker.json']);
    await copyFile(bea.path('weaker.json'), ana.path('weaker.json'));
    expect((await run(ana, ['policy', 'apply', 'weaker.json'])).exit).toBe(0);
  });

  test('refuses a policy or roster change that would leave too few admins to sign the next change', async () => {
    const { ana, bea } = await twoAdmins();
    await writeFile(ana.path('three.json'), JSON.stringify({ approvals: { required: 1, wideningAdmins: 3 } }));
    expect((await run(ana, ['policy', 'sign', 'three.json'])).message).toMatch(/asks for 3 admins for policy-widening changes, but only 2 admins have a device key/);
    expect((await policy(ana, bea, { approvals: { required: 1, wideningAdmins: 2 } }, 'policy.json', false)).exit).toBe(0);
    expect((await run(ana, ['team', 'remove', 'bea', '-o', 'remove-bea.json'])).message).toMatch(/fewer admins with a device key would remain than the team policy's approvals\.wideningAdmins \(2\)/);
  });

  test('warns when one admin\'s signature can add an operator but the policy needs more than one approver', async () => {
    const ana = await computer('ana');
    await run(ana, ['team', 'init', '--id', 'ana']);
    await writeFile(ana.path('policy.json'), JSON.stringify({ approvals: { required: 2, wideningAdmins: 1 } }));
    await run(ana, ['policy', 'sign', 'policy.json']); await run(ana, ['policy', 'apply', 'policy.json']);
    const ben = await computer('ben'); await run(ben, ['team', 'card', '-o', 'ben.json']); await copyFile(ben.path('ben.json'), ana.path('ben.json'));
    const added = await run(ana, ['team', 'add', 'ben', '--role', 'operator', '--card', 'ben.json']);
    expect(added.exit).toBe(0);
    expect(added.diagnostics).toMatch(/Warning: this change needs one admin signature, but the team policy needs more than one approver/);
  });

  // fix-verify M-c: a 2-of-2 widening rule (the README example) or a single admin leaves no spare signing admin.
  test('warns when signing or applying leaves no spare admin, and not when a spare remains', async () => {
    const { ana, bea } = await twoAdmins();
    const noSpare = /Warning: no spare admin\. Every later roster or policy change needs 2 admin signatures and only 2 admins have a device key, so if one admin device is lost, no roster or policy change can be signed again; keysentry has no bypass\. Keep a spare/;
    await writeFile(ana.path('policy.json'), JSON.stringify({ approvals: { required: 2, wideningAdmins: 2 } }));
    expect((await run(ana, ['policy', 'sign', 'policy.json'])).diagnostics).toMatch(noSpare);
    await copyFile(ana.path('policy.json'), bea.path('policy.json'));
    expect((await run(bea, ['policy', 'sign', 'policy.json'])).diagnostics).toMatch(noSpare);
    await copyFile(bea.path('policy.json'), ana.path('policy.json'));
    const applied = await run(ana, ['policy', 'apply', 'policy.json']);
    expect(applied.exit).toBe(0);
    expect(applied.diagnostics).toMatch(noSpare);
    // Adding a third admin restores a spare: that change says nothing about it.
    const cy = await computer('cy');
    await run(cy, ['team', 'card', '-o', 'cy.json']);
    await copyFile(cy.path('cy.json'), ana.path('cy.json'));
    const proposed = await run(ana, ['team', 'add', 'cy', '--role', 'admin', '--card', 'cy.json', '-o', 'add-cy.json']);
    expect(proposed.exit).toBe(0);
    expect(proposed.diagnostics).not.toMatch(/no spare admin/);
    // Removing an admin from a 2-of-3 team leaves none: the removal proposal warns before anyone signs it.
    await copyFile(ana.path('add-cy.json'), bea.path('add-cy.json'));
    await run(bea, ['team', 'sign', 'add-cy.json']);
    await copyFile(bea.path('add-cy.json'), ana.path('add-cy.json'));
    expect((await run(ana, ['team', 'apply', 'add-cy.json'])).exit).toBe(0);
    const removal = await run(ana, ['team', 'remove', 'cy', '-o', 'remove-cy.json']);
    expect(removal.exit).toBe(0);
    expect(removal.diagnostics).toMatch(noSpare);
  });

  test('a team of one admin is told on creation that it has no spare admin', async () => {
    const solo = await computer('solo');
    const created = await run(solo, ['team', 'init', '--id', 'solo']);
    expect(created.exit).toBe(0);
    expect(created.diagnostics).toMatch(/Warning: no spare admin\. Every later roster or policy change needs 1 admin signature and only 1 admin has a device key/);
  });
});

describe('enrollment with no admin key on the team server (H3)', () => {
  test('the admin signs the link; the server checks it, exports a card; the admin adds the passkey from the card; the server applies the roster', async () => {
    const ana = await computer('ana'); const server = await computer('server');
    await run(ana, ['team', 'init', '--id', 'ana']);
    const ben = await computer('ben'); await run(ben, ['team', 'card', '-o', 'ben.json']); await copyFile(ben.path('ben.json'), ana.path('ben.json'));
    await run(ana, ['team', 'add', 'ben', '--role', 'operator', '--card', 'ben.json']);
    await run(ana, ['team', 'export', '-o', 'roster.json']);
    await copyFile(ana.path('roster.json'), server.path('roster.json'));
    const fingerprint = (await run(ana, ['team', 'list'])).output.match(/fingerprint ((?:[a-f0-9]{4}-){7}[a-f0-9]{4})/)![1]!;
    expect((await run(server, ['team', 'apply', 'roster.json', '--fingerprint', fingerprint])).exit).toBe(0);
    // The server is not an admin: it cannot sign invitations or roster changes.
    expect((await run(server, ['team', 'invite', 'ben', '--origin', ORIGIN])).message).toMatch(/does not belong to an admin/);

    const invite = await run(ana, ['team', 'invite', 'ben', '--origin', ORIGIN]);
    const token = /\/enroll#([A-Za-z0-9_-]+\.[A-Za-z0-9_-]{86})/.exec(invite.output)![1]!;
    const roster = (await loadTeam(server.rt.store))!.roster.roster;
    expect(verifyInvite(token, { roster, origin: ORIGIN, now: NOW })).toMatchObject({ memberId: 'ben', signerId: 'ana' });
    // What the team dashboard does on /enroll/finish.
    const credential: PasskeyCredential = { id: 'YmVuLWRhc2hib2FyZC1wYXNza2V5', publicKeyCose: 'pQECAyYgASFYIDj6UG7J2Jg7ZbCYvNfu6aiQ8vVF7ymS4f8hJlU9xX1bIlggi0EzH7m4i0mGoVKqk4Rf_x3n1lKpmbSz9yZf8M0Wvqo',
      alg: -7, signCount: 0, backupEligible: false, rpId: 'keysentry.example.com', origins: [ORIGIN], label: 'Team dashboard passkey', createdAt: NOW.toISOString() };
    await completeEnrollment(server.rt.store, { token, roster, origin: ORIGIN, memberId: 'ben', credential, aaguid: 'ad'.repeat(16), now: NOW });

    // Anyone on the server can list and export the candidate; the authenticator's id is labelled as unverified (L5).
    const pending = await run(server, ['team', 'passkeys', 'pending']);
    expect(pending.output).toContain('(authenticator model adadadadadadadadadadadadadadadad, reported by the authenticator, not verified)');
    expect(pending.output).toMatch(/ben +2026-10-28T10:00:00\.000Z +(?:[a-f0-9]{4}-){7}[a-f0-9]{4} {2}YmVuLWRhc2hib2FyZC1wYXNza2V5/);
    expect(await run(server, ['team', 'passkeys', 'pending', '-o', 'card.json'])).toMatchObject({ exit: 0, output: expect.stringMatching(/^Wrote 1 waiting passkey to .*card\.json/) });
    const cardText = await readFile(server.path('card.json'), 'utf8');
    expect(JSON.parse(cardText)).toMatchObject({ v: 1, kind: 'keysentry-passkey-candidates', candidates: [{ memberId: 'ben', credential: { id: credential.id } }] });
    await copyFile(server.path('card.json'), ana.path('card.json'));

    expect((await run(ana, ['team', 'add-passkey', 'cy', '--card', 'card.json'])).message).toBe('The card has no passkey for cy.');
    expect((await run(ana, ['team', 'add-passkey', 'ana', credential.id, '--card', 'card.json'])).message).toMatch(/enrolled from another member/);
    const added = await run(ana, ['team', 'add-passkey', 'ben', '--card', 'card.json']);
    expect(added).toMatchObject({ exit: 0, output: expect.stringMatching(/^Roster version 3 applied/) });
    expect(added.diagnostics).toMatch(/Passkey YmVuLWRhc2hib2FyZC1wYXNza2V5 for ben, created 2026-10-28T10:00:00\.000Z at https:\/\/keysentry\.example\.com; fingerprint (?:[a-f0-9]{4}-){7}[a-f0-9]{4}/);

    // The server takes the new roster like any computer; the candidate is settled.
    await run(ana, ['team', 'export', '-o', 'roster-v3.json']);
    await copyFile(ana.path('roster-v3.json'), server.path('roster-v3.json'));
    expect((await run(server, ['team', 'apply', 'roster-v3.json'])).exit).toBe(0);
    expect((await loadTeam(server.rt.store))!.roster.roster.members.find(entry => entry.id === 'ben')!.passkeys.map(passkey => passkey.id)).toEqual([credential.id]);
    expect((await run(server, ['team', 'passkeys', 'pending'])).output).toBe('No passkeys are waiting.');
    expect(JSON.stringify(server.events)).not.toContain(token);
  });
});

describe('a member\'s own channels when they leave (M5) and deployed watchers (M6)', () => {
  const yaml = 'notify:\n  channels:\n    # the team\'s shared channel\n    - id: team-slack\n      kind: console\n    - id: bob-telegram\n      kind: console\n';

  test('team remove refuses while the member has channels nobody else receives, unless --drop-channels removes them here', async () => {
    const ana = await computer('ana', yaml);
    await run(ana, ['team', 'init', '--id', 'ana']);
    const bob = await computer('bob'); await run(bob, ['team', 'card', '-o', 'bob.json']); await copyFile(bob.path('bob.json'), ana.path('bob.json'));
    await run(ana, ['team', 'add', 'bob', '--role', 'operator', '--card', 'bob.json', '--notify', 'bob-telegram', '--min-severity', 'urgent']);
    await run(ana, ['team', 'notify', 'ana', '--channels', 'team-slack', '--min-severity', 'info']);
    const refused = await run(ana, ['team', 'remove', 'bob']);
    expect(refused.message).toBe('bob receives notifications on channels no other member receives (bob-telegram). Run again with --drop-channels to remove them from keysentry.yaml on this computer; after the change the roster keeps them member-owned, so other computers send them no team messages.');
    expect((await loadTeam(ana.rt.store))!.roster.roster.members.map(entry => entry.id)).toEqual(['ana', 'bob']);

    const removed = await run(ana, ['team', 'remove', 'bob', '--drop-channels']);
    expect(removed.exit).toBe(0);
    expect(removed.diagnostics).toContain('Stop sending team messages to bob-telegram (no member receives it any more).');
    expect(removed.diagnostics).toContain('Removed bob-telegram from keysentry.yaml on this computer.');
    const text = await readFile(ana.rt.config.configPath, 'utf8');
    expect(text).toContain('# the team\'s shared channel');
    expect(parse(text).notify.channels).toEqual([{ id: 'team-slack', kind: 'console' }]);
    const roster = (await loadTeam(ana.rt.store))!.roster.roster;
    expect(roster.retiredChannels).toEqual(['bob-telegram']);
    // Another computer that still lists Bob's channel sends it nothing.
    expect(routeChannels(roster, ['team-slack', 'bob-telegram'], { severity: 'urgent' })).toEqual(['team-slack']);
  });

  test('team notify --clear refuses the same way; --drop-channels needs --clear', async () => {
    const ana = await computer('ana', yaml);
    await run(ana, ['team', 'init', '--id', 'ana']);
    await run(ana, ['team', 'notify', 'ana', '--channels', 'bob-telegram', '--min-severity', 'urgent']);
    expect((await run(ana, ['team', 'notify', 'ana', '--clear'])).message).toMatch(/^ana receives notifications on channels no other member receives \(bob-telegram\)/);
    expect((await run(ana, ['team', 'notify', 'ana', '--channels', 'team-slack', '--drop-channels'])).message).toBe('Use --drop-channels together with --clear.');
    expect((await run(ana, ['team', 'notify', 'ana', '--clear', '--drop-channels'])).exit).toBe(0);
    expect((await loadTeam(ana.rt.store))!.roster.roster.retiredChannels).toEqual(['bob-telegram']);
  });

  test('team remove and team role remind that deployed watchers keep the roster sealed at setup', async () => {
    const ana = await computer('ana');
    await run(ana, ['team', 'init', '--id', 'ana']);
    const bob = await computer('bob'); await run(bob, ['team', 'card', '-o', 'bob.json']); await copyFile(bob.path('bob.json'), ana.path('bob.json'));
    await run(ana, ['team', 'add', 'bob', '--role', 'operator', '--card', 'bob.json']);
    expect((await run(ana, ['team', 'role', 'bob', 'viewer'])).diagnostics).not.toMatch(/watcher setup/);
    await ana.vault.set('watcher/signing/public', Buffer.from('watcher-public-key'));
    const role = await run(ana, ['team', 'role', 'bob', 'operator']);
    expect(role.diagnostics).toContain('Deployed watchers and cloud boxes keep the roster sealed when they were set up: until you run keysentry watcher setup again (and keysentry box send-tokens for a cloud box), they still accept approvals and disarms from bob as before.');
    expect((await run(ana, ['team', 'remove', 'bob'])).diagnostics).toMatch(/until you run keysentry watcher setup again/);
  });
});

test('emails fold ASCII case only; a non-ASCII address is refused (L4)', async () => {
  const ana = await computer('ana');
  expect((await run(ana, ['team', 'init', '--id', 'ana', '--email', 'Ken@example.test'])).message).toBe('Use a valid email address.');
  expect((await run(ana, ['team', 'init', '--id', 'ana', '--email', 'KEN@Example.test'])).exit).toBe(0);
  expect((await loadTeam(ana.rt.store))!.roster.roster.members[0]!.email).toBe('ken@example.test');
});

test('signInvite refuses a member id that is not one', () => {
  const key = { keyId: '', publicKeyDer: Buffer.alloc(0), privateKeyDer: Buffer.alloc(0) };
  expect(() => signInvite({ memberId: 'Bad Id', origin: ORIGIN, now: NOW, signer: key })).toThrow(/Choose a member/);
});
