// `keysentry team ...` and `keysentry policy ...`: the signed roster and the signed policy-as-code file.
// Every command that changes the roster or the policy goes through the human gate first.
import type { Command } from 'commander';
import { randomBytes } from 'node:crypto';
import { readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { isMap, isSeq, parseDocument } from 'yaml';
import type { DeviceKey } from '../security/index.js';
import type { NotifySeverity, SignedTeamPolicy, SignedTeamRoster, TeamRole, TeamRoster } from '../types.js';
import {
  adminsNeeded, applyRoster, asciiEmail, candidateCard, candidateFingerprint, checkProposal, createRoster, describeRosterChange, devicePublicKey, exclusiveChannels,
  foldEmail, INVITE_TTL_MS, listCandidates, loadTeam, memberCardSchema, nextRoster, parseCandidateCard, parseSignedRoster, removeCandidates, rosterFingerprint,
  rosterHash, signInvite, signRoster, TeamError, vaultTeamAnchor, verifyFirstUse, verifyRoster,
  type EnrollmentCandidate, type LoadedTeam, type RosterChange, type TeamAnchor,
} from '../team/index.js';
import { ssoSchema } from '../team/schema.js';
import {
  applyPolicy, checkPolicyProposal, describePolicy, loadGovernance, loadPolicyHead, policyFingerprint, preparePolicyDraft, readTeamFile, signPolicy,
  verifyPolicy, type Governance, type PolicyHead,
} from '../policy/index.js';
import { configSchema, type ConfigSettings } from './config.js';
import { CliError } from './errors.js';
import { listPasskeys } from './passkeys.js';
import { confirmAction, type PromptIO } from './prompts.js';
import type { KeysentryRuntime } from './runtime.js';
import { knownWatcherKeys } from './watcher-keys.js';

/** The parts of the runtime the team commands use (the full runtime satisfies it). */
export type TeamRuntime = Pick<KeysentryRuntime, 'store' | 'vault' | 'audit' | 'projectId' | 'signingKey'> & {
  config: { cwd: string; configPath: string; settings: ConfigSettings };
  now?: () => Date;
};

export interface TeamCommandsOptions {
  getRuntime(): Promise<TeamRuntime>;
  /** assertHumanForMutation with the CLI's environment and terminal state. */
  human(action: string): void;
  emit(value: unknown, text?: string): void;
  diagnostic(text: string): void;
  json?(): boolean;
  setExit(code: number): void;
  env?: NodeJS.ProcessEnv;
  promptIO?: PromptIO;
  /** Typed confirmation before signing or applying, unless --yes. Defaults to the terminal prompt. */
  confirm?: (word: string) => Promise<boolean>;
  /** True when `text` prints unchanged (the output redactor would not mask it). Used for enrollment links. */
  printable?: (text: string) => boolean;
}

const ROLES: readonly TeamRole[] = ['viewer', 'operator', 'admin'];
const SEVERITIES: readonly NotifySeverity[] = ['info', 'warning', 'urgent'];
const collect = (value: string, previous: string[] = []) => [...previous, ...value.split(',').map(item => item.trim()).filter(Boolean)];

function role(value: string): TeamRole {
  if (!ROLES.includes(value as TeamRole)) throw new CliError('Use a role of viewer, operator or admin.');
  return value as TeamRole;
}
function severity(value: string | undefined): NotifySeverity {
  if (value === undefined) return 'info';
  if (!SEVERITIES.includes(value as NotifySeverity)) throw new CliError('Use a minimum severity of info, warning or urgent.');
  return value as NotifySeverity;
}
function threshold(value: string): number {
  if (!/^\d{1,3}$/.test(value) || Number(value) < 1) throw new CliError('Use a whole number of admins, at least 1.');
  return Number(value);
}
function displayName(value: string | undefined, fallback: string): string {
  const name = value ?? fallback;
  if (!name.length || name.length > 80 || /[\u0000-\u001f\u007f-\u009f]/.test(name) || name.trim() !== name) throw new CliError('Use a name of 1 to 80 characters without control characters or surrounding spaces.');
  return name;
}
function email(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  // ASCII case folding only (review L4): a non-ASCII address is refused, not lower-cased onto an ASCII one.
  const trimmed = value.trim();
  const lower = foldEmail(trimmed);
  if (!asciiEmail(trimmed) || lower.length > 254 || !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(lower)) {
    throw new CliError('Use a valid email address.');
  }
  return lower;
}

function anchors(rt: TeamRuntime): { roster?: TeamAnchor; policy?: TeamAnchor } {
  // An environment-variable vault is read-only (CI); the encrypted state file is then the only record.
  if (rt.vault.backend === 'env') return {};
  return { roster: vaultTeamAnchor(rt.vault, rt.projectId, 'roster'), policy: vaultTeamAnchor(rt.vault, rt.projectId, 'policy') };
}
const now = (rt: TeamRuntime) => rt.now?.() ?? new Date();
const target = (rt: TeamRuntime, path: string) => resolve(rt.config.cwd, path);

async function requireTeam(rt: TeamRuntime): Promise<LoadedTeam> {
  const team = await loadTeam(rt.store, { anchor: anchors(rt).roster });
  if (!team) throw new TeamError('This project has no team yet. Run keysentry team init, or keysentry team apply with your team\'s roster.');
  return team;
}

/**
 * The policy applied on this computer, whose `approvals.wideningAdmins` also binds roster changes (review H1). A
 * checkpoint without saved state refuses (fail closed) rather than falling back to the roster's threshold.
 */
async function appliedPolicy(rt: TeamRuntime): Promise<PolicyHead | null> {
  return loadPolicyHead(rt.store, { anchor: anchors(rt).policy });
}

/** Remove notification channels from keysentry.yaml (comments kept) and their vault entries; returns the ids removed. */
async function dropChannels(rt: TeamRuntime, ids: readonly string[]): Promise<string[]> {
  if (!ids.length) return [];
  let source = '';
  try { source = await readFile(rt.config.configPath, 'utf8'); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new CliError('Unable to read configuration file.'); }
  const document = parseDocument(source, { prettyErrors: false });
  if (document.errors.length) throw new CliError('Invalid YAML configuration. Check the file syntax.');
  const channels = document.getIn(['notify', 'channels'], true);
  const removed: string[] = [];
  if (isSeq(channels)) {
    channels.items = channels.items.filter(item => {
      const id = isMap(item) ? item.get('id') : undefined;
      if (typeof id === 'string' && ids.includes(id)) { removed.push(id); return false; }
      return true;
    });
  }
  if (removed.length) {
    let value: unknown;
    try { value = document.toJS({ maxAliasCount: 100 }) ?? {}; } catch { throw new CliError('Invalid YAML configuration: too many aliases or invalid structure.'); }
    if (!configSchema.safeParse(value).success) throw new CliError('keysentry.yaml would not be valid after this change, so it was not changed.');
    try { await writeFile(rt.config.configPath, document.toString(), { mode: 0o600 }); }
    catch { throw new CliError('Unable to write the configuration file.'); }
    rt.config.settings.notify.channels = rt.config.settings.notify.channels.filter(channel => !removed.includes(channel.id));
  }
  for (const id of removed) for (const name of await rt.vault.list(`notify/${id}/`)) await rt.vault.delete(name);
  return removed;
}

/** This computer's device key, as an admin of `roster`. The caller clears the private key. */
async function localAdmin(rt: TeamRuntime, roster: TeamRoster): Promise<{ memberId: string; key: DeviceKey }> {
  const key = await rt.signingKey();
  const member = roster.members.find(candidate => candidate.deviceKeys.some(entry => entry.keyId === key.keyId));
  if (!member || member.role !== 'admin') {
    key.privateKeyDer.fill(0);
    throw new TeamError('This computer\'s device key does not belong to an admin of the current roster, so it cannot sign team changes.');
  }
  return { memberId: member.id, key };
}

async function writeNew(path: string, value: unknown): Promise<void> {
  try { await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o644, flag: 'wx' }); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new CliError('A file already exists at that path. Choose another with -o.');
    throw new CliError('The file could not be written.');
  }
}
async function replace(path: string, value: unknown): Promise<void> {
  const temp = join(dirname(path), `.keysentry-${randomBytes(8).toString('hex')}.tmp`);
  try {
    await writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o644, flag: 'wx' });
    await rename(temp, path);
  } catch {
    await unlink(temp).catch(() => undefined);
    throw new CliError('The file could not be written.');
  }
}

/** Change only team.* in keysentry.yaml, keeping comments and other settings; the result must still validate. */
export async function updateTeamSettings(configPath: string, change: { enabled?: true; policyFile?: string }): Promise<void> {
  let source = '';
  try { source = await readFile(configPath, 'utf8'); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new CliError('Unable to read configuration file.'); }
  const document = parseDocument(source, { prettyErrors: false });
  if (document.errors.length) throw new CliError('Invalid YAML configuration. Check the file syntax.');
  if (change.enabled) document.setIn(['team', 'enabled'], true);
  if (change.policyFile !== undefined) document.setIn(['team', 'policyFile'], change.policyFile);
  let value: unknown;
  try { value = document.toJS({ maxAliasCount: 100 }) ?? {}; } catch { throw new CliError('Invalid YAML configuration: too many aliases or invalid structure.'); }
  if (!configSchema.safeParse(value).success) throw new CliError('keysentry.yaml would not be valid after this change, so it was not changed.');
  try { await writeFile(configPath, document.toString(), { mode: 0o600 }); }
  catch { throw new CliError('Unable to write the configuration file.'); }
}

/** An https origin without a path, as members open the team dashboard. */
function dashboardOrigin(value: string): string {
  const message = 'Use --origin with the team dashboard’s https address, for example https://keysentry.example.com.';
  let url: URL;
  try { url = new URL(value); } catch { throw new CliError(message); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/' || value.replace(/\/$/, '') !== url.origin) {
    throw new CliError(message);
  }
  return url.origin;
}

function rosterSummary(team: { roster: SignedTeamRoster; hash: string }) {
  const { roster } = team.roster;
  return {
    teamId: roster.teamId, version: roster.version, fingerprint: rosterFingerprint(team.roster), hash: team.hash,
    adminThreshold: roster.adminThreshold, updatedAt: roster.updatedAt,
    members: roster.members.map(member => ({ id: member.id, name: member.name, role: member.role, ...(member.email ? { email: member.email } : {}),
      ...(member.sso ? { sso: { ...member.sso } } : {}),
      deviceKeys: member.deviceKeys.map(key => key.keyId), passkeys: member.passkeys.map(passkey => ({ id: passkey.id, label: passkey.label, rpId: passkey.rpId })),
      ...(member.notify ? { notify: member.notify } : {}) })),
  };
}

function rosterTable(summary: ReturnType<typeof rosterSummary>, wideningAdmins?: number): string {
  const rows = summary.members.map(member => `${member.id.padEnd(14)} ${member.role.padEnd(9)} ${String(member.deviceKeys.length).padEnd(5)} ${String(member.passkeys.length).padEnd(9)} ${
    member.notify ? `${member.notify.channels.join(',') || '(none)'} (${member.notify.minSeverity}+)` : 'all channels'}  ${member.name}`);
  return [
    `Team ${summary.teamId} · roster version ${summary.version} · fingerprint ${summary.fingerprint}`,
    wideningAdmins !== undefined && wideningAdmins > summary.adminThreshold
      ? `Admin signatures needed for roster and policy changes: ${wideningAdmins} (the team policy's approvals.wideningAdmins; the roster's threshold is ${summary.adminThreshold})`
      : `Admin signatures needed for roster and policy changes: ${summary.adminThreshold}`,
    'Member         Role      Keys  Passkeys  Notifications  Name',
    ...rows,
  ].join('\n');
}

function governanceLines(governance: Governance): string[] {
  const lines: string[] = [];
  if (governance.team) lines.push(`Roster version ${governance.team.roster.roster.version} verified (fingerprint ${rosterFingerprint(governance.team.roster)}).`);
  else lines.push('This project has no team roster.');
  if (governance.policy.status === 'ok') lines.push(`Policy version ${governance.policy.policy.policy.version} verified (fingerprint ${policyFingerprint(governance.policy.policy)}).`);
  else if (governance.policy.status === 'none') lines.push('No team policy file is configured.');
  for (const blocker of governance.blockers) lines.push(`Changes are paused: ${blocker}`);
  return lines;
}

export function registerTeamCommands(program: Command, options: TeamCommandsOptions): void {
  const confirm = options.confirm ?? ((word: string) => confirmAction(word, options.diagnostic, options.promptIO));
  async function confirmed(word: string, yes: boolean | undefined): Promise<boolean> {
    if (yes) return true;
    return confirm(word);
  }
  const governance = (rt: TeamRuntime) => loadGovernance({ store: rt.store, settings: rt.config.settings, cwd: rt.config.cwd,
    env: options.env, anchors: anchors(rt) });

  /**
   * Sign and apply a roster change, or save a proposal when more than one admin must sign. The caller passed the human
   * gate. A change needs `max(adminThreshold, policy approvals.wideningAdmins)` admins of the current roster (review H1).
   */
  async function change(rt: TeamRuntime, change: RosterChange, output: string | undefined): Promise<SignedTeamRoster> {
    const team = await requireTeam(rt);
    const policy = (await appliedPolicy(rt))?.policy.policy ?? null;
    const wideningAdmins = policy?.approvals.wideningAdmins;
    const next = nextRoster(team.roster, change, now(rt));
    const signer = await localAdmin(rt, team.roster.roster);
    let signed: SignedTeamRoster;
    try { signed = signRoster(next, signer.memberId, signer.key); }
    finally { signer.key.privateKeyDer.fill(0); }
    const proposal = checkProposal(signed, team.roster, { wideningAdmins });
    if (!proposal.ok) throw new TeamError(proposal.reason);
    for (const line of describeRosterChange(team.roster.roster, next)) options.diagnostic(line);
    const required = adminsNeeded(team.roster.roster, wideningAdmins);
    const widens = (change.kind === 'add' && change.member.role !== 'viewer') || (change.kind === 'role' && change.role !== 'viewer');
    if (widens && required <= 1 && policy && Math.max(policy.approvals.required, ...Object.values(policy.approvals.requiredByTier ?? {}).filter((value): value is number => value !== undefined)) > 1) {
      options.diagnostic('Warning: this change needs one admin signature, but the team policy needs more than one approver for some actions. One admin can add or promote a member whose key they hold and then meet that quorum alone. Set approvals.wideningAdmins to 2 or more in the policy so member changes need more than one admin.');
    }
    if (required <= 1) {
      const result = await applyRoster(rt.store, signed, { anchor: anchors(rt).roster, wideningAdmins });
      await settleCandidates(rt, result.roster);
      await rt.audit.append({ kind: 'team:roster-applied', summary: 'Team roster change applied.', data: { version: next.version } });
      options.emit({ status: 'applied', version: next.version, fingerprint: rosterFingerprint(result.roster) },
        `Roster version ${next.version} applied (fingerprint ${rosterFingerprint(result.roster)}). Share the roster with other members' computers: keysentry team apply.`);
      return signed;
    }
    const path = target(rt, output ?? `keysentry-team-v${next.version}.json`);
    await writeNew(path, signed);
    await rt.audit.append({ kind: 'team:roster-proposed', summary: 'Team roster change proposed.', data: { version: next.version } });
    const why = required > team.roster.roster.adminThreshold ? ' The team policy asks for that many admins (approvals.wideningAdmins) for roster changes.' : '';
    options.emit({ status: 'proposed', version: next.version, path, signatures: 1, required },
      `Proposed roster version ${next.version} saved to ${path} with your signature (1 of ${required}).${why} Each other admin runs keysentry team sign <file> on their own computer; then run keysentry team apply <file>.`);
    return signed;
  }

  /**
   * Review M6: deployed watchers and cloud boxes keep the roster sealed at setup, so a removed or demoted member keeps
   * the rights they had there until setup runs again.
   */
  async function watcherReminder(rt: TeamRuntime, memberId: string): Promise<void> {
    let deployed: { signer: string }[] = [];
    try { deployed = await knownWatcherKeys(rt.vault); } catch { deployed = []; }
    if (!deployed.length) return;
    options.diagnostic(`Deployed watchers and cloud boxes keep the roster sealed when they were set up: until you run keysentry watcher setup again (and keysentry box send-tokens for a cloud box), they still accept approvals and disarms from ${memberId} as before.`);
  }

  /** Review M5: a member's channels that nobody else receives. Refuse unless the caller drops them from this computer. */
  async function memberChannels(rt: TeamRuntime, memberId: string, drop: boolean | undefined): Promise<string[]> {
    const team = await requireTeam(rt);
    const own = exclusiveChannels(team.roster.roster, memberId);
    if (own.length && !drop) {
      throw new TeamError(`${memberId} receives notifications on channels no other member receives (${own.join(', ')}). Run again with --drop-channels to remove them from keysentry.yaml on this computer; after the change the roster keeps them member-owned, so other computers send them no team messages.`);
    }
    return own;
  }

  const team = program.command('team').description('Team roster: members, roles and the admins who sign changes');
  team.command('init').description('Start a team; this computer becomes its first admin')
    .option('--id <id>', 'Your member id (lowercase)', 'admin').option('--name <name>', 'Your display name').option('--email <email>', 'Your email, for single sign-on')
    .action(async (opts: { id: string; name?: string; email?: string }) => {
      options.human('create a team');
      const rt = await options.getRuntime();
      if (await loadTeam(rt.store, { anchor: anchors(rt).roster })) throw new TeamError('This project already has a team. Use keysentry team list to see it.');
      const key = await rt.signingKey();
      let signed: SignedTeamRoster;
      try {
        const roster = createRoster({ now: now(rt), admin: { id: opts.id, name: displayName(opts.name, opts.id), email: email(opts.email),
          deviceKeys: [devicePublicKey(key)], passkeys: await listPasskeys(rt.store, rt.vault) } });
        signed = signRoster(roster, opts.id, key);
      } finally { key.privateKeyDer.fill(0); }
      const result = await applyRoster(rt.store, signed, { anchor: anchors(rt).roster });
      await rt.audit.append({ kind: 'team:init', summary: 'Team roster created.', data: { version: 1 } });
      let enabledNote = '';
      if (!rt.config.settings.team.enabled) {
        await updateTeamSettings(rt.config.configPath, { enabled: true });
        rt.config.settings.team.enabled = true;
        enabledNote = '\nTeam mode turned on in keysentry.yaml (team.enabled: true).';
      }
      options.emit({ status: 'created', teamId: signed.roster.teamId, version: 1, fingerprint: rosterFingerprint(result.roster), memberId: opts.id },
        `Team ${signed.roster.teamId} created. You (${opts.id}) are its first admin. Roster fingerprint: ${rosterFingerprint(result.roster)}.${enabledNote}`);
    });
  team.command('card').description('Print this computer\'s public member card (device key and passkeys) for an admin')
    .option('-o, --output <file>', 'Write the card to a new file')
    .action(async (opts: { output?: string }) => {
      const rt = await options.getRuntime();
      const key = await rt.signingKey();
      let card;
      try { card = { v: 1 as const, kind: 'keysentry-member-card' as const, deviceKeys: [devicePublicKey(key)], passkeys: await listPasskeys(rt.store, rt.vault) }; }
      finally { key.privateKeyDer.fill(0); }
      if (opts.output) {
        const path = target(rt, opts.output);
        await writeNew(path, card);
        options.emit({ path, deviceKey: card.deviceKeys[0]!.keyId }, `Member card written to ${path}. It holds only public keys; send it to a team admin.`);
      } else options.emit(card, JSON.stringify(card, null, 2));
    });
  team.command('add <id>').description('Add a member (signs the change, or saves a proposal for other admins)')
    .requiredOption('--role <role>', 'viewer, operator or admin').option('--card <file>', 'The member card from keysentry team card')
    .option('--name <name>', 'Display name').option('--email <email>', 'Email for single sign-on')
    .option('--notify <channels>', 'Notification channel ids this member receives', collect).option('--min-severity <severity>', 'info, warning or urgent')
    .option('-o, --output <file>', 'Where to save a proposal that other admins must sign')
    .action(async (id: string, opts: { role: string; card?: string; name?: string; email?: string; notify?: string[]; minSeverity?: string; output?: string }) => {
      options.human('add a team member');
      const memberRole = role(opts.role);
      const rt = await options.getRuntime();
      let keys: { deviceKeys: { keyId: string; publicKeyDer: string }[]; passkeys: SignedTeamRoster['roster']['members'][number]['passkeys'] } = { deviceKeys: [], passkeys: [] };
      if (opts.card) {
        const parsed = memberCardSchema.safeParse(await readTeamFile(target(rt, opts.card), 'member card'));
        if (!parsed.success) throw new CliError('The member card is not valid. Ask the member to run keysentry team card again.');
        keys = { deviceKeys: parsed.data.deviceKeys, passkeys: parsed.data.passkeys as typeof keys.passkeys };
      } else if (memberRole !== 'viewer') options.diagnostic('No member card: this member cannot approve or sign until their device key or passkey is added.');
      const notify = opts.notify ? { channels: opts.notify, minSeverity: severity(opts.minSeverity) } : undefined;
      warnUnknownChannels(rt, notify?.channels);
      await change(rt, { kind: 'add', member: { id, name: displayName(opts.name, id), role: memberRole, email: email(opts.email), ...keys, ...(notify ? { notify } : {}) } },
        opts.output);
    });
  team.command('remove <id>').description('Remove a member').option('-o, --output <file>', 'Where to save a proposal that other admins must sign')
    .option('--drop-channels', 'Also remove the member\'s own notification channels (ones no other member receives) from keysentry.yaml')
    .action(async (id: string, opts: { output?: string; dropChannels?: boolean }) => {
      options.human('remove a team member');
      const rt = await options.getRuntime();
      const own = await memberChannels(rt, id, opts.dropChannels);
      await change(rt, { kind: 'remove', memberId: id }, opts.output);
      const dropped = await dropChannels(rt, own);
      if (dropped.length) options.diagnostic(`Removed ${dropped.join(', ')} from keysentry.yaml on this computer.`);
      await watcherReminder(rt, id);
    });
  team.command('role <id> <role>').description('Change a member\'s role').option('-o, --output <file>', 'Where to save a proposal that other admins must sign')
    .action(async (id: string, value: string, opts: { output?: string }) => {
      options.human('change a team role');
      const memberRole = role(value);
      const rt = await options.getRuntime();
      await change(rt, { kind: 'role', memberId: id, role: memberRole }, opts.output);
      await watcherReminder(rt, id);
    });
  team.command('threshold <n>').description('How many admins must sign roster and policy changes').option('-o, --output <file>', 'Where to save a proposal that other admins must sign')
    .action(async (value: string, opts: { output?: string }) => {
      options.human('change the team admin threshold');
      const count = threshold(value);
      await change(await options.getRuntime(), { kind: 'threshold', adminThreshold: count }, opts.output);
    });
  team.command('notify <id>').description('Route notification channels to a member')
    .option('--channels <ids>', 'Channel ids this member receives', collect).option('--min-severity <severity>', 'info, warning or urgent')
    .option('--clear', 'Stop routing to this member; channels nobody else receives stop receiving team messages')
    .option('--drop-channels', 'With --clear: also remove the member\'s own channels (ones no other member receives) from keysentry.yaml')
    .option('-o, --output <file>', 'Where to save a proposal that other admins must sign')
    .action(async (id: string, opts: { channels?: string[]; minSeverity?: string; clear?: boolean; dropChannels?: boolean; output?: string }) => {
      options.human('change team notification routing');
      if (!!opts.clear === (opts.channels !== undefined)) throw new CliError('Use either --channels (with --min-severity) or --clear.');
      if (opts.dropChannels && !opts.clear) throw new CliError('Use --drop-channels together with --clear.');
      const rt = await options.getRuntime();
      const notify = opts.channels ? { channels: opts.channels, minSeverity: severity(opts.minSeverity) } : null;
      warnUnknownChannels(rt, notify?.channels);
      const own = opts.clear ? await memberChannels(rt, id, opts.dropChannels) : [];
      await change(rt, { kind: 'notify', memberId: id, notify }, opts.output);
      const dropped = await dropChannels(rt, own);
      if (dropped.length) options.diagnostic(`Removed ${dropped.join(', ')} from keysentry.yaml on this computer.`);
    });
  team.command('list').description('Show the team roster').action(async () => {
    const rt = await options.getRuntime();
    const loaded = await loadTeam(rt.store, { anchor: anchors(rt).roster });
    if (!loaded) { options.emit({ team: null }, 'This project has no team. Run keysentry team init to start one.'); return; }
    const summary = rosterSummary(loaded);
    // The applied policy can raise what roster and policy changes need (review H1); an unreadable one is reported by team verify.
    let wideningAdmins: number | undefined;
    try { wideningAdmins = (await appliedPolicy(rt))?.policy.policy.approvals.wideningAdmins; } catch { wideningAdmins = undefined; }
    options.emit({ ...summary, adminsNeeded: adminsNeeded(loaded.roster.roster, wideningAdmins) }, rosterTable(summary, wideningAdmins));
  });
  team.command('export').description('Write the signed roster in use, for other members\' computers (keysentry team apply)')
    .option('-o, --output <file>', 'Write to a new file instead of printing')
    .action(async (opts: { output?: string }) => {
      const rt = await options.getRuntime();
      const loaded = await requireTeam(rt);
      const fp = rosterFingerprint(loaded.roster);
      if (opts.output) {
        const path = target(rt, opts.output);
        await writeNew(path, loaded.roster);
        options.emit({ path, version: loaded.roster.roster.version, fingerprint: fp },
          `Roster version ${loaded.roster.roster.version} written to ${path}. A new member's computer applies it with: keysentry team apply <file> --fingerprint ${fp}`);
      } else options.emit(loaded.roster, JSON.stringify(loaded.roster, null, 2));
    });
  team.command('verify').description('Check the saved roster, team mode and the policy file').action(async () => {
    const rt = await options.getRuntime();
    const result = await governance(rt);
    const lines = governanceLines(result);
    options.emit({ ok: result.blockers.length === 0, roster: result.team ? rosterSummary(result.team) : null,
      policy: result.policy.status === 'ok' ? { version: result.policy.policy.policy.version, fingerprint: policyFingerprint(result.policy.policy) } : null,
      blockers: result.blockers }, lines.join('\n'));
    if (result.blockers.length) options.setExit(1);
  });
  team.command('sign <file>').description('Add your admin signature to a proposed roster from another admin')
    .option('--yes', 'Skip the typed confirmation; an interactive terminal is still required')
    .action(async (file: string, opts: { yes?: boolean }) => {
      options.human('sign a team roster change');
      const rt = await options.getRuntime();
      const current = await requireTeam(rt);
      const path = target(rt, file);
      const wideningAdmins = (await appliedPolicy(rt))?.policy.policy.approvals.wideningAdmins;
      const proposal = checkProposal(await readTeamFile(path, 'roster proposal'), current.roster, { wideningAdmins });
      if (!proposal.ok) throw new TeamError(proposal.reason);
      for (const line of describeRosterChange(current.roster.roster, proposal.roster.roster)) options.diagnostic(line);
      if (!await confirmed(`roster-v${proposal.roster.roster.version}`, opts.yes)) { options.emit({ cancelled: true }, 'Not signed. Nothing changed.'); return; }
      const signer = await localAdmin(rt, current.roster.roster);
      let signed: SignedTeamRoster;
      try { signed = signRoster(proposal.roster, signer.memberId, signer.key); }
      finally { signer.key.privateKeyDer.fill(0); }
      await replace(path, signed);
      const count = new Set([...proposal.signers, signer.memberId]).size;
      await rt.audit.append({ kind: 'team:roster-signed', summary: 'Team roster change signed.', data: { version: proposal.roster.roster.version } });
      options.emit({ status: 'signed', path, version: proposal.roster.roster.version, signatures: count, required: proposal.required },
        `Signed roster version ${proposal.roster.roster.version} (${count} of ${proposal.required} admin signatures). ${count >= proposal.required
          ? `It has enough signatures: run keysentry team apply ${file}.` : 'Send it to another admin to sign.'}`);
    });
  team.command('apply <file>').description('Apply a fully signed roster (also how a member\'s computer joins the team)')
    .option('--fingerprint <fingerprint>', 'The roster fingerprint an admin gave you (needed when this computer has no roster yet)')
    .option('--yes', 'Skip the typed confirmation; an interactive terminal is still required')
    .action(async (file: string, opts: { fingerprint?: string; yes?: boolean }) => {
      options.human('apply a team roster change');
      const rt = await options.getRuntime();
      const anchor = anchors(rt).roster;
      let current: LoadedTeam | null = null;
      // A roster missing from saved state can be restored with a fingerprint-checked file (applyRoster checks the checkpoint).
      try { current = await loadTeam(rt.store, { anchor }); }
      catch (error) { if (!opts.fingerprint) throw error; }
      if (!current && !opts.fingerprint) {
        throw new TeamError('This computer has no team roster yet. Ask an admin for the roster fingerprint (keysentry team list shows it), then run keysentry team apply <file> --fingerprint <fingerprint>.');
      }
      const input = await readTeamFile(target(rt, file), 'roster file');
      const parsed = parseSignedRoster(input);
      if (!parsed.ok) throw new TeamError(parsed.reason);
      if (current && rosterHash(parsed.value) === current.hash) {
        options.emit({ status: 'unchanged', version: current.roster.roster.version }, `Roster version ${current.roster.roster.version} is already in use.`); return;
      }
      // The policy applied here binds roster changes too: wideningAdmins admins of the current roster (review H1).
      const wideningAdmins = current ? (await appliedPolicy(rt))?.policy.policy.approvals.wideningAdmins : undefined;
      const check = current ? verifyRoster(input, current.roster, { wideningAdmins }) : verifyFirstUse(input, opts.fingerprint!);
      if (!check.ok) throw new TeamError(check.reason);
      for (const line of describeRosterChange(current?.roster.roster ?? null, check.roster.roster)) options.diagnostic(line);
      if (!await confirmed(`roster-v${check.roster.roster.version}`, opts.yes)) { options.emit({ cancelled: true }, 'Not applied. Nothing changed.'); return; }
      const result = await applyRoster(rt.store, input, { anchor, wideningAdmins, ...(current ? {} : { trust: { fingerprint: opts.fingerprint! } }) });
      if (result.status === 'unchanged') { options.emit({ status: 'unchanged', version: result.roster.roster.version }, `Roster version ${result.roster.roster.version} is already in use.`); return; }
      await rt.audit.append({ kind: 'team:roster-applied', summary: 'Team roster change applied.', data: { version: result.roster.roster.version } });
      await settleCandidates(rt, result.roster);
      let enabledNote = '';
      if (!rt.config.settings.team.enabled) {
        await updateTeamSettings(rt.config.configPath, { enabled: true });
        rt.config.settings.team.enabled = true;
        enabledNote = ' Team mode turned on in keysentry.yaml.';
      }
      options.emit({ status: 'applied', version: result.roster.roster.version, fingerprint: rosterFingerprint(result.roster) },
        `Roster version ${result.roster.roster.version} applied (fingerprint ${rosterFingerprint(result.roster)}).${enabledNote}`);
    });

  team.command('sso <id>').description('Pin a member’s single sign-on identity (issuer and subject) in the roster')
    .option('--issuer <url>', 'The identity provider issuer, exactly as it publishes it').option('--subject <sub>', 'The member’s subject (sub) at that provider')
    .option('--clear', 'Remove the pinned identity; the member signs in by verified email again')
    .option('-o, --output <file>', 'Where to save a proposal that other admins must sign')
    .action(async (id: string, opts: { issuer?: string; subject?: string; clear?: boolean; output?: string }) => {
      options.human('pin a single sign-on identity');
      if (!!opts.clear === (opts.issuer !== undefined || opts.subject !== undefined)) throw new CliError('Use --issuer with --subject, or --clear.');
      let sso: { issuer: string; subject: string } | null = null;
      if (!opts.clear) {
        const parsed = ssoSchema.safeParse({ issuer: opts.issuer, subject: opts.subject });
        if (!parsed.success) {
          throw new CliError('Use --issuer with the provider’s https issuer URL and --subject with the member’s subject (1 to 255 printable characters). The team dashboard’s account page shows both.');
        }
        sso = parsed.data;
      }
      await change(await options.getRuntime(), { kind: 'sso', memberId: id, sso }, opts.output);
    });
  team.command('invite <id>').description('Print a single-use link, signed by your admin device key, that lets a member add a passkey on the team dashboard (15 minutes)')
    .requiredOption('--origin <url>', 'The team dashboard’s https address (its public origin)')
    .action(async (id: string, opts: { origin: string }) => {
      options.human('invite a team member to add a passkey');
      const origin = dashboardOrigin(opts.origin);
      const rt = await options.getRuntime();
      const current = await requireTeam(rt);
      const member = current.roster.roster.members.find(candidate => candidate.id === id);
      if (!member) throw new TeamError(`There is no member ${/^[a-z][a-z0-9_-]{0,31}$/.test(id) ? id : 'with that id'} on this team.`);
      // Review H3: the invitation is signed here, on an admin's own computer. The team server only checks the signature
      // against the roster's admins and remembers the link once used; it never needs an admin's private key.
      const signer = await localAdmin(rt, current.roster.roster);
      let invite: { token: string; expiresAt: string };
      try {
        invite = signInvite({ memberId: member.id, origin, now: now(rt), ttlMs: INVITE_TTL_MS, signer: signer.key,
          ...(options.printable ? { printable: (token: string) => options.printable!(`${origin}/enroll#${token}`) } : {}) });
      } finally { signer.key.privateKeyDer.fill(0); }
      await rt.audit.append({ kind: 'team:invite', summary: 'A passkey enrollment link was signed.', data: { memberId: member.id } });
      // The link is in the fragment, so browsers never send it with the page request or put it in a request log.
      const link = `${origin}/enroll#${invite.token}`;
      options.emit({ memberId: member.id, origin, expiresAt: invite.expiresAt, link },
        [`Enrollment link for ${member.id} (works once, until ${invite.expiresAt}):`, link,
          `Send it to ${member.id} privately. The passkey they create works only after admins add it to the roster: on the team dashboard host run keysentry team passkeys pending -o <file> (or download the card from the dashboard's Account page), then on your computer keysentry team add-passkey ${member.id} --card <file>.`].join('\n'));
    });
  const passkeys = team.command('passkeys').description('Passkeys members created on the team dashboard');
  passkeys.command('pending').description('List passkeys waiting for an admin to add them to the roster; -o writes them as a card for an admin')
    .option('-o, --output <file>', 'Write the waiting passkeys (public keys only) to a new card file for keysentry team add-passkey --card')
    .action(async (opts: { output?: string }) => {
      // Read-only and public: the team server (no admin key) lists and exports candidates for an admin's computer.
      const rt = await options.getRuntime();
      const loaded = await loadTeam(rt.store, { anchor: anchors(rt).roster });
      const onRoster = new Set(loaded?.roster.roster.members.flatMap(member => member.passkeys.map(passkey => passkey.id)) ?? []);
      const candidates = (await listCandidates(rt.store)).filter(candidate => !onRoster.has(candidate.credential.id));
      const pending = candidates.map(candidate => ({ memberId: candidate.memberId, credentialId: candidate.credential.id, createdAt: candidate.createdAt,
        rpId: candidate.credential.rpId, origin: candidate.credential.origins[0] ?? null, fingerprint: candidateFingerprint(candidate),
        ...(candidate.aaguid ? { reportedAuthenticator: candidate.aaguid } : {}) }));
      if (opts.output) {
        if (!candidates.length) { options.emit({ pending, path: null }, 'No passkeys are waiting, so no card was written.'); return; }
        const path = target(rt, opts.output);
        await writeNew(path, candidateCard(candidates));
        options.emit({ pending, path }, [`Wrote ${candidates.length} waiting passkey${candidates.length === 1 ? '' : 's'} to ${path}. The card holds public keys only.`,
          'On an admin\'s computer: keysentry team add-passkey <member> --card <file>. Compare each fingerprint with the member first.'].join('\n'));
        return;
      }
      options.emit({ pending }, pending.length ? ['Member         Created at                Fingerprint                              Credential id', ...pending.map(item =>
        `${item.memberId.padEnd(14)} ${item.createdAt.padEnd(25)} ${item.fingerprint}  ${item.credentialId}${item.reportedAuthenticator
          ? `  (authenticator model ${item.reportedAuthenticator}, reported by the authenticator, not verified)` : ''}`),
      'Compare the fingerprint with the member, then export a card for an admin: keysentry team passkeys pending -o <file>.'].join('\n') : 'No passkeys are waiting.');
    });
  team.command('add-passkey <id> [credentialId]').description('Add a passkey a member created on the team dashboard (a signed roster change on an admin\'s computer)')
    .option('--card <file>', 'The card from keysentry team passkeys pending -o on the team dashboard host')
    .option('-o, --output <file>', 'Where to save a proposal that other admins must sign')
    .action(async (id: string, credentialId: string | undefined, opts: { card?: string; output?: string }) => {
      options.human('add a passkey to the team roster');
      const rt = await options.getRuntime();
      const available: EnrollmentCandidate[] = opts.card ? parseCandidateCard(await readTeamFile(target(rt, opts.card), 'passkey card')) : await listCandidates(rt.store);
      const forMember = available.filter(item => item.memberId === id);
      let candidate: EnrollmentCandidate | undefined;
      if (credentialId !== undefined) {
        candidate = available.find(item => item.credential.id === credentialId);
        if (!candidate) throw new TeamError(opts.card ? 'The card has no passkey with that credential id.' : 'No pending passkey has that credential id. Run keysentry team passkeys pending.');
        // A candidate is bound to the member whose invitation created it; it never goes on anyone else's card.
        if (candidate.memberId !== id) throw new TeamError('That passkey was enrolled from another member’s link. Add it only to that member.');
      } else {
        if (!opts.card) throw new CliError('Name the credential id, or pass the card from the team dashboard host with --card <file>.');
        if (forMember.length !== 1) {
          throw new TeamError(forMember.length ? `The card has ${forMember.length} passkeys for ${id}. Name the one to add by its credential id.` : `The card has no passkey for ${id}.`);
        }
        candidate = forMember[0];
      }
      options.diagnostic(`Passkey ${candidate!.credential.id} for ${id}, created ${candidate!.createdAt} at ${candidate!.credential.origins.join(', ')}; fingerprint ${candidateFingerprint(candidate!)}. Compare the fingerprint with ${id} before you sign.`);
      await change(rt, { kind: 'passkey', memberId: id, passkey: candidate!.credential }, opts.output);
    });

  const policy = program.command('policy').description('Team policy-as-code: rules that only narrow what this project may do');
  policy.command('show').description('Show the team policy in force').action(async () => {
    const rt = await options.getRuntime();
    const result = await governance(rt);
    if (result.policy.status === 'ok') {
      const signed = result.policy.policy;
      options.emit({ version: signed.policy.version, fingerprint: policyFingerprint(signed), path: result.policy.path, policy: signed.policy, blockers: result.blockers },
        [`Team policy version ${signed.policy.version} (fingerprint ${policyFingerprint(signed)}) from ${result.policy.path}`, ...describePolicy(signed.policy),
          ...result.blockers.map(blocker => `Changes are paused: ${blocker}`)].join('\n'));
    } else if (result.policy.status === 'none') {
      options.emit({ policy: null, blockers: result.blockers }, ['No team policy is in use. Set team.policyFile in keysentry.yaml to use one.', ...result.blockers.map(blocker => `Changes are paused: ${blocker}`)].join('\n'));
    } else {
      options.emit({ policy: null, blockers: result.blockers }, result.blockers.map(blocker => `Changes are paused: ${blocker}`).join('\n'));
    }
    if (result.blockers.length) options.setExit(1);
  });
  policy.command('sign <file>').description('Sign a policy draft or another admin\'s proposed policy')
    .option('--yes', 'Skip the typed confirmation; an interactive terminal is still required')
    .action(async (file: string, opts: { yes?: boolean }) => {
      options.human('sign a team policy');
      const rt = await options.getRuntime();
      const current = await requireTeam(rt);
      const path = target(rt, file);
      const head = await loadPolicyHead(rt.store, { anchor: anchors(rt).policy });
      const prepared = preparePolicyDraft(await readTeamFile(path, 'policy file'), { roster: current.roster.roster, head, now: now(rt) });
      const check = checkPolicyProposal(prepared, current.roster.roster, head);
      if (!check.ok) throw new CliError(check.reason);
      if (check.relation === 'same') throw new CliError('This is the policy already in use. Make your changes in a new draft.');
      options.diagnostic(`Policy version ${prepared.policy.version}:`);
      for (const line of describePolicy(prepared.policy)) options.diagnostic(`  ${line}`);
      if (!await confirmed(`policy-v${prepared.policy.version}`, opts.yes)) { options.emit({ cancelled: true }, 'Not signed. Nothing changed.'); return; }
      const signer = await localAdmin(rt, current.roster.roster);
      let signed: SignedTeamPolicy;
      try { signed = signPolicy(prepared, signer.memberId, signer.key); }
      finally { signer.key.privateKeyDer.fill(0); }
      await replace(path, signed);
      const count = new Set([...check.signers, signer.memberId]).size;
      // A newer version needs the policy in force's approvals.wideningAdmins admins too (review H1).
      const required = check.required;
      const why = required > current.roster.roster.adminThreshold ? ' The policy in force asks for that many admins (approvals.wideningAdmins) before its rules can change.' : '';
      await rt.audit.append({ kind: 'policy:signed', summary: 'Team policy signed.', data: { version: prepared.policy.version } });
      options.emit({ status: 'signed', path, version: prepared.policy.version, signatures: count, required },
        `Signed policy version ${prepared.policy.version} (${count} of ${required} admin signatures).${why} ${count >= required
          ? `It has enough signatures: run keysentry policy apply ${file}.` : 'Send it to another admin to sign.'}`);
    });
  policy.command('apply <file>').description('Apply a fully signed policy and make it the project\'s policy file')
    .option('--yes', 'Skip the typed confirmation; an interactive terminal is still required')
    .action(async (file: string, opts: { yes?: boolean }) => {
      options.human('apply a team policy');
      const rt = await options.getRuntime();
      const current = await requireTeam(rt);
      const path = target(rt, file);
      const input = await readTeamFile(path, 'policy file');
      const anchor = anchors(rt).policy;
      const check = verifyPolicy(input, current.roster.roster, await loadPolicyHead(rt.store, { anchor }));
      if (!check.ok) throw new CliError(check.reason);
      for (const line of describePolicy(check.policy.policy)) options.diagnostic(line);
      if (check.relation !== 'same' && !await confirmed(`policy-v${check.policy.policy.version}`, opts.yes)) { options.emit({ cancelled: true }, 'Not applied. Nothing changed.'); return; }
      const result = await applyPolicy(rt.store, input, { roster: current.roster.roster, anchor });
      const configured = rt.config.settings.team.policyFile;
      let where = '';
      if (!configured) {
        const relativePath = relative(rt.config.cwd, path);
        const setting = relativePath && !relativePath.startsWith('..') && !isAbsolute(relativePath) ? relativePath.split('\\').join('/') : path;
        await updateTeamSettings(rt.config.configPath, { policyFile: setting });
        rt.config.settings.team.policyFile = setting;
        where = ` team.policyFile set to ${setting} in keysentry.yaml.`;
      } else if (resolve(rt.config.cwd, configured) !== path) {
        await replace(resolve(rt.config.cwd, configured), result.policy);
        where = ` Copied to ${configured}.`;
      }
      if (result.status === 'applied') await rt.audit.append({ kind: 'policy:applied', summary: 'Team policy applied.', data: { version: result.policy.policy.version } });
      options.emit({ status: result.status, version: result.policy.policy.version, fingerprint: policyFingerprint(result.policy) },
        `${result.status === 'applied' ? 'Applied' : 'Already using'} team policy version ${result.policy.policy.version} (fingerprint ${policyFingerprint(result.policy)}).${where}`);
    });
  policy.command('verify').description('Check the policy file against the roster and the applied version').action(async () => {
    const rt = await options.getRuntime();
    const result = await governance(rt);
    options.emit({ ok: result.blockers.length === 0, policy: result.policy.status === 'ok'
      ? { version: result.policy.policy.policy.version, fingerprint: policyFingerprint(result.policy.policy) } : null, blockers: result.blockers },
    governanceLines(result).join('\n'));
    if (result.blockers.length) options.setExit(1);
  });

  /** Pending passkeys that the applied roster now lists are done; drop them from the waiting list. */
  async function settleCandidates(rt: TeamRuntime, roster: SignedTeamRoster): Promise<void> {
    const ids = roster.roster.members.flatMap(member => member.passkeys.map(passkey => passkey.id));
    try { await removeCandidates(rt.store, ids); }
    catch { options.diagnostic('The list of pending passkeys could not be updated. Run keysentry team passkeys pending to review it.'); }
  }

  function warnUnknownChannels(rt: TeamRuntime, channels: string[] | undefined): void {
    if (!channels) return;
    if (channels.some(id => !/^[A-Za-z0-9_-]{1,64}$/.test(id))) throw new CliError('Channel ids use letters, digits, - and _.');
    const known = new Set(rt.config.settings.notify.channels.map(channel => channel.id));
    if (channels.some(id => !known.has(id))) options.diagnostic('Some channel ids are not configured on this computer; they apply where a channel with that id exists.');
  }
}
