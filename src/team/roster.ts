// The signed team roster: create, change, sign, verify the version chain, and keep the latest verified version in
// encrypted project state with rollback and fork protection.
import { randomBytes } from 'node:crypto';
import { join, resolve } from 'node:path';
import { CliError } from '../cli/errors.js';
import type { StateStore } from '../core/store.js';
import type { DeviceKey } from '../security/index.js';
import type { NotifySeverity, PasskeyCredential, SignedTeamRoster, TeamMember, TeamRole, TeamRoster, Vault } from '../types.js';
import {
  asciiEmail, foldEmail, keyIdFor, parseSignedRoster, ROLE_RANK, rosterProblem, rosterSchema, MAX_MEMBERS, MAX_RETIRED_CHANNELS, memberIdPattern, teamIdPattern,
} from './schema.js';
import { documentHash, fingerprint, fingerprintMatches, signTeamDocument, verifyTeamSignatures } from './signature.js';

/** A refused team operation. Messages are fixed text (member ids are validated identifiers, never secrets). */
export class TeamError extends CliError {
  readonly code = 'TEAM_REFUSED';
  constructor(message: string) { super(message); this.name = 'TeamError'; }
}

export function rosterHash(signed: SignedTeamRoster): string { return documentHash(signed); }
export function rosterFingerprint(signed: SignedTeamRoster): string { return fingerprint(rosterHash(signed)); }

export function hasRole(member: Pick<TeamMember, 'role'>, role: TeamRole): boolean {
  return ROLE_RANK[member.role] >= ROLE_RANK[role];
}

function clone<T>(value: T): T { return structuredClone(value); }

function checked(roster: TeamRoster): TeamRoster {
  if (Array.isArray(roster.members) && roster.members.length > MAX_MEMBERS) throw new TeamError(`A team can have at most ${MAX_MEMBERS} members.`);
  const parsed = rosterSchema.safeParse(roster);
  if (!parsed.success) throw new TeamError('The roster change is not valid (wrong type, unknown field, or invalid value).');
  const problem = rosterProblem(parsed.data);
  if (problem) throw new TeamError(problem);
  return parsed.data as TeamRoster;
}

export interface NewMember {
  id: string;
  name: string;
  role: TeamRole;
  email?: string;
  sso?: { issuer: string; subject: string };
  passkeys?: PasskeyCredential[];
  deviceKeys?: { keyId: string; publicKeyDer: string }[];
  notify?: { channels: string[]; minSeverity: NotifySeverity };
}

function member(input: NewMember): TeamMember {
  if (!memberIdPattern.test(input.id)) throw new TeamError('Member ids use lowercase letters, digits, - and _, start with a letter, and have at most 32 characters.');
  return {
    id: input.id, name: input.name, role: input.role,
    ...(input.email === undefined ? {} : { email: foldEmail(input.email) }),
    ...(input.sso === undefined ? {} : { sso: { issuer: input.sso.issuer, subject: input.sso.subject } }),
    passkeys: clone(input.passkeys ?? []), deviceKeys: clone(input.deviceKeys ?? []),
    ...(input.notify ? { notify: { channels: [...input.notify.channels], minSeverity: input.notify.minSeverity } } : {}),
  };
}

export function devicePublicKey(key: Pick<DeviceKey, 'keyId' | 'publicKeyDer'>): { keyId: string; publicKeyDer: string } {
  return { keyId: keyIdFor(key.publicKeyDer), publicKeyDer: key.publicKeyDer.toString('base64') };
}

/** Version 1: this device's owner is the first admin (a team of one signs its own roster). */
export function createRoster(input: { admin: Omit<NewMember, 'role'>; teamId?: string; now: Date }): TeamRoster {
  const teamId = input.teamId ?? randomBytes(16).toString('base64url');
  if (!teamIdPattern.test(teamId)) throw new TeamError('A team id uses 8 to 64 letters, digits, - or _.');
  return checked({ v: 1, teamId, version: 1, prev: null, updatedAt: input.now.toISOString(), members: [member({ ...input.admin, role: 'admin' })], adminThreshold: 1 });
}

export type RosterChange =
  | { kind: 'add'; member: NewMember }
  | { kind: 'remove'; memberId: string }
  | { kind: 'role'; memberId: string; role: TeamRole }
  | { kind: 'threshold'; adminThreshold: number }
  | { kind: 'notify'; memberId: string; notify: { channels: string[]; minSeverity: NotifySeverity } | null }
  /** Pin (or clear) the identity provider's subject for single sign-on. */
  | { kind: 'sso'; memberId: string; sso: { issuer: string; subject: string } | null }
  /** Add a passkey enrolled on the team dashboard (its public credential only). */
  | { kind: 'passkey'; memberId: string; passkey: PasskeyCredential };

/** The unsigned next version of `current` with one change applied. */
export function nextRoster(current: SignedTeamRoster, change: RosterChange, now: Date): TeamRoster {
  const base = current.roster;
  const members = clone(base.members);
  let adminThreshold = base.adminThreshold;
  const find = (id: string) => {
    const found = members.find(candidate => candidate.id === id);
    if (!found) throw new TeamError(`There is no member ${memberIdPattern.test(id) ? id : 'with that id'} on this team.`);
    return found;
  };
  switch (change.kind) {
    case 'add':
      if (members.some(candidate => candidate.id === change.member.id)) throw new TeamError(`Member ${change.member.id} is already on this team.`);
      members.push(member(change.member));
      break;
    case 'remove': {
      const removed = find(change.memberId);
      members.splice(members.indexOf(removed), 1);
      break;
    }
    case 'role': find(change.memberId).role = change.role; break;
    case 'threshold': adminThreshold = change.adminThreshold; break;
    case 'notify': {
      const target = find(change.memberId);
      if (change.notify) target.notify = { channels: [...change.notify.channels], minSeverity: change.notify.minSeverity };
      else delete target.notify;
      break;
    }
    case 'sso': {
      const target = find(change.memberId);
      if (change.sso) target.sso = { issuer: change.sso.issuer, subject: change.sso.subject };
      else delete target.sso;
      break;
    }
    case 'passkey': {
      const target = find(change.memberId);
      if (members.some(candidate => candidate.passkeys.some(passkey => passkey.id === change.passkey.id))) throw new TeamError('This passkey is already on the team roster.');
      target.passkeys.push(clone(change.passkey));
      break;
    }
  }
  if (!Number.isSafeInteger(base.version + 1)) throw new TeamError('The roster version cannot be increased.');
  // A channel a member received stays member-owned once nobody is assigned to it: it is retired and routed nothing,
  // rather than becoming a channel that receives every team message (review M5).
  const assigned = new Set(members.flatMap(entry => entry.notify?.channels ?? []));
  const retired = [...new Set([...base.retiredChannels ?? [], ...assignedChannels(base)])].filter(channel => !assigned.has(channel)).sort();
  if (retired.length > MAX_RETIRED_CHANNELS) throw new TeamError(`A roster can keep at most ${MAX_RETIRED_CHANNELS} retired notification channels.`);
  const { retiredChannels: _previous, ...rest } = base;
  return checked({ ...rest, version: base.version + 1, prev: rosterHash(current), updatedAt: now.toISOString(), members, adminThreshold,
    ...(retired.length ? { retiredChannels: retired } : {}) });
}

function assignedChannels(roster: TeamRoster): string[] {
  return roster.members.flatMap(entry => entry.notify?.channels ?? []);
}

/** Channels routed to `memberId` that no other member receives (they would be retired if the member left). */
export function exclusiveChannels(roster: TeamRoster, memberId: string): string[] {
  const target = roster.members.find(entry => entry.id === memberId);
  if (!target?.notify) return [];
  const others = new Set(roster.members.filter(entry => entry.id !== memberId).flatMap(entry => entry.notify?.channels ?? []));
  return target.notify.channels.filter(channel => !others.has(channel));
}

/**
 * Distinct admins of the roster in force that a roster or policy change needs: the roster's threshold, or the policy
 * in force's `approvals.wideningAdmins` when that is higher (review H1).
 */
export function adminsNeeded(roster: Pick<TeamRoster, 'adminThreshold'>, wideningAdmins?: number): number {
  return Math.max(roster.adminThreshold, wideningAdmins ?? 0);
}

/** Admins of `roster` who hold a device key, i.e. who could sign a later change. */
function signingAdmins(roster: TeamRoster): number {
  return roster.members.filter(entry => entry.role === 'admin' && entry.deviceKeys.length > 0).length;
}

/**
 * A plain warning when `roster`, under a policy with `wideningAdmins`, leaves no spare signing admin: every admin with
 * a device key is needed to sign the next roster or policy change (a 2-of-2 widening rule, or a single admin), so losing
 * one admin device blocks every later change. There is no bypass; the recovery is to keep a spare admin. Null otherwise.
 */
export function noSpareAdminWarning(roster: Pick<TeamRoster, 'adminThreshold' | 'members'>, wideningAdmins?: number): string | null {
  const signing = signingAdmins(roster as TeamRoster);
  const needed = adminsNeeded(roster, wideningAdmins);
  if (signing > needed) return null;
  const admins = signing === 1 ? 'only 1 admin has' : `only ${signing} admins have`;
  return `Warning: no spare admin. Every later roster or policy change needs ${needed} admin signature${needed === 1 ? '' : 's'} and ${admins} a device key, so if one admin device is lost, no roster or policy change can be signed again; keysentry has no bypass. Keep a spare: add another admin with a device key (keysentry team add <id> --role admin --card <file>).`;
}

/** Add this admin's signature. Signing never changes the document; a second signature by the same key is refused. */
export function signRoster(input: SignedTeamRoster | TeamRoster, memberId: string, key: DeviceKey): SignedTeamRoster {
  const signed: SignedTeamRoster = 'roster' in input ? clone(input) : { roster: clone(input), signatures: [] };
  checked(signed.roster);
  if (signed.signatures.some(signature => signature.memberId === memberId && signature.keyId === key.keyId)) {
    throw new TeamError('This device has already signed this roster.');
  }
  signed.signatures.push(signTeamDocument(signed.roster, memberId, key));
  return signed;
}

export type RosterVerification = { ok: true; roster: SignedTeamRoster; hash: string; signers: string[] } | { ok: false; reason: string };

/** The policy in force where a roster change is checked: its `approvals.wideningAdmins`, when a policy is applied. */
export interface RosterRules { wideningAdmins?: number }

/**
 * Version 1 must carry `adminThreshold` signatures by its own admins. Every later version must extend `previous`
 * (same team, version + 1, `prev` = hash of `previous`) and carry signatures from `adminsNeeded(previous, wideningAdmins)`
 * admins of `previous`: a removed admin cannot sign the next version, a new admin cannot vote for their own addition,
 * and the policy's widening rule binds roster changes too (adding or promoting members widens who can approve).
 * Under a policy, the new version must keep enough admins with device keys to sign the next change.
 */
export function verifyRoster(input: unknown, previous: SignedTeamRoster | null, rules: RosterRules = {}): RosterVerification {
  const parsed = parseSignedRoster(input);
  if (!parsed.ok) return parsed;
  const signed = parsed.value;
  const { roster } = signed;
  if (previous === null) {
    if (roster.version !== 1) return { ok: false, reason: 'Only version 1 of a roster can start a team.' };
    const check = verifyTeamSignatures(roster, signed.signatures, roster, roster.adminThreshold);
    return check.ok ? { ok: true, roster: signed, hash: rosterHash(signed), signers: check.signers } : { ok: false, reason: check.reason };
  }
  const problem = linkProblem(roster, previous) ?? deadlockProblem(roster, rules);
  if (problem) return { ok: false, reason: problem };
  const check = verifyTeamSignatures(roster, signed.signatures, previous.roster, adminsNeeded(previous.roster, rules.wideningAdmins));
  return check.ok ? { ok: true, roster: signed, hash: rosterHash(signed), signers: check.signers } : { ok: false, reason: check.reason };
}

function deadlockProblem(roster: TeamRoster, rules: RosterRules): string | null {
  const widening = rules.wideningAdmins ?? 0;
  if (widening > 1 && signingAdmins(roster) < widening) {
    return `After this change fewer admins with a device key would remain than the team policy's approvals.wideningAdmins (${widening}), so no later roster or policy change could be signed. Lower approvals.wideningAdmins in the policy first.`;
  }
  return null;
}

/**
 * A proposal that is still collecting signatures: it must already link to `previous`, and every signature it carries
 * must be valid and from an admin of `previous`. Only the number of signatures is not required yet.
 */
export function checkProposal(input: unknown, previous: SignedTeamRoster, rules: RosterRules = {}):
  { ok: true; roster: SignedTeamRoster; signers: string[]; required: number } | { ok: false; reason: string } {
  const parsed = parseSignedRoster(input);
  if (!parsed.ok) return parsed;
  const problem = linkProblem(parsed.value.roster, previous) ?? deadlockProblem(parsed.value.roster, rules);
  if (problem) return { ok: false, reason: problem };
  const check = verifyTeamSignatures(parsed.value.roster, parsed.value.signatures, previous.roster, 0);
  if (!check.ok) return { ok: false, reason: check.reason };
  return { ok: true, roster: parsed.value, signers: check.signers, required: adminsNeeded(previous.roster, rules.wideningAdmins) };
}

function linkProblem(roster: TeamRoster, previous: SignedTeamRoster): string | null {
  if (roster.teamId !== previous.roster.teamId) return 'This roster belongs to a different team.';
  if (roster.version !== previous.roster.version + 1) {
    return roster.version <= previous.roster.version
      ? 'This roster is not newer than the one in use, so it was refused (rollback protection).'
      : 'This roster skips a version. Apply the versions in order.';
  }
  if (roster.prev !== rosterHash(previous)) return 'This roster does not extend the one in use (fork protection).';
  return null;
}

/**
 * First roster on a computer that has none (trust on first use): the human checks the fingerprint with an admin out
 * of band, and that check is what establishes trust. Version 1 is fully verified. A later version cannot show its
 * link without the previous roster (its signers may have been admins of that one), so every signature by an admin
 * still listed must verify and at least one must be present; signatures by others cannot be checked and are not counted.
 */
export function verifyFirstUse(input: unknown, expectedFingerprint: string): RosterVerification {
  const parsed = parseSignedRoster(input);
  if (!parsed.ok) return parsed;
  const signed = parsed.value;
  const hash = rosterHash(signed);
  if (!fingerprintMatches(hash, expectedFingerprint)) return { ok: false, reason: 'The roster fingerprint does not match the one you were given. Check it with an admin.' };
  if (signed.roster.version === 1) return verifyRoster(signed, null);
  const admins = new Set(signed.roster.members.filter(candidate => candidate.role === 'admin').map(candidate => candidate.id));
  const own = signed.signatures.filter(signature => admins.has(signature.memberId));
  const check = verifyTeamSignatures(signed.roster, own, signed.roster, 1);
  if (!check.ok) return { ok: false, reason: check.signers?.length === 0 ? 'This roster carries no signature from an admin listed in it, so it cannot be checked here.' : check.reason };
  return { ok: true, roster: signed, hash, signers: check.signers };
}

// ------------------------------------------------------------------------------------------------ lookups
/** The member who registered this passkey; the stored public key must match, not just the credential id. */
export function memberForPasskey(roster: TeamRoster, credential: Pick<PasskeyCredential, 'id' | 'publicKeyCose'>): TeamMember | undefined {
  return roster.members.find(candidate => candidate.passkeys.some(passkey => passkey.id === credential.id && passkey.publicKeyCose === credential.publicKeyCose));
}

export function memberForDeviceKey(roster: TeamRoster, keyId: string): { member: TeamMember; publicKeyDer: Buffer } | undefined {
  for (const candidate of roster.members) {
    const key = candidate.deviceKeys.find(entry => entry.keyId === keyId);
    if (key) return { member: candidate, publicKeyDer: Buffer.from(key.publicKeyDer, 'base64') };
  }
  return undefined;
}

/** Members' passkeys (copies), optionally only for members with at least `minRole`. */
export function teamPasskeys(roster: TeamRoster, minRole: TeamRole = 'viewer'): PasskeyCredential[] {
  return roster.members.filter(candidate => hasRole(candidate, minRole))
    .flatMap(candidate => candidate.passkeys.map(passkey => ({ ...passkey, origins: [...passkey.origins] })));
}

/** Members' device keys, optionally only for members with at least `minRole` (operators and admins may disarm). */
export function teamDeviceKeys(roster: TeamRoster, minRole: TeamRole = 'viewer'): { keyId: string; publicKeyDer: Buffer; memberId: string }[] {
  return roster.members.filter(candidate => hasRole(candidate, minRole))
    .flatMap(candidate => candidate.deviceKeys.map(key => ({ keyId: key.keyId, publicKeyDer: Buffer.from(key.publicKeyDer, 'base64'), memberId: candidate.id })));
}

/**
 * Single sign-on maps a verified email to exactly one member. Members with a pinned `sso` identity are never matched
 * by email; their subject decides (`memberForSso`).
 */
export function memberForEmail(roster: TeamRoster, email: string): TeamMember | undefined {
  // ASCII case only: a non-ASCII address never matches (it is a different mailbox, whatever it lower-cases to).
  if (!asciiEmail(email)) return undefined;
  const wanted = foldEmail(email);
  return roster.members.find(candidate => candidate.email === wanted && candidate.sso === undefined);
}

/** The member whose pinned single sign-on identity is exactly (`issuer`, `subject`). */
export function memberForSso(roster: TeamRoster, issuer: string, subject: string): TeamMember | undefined {
  return roster.members.find(candidate => candidate.sso?.issuer === issuer && candidate.sso.subject === subject);
}

// ------------------------------------------------------------------------------------------------ storage
/** A monotonic copy of the applied head outside the state directory, so an older state file cannot be restored. */
export interface TeamAnchor {
  read(): Promise<{ version: number; hash: string } | null>;
  write(head: { version: number; hash: string }): Promise<void>;
}

export function vaultTeamAnchor(vault: Vault, projectId: string, document: 'roster' | 'policy'): TeamAnchor {
  const name = `project/${projectId}/team/${document}-head`;
  return {
    async read() {
      const bytes = await vault.get(name);
      if (!bytes) return null;
      try {
        const match = /^(\d{1,16}):([a-f0-9]{64})$/.exec(bytes.toString('utf8'));
        if (!match) throw new TeamError('The saved team checkpoint could not be read.');
        return { version: Number(match[1]), hash: match[2]! };
      } finally { bytes.fill(0); }
    },
    async write(head) { await vault.set(name, Buffer.from(`${head.version}:${head.hash}`, 'utf8')); },
  };
}

export interface LoadedTeam { roster: SignedTeamRoster; hash: string }
interface StoredRoster { v: 1; roster: SignedTeamRoster; hash: string }

const queues = new Map<string, Promise<unknown>>();
/** Serialize read/check/write sequences on one state file, across callers in this process. */
export function serialized<T>(path: string, operation: () => Promise<T>): Promise<T> {
  const key = resolve(path);
  const previous = queues.get(key) ?? Promise.resolve();
  const current = previous.catch(() => undefined).then(operation);
  queues.set(key, current);
  return current.finally(() => { if (queues.get(key) === current) queues.delete(key); });
}

export function rosterPath(store: StateStore): string { return join(store.paths.dir, 'team-roster.json'); }

async function readStored(store: StateStore, anchor?: TeamAnchor): Promise<LoadedTeam | null> {
  const raw = await store.readJson<StoredRoster>('plan', rosterPath(store));
  const head = anchor ? await anchor.read() : null;
  if (raw === null) {
    if (head) throw new TeamError(`The saved team roster is missing, but this computer applied version ${head.version}. Restore it with keysentry team apply <file> --fingerprint <fingerprint>.`);
    return null;
  }
  const parsed = raw && typeof raw === 'object' && raw.v === 1 ? parseSignedRoster(raw.roster) : { ok: false as const, reason: '' };
  if (!parsed.ok || rosterHash(parsed.value) !== raw.hash) throw new TeamError('The saved team roster could not be verified. Restore it with keysentry team apply.');
  if (head && (head.version > parsed.value.roster.version || (head.version === parsed.value.roster.version && head.hash !== raw.hash))) {
    throw new TeamError('The saved team roster is older than one this computer already applied, so it was refused (rollback protection).');
  }
  return { roster: parsed.value, hash: raw.hash };
}

/** The latest verified roster, or null when this project has no team. Throws TeamError when it cannot be trusted. */
export function loadTeam(store: StateStore, options: { anchor?: TeamAnchor } = {}): Promise<LoadedTeam | null> {
  return serialized(rosterPath(store), () => readStored(store, options.anchor));
}

export interface ApplyRosterOptions {
  anchor?: TeamAnchor;
  /** Required to accept a first roster other than one this computer created (`team init`). */
  trust?: { fingerprint: string };
  /** The applied policy's `approvals.wideningAdmins`: a roster change needs that many admins when it is above the threshold. */
  wideningAdmins?: number;
}

/** Replace the saved roster only with a verified extension of it; the same roster again is a no-op. */
export function applyRoster(store: StateStore, input: unknown, options: ApplyRosterOptions = {}):
  Promise<{ status: 'applied' | 'unchanged'; roster: SignedTeamRoster; hash: string; previous: SignedTeamRoster | null; signers: string[] }> {
  return serialized(rosterPath(store), async () => {
    let current: LoadedTeam | null = null;
    let head: { version: number; hash: string } | null = null;
    try { current = await readStored(store, options.anchor); }
    catch (error) {
      // A missing state file with a checkpoint can be restored by a fingerprint-checked roster at least that new.
      if (!(error instanceof TeamError) || !options.trust || !options.anchor) throw error;
      if (await store.readJson('plan', rosterPath(store)) !== null) throw error;
      head = await options.anchor.read();
    }
    let result: RosterVerification;
    if (current) {
      const parsed = parseSignedRoster(input);
      if (parsed.ok && rosterHash(parsed.value) === current.hash) return { status: 'unchanged', roster: current.roster, hash: current.hash, previous: null, signers: [] };
      result = verifyRoster(input, current.roster, { wideningAdmins: options.wideningAdmins });
    } else result = options.trust ? verifyFirstUse(input, options.trust.fingerprint) : verifyRoster(input, null);
    if (!result.ok) throw new TeamError(result.reason);
    if (head && (result.roster.roster.version < head.version || (result.roster.roster.version === head.version && result.hash !== head.hash))) {
      throw new TeamError('This roster is older than one this computer already applied, so it was refused (rollback protection).');
    }
    const stored: StoredRoster = { v: 1, roster: result.roster, hash: result.hash };
    await store.writeJson('plan', rosterPath(store), stored);
    await options.anchor?.write({ version: result.roster.roster.version, hash: result.hash });
    return { status: 'applied', roster: result.roster, hash: result.hash, previous: current?.roster ?? null, signers: result.signers };
  });
}

/** Plain-English differences between two roster versions, for review before signing or applying. */
export function describeRosterChange(previous: TeamRoster | null, next: TeamRoster): string[] {
  if (!previous) return [`New team with ${next.members.length} member${next.members.length === 1 ? '' : 's'}; ${next.adminThreshold} admin signature${next.adminThreshold === 1 ? '' : 's'} needed for changes.`];
  const lines: string[] = [];
  for (const entry of next.members) {
    const before = previous.members.find(candidate => candidate.id === entry.id);
    if (!before) { lines.push(`Add ${entry.id} (${entry.name}) as ${entry.role}.`); continue; }
    if (before.role !== entry.role) lines.push(`Change ${entry.id} from ${before.role} to ${entry.role}.`);
    if (JSON.stringify(before.deviceKeys) !== JSON.stringify(entry.deviceKeys) || JSON.stringify(before.passkeys) !== JSON.stringify(entry.passkeys)) {
      lines.push(`Change the device keys or passkeys of ${entry.id}.`);
    }
    if (before.email !== entry.email || before.name !== entry.name) lines.push(`Change the name or email of ${entry.id}.`);
    if (JSON.stringify(before.sso ?? null) !== JSON.stringify(entry.sso ?? null)) {
      lines.push(entry.sso ? `Pin the single sign-on identity of ${entry.id} to issuer ${entry.sso.issuer}, subject ${entry.sso.subject}.`
        : `Remove the pinned single sign-on identity of ${entry.id}.`);
    }
    if (JSON.stringify(before.notify ?? null) !== JSON.stringify(entry.notify ?? null)) lines.push(`Change notification routing for ${entry.id}.`);
  }
  for (const entry of previous.members) if (!next.members.some(candidate => candidate.id === entry.id)) lines.push(`Remove ${entry.id} (${entry.role}).`);
  if (previous.adminThreshold !== next.adminThreshold) lines.push(`Admin signatures needed for changes: ${previous.adminThreshold} → ${next.adminThreshold}.`);
  const newlyRetired = (next.retiredChannels ?? []).filter(channel => !(previous.retiredChannels ?? []).includes(channel));
  if (newlyRetired.length) lines.push(`Stop sending team messages to ${newlyRetired.join(', ')} (no member receives ${newlyRetired.length === 1 ? 'it' : 'them'} any more).`);
  return lines.length ? lines : ['No membership changes.'];
}
