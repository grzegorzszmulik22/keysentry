// Signed policy-as-code: draft, sign, verify against the roster's admins, keep the applied head in encrypted state
// (rollback and fork protection), and read the file named by team.policyFile.
import { lstat, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { CliError } from '../cli/errors.js';
import type { StateStore } from '../core/store.js';
import type { DeviceKey } from '../security/index.js';
import type { SignedTeamPolicy, TeamPolicy, TeamRoster } from '../types.js';
import { MAX_TEAM_FILE_BYTES } from '../team/schema.js';
import { serialized, type LoadedTeam, type TeamAnchor } from '../team/roster.js';
import { documentHash, fingerprint, signTeamDocument, verifyTeamSignatures } from '../team/signature.js';
import { draftSchema, parseSignedPolicy, policySchema } from './schema.js';

export class PolicyError extends CliError {
  readonly code = 'POLICY_REFUSED';
  constructor(message: string) { super(message); this.name = 'PolicyError'; }
}

export function policyHash(signed: SignedTeamPolicy): string { return documentHash(signed); }
export function policyFingerprint(signed: SignedTeamPolicy): string { return fingerprint(policyHash(signed)); }

export interface PolicyHead { policy: SignedTeamPolicy; hash: string }

/**
 * Turn what an admin wrote into a document ready to sign. A file that already carries signatures is returned as it
 * is (its body can no longer change). An unsigned draft gets the team id, the next version, the previous hash and
 * the time filled in; values it already states must agree with them.
 */
export function preparePolicyDraft(input: unknown, context: { roster: TeamRoster; head: PolicyHead | null; now: Date }): SignedTeamPolicy {
  const wrapper = input && typeof input === 'object' && !Array.isArray(input) && 'policy' in input ? input as { policy?: unknown; signatures?: unknown } : null;
  if (wrapper && Array.isArray(wrapper.signatures) && wrapper.signatures.length) {
    const parsed = parseSignedPolicy(input);
    if (!parsed.ok) throw new PolicyError(parsed.reason);
    return parsed.value;
  }
  if (wrapper && Object.keys(wrapper).some(key => key !== 'policy' && key !== 'signatures')) throw new PolicyError('The policy draft has unknown fields.');
  const draft = draftSchema.safeParse(wrapper ? wrapper.policy : input);
  if (!draft.success) {
    const fields = [...new Set(draft.error.issues.map(issue => issue.path.filter(part => typeof part === 'string').slice(0, 3).join('.') || 'policy'))].slice(0, 5);
    throw new PolicyError(`The policy draft is not valid: check ${fields.join(', ')} (wrong type, unknown field, or invalid value).`);
  }
  const body = draft.data;
  const version = context.head ? context.head.policy.policy.version + 1 : 1;
  const prev = context.head ? context.head.hash : null;
  if (body.teamId !== undefined && body.teamId !== context.roster.teamId) throw new PolicyError('This policy draft belongs to a different team.');
  if (body.version !== undefined && body.version !== version) throw new PolicyError(`This policy draft says version ${body.version}, but the next version is ${version}.`);
  if (body.prev !== undefined && body.prev !== prev) throw new PolicyError('This policy draft does not extend the policy in use.');
  const policy: TeamPolicy = {
    v: 1, teamId: context.roster.teamId, version, prev, updatedAt: body.updatedAt ?? context.now.toISOString(),
    autopilot: body.autopilot ?? {},
    approvals: { required: body.approvals?.required ?? 1, wideningAdmins: body.approvals?.wideningAdmins ?? 1,
      ...(body.approvals?.requiredByTier ? { requiredByTier: body.approvals.requiredByTier } : {}) },
    network: body.network ?? {}, notify: body.notify ?? {}, rotation: body.rotation ?? {}, audit: body.audit ?? {},
  };
  const parsed = policySchema.safeParse(policy);
  if (!parsed.success) throw new PolicyError('The policy draft is not valid.');
  return { policy: parsed.data as TeamPolicy, signatures: [] };
}

export function signPolicy(input: SignedTeamPolicy, memberId: string, key: DeviceKey): SignedTeamPolicy {
  const parsed = parseSignedPolicy(input);
  if (!parsed.ok) throw new PolicyError(parsed.reason);
  const signed = structuredClone(parsed.value);
  if (signed.signatures.some(signature => signature.memberId === memberId && signature.keyId === key.keyId)) throw new PolicyError('This device has already signed this policy.');
  signed.signatures.push(signTeamDocument(signed.policy, memberId, key));
  return signed;
}

export type PolicyVerification =
  | { ok: true; policy: SignedTeamPolicy; hash: string; signers: string[]; relation: 'same' | 'first' | 'newer' }
  | { ok: false; reason: string };

/**
 * A policy is valid when `roster.adminThreshold` distinct admins of the current roster signed it (a policy signed by
 * an admin who has since been removed must be signed again). Against the applied head it must be the same document,
 * or a newer version: the next version must link to the head by hash; a later version may skip versions only because
 * each version is independently signed by the current admins. Older versions and different documents with the same
 * version are refused.
 */
export function verifyPolicy(input: unknown, roster: TeamRoster, head: PolicyHead | null): PolicyVerification {
  return checkPolicy(input, roster, head, roster.adminThreshold);
}

/** A policy still collecting signatures: everything `verifyPolicy` checks except the number of signatures. */
export function checkPolicyProposal(input: unknown, roster: TeamRoster, head: PolicyHead | null): PolicyVerification {
  return checkPolicy(input, roster, head, 0);
}

function checkPolicy(input: unknown, roster: TeamRoster, head: PolicyHead | null, threshold: number): PolicyVerification {
  const parsed = parseSignedPolicy(input);
  if (!parsed.ok) return parsed;
  const signed = parsed.value;
  const { policy } = signed;
  if (policy.teamId !== roster.teamId) return { ok: false, reason: 'This policy belongs to a different team.' };
  const hash = policyHash(signed);
  // Signatures first: a document changed after signing is reported as such, not as a version conflict.
  const check = verifyTeamSignatures(policy, signed.signatures, roster, threshold);
  if (!check.ok) return { ok: false, reason: check.reason };
  let relation: 'same' | 'first' | 'newer' = 'first';
  if (head) {
    const applied = head.policy.policy.version;
    if (policy.version < applied) return { ok: false, reason: 'This policy is older than the one in use, so it was refused (rollback protection).' };
    if (policy.version === applied && hash !== head.hash) return { ok: false, reason: 'This policy has the same version as the one in use but different contents (fork protection).' };
    if (policy.version === applied + 1 && policy.prev !== head.hash) return { ok: false, reason: 'This policy does not extend the one in use (fork protection).' };
    relation = hash === head.hash ? 'same' : 'newer';
  }
  return { ok: true, policy: signed, hash, signers: check.signers, relation };
}

// ------------------------------------------------------------------------------------------------ storage
interface StoredPolicy { v: 1; policy: SignedTeamPolicy; hash: string }
export function policyStatePath(store: StateStore): string { return join(store.paths.dir, 'team-policy.json'); }

async function readHead(store: StateStore, anchor?: TeamAnchor): Promise<PolicyHead | null> {
  const raw = await store.readJson<StoredPolicy>('plan', policyStatePath(store));
  const checkpoint = anchor ? await anchor.read() : null;
  if (raw === null) {
    if (checkpoint) throw new PolicyError(`The applied team policy is missing from saved state, but this computer applied version ${checkpoint.version}. Apply the current policy again with keysentry policy apply.`);
    return null;
  }
  const parsed = raw && typeof raw === 'object' && raw.v === 1 ? parseSignedPolicy(raw.policy) : { ok: false as const, reason: '' };
  if (!parsed.ok || policyHash(parsed.value) !== raw.hash) throw new PolicyError('The applied team policy in saved state could not be verified. Apply it again with keysentry policy apply.');
  if (checkpoint && (checkpoint.version > parsed.value.policy.version || (checkpoint.version === parsed.value.policy.version && checkpoint.hash !== raw.hash))) {
    throw new PolicyError('The applied team policy in saved state is older than one this computer already applied, so it was refused (rollback protection).');
  }
  return { policy: parsed.value, hash: raw.hash };
}

export function loadPolicyHead(store: StateStore, options: { anchor?: TeamAnchor } = {}): Promise<PolicyHead | null> {
  return serialized(policyStatePath(store), () => readHead(store, options.anchor));
}

/** Verify against the roster and the applied head, then record it as the new head. The same policy again is a no-op. */
export function applyPolicy(store: StateStore, input: unknown, options: { roster: TeamRoster; anchor?: TeamAnchor }):
  Promise<{ status: 'applied' | 'unchanged'; policy: SignedTeamPolicy; hash: string; previous: PolicyHead | null; signers: string[] }> {
  return serialized(policyStatePath(store), async () => {
    const head = await readHead(store, options.anchor);
    const result = verifyPolicy(input, options.roster, head);
    if (!result.ok) throw new PolicyError(result.reason);
    if (result.relation === 'same') return { status: 'unchanged', policy: result.policy, hash: result.hash, previous: head, signers: result.signers };
    await store.writeJson('plan', policyStatePath(store), { v: 1, policy: result.policy, hash: result.hash } satisfies StoredPolicy);
    await options.anchor?.write({ version: result.policy.policy.version, hash: result.hash });
    return { status: 'applied', policy: result.policy, hash: result.hash, previous: head, signers: result.signers };
  });
}

/** Read a team document from disk: a regular file, at most 1 MiB, JSON. Errors never echo file contents. */
export async function readTeamFile(path: string, what: string): Promise<unknown> {
  let source: string;
  try {
    const info = await lstat(path);
    if (!info.isFile()) throw new PolicyError(`The ${what} must be a regular file.`);
    if (info.size > MAX_TEAM_FILE_BYTES) throw new PolicyError(`The ${what} is larger than 1 MiB.`);
    source = await readFile(path, 'utf8');
  } catch (error) {
    if (error instanceof PolicyError) throw error;
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw new PolicyError(`The ${what} was not found.`);
    throw new PolicyError(`The ${what} could not be read.`);
  }
  if (Buffer.byteLength(source) > MAX_TEAM_FILE_BYTES) throw new PolicyError(`The ${what} is larger than 1 MiB.`);
  try { return JSON.parse(source.replace(/^﻿/, '')); }
  catch { throw new PolicyError(`The ${what} is not valid JSON.`); }
}

export type PolicyStatus =
  | { status: 'none' }
  | { status: 'ok'; policy: SignedTeamPolicy; hash: string; path: string; advanced: boolean }
  | { status: 'refused'; reason: string };

export interface LoadPolicyOptions {
  store: StateStore;
  /** The project directory that keysentry.yaml paths are relative to. */
  cwd: string;
  /** settings.team.policyFile */
  policyFile: string | undefined;
  team: LoadedTeam | null;
  anchor?: TeamAnchor;
}

/**
 * The policy in force. `refused` means changes must not run, and `reason` says why (missing file, invalid file,
 * no roster, rollback). A verified newer version of the file becomes the applied head.
 */
export async function loadPolicy(options: LoadPolicyOptions): Promise<PolicyStatus> {
  try {
    return await serialized(policyStatePath(options.store), async () => {
      const head = await readHead(options.store, options.anchor);
      if (!options.policyFile) {
        return head ? { status: 'refused', reason: 'This project has an applied team policy, but team.policyFile is not set in keysentry.yaml. Set it to the policy file.' } : { status: 'none' };
      }
      if (!options.team) return { status: 'refused', reason: 'team.policyFile is set in keysentry.yaml, but this project has no team roster. Run keysentry team init or keysentry team apply first.' };
      const path = resolve(options.cwd, options.policyFile);
      let input: unknown;
      try { input = await readTeamFile(path, 'team policy file named in team.policyFile'); }
      catch (error) { return { status: 'refused', reason: error instanceof PolicyError ? error.message : 'The team policy file could not be read.' }; }
      const result = verifyPolicy(input, options.team.roster.roster, head);
      if (!result.ok) return { status: 'refused', reason: `The team policy file is not valid: ${result.reason}` };
      let advanced = false;
      if (result.relation !== 'same') {
        await options.store.writeJson('plan', policyStatePath(options.store), { v: 1, policy: result.policy, hash: result.hash } satisfies StoredPolicy);
        await options.anchor?.write({ version: result.policy.policy.version, hash: result.hash });
        advanced = true;
      }
      return { status: 'ok', policy: result.policy, hash: result.hash, path, advanced };
    });
  } catch (error) {
    return { status: 'refused', reason: error instanceof CliError ? error.message : 'The team policy could not be checked.' };
  }
}

/** For commands that change keys, the roster, the policy or approvals: refuse unless the policy check passed. */
export function requirePolicyForChanges(status: PolicyStatus): TeamPolicy | null {
  if (status.status === 'refused') throw new PolicyError(`Changes are paused: ${status.reason}`);
  return status.status === 'ok' ? status.policy.policy : null;
}
