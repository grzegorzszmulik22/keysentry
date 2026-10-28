// One place that decides whether team governance lets changes run: roster present and trusted, team mode
// consistent with keysentry.yaml, policy file present and valid, and the policy's own requirements met.
import { z } from 'zod';
import type { ConfigSettings } from '../cli/config.js';
import type { StateStore } from '../core/store.js';
import type { SignedTeamPolicy, SignedTeamRoster, TeamPolicy } from '../types.js';
import { loadTeam, rosterHash, TeamError, type LoadedTeam, type TeamAnchor } from '../team/roster.js';
import { parseSignedRoster } from '../team/schema.js';
import { effectiveSettings, policyBlockers } from './effective.js';
import { loadPolicy, policyHash, PolicyError, verifyPolicy, type PolicyStatus } from './policy.js';

export interface Governance {
  team: LoadedTeam | null;
  policy: PolicyStatus;
  /** Settings narrowed by the policy (a copy; equal to the input without a policy). */
  settings: ConfigSettings;
  /** Fixed messages. Any entry means commands that change keys, the roster, the policy or approvals must not run. */
  blockers: string[];
}

export interface GovernanceOptions {
  store: StateStore;
  settings: ConfigSettings;
  cwd: string;
  env?: NodeJS.ProcessEnv;
  anchors?: { roster?: TeamAnchor; policy?: TeamAnchor };
}

export async function loadGovernance(options: GovernanceOptions): Promise<Governance> {
  const blockers: string[] = [];
  let team: LoadedTeam | null = null;
  let rosterFailed = false;
  try { team = await loadTeam(options.store, { anchor: options.anchors?.roster }); }
  catch (error) {
    rosterFailed = true;
    blockers.push(error instanceof TeamError ? error.message : 'The team roster could not be read.');
  }
  const enabled = options.settings.team.enabled;
  if (!rosterFailed && enabled && !team) blockers.push('Team mode is on in keysentry.yaml, but this project has no team roster. Run keysentry team init, or keysentry team apply with the team\'s roster.');
  if (!rosterFailed && !enabled && team) blockers.push('This project has a team roster, but team.enabled is false in keysentry.yaml. Set team.enabled: true.');
  const policy = rosterFailed && options.settings.team.policyFile
    ? { status: 'refused' as const, reason: 'The team policy cannot be checked without a trusted roster.' }
    : await loadPolicy({ store: options.store, cwd: options.cwd, policyFile: options.settings.team.policyFile, team, anchor: options.anchors?.policy });
  if (policy.status === 'refused') blockers.push(policy.reason);
  const rules = policy.status === 'ok' ? policy.policy.policy : null;
  const settings = effectiveSettings(options.settings, rules);
  blockers.push(...policyBlockers(settings, rules, options.env));
  return { team, policy, settings, blockers };
}

/** The verified policy rules in force, or null. */
export function policyRules(governance: Pick<Governance, 'policy'>): TeamPolicy | null {
  return governance.policy.status === 'ok' ? governance.policy.policy.policy : null;
}

/** Throw a calm, specific refusal when governance does not let changes run. */
export function assertChangesAllowed(governance: Pick<Governance, 'blockers'>): void {
  if (governance.blockers.length) throw new PolicyError(`Changes are paused. ${governance.blockers.join(' ')}`);
}

// ------------------------------------------------------------------------------------------------ watcher bundle
/** The team part of the sealed watcher config. The seal (deploy key) authenticates it; the policy is checked here too. */
export interface TeamBundle { roster: SignedTeamRoster; policy: SignedTeamPolicy | null }

const bundleShape = z.object({ roster: z.unknown(), policy: z.unknown().nullable() }).strict();

export function parseTeamBundle(input: unknown): TeamBundle & { rosterHash: string } {
  const shape = bundleShape.safeParse(input);
  if (!shape.success) throw new TeamError('The team settings in the watcher config are not valid.');
  const roster = parseSignedRoster(shape.data.roster);
  if (!roster.ok) throw new TeamError('The team roster in the watcher config is not valid.');
  let policy: SignedTeamPolicy | null = null;
  if (shape.data.policy !== null) {
    const verified = verifyPolicy(shape.data.policy, roster.value.roster, null);
    if (!verified.ok) throw new PolicyError('The team policy in the watcher config is not signed by enough current admins.');
    policy = verified.policy;
  }
  return { roster: roster.value, policy, rosterHash: rosterHash(roster.value) };
}

/**
 * Governance for a sealed watcher: the roster and policy come from its authenticated config (the deploy key seals
 * them), not from local state, which a fresh watcher does not have.
 */
export function governanceFromBundle(bundle: TeamBundle | null | undefined, settings: ConfigSettings, env?: NodeJS.ProcessEnv): Governance {
  if (!bundle) {
    const blockers = settings.team.enabled ? ['Team mode is on, but the sealed watcher config carries no team roster. Run keysentry watcher setup again.'] : [];
    return { team: null, policy: { status: 'none' }, settings: effectiveSettings(settings, null), blockers };
  }
  const rules = bundle.policy?.policy ?? null;
  const effective = effectiveSettings(settings, rules);
  return {
    team: { roster: structuredClone(bundle.roster), hash: rosterHash(bundle.roster) },
    policy: bundle.policy ? { status: 'ok', policy: structuredClone(bundle.policy), hash: policyHash(bundle.policy), path: 'sealed watcher config', advanced: false } : { status: 'none' },
    settings: effective,
    blockers: policyBlockers(effective, rules, env),
  };
}

/** What `watcher setup` seals for the watcher, or null without a team. Refuses when governance blocks changes. */
export async function buildTeamBundle(options: GovernanceOptions): Promise<TeamBundle | null> {
  const governance = await loadGovernance(options);
  assertChangesAllowed(governance);
  if (!governance.team) return null;
  return { roster: structuredClone(governance.team.roster), policy: governance.policy.status === 'ok' ? structuredClone(governance.policy.policy) : null };
}
