// Shared wiring for team governance in the CLI, dashboard and watcher: vault checkpoints for the roster and policy,
// the approval quorum read from the verified roster and policy, and value-free wording for quorum progress.
import type { ApprovalQuorum } from '../approvals/index.js';
import { ApprovalPendingError } from '../approvals/index.js';
import type { StateStore } from '../core/store.js';
import { loadPolicy, tiersForClusters, type Governance, type TeamBundle } from '../policy/index.js';
import { loadTeam, vaultTeamAnchor, type TeamAnchor } from '../team/index.js';
import type { TeamPolicy, TeamRoster, Vault } from '../types.js';

export interface TeamAnchors { roster?: TeamAnchor; policy?: TeamAnchor }

/** Vault checkpoints of the applied roster and policy. An environment vault is read-only (CI), so it has none. */
export function teamAnchors(vault: Vault, projectId: string): TeamAnchors {
  if (vault.backend === 'env') return {};
  return { roster: vaultTeamAnchor(vault, projectId, 'roster'), policy: vaultTeamAnchor(vault, projectId, 'policy') };
}

async function tiersFromInventory(store: StateStore, clusterIds: readonly string[]) {
  const inventory = await store.loadInventory();
  return tiersForClusters(clusterIds, inventory?.clusters ?? []);
}

/**
 * The quorum for approval services on this computer: the roster and policy are re-read and re-verified for every
 * request and approval. Without a roster it returns null (single approval, unchanged). A roster or policy that cannot
 * be verified throws, which pauses approvals rather than falling back to a single approval.
 */
export function stateQuorum(input: { store: StateStore; cwd: string; policyFile: () => string | undefined; anchors: TeamAnchors }): ApprovalQuorum {
  return {
    async team() {
      const team = await loadTeam(input.store, { anchor: input.anchors.roster });
      if (!team) return null;
      const status = await loadPolicy({ store: input.store, cwd: input.cwd, policyFile: input.policyFile(), team, anchor: input.anchors.policy });
      if (status.status === 'refused') throw new Error('The team policy could not be verified.');
      return { roster: team.roster.roster, policy: status.status === 'ok' ? status.policy.policy : null };
    },
    tiers: action => tiersFromInventory(input.store, action.clusterIds),
  };
}

/** The quorum for a watcher: the roster and policy sealed into its config (authenticated by the deploy key). */
export function bundleQuorum(bundle: TeamBundle | null | undefined, store: StateStore): ApprovalQuorum {
  return {
    async team() { return bundle ? { roster: bundle.roster.roster, policy: bundle.policy?.policy ?? null } : null; },
    tiers: action => tiersFromInventory(store, action.clusterIds),
  };
}

/** The roster and policy of loaded governance as a bundle (null without a team). */
export function governanceBundle(governance: Pick<Governance, 'team' | 'policy'>): TeamBundle | null {
  if (!governance.team) return null;
  return { roster: governance.team.roster, policy: governance.policy.status === 'ok' ? governance.policy.policy : null };
}

/** The verified roster and policy rules of a bundle, for code that needs them directly. */
export function bundleRules(bundle: TeamBundle | null | undefined): { roster: TeamRoster | null; policy: TeamPolicy | null } {
  return { roster: bundle?.roster.roster ?? null, policy: bundle?.policy?.policy ?? null };
}

/** Plain text for a recorded team approval that still needs other members. Never treated as a failure. */
export function pendingText(error: ApprovalPendingError): string {
  const needed = error.needed;
  return `${error.message} ${needed.charAt(0).toUpperCase()}${needed.slice(1)}.`;
}
