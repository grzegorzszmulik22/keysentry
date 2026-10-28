import type { HostId, Inventory, ServiceRef } from '../types.js';
import { automaticCredentialsConfigured } from '../providers/index.js';
import { builtInActivation, canConfirmActivation } from '../hosts/activation.js';

/** Runtime facts needed for the drill score. Pass credential names, never their values. */
export interface ReadinessInput {
  inventory: Pick<Inventory, 'clusters' | 'services'>;
  /** Names of credentials whose configured value is truthy. */
  configuredCredentials: readonly string[];
  /** Host redeploy support; a missing host is treated as unsupported. */
  redeploy: Readonly<Partial<Record<HostId, boolean>>>;
  canaries: number;
  /**
   * Whether a service needs a manual restart or next deploy, decided by the connected adapters (the runtime passes
   * its shared activation check). Without it, the built-in host rules and `redeploy` decide.
   */
  manualActivation?: (service: ServiceRef) => boolean;
}

function builtInManual(service: ServiceRef, redeploy: ReadinessInput['redeploy']): boolean {
  const supported = redeploy[service.host];
  if (supported === undefined) return true;
  const mode = builtInActivation(service);
  return mode === 'redeploy' && !supported || !canConfirmActivation(mode);
}

/** The CLI's six-factor readiness score, without scanning, storage or a dry run. */
export function readinessScore(input: ReadinessInput): { score: number; reasons: string[] } {
  const { inventory: inv, redeploy, canaries } = input;
  const credentials = new Set(input.configuredCredentials);
  const total = inv.clusters.length;
  // Credential lists may be alternatives (Google) or partly conditional (Twilio): the provider decides what suffices.
  const configured = (cluster: Inventory['clusters'][number]) => automaticCredentialsConfigured(cluster.provider, credentials);
  const automatic = inv.clusters.filter(cluster => cluster.method === 'generate' ||
    cluster.method !== 'guided' && cluster.fingerprint !== null && configured(cluster)).length;
  const sealed = inv.clusters.filter(cluster => cluster.fingerprint === null).length;
  const duplicate = inv.clusters.filter(cluster => cluster.consumers.length > 1).length;
  const missing = inv.clusters.filter(cluster => !configured(cluster)).length;
  const manual = input.manualActivation ?? ((service: ServiceRef) => builtInManual(service, redeploy));
  const manualDeploys = inv.services.filter(service => manual(service)).length;
  const ratio = (count: number, denominator = total) => denominator ? count / denominator : 0;
  const score = total ? Math.round(40 * ratio(automatic) + 15 * (1 - ratio(sealed)) + 15 * (1 - ratio(duplicate)) +
    15 * (1 - ratio(missing)) + 10 * (1 - ratio(manualDeploys, inv.services.length)) + (canaries ? 5 : 0)) : 0;
  return { score: Math.max(0, Math.min(100, score)), reasons: [
    `${automatic}/${total} clusters are currently auto-rotatable: automatic, atomic-roll, or generated (40 points).`,
    `${sealed}/${total} clusters are sealed (15 points).`,
    `${duplicate}/${total} clusters have duplicate consumers (15 points).`,
    `${missing}/${total} clusters lack configured admin credentials (15 points).`,
    `${manualDeploys}/${inv.services.length} services require manual activation or have no redeploy support (10 points).`,
    `${canaries} canaries configured (5 points).`,
  ] };
}
