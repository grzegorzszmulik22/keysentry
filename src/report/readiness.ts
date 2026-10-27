import type { HostId, Inventory } from '../types.js';
import { PROVIDER_CREDENTIALS } from '../providers/index.js';

/** Runtime facts needed for the drill score. Pass credential names, never their values. */
export interface ReadinessInput {
  inventory: Pick<Inventory, 'clusters' | 'services'>;
  /** Names of credentials whose configured value is truthy. */
  configuredCredentials: readonly string[];
  /** Host redeploy support; a missing host is treated as unsupported. */
  redeploy: Readonly<Partial<Record<HostId, boolean>>>;
  canaries: number;
}

/** The CLI's six-factor readiness score, without scanning, storage or a dry run. */
export function readinessScore(input: ReadinessInput): { score: number; reasons: string[] } {
  const { inventory: inv, redeploy, canaries } = input;
  const credentials = new Set(input.configuredCredentials);
  const total = inv.clusters.length;
  const automatic = inv.clusters.filter(cluster => cluster.method === 'generate' ||
    cluster.method !== 'guided' && cluster.fingerprint !== null && PROVIDER_CREDENTIALS[cluster.provider].every(name => credentials.has(name))).length;
  const sealed = inv.clusters.filter(cluster => cluster.fingerprint === null).length;
  const duplicate = inv.clusters.filter(cluster => cluster.consumers.length > 1).length;
  const missing = inv.clusters.filter(cluster => PROVIDER_CREDENTIALS[cluster.provider].some(name => !credentials.has(name))).length;
  const manualDeploys = inv.services.filter(service => !redeploy[service.host] || service.host === 'fly' ||
    service.host === 'vercel' && service.environmentId !== 'production' || service.host === 'railway' && service.serviceId === '').length;
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
