import type { Cluster, Inventory, ProviderId } from '../../src/types.js';

export const FIRST = 'a'.repeat(32);
export const SECOND = 'b'.repeat(32);
export const NOW = '2026-10-27T12:00:00.000Z';

export function cluster(id = FIRST, provider: ProviderId = 'openrouter'): Cluster {
  const service = { host: 'railway' as const, projectId: 'project', projectName: 'Project',
    serviceId: 'api', serviceName: 'API', environmentId: 'prod', environmentName: 'Production' };
  return { id, fingerprint: id, provider, tier: 'ai', method: 'auto', hint: 'sk-or-v…1234',
    consumers: [{ service, varName: 'API_KEY', fingerprint: id, hint: 'sk-or-v…1234', sealed: false }] };
}

export function inventory(clusters = [cluster()]): Inventory {
  return { version: 1, scannedAt: NOW, hosts: ['railway'], services: [], findings: [], clusters, errors: [] };
}
