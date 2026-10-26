import type {
  Classification,
  Cluster,
  Consumer,
  HostAdapter,
  HostId,
  Inventory,
  Logger,
  RawVariable,
  SecretFinding,
  ServiceRef,
} from '../types.js';
import { classify, methodFor } from './classify.js';
import { fingerprint, makeHint } from './fingerprint.js';
import { serviceKey } from './service-key.js';

export interface HostScan {
  host: HostId;
  services: { service: ServiceRef; vars: RawVariable[] }[];
  error?: string;
}

const scanErrorMessage = 'Unable to completely scan host; some variables may be missing.';
const confidenceRank: Record<Classification['confidence'], number> = { low: 0, medium: 1, high: 2 };

function classificationSafetyRank(provider: Classification['provider']): number {
  if (provider === 'encryption-key') return 2;
  if (provider === 'app-secret') return 0;
  return 1;
}

interface ClusterEntry {
  cluster: Cluster;
  confidence: Classification['confidence'];
}

interface RailwayReference {
  serviceName: string;
  varName: string;
}

interface InventoryVariable {
  service: ServiceRef;
  variable: RawVariable;
  references?: RailwayReference[];
  clusterId?: string;
}

function parseRailwayReferences(value: string | undefined): RailwayReference[] {
  const references: RailwayReference[] = [];
  if (value === undefined) return references;
  for (const match of value.matchAll(/\$\{\{\s*([^{}]+?)\s*\.\s*([^.\s{}]+)\s*\}\}/g)) {
    const serviceName = match[1]?.trim();
    const varName = match[2];
    if (serviceName && varName) references.push({ serviceName, varName });
  }
  return references;
}

function referenceServiceKey(service: ServiceRef, serviceName: string): string {
  return JSON.stringify([service.host, service.projectId, service.environmentId, serviceName]);
}

function variableKey(serviceId: string, varName: string): string {
  return JSON.stringify([serviceId, varName]);
}

export function buildInventory(scans: HostScan[], key: Buffer, now = new Date()): Inventory {
  const hosts = new Set<HostId>();
  const services = new Map<string, ServiceRef>();
  const findings: SecretFinding[] = [];
  const clusters = new Map<string, ClusterEntry>();
  const errors: Inventory['errors'] = [];
  const railwayServices = new Map<string, Set<string>>();
  const railwayVariables = new Map<string, InventoryVariable | null>();
  const references: InventoryVariable[] = [];

  for (const scan of scans) {
    hosts.add(scan.host);
    // Adapter errors can embed request headers or response bodies. Their text is never retained.
    if (scan.error !== undefined) errors.push({ host: scan.host, message: scanErrorMessage });

    for (const { service, vars } of scan.services) {
      const serviceId = serviceKey(service);
      if (!services.has(serviceId)) services.set(serviceId, service);
      if (service.host === 'railway') {
        const nameKey = referenceServiceKey(service, service.serviceName);
        const matchingServices = railwayServices.get(nameKey) ?? new Set<string>();
        matchingServices.add(serviceId);
        railwayServices.set(nameKey, matchingServices);
      }

      for (const variable of vars) {
        // A sealed flag takes precedence over any value accidentally supplied by an adapter.
        const value = variable.sealed ? undefined : variable.value;
        const entry: InventoryVariable = { service, variable };
        if (service.host === 'railway') {
          const parsedReferences = parseRailwayReferences(value);
          if (parsedReferences.length > 0) {
            entry.references = parsedReferences;
            references.push(entry);
          }
          const entryKey = variableKey(serviceId, variable.name);
          const previous = railwayVariables.get(entryKey);
          if (previous === undefined) railwayVariables.set(entryKey, entry);
          else if (previous === null || previous.variable.sealed !== variable.sealed
            || (!variable.sealed && previous.variable.value !== variable.value)) {
            // Conflicting observations of one variable cannot safely identify a reference target.
            railwayVariables.set(entryKey, null);
          }
        }
        let classification = classify(variable.name, value);
        if (!classification.isSecret) {
          if (!variable.sealed) continue;
          classification = { provider: 'unknown', tier: 'unknown', isSecret: true, confidence: 'low' };
        }

        const consumer: Consumer = {
          service,
          varName: variable.name,
          fingerprint: value === undefined ? null : fingerprint(value, key),
          hint: value === undefined ? null : makeHint(value),
          sealed: value === undefined,
        };
        findings.push({
          ...consumer,
          provider: classification.provider,
          tier: classification.tier,
          isSecret: classification.isSecret,
          confidence: classification.confidence,
        });

        const id = consumer.fingerprint ?? `sealed:${serviceId}:${variable.name}`;
        entry.clusterId = id;
        const existing = clusters.get(id);
        if (!existing) {
          clusters.set(id, {
            cluster: {
              id,
              fingerprint: consumer.fingerprint,
              provider: classification.provider,
              tier: classification.tier,
              method: methodFor(classification.provider),
              hint: consumer.hint,
              consumers: [consumer],
            },
            confidence: classification.confidence,
          });
          continue;
        }

        existing.cluster.consumers.push(consumer);
        // Encryption use always needs guidance. Generation requires every direct secret finding to agree;
        // once a non-app classification wins, a later app-secret finding cannot restore generation.
        const safetyDifference = classificationSafetyRank(classification.provider)
          - classificationSafetyRank(existing.cluster.provider);
        const confidenceDifference = confidenceRank[classification.confidence] - confidenceRank[existing.confidence];
        if (safetyDifference > 0 || (safetyDifference === 0 && confidenceDifference > 0)) {
          existing.cluster.provider = classification.provider;
          existing.cluster.tier = classification.tier;
          existing.cluster.method = methodFor(classification.provider);
          existing.confidence = classification.confidence;
        }
      }
    }
  }

  // Resolve after ordinary clusters are complete, including their final safety-selected classification.
  function resolveReferences(start: InventoryVariable): ClusterEntry[] {
    if (railwayVariables.get(variableKey(serviceKey(start.service), start.variable.name)) === null) return [];
    const pending: InventoryVariable[] = [start];
    const visited = new Set<InventoryVariable>();
    const resolved = new Map<string, ClusterEntry>();

    // Traverse independently for each observation: caching a partial cyclic path can hide valid branches.
    for (let index = 0; index < pending.length; index += 1) {
      const current = pending[index]!;
      if (visited.has(current)) continue;
      visited.add(current);
      // An interpolated value may also contain literal credentials; keep its direct consumer exactly once.
      if (current.clusterId !== undefined && current.clusterId !== start.clusterId) {
        const cluster = clusters.get(current.clusterId);
        if (cluster) resolved.set(current.clusterId, cluster);
      }
      for (const reference of current.references ?? []) {
        const matchingServices = railwayServices.get(referenceServiceKey(current.service, reference.serviceName));
        // Service names are only meaningful within one host/project/environment and must be unambiguous.
        if (matchingServices?.size !== 1) continue;
        const targetServiceId = matchingServices.values().next().value;
        if (targetServiceId === undefined) continue;
        const target = railwayVariables.get(variableKey(targetServiceId, reference.varName));
        if (target) pending.push(target);
      }
    }

    return [...resolved.values()];
  }

  for (const entry of references) {
    for (const { cluster, confidence } of resolveReferences(entry)) {
      const consumer: Consumer = {
        service: entry.service,
        varName: entry.variable.name,
        fingerprint: cluster.fingerprint,
        hint: cluster.hint,
        sealed: cluster.fingerprint === null,
        reference: true,
      };
      cluster.consumers.push(consumer);
      findings.push({ ...consumer, provider: cluster.provider, tier: cluster.tier, isSecret: true, confidence });
    }
  }

  return {
    version: 1,
    scannedAt: now.toISOString(),
    hosts: [...hosts],
    services: [...services.values()],
    findings,
    clusters: [...clusters.values()].map(({ cluster }) => cluster),
    errors,
  };
}

export async function scanHosts(hosts: HostAdapter[], key: Buffer, log: Logger): Promise<Inventory> {
  let active = 0;
  const waiting: (() => void)[] = [];

  async function limited<T>(operation: () => Promise<T>): Promise<T> {
    if (active >= 4) await new Promise<void>((resolve) => waiting.push(resolve));
    else active += 1;

    try {
      return await operation();
    } finally {
      // Transfer the reserved permit directly to the next waiter to avoid oversubscription.
      const next = waiting.shift();
      if (next) next();
      else active -= 1;
    }
  }

  const scans = await Promise.all(hosts.map(async (host): Promise<HostScan> => {
    let services: ServiceRef[];
    try {
      services = await limited(() => host.listServices());
    } catch {
      log.warn(scanErrorMessage, { host: host.id });
      return { host: host.id, services: [], error: scanErrorMessage };
    }

    let failed = false;
    const scannedServices = await Promise.all(services.map(async (service) => {
      try {
        const vars = await limited(() => host.readVariables(service));
        return { service, vars };
      } catch {
        failed = true;
        // The discovered service remains visible even if its variables could not be read.
        return { service, vars: [] };
      }
    }));
    if (failed) log.warn(scanErrorMessage, { host: host.id });
    return { host: host.id, services: scannedServices, ...(failed ? { error: scanErrorMessage } : {}) };
  }));

  return buildInventory(scans, key);
}
