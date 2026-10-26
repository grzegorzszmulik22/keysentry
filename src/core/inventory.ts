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

export function buildInventory(scans: HostScan[], key: Buffer, now = new Date()): Inventory {
  const hosts = new Set<HostId>();
  const services = new Map<string, ServiceRef>();
  const findings: SecretFinding[] = [];
  const clusters = new Map<string, { cluster: Cluster; confidence: Classification['confidence'] }>();
  const errors: Inventory['errors'] = [];

  for (const scan of scans) {
    hosts.add(scan.host);
    // Adapter errors can embed request headers or response bodies. Their text is never retained.
    if (scan.error !== undefined) errors.push({ host: scan.host, message: scanErrorMessage });

    for (const { service, vars } of scan.services) {
      const serviceId = serviceKey(service);
      if (!services.has(serviceId)) services.set(serviceId, service);

      for (const variable of vars) {
        // A sealed flag takes precedence over any value accidentally supplied by an adapter.
        const value = variable.sealed ? undefined : variable.value;
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
        // Strict comparison preserves the first classification when confidence is tied.
        if (confidenceRank[classification.confidence] > confidenceRank[existing.confidence]) {
          existing.cluster.provider = classification.provider;
          existing.cluster.tier = classification.tier;
          existing.cluster.method = methodFor(classification.provider);
          existing.confidence = classification.confidence;
        }
      }
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
