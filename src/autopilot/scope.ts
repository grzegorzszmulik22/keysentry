import type { ArmedCluster, ArmedPlan, Cluster, HostId, Inventory, ScopeDecision } from '../types.js';
import { serviceKey } from '../core/service-key.js';
import { adoptionNeeded, autopilotEligibility } from './armed-plan.js';

type AdoptedCluster = Cluster & { adopted?: ArmedCluster['adopted'] };

function consumerKey(consumer: { serviceKey: string; varName: string }): string {
  return JSON.stringify([consumer.serviceKey, consumer.varName]);
}

/** The caller must verify the signed plan with verifyArmedPlan before checking its scope. */
export function checkScope(input: {
  plan: ArmedPlan;
  inventory: Inventory;
  candidateClusterIds: string[];
  host: HostId;
}): ScopeDecision {
  const { plan, inventory, host } = input;
  const candidates = [...new Set(input.candidateClusterIds)];
  const armedById = new Map(plan.clusters.map(cluster => [cluster.clusterId, cluster]));
  const currentById = new Map(inventory.clusters.map(cluster => [cluster.id, cluster]));
  const reasonsById = new Map<string, string[]>();
  const execute: string[] = [];

  for (const clusterId of candidates) {
    const reasons: string[] = [];
    const addReason = (reason: string): void => {
      if (!reasons.includes(reason)) reasons.push(reason);
    };
    if (!plan.hosts.includes(host)) addReason('host not covered by the armed plan');
    const armed = armedById.get(clusterId);
    const current = currentById.get(clusterId);

    if (!armed) {
      addReason('not armed');
    } else if (!current) {
      addReason('consumer removed');
    } else {
      if (!current.consumers.some(consumer => consumer.service.host === host)) {
        addReason('host not covered by the armed plan');
      }

      const before = new Map(armed.consumers.map(consumer => [consumerKey(consumer), consumer]));
      const after = new Map(current.consumers.map(consumer => {
        const snapshot = { serviceKey: serviceKey(consumer.service), varName: consumer.varName, fingerprint: consumer.fingerprint };
        return [consumerKey(snapshot), snapshot];
      }));

      for (const [key, consumer] of after) {
        const previous = before.get(key);
        if (!previous) {
          addReason(`a new consumer appeared since arming: ${consumer.serviceKey}:${consumer.varName}`);
        } else if (previous.fingerprint !== consumer.fingerprint) {
          addReason("a consumer's value changed since arming");
        }
      }
      if ([...before.keys()].some(key => !after.has(key))) addReason('consumer removed');
      // An ambiguous duplicate identity cannot establish an unchanged consumer set.
      if (before.size !== armed.consumers.length || after.size !== current.consumers.length) {
        addReason("a consumer's value changed since arming");
      }

      // Only the signed adoption authorizes a write-only consumer. A fresh scan does
      // not carry adoption metadata in the shared Inventory contract.
      const effective: AdoptedCluster = { ...current, adopted: armed.adopted };
      const needsAdoption = adoptionNeeded(effective);
      if (needsAdoption) addReason('write-only consumer was not adopted');
      const eligibility = autopilotEligibility(effective);
      if (current.provider !== armed.provider || current.method !== armed.method
        || (!eligibility.eligible && !needsAdoption)) {
        addReason('method not allowed automatically');
      }
    }

    reasonsById.set(clusterId, reasons);
    if (reasons.length === 0) execute.push(clusterId);
  }

  const services = new Set(execute.flatMap(clusterId => currentById.get(clusterId)!.consumers.map(consumer => serviceKey(consumer.service))));
  if (services.size > plan.maxServicesPerWave) {
    const reason = `would touch ${services.size} services (limit ${plan.maxServicesPerWave})`;
    return {
      execute: [],
      ask: candidates.map(clusterId => ({ clusterId, reasons: [...reasonsById.get(clusterId)!, reason] })),
    };
  }
  return {
    execute,
    ask: candidates.filter(clusterId => reasonsById.get(clusterId)!.length > 0)
      .map(clusterId => ({ clusterId, reasons: reasonsById.get(clusterId)! })),
  };
}
