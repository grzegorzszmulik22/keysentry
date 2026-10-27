// In-memory InFlightStore for engine tests (owned by the orchestrator). put after shred throws, like the real store.
import type { InFlightStore } from '../../src/types.js';

export function createFakeInFlight(): InFlightStore & { shredded: Set<string>; calls: string[] } {
  const plans = new Map<string, Map<string, string>>();
  const shredded = new Set<string>();
  const calls: string[] = [];
  return {
    shredded,
    calls,
    async put(planId, slot, value) {
      calls.push(`put:${slot}`);
      if (shredded.has(planId)) throw new Error(`in-flight store for ${planId} was already shredded`);
      let m = plans.get(planId);
      if (!m) plans.set(planId, (m = new Map()));
      m.set(slot, value);
    },
    async get(planId, slot) {
      calls.push(`get:${slot}`);
      return plans.get(planId)?.get(slot) ?? null;
    },
    async slots(planId) {
      return [...(plans.get(planId)?.keys() ?? [])].sort();
    },
    async shred(planId) {
      calls.push('shred');
      plans.delete(planId);
      shredded.add(planId);
    },
  };
}
