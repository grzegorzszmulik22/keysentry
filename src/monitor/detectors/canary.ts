import { randomUUID } from 'node:crypto';
import type { ProviderKeyInfo, Signal, UsageSample } from '../../types.js';
import { serviceKey } from '../../core/service-key.js';
import { findProvider, now, type DetectorContext } from '../context.js';

export async function detectCanaries(ctx: DetectorContext): Promise<Signal[]> {
  const signals: Signal[] = [];
  const at = now(ctx);
  for (const canary of ctx.state.canaries) {
    if (canary.triggeredAt) continue;
    const provider = findProvider(ctx, canary.provider);
    if (!provider) continue;
    let sample: UsageSample | undefined;
    let key: ProviderKeyInfo | undefined;
    if (provider.usage) {
      try {
        sample = await provider.usage(canary.keyRef, { from: new Date(canary.createdAt), to: at }, ctx.providerCtx);
      } catch {
        ctx.log.warn('Unable to read canary usage.');
      }
    }
    if (provider.listKeys) {
      try {
        key = (await provider.listKeys(ctx.providerCtx)).find(candidate => candidate.keyRef === canary.keyRef);
      } catch {
        ctx.log.warn('Unable to read canary key status.');
      }
    }
    const cost = sample?.cumulativeCostUsd ?? sample?.costUsd ?? 0;
    const used = Number.isFinite(cost) && cost > 0 || (sample?.requests ?? 0) > 0;
    // ProviderKeyInfo exposes disabled+limit but not a reason. A disabled one-cent
    // decoy is treated conservatively as exhausted even when usage is unavailable.
    const exhausted = key?.disabled === true && key.limitUsd === 0.01;
    if (!used && !exhausted) continue;
    const plantedService = serviceKey(canary.service);
    canary.triggeredAt = at.toISOString();
    signals.push({
      id: `signal-${randomUUID()}`, kind: 'canary_triggered', at: at.toISOString(), confidence: 'high',
      clusterIds: ctx.inventory.clusters.filter(cluster => cluster.consumers.some(consumer => serviceKey(consumer.service) === plantedService)).map(cluster => cluster.id),
      host: canary.service.host, serviceKeys: [plantedService],
      summary: 'A planted decoy key was used or exhausted its spending limit.',
      evidence: { canaryId: canary.id, used, exhausted },
    });
  }
  return signals;
}
