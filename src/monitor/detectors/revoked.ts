import { randomUUID } from 'node:crypto';
import { fingerprint } from '../../core/fingerprint.js';
import type { Signal } from '../../types.js';
import { findProvider, now, readClusterSecret, type DetectorContext } from '../context.js';

const HOUR_MS = 3_600_000;

/** Observe authentication transitions without interpreting transport failures as revocations. */
export async function detectRevoked(ctx: DetectorContext): Promise<Signal[]> {
  const current = now(ctx);
  const at = current.toISOString();
  const signals: Signal[] = [];

  for (const cluster of ctx.inventory.clusters) {
    const provider = findProvider(ctx, cluster.provider);
    if (!provider) continue;
    const previous = ctx.state.lastVerify[cluster.id];
    if (previous && current.getTime() - Date.parse(previous.at) < HOUR_MS) continue;

    // Timestamp attempts as well as results, so unavailable hosts/providers cannot cause a tight retry loop.
    ctx.state.lastVerify[cluster.id] = previous
      ? { ...previous, at }
      : { at, ok: false, fingerprint: cluster.fingerprint ?? '' };

    try {
      const secret = await readClusterSecret(cluster, ctx);
      if (!secret || secret.variable.sealed || secret.variable.value === undefined) continue;
      const currentFingerprint = fingerprint(secret.variable.value, ctx.fingerprintKey);
      const sameCredential = previous?.fingerprint === currentFingerprint;
      const result = await provider.verify(secret.variable.value, secret.providerCtx);
      const rejected = !result.ok && (result.status === 401 || result.status === 403);

      // An outage is inconclusive. Keep the last authentication result for this exact value,
      // while the timestamp above still limits polling to once an hour.
      if (!result.ok && !rejected) {
        ctx.state.lastVerify[cluster.id] = sameCredential
          ? { ...previous!, at }
          : { at, ok: false, fingerprint: currentFingerprint };
        continue;
      }

      ctx.state.lastVerify[cluster.id] = {
        at, ok: result.ok, fingerprint: currentFingerprint,
        ...(result.status === undefined ? {} : { status: result.status }),
      };
      if (!rejected || !sameCredential || !previous?.ok) continue;
      signals.push({
        id: `revoked-${randomUUID()}`,
        kind: 'revoked_upstream',
        at,
        confidence: 'high',
        clusterIds: [cluster.id],
        summary: 'The provider rejected a previously valid credential.',
        evidence: { provider: provider.id, status: result.status },
      });
    } catch {
      // Adapter diagnostics can contain credentials; retain neither their text nor identities.
      ctx.log.warn('Unable to verify a monitored credential.');
    }
  }
  return signals;
}
