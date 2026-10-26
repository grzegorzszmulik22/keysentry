import { fingerprint } from '../../core/fingerprint.js';
import type { Signal } from '../../types.js';
import { now, type DetectorContext } from '../context.js';

export interface GithubOptions {
  repos: readonly string[];
  token?: string;
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

/** Match alert secrets in memory only. Raw alert fields never enter state, diagnostics or notifications. */
export async function detectGithubLeaks(ctx: DetectorContext, options: GithubOptions): Promise<Signal[]> {
  const signals: Signal[] = [];
  const at = now(ctx).toISOString();
  const token = options.token ?? ctx.providerCtx.credentials.GITHUB_TOKEN;
  if (!token) {
    if (options.repos.length > 0) ctx.log.warn('GitHub secret scanning requires a configured token.');
    return signals;
  }
  for (const repo of new Set(options.repos)) {
    try {
      // Construct pagination URLs locally: never send authorization to an upstream-supplied Link target.
      if (!/^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/.test(repo) || repo.includes(token)) throw new Error();
      const pageNumbers = new Set<number>();
      for (let page = 1; page <= 100; page++) {
        const response = await ctx.providerCtx.http.request({
          method: 'GET',
          url: `https://api.github.com/repos/${repo}/secret-scanning/alerts?state=open&per_page=100${page > 1 ? `&page=${page}` : ''}`,
          headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' },
        });
        if (response.status < 200 || response.status >= 300) throw new Error();
        const alerts = response.json<unknown>();
        if (!Array.isArray(alerts)) throw new Error();
        let newNumbers = 0;
        for (const raw of alerts) {
          const alert = record(raw);
          if (!alert || typeof alert.number !== 'number' || !Number.isSafeInteger(alert.number) || alert.number < 1) continue;
          if (!pageNumbers.has(alert.number)) newNumbers++;
          pageNumbers.add(alert.number);
          const alertId = fingerprint(`${repo}:${alert.number}`, ctx.fingerprintKey);
          if (ctx.state.seenGithubAlerts[alertId] || typeof alert.secret !== 'string' || alert.secret.length === 0) continue;
          const digest = fingerprint(alert.secret, ctx.fingerprintKey);
          const clusterIds = ctx.inventory.clusters.filter(cluster => cluster.fingerprint === digest).map(cluster => cluster.id);
          ctx.state.seenGithubAlerts[alertId] = at;
          if (clusterIds.length === 0) continue;
          signals.push({
            id: `github-${alertId}`, kind: 'leak_detected', at, confidence: 'high', clusterIds,
            summary: 'GitHub secret scanning found an inventory secret in a configured repository.',
            evidence: { alertNumber: alert.number, alertId },
          });
        }
        if (alerts.length < 100 || newNumbers === 0) break;
        if (page === 100) ctx.log.warn('GitHub secret scanning reached its pagination limit.');
      }
    } catch {
      ctx.log.warn('Unable to poll GitHub secret scanning alerts for a configured repository.');
    }
  }
  return signals;
}
