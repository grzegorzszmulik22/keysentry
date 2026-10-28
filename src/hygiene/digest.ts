import type { AutopilotWave } from '../autopilot/runner.js';
import type { FirstRunFinding, HostId, Incident, Inventory, KeyHygiene, NotifyMessage, Signal } from '../types.js';

export interface DigestInput {
  since: string;
  now: string;
  inventory: Inventory;
  hygiene: readonly KeyHygiene[];
  incidents: readonly Incident[];
  waves: readonly AutopilotWave[];
  signals: readonly Signal[];
  /** Inventory has no git-history metadata; supply the first-run findings when available. */
  findings?: readonly FirstRunFinding[];
  showHints?: boolean;
}

const HOSTS: Record<HostId, string> = {
  railway: 'Railway', vercel: 'Vercel', render: 'Render', fly: 'Fly',
  'github-actions': 'GitHub Actions', dotenv: 'local environment',
  netlify: 'Netlify', 'cloudflare-workers': 'Cloudflare Workers', 'supabase-functions': 'Supabase Edge Functions',
  heroku: 'Heroku', digitalocean: 'DigitalOcean App Platform', coolify: 'Coolify', zeabur: 'Zeabur',
  kubernetes: 'Kubernetes', 'aws-secrets-manager': 'AWS Secrets Manager', 'vault-kv': 'HashiCorp Vault', doppler: 'Doppler', infisical: 'Infisical',
};

function unique<T>(items: readonly T[], key: (item: T) => string): T[] {
  const seen = new Set<string>();
  return items.filter(item => {
    const id = key(item);
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
}

/** Accept only the bounded, partial shapes emitted by makeHint, never a whole supplied value. */
function safeHint(hint: string | null | undefined): string | undefined {
  if (typeof hint !== 'string') return undefined;
  return /^(?:[A-Za-z0-9_.+\/-]{0,7}\u2026[A-Za-z0-9_.+\/=-]{2,4}|(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?):\/\/\u2026[A-Za-z0-9.-]{1,4})$/.test(hint)
    ? hint : undefined;
}

/** Build unsigned plain data; the existing notification dispatcher signs and delivers it. */
export function buildDigest(input: DigestInput): NotifyMessage {
  const from = Date.parse(input.since);
  const to = Date.parse(input.now);
  if (!Number.isFinite(from) || !Number.isFinite(to) || from > to) {
    throw new TypeError('Invalid digest time window.');
  }
  const inWindow = (at: string | undefined): boolean => {
    const time = at === undefined ? Number.NaN : Date.parse(at);
    return time >= from && time <= to;
  };
  const lines: string[] = [];
  const clusters = new Map(input.inventory.clusters.map(cluster => [cluster.id, cluster]));
  const add = (text: string, hint?: string | null): void => {
    const partial = input.showHints === true ? safeHint(hint) : undefined;
    lines.push(`${text}${partial ? ` (${partial})` : ''}.`);
  };

  // Sources contain arbitrary titles, errors, URLs and evidence. None of that text crosses this boundary.
  for (const incident of unique(input.incidents, item => item.id)) {
    if (!inWindow(incident.openedAt) && !inWindow(incident.trigger?.at)) continue;
    const host = Object.hasOwn(HOSTS, incident.host) ? HOSTS[incident.host] : 'platform';
    if (incident.status === 'triggered') add(`A ${host} incident triggered a rotation`);
    else if (incident.status === 'closed') add(`A ${host} incident was closed`);
    else if (incident.status === 'watching') add(`A ${host} advisory is being watched`);
    else add(`A ${host} incident needs review`);
  }

  const waves = unique(input.waves, item => item.id).filter(wave => Date.parse(wave.startedAt) <= to);
  for (const wave of waves.filter(wave => wave.status === 'stopped')) add('A rotation stopped and needs review');
  for (const wave of waves.filter(wave => wave.status === 'running' || wave.status === 'grace')) {
    add(wave.status === 'grace' ? 'A rotation is waiting for its grace period to finish' : 'A rotation is still pending');
  }

  for (const finding of unique(input.findings ?? [], item => item.id)) {
    if (finding.inGitHistory) add('A key appears in git history; rotate it', finding.hint);
  }

  const hygiene = unique(input.hygiene, item => item.clusterId).filter(item => clusters.has(item.clusterId));
  for (const item of hygiene) {
    if (item.rotateBy !== undefined && Date.parse(item.rotateBy) < to) {
      add('A key is past its rotate-by date', clusters.get(item.clusterId)?.hint);
    }
  }
  for (const item of hygiene) {
    if (item.unusedDays !== undefined && Number.isFinite(item.unusedDays) && item.unusedDays >= 30) {
      add(`A key shows no usage for ${Math.floor(item.unusedDays)} days`, clusters.get(item.clusterId)?.hint);
    }
  }

  for (const signal of unique(input.signals, item => item.id)) {
    if (signal.kind !== 'usage_anomaly' || !inWindow(signal.at)) continue;
    const hint = signal.clusterIds.map(id => clusters.get(id)?.hint).find(hint => safeHint(hint));
    add('A spend spike needs review', hint);
  }

  const summary = lines.length === 0 ? 'Nothing needed your attention this week.'
    : `${lines.length} ${lines.length === 1 ? 'item' : 'items'} needed your attention this week.`;
  return {
    id: `digest-${from}-${to}`, at: new Date(to).toISOString(), kind: 'digest', severity: 'info',
    title: 'Weekly digest', lines: [summary, ...lines.slice(0, 8)],
  };
}
