import { randomBytes } from 'node:crypto';
import type { HostId, Incident, IncidentEvidence } from '../types.js';
import { DEFAULT_SOURCES, mentionsHost, PLATFORM_HOSTS } from './sources.js';

const WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
const CORROBORATION_MS = 72 * 60 * 60 * 1000;

function evidenceHosts(evidence: IncidentEvidence): readonly HostId[] {
  if (evidence.kind === 'official') {
    const source = DEFAULT_SOURCES.find(source => source.kind === 'official' && source.id === evidence.sourceId);
    if (source) return source.hosts;
  }
  // The fixed evidence contract has no host field: use only the persisted title, never links or outlet text.
  const mentioned = PLATFORM_HOSTS.filter(host => mentionsHost(host, evidence.title));
  return evidence.kind === 'official' && mentioned.length !== 1 ? [] : mentioned;
}

function triggerRule(evidence: readonly IncidentEvidence[]): NonNullable<Incident['trigger']>['rule'] | undefined {
  const official = evidence.filter(item => item.kind === 'official');
  if (official.some(item => item.confidence === 'high')) return 'official';
  const news = evidence.filter(item => item.kind === 'news' && item.credentialExposure);
  if (official.some(item => item.confidence === 'medium') && news.length > 0) return 'official+news';
  for (let i = 0; i < news.length; i++) {
    const first = news[i]!;
    const firstAt = first.publishedAt === null ? NaN : Date.parse(first.publishedAt);
    if (!Number.isFinite(firstAt) || !first.owner.trim()) continue;
    for (const second of news.slice(i + 1)) {
      const secondAt = second.publishedAt === null ? NaN : Date.parse(second.publishedAt);
      if (second.owner.trim() && first.owner.trim().toLowerCase() !== second.owner.trim().toLowerCase()
        && Number.isFinite(secondAt) && Math.abs(firstAt - secondAt) <= CORROBORATION_MS) return 'corroborated-news';
    }
  }
  return undefined;
}

/** Compute copied state. Persist the returned incidents before acting on the triggered list. */
export function updateIncidents(
  state: { incidents: Incident[] }, evidence: IncidentEvidence[], now: Date,
): { incidents: Incident[]; changed: Incident[]; triggered: Incident[] } {
  const at = now.toISOString();
  const timestamp = now.getTime();
  const changedIds = new Set<string>();
  const incidents = state.incidents.map(incident => ({ ...incident, evidence: [...incident.evidence],
    ...(incident.trigger ? { trigger: { ...incident.trigger } } : {}) }));
  for (const incident of incidents) {
    if (incident.status !== 'closed' && timestamp >= Date.parse(incident.openedAt) + WINDOW_MS) {
      incident.status = 'closed';
      changedIds.add(incident.id);
    }
  }
  // Historical dedupe prevents unchanged old feed items starting another rotation after seven days.
  const seenByHost = new Map<HostId, Set<string>>();
  for (const incident of incidents) {
    const seen = seenByHost.get(incident.host) ?? new Set<string>();
    for (const item of incident.evidence) seen.add(item.itemKey);
    seenByHost.set(incident.host, seen);
  }
  for (const item of evidence) {
    for (const host of evidenceHosts(item)) {
      const seen = seenByHost.get(host) ?? new Set<string>();
      if (seen.has(item.itemKey)) continue;
      seen.add(item.itemKey);
      seenByHost.set(host, seen);
      // A manually closed incident also occupies its window; subsequent evidence never reopens it.
      let incident = incidents.find(candidate => candidate.host === host
        && timestamp >= Date.parse(candidate.openedAt) && timestamp < Date.parse(candidate.openedAt) + WINDOW_MS);
      if (!incident) {
        incident = { id: `inc-${host}-${at.slice(0, 10).replace(/-/g, '')}-${randomBytes(4).toString('hex')}`,
          host, openedAt: at, evidence: [], status: 'watching' };
        incidents.push(incident);
      }
      incident.evidence.push({ ...item });
      changedIds.add(incident.id);
    }
  }
  const triggered: Incident[] = [];
  for (const incident of incidents) {
    if (!changedIds.has(incident.id) || incident.status === 'closed' || incident.status === 'triggered' || incident.trigger) continue;
    const rule = triggerRule(incident.evidence);
    if (rule) {
      incident.status = 'triggered';
      incident.trigger = { at, rule };
      triggered.push(incident);
    } else if (incident.evidence.some(item => item.kind === 'news')) incident.status = 'alerted';
  }
  return { incidents, changed: incidents.filter(incident => changedIds.has(incident.id)), triggered };
}
