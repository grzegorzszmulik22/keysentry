import { createHash, randomBytes } from 'node:crypto';
import type { FeedSource, HostId, Incident, IncidentEvidence } from '../types.js';
import type { FeedItem } from '../feeds/index.js';
import { DEFAULT_SOURCES, mentionsHost, PLATFORM_HOSTS } from './sources.js';

const WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
const CORROBORATION_MS = 72 * 60 * 60 * 1000;
const FUTURE_TOLERANCE_MS = 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

export interface SourceBaseline {
  baselineAt: string;
  seenItemKeys: string[];
  /** Only unseen, undated items from reads after the baseline are eligible. */
  undatedFirstSeenAt: Record<string, string>;
}

export interface IncidentsState {
  incidents: Incident[];
  /** Optional for existing saved state; missing sources establish a silent baseline on their next read. */
  sources?: Record<string, SourceBaseline>;
}

export interface IncidentOptions {
  /** Suppress further automatic host triggers for this many days after a trigger; defaults to 30. */
  cooldownDays?: number;
}

function freshTimestamp(value: string, timestamp: number): boolean {
  const published = Date.parse(value);
  return Number.isFinite(published) && published >= timestamp - CORROBORATION_MS
    && published <= timestamp + FUTURE_TOLERANCE_MS;
}

/** Call only after a successful content read (not a 304). Pass the same keyed identity function as classifyItem. */
export function filterNewItems(
  state: IncidentsState, source: FeedSource, items: readonly FeedItem[], now: Date,
  itemKey: (id: string) => string = id => createHash('sha256').update(id).digest('hex'),
): { fresh: FeedItem[]; state: IncidentsState } {
  const at = now.toISOString();
  const previous = state.sources && Object.hasOwn(state.sources, source.id) ? state.sources[source.id] : undefined;
  const seen = new Set(previous?.seenItemKeys ?? []);
  const undatedFirstSeenAt = { ...previous?.undatedFirstSeenAt };
  const fresh: FeedItem[] = [];
  for (const item of items) {
    const key = itemKey(item.id);
    if (seen.has(key)) continue;
    seen.add(key);
    if (!previous || now.getTime() < Date.parse(previous.baselineAt)) continue;
    if (item.publishedAt !== null && !freshTimestamp(item.publishedAt, now.getTime())) continue;
    if (item.publishedAt === null) Object.defineProperty(undatedFirstSeenAt, key, { value: at, enumerable: true, configurable: true, writable: true });
    fresh.push(item);
  }
  return { fresh, state: { ...state, sources: { ...state.sources, [source.id]: {
    baselineAt: previous?.baselineAt ?? at, seenItemKeys: [...seen], undatedFirstSeenAt,
  } } } };
}

function undatedFirstSeen(item: IncidentEvidence, state: IncidentsState): string | undefined {
  const source = state.sources && Object.hasOwn(state.sources, item.sourceId) ? state.sources[item.sourceId] : undefined;
  const firstSeen = source && Object.hasOwn(source.undatedFirstSeenAt, item.itemKey)
    ? source.undatedFirstSeenAt[item.itemKey] : undefined;
  return firstSeen !== undefined && Date.parse(firstSeen) >= Date.parse(source!.baselineAt) ? firstSeen : undefined;
}

function freshEvidence(item: IncidentEvidence, state: IncidentsState, timestamp: number): boolean {
  if (item.publishedAt !== null) return freshTimestamp(item.publishedAt, timestamp);
  const firstSeen = undatedFirstSeen(item, state);
  return firstSeen !== undefined && freshTimestamp(firstSeen, timestamp) && Date.parse(firstSeen) <= timestamp;
}

function evidenceHosts(evidence: IncidentEvidence): readonly HostId[] {
  if (evidence.kind === 'official') {
    const source = DEFAULT_SOURCES.find(source => source.kind === 'official' && source.id === evidence.sourceId);
    if (source) return source.hosts;
  }
  // The fixed evidence contract has no host field: use only the persisted title, never links or outlet text.
  const mentioned = PLATFORM_HOSTS.filter(host => mentionsHost(host, evidence.title));
  return evidence.kind === 'official' && mentioned.length !== 1 ? [] : mentioned;
}

function triggerRule(evidence: readonly IncidentEvidence[], state: IncidentsState): NonNullable<Incident['trigger']>['rule'] | undefined {
  const official = evidence.filter(item => item.kind === 'official');
  if (official.some(item => item.confidence === 'high' && item.credentialExposure)) return 'official';
  const news = evidence.filter(item => item.kind === 'news' && item.credentialExposure);
  if (official.some(item => item.confidence === 'medium') && news.length > 0) return 'official+news';
  for (let i = 0; i < news.length; i++) {
    const first = news[i]!;
    const firstAt = Date.parse(first.publishedAt ?? undatedFirstSeen(first, state) ?? '');
    if (!Number.isFinite(firstAt) || !first.owner.trim()) continue;
    for (const second of news.slice(i + 1)) {
      const secondAt = Date.parse(second.publishedAt ?? undatedFirstSeen(second, state) ?? '');
      if (second.owner.trim() && first.owner.trim().toLowerCase() !== second.owner.trim().toLowerCase()
        && Number.isFinite(secondAt) && Math.abs(firstAt - secondAt) <= CORROBORATION_MS) return 'corroborated-news';
    }
  }
  return undefined;
}

/** Compute copied state. Persist the returned incidents before acting on the triggered list. */
export function updateIncidents(
  state: IncidentsState, evidence: IncidentEvidence[], now: Date, options: IncidentOptions = {},
): IncidentsState & { changed: Incident[]; triggered: Incident[] } {
  const cooldownDays = options.cooldownDays ?? 30;
  if (!Number.isFinite(cooldownDays) || cooldownDays < 0) throw new Error('Incident cooldown must be nonnegative and finite.');
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
    if (!freshEvidence(item, state, timestamp)) continue;
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
    const coolingDown = incidents.some(previous => previous.id !== incident.id && previous.host === incident.host
      && previous.trigger && timestamp < Date.parse(previous.trigger.at) + cooldownDays * DAY_MS);
    if (coolingDown) {
      incident.status = 'alerted';
      continue;
    }
    const rule = triggerRule(incident.evidence.filter(item => freshEvidence(item, state, timestamp)), state);
    if (rule) {
      incident.status = 'triggered';
      incident.trigger = { at, rule };
      triggered.push(incident);
    } else if (incident.evidence.some(item => item.kind === 'news' || item.confidence === 'medium')) incident.status = 'alerted';
  }
  return { incidents, ...(state.sources ? { sources: state.sources } : {}),
    changed: incidents.filter(incident => changedIds.has(incident.id)), triggered };
}
