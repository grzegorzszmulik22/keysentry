import type { AuditEvent, Cluster, JournalEntry, Redactor, TimelineEvent } from '../types.js';
import { createRedactor } from '../core/redact.js';

export interface TimelineAuditEntry extends AuditEvent { at: string }
export interface TimelineOptions {
  /** Hints come only from this caller-supplied metadata, never arbitrary journal data. */
  showHints?: boolean;
  clusters?: readonly Pick<Cluster, 'id' | 'provider' | 'hint'>[];
  /** Supply the runtime redactor to protect identifiers containing registered custom values. */
  redactor?: Redactor;
}

type Description = Pick<TimelineEvent, 'kind' | 'summary'>;
const describe = (kind: TimelineEvent['kind'], summary: string): Description => ({ kind, summary });
const PROVIDERS: Readonly<Record<Cluster['provider'], string>> = {
  openai: 'OpenAI', anthropic: 'Anthropic', openrouter: 'OpenRouter', stripe: 'Stripe', resend: 'Resend',
  cloudflare: 'Cloudflare', github: 'GitHub', aws: 'AWS', supabase: 'Supabase', database: 'Database',
  slack: 'Slack', sendgrid: 'SendGrid', twilio: 'Twilio', google: 'Google', 'private-key': 'Private',
  'crypto-wallet': 'Wallet', 'app-secret': 'App secret', 'encryption-key': 'Encryption', unknown: 'Unknown',
};
// Audit mirrors retain counts, but discard the journal's undo, cleanup, activation and outcome flags.
const AUDIT_MIRRORS: Readonly<Partial<Record<JournalEntry['event'], Description>>> = {
  'plan-start': describe('decided', 'Rotation start recorded'),
  created: describe('created', 'Key preparation recorded'), written: describe('written', 'Key write recorded'),
  redeploy: describe('deployed', 'Deployment request recorded'), 'deploy-result': describe('deployed', 'Deployment result recorded'),
  revoked: describe('revoked', 'Key revocation recorded'), failed: describe('failed', 'Rotation failure recorded'),
  'plan-end': describe('decided', 'Rotation attempt ended'), 'value-stored': describe('decided', 'Recovery copy stored'),
  'grace-start': describe('grace', 'Grace period started'), 'grace-end': describe('grace', 'Grace period ended'),
  undo: describe('undone', 'Undo recorded'), resume: describe('decided', 'Rotation recovery recorded'),
  shredded: describe('decided', 'Recovery copies removed'), 'orphan-suspected': describe('failed', 'A provider key may need review'),
};

function utc(at: string): string {
  if (typeof at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(at)
    || !Number.isFinite(Date.parse(at))) {
    throw new TypeError('Timeline timestamps must include a valid UTC offset.');
  }
  const result = new Date(at).toISOString();
  // Date.parse otherwise silently normalizes impossible calendar dates and 24:00.
  if (new Date(at.slice(0, 19) + 'Z').toISOString().slice(0, 19) !== at.slice(0, 19) || result.length !== 24) {
    throw new TypeError('Timeline timestamps must include a valid UTC offset.');
  }
  return result;
}

function chronological<T extends { at: string }>(events: readonly T[]): T[] {
  // Array.sort is stable: journal order wins ties, followed by audit order.
  return [...events].sort((a, b) => a.at.localeCompare(b.at));
}

function journalDescription(event: JournalEntry['event'], data: JournalEntry['data'], key: string): Description {
  const undo = data?.undo === true;
  switch (event) {
    case 'plan-start': return describe('decided', data?.dryRun === true ? 'Dry run started' : 'Rotation started');
    case 'created': return data?.phase === 'guided-fallback'
      ? describe('decided', `Replacement needs human input${key}`) : describe('created', `New key created${key}`);
    case 'value-stored': return describe('decided', `Recovery copy stored${key}`);
    case 'written': return undo ? describe('undone', `Old key written during undo${key}`)
      : describe('written', `New key written${key}`);
    case 'redeploy': return describe(undo ? 'undone' : 'deployed', `Deployment requested${undo ? ' during undo' : ''}`);
    case 'deploy-result': {
      const suffix = undo ? ' during undo' : '';
      if (data?.state === 'failed') return describe('failed', data.phase === 'grace-health'
        ? 'Health check failed during grace' : `Deployment failed${suffix}`);
      const result = data?.state === 'success' ? 'Deployment succeeded' : data?.state === 'skipped'
        ? 'Deployment skipped' : data?.state === 'pending' ? 'Deployment pending' : 'Activation unconfirmed';
      return describe(undo ? 'undone' : 'deployed', result + suffix);
    }
    case 'verified': return undo ? describe('undone', `Old key verified during undo${key}`)
      : describe('verified', `New key verified${key}`);
    case 'grace-start': return describe('grace', `Grace period started${key}`);
    case 'grace-end': return describe('grace', `Grace period ended${data?.pending === true ? '; old key retirement is pending' : ''}${key}`);
    case 'revoked': return undo ? describe('undone', `Replacement key revoked during undo${key}`)
      : describe('revoked', `${data?.cleanup === true ? 'Unused replacement key revoked' : 'Old key revoked'}${key}`);
    case 'failed': return describe('failed', `${undo ? 'Undo step failed' : 'Rotation step failed'}${key}`);
    case 'undo': return describe('undone', `Old key restored${key}`);
    case 'resume': return describe(undo ? 'undone' : 'decided', undo ? 'Undo started' : 'Rotation resumed');
    case 'shredded': return describe('decided', 'Recovery copies removed');
    case 'orphan-suspected': return describe('failed', `A provider key may need review${key}`);
    case 'plan-end': {
      if (data?.dryRun === true || data?.status === 'dry-run') return describe('decided', 'Dry run finished');
      if (data?.status === 'failed') return describe('failed', 'Rotation failed');
      if (data?.status === 'partial' || data?.aborted === true) return describe('failed', 'Rotation needs follow-up');
      if (data?.status === 'grace-pending' || data?.pending === true) return describe('grace', 'Rotation is waiting in grace');
      return data?.undone === true ? describe('undone', 'Undo finished') : describe('decided', 'Rotation finished');
    }
  }
}

function auditDescription(entry: TimelineAuditEntry): Description | null {
  if (entry.kind === 'notify-add') return describe('notified', 'Notification channel added');
  if (entry.kind === 'notify-remove') return describe('notified', 'Notification channel removed');
  if (entry.kind === 'notify-test') return describe('notified', 'Notification test completed');
  if (/^(?:notify|notification|notifications):/.test(entry.kind)) {
    const action = entry.kind.slice(entry.kind.indexOf(':') + 1);
    if (action === 'failed' || action === 'failure') return describe('failed', 'Notification delivery failed');
    return describe('notified', action === 'sent' || action === 'delivered' ? 'Notification sent' : 'Notification activity recorded');
  }
  if (!entry.kind.startsWith('autopilot:')) return null;
  const action = entry.kind.slice('autopilot:'.length);
  switch (action) {
    case 'detected': case 'incident': return describe('detected', 'Platform incident detected');
    case 'verified': {
      const counts = entry.data?.counts;
      const affected = counts && typeof counts === 'object' ? (counts as Record<string, unknown>).affected : undefined;
      return typeof affected === 'number' && Number.isFinite(affected) && affected > 0
        ? describe('verified', 'Key verification recorded') : describe('decided', 'Armed plan verified');
    }
    case 'verification-failed': return describe('failed', 'Armed plan verification failed');
    case 'scope': return describe('decided', 'Autopilot scope checked');
    case 'ask': return describe('decided', 'Human approval requested');
    case 'start': return describe('decided', 'Autopilot rotation started');
    case 'stopped': case 'failure': return describe('failed', 'Autopilot stopped');
    case 'grace': return describe('grace', 'Autopilot is waiting in grace');
    case 'arm': return describe('decided', 'Autopilot armed');
    case 'disarm': return describe('decided', 'Autopilot disarmed');
    case 'duplicate': return describe('decided', 'Incident already handled');
    case 'alert-only': case 'resume-alert-only': case 'finish-alert-only':
      return describe('decided', 'Autopilot is in alert-only mode');
    case 'authorization-changed': return describe('decided', 'Autopilot authorization changed; human review needed');
    case 'resume-blocked': case 'finish-blocked': return describe('decided', 'Automatic recovery needs human review');
    case 'adoption-updated': return describe('decided', 'Replacement references saved; local re-arming needed');
    case 'end': {
      const counts = entry.data?.counts;
      if (counts && typeof counts === 'object') {
        const { failed, pending } = counts as Record<string, unknown>;
        if (typeof failed === 'number' && Number.isFinite(failed) && failed > 0) return describe('failed', 'Autopilot finished with failed or skipped keys');
        if (typeof pending === 'number' && Number.isFinite(pending) && pending > 0) return describe('grace', 'Autopilot finished with old keys pending');
      }
      return describe('decided', 'Autopilot run ended');
    }
    default: return Object.hasOwn(AUDIT_MIRRORS, action) ? AUDIT_MIRRORS[action as JournalEntry['event']]!
      : describe('decided', 'Autopilot activity recorded');
  }
}

/** The caller selects the plan/wave's entries. Raw data, errors and audit summaries are never reflected. */
export function buildTimeline(entries: readonly JournalEntry[], audit: readonly TimelineAuditEntry[], opts: TimelineOptions = {}): TimelineEvent[] {
  const journal = chronological(entries.map(entry => ({ ...entry, at: utc(entry.at) })));
  const ids = [...new Set(journal.flatMap(entry => entry.clusterId === undefined ? [] : [entry.clusterId]))];
  const ordinals = new Map(ids.map((id, index) => [id, index + 1]));
  const clusters = new Map(opts.clusters?.map(cluster => [cluster.id, cluster]));
  const redactor = createRedactor();
  function safeReference(value: string | undefined): string | undefined {
    if (value === undefined || /[\x00-\x1f\x7f]/.test(value)) return undefined;
    return redactor.redact(value) === value && (!opts.redactor || opts.redactor.redact(value) === value) ? value : undefined;
  }
  function key(id: string | undefined): string {
    if (id === undefined) return '';
    const cluster = clusters.get(id);
    if (opts.showHints === true && cluster && typeof cluster.hint === 'string'
      && /^[A-Za-z0-9_-]{1,7}…[A-Za-z0-9_-]{4}$/.test(cluster.hint)) {
      const provider = Object.hasOwn(PROVIDERS, cluster.provider) ? PROVIDERS[cluster.provider] : undefined;
      if (provider) return ` for ${provider} key ${cluster.hint}`;
    }
    return ` (key ${ordinals.get(id)} of ${ids.length})`;
  }
  const events: TimelineEvent[] = journal.map(entry => {
    const clusterId = safeReference(entry.clusterId);
    const serviceKey = safeReference(entry.serviceKey);
    return { at: entry.at, ...journalDescription(entry.event, entry.data, key(entry.clusterId)),
      ...(clusterId === undefined ? {} : { clusterId }), ...(serviceKey === undefined ? {} : { serviceKey }) };
  });
  for (const entry of audit) {
    const description = auditDescription(entry);
    if (description) events.push({ at: utc(entry.at), ...description });
  }
  return chronological(events);
}

const EVENT_LABELS: Readonly<Record<TimelineEvent['kind'], string>> = {
  detected: 'Detected', decided: 'Decision', created: 'Created', written: 'Written', deployed: 'Deployment',
  verified: 'Verified', grace: 'Grace', revoked: 'Revoked', failed: 'Failed', undone: 'Undo', notified: 'Notification',
};

function markdownCell(text: string, redactor: Redactor): string {
  return redactor.redact(text).replace(/[\r\n\t]+/g, ' ').replace(/[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/[\\`*_\[\]{}|]/g, character => `&#${character.charCodeAt(0)};`);
}

/** Counts distinct keys whose old key retirement is recorded, excluding unused replacement cleanup. */
export function renderTimelineMarkdown(events: readonly TimelineEvent[]): string {
  const ordered = chronological(events.map(event => ({ ...event, at: utc(event.at) })));
  const first = ordered.at(0), last = ordered.at(-1);
  const seconds = first && last ? Math.floor((Date.parse(last.at) - Date.parse(first.at)) / 1_000) : 0;
  const rotated = new Set(ordered.filter(event => event.kind === 'revoked' && event.clusterId !== undefined
    && !event.summary.startsWith('Unused replacement key revoked')).map(event => event.clusterId)).size;
  const failed = ordered.some(event => event.kind === 'failed');
  const redactor = createRedactor();
  const rows = ordered.map(event => `| ${event.at.replace('T', ' ').replace('Z', ' UTC')} | ${EVENT_LABELS[event.kind] ?? 'Recorded'} | ${markdownCell(event.summary, redactor)} |`);
  return ['# Incident timeline', '',
    `Duration: ${Math.floor(seconds / 60)} min ${seconds % 60} s; ${rotated} ${rotated === 1 ? 'key' : 'keys'} rotated; ${failed ? 'failures recorded' : 'no failures recorded'}.`,
    '', '| Time (UTC) | Event | Detail |', '| --- | --- | --- |', ...rows, ''].join('\n');
}
