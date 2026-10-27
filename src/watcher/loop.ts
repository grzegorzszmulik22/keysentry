import { setTimeout as delay } from 'node:timers/promises';
import type { HostId, Incident, IncidentEvidence, Logger, NotifyMessage } from '../types.js';
import { heartbeatDue, selfCheck, type SelfCheckResult } from './self-check.js';
import type { DetectedPlatform } from './platform.js';

type MaybePromise<T> = T | Promise<T>;

export interface WatcherTickResult {
  status: 'ok' | 'error' | 'alert-only';
  /** Fixed step names only. Exceptions and their messages never cross this boundary. */
  errors: string[];
  reasons: string[];
}

export interface WatcherActionContext {
  alertOnly: boolean;
  reasons: string[];
  /** Adapters must never include these credentials in a rotation, including resumed waves. */
  excludedTokenNames: readonly string[];
  ownHost: HostId | null;
}

/** Store this metadata through the encrypted StateStore before acting. Never store credentials here. */
export interface WatcherTickState {
  /** Original watcher activation, retained even when notification delivery has never succeeded. */
  startedAt?: string;
  lastNotifySuccessAt?: string | null;
  pendingTriggered: Incident[];
  pendingAlerted: Incident[];
  ownPlatformNotified: string[];
  completedTriggered?: string[];
  pausedTriggeredNotified?: string[];
  approvalsRequested: string[];
  lastHeartbeatAt: string | null;
}

export interface WatcherTickDependencies {
  now?: () => Date;
  startedAt?: Date;
  platform: DetectedPlatform;
  ownTokenNames: readonly string[];
  log: Pick<Logger, 'warn'>;
  selfCheck: (input: { startedAt: Date; now: Date; lastNotifySuccessAt: string | null }) => MaybePromise<SelfCheckResult>;
  resumeWaves: (context: WatcherActionContext) => Promise<unknown>;
  relay?: {
    /** The relay/service adapter must authenticate messages before applying approvals or disarms. */
    poll: () => Promise<{ approvals: unknown[]; disarms?: unknown[] }>;
    approve: (message: unknown) => Promise<unknown>;
    disarm: (message: unknown) => Promise<unknown>;
  };
  fetchSources: () => Promise<IncidentEvidence[]>;
  /** This adapter must persist returned incident state before resolving, so a crash cannot retrigger a wave. */
  updateIncidents: (evidence: IncidentEvidence[], now: Date) => MaybePromise<{
    incidents: Incident[]; changed: Incident[]; triggered: Incident[];
  }>;
  runAutopilot: (incident: Incident, context: WatcherActionContext) => Promise<unknown>;
  settleWaves: (context: WatcherActionContext) => Promise<unknown>;
  requestApproval: (incident: Incident) => Promise<unknown>;
  /** Always runs; the adapter must suppress monitor mutations when alertOnly is true. */
  runMonitorOnce: (context: WatcherActionContext) => Promise<unknown>;
  /** Use the dispatcher's actual successful-delivery timestamp, preserved across runtime restarts. */
  lastNotifySuccessAt: () => string | null;
  /** Sign with the watcher/device key and reject when no channel delivered successfully. */
  notify: (message: NotifyMessage) => Promise<unknown>;
  state?: WatcherTickState;
  /** Supply encrypted persistence in production; absence is useful for in-memory execution. */
  saveState?: (state: WatcherTickState) => Promise<void>;
}

function initialState(): WatcherTickState {
  return { pendingTriggered: [], pendingAlerted: [], ownPlatformNotified: [], approvalsRequested: [], lastHeartbeatAt: null };
}

/** One serialized, non-throwing cycle. Production I/O belongs in the supplied adapters. */
export function createWatcherTick(deps: WatcherTickDependencies): () => Promise<WatcherTickResult> {
  const state = deps.state ?? initialState();
  const startedAt = state.startedAt === undefined ? deps.startedAt ?? new Date() : new Date(state.startedAt);
  const completedTriggered = state.completedTriggered ??= [];
  const pausedTriggeredNotified = state.pausedTriggeredNotified ??= [];
  let tail: Promise<unknown> = Promise.resolve();

  async function cycle(): Promise<WatcherTickResult> {
    const errors: string[] = [];
    const reasons = new Set<string>();
    let alertOnly = false;
    let persistenceFailed = false;
    const lastNotifySuccessAt = () => deps.lastNotifySuccessAt() ?? state.lastNotifySuccessAt ?? null;
    const failed = (step: string) => {
      if (!errors.includes(step)) errors.push(step);
      try { deps.log.warn(`The watcher could not complete ${step}.`); } catch { /* Logging cannot stop the tick. */ }
    };
    const step = async <T>(name: string, operation: () => MaybePromise<T>): Promise<{ ok: true; value: T } | { ok: false }> => {
      try { return { ok: true, value: await operation() }; }
      catch { failed(name); return { ok: false }; }
    };
    const context = async (): Promise<WatcherActionContext> => {
      const checked = await step('self-check', async () => {
        const input = { startedAt: new Date(startedAt), now: (deps.now ?? (() => new Date()))(), lastNotifySuccessAt: lastNotifySuccessAt() };
        const checked = await deps.selfCheck(input);
        // Enforce delivery independently of adapters, using the persisted activation
        // anchor so short-lived scheduled processes cannot reset the 24-hour window.
        const delivery = selfCheck({
          ...input,
          stateWritable: !persistenceFailed, armedValid: true,
        });
        return { ok: checked.ok && delivery.ok, reasons: [...checked.reasons, ...delivery.reasons] };
      });
      const safe = checked.ok && checked.value.ok === true && Array.isArray(checked.value.reasons);
      if (!safe) {
        alertOnly = true;
        if (checked.ok) checked.value.reasons.forEach(reason => reasons.add(reason));
        else reasons.add('The watcher self-check could not complete.');
      }
      return { alertOnly: !safe, reasons: [...reasons], excludedTokenNames: [...deps.ownTokenNames], ownHost: deps.platform.host };
    };
    const persist = async () => {
      const result = await step('state save', () => {
        state.lastNotifySuccessAt = lastNotifySuccessAt();
        return deps.saveState?.(structuredClone(state));
      });
      if (!result.ok) persistenceFailed = true;
      return result;
    };

    try {
      const now = (deps.now ?? (() => new Date()))();
      const at = now.toISOString();
      state.startedAt ??= startedAt.toISOString();
      await persist();
      const resume = await context();
      if (!resume.alertOnly) await step('wave resume', () => deps.resumeWaves(resume));

      if (deps.relay) {
        const relay = deps.relay;
        const messages = await step('relay poll', () => relay.poll());
        if (messages.ok) {
          // Process disarm first; a simultaneous approval cannot undo it.
          for (const message of messages.value.disarms ?? []) await step('relay disarm', () => relay.disarm(message));
          for (const message of messages.value.approvals) await step('relay approval', () => relay.approve(message));
        }
      }

      const evidence = await step('source fetch', () => deps.fetchSources());
      let durable = true;
      if (evidence.ok) {
        const updated = await step('incident update', () => deps.updateIncidents(evidence.value, now));
        if (updated.ok) {
          // Recover the crash window between the incident adapter committing a trigger
          // and this queue being saved. Runner incident/wave idempotency covers a crash
          // after its own effects but before our completion acknowledgment is saved.
          const candidates = [...updated.value.triggered, ...updated.value.incidents.filter(item => item.status === 'triggered')];
          for (const incident of candidates) {
            if (!completedTriggered.includes(incident.id) && !incident.waveId
              && !state.pendingTriggered.some(existing => existing.id === incident.id)) state.pendingTriggered.push(structuredClone(incident));
          }
          const closedIds = new Set(updated.value.incidents.filter(item => item.status === 'closed' || item.waveId).map(item => item.id));
          state.pendingTriggered = state.pendingTriggered.filter(item => !closedIds.has(item.id));
          for (const incident of updated.value.incidents.filter(item => item.status === 'alerted')) {
            if (!state.approvalsRequested.includes(incident.id) && !state.pendingAlerted.some(existing => existing.id === incident.id)) {
              state.pendingAlerted.push(structuredClone(incident));
            }
          }
          // A later corroboration supersedes the earlier news-only approval queue entry.
          const triggeredIds = new Set(updated.value.incidents.filter(item => item.status !== 'alerted').map(item => item.id));
          state.pendingAlerted = state.pendingAlerted.filter(item => !triggeredIds.has(item.id));
          durable = (await persist()).ok;
        } else durable = false;
      }

      if (durable) {
        for (const incident of [...state.pendingTriggered]) {
          let done = false;
          if (deps.platform.host !== null && incident.host === deps.platform.host) {
            if (state.ownPlatformNotified.includes(incident.id)) done = true;
            else {
              const names = deps.ownTokenNames.filter(name => /^[A-Z][A-Z0-9_]{0,199}$/.test(name)).join(', ') || 'the configured tokens';
              const sent = await step('own-platform notification', () => deps.notify({
                id: `watcher-own-platform-${incident.id}`, at: incident.trigger?.at ?? at,
                kind: 'watcher-own-platform', severity: 'urgent', title: 'Watcher platform incident',
                lines: [`The platform this watcher runs on reported a security incident. Rotate the tokens you gave keysentry (${names}) by hand, then run \`keysentry watcher setup\` again.`],
              }));
              if (sent.ok) { state.ownPlatformNotified.push(incident.id); done = true; }
            }
          } else {
            const action = await context();
            if (!action.alertOnly) done = (await step('autopilot', () => deps.runAutopilot(incident, action))).ok;
            else {
              if (!pausedTriggeredNotified.includes(incident.id)) {
                const sent = await step('paused incident notification', () => deps.notify({
                  id: `watcher-incident-paused-${incident.id}`, at: incident.trigger?.at ?? at,
                  kind: 'watcher-incident-paused', severity: 'warning', title: 'Incident needs review',
                  lines: [`An incident for ${incident.host} needs review. Automatic actions are paused. Review the watcher checks before continuing.`],
                }));
                if (sent.ok) pausedTriggeredNotified.push(incident.id);
              }
              if (!state.approvalsRequested.includes(incident.id)) {
                const requested = await step('approval request', () => deps.requestApproval(incident));
                if (requested.ok) state.approvalsRequested.push(incident.id);
              }
              if (!(await persist()).ok) { durable = false; break; }
            }
          }
          if (done) {
            completedTriggered.push(incident.id);
            state.pendingTriggered = state.pendingTriggered.filter(item => item.id !== incident.id);
            if (!(await persist()).ok) { durable = false; break; }
          }
        }
        if (durable) for (const incident of [...state.pendingAlerted]) {
          if (state.approvalsRequested.includes(incident.id)) continue;
          const requested = await step('approval request', () => deps.requestApproval(incident));
          if (requested.ok) {
            state.approvalsRequested.push(incident.id);
            state.pendingAlerted = state.pendingAlerted.filter(item => item.id !== incident.id);
            if (!(await persist()).ok) break;
          }
        }
      }

      const settle = await context();
      if (!settle.alertOnly) await step('grace settlement', () => deps.settleWaves(settle));
      const monitor = await context();
      await step('monitor', () => deps.runMonitorOnce(monitor));
      await step('heartbeat', async () => {
        if (heartbeatDue({ startedAt, now, lastNotifySuccessAt: lastNotifySuccessAt(), lastHeartbeatAt: state.lastHeartbeatAt })) {
          await deps.notify({ id: `watcher-heartbeat-${at}`, at, kind: 'watcher-heartbeat', severity: 'info',
            title: 'Watcher heartbeat', lines: [alertOnly ? 'The watcher is running in alert-only mode.' : 'The watcher is running.'] });
          state.lastHeartbeatAt = at;
          await persist();
        }
      });
    } catch { failed('cycle'); }
    finally {
      // Runner, recovery, settlement and detector adapters can also deliver a
      // notification, including before rejecting. Preserve the real dispatcher
      // timestamp before a scheduled process exits.
      await persist();
    }
    return { status: errors.length ? 'error' : alertOnly ? 'alert-only' : 'ok', errors, reasons: [...reasons] };
  }

  return () => {
    const running = tail.then(cycle);
    tail = running;
    return running;
  };
}

export interface RunOnceDependencies {
  tick: () => Promise<void | WatcherTickResult>;
  settleWaves: () => Promise<unknown>;
  /** Recheck immediately before final settlement, including an environment kill switch. */
  selfCheck: () => MaybePromise<SelfCheckResult>;
}

export async function runOnce(deps: RunOnceDependencies): Promise<number> {
  let error = false;
  let alertOnly = false;
  try {
    const result = await deps.tick();
    error = result?.status === 'error';
    alertOnly = result?.status === 'alert-only' || (result?.reasons.length ?? 0) > 0;
  } catch { error = true; }
  try {
    if (!(await deps.selfCheck()).ok) alertOnly = true;
    if (!alertOnly) await deps.settleWaves();
  } catch { error = true; }
  return error ? 1 : alertOnly ? 2 : 0;
}

export async function runWatcherLoop(deps: {
  tick: () => Promise<unknown>; intervalMs: number; signal: AbortSignal;
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
}): Promise<void> {
  if (!Number.isSafeInteger(deps.intervalMs) || deps.intervalMs <= 0) throw new TypeError('Watcher interval must be a positive number of milliseconds.');
  const sleep = deps.sleep ?? ((ms: number, signal: AbortSignal) => delay(ms, undefined, { signal }));
  while (!deps.signal.aborted) {
    try { await deps.tick(); } catch { /* createWatcherTick logs failures; other injected ticks cannot stop polling. */ }
    if (deps.signal.aborted) return;
    try { await sleep(deps.intervalMs, deps.signal); }
    catch { if (deps.signal.aborted) return; throw new Error('The watcher could not wait for its next cycle.'); }
  }
}
