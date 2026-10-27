import { createHash } from 'node:crypto';
import { join } from 'node:path';
import type { StateStore } from '../core/index.js';
import { buildPlan, fingerprint } from '../core/index.js';
import { DEFAULT_SOURCES, classifyItem, executeApprovedAction, isAlertOnly, planHashFor, resumeWaves, retryPendingAsks, runAutopilot, settleWaves, updateIncidents, verifyArmedPlan } from '../autopilot/index.js';
import type { AutopilotDeps, AutopilotState, PendingAutopilotAction } from '../autopilot/index.js';
import { filterNewItems, type IncidentsState } from '../autopilot/incidents.js';
import { ApprovalError, createApprovalServer, createApprovalService, createRelay, verifyDisarm } from '../approvals/index.js';
import type { SignedDeviceApproval, SignedDisarm } from '../approvals/index.js';
import { fetchFeed, type FeedCache } from '../feeds/index.js';
import { createDispatcher, signMessage } from '../notify/index.js';
import type { EngineDeps, RotateOptions } from '../rotate/index.js';
import { canonicalJson, signDetached, type DeviceKey } from '../security/index.js';
import { CREDENTIAL_NAMES } from '../vault/index.js';
import { createActionsRecovery, createWatcherResumeRelay, createWatcherTick, detectPlatform, runOnce, runWatcherLoop, selfCheck, trackHttpClock } from '../watcher/index.js';
import type { ActionsRecoveryState, SignedWatcherResume, WatcherActionContext, WatcherConfig, WatcherTickState } from '../watcher/index.js';
import type { ArmedPlan, AuditLog, FeedSource, HttpClient, Incident, IncidentEvidence, Inventory, Logger, NotifyChannel, NotifyMessage, PasskeyCredential, SignedNotifyMessage, Vault } from '../types.js';
import { CliError } from './errors.js';
import { cacheNotificationMessage, type NotifyChannelSettings } from './notifications.js';
import { createWatcherStateStore } from './watcher-state.js';

export { setupWatcher, watcherStatus } from './watcher-setup.js';
export type { WatcherSetupDependencies, WatcherDeploymentSecrets, WatcherPlatform } from './watcher-setup.js';

export interface WatchRuntimeDependencies {
  store: StateStore; audit: AuditLog; http: HttpClient; log: Logger; rotation: RotateOptions; fingerprintKey: Buffer;
  /** The configured project identity binds signed relay disarms to this watcher. */
  projectId?: string;
  signingKey(): Promise<DeviceKey>;
  deviceKeys(): Promise<{ keyId: string; publicKeyDer: Buffer }[]>;
  passkeys(): Promise<PasskeyCredential[]>;
  channels(): Promise<NotifyChannel[]>;
  engine(): Promise<EngineDeps>;
  /** Always read-role, and always a new scan. Saved inventory is insufficient for revocation. */
  freshInventory(): Promise<Inventory>;
  /** The adapter must suppress monitor writes whenever context.alertOnly is true. */
  monitor(context: WatcherActionContext, notify: (message: NotifyMessage) => Promise<void>, assertActive: () => Promise<void>): Promise<unknown>;
  assertHuman(action: string): void;
  sources?: readonly FeedSource[];
  env?: NodeJS.ProcessEnv; now?: () => Date; intervalSeconds?: number; showHints?: boolean;
  publicOrigin?: string | null; relay?: { server: string; topic: string; token?: string } | null;
  /** Only true after successful sealed-container bootstrap. An ordinary CI flag is not authorization. */
  sealed?: boolean;
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
  /** Local runtime can refresh adopted references with the device key. A deployed watcher omits this. */
  applyAdoptionUpdates?: (updates: NonNullable<AutopilotState['adoptionUpdates']>) => Promise<void>;
  onSignedMessage?: (message: SignedNotifyMessage, delivered: boolean) => Promise<void>;
  /** Re-evaluated at each automatic-action boundary, including sealed/container execution. */
  integrityCheck?: () => Promise<{ ok: boolean; reasons: string[] }>;
}

const path = (store: StateStore, name: string) => join(store.paths.dir, name);
const emptyState = (): AutopilotState => ({ armedPlanId: null, disarmed: true, waves: [] });
const emptyTick = (): WatcherTickState => ({ pendingTriggered: [], pendingAlerted: [], ownPlatformNotified: [], approvalsRequested: [], lastHeartbeatAt: null });
const ownNames = [...CREDENTIAL_NAMES, 'KEYSENTRY_WATCHER_KEY', 'KEYSENTRY_STATE_KEY', 'KEYSENTRY_VAULT_PASSPHRASE', 'KEYSENTRY_WATCHER_CONFIG'];
const ownName = (name: string) => ownNames.includes(name) || name.startsWith('KEYSENTRY_');
const protectedInventory = (inventory: Inventory): Inventory => ({ ...inventory,
  clusters: inventory.clusters.filter(cluster => !cluster.consumers.some(consumer => ownName(consumer.varName))),
});

export const APPROVAL_REQUEST_PREFIX = 'keysentry-approval-request:v1\n';

/** WebAuthn's localhost RP is shared by local ports; the HTTP server still checks one exact Origin. */
export function passkeysForWatcherOrigin(credentials: PasskeyCredential[], origin: string): PasskeyCredential[] {
  const isLocal = (value: string): boolean => {
    try { const url = new URL(value); return url.protocol === 'http:' && url.hostname === 'localhost' && url.origin === value; }
    catch { return false; }
  };
  return credentials.map(credential => ({ ...credential,
    origins: isLocal(origin) && credential.rpId === 'localhost' && credential.origins.every(isLocal) ? [origin] : [...credential.origins],
  }));
}

/** Only platform-managed HTTPS ingress has the forwarding hop assumed by the hosted templates. */
export function approvalProxyHops(origin: string | null | undefined, env: NodeJS.ProcessEnv): 0 | 1 {
  if (!origin) return 0;
  try {
    const url = new URL(origin);
    if (url.protocol !== 'https:' || url.origin !== origin) return 0;
    const hosted = ['railway', 'fly', 'render'].includes(detectPlatform(env).platform)
      || ['railway.app', 'fly.dev', 'onrender.com'].some(domain => url.hostname.endsWith(`.${domain}`));
    return hosted ? 1 : 0;
  } catch { return 0; }
}

/** Compose the landed watcher modules using the CLI's vault, encrypted state and guarded HTTP client. */
export async function createWatchRuntime(deps: WatchRuntimeDependencies) {
  const now = deps.now ?? (() => new Date());
  const env = deps.env ?? process.env;
  const platform = detectPlatform(env);
  const actions = platform.platform === 'github-actions';
  deps = { ...deps, store: createWatcherStateStore(deps.store, actions) };
  const stateFile = path(deps.store, 'autopilot.json');
  const savedInitialState = await deps.store.readJson<AutopilotState>('plan', stateFile);
  // Missing local scope differs from an explicit disarm; only a verified grant can pass checks without an arm.
  const state = savedInitialState ?? { ...emptyState(), disarmed: actions };
  const activationFile = path(deps.store, 'watcher-activation.json');
  const activation = actions ? await deps.store.readJson<{ awaitingInitialResume: boolean; resumeAfter?: string }>('plan', activationFile)
    ?? { awaitingInitialResume: savedInitialState === null, resumeAfter: now().toISOString() } : undefined;
  if (activation) await deps.store.writeJson('plan', activationFile, activation);
  const tickState = await deps.store.readJson<WatcherTickState>('plan', path(deps.store, 'watcher-tick.json')) ?? emptyTick();
  const sourceCache = await deps.store.readJson<Record<string, FeedCache>>('plan', path(deps.store, 'watcher-feeds.json')) ?? {};
  const clock = trackHttpClock(deps.http, now);
  const signing = await deps.signingKey();
  const publicKeys = await deps.deviceKeys();
  const trustedKeyIds = publicKeys.map(key => key.keyId);
  const dispatcher = createDispatcher(await deps.channels(), { log: deps.log, now });
  let lastSuccess = tickState.lastExternalSuccessAt ?? null;
  let approvalOrigin = deps.publicOrigin ?? 'http://localhost';
  const watcherCheckMinutes = Math.max(1, Math.ceil((deps.intervalSeconds ?? 300) / 60));
  const approvals = createApprovalService({ store: deps.store, audit: deps.audit, credentials: async () => passkeysForWatcherOrigin(await deps.passkeys(), approvalOrigin),
    deviceKeys: deps.deviceKeys, rpId: new URL(approvalOrigin).hostname, origins: [approvalOrigin], now, mode: actions ? 'actions' : 'interactive' });

  const recoveryFile = path(deps.store, 'watcher-recovery.json');
  const recovery = actions ? createActionsRecovery({ watcherId: deps.projectId ?? '',
    state: await deps.store.readJson<ActionsRecoveryState>('plan', recoveryFile), trustedKeyIds, deviceKeys: deps.deviceKeys, now,
    saveState: value => deps.store.writeJson('plan', recoveryFile, value) }) : undefined;
  // Persist a cold-start hold before checks, heartbeat or any automatic work.
  if (recovery) await deps.store.writeJson('plan', recoveryFile, recovery.state);
  async function activateAfterResume(): Promise<void> {
    if (!activation?.awaitingInitialResume || !recovery || recovery.alertOnly()) return;
    const existing = await deps.store.readJson<AutopilotState>('plan', stateFile);
    if (!existing) {
      const armed = await deps.store.readJson<ArmedPlan>('plan', path(deps.store, 'armed-plan.json'));
      const verified = verifyArmedPlan(armed, { now: now(), trustedKeyIds });
      if (!verified.ok) throw new CliError('The armed plan could not be verified for watcher recovery.');
      const initial: AutopilotState = { armedPlanId: verified.plan.id, disarmed: false, waves: [] };
      await deps.store.writeJson('plan', stateFile, initial);
      Object.assign(state, initial);
    } else Object.assign(state, existing);
    // An explicit disarm, even during recovery, wins. Resume never clears it.
    await deps.store.writeJson('plan', activationFile, { ...activation, awaitingInitialResume: false });
    activation.awaitingInitialResume = false;
  }
  await activateAfterResume();

  async function notify(message: NotifyMessage): Promise<void> {
    if (message.actionId) {
      const origin = deps.publicOrigin;
      const available = origin && passkeysForWatcherOrigin(await deps.passkeys(), origin).some(credential =>
        credential.rpId === new URL(origin).hostname && credential.origins.includes(origin));
      const { approveUrl: _oldUrl, ...body } = message;
      message = { ...body, lines: [...message.lines], ...(available ? { approveUrl: `${origin}/a/${message.actionId}` } : {}) };
      if (!available) message.lines.push(`Approve with keysentry approve ${message.actionId} on your computer.`);
    }
    const signed = signMessage(message, signing);
    const result = await dispatcher.send(signed);
    lastSuccess = dispatcher.lastExternalSuccessAt() ?? lastSuccess;
    await cacheNotificationMessage({ store: deps.store, now }, signed, result.delivered.length > 0);
    await deps.onSignedMessage?.(signed, result.delivered.length > 0);
    if (!result.delivered.length) throw new CliError('No notification channel delivered the message. Automatic actions are paused.');
  }
  async function saveState(): Promise<void> {
    // A separate local disarm must not be overwritten by this process's wave metadata.
    const saved = await deps.store.readJson<AutopilotState>('plan', stateFile);
    if (saved?.disarmed) { state.disarmed = true; state.disarmedAt = saved.disarmedAt; }
    await deps.store.writeJson('plan', stateFile, state);
  }
  async function disarm(): Promise<void> {
    state.disarmed = true; state.disarmedAt = now().toISOString();
    await saveState();
    await deps.audit.append({ kind: 'autopilot:disarm', summary: 'Autopilot disarmed.' });
  }
  const startedAt = new Date(tickState.startedAt ?? now());
  async function check(input: { startedAt: Date; now: Date; lastNotifySuccessAt?: string | null; lastExternalSuccessAt?: string | null }
    = { startedAt, now: now(), lastExternalSuccessAt: lastSuccess }) {
    const saved = await deps.store.readJson<AutopilotState>('plan', stateFile);
    const armed = await deps.store.readJson<ArmedPlan>('plan', path(deps.store, 'armed-plan.json'));
    const valid = verifyArmedPlan(armed, { now: input.now, trustedKeyIds });
    // Local re-arming uses a new signed plan id and cannot occur while a wave is pending.
    if (valid.ok && saved?.armedPlanId === valid.plan.id && saved.armedPlanId !== state.armedPlanId
      && state.waves.every(wave => wave.status === 'done')) {
      state.armedPlanId = saved.armedPlanId; state.disarmed = saved.disarmed; state.disarmedAt = saved.disarmedAt;
      state.waves = saved.waves;
      state.adoptionUpdates = saved.adoptionUpdates; state.adoptionUpdatesPlanId = saved.adoptionUpdatesPlanId;
      state.adoptionNoticeSent = saved.adoptionNoticeSent;
    } else if (saved?.disarmed) { state.disarmed = true; state.disarmedAt = saved.disarmedAt; }
    let writable = true;
    try { await deps.store.writeJson('plan', path(deps.store, 'watcher-check.json'), { at: input.now.toISOString() }); }
    catch { writable = false; }
    const approvedWithoutArm = !armed && state.armedPlanId === null && ((await approvals.approved()).some(entry =>
      entry.action.kind === 'autopilot' && !!entry.action.planHash) || state.waves.some(wave =>
      wave.approval && wave.status !== 'stopped' && wave.plan && wave.inventory));
    const result = selfCheck({ ...input, lastExternalSuccessAt: input.lastExternalSuccessAt ?? lastSuccess,
      stateWritable: writable, armedValid: valid.ok && state.armedPlanId === valid.plan.id || approvedWithoutArm,
      clockSkewSeconds: clock.clockSkewSeconds() });
    if (deps.integrityCheck) {
      try {
        const integrity = await deps.integrityCheck();
        if (!integrity.ok) {
          result.ok = false;
          result.reasons.push(...(integrity.reasons.length ? integrity.reasons : ['The local installation could not be verified.']));
        }
      } catch {
        result.ok = false;
        result.reasons.push('The local installation check could not complete.');
      }
    }
    const kill = isAlertOnly({ env, state, selfCheck: result });
    const unsafeWave = state.waves.some(wave => (wave.status === 'running' || wave.status === 'grace')
      && wave.plan?.steps.some(step => step.consumers.some(consumer => ownName(consumer.varName))));
    return { ok: result.ok && !kill.alertOnly && !unsafeWave && !recovery?.alertOnly(),
      reasons: [...new Set([...result.reasons, ...kill.reasons,
        ...(recovery?.alertOnly() ? ['Autopilot is paused until a device resumes this watcher.'] : []),
        ...(unsafeWave ? ['A saved wave includes the watcher\'s own credentials.'] : [])])] };
  }
  async function request(clusterIds: string[], reasons: string[], actionId?: string, proposed?: PendingAutopilotAction) {
    const id = actionId ?? `approval-${createHash('sha256').update(JSON.stringify([clusterIds, reasons])).digest('hex').slice(0, 24)}`;
    const inventory = !proposed || deps.showHints && !proposed.clusters ? protectedInventory(await deps.freshInventory()) : undefined;
    const action: PendingAutopilotAction = proposed ? structuredClone(proposed) : { id, kind: 'autopilot', clusterIds: [...clusterIds],
      planHash: planHashFor(buildPlan(inventory!, { clusterIds })) };
    if (!action.clusters) action.clusters = action.clusterIds.map(clusterId => ({ clusterId,
      hint: deps.showHints ? inventory?.clusters.find(cluster => cluster.id === clusterId)?.hint ?? null : null }));
    const request = await approvals.request(action, false);
    // The local CLI can inspect the exact action and sign its digest without asking a relay to invent it.
    const file = path(deps.store, 'watcher-approvals.json');
    const pending = await deps.store.readJson<{ actions: { action: typeof action; request: typeof request }[] }>('pending', file) ?? { actions: [] };
    pending.actions = pending.actions.filter(item => item.action.id !== action.id);
    pending.actions.push({ action, request });
    await deps.store.writeJson('pending', file, pending);
    if (deps.relay) {
      const metadata = { actionId: request.actionId, digest: request.digest, expiresAt: request.expiresAt, kind: action.kind,
        keyCount: action.clusterIds.length, clusters: request.clusters, watcherCheckMinutes };
      const signed = { request: metadata, keyId: signing.keyId };
      const sig = signDetached(signing.privateKeyDer, Buffer.from(APPROVAL_REQUEST_PREFIX + canonicalJson(signed))).toString('base64');
      const response = await clock.http.request({ method: 'POST', url: `${new URL(deps.relay.server).origin}/${deps.relay.topic}`,
        headers: { 'Content-Type': 'application/json', ...(deps.relay.token ? { Authorization: `Bearer ${deps.relay.token}` } : {}) },
        body: JSON.stringify({ type: 'keysentry-approval-request', v: 1, ...signed, sig }) });
      if (response.status < 200 || response.status >= 300) throw new CliError('The approval relay could not receive this request.');
    }
    return action.id;
  }
  async function requestIncident(incident: Incident) {
    const inventory = protectedInventory(await deps.freshInventory());
    const clusterIds = inventory.clusters.filter(cluster => cluster.consumers.some(consumer => consumer.service.host === incident.host)).map(cluster => cluster.id);
    const id = `approval-${createHash('sha256').update(incident.id).digest('hex').slice(0, 24)}`;
    await request(clusterIds, ['The incident needs your review.'], id,
      { id, kind: 'autopilot', clusterIds, planHash: planHashFor(buildPlan(inventory, { clusterIds })),
        clusters: clusterIds.map(clusterId => ({ clusterId, hint: deps.showHints ? inventory.clusters.find(cluster => cluster.id === clusterId)?.hint ?? null : null })) });
    await notify({ id: `notify-${id}`, at: now().toISOString(), kind: 'autopilot:ask', severity: 'warning',
      title: 'Incident needs your approval', lines: ['Review this incident before choosing any rotation.'], actionId: id,
      ...(deps.publicOrigin ? { approveUrl: `${deps.publicOrigin}/a/${id}` } : {}) });
  }
  async function runner(context?: WatcherActionContext) : Promise<AutopilotDeps> {
    const engine = await deps.engine();
    return { engine: { ...engine, providerCtx: { ...engine.providerCtx, http: clock.http } },
      options: { ...deps.rotation, dryRun: false, showHints: deps.showHints === true }, notify, requestApproval: request, audit: deps.audit,
      shouldStop: context?.shouldStop ?? (async () => !(await check()).ok),
      async saveState() { await saveState(); } };
  }
  async function updated(updates: AutopilotState['adoptionUpdates']) {
    const pending = state.adoptionUpdates ?? updates;
    if (!deps.applyAdoptionUpdates || !pending || !Object.keys(pending).length || state.waves.some(wave => wave.status !== 'done')) return;
    await deps.applyAdoptionUpdates(pending);
    const refreshed = await deps.store.readJson<AutopilotState>('plan', stateFile);
    if (refreshed) {
      state.armedPlanId = refreshed.armedPlanId;
      state.waves = refreshed.waves;
      state.disarmed ||= refreshed.disarmed;
      delete state.adoptionUpdates; delete state.adoptionUpdatesPlanId; delete state.adoptionNoticeSent;
      if (refreshed.adoptionUpdates) state.adoptionUpdates = refreshed.adoptionUpdates;
      if (refreshed.adoptionUpdatesPlanId) state.adoptionUpdatesPlanId = refreshed.adoptionUpdatesPlanId;
      if (refreshed.adoptionNoticeSent !== undefined) state.adoptionNoticeSent = refreshed.adoptionNoticeSent;
    }
  }
  let activeContext: WatcherActionContext | undefined;
  async function settle(context: WatcherActionContext | undefined = activeContext) {
    const checked = await check(); if (!checked.ok) return;
    // Re-read every consumer using read-role adapters immediately before revocation.
    const inventory = protectedInventory(await deps.freshInventory());
    const current = await check(); if (!current.ok) return;
    const result = await settleWaves({ state, now: now(), disarmed: state.disarmed, inventory },
      { ...await runner(context), trustedKeyIds, env, selfCheck: current });
    await updated(result.adoptionUpdates);
  }
  async function executeApprovals(context?: WatcherActionContext, actionId?: string): Promise<{ executed: boolean; reason?: string }> {
    let executed = false;
    for (const { action, grant } of await approvals.approved()) {
      if (actionId && action.id !== actionId || action.kind !== 'autopilot' || !action.planHash) continue;
      const current = await check();
      if (!current.ok || await context?.shouldStop()) return { executed: false, reason: 'Approved rotation is paused by the watcher checks.' };
      const existing = state.waves.find(wave => wave.approval?.action.id === action.id && wave.approval.grant.digest === grant.digest);
      if (existing) {
        if ((existing.status === 'grace' || existing.status === 'done') && existing.plan?.steps.length === action.clusterIds.length) {
          await approvals.markExecuted(action.id, grant.digest); executed = true;
        }
        continue;
      }
      const inventory = protectedInventory(await deps.freshInventory());
      const checked = await check();
      if (!checked.ok) return { executed: false, reason: 'Approved rotation is paused by the watcher checks.' };
      const armed = await deps.store.readJson<ArmedPlan>('plan', path(deps.store, 'armed-plan.json'));
      const result = await executeApprovedAction({ action: { ...action, kind: 'autopilot', planHash: action.planHash }, grant,
        inventory, armed: armed ?? undefined, state, now: now() }, { ...await runner(context), trustedKeyIds, env, selfCheck: checked });
      await updated(result.adoptionUpdates);
      if (!result.reason && !result.asked.length && !result.guided.length
        && (result.report?.status === 'complete' || result.report?.status === 'grace-pending')) {
        await approvals.markExecuted(action.id, grant.digest); executed = true;
      } else if (actionId) return { executed: false, reason: result.reason ?? 'The approved action needs further review or a guided rotation.' };
    }
    return { executed };
  }
  const relay = deps.relay ? createRelay({ ...deps.relay, http: clock.http, trustedKeyIds, watcherId: deps.projectId,
    deviceKeys: deps.deviceKeys, audit: deps.audit, now }) : undefined;
  const resumeRelay = deps.relay && deps.projectId ? createWatcherResumeRelay({ ...deps.relay, watcherId: deps.projectId,
    http: clock.http, trustedKeyIds, deviceKeys: deps.deviceKeys, now }) : undefined;
  const relayState = await deps.store.readJson<{ cursor: string | null; resumeCursor?: string | null; pendingResumes?: SignedWatcherResume[];
    pendingApprovals?: SignedDeviceApproval[]; pendingDisarms?: SignedDisarm[] }>('pending', path(deps.store, 'watcher-relay.json')) ?? { cursor: null };
  relayState.pendingApprovals ??= []; relayState.pendingDisarms ??= [];
  relayState.pendingResumes ??= []; relayState.resumeCursor ??= null;
  const saveRelay = () => deps.store.writeJson('pending', path(deps.store, 'watcher-relay.json'), relayState);
  const tick = createWatcherTick({ now, startedAt, platform, ownTokenNames: ownNames, log: deps.log, state: tickState,
    selfCheck: check,
    async resumeWaves(context) {
      activeContext = context;
      const current = await check(); if (!current.ok) return;
      const result = await resumeWaves({ state, now: now(), disarmed: state.disarmed }, { ...await runner(context), trustedKeyIds, env, selfCheck: current });
      await updated(result.adoptionUpdates);
    },
    executeApprovals: context => executeApprovals(context),
    ...(recovery ? { recovery: { alertOnly: () => recovery.alertOnly(), async resume(message: unknown) {
      if (activation?.resumeAfter && Date.parse((message as SignedWatcherResume).at) < Date.parse(activation.resumeAfter)) {
        relayState.pendingResumes = relayState.pendingResumes!.filter(item => item.sig !== (message as SignedWatcherResume).sig);
        await saveRelay();
        return { ok: false, reason: 'Watcher resume predates this recovery request.' };
      }
      const result = await recovery.resume(message);
      if (!result.ok && (result.reason === 'Watcher resume could not be verified.' || result.reason === 'Watcher resume state could not be saved.'))
        throw new CliError('Watcher resume could not complete. It will be retried.');
      await activateAfterResume();
      const sig = (message as SignedWatcherResume).sig;
      relayState.pendingResumes = relayState.pendingResumes!.filter(item => item.sig !== sig);
      await saveRelay();
      return result;
    } } } : {}),
    ...(relay ? { relay: {
      async poll() {
        const result = await relay.poll(relayState.cursor);
        const merge = <T extends { sig: string }>(old: T[], fresh: T[]): T[] => [...new Map([...old, ...fresh].map(item => [item.sig, item])).values()];
        relayState.cursor = result.cursor;
        relayState.pendingApprovals = merge(relayState.pendingApprovals!, result.approvals);
        relayState.pendingDisarms = merge(relayState.pendingDisarms!, result.disarms);
        // Persist authenticated inboxes atomically with their independent cursors before acknowledging any message.
        await saveRelay();
        if (resumeRelay && recovery) {
          try {
            const resumed = await resumeRelay.poll(relayState.resumeCursor!);
            relayState.resumeCursor = resumed.cursor; relayState.pendingResumes = merge(relayState.pendingResumes!, resumed.resumes);
            await saveRelay();
          } catch {
            // A resume transport failure cannot discard an authenticated disarm already received.
            if (!relayState.pendingDisarms!.length) throw new CliError('The watcher resume relay check could not complete.');
          }
        }
        return { approvals: [...relayState.pendingApprovals!], disarms: [...relayState.pendingDisarms!], resumes: [...relayState.pendingResumes!] };
      },
      async approve(input: unknown) {
        const message = input as SignedDeviceApproval;
        try {
          if (await approvals.status(message.actionId) !== 'approved') await approvals.approveWithDevice(message.actionId, message);
        } catch (error) {
          // A durably audited rejection is terminal. Storage/audit failures stay in the inbox for retry.
          if (!(error instanceof ApprovalError)) throw error;
        }
        relayState.pendingApprovals = relayState.pendingApprovals!.filter(item => item.sig !== message.sig);
        await saveRelay();
      },
      async disarm(input: unknown) {
        const message = input as SignedDisarm;
        // Saved inboxes may predate project-bound disarms. Never apply an old
        // or foreign recipient after an upgrade or a moved state directory.
        if (deps.projectId && verifyDisarm(message, await deps.deviceKeys(), deps.projectId)) {
          if (!state.disarmed) await disarm();
          else await saveState();
        }
        relayState.pendingDisarms = relayState.pendingDisarms!.filter(item => item.sig !== message.sig);
        await saveRelay();
      },
    } } : {}),
    async fetchSources() {
      const evidence: IncidentEvidence[] = [];
      const incidentFile = path(deps.store, 'watcher-incidents.json');
      let incidentState = await deps.store.readJson<IncidentsState>('plan', incidentFile) ?? { incidents: [] };
      const itemKey = (value: string) => fingerprint(value, deps.fingerprintKey);
      const results = await Promise.allSettled((deps.sources ?? DEFAULT_SOURCES).map(async source => {
        const feed = await fetchFeed(clock.http, source, sourceCache[source.id] ?? {});
        sourceCache[source.id] = { etag: feed.etag, lastModified: feed.lastModified };
        if (feed.status !== 'ok') return [];
        const filtered = filterNewItems(incidentState, source, feed.items, now(), itemKey);
        incidentState = filtered.state;
        return filtered.fresh.map(item => classifyItem(item, source, itemKey)).filter((item): item is IncidentEvidence => item !== null);
      }));
      for (const result of results) {
        if (result.status === 'fulfilled') evidence.push(...result.value);
        else deps.log.warn('The watcher could not read one configured source.');
      }
      // Save seen-item baselines before validators: after a crash, a 304 must
      // never hide content whose baseline had not reached durable state.
      await deps.store.writeJson('plan', incidentFile, incidentState);
      await deps.store.writeJson('plan', path(deps.store, 'watcher-feeds.json'), sourceCache);
      return evidence;
    },
    async updateIncidents(evidence, at) {
      const file = path(deps.store, 'watcher-incidents.json');
      const incidents = await deps.store.readJson<IncidentsState>('plan', file) ?? { incidents: [] };
      const result = updateIncidents(incidents, evidence, at);
      await deps.store.writeJson('plan', file, { incidents: result.incidents, ...(result.sources ? { sources: result.sources } : {}) });
      return result;
    },
    async runAutopilot(incident, context) {
      activeContext = context;
      const checked = await check(); if (!checked.ok) throw new CliError('Automatic actions are paused.');
      const inventory = protectedInventory(await deps.freshInventory());
      const current = await check(); if (!current.ok) throw new CliError('Automatic actions are paused.');
      const armed = await deps.store.readJson('plan', path(deps.store, 'armed-plan.json'));
      const result = await runAutopilot({ incident, armed, trustedKeyIds, inventory, state, selfCheck: current, env, now: now(),
        watcherHost: context.ownHost, ownTokenNames: [...context.excludedTokenNames] }, await runner(context));
      await updated(result.adoptionUpdates);
    },
    settleWaves: settle, requestApproval: requestIncident,
    runMonitorOnce: async context => {
      activeContext = context;
      await retryPendingAsks({ state, now: now() }, await runner(context));
      return deps.monitor(context, notify, async () => {
        if (await context.shouldStop()) throw new CliError('Automatic actions are paused.');
      });
    },
    notify, lastExternalSuccessAt: () => dispatcher.lastExternalSuccessAt() ?? lastSuccess,
    async saveState(snapshot) { await deps.store.writeJson('plan', path(deps.store, 'watcher-tick.json'), snapshot); },
  });
  return { tick, settle, check, state, approvals, notify, disarm, executeApprovedAction: (actionId: string) => executeApprovals(undefined, actionId),
    async server(port: number) {
      if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new CliError('The approval port must be from 1 to 65535.');
      approvalOrigin = deps.publicOrigin ?? `http://localhost:${port}`;
      // A local server must create its service with that exact ceremony origin.
      const service = createApprovalService({ store: deps.store, audit: deps.audit, credentials: async () => passkeysForWatcherOrigin(await deps.passkeys(), approvalOrigin),
        deviceKeys: deps.deviceKeys, rpId: new URL(approvalOrigin).hostname, origins: [approvalOrigin], now, mode: actions ? 'actions' : 'interactive' });
      const server = createApprovalServer({ service, port, host: deps.publicOrigin ? '0.0.0.0' : '127.0.0.1', publicOrigin: approvalOrigin, disarm,
        watcherCheckMinutes, trustProxyHops: approvalProxyHops(deps.publicOrigin, env) });
      await server.listen(); return server;
    },
  };
}

export async function runWatch(deps: WatchRuntimeDependencies, options: { once?: boolean; port?: number; signal?: AbortSignal } = {}): Promise<number> {
  if (!deps.sealed) deps.assertHuman('run the watcher');
  const watcher = await createWatchRuntime(deps);
  const controller = new AbortController();
  const stop = () => controller.abort();
  if (!options.signal) { process.once('SIGINT', stop); process.once('SIGTERM', stop); }
  let server: Awaited<ReturnType<typeof watcher.server>> | undefined;
  try {
    server = options.port === undefined ? undefined : await watcher.server(options.port);
    if (options.once) return await runOnce({ tick: watcher.tick, settleWaves: watcher.settle, selfCheck: watcher.check });
    await runWatcherLoop({ tick: watcher.tick, intervalMs: (deps.intervalSeconds ?? 300) * 1000, signal: options.signal ?? controller.signal, sleep: deps.sleep });
    return 0;
  } finally {
    await server?.close(); await deps.audit.checkpoint();
    if (!options.signal) { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
  }
}

export interface WatcherSetupConfigDependencies {
  projectId: string; store: StateStore; vault: Vault; notifications: NotifyChannelSettings[];
  deviceKeys(): Promise<{ keyId: string; publicKeyDer: Buffer }[]>;
  passkeys(): Promise<PasskeyCredential[]>;
  sources?: { disabled: string[]; extra: FeedSource[] }; intervalSeconds?: number;
  publicOrigin?: string | null; relayServer?: string;
}

/** Resolve only the sealed-config contract's settings. Host tokens remain in the portable encrypted vault. */
export async function buildWatcherSetupConfig(deps: WatcherSetupConfigDependencies): Promise<WatcherConfig> {
  const keys = await deps.deviceKeys();
  const channels = [];
  for (const channel of deps.notifications) {
    if (channel.kind === 'console') continue;
    const settings: Record<string, string> = {};
    for (const [field, value] of Object.entries(channel)) if (field !== 'kind' && value !== undefined) settings[field] = Array.isArray(value) ? JSON.stringify(value) : String(value);
    for (const name of await deps.vault.list(`notify/${channel.id}/`)) {
      const bytes = await deps.vault.get(name);
      try { if (bytes) settings[name.slice(`notify/${channel.id}/`.length)] = bytes.toString(); }
      finally { bytes?.fill(0); }
    }
    channels.push({ kind: channel.kind, settings });
  }
  let relay: WatcherConfig['approvals']['relay'] = null;
  if (deps.relayServer) {
    const bytes = await deps.vault.get('notify/relay/topic');
    try { if (bytes) relay = { server: deps.relayServer, topic: bytes.toString() }; }
    finally { bytes?.fill(0); }
  }
  return { v: 1, projectId: deps.projectId,
    armed: await deps.store.readJson<ArmedPlan>('plan', path(deps.store, 'armed-plan.json')),
    trustedKeyIds: keys.map(key => key.keyId), devicePublicKeys: keys.map(key => ({ keyId: key.keyId, publicKeyDer: key.publicKeyDer.toString('base64') })),
    passkeys: await deps.passkeys(), notify: { channels }, sources: deps.sources ?? { disabled: [], extra: [] },
    approvals: { publicOrigin: deps.publicOrigin ?? null, relay }, intervalSeconds: deps.intervalSeconds ?? 300 };
}
