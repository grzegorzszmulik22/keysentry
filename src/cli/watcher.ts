import { createHash } from 'node:crypto';
import { join } from 'node:path';
import type { StateStore } from '../core/index.js';
import { fingerprint } from '../core/index.js';
import { DEFAULT_SOURCES, classifyItem, isAlertOnly, resumeWaves, runAutopilot, settleWaves, updateIncidents, verifyArmedPlan } from '../autopilot/index.js';
import type { AutopilotDeps, AutopilotState } from '../autopilot/index.js';
import { ApprovalError, createApprovalServer, createApprovalService, createRelay } from '../approvals/index.js';
import type { SignedDeviceApproval, SignedDisarm } from '../approvals/index.js';
import { fetchFeed, type FeedCache } from '../feeds/index.js';
import { createDispatcher, signMessage } from '../notify/index.js';
import type { EngineDeps, RotateOptions } from '../rotate/index.js';
import { canonicalJson, signDetached, type DeviceKey } from '../security/index.js';
import { CREDENTIAL_NAMES } from '../vault/index.js';
import { createWatcherTick, detectPlatform, runOnce, runWatcherLoop, selfCheck, trackHttpClock } from '../watcher/index.js';
import type { WatcherActionContext, WatcherConfig, WatcherTickState } from '../watcher/index.js';
import type { ArmedPlan, AuditLog, FeedSource, HttpClient, Incident, IncidentEvidence, Inventory, Logger, NotifyChannel, NotifyMessage, PasskeyCredential, SignedNotifyMessage, Vault } from '../types.js';
import { CliError } from './errors.js';
import { cacheNotificationMessage, type NotifyChannelSettings } from './notifications.js';

export { setupWatcher, watcherStatus } from './watcher-setup.js';
export type { WatcherSetupDependencies, WatcherDeploymentSecrets, WatcherPlatform } from './watcher-setup.js';

export interface WatchRuntimeDependencies {
  store: StateStore; audit: AuditLog; http: HttpClient; log: Logger; rotation: RotateOptions; fingerprintKey: Buffer;
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

/** Compose the landed watcher modules using the CLI's vault, encrypted state and guarded HTTP client. */
export async function createWatchRuntime(deps: WatchRuntimeDependencies) {
  const now = deps.now ?? (() => new Date());
  const env = deps.env ?? process.env;
  const stateFile = path(deps.store, 'autopilot.json');
  const state = await deps.store.readJson<AutopilotState>('plan', stateFile) ?? emptyState();
  const tickState = await deps.store.readJson<WatcherTickState>('plan', path(deps.store, 'watcher-tick.json')) ?? emptyTick();
  const sourceCache = await deps.store.readJson<Record<string, FeedCache>>('plan', path(deps.store, 'watcher-feeds.json')) ?? {};
  const clock = trackHttpClock(deps.http, now);
  const signing = await deps.signingKey();
  const publicKeys = await deps.deviceKeys();
  const trustedKeyIds = publicKeys.map(key => key.keyId);
  const dispatcher = createDispatcher(await deps.channels(), { log: deps.log, now });
  let lastSuccess = tickState.lastNotifySuccessAt ?? null;
  let approvalOrigin = deps.publicOrigin ?? 'http://localhost';
  const approvals = createApprovalService({ store: deps.store, audit: deps.audit, credentials: async () => passkeysForWatcherOrigin(await deps.passkeys(), approvalOrigin),
    deviceKeys: deps.deviceKeys, rpId: new URL(approvalOrigin).hostname, origins: [approvalOrigin], now });

  async function notify(message: NotifyMessage): Promise<void> {
    const signed = signMessage(message, signing);
    const result = await dispatcher.send(signed);
    if (result.delivered.length) lastSuccess = dispatcher.lastSuccessAt();
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
  async function check(input = { startedAt: new Date(tickState.startedAt ?? now()), now: now(), lastNotifySuccessAt: lastSuccess }) {
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
    const result = selfCheck({ ...input, stateWritable: writable, armedValid: valid.ok && state.armedPlanId === valid.plan.id,
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
    return { ok: result.ok && !kill.alertOnly && !unsafeWave,
      reasons: [...new Set([...result.reasons, ...kill.reasons,
        ...(unsafeWave ? ['A saved wave includes the watcher\'s own credentials.'] : [])])] };
  }
  async function request(clusterIds: string[], reasons: string[], actionId?: string) {
    const id = actionId ?? `approval-${createHash('sha256').update(JSON.stringify([clusterIds, reasons])).digest('hex').slice(0, 24)}`;
    const action = { id, kind: 'autopilot', clusterIds: [...clusterIds], planHash: createHash('sha256').update(JSON.stringify(reasons)).digest('hex') };
    const request = await approvals.request(action, false);
    // The local CLI can inspect the exact action and sign its digest without asking a relay to invent it.
    const file = path(deps.store, 'watcher-approvals.json');
    const pending = await deps.store.readJson<{ actions: { action: typeof action; request: typeof request }[] }>('pending', file) ?? { actions: [] };
    pending.actions = pending.actions.filter(item => item.action.id !== id);
    pending.actions.push({ action, request });
    await deps.store.writeJson('pending', file, pending);
    if (deps.relay) {
      const metadata = { actionId: request.actionId, digest: request.digest, expiresAt: request.expiresAt, kind: action.kind, keyCount: action.clusterIds.length };
      const signed = { request: metadata, keyId: signing.keyId };
      const sig = signDetached(signing.privateKeyDer, Buffer.from(APPROVAL_REQUEST_PREFIX + canonicalJson(signed))).toString('base64');
      const response = await clock.http.request({ method: 'POST', url: `${new URL(deps.relay.server).origin}/${deps.relay.topic}`,
        headers: { 'Content-Type': 'application/json', ...(deps.relay.token ? { Authorization: `Bearer ${deps.relay.token}` } : {}) },
        body: JSON.stringify({ type: 'keysentry-approval-request', v: 1, ...signed, sig }) });
      if (response.status < 200 || response.status >= 300) throw new CliError('The approval relay could not receive this request.');
    }
    return id;
  }
  async function requestIncident(incident: Incident) {
    const inventory = protectedInventory(await deps.freshInventory());
    const clusterIds = inventory.clusters.filter(cluster => cluster.consumers.some(consumer => consumer.service.host === incident.host)).map(cluster => cluster.id);
    const id = await request(clusterIds, ['The incident needs your review.'], `approval-${createHash('sha256').update(incident.id).digest('hex').slice(0, 24)}`);
    await notify({ id: `notify-${id}`, at: now().toISOString(), kind: 'autopilot:ask', severity: 'warning',
      title: 'Incident needs your approval', lines: ['Review this incident before choosing any rotation.'], actionId: id,
      ...(deps.publicOrigin ? { approveUrl: `${deps.publicOrigin}/a/${id}` } : {}) });
  }
  async function runner() : Promise<AutopilotDeps> {
    const engine = await deps.engine();
    return { engine: { ...engine, providerCtx: { ...engine.providerCtx, http: clock.http } },
      options: { ...deps.rotation, dryRun: false, showHints: deps.showHints === true }, notify, requestApproval: request, audit: deps.audit,
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
  async function settle() {
    const checked = await check(); if (!checked.ok) return;
    // Re-read every consumer using read-role adapters immediately before revocation.
    const inventory = protectedInventory(await deps.freshInventory());
    const current = await check(); if (!current.ok) return;
    const result = await settleWaves({ state, now: now(), disarmed: state.disarmed, inventory },
      { ...await runner(), trustedKeyIds, env, selfCheck: current });
    await updated(result.adoptionUpdates);
  }
  const relay = deps.relay ? createRelay({ ...deps.relay, http: clock.http, trustedKeyIds, deviceKeys: deps.deviceKeys, audit: deps.audit, now }) : undefined;
  const relayState = await deps.store.readJson<{ cursor: string | null; pendingApprovals?: SignedDeviceApproval[]; pendingDisarms?: SignedDisarm[] }>('pending', path(deps.store, 'watcher-relay.json')) ?? { cursor: null };
  relayState.pendingApprovals ??= []; relayState.pendingDisarms ??= [];
  const saveRelay = () => deps.store.writeJson('pending', path(deps.store, 'watcher-relay.json'), relayState);
  const tick = createWatcherTick({ now, startedAt: new Date(tickState.startedAt ?? now()), platform: detectPlatform(env), ownTokenNames: ownNames, log: deps.log, state: tickState,
    selfCheck: check,
    async resumeWaves() {
      const current = await check(); if (!current.ok) return;
      const result = await resumeWaves({ state, now: now(), disarmed: state.disarmed }, { ...await runner(), trustedKeyIds, env, selfCheck: current });
      await updated(result.adoptionUpdates);
    },
    ...(relay ? { relay: {
      async poll() {
        if (!relayState.pendingApprovals!.length && !relayState.pendingDisarms!.length) {
          const result = await relay.poll(relayState.cursor);
          relayState.cursor = result.cursor;
          relayState.pendingApprovals = result.approvals; relayState.pendingDisarms = result.disarms;
          // The authenticated inbox is atomic with its cursor; a crash cannot drop an unapplied disarm.
          await saveRelay();
        }
        return { approvals: [...relayState.pendingApprovals!], disarms: [...relayState.pendingDisarms!] };
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
        if (!state.disarmed) await disarm();
        else await saveState();
        relayState.pendingDisarms = relayState.pendingDisarms!.filter(item => item.sig !== message.sig);
        await saveRelay();
      },
    } } : {}),
    async fetchSources() {
      const evidence: IncidentEvidence[] = [];
      const results = await Promise.allSettled((deps.sources ?? DEFAULT_SOURCES).map(async source => {
        const feed = await fetchFeed(clock.http, source, sourceCache[source.id] ?? {});
        sourceCache[source.id] = { etag: feed.etag, lastModified: feed.lastModified };
        return feed.items.map(item => classifyItem(item, source, value => fingerprint(value, deps.fingerprintKey))).filter((item): item is IncidentEvidence => item !== null);
      }));
      for (const result of results) {
        if (result.status === 'fulfilled') evidence.push(...result.value);
        else deps.log.warn('The watcher could not read one configured source.');
      }
      await deps.store.writeJson('plan', path(deps.store, 'watcher-feeds.json'), sourceCache);
      return evidence;
    },
    async updateIncidents(evidence, at) {
      const file = path(deps.store, 'watcher-incidents.json');
      const incidents = await deps.store.readJson<{ incidents: Incident[] }>('plan', file) ?? { incidents: [] };
      const result = updateIncidents(incidents, evidence, at);
      await deps.store.writeJson('plan', file, { incidents: result.incidents });
      return result;
    },
    async runAutopilot(incident) {
      const checked = await check(); if (!checked.ok) return;
      const inventory = protectedInventory(await deps.freshInventory());
      const current = await check(); if (!current.ok) return;
      const armed = await deps.store.readJson('plan', path(deps.store, 'armed-plan.json'));
      const result = await runAutopilot({ incident, armed, trustedKeyIds, inventory, state, selfCheck: current, env, now: now() }, await runner());
      await updated(result.adoptionUpdates);
    },
    settleWaves: settle, requestApproval: requestIncident,
    runMonitorOnce: context => deps.monitor(context, notify, async () => {
      if (!(await check()).ok) throw new CliError('Automatic actions are paused.');
    }),
    notify, lastNotifySuccessAt: () => dispatcher.lastSuccessAt() ?? lastSuccess,
    async saveState(snapshot) { await deps.store.writeJson('plan', path(deps.store, 'watcher-tick.json'), snapshot); },
  });
  return { tick, settle, check, state, approvals, notify, disarm,
    async server(port: number) {
      if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new CliError('The approval port must be from 1 to 65535.');
      approvalOrigin = deps.publicOrigin ?? `http://localhost:${port}`;
      // A local server must create its service with that exact ceremony origin.
      const service = createApprovalService({ store: deps.store, audit: deps.audit, credentials: async () => passkeysForWatcherOrigin(await deps.passkeys(), approvalOrigin),
        deviceKeys: deps.deviceKeys, rpId: new URL(approvalOrigin).hostname, origins: [approvalOrigin], now });
      const server = createApprovalServer({ service, port, host: deps.publicOrigin ? '0.0.0.0' : '127.0.0.1', publicOrigin: approvalOrigin, disarm });
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
