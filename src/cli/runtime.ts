import { CliError, RotationInterruptedError } from './errors.js';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash } from 'node:crypto';
import { lstat, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, relative, resolve, sep } from 'node:path';
import {
  buildPlan, classify, createLogger, createRedactor, createStateStore, createStateCipher, createInFlightStore,
  renderBlastRadius, renderRunbook, scanHosts, serviceKey, statePaths, StateLockedError, type StateStore,
} from '../core/index.js';
import { getProvider, NON_SECRET_CREDENTIALS, PROVIDER_CREDENTIALS } from '../providers/index.js';
import { executePlan, resumeRotation, finishRotation, undoRotation, type RotateOptions, type EngineDeps } from '../rotate/index.js';
import { createAuditLog } from '../security/index.js';
import { CREDENTIAL_NAMES, credentialVaultName, createCredentialSource, createMemoryVault, deviceKey, fingerprintKey as vaultFingerprintKey, getProjectId, importFromEnv, openVault } from '../vault/index.js';
import { createKeyWrapper, createKmsHttp, KMS_CREDENTIAL_NAMES, kmsEgressRules, loadProjectStateKey } from '../kms/index.js';
import { auditExportEgressRules } from '../audit-export/index.js';
import { offlineEgressRules } from '../feeds/index.js';
import { setupNetwork } from './network-setup.js';
import { needsManualActivation } from '../hosts/activation.js';
import { acceptedCredentialName, VAULT_SET_NAMES } from './credential-names.js';
import { createGuardedHttp, createFileReceipt, EGRESS_RULES, rulesForUserFeeds, rulesForUserUrls } from '../net/index.js';
import { createFetchHttp } from '../http.js';
import { checkLocalIntegrity } from '../release/index.js';
import { runDoctor } from '../doctor/index.js';
import { assertHumanForMutation, MEMORY_ONLY_ROTATION_WARNING } from '../safety/index.js';
import {
  approve, createCanary, createFileMonitorStateStore, createMonitorState, dismiss, listCanaries, removeCanary,
  runMonitorOnce, type BreachFeed, type DetectorContext, type MonitorState, type MonitorStateStore, type RotateExecutor,
} from '../monitor/index.js';
import type {
  GuidedPrompt, HostAdapter, HostId, HttpClient, Inventory, Logger, Policy, ProviderAdapter, TeamPolicy,
  ProviderId, Redactor, RotationPlan, RotationReport, ServiceRef, AuditLog, InFlightStore, Vault, TokenRole, GraceInfo, GraceDecision,
} from '../types.js';
import { loadConfig, loadConfigMetadata, type ConfigSettings } from './config.js';
import { createAutopilotManager, recordDrill, type AutopilotManagerOptions } from './autopilot.js';
import { createWatcherStateStore } from './watcher-state.js';
import { humanizeProviderNames } from './provider-names.js';
import { notificationEgress } from './notifications.js';
import { persistManualAdoption, reconcileAutopilotRecovery } from './adoption-recovery.js';
import { verifyArmedPlan } from '../autopilot/index.js';
import { inventorySchema, planIdSchema, planSchema } from './schemas.js';
import { humanizeServices, serviceLabel } from './display.js';
import { hasInteractiveTerminal, promptSecret, revealSecret, promptPassphrase, promptGrace, confirmVaultFallback, confirmInventoryReplacement, confirmMissingManifest, promptVaultBackend, type RevealInfo, type PromptIO } from './prompts.js';
import { RotationAbortedError } from '../types.js';
import { readinessScore } from '../report/index.js';
import { createHygieneState, createHygieneStateStore, updateFirstSeen, updateLastRotation } from '../hygiene/index.js';
import { dashboardSettingsSchema } from './phase3-runtime.js';
import {
  assertChangesAllowed, autopilotRefusal, governanceFromBundle, loadGovernance, monitorAutomationAllowed, narrowMonitorPolicy, narrowRotationOptions, policyRules,
  restrictUserEgress, type Governance, type TeamBundle,
} from '../policy/index.js';
import { stateQuorum, teamAnchors } from './team-governance.js';
import { actionDigest, ApprovalError, createApprovalService } from '../approvals/index.js';
import type { NotifyChannelSettings } from './notifications.js';

export type PlanFilters = NonNullable<Parameters<typeof buildPlan>[1]>;
type Reveal = (info: RevealInfo, value: string) => Promise<boolean>;
export interface RuntimeOptions {
  firstRunGit?: import('../firstrun/index.js').GitRunner;
  cwd?: string; config?: string; env?: NodeJS.ProcessEnv; http?: HttpClient;
  settings?: ConfigSettings;
  trustedPlanKeyIds?: string[];
  /** Set only after authenticated sealed-watcher bootstrap in the CLI entry point. */
  watcherAuthorized?: boolean;
  /** Sealed watcher only (with watcherAuthorized): the team roster and policy from the authenticated config. */
  teamBundle?: TeamBundle | null;
  hosts?: HostAdapter[]; providers?: (id: ProviderId) => ProviderAdapter;
  policy?: Policy; feeds?: BreachFeed[]; fingerprintKey?: Buffer;
  prompt?: (p: GuidedPrompt) => Promise<string | null>; log?: Logger;
  reveal?: Reveal;
  vault?: Vault; inflight?: InFlightStore; audit?: AuditLog; crashHook?: EngineDeps['crashHook'];
  stdinIsTTY?: boolean; stdoutIsTTY?: boolean; userDir?: string;
  grace?: (info: GraceInfo) => Promise<GraceDecision>;
  passphrase?: () => Promise<Buffer>; allowFileFallback?: (reason: string) => Promise<boolean>;
  confirmInventoryReplacement?: () => Promise<boolean>;
  confirmMissingManifest?: () => Promise<boolean>;
  promptIO?: PromptIO;
  verbose?: boolean; json?: boolean; sleep?: (ms: number) => Promise<void>; now?: () => Date;
}
export interface ExecutionOptions {
  execute?: boolean; prompt?: (p: GuidedPrompt) => Promise<string | null>;
  revoke?: RotateOptions['revoke']; redeploy?: boolean;
  revokeUnconfirmed?: boolean; acceptUnplannedSealed?: boolean; allowGenerate?: boolean; verifyRetries?: number;
  reveal?: Reveal;
}
export interface ApprovalOptions extends Pick<ExecutionOptions, 'prompt' | 'reveal'> { interactive?: boolean; reviewHash?: string }
/** An approved team request a team dashboard change runs under (kind `dashboard:<route>`), re-checked by each entry point. */
export interface TeamGrantRef { actionId: string; digest: string; kind: string }
interface DashboardContext {
  /** Inside a passkey-gated dashboard change. */
  authorized: boolean;
  /** The signed-in team member (team dashboard only). */
  memberId?: string;
  grant?: TeamGrantRef;
}
/** Team dashboard changes run only under a met quorum: their approval requests stay open for an hour. */
export const TEAM_DASHBOARD_REQUEST_TTL_MS = 60 * 60 * 1000;

/** Register opaque and even short secrets as well as the core's recognizable patterns. */
function outputRedactor(): Redactor {
  const base = createRedactor();
  const short = new Set<string>();
  return {
    register(value) { if (value && value.length < 6) short.add(value); base.register(value); },
    redact(text) {
      // Core merges recognizable and registered spans from the original text. Mask them
      // before short values so a short registered prefix cannot hide a complete key.
      text = base.redact(text);
      const values = [...short].sort((a, b) => b.length - a.length);
      if (values.length) {
        const escaped = values.map(value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
        text = text.replace(new RegExp(escaped.join('|'), 'g'), '«redacted»');
      }
      return text;
    },
  };
}

export async function createRuntime(options: RuntimeOptions = {}) {
  const env = options.env ?? process.env;
  const userDir = resolve(options.cwd ?? process.cwd(), options.userDir ?? env.KEYSENTRY_USER_DIR
    ?? (env.KEYSENTRY_STATE_DIR ? join(resolve(options.cwd ?? process.cwd(), env.KEYSENTRY_STATE_DIR), 'user') : join(homedir(), '.keysentry')));
  const interactive = (options.stdinIsTTY ?? !!process.stdin.isTTY) && (options.stdoutIsTTY ?? !!process.stdout.isTTY);
  const mutationContext = { env, stdinIsTTY: options.stdinIsTTY ?? !!process.stdin.isTTY, stdoutIsTTY: options.stdoutIsTTY ?? !!process.stdout.isTTY };
  // Entered only by passkey-gated dashboard handlers. Authorization follows this
  // async operation, and cannot leak to a concurrent CLI/read request. On the team dashboard it also carries the
  // signed-in member (every audit event records them, review M4) and, for changes that need the team's quorum, the
  // approved request the change runs under (review C1).
  const dashboardContext = new AsyncLocalStorage<DashboardContext>();
  const dashboardAuthorized = () => dashboardContext.getStore()?.authorized === true;
  const assertHuman = (action: string, allowPipedStdin = false) => assertHumanForMutation({ ...mutationContext, action, allowPipedStdin,
    ...(dashboardAuthorized() ? { stdinIsTTY: true, stdoutIsTTY: true } : {}) });
  const dashboardAction = async <T>(operation: () => Promise<T>, context: { memberId?: string; grant?: TeamGrantRef } = {}): Promise<T> => {
    assertHumanForMutation({ env, stdinIsTTY: true, stdoutIsTTY: true, action: 'make dashboard changes' });
    if (context.memberId !== undefined && !/^[a-z][a-z0-9_-]{0,31}$/.test(context.memberId)) throw new CliError('The dashboard member could not be identified.');
    return dashboardContext.run({ authorized: true, ...(context.memberId ? { memberId: context.memberId } : {}), ...(context.grant ? { grant: { ...context.grant } } : {}) }, operation);
  };
  /** Team dashboard reads and non-mutating actions: attribute audit events to the member without authorizing changes. */
  const asMember = <T>(memberId: string, operation: () => Promise<T>): Promise<T> => {
    if (!/^[a-z][a-z0-9_-]{0,31}$/.test(memberId)) throw new CliError('The dashboard member could not be identified.');
    return dashboardContext.run({ authorized: false, memberId }, operation);
  };
  const redactor = outputRedactor();
  const knownServices = new Map<string, ServiceRef>();
  const remember = (services: ServiceRef[]) => { for (const service of services) knownServices.set(serviceKey(service), service); };
  const humanize = (text: string) => humanizeProviderNames(humanizeServices(text, [...knownServices.values()]));
  const baseLog = options.log ?? createLogger({ redactor, level: options.verbose ? 'debug' : 'info', json: options.json });
  const logValue = (input: unknown): unknown => {
    if (typeof input === 'string') return redactor.redact(humanize(input));
    if (Array.isArray(input)) return input.map(logValue);
    if (input && typeof input === 'object') return Object.fromEntries(Object.entries(input).map(([key, value]) => [key, logValue(value)]));
    return input;
  };
  const log: Logger = Object.fromEntries((['info', 'warn', 'error', 'debug'] as const).map(level => [level,
    (message: string, data?: Record<string, unknown>) => baseLog[level](redactor.redact(humanize(message)), data === undefined ? undefined : logValue(data) as Record<string, unknown>),
  ])) as unknown as Logger;
  const diagnostic = (text: string) => log.info(text);
  let metadata = await loadConfigMetadata(options);
  /** keysentry.yaml as written. Everything that acts uses `metadata.settings`, narrowed by a verified team policy below. */
  const rawSettings = metadata.settings;
  const paths = statePaths(metadata.cwd);
  async function prepareDirectory(path: string, variable: string) {
    try { await mkdir(path, { recursive: true, mode: 0o700 }); }
    catch { throw new CliError(`Could not prepare the directory ${path}. Set ${variable} to a writable directory.`); }
  }
  await prepareDirectory(userDir, 'KEYSENTRY_USER_DIR');
  await prepareDirectory(paths.dir, 'KEYSENTRY_STATE_DIR');
  const passphrase = options.passphrase ?? (async () => {
    // A passphrase the user put in the environment is used as given, in a terminal too (like restic and borg).
    if (env.KEYSENTRY_VAULT_PASSPHRASE || !interactive) {
      if (!env.KEYSENTRY_VAULT_PASSPHRASE) throw new CliError('The encrypted file needs KEYSENTRY_VAULT_PASSPHRASE when no interactive terminal is available.');
      redactor.register(env.KEYSENTRY_VAULT_PASSPHRASE);
      return Buffer.from(env.KEYSENTRY_VAULT_PASSPHRASE);
    }
    const value = await promptPassphrase(diagnostic, options.promptIO);
    try {
      let isNew = false;
      try { await lstat(join(userDir, 'vault.enc')); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; isNew = true; }
      if (isNew) {
        diagnostic('Enter the passphrase again.');
        const confirmation = await promptPassphrase(diagnostic, options.promptIO);
        try { if (!value.equals(confirmation)) throw new CliError('The passphrases did not match. Try again.'); }
        finally { confirmation.fill(0); }
      }
      redactor.register(value.toString());
      return value;
    } catch (error) { value.fill(0); throw error; }
  });
  const storeName = env.KEYSENTRY_VAULT ?? (process.platform === 'win32' ? 'windows-dpapi' : process.platform === 'darwin' ? 'macos-keychain' : 'linux-secret-service');
  const vault = options.vault ?? await openVault({ env, userDir, log, passphrase,
    allowFileFallback: options.allowFileFallback ?? (reason => interactive ? confirmVaultFallback(storeName, reason, diagnostic, options.promptIO) : Promise.resolve(false)),
    ...(interactive ? { chooseBackend: (backend: import('../types.js').VaultBackendId) => promptVaultBackend(backend, diagnostic, options.promptIO) } : {}),
  });
  const projectId = await getProjectId(paths.dir);
  const receipt = createFileReceipt(join(paths.dir, 'network.jsonl'));
  // With kms configured the state key exists only wrapped and is unwrapped into memory here; a KMS failure
  // refuses to start and never creates a new key (src/kms/state-key.ts). The team roster and policy live in the
  // encrypted state, so this one call uses keysentry.yaml's proxy and CA settings; the team policy applies after it.
  const stateKms = metadata.settings.kms;
  const kmsTransport = stateKms ? (await setupNetwork({ settings: metadata.settings.network, cwd: metadata.cwd, env, vault, redactor,
    policy: null, ...(options.http ? { injected: options.http } : {}) })).transport : undefined;
  const key = await loadProjectStateKey({ vault, projectId, log, now: options.now,
    // Two processes starting a new project together create one wrapped key between them (review M1).
    lockPath: join(paths.dir, 'state-key.lock'),
    envWrapped: vault.backend === 'env' ? env.KEYSENTRY_STATE_KEY_WRAPPED || undefined : undefined,
    ...(stateKms && kmsTransport ? { wrapper: createKeyWrapper(stateKms, { http: createKmsHttp(kmsTransport, stateKms, { receipt, log }),
      credentials: createCredentialSource(vault, env), now: options.now }) } : {}) });
  // The env backend has no writable durable store. Keep internal binding markers
  // process-local, like its in-flight values; supplied environment markers win.
  const transientMetadata = createMemoryVault();
  const stateMetadata = (name: string) => name.startsWith('projects/by-path/') || name.endsWith('/state-initialized');
  const stateVault: Vault = vault.backend === 'env' ? {
    backend: vault.backend, weakness: vault.weakness,
    // The environment vault cannot persist the initialized marker, and environments that use it (CI, the
    // watcher) never held 0.1 plaintext state: report state as initialized so plaintext is never migrated there.
    get: async name => name.endsWith('/state-initialized') ? Buffer.from('1')
      : stateMetadata(name) ? await vault.get(name) ?? transientMetadata.get(name) : vault.get(name),
    set: (name, value) => stateMetadata(name) ? transientMetadata.set(name, value) : vault.set(name, value),
    delete: name => stateMetadata(name) ? transientMetadata.delete(name) : vault.delete(name),
    list: prefix => vault.list(prefix),
  } : vault;
  let baseStore: StateStore;
  try { baseStore = createStateStore({ cwd: metadata.cwd, cipher: createStateCipher(key), vault: stateVault, projectId }); }
  finally { key.fill(0); }
  const migration = await baseStore.migratePlaintext();
  if (migration.migrated.length) log.info(`Encrypted ${migration.migrated.length} files saved by keysentry 0.1. Nothing else changed.`);
  // Phase 5 team governance (notes/team-policy.md): the verified roster and policy. A sealed watcher reads them from
  // its authenticated config; everyone else from encrypted state, checked against the vault checkpoints.
  const anchors = teamAnchors(vault, projectId);
  const sealedTeam = options.watcherAuthorized === true && options.teamBundle !== undefined;
  // `team init`, `team apply` and `policy apply` update the team settings in this process; later reads must see them.
  let teamSettings = () => rawSettings.team;
  const readGovernance = async (): Promise<Governance> => sealedTeam ? governanceFromBundle(options.teamBundle, rawSettings, env)
    : loadGovernance({ store: baseStore, settings: { ...rawSettings, team: teamSettings() }, cwd: metadata.cwd, env, anchors });
  const governance = await readGovernance();
  const teamPolicy: TeamPolicy | null = policyRules(governance);
  // Everything built from settings below (hosts, channels, egress rules, feeds) sees the narrowed copy.
  metadata = await loadConfigMetadata({ ...options, settings: governance.settings });
  const configOptions: RuntimeOptions = { ...options, settings: metadata.settings };
  // Phase 5 network (notes/network-enterprise.md): proxy, extra CA and offline mode, with the verified team policy's
  // offline and requireProxy rules (a required proxy carries every request; network.noProxy is emptied by the policy).
  const network = await setupNetwork({ settings: metadata.settings.network, cwd: metadata.cwd, env, vault, redactor,
    policy: teamPolicy, ...(options.http ? { injected: options.http } : {}) });
  const rawTransport = network.transport;
  /** Refuse a change while governance blocks changes. Re-read each time, so a long-running dashboard sees roster changes. */
  async function assertGovernance(): Promise<void> { assertChangesAllowed(await readGovernance()); }
  const fingerprintKey = options.fingerprintKey ?? await vaultFingerprintKey(vault, projectId, join(userDir, 'fingerprint.key'));
  const transientHeads = createMemoryVault();
  const anchorMarker = join(userDir, 'audit-heads', `${createHash('sha256').update(resolve(paths.audit)).digest('hex').slice(0, 16)}.json`);
  const markAnchor = async () => {
    await mkdir(join(userDir, 'audit-heads'), { recursive: true, mode: 0o700 });
    await writeFile(anchorMarker, '{"v":1}\n', { mode: 0o600 });
  };
  // Environment credentials are read-only. Keep signed checkpoints, but only a
  // process-local head is possible; never present it as a durable vault anchor.
  const auditVault: Vault = vault.backend === 'env' ? {
    backend: vault.backend, weakness: vault.weakness,
    get: async name => name.startsWith('audit/head/') || name === 'audit/mac' ? await transientHeads.get(name) ?? vault.get(name) : vault.get(name),
    set: (name, value) => name.startsWith('audit/head/') || name === 'audit/mac' ? transientHeads.set(name, value) : vault.set(name, value),
    delete: name => name.startsWith('audit/head/') || name === 'audit/mac' ? transientHeads.delete(name) : vault.delete(name),
    list: prefix => vault.list(prefix),
  } : {
    backend: vault.backend, weakness: vault.weakness,
    get: name => vault.get(name),
    async set(name, value) { if (name.startsWith('audit/head/')) await markAnchor(); await vault.set(name, value); },
    delete: name => vault.delete(name), list: prefix => vault.list(prefix),
  };
  const rawAudit = options.audit ?? createAuditLog({ path: paths.audit, vault: auditVault, deviceKey: () => deviceKey(vault), keyLockPath: join(userDir, 'audit-mac'), redactor, now: options.now });
  let auditDirty = false;
  let auditWeaknessReported = false;
  const audit: AuditLog = {
    async append(event) {
      if (!options.audit && vault.backend === 'env' && !auditWeaknessReported) {
        log.warn('The environment vault cannot save an independent audit head. Its audit MAC key is process-local unless supplied in the environment; verification across runs needs the same key.');
        auditWeaknessReported = true;
      }
      // Team dashboard (review M4): every event a member's request causes names that member, so exports carry an actor.
      const memberId = dashboardContext.getStore()?.memberId;
      if (memberId && event.data?.memberId === undefined && event.data?.actor === undefined) event = { ...event, data: { ...event.data, memberId } };
      await rawAudit.append(event); auditDirty = true;
    },
    async checkpoint() {
      if (!auditDirty) return;
      await rawAudit.checkpoint(); auditDirty = false;
    },
    verify: () => rawAudit.verify(),
  };
  const rawJournal = baseStore.journal();
  const journal = {
    read: rawJournal.read.bind(rawJournal),
    async append(entry: Parameters<typeof rawJournal.append>[0]) {
      await rawJournal.append(safe(entry));
      await audit.append({ kind: `journal:${entry.event}`, summary: `Rotation ${entry.event}.`, data: {
        planId: entry.planId, ...(entry.clusterId === undefined ? {} : { clusterId: entry.clusterId }),
        ...(entry.serviceKey === undefined ? {} : { serviceKey: entry.serviceKey }),
      } });
    },
  };
  // Every caller, including monitor/recovery and embedders, receives the mirrored journal.
  const store: StateStore = createWatcherStateStore({ ...baseStore, journal: () => journal }, env.GITHUB_ACTIONS === 'true' && options.watcherAuthorized === true);
  const inflight = options.inflight ?? createInFlightStore({ dir: join(paths.dir, 'inflight'), vault, projectId });
  const credentials = createCredentialSource(vault, env);
  // Defence in depth: KMS credentials are not CREDENTIAL_NAMES (loadConfig does not read them), so register them here.
  if (metadata.settings.kms) for (const name of KMS_CREDENTIAL_NAMES) {
    const found = await credentials.get(name, 'read');
    if (found?.value) redactor.register(found.value);
  }
  let automaticGuard: (() => Promise<void>) | undefined;
  const transport: HttpClient = { async request(request) {
    const notificationUrl = [...metadata.webhooks, ...notification.trustedUrls, ...relayUrls]
      .some(value => new URL(value).href === new URL(request.url).href);
    if (request.method !== 'GET' && !notificationUrl) await automaticGuard?.();
    return rawTransport.request(request);
  } };
  // Offline mode polls no feed: none is configured here, and offlineEgressRules below blocks a forgotten call site.
  const feedUrls = network.feedMode.offline ? [] : options.feeds?.map(feed => feed.url) ?? metadata.feedUrls;
  const notification = { rules: [] as import('../types.js').EgressRule[], trustedUrls: [] as string[] };
  for (const setting of metadata.settings.notify.channels) {
    try {
      const entries = await notificationEgress([setting], vault);
      notification.rules.push(...entries.rules); notification.trustedUrls.push(...entries.trustedUrls);
    } catch { log.warn('A notification channel needs its settings repaired. Run notify test or remove and add it again.'); }
  }
  notification.trustedUrls.forEach(url => redactor.register(url));
  const healthUrls: string[] = [];
  const savedArmed = await store.readJson<import('../types.js').ArmedPlan>('plan', join(paths.dir, 'armed-plan.json'));
  if (savedArmed) {
    const signer = await deviceKey(vault);
    try {
      const checked = verifyArmedPlan(savedArmed, { now: new Date(savedArmed.createdAt), trustedKeyIds: options.trustedPlanKeyIds ?? [signer.keyId] });
      if (checked.ok && checked.plan.projectId === projectId) healthUrls.push(...checked.plan.healthChecks.map(check => check.url));
    } finally { signer.privateKeyDer.fill(0); }
  }
  const relayUrls: string[] = [];
  if (metadata.settings.notify.relay) {
    const topic = await vault.get('notify/relay/topic');
    if (topic) {
      try {
        const value = topic.toString();
        if (!/^[A-Za-z0-9_-]{1,64}$/.test(value)) throw new CliError('The approval relay topic is invalid. Run watcher setup again.');
        redactor.register(value);
        relayUrls.push(`${metadata.settings.notify.relay.server.replace(/\/$/, '')}/${value}`);
      } finally { topic.fill(0); }
    }
  }
  const allRules = [...EGRESS_RULES, ...rulesForUserFeeds(feedUrls), ...rulesForUserUrls(metadata.webhooks, 'notification webhook you configured'),
    ...metadata.userHostRules, ...notification.rules, ...rulesForUserUrls(healthUrls, 'health check you configured'),
    ...rulesForUserUrls(relayUrls, 'approval relay you configured'),
    // Shown in `keysentry network`; the KMS and audit export clients also carry their own narrower rule lists.
    ...(metadata.settings.kms ? kmsEgressRules(metadata.settings.kms) : []),
    ...auditExportEgressRules(metadata.settings.audit.export)];
  // A team policy's network.allowHosts drops user-added destinations it does not list (notes/team-policy.md).
  const rules = restrictUserEgress(network.feedMode.offline ? offlineEgressRules(allRules) : allRules, teamPolicy);
  const http = createGuardedHttp(transport, { rules, receipt,
    trustedUrls: [...metadata.webhooks, ...notification.trustedUrls, ...relayUrls], log });
  const config = await loadConfig({ ...configOptions, vault, http, role: 'read', redactor, log });
  teamSettings = () => config.settings.team;
  try {
    const saved = await store.readJson('monitor', join(paths.dir, 'dashboard-settings.json'));
    if (saved !== null) {
      const result = dashboardSettingsSchema.safeParse(saved);
      if (!result.success) throw new CliError('Saved dashboard settings are invalid. Restore them before making changes.');
      config.rotation.graceMs = result.data.graceMinutes * 60000;
      config.settings.autopilot.graceMinutes = result.data.graceMinutes;
      config.settings.autopilot.showHints = result.data.showHints;
    }
  } catch (error) {
    // A read-only rescan can still rebuild observational inventory after key
    // loss. The unreadable preferences stay intact for later recovery/reset.
    if (!(error instanceof StateLockedError)) throw error;
  }
  // The policy's revocation rule and minimum grace also clamp a grace period saved from the dashboard.
  config.rotation = narrowRotationOptions(config.rotation, teamPolicy);
  // Review M1: "revoke now" at the grace prompt and finish --now keep old keys until the policy's minimum has passed.
  if (teamPolicy?.rotation.minGraceSeconds) config.rotation.minGraceMs = teamPolicy.rotation.minGraceSeconds * 1000;
  if (options.policy) config.monitor.policy = options.policy;
  // Review H2: under a team policy the monitor acts on its own only when the signed policy allows it. Applied after the
  // KEYSENTRY_AUTO_* environment overrides, which loadConfig reads again.
  config.monitor.policy = narrowMonitorPolicy(config.monitor.policy, teamPolicy);
  if (!monitorAutomationAllowed(teamPolicy)) {
    config.settings.monitor.autoExecute = false; config.settings.monitor.autoContain = false;
    config.settings.monitor.revokeUnconfirmedOnHighConfidence = false;
  }
  /** Inside the policy's autopilot limits (hosts, providers, tiers); other clusters' automatic actions wait for approval. */
  const automaticAllowed = (inv: Inventory) => teamPolicy ? (clusterId: string) => {
    const cluster = inv.clusters.find(candidate => candidate.id === clusterId);
    return cluster !== undefined && autopilotRefusal({ provider: cluster.provider, hosts: [...new Set(cluster.consumers.map(consumer => consumer.service.host))] }, teamPolicy) === null;
  } : undefined;
  if (options.feeds) config.monitor.feeds = options.feeds;
  // Offline mode: the legacy monitor detector would otherwise fall back to DEFAULT_BREACH_FEEDS.
  if (network.feedMode.offline) config.monitor.feeds = [];
  const providers = options.providers ?? getProvider;
  const stateStore = createFileMonitorStateStore(config.cwd, store);
  const visibleChannelIds = new Set(metadata.settings.notify.channels.map(channel => channel.id));

  /** Project typed metadata before persistence; never serialize a raw adapter response. */
  function safe<T>(value: T): T {
    function visit(input: unknown): unknown {
      if (typeof input === 'string') return redactor.redact(input);
      if (Array.isArray(input)) return input.map(visit);
      if (input && typeof input === 'object') return Object.fromEntries(Object.entries(input).map(([key, item]) => [redactor.redact(key), visit(item)]));
      return input;
    }
    return visit(value) as T;
  }

  // Bind rather than spread: adapters may keep methods on their prototype (including test fakes).
  const wrapHosts = (adapters: HostAdapter[]) => adapters.map((host): HostAdapter => ({
    id: host.id, capabilities: host.capabilities,
    listServices: () => host.listServices(),
    async readVariables(service) {
      const vars = await host.readVariables(service);
      for (const variable of vars) if (variable.value && classify(variable.name, variable.value).isSecret) redactor.register(variable.value);
      return vars;
    },
    async writeVariables(service, vars, opts) {
      await automaticGuard?.();
      for (const value of Object.values(vars)) redactor.register(value);
      await host.writeVariables(service, vars, opts);
    },
    async redeploy(service) { await automaticGuard?.(); return host.redeploy(service); },
    deploymentStatus: (service, id) => host.deploymentStatus(service, id),
    ...(host.activationFor ? { activationFor: (service: ServiceRef) => host.activationFor!(service) } : {}),
  }));
  const hosts = wrapHosts(options.hosts ?? config.hosts);
  config.hosts = hosts;
  if (options.hosts) config.disabledHosts = [];
  const hostMap = Object.fromEntries(hosts.map(host => [host.id, host])) as Partial<Record<HostId, HostAdapter>>;
  const providerList = () => (Object.keys(PROVIDER_CREDENTIALS) as ProviderId[]).map(providers);
  const grace = options.grace ?? (info => promptGrace(info, diagnostic, options.promptIO, options.now));
  async function refreshConnections(): Promise<void> {
    const fresh = await loadConfig({ ...configOptions, vault, http, role: 'read', redactor, log });
    config.providerCtx = fresh.providerCtx;
    if (!options.hosts) {
      config.hosts = fresh.hosts; config.disabledHosts = fresh.disabledHosts;
      hosts.splice(0, hosts.length, ...wrapHosts(fresh.hosts));
      for (const id of Object.keys(hostMap) as HostId[]) delete hostMap[id];
      for (const host of hosts) hostMap[host.id] = host;
    }
  }

  /** Write credentials are fetched only after the calling operation's human gate. */
  async function adapters(role: TokenRole) {
    if (role === 'read') return { hosts, hostMap, providerCtx: config.providerCtx };
    const writeConfig = await loadConfig({ ...configOptions, vault, http, role, redactor, log });
    const selected = wrapHosts(options.hosts ?? writeConfig.hosts);
    return { hosts: selected, hostMap: Object.fromEntries(selected.map(host => [host.id, host])) as Partial<Record<HostId, HostAdapter>>,
      providerCtx: writeConfig.providerCtx };
  }

  let rotationVaultWarningShown = false;
  let developmentWarningShown = false;
  let missingManifestAccepted = false;
  async function prepareExecution(write: (text: string) => void = diagnostic, developmentAlreadyReported = false) {
    // Team governance first: an untrusted roster, an invalid policy or an unmet policy requirement stops every change.
    await assertGovernance();
    developmentWarningShown ||= developmentAlreadyReported;
    if (!rotationVaultWarningShown && (vault.backend === 'env' || vault.backend === 'memory')) {
      write(MEMORY_ONLY_ROTATION_WARNING); rotationVaultWarningShown = true;
    }
    const integrity = await checkLocalIntegrity();
    if (integrity.status === 'mismatch') throw new CliError('The local installation check did not match. Reinstall keysentry before rotating keys.');
    if (integrity.status === 'dev' && !developmentWarningShown) {
      write('Development copy: release integrity has not been checked.'); developmentWarningShown = true;
    }
    if (integrity.status === 'missing-manifest' && !missingManifestAccepted) {
      write('This installation has no release manifest. Its local integrity could not be checked.');
      if (!interactive || !await (options.confirmMissingManifest ?? (() => confirmMissingManifest(write, options.promptIO)))()) {
        throw new CliError('Execution cancelled because the release manifest is missing. Type yes at the confirmation to continue.');
      }
      missingManifestAccepted = true;
    }
  }

  async function scan(allowReplacement = false): Promise<Inventory> {
    await refreshConnections();
    let previousInventory: Inventory | null = null;
    let monitorState: MonitorState | undefined;
    let inventoryLocked = false; let monitorLocked = false;
    try { previousInventory = await store.loadInventory(); }
    catch (error) { if (!(error instanceof StateLockedError)) throw error; inventoryLocked = true; }
    try { monitorState = await stateStore.load(); }
    catch (error) { if (!(error instanceof StateLockedError)) throw error; monitorLocked = true; }
    if (inventoryLocked || monitorLocked) {
      if (!allowReplacement || !interactive) throw new CliError('keysentry can\'t read the saved inventory on this computer. Run "keysentry state reset" in an interactive terminal to start over.');
      const auditCheck = await audit.verify();
      if (!auditCheck.ok) throw new CliError('The saved audit log cannot be authenticated. Restore its matching vault audit key before replacing saved state.');
      if (!await (options.confirmInventoryReplacement ?? (() => confirmInventoryReplacement(diagnostic, options.promptIO)))()) {
        throw new CliError('Fresh scan cancelled. Saved state was kept.');
      }
      monitorState ??= createMonitorState();
    }
    const inventory = await scanHosts(hosts, fingerprintKey, log);
    if (!options.hosts) inventory.errors.push(...config.disabledHosts.map(item => ({ host: item.host, message: item.reason })));
    // Retain only fingerprint metadata for unavailable hosts. Dropping a known
    // consumer would let a later partial scan understate a shared key's scope.
    const failedHosts = new Set(inventory.errors.map(error => error.host));
    if (failedHosts.size) {
      const previous = inventorySchema.safeParse(previousInventory);
      if (previous.success) {
        const consumerKey = (consumer: Inventory['findings'][number] | Inventory['clusters'][number]['consumers'][number]) => `${serviceKey(consumer.service)}\0${consumer.varName}`;
        const services = new Set(inventory.services.map(serviceKey));
        for (const service of previous.data.services) if (failedHosts.has(service.host) && !services.has(serviceKey(service))) {
          inventory.services.push(service); services.add(serviceKey(service));
        }
        const findings = new Set(inventory.findings.map(consumerKey));
        const scannedLocations = new Set(findings);
        for (const finding of previous.data.findings) if (failedHosts.has(finding.service.host) && !findings.has(consumerKey(finding))) {
          inventory.findings.push(finding); findings.add(consumerKey(finding));
        }
        const clusters = new Map(inventory.clusters.map(cluster => [cluster.id, cluster]));
        for (const old of previous.data.clusters) {
          const missing = old.consumers.filter(consumer => failedHosts.has(consumer.service.host) && !scannedLocations.has(consumerKey(consumer)));
          if (!missing.length) continue;
          const current = clusters.get(old.id);
          if (!current) {
            const retained = { ...old, consumers: missing };
            inventory.clusters.push(retained); clusters.set(retained.id, retained);
          } else {
            const present = new Set(current.consumers.map(consumerKey));
            for (const consumer of missing) if (!present.has(consumerKey(consumer))) {
              current.consumers.push(consumer); present.add(consumerKey(consumer));
            }
          }
        }
      }
    }
    const state = monitorState!;
    // Decoys are monitored separately. Never rotate one into a fully privileged production key.
    const decoys = new Set(state.canaries.map(canary => `${serviceKey(canary.service)}\0${canary.varName}`));
    const realConsumer = (consumer: Inventory['findings'][number] | Inventory['clusters'][number]['consumers'][number]) => !decoys.has(`${serviceKey(consumer.service)}\0${consumer.varName}`);
    inventory.findings = inventory.findings.filter(realConsumer);
    inventory.clusters = inventory.clusters.map(cluster => ({ ...cluster, consumers: cluster.consumers.filter(realConsumer) })).filter(cluster => cluster.consumers.length > 0);
    const clean = safe(inventorySchema.parse(inventory));
    remember(clean.services);
    if (monitorLocked) await store.writeJson('monitor', paths.monitor, state, { replaceUndecryptable: true });
    if (inventoryLocked) await store.writeJson('inventory', paths.inventory, clean, { replaceUndecryptable: true });
    else await store.saveInventory(clean);
    const hygieneStore = createHygieneStateStore(store);
    let hygiene; let hygieneLocked = false;
    try { hygiene = await hygieneStore.load(); }
    catch (error) {
      if (!(error instanceof StateLockedError) || !(inventoryLocked || monitorLocked)) throw error;
      // The confirmed rebuild above applies to observational state only. Never
      // replace plans, journals or recovery values when their keys are missing.
      hygiene = createHygieneState(); hygieneLocked = true;
    }
    updateFirstSeen(hygiene, clean, (options.now ?? (() => new Date()))());
    try { updateLastRotation(hygiene, await journal.read()); }
    catch (error) { if (!(error instanceof StateLockedError)) throw error; }
    if (hygieneLocked) await store.writeJson('monitor', join(paths.dir, 'hygiene.json'), hygiene, { replaceUndecryptable: true });
    else await hygieneStore.save(hygiene);
    await audit.append({ kind: 'scan', summary: 'Scan saved.', data: { hosts: clean.hosts.length, services: clean.services.length, clusters: clean.clusters.length, errors: clean.errors.length } });
    return clean;
  }

  async function inventory(): Promise<Inventory> {
    const stored = await store.loadInventory();
    if (!stored) return scan();
    const result = inventorySchema.safeParse(stored);
    if (!result.success) throw new CliError('Invalid inventory file; run scan to rebuild it.');
    remember(result.data.services);
    return safe(result.data);
  }

  async function plan(filters?: PlanFilters, opts: { preview?: boolean } = {}): Promise<RotationPlan> {
    const result = buildPlan(await inventory(), filters);
    await store.writeJson('plan', join(paths.plans, `${result.id}.json`), safe(result));
    if (!opts.preview) await audit.append({ kind: 'plan-saved', summary: 'Rotation plan saved.', data: { id: result.id, steps: result.steps.length } });
    return result;
  }

  async function loadPlan(id: string): Promise<RotationPlan> {
    if (!planIdSchema.safeParse(id).success) throw new CliError('Invalid plan identifier.');
    let stored = await store.readJson('plan', join(paths.plans, `${id}.json`));
    if (stored === null) stored = (await autopilotManager().loadState()).waves.find(wave => wave.planId === id)?.plan ?? null;
    const result = planSchema.safeParse(stored);
    if (!result.success) throw new CliError('Saved plan is missing or invalid; create a new plan.');
    remember(result.data.services);
    return safe(result.data);
  }

  async function execute(rotationPlan: RotationPlan, inv: Inventory, opts: ExecutionOptions, inheritInteraction = true): Promise<RotationReport> {
    // A team policy clamps per-run choices too, e.g. rotate --revoke immediately under revoke: after-deploy.
    opts = narrowRotationOptions(opts, teamPolicy);
    const selected = await adapters(opts.execute === true ? 'write' : 'read');
    remember(rotationPlan.services);
    if (opts.execute === true) assertPlanScan(rotationPlan, inv);
    if (opts.execute === true && !await store.readJson('plan', join(paths.plans, `${rotationPlan.id}.json`))) {
      await store.writeJson('plan', join(paths.plans, `${rotationPlan.id}.json`), safe(rotationPlan));
      await audit.append({ kind: 'plan-saved', summary: 'Rotation plan saved.', data: { id: rotationPlan.id, steps: rotationPlan.steps.length } });
    }
    let aborted: RotationAbortedError | undefined;
    const prompt = opts.prompt ?? (inheritInteraction ? options.prompt : undefined) ?? (async () => null);
    const reveal = Object.hasOwn(opts, 'reveal') ? opts.reveal : inheritInteraction ? options.reveal : undefined;
    const ensureActive = () => { if (aborted) throw aborted; };
    const preserveAbort = async <T>(operation: () => Promise<T>, recovery = false): Promise<T> => {
      if (!recovery) ensureActive();
      try { return await operation(); }
      catch (error) { if (error instanceof RotationAbortedError) aborted = error; throw error; }
    };
    // Cancellation stops new provider mutations. Delivery, reveal offers and
    // deployment of values already created must finish even after cancellation.
    const guardMutations = <T extends object>(adapter: T, mutations: string[]): T => new Proxy(adapter, {
      get(target, property) {
        const member: unknown = Reflect.get(target, property, target);
        if (typeof member !== 'function') return member;
        return (...args: unknown[]) => {
          if (typeof property === 'string' && mutations.includes(property)) return (async () => {
            await automaticGuard?.(); ensureActive(); return Reflect.apply(member, target, args);
          })();
          return Reflect.apply(member, target, args);
        };
      },
    });
    // A preview never writes the engine's lifecycle to the real rotation journal.
    const previewJournal = { read: async () => [], append: async () => {} };
    const report = await executePlan(rotationPlan, inv, {
      hosts: selected.hostMap, providers: id => guardMutations(providers(id), ['rotate', 'revoke', 'cap']), providerCtx: selected.providerCtx,
      journal: opts.execute === true ? journal : previewJournal,
      prompt: p => preserveAbort(() => prompt(p)), fingerprintKey, redactor, log,
      sleep: options.sleep, now: options.now,
      inflight, crashHook: options.crashHook, grace: dashboardAuthorized() ? async () => 'defer' : inheritInteraction && interactive ? grace : undefined,
      reveal: reveal ? (info, value) => preserveAbort(() => reveal(info, value), true) : undefined,
    }, { ...config.rotation, dryRun: opts.execute !== true,
      ...(opts.revoke ? { revoke: opts.revoke } : {}), ...(opts.redeploy !== undefined ? { redeploy: opts.redeploy } : {}),
      ...(opts.revokeUnconfirmed !== undefined ? { revokeUnconfirmed: opts.revokeUnconfirmed } : {}),
      ...(opts.acceptUnplannedSealed !== undefined ? { acceptUnplannedSealed: opts.acceptUnplannedSealed } : {}),
      ...(opts.allowGenerate !== undefined ? { allowGenerate: opts.allowGenerate } : {}),
      ...(opts.verifyRetries !== undefined ? { verifyRetries: opts.verifyRetries } : {}),
    });
    await saveRotationReport(report);
    if (report.dryRun) await audit.append({ kind: 'previewed', summary: 'Rotation plan previewed.', data: { planId: report.planId } });
    if (aborted) throw new RotationInterruptedError(safe(report));
    return report;
  }

  async function saveRotationReport(report: RotationReport) {
    if (!planIdSchema.safeParse(report.planId).success) throw new CliError('Invalid plan identifier.');
    // Reopening a saved executing plan without --execute is still a preview.
    // Preserve its real progress even when the preview uses the same plan id.
    if (report.dryRun && (await rotationReport(report.planId))?.dryRun === false) return;
    await store.writeJson('report', join(paths.dir, 'reports', `${report.planId}.json`), safe(report));
    // Keep the last real report for upgrades and existing integrations. Previews
    // and drills cannot replace this pointer to a real rotation.
    if (!report.dryRun) await store.writeJson('report', join(paths.dir, 'rotation-report.json'), safe(report));
  }

  async function rotationReport(planId?: string): Promise<RotationReport | null> {
    if (planId !== undefined) {
      if (!planIdSchema.safeParse(planId).success) throw new CliError('Invalid plan identifier.');
      const report = await store.readJson<RotationReport>('report', join(paths.dir, 'reports', `${planId}.json`));
      if (report) return report;
    }
    const legacy = await store.readJson<RotationReport>('report', join(paths.dir, 'rotation-report.json'));
    return legacy && !legacy.dryRun && (planId === undefined || legacy.planId === planId) ? legacy : null;
  }

  async function rotate(rotationPlan: RotationPlan, opts: ExecutionOptions = {}): Promise<RotationReport> {
    if (opts.execute === true) { assertHuman('rotate keys'); await prepareExecution(); await requireTeamGrant('dashboard:rotate/execute'); }
    const inv = await inventory();
    let interrupted: RotationInterruptedError | undefined;
    let report: RotationReport;
    try { report = await execute(rotationPlan, inv, opts); }
    catch (error) {
      if (!(error instanceof RotationInterruptedError)) throw error;
      interrupted = error;
      report = error.report;
    }
    if (!report.dryRun) {
      await rememberKeyRefs(report, rotationPlan);
      await scan();
      await refreshManualAdoption(report);
    }
    if (interrupted) throw interrupted;
    return safe(report);
  }

  async function rememberKeyRefs(report: RotationReport, rotationPlan: RotationPlan) {
    const state = await stateStore.load();
    for (const step of report.steps) if (step.newFingerprint && step.newKeyRef && ['written', 'deployed', 'verified', 'revoked'].includes(step.status)) {
      state.keyRefs[step.newFingerprint] = step.newKeyRef;
      delete state.keyRefs[step.clusterId];
      if (rotationPlan.steps.find(item => item.clusterId === step.clusterId)?.consumers.some(consumer => consumer.fingerprint === null)) {
        state.keyRefs[step.clusterId] = step.newKeyRef;
      }
    }
    await stateStore.save(state);
  }

  function autopilotManager(overrides: Partial<Pick<AutopilotManagerOptions, 'confirmAdoption' | 'emitEligibility' | 'relayDisarm' | 'relayResume' | 'selfCheck' | 'lastNotificationSuccess' | 'assertActive'>> = {}) {
    return createAutopilotManager({ store, audit, projectId, deviceKey: () => deviceKey(vault), assertHuman,
      teamPolicy: () => teamPolicy, assertChanges: async () => { await assertGovernance(); await requireTeamGrant('dashboard:autopilot/arm'); },
      // On the team dashboard arming runs under a met admin quorum (approvals.wideningAdmins admins approved it).
      wideningApproved: () => dashboardContext.getStore()?.grant?.kind === 'dashboard:autopilot/arm',
      scan: async () => rotationInventory(await scan()), rotateCluster: async clusterId => rotate(await plan({ clusterIds: [clusterId] }), {
        execute: true, prompt: options.prompt ?? (p => promptSecret(p, diagnostic, options.promptIO)),
      }),
      settings: config.settings.autopilot, env, now: options.now, ...overrides });
  }

  function rotationInventory(inv: Inventory): Inventory {
    return { ...inv, errors: inv.errors.filter(error => !config.disabledHosts.some(item => item.host === error.host && item.reason === error.message)
      || inv.services.some(service => service.host === error.host)
      || inv.clusters.some(cluster => cluster.consumers.some(consumer => consumer.service.host === error.host))) };
  }

  async function refreshManualAdoption(report: RotationReport) {
    const manager = autopilotManager(); const armed = await manager.loadPlan();
    if (!armed) return;
    const state = await manager.loadState();
    if (reconcileAutopilotRecovery(state, { planId: report.planId, report })) await manager.saveState(state);
    const key = await deviceKey(vault);
    try {
      await persistManualAdoption({ report, armed, state, inventory: rotationInventory(await inventory()), trustedKeyIds: [key.keyId],
        now: (options.now ?? (() => new Date()))(), entries: await journal.read(), saveState: manager.saveState,
        applyUpdates: manager.applyAdoptionUpdates });
    } finally { key.privateKeyDer.fill(0); }
  }

  function detector(inv: Inventory, state: MonitorState, selected = { hosts, providerCtx: config.providerCtx }): DetectorContext {
    // Detection uses read credentials. A provider-side automatic containment fetches
    // write credentials only when that action is actually called.
    const list = providerList().map(provider => new Proxy(provider, {
      get(target, property) {
        const member: unknown = Reflect.get(target, property, target);
        if (typeof member !== 'function') return member;
        if (!['cap', 'revoke', 'rotate'].includes(String(property))) return member.bind(target);
        return async (value: string, ctx: typeof config.providerCtx) => {
          await automaticGuard?.();
          const write = await adapters('write');
          await automaticGuard?.();
          return Reflect.apply(member, target, [value, { ...ctx, ...write.providerCtx, siblingVars: ctx.siblingVars }]);
        };
      },
    }));
    return { inventory: inv, hosts: selected.hosts, providers: list, providerCtx: selected.providerCtx, state, fingerprintKey, log, clock: options.now };
  }

  function assertPlanScan(rotationPlan: RotationPlan, inv: Inventory): void {
    const failed = new Set(inv.errors.map(error => error.host));
    if (!failed.size) return;
    const selected = new Set(rotationPlan.steps.map(step => step.clusterId));
    const consumers = [...rotationPlan.steps.flatMap(step => step.consumers), ...inv.clusters.filter(cluster => selected.has(cluster.id)).flatMap(cluster => cluster.consumers)];
    if (consumers.some(consumer => failed.has(consumer.service.host))) {
      throw new CliError('Host scans failed for consumers in this plan; execution is blocked. Run scan successfully before retrying.');
    }
    log.warn('Host scans failed outside this plan; proceeding with unaffected consumers. Unscanned copies may exist.');
  }

  async function monitored(rotationPlan: RotationPlan, inv: Inventory, opts: Parameters<RotateExecutor>[1], interaction: Pick<ExecutionOptions, 'prompt' | 'reveal'> = {}, humanInteraction = false): Promise<RotationReport> {
    const report = await execute(rotationPlan, inv, { execute: true,
      revoke: 'after-deploy', redeploy: true, acceptUnplannedSealed: false,
      revokeUnconfirmed: opts.revokeUnconfirmed, allowGenerate: false, ...interaction,
    }, humanInteraction);
    // Engine 'deployed' means new-key verification, all writes and activation succeeded,
    // while monitor's completion contract accepts 'verified'/'revoked'. Preserve the
    // exact engine report on disk and every warning about manual old-key revocation.
    return { ...report, steps: report.steps.map(step => step.status === 'deployed' ? { ...step, status: 'verified' as const } : step) };
  }

  async function monitorOnce() {
    if (config.monitor.policy.autoExecute || config.monitor.policy.autoContain) { assertHuman('run automatic monitor actions'); await prepareExecution(); }
    const inv = await scan();
    if (inv.errors.length) log.warn('Host scans failed or are disabled; monitoring continues on partial inventory. Clusters on unavailable hosts require remediation.');
    const ctx = { ...detector(inv, await stateStore.load()), state: stateStore as MonitorStateStore,
      ...config.monitor, policy: config.monitor.policy, notifier: config.monitor.notifier,
      rotate: (rotationPlan: RotationPlan, opts: Parameters<RotateExecutor>[1]) => monitored(rotationPlan, inv, opts),
      automaticAllowed: automaticAllowed(inv),
    };
    const result = await runMonitorOnce(ctx);
    return safe(result);
  }

  async function monitor(signal: AbortSignal, intervalMs = config.monitor.intervalMs, onPoll?: (result: Awaited<ReturnType<typeof monitorOnce>>) => void) {
    while (!signal.aborted) {
      try { const result = await checkpointAfter(monitorOnce); onPoll?.(result); } catch { log.error('Monitor poll failed; inspect configuration and state.'); }
      if (signal.aborted) break;
      await new Promise<void>(done => {
        const finish = () => { clearTimeout(timer); signal.removeEventListener('abort', finish); done(); };
        const timer = setTimeout(finish, intervalMs);
        signal.addEventListener('abort', finish, { once: true });
        if (signal.aborted) finish();
      });
    }
  }

  async function actionContext(interaction: Pick<ExecutionOptions, 'prompt' | 'reveal'> = {}, interactive = false, write = false) {
    const inv = await inventory();
    const state = await stateStore.load();
    const selected = write ? await adapters('write') : { hosts, providerCtx: config.providerCtx };
    return { ...detector(inv, state, selected), policy: config.monitor.policy, notifier: config.monitor.notifier, interactive,
      rotate: (rotationPlan: RotationPlan, opts: Parameters<RotateExecutor>[1]) => monitored(rotationPlan, inv, opts, interaction, interactive),
      saveState: () => stateStore.save(state),
    };
  }

  function manualActivation(service: ServiceRef): boolean {
    const host = hostMap[service.host];
    return !host || needsManualActivation(service, host);
  }

  function describeAction(id: string, inv: Inventory, state: MonitorState) {
    const action = state.pendingActions.find(action => action.id === id && action.status === 'pending');
    if (!action) throw new CliError('No pending monitor action with this identifier.');
    const selected = buildPlan(inv, { clusterIds: action.clusterIds });
    const rotation = action.action === 'rotate' || action.action === 'breach-mode';
    const details = {
      requiresInteractive: action.requiresInteractive === true || rotation && selected.steps.some(step => step.method === 'atomic-roll'),
      revokeUnconfirmed: rotation && action.revokeUnconfirmed === true && config.monitor.policy.revokeUnconfirmedOnHighConfidence,
      manualRestarts: rotation ? selected.services.filter(manualActivation) : [],
    };
    // Bind confirmation to stable plan content, excluding its fresh id/timestamp.
    const reviewHash = createHash('sha256').update(JSON.stringify({ action, steps: selected.steps, services: selected.services, ...details })).digest('hex');
    return safe({ action, plan: selected, ...details, reviewHash });
  }

  async function reviewAction(id: string) {
    return describeAction(id, await inventory(), await stateStore.load());
  }

  /** Approval requests for team dashboard changes, with the quorum read from the verified roster and policy here. */
  function teamApprovalService() {
    const quorum = stateQuorum({ store, cwd: metadata.cwd, policyFile: () => config.settings.team.policyFile, anchors });
    return createApprovalService({ store, audit, credentials: async () => [], deviceKeys: async () => [], rpId: 'localhost', origins: ['http://localhost'],
      now: options.now, requestTtlMs: TEAM_DASHBOARD_REQUEST_TTL_MS, quorum });
  }

  /**
   * Review C1: on the team dashboard a change runs only under an approved team request of its own kind
   * (`dashboard:<route>`). Each runtime entry point checks that here, against the current roster and policy, so no route
   * or caller can skip the quorum. Outside the team dashboard (terminal, local dashboard, watcher) it does nothing.
   */
  async function requireTeamGrant(kind: string): Promise<void> {
    const context = dashboardContext.getStore();
    if (!context?.memberId) return;
    const grant = context.grant;
    const refused = 'This change needs the team\'s approvals first. Team members approve it on the team dashboard\'s Approvals screen.';
    if (!grant || grant.kind !== kind || sealedTeam) throw new CliError(refused);
    const service = teamApprovalService();
    try {
      const entry = (await service.approved()).find(item => item.action.id === grant.actionId && item.request.digest === grant.digest);
      if (!entry || entry.action.kind !== kind) throw new CliError(refused);
      await service.checkGrant(grant.actionId, grant.digest);
    } catch (error) {
      if (error instanceof ApprovalError) throw new CliError(error.message);
      throw error;
    }
  }

  /** Team mode: the met quorum for this reviewed monitor action, or a refusal. Null without a team. */
  async function monitorTeamGrant(id: string, clusterIds: string[], reviewHash: string): Promise<{ markExecuted(): Promise<void> } | null> {
    if (sealedTeam) return null;
    const quorum = stateQuorum({ store, cwd: metadata.cwd, policyFile: () => config.settings.team.policyFile, anchors });
    try { if (await quorum.team() === null) return null; }
    catch { throw new CliError('The team roster or policy could not be verified, so approvals are paused.'); }
    const service = createApprovalService({ store, audit, credentials: async () => [], deviceKeys: async () => [], rpId: 'localhost', origins: ['http://localhost'],
      now: options.now, quorum });
    const digest = actionDigest({ id, kind: 'monitor', clusterIds: [...clusterIds], planHash: reviewHash });
    if (!(await service.approved()).some(entry => entry.action.id === id && entry.request.digest === digest)) {
      throw new CliError('This action needs the team\'s approvals first. Approve it with keysentry approve <id> or on the team dashboard.');
    }
    return { markExecuted: () => service.markExecuted(id, digest) };
  }

  async function approveAction(id: string, opts: ApprovalOptions = {}) {
    assertHuman('approve a key change');
    await prepareExecution();
    const interactive = opts.interactive ?? hasInteractiveTerminal();
    const diagnostic = (text: string) => process.stderr.write(`${redactor.redact(humanize(text))}\n`);
    const interaction = interactive ? {
      prompt: opts.prompt ?? options.prompt ?? ((p: GuidedPrompt) => promptSecret(p, diagnostic)),
      reveal: opts.reveal ?? options.reveal ?? ((info: RevealInfo, value: string) => revealSecret(info, value, diagnostic)),
    } : {};
    const ctx = await actionContext(interaction, interactive, true);
    const review = describeAction(id, ctx.inventory, ctx.state);
    if (opts.reviewHash !== undefined && opts.reviewHash !== review.reviewHash) throw new CliError('Pending action changed after review; inspect it and approve again.');
    if (review.requiresInteractive && !interactive) throw new CliError('This action requires an interactive terminal for atomic-roll recovery. Run keysentry approve <id> in a terminal; --yes only skips confirmation.');
    // Team mode: the action runs only with a met quorum for exactly this review (recorded by keysentry approve or the
    // team dashboard, src/cli/team-approvals.ts). Checked here too, so no caller can run it on one approval.
    const teamGrant = await monitorTeamGrant(id, review.action.clusterIds, review.reviewHash);
    // Monitor integrations may translate executor errors into a failed action. Preserve
    // explicit operator cancellation so the CLI always reports a whole-run abort.
    let aborted: RotationAbortedError | undefined;
    const rotate = ctx.rotate;
    ctx.rotate = async (plan, options) => {
      try { return await rotate(plan, options); }
      catch (error) { if (error instanceof RotationAbortedError) aborted = error; throw error; }
    };
    const result = await approve(id, ctx);
    await teamGrant?.markExecuted().catch(() => log.warn('The team approval could not be marked as used. It expires on its own.'));
    await audit.append({ kind: 'approval', summary: 'Monitor action approved.', data: { id } });
    if (aborted) throw aborted;
    await scan();
    if (result) await refreshManualAdoption(result);
    return safe(result);
  }

  async function plant(opts: { host: HostId; service: string; varName?: string; execute?: boolean }) {
    if (opts.execute) { assertHuman('create a canary'); await prepareExecution(); await requireTeamGrant('dashboard:canary'); }
    const selected = await adapters(opts.execute ? 'write' : 'read');
    const host = selected.hostMap[opts.host];
    if (!host) throw new CliError('Requested host is not enabled.');
    const services = (await host.listServices()).filter(service => [serviceKey(service), serviceLabel(service), service.serviceId, service.serviceName].includes(opts.service));
    if (services.length !== 1) throw new CliError('Service must identify exactly one service; use its full project/service label from scan.');
    const inv = await inventory();
    await host.readVariables(services[0]!);
    if (JSON.stringify(safe(services[0])) !== JSON.stringify(services[0]) || opts.varName && safe(opts.varName) !== opts.varName) {
      throw new CliError('Canary destination metadata contains credential-like text; choose a safe service and variable name.');
    }
    const state = await stateStore.load();
    const result = await createCanary({ provider: 'openrouter', host, service: services[0]!, varName: opts.varName, dryRun: opts.execute !== true }, detector(inv, state, selected));
    if (result) await stateStore.save(state);
    return safe(result);
  }

  async function readiness() {
    const start = performance.now();
    const inv = await scan();
    const rotationPlan = await plan();
    const report = await execute(rotationPlan, inv, { execute: false });
    await recordDrill(store, { at: (options.now ?? (() => new Date()))(),
      passed: rotationInventory(inv).errors.length === 0 && report.steps.every(step => step.status !== 'failed') && report.deployments.every(deploy => deploy.state !== 'failed') });
    const canaries = (await stateStore.load()).canaries.length;
    return safe({ ...readinessScore({ inventory: inv, canaries,
      configuredCredentials: Object.keys(config.providerCtx.credentials).filter(name => !!config.providerCtx.credentials[name]),
      redeploy: Object.fromEntries(hosts.map(host => [host.id, host.capabilities.redeploy])), manualActivation }),
      elapsedMs: Math.round(performance.now() - start), report });
  }

  async function recoveryInput(id?: string) {
    const entries = await journal.read();
    if (!id) {
      const candidates = [...new Set(entries.filter(entry => entry.event === 'plan-start' || entry.event === 'resume').map(entry => entry.planId))].reverse();
      for (const candidate of candidates) {
        const own = entries.filter(entry => entry.planId === candidate);
        const last = own.filter(entry => entry.event === 'plan-end').at(-1);
        if (!last || last.data?.pending === true || last.data?.status === 'grace-pending'
          || last.data?.status === 'partial' && (await inflight.slots(candidate)).length) { id = candidate; break; }
      }
    }
    if (!id) throw new CliError('No saved plan has unfinished work.');
    const savedPlan = await loadPlan(id);
    const stored = await store.loadInventory();
    const inv = inventorySchema.safeParse(stored);
    if (!inv.success) throw new CliError('Saved inventory is missing or invalid; run scan before recovering this plan.');
    remember(inv.data.services);
    return { plan: savedPlan, inventory: inv.data, entries: entries.filter(entry => entry.planId === id) };
  }

  async function recoveryDeps(): Promise<EngineDeps> {
    const selected = await adapters('write');
    return { hosts: selected.hostMap, providers, providerCtx: selected.providerCtx, journal, fingerprintKey, redactor, log,
      prompt: options.prompt ?? (p => promptSecret(p, diagnostic, options.promptIO)), reveal: options.reveal,
      sleep: options.sleep, now: options.now, inflight, crashHook: options.crashHook,
      grace: dashboardAuthorized() ? async () => 'defer' : interactive ? grace : undefined };
  }

  async function recover(mode: 'resume' | 'finish', id?: string, now = false) {
    assertHuman(mode === 'resume' ? 'resume a rotation' : 'finish a rotation');
    await prepareExecution();
    await requireTeamGrant(mode === 'resume' ? 'dashboard:rotation/resume' : 'dashboard:rotation/finish');
    await scan();
    const input = await recoveryInput(id);
    const deps = await recoveryDeps();
    const opts = { ...config.rotation, dryRun: false, early: now };
    const report = mode === 'resume' ? await resumeRotation(input, deps, opts) : await finishRotation(input, deps, opts);
    await saveRotationReport(report);
    await rememberKeyRefs(report, input.plan);
    await scan();
    await refreshManualAdoption(report);
    return safe(report);
  }

  function credentialName(name: string, role: TokenRole) {
    if (!acceptedCredentialName(name)) throw new CliError('Unknown credential name. Run keysentry vault status for supported names.');
    if (role !== 'read' && role !== 'write') throw new CliError('Credential role must be read or write.');
    return credentialVaultName(name, role);
  }

  async function vaultList() {
    const names = new Set(await vault.list('cred/'));
    return VAULT_SET_NAMES.flatMap(name => (['read', 'write'] as const).filter(role => names.has(credentialVaultName(name, role))).map(role => ({ name, role })));
  }

  async function assertStateResetSafe(force = false) {
    let entries: Awaited<ReturnType<typeof journal.read>> = [];
    try { entries = await journal.read(); }
    catch (error) { if (!force) throw error; }
    const planIds = [...new Set(entries.map(entry => entry.planId))];
    for (const id of planIds) {
      const own = entries.filter(entry => entry.planId === id);
      const last = own.filter(entry => entry.event === 'plan-end').at(-1);
      const status = last?.data?.status;
      if (!force && (status === 'grace-pending' || (status === 'partial' || !last) && (await inflight.slots(id)).length)) {
        throw new CliError('A rotation still has in-flight values. Run keysentry finish or undo first, or use state reset --force.');
      }
    }
    return planIds;
  }

  async function resetState(force = false) {
    assertHuman('reset saved state'); await requireTeamGrant('dashboard:state/reset');
    const planIds = await assertStateResetSafe(force);
    const deleted: string[] = [];
    const files: string[] = [];
    const withinState = (path: string) => { const rel = relative(paths.dir, resolve(path)); return rel !== '' && rel !== '..' && !rel.startsWith(`..${sep}`) && !/^(?:[A-Za-z]:|[\\/])/.test(rel); };
    async function collectEncrypted(dir: string) {
      for (const entry of await readdir(dir, { withFileTypes: true })) {
        const path = join(dir, entry.name);
        if (!withinState(path) || entry.isSymbolicLink()) throw new CliError('Saved state contains a link outside its directory. Reset was stopped.');
        if (entry.isDirectory()) { if (entry.name === 'plans') await collectEncrypted(path); continue; }
        if (entry.name === 'audit.jsonl' || entry.name === 'network.jsonl' || entry.name === 'network.jsonl.1') continue;
        if (/\.(?:json|jsonl|enc)$/.test(entry.name) && (await readFile(path, 'utf8')).startsWith('keysentry-encrypted:v1\n')) {
          files.push(path);
        }
      }
    }
    const stateInfo = await lstat(paths.dir);
    if (stateInfo.isSymbolicLink()) throw new CliError('The state directory is a link. Reset was stopped.');
    await collectEncrypted(paths.dir);
    const inflightDir = join(paths.dir, 'inflight');
    if (!withinState(inflightDir)) throw new CliError('Invalid in-flight directory.');
    try {
      if ((await lstat(inflightDir)).isSymbolicLink()) throw new CliError('The in-flight directory is a link. Reset was stopped.');
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    // All path checks finish before any recovery key is destroyed.
    for (const id of planIds) await inflight.shred(id);
    for (const name of await vault.list(`project/${projectId}/inflight/`)) await vault.delete(name);
    // The team roster and policy state files are removed below; their checkpoints go too, or the next run would refuse.
    if (vault.backend !== 'env') for (const name of [`project/${projectId}/team/roster-head`, `project/${projectId}/team/policy-head`]) await vault.delete(name);
    for (const path of files) { await rm(path); deleted.push(relative(paths.dir, path)); }
    await rm(inflightDir, { recursive: true, force: true });
    await audit.append({ kind: 'state-reset', summary: 'Encrypted saved state reset.', data: { files: deleted.length, force } });
    return { reset: true, files: deleted.length };
  }

  async function checkpointAfter<T>(operation: () => Promise<T>): Promise<T> {
    try { return await operation(); } finally { await audit.checkpoint(); }
  }
  const command = <A extends unknown[], R>(operation: (...args: A) => Promise<R>) => (...args: A) => checkpointAfter(() => operation(...args));

  return {
    config, paths, redactor, providers, safe, humanize, vault, store, inflight, audit, credentials, http, receipt, rules, userDir, interactive, assertHuman, mutationContext, assertStateResetSafe, prepareExecution,
    dashboardAction, asMember, requireTeamGrant, teamApprovalService, dashboardMember: () => dashboardContext.getStore()?.memberId, refreshConnections, firstRunGit: options.firstRunGit, now: options.now ?? (() => new Date()),
    providerContext: async (role: TokenRole) => { if (role === 'read') await refreshConnections(); return (await adapters(role)).providerCtx; },
    dashboardDisarm: command(() => createAutopilotManager({ store, audit, projectId, deviceKey: () => deviceKey(vault),
      scan: async () => rotationInventory(await scan()), rotateCluster: async () => { throw new CliError('Disarm cannot rotate keys.'); },
      assertHuman: () => {}, env, now: options.now }).disarm()),
    projectId, log, fingerprintKey, autopilotManager, signingKey: () => deviceKey(vault), recoveryDeps,
    httpForUrls: (urls: string[], purpose: string) => createGuardedHttp(transport, {
      rules: restrictUserEgress([...rules, ...rulesForUserUrls(urls, purpose)], teamPolicy), receipt, log,
      trustedUrls: [...metadata.webhooks, ...notification.trustedUrls, ...relayUrls],
    }),
    /**
     * A guarded client that reaches exactly one configured host and follows no redirect, over the raw (proxy-aware)
     * transport. Audit export gives each target its own, so a custom header can never be redirected elsewhere.
     */
    singleHostHttp: (url: string, purpose: string) => createGuardedHttp(rawTransport, {
      rules: restrictUserEgress(rulesForUserUrls([url], purpose, 'config'), teamPolicy), receipt, log, maxRedirects: 0,
    }),
    /** Team governance as loaded at start: roster, policy, narrowed settings and blockers. */
    governance, teamPolicy, teamAnchors: anchors, rawSettings, assertGovernance,
    /** The approval quorum from the verified roster and policy on this computer; null for a sealed watcher (its config carries them). */
    teamQuorum: () => sealedTeam ? null : stateQuorum({ store, cwd: metadata.cwd, policyFile: () => config.settings.team.policyFile, anchors }),
    /**
     * Notification settings to save: `channels` plus the channels keysentry.yaml lists but the team policy hides, so
     * editing channels in the narrowed view never deletes the hidden ones.
     */
    withHiddenChannels: (channels: NotifyChannelSettings[]): NotifyChannelSettings[] => [...channels,
      ...rawSettings.notify.channels.filter(channel => !visibleChannelIds.has(channel.id) && !channels.some(item => item.id === channel.id))],
    /** Proxy, extra CA and offline state (notes/network-enterprise.md); `transport` is only ever wrapped by a guard. */
    // `problem` is the fixed reason the transport refuses every request (watcher health); `ca` feeds syslog over TLS.
    network: { feedMode: network.feedMode, summary: network.summary, transport: rawTransport, problem: network.problem?.message ?? null,
      ca: network.ca },
    /** Reads the audit log's MAC key through the same vault view the audit log uses (audit export checks each entry). */
    auditMacKey: () => auditVault.get('audit/mac'),
    freshInventory: async () => rotationInventory(await scan()),
    async watcherMonitor(context: import('../watcher/index.js').WatcherActionContext, notifier: import('../types.js').Notifier,
      assertActive?: () => Promise<void>) {
      let policy = context.alertOnly ? { ...config.monitor.policy, autoExecute: false, autoContain: false } : config.monitor.policy;
      if (policy.autoExecute || policy.autoContain) {
        assertHumanForMutation({ env, stdinIsTTY: true, stdoutIsTTY: true, action: 'run automatic monitor actions' });
        await prepareExecution();
      }
      const scanned = await scan();
      try { await assertActive?.(); } catch { policy = { ...policy, autoExecute: false, autoContain: false }; }
      const excluded = new Set([...CREDENTIAL_NAMES, ...context.excludedTokenNames]);
      const own = (name: string) => excluded.has(name) || name.startsWith('KEYSENTRY_');
      const inv = { ...scanned, findings: scanned.findings.filter(item => !own(item.varName)),
        clusters: scanned.clusters.filter(cluster => !cluster.consumers.some(consumer => own(consumer.varName))) };
      const state = await stateStore.load();
      // The incident pipeline owns breach corroboration. Legacy feeds have no source kind.
      const previous = automaticGuard; automaticGuard = assertActive;
      try {
        return await runMonitorOnce({ ...detector(inv, state), ...config.monitor, feeds: [], policy, state: stateStore, notifier,
          rotate: (rotationPlan, rotationOptions) => monitored(rotationPlan, inv, rotationOptions), automaticAllowed: automaticAllowed(inv) });
      } finally { automaticGuard = previous; }
    },
    async monitorReadOnly(notifier?: import('../types.js').Notifier) {
      const inv = await scan(); const state = await stateStore.load();
      const readPolicy = { ...config.monitor.policy, autoExecute: false, autoContain: false };
      return runMonitorOnce({ ...detector(inv, state), policy: readPolicy, state: stateStore,
        notifier: notifier ?? config.monitor.notifier, rotate: async () => { throw new CliError('Monitor actions require approval.'); },
        feeds: config.monitor.feeds, github: config.monitor.github, usageOptions: config.monitor.usageOptions });
    },
    scan: command(() => scan(true)), inventory: command(inventory), plan: command(plan), loadPlan, rotationReport, saveRotationReport, rotate: command(rotate),
    monitorOnce: command(monitorOnce), monitor, reviewAction, checkpoint: () => audit.checkpoint(),
    createCanary: command(plant), drill: command(readiness),
    resume: command((id?: string) => recover('resume', id)), finish: command((id?: string, now: boolean = false) => recover('finish', id, now)),
    undo: command(async (id: string, clusterIds?: string[]) => {
      assertHuman('undo a rotation');
      await prepareExecution();
      await requireTeamGrant('dashboard:rotation/undo');
      const input = await recoveryInput(id);
      const report = await undoRotation({ ...input, clusterIds }, await recoveryDeps(), { ...config.rotation, dryRun: false });
      const state = await stateStore.load();
      for (const restored of report.restored) {
        const related = input.entries.filter(entry => entry.clusterId === restored.clusterId);
        const oldRef = related.map(entry => entry.data?.oldKeyRef).find((value): value is string => typeof value === 'string');
        for (const entry of related) if (typeof entry.data?.newFingerprint === 'string') delete state.keyRefs[entry.data.newFingerprint];
        delete state.keyRefs[restored.clusterId];
        if (oldRef) state.keyRefs[restored.clusterId] = oldRef;
      }
      await stateStore.save(state);
      const manager = autopilotManager(); const autopilot = await manager.loadState();
      if (reconcileAutopilotRecovery(autopilot, { planId: id, undo: report, entries: await journal.read() })) await manager.saveState(autopilot);
      await scan(); return safe(report);
    }),
    resetState: command(resetState), vaultList,
    async vaultStatus() { return { backend: vault.backend, ...(vault.weakness ? { weakness: vault.weakness } : {}), credentials: await vaultList(), supportedNames: [...VAULT_SET_NAMES] }; },
    vaultSet: command(async (name: string, value: string, role: TokenRole = 'write', opts: { stdin?: boolean } = {}) => {
      assertHuman('store a credential', opts.stdin === true); await requireTeamGrant('dashboard:vault/store'); const item = credentialName(name, role);
      if (!value) throw new CliError('The credential value was empty. Nothing was stored.');
      redactor.register(value); const bytes = Buffer.from(value);
      try { await vault.set(item, bytes); } finally { bytes.fill(0); }
      await refreshConnections();
      await audit.append({ kind: 'vault-set', summary: 'Credential stored.', data: { name, role } });
      return { name, role, stored: true };
    }),
    vaultRemove: command(async (name: string, role: TokenRole = 'write') => {
      assertHuman('remove a credential'); await requireTeamGrant('dashboard:vault/remove'); const removed = await vault.delete(credentialName(name, role));
      await refreshConnections();
      await audit.append({ kind: 'vault-remove', summary: 'Credential removed.', data: { name, role } }); return { name, role, removed };
    }),
    vaultImportEnv: command(async () => {
      assertHuman('import credentials'); await requireTeamGrant('dashboard:vault/import');
      for (const name of CREDENTIAL_NAMES) if (env[name] && !NON_SECRET_CREDENTIALS.includes(name)) redactor.register(env[name]!);
      const names = await importFromEnv(vault, env);
      for (const name of names) await audit.append({ kind: 'vault-import', summary: 'Credential imported.', data: { name, role: 'write' } });
      return { names };
    }),
    doctor: command(async (probe = false) => {
      const path = join(paths.dir, 'doctor.json');
      const previous = await store.readJson<Record<string, string>>('doctor', path) ?? undefined;
      const enabledHosts = [...new Set([...config.hosts.map(host => host.id), ...config.disabledHosts.filter(item => item.reason !== 'Disabled in configuration.').map(item => item.host)])];
      const result = await runDoctor({ vault, credentials, enabledHosts, env, nodeVersion: process.versions.node,
        ...(probe ? { probe: { http } } : {}), previous, integrity: await checkLocalIntegrity(),
        sandboxed: !!process.permission, network: network.summary });
      if (probe) await store.writeJson('doctor', path, result.fingerprints);
      // Team governance (fresh read): roster and policy in force, and anything that pauses changes.
      const current = await readGovernance();
      if (current.team || current.blockers.length || current.policy.status !== 'none') {
        const team = current.team ? `Roster version ${current.team.roster.roster.version} verified.` : 'No team roster.';
        const policy = current.policy.status === 'ok' ? ` Policy version ${current.policy.policy.policy.version} verified.` : '';
        result.items.push(current.blockers.length
          ? { area: 'team', status: 'fail', title: 'Team governance', detail: `${team}${policy} Changes are paused: ${current.blockers.join(' ')}`, fix: 'Run keysentry team verify and keysentry policy verify for details.' }
          : { area: 'team', status: 'ok', title: 'Team governance', detail: `${team}${policy}` });
      }
      await audit.append({ kind: 'doctor', summary: 'Doctor checks completed.', data: { probe, checks: result.items.length, warnings: result.items.filter(item => item.status === 'warn').length } });
      return safe(result);
    }),
    async init() {
      await stateStore.save(await stateStore.load());
      let created = false;
      try { await writeFile(config.configPath, '# Store tokens with keysentry vault set or vault import-env.\nhosts:\n  dotenv:\n    roots: [.]\nrotation:\n  graceSeconds: 120\nnetwork:\n  allowHosts: []\nmonitor:\n  autoExecute: false\n', { flag: 'wx', mode: 0o600 }); created = true; }
      catch (error) { if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw new CliError('Unable to create sample configuration.'); }
      return { stateDirectory: paths.dir, configPath: config.configPath, configCreated: created };
    },
    async report() { return redactor.redact(humanize(renderBlastRadius(await inventory()))); },
    async runbook(rotationPlan: RotationPlan) { remember(rotationPlan.services); return redactor.redact(humanize(renderRunbook(rotationPlan, await inventory()))); },
    async canaries() { return safe(listCanaries(await stateStore.load())); },
    async removeCanary(id: string, execute = false) {
      if (execute) { assertHuman('remove a canary'); await prepareExecution(); await requireTeamGrant('dashboard:canary'); }
      const selected = await adapters(execute ? 'write' : 'read');
      const state = await stateStore.load();
      await removeCanary(id, detector(await inventory(), state, selected), { dryRun: !execute });
      if (execute) await stateStore.save(state);
      return { id, dryRun: !execute, removed: execute };
    },
    async pendingActions() { return safe((await stateStore.load()).pendingActions.filter(action => action.status === 'pending')); },
    async monitorStatus() {
      const state = await stateStore.load();
      return safe({ policy: config.monitor.policy, canaries: listCanaries(state), pendingActions: state.pendingActions, cooldowns: state.cooldowns, autoRotations: state.autoRotations });
    },
    approve: command(approveAction),
    async dismiss(id: string) {
      assertHuman('dismiss a pending action'); await requireTeamGrant('dashboard:approvals/dismiss');
      await dismiss(id, await actionContext()); return { id, status: 'dismissed' };
    },
    async writeRunbook(path: string, text: string) {
      const target = resolve(config.cwd, path);
      await writeFile(target, redactor.redact(text), { mode: 0o600, flag: 'wx' });
      return target;
    },
  };
}

export type KeysentryRuntime = Awaited<ReturnType<typeof createRuntime>>;
