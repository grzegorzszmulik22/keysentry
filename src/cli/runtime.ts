import { CliError, RotationInterruptedError } from './errors.js';
import { createHash } from 'node:crypto';
import { lstat, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, relative, resolve, sep } from 'node:path';
import {
  buildPlan, classify, createLogger, createRedactor, createStateStore, createStateCipher, createInFlightStore,
  renderBlastRadius, renderRunbook, scanHosts, serviceKey, statePaths, type StateStore,
} from '../core/index.js';
import { getProvider, PROVIDER_CREDENTIALS } from '../providers/index.js';
import { executePlan, resumeRotation, finishRotation, undoRotation, type RotateOptions, type EngineDeps } from '../rotate/index.js';
import { createAuditLog } from '../security/index.js';
import { CREDENTIAL_NAMES, credentialVaultName, createCredentialSource, createMemoryVault, deviceKey, fingerprintKey as vaultFingerprintKey, getProjectId, importFromEnv, openVault, stateKey } from '../vault/index.js';
import { createGuardedHttp, createFileReceipt, EGRESS_RULES, rulesForUserFeeds, rulesForUserUrls } from '../net/index.js';
import { createFetchHttp } from '../http.js';
import { checkLocalIntegrity } from '../release/index.js';
import { runDoctor } from '../doctor/index.js';
import { assertHumanForMutation } from '../safety/index.js';
import {
  approve, createCanary, createFileMonitorStateStore, dismiss, listCanaries, removeCanary,
  runMonitorOnce, type BreachFeed, type DetectorContext, type MonitorState, type MonitorStateStore, type RotateExecutor,
} from '../monitor/index.js';
import type {
  GuidedPrompt, HostAdapter, HostId, HttpClient, Inventory, Logger, Policy, ProviderAdapter,
  ProviderId, Redactor, RotationPlan, RotationReport, ServiceRef, AuditLog, InFlightStore, Vault, TokenRole, GraceInfo, GraceDecision,
} from '../types.js';
import { loadConfig, loadConfigMetadata } from './config.js';
import { inventorySchema, planIdSchema, planSchema } from './schemas.js';
import { humanizeServices, serviceLabel } from './display.js';
import { hasInteractiveTerminal, promptSecret, revealSecret, promptPassphrase, promptGrace, confirmVaultFallback, type RevealInfo, type PromptIO } from './prompts.js';
import { RotationAbortedError } from '../types.js';

export type PlanFilters = NonNullable<Parameters<typeof buildPlan>[1]>;
type Reveal = (info: RevealInfo, value: string) => Promise<boolean>;
export interface RuntimeOptions {
  cwd?: string; config?: string; env?: NodeJS.ProcessEnv; http?: HttpClient;
  hosts?: HostAdapter[]; providers?: (id: ProviderId) => ProviderAdapter;
  policy?: Policy; feeds?: BreachFeed[]; fingerprintKey?: Buffer;
  prompt?: (p: GuidedPrompt) => Promise<string | null>; log?: Logger;
  reveal?: Reveal;
  vault?: Vault; inflight?: InFlightStore; audit?: AuditLog; crashHook?: EngineDeps['crashHook'];
  stdinIsTTY?: boolean; stdoutIsTTY?: boolean; userDir?: string;
  grace?: (info: GraceInfo) => Promise<GraceDecision>;
  passphrase?: () => Promise<Buffer>; allowFileFallback?: (reason: string) => Promise<boolean>;
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
  const userDir = resolve(options.userDir ?? join(homedir(), '.keysentry'));
  const interactive = (options.stdinIsTTY ?? !!process.stdin.isTTY) && (options.stdoutIsTTY ?? !!process.stdout.isTTY);
  const mutationContext = { env, stdinIsTTY: options.stdinIsTTY ?? !!process.stdin.isTTY, stdoutIsTTY: options.stdoutIsTTY ?? !!process.stdout.isTTY };
  const assertHuman = (action: string) => assertHumanForMutation({ ...mutationContext, action });
  const redactor = outputRedactor();
  const knownServices = new Map<string, ServiceRef>();
  const remember = (services: ServiceRef[]) => { for (const service of services) knownServices.set(serviceKey(service), service); };
  const humanize = (text: string) => humanizeServices(text, [...knownServices.values()]);
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
  const metadata = await loadConfigMetadata(options);
  const paths = statePaths(metadata.cwd);
  const passphrase = options.passphrase ?? (async () => {
    if (!interactive) {
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
  });
  const projectId = await getProjectId(paths.dir);
  const key = await stateKey(vault, projectId);
  let baseStore: StateStore;
  try { baseStore = createStateStore({ cwd: metadata.cwd, cipher: createStateCipher(key) }); }
  finally { key.fill(0); }
  const migration = await baseStore.migratePlaintext();
  if (migration.migrated.length) log.info(`Encrypted ${migration.migrated.length} files saved by keysentry 0.1. Nothing else changed.`);
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
    get: async name => name.startsWith('audit/head/') ? await transientHeads.get(name) ?? vault.get(name) : vault.get(name),
    set: (name, value) => name.startsWith('audit/head/') ? transientHeads.set(name, value) : vault.set(name, value),
    delete: name => name.startsWith('audit/head/') ? transientHeads.delete(name) : vault.delete(name),
    list: prefix => vault.list(prefix),
  } : {
    backend: vault.backend, weakness: vault.weakness,
    get: name => vault.get(name),
    async set(name, value) { if (name.startsWith('audit/head/')) await markAnchor(); await vault.set(name, value); },
    delete: name => vault.delete(name), list: prefix => vault.list(prefix),
  };
  const rawAudit = options.audit ?? createAuditLog({ path: paths.audit, vault: auditVault, deviceKey: () => deviceKey(vault), redactor, now: options.now });
  let auditDirty = false;
  let auditWeaknessReported = false;
  const audit: AuditLog = {
    async append(event) {
      if (!options.audit && vault.backend === 'env' && !auditWeaknessReported) {
        log.warn('The environment vault cannot save an independent audit head. Checkpoint signatures are still checked.');
        auditWeaknessReported = true;
      }
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
  const store: StateStore = { ...baseStore, journal: () => journal };
  const inflight = options.inflight ?? createInFlightStore({ dir: join(paths.dir, 'inflight'), vault, projectId });
  const credentials = createCredentialSource(vault, env);
  const receipt = createFileReceipt(join(paths.dir, 'network.jsonl'));
  const feedUrls = options.feeds?.map(feed => feed.url) ?? metadata.feedUrls;
  const rules = [...EGRESS_RULES, ...rulesForUserFeeds(feedUrls), ...rulesForUserUrls(metadata.webhooks, 'notification webhook you configured'), ...metadata.userHostRules];
  const http = createGuardedHttp(options.http ?? createFetchHttp(), { rules, receipt, trustedUrls: metadata.webhooks, log });
  const config = await loadConfig({ ...options, vault, http, role: 'read', redactor, log });
  if (options.policy) config.monitor.policy = options.policy;
  if (options.feeds) config.monitor.feeds = options.feeds;
  const providers = options.providers ?? getProvider;
  const stateStore = createFileMonitorStateStore(config.cwd, store);

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
      for (const value of Object.values(vars)) redactor.register(value);
      await host.writeVariables(service, vars, opts);
    },
    redeploy: service => host.redeploy(service),
    deploymentStatus: (service, id) => host.deploymentStatus(service, id),
  }));
  const hosts = wrapHosts(options.hosts ?? config.hosts);
  config.hosts = hosts;
  if (options.hosts) config.disabledHosts = [];
  const hostMap = Object.fromEntries(hosts.map(host => [host.id, host])) as Partial<Record<HostId, HostAdapter>>;
  const providerList = () => (Object.keys(PROVIDER_CREDENTIALS) as ProviderId[]).map(providers);
  const grace = options.grace ?? (info => promptGrace(info, diagnostic, options.promptIO, options.now));

  /** Write credentials are fetched only after the calling operation's human gate. */
  async function adapters(role: TokenRole) {
    if (role === 'read') return { hosts, hostMap, providerCtx: config.providerCtx };
    const writeConfig = await loadConfig({ ...options, vault, http, role, redactor, log });
    const selected = wrapHosts(options.hosts ?? writeConfig.hosts);
    return { hosts: selected, hostMap: Object.fromEntries(selected.map(host => [host.id, host])) as Partial<Record<HostId, HostAdapter>>,
      providerCtx: writeConfig.providerCtx };
  }

  async function integrityForExecution() {
    const integrity = await checkLocalIntegrity();
    if (integrity.status === 'mismatch') throw new CliError('The local installation check did not match. Reinstall keysentry before rotating keys.');
  }

  async function scan(): Promise<Inventory> {
    const inventory = await scanHosts(hosts, fingerprintKey, log);
    if (!options.hosts) inventory.errors.push(...config.disabledHosts.map(item => ({ host: item.host, message: item.reason })));
    // Retain only fingerprint metadata for unavailable hosts. Dropping a known
    // consumer would let a later partial scan understate a shared key's scope.
    const failedHosts = new Set(inventory.errors.map(error => error.host));
    if (failedHosts.size) {
      const previous = inventorySchema.safeParse(await store.loadInventory());
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
    const state = await stateStore.load();
    // Decoys are monitored separately. Never rotate one into a fully privileged production key.
    const decoys = new Set(state.canaries.map(canary => `${serviceKey(canary.service)}\0${canary.varName}`));
    const realConsumer = (consumer: Inventory['findings'][number] | Inventory['clusters'][number]['consumers'][number]) => !decoys.has(`${serviceKey(consumer.service)}\0${consumer.varName}`);
    inventory.findings = inventory.findings.filter(realConsumer);
    inventory.clusters = inventory.clusters.map(cluster => ({ ...cluster, consumers: cluster.consumers.filter(realConsumer) })).filter(cluster => cluster.consumers.length > 0);
    const clean = safe(inventorySchema.parse(inventory));
    remember(clean.services);
    await store.saveInventory(clean);
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

  async function plan(filters?: PlanFilters): Promise<RotationPlan> {
    const result = buildPlan(await inventory(), filters);
    await store.writeJson('plan', join(paths.plans, `${result.id}.json`), safe(result));
    await audit.append({ kind: 'plan-saved', summary: 'Rotation plan saved.', data: { id: result.id, steps: result.steps.length } });
    return result;
  }

  async function loadPlan(id: string): Promise<RotationPlan> {
    if (!planIdSchema.safeParse(id).success) throw new CliError('Invalid plan identifier.');
    const stored = await store.readJson('plan', join(paths.plans, `${id}.json`));
    const result = planSchema.safeParse(stored);
    if (!result.success) throw new CliError('Saved plan is missing or invalid; create a new plan.');
    remember(result.data.services);
    return safe(result.data);
  }

  async function execute(rotationPlan: RotationPlan, inv: Inventory, opts: ExecutionOptions, inheritInteraction = true): Promise<RotationReport> {
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
          if (typeof property === 'string' && mutations.includes(property)) ensureActive();
          return Reflect.apply(member, target, args);
        };
      },
    });
    const report = await executePlan(rotationPlan, inv, {
      hosts: selected.hostMap, providers: id => guardMutations(providers(id), ['rotate', 'revoke', 'cap']), providerCtx: selected.providerCtx, journal,
      prompt: p => preserveAbort(() => prompt(p)), fingerprintKey, redactor, log,
      sleep: options.sleep, now: options.now,
      inflight, crashHook: options.crashHook, grace: inheritInteraction && interactive ? grace : undefined,
      reveal: reveal ? (info, value) => preserveAbort(() => reveal(info, value), true) : undefined,
    }, { ...config.rotation, dryRun: opts.execute !== true,
      ...(opts.revoke ? { revoke: opts.revoke } : {}), ...(opts.redeploy !== undefined ? { redeploy: opts.redeploy } : {}),
      ...(opts.revokeUnconfirmed !== undefined ? { revokeUnconfirmed: opts.revokeUnconfirmed } : {}),
      ...(opts.acceptUnplannedSealed !== undefined ? { acceptUnplannedSealed: opts.acceptUnplannedSealed } : {}),
      ...(opts.allowGenerate !== undefined ? { allowGenerate: opts.allowGenerate } : {}),
      ...(opts.verifyRetries !== undefined ? { verifyRetries: opts.verifyRetries } : {}),
    });
    await store.writeJson('report', join(paths.dir, 'rotation-report.json'), safe(report));
    if (aborted) throw new RotationInterruptedError(safe(report));
    return report;
  }

  async function rotate(rotationPlan: RotationPlan, opts: ExecutionOptions = {}): Promise<RotationReport> {
    if (opts.execute === true) { assertHuman('rotate keys'); await integrityForExecution(); }
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

  function detector(inv: Inventory, state: MonitorState, selected = { hosts, providerCtx: config.providerCtx }): DetectorContext {
    // Detection uses read credentials. A provider-side automatic containment fetches
    // write credentials only when that action is actually called.
    const list = providerList().map(provider => new Proxy(provider, {
      get(target, property) {
        const member: unknown = Reflect.get(target, property, target);
        if (typeof member !== 'function') return member;
        if (!['cap', 'revoke', 'rotate'].includes(String(property))) return member.bind(target);
        return async (value: string, ctx: typeof config.providerCtx) => {
          const write = await adapters('write');
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
    if (config.monitor.policy.autoExecute || config.monitor.policy.autoContain) assertHuman('run automatic monitor actions');
    const inv = await scan();
    if (inv.errors.length) log.warn('Host scans failed or are disabled; monitoring continues on partial inventory. Clusters on unavailable hosts require remediation.');
    const ctx = { ...detector(inv, await stateStore.load()), state: stateStore as MonitorStateStore,
      ...config.monitor, policy: config.monitor.policy, notifier: config.monitor.notifier,
      rotate: (rotationPlan: RotationPlan, opts: Parameters<RotateExecutor>[1]) => monitored(rotationPlan, inv, opts),
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
    return !hostMap[service.host]?.capabilities.redeploy || ['dotenv', 'fly', 'github-actions'].includes(service.host)
      || service.host === 'vercel' && service.environmentId !== 'production'
      || service.host === 'railway' && service.serviceId === '';
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

  async function approveAction(id: string, opts: ApprovalOptions = {}) {
    assertHuman('approve a key change');
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
    // Monitor integrations may translate executor errors into a failed action. Preserve
    // explicit operator cancellation so the CLI always reports a whole-run abort.
    let aborted: RotationAbortedError | undefined;
    const rotate = ctx.rotate;
    ctx.rotate = async (plan, options) => {
      try { return await rotate(plan, options); }
      catch (error) { if (error instanceof RotationAbortedError) aborted = error; throw error; }
    };
    const result = await approve(id, ctx);
    await audit.append({ kind: 'approval', summary: 'Monitor action approved.', data: { id } });
    if (aborted) throw aborted;
    await scan();
    return safe(result);
  }

  async function plant(opts: { host: HostId; service: string; varName?: string; execute?: boolean }) {
    if (opts.execute) assertHuman('create a canary');
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
    const total = inv.clusters.length;
    const automatic = inv.clusters.filter(cluster => cluster.method === 'generate' ||
      cluster.method !== 'guided' && cluster.fingerprint !== null && PROVIDER_CREDENTIALS[cluster.provider].every(name => !!config.providerCtx.credentials[name])).length;
    const sealed = inv.clusters.filter(cluster => cluster.fingerprint === null).length;
    const duplicate = inv.clusters.filter(cluster => cluster.consumers.length > 1).length;
    const missing = inv.clusters.filter(cluster => PROVIDER_CREDENTIALS[cluster.provider].some(name => !config.providerCtx.credentials[name])).length;
    const manualDeploys = inv.services.filter(service => !hostMap[service.host]?.capabilities.redeploy || service.host === 'fly' || service.host === 'vercel' && service.environmentId !== 'production' || service.host === 'railway' && service.serviceId === '').length;
    const canaries = (await stateStore.load()).canaries.length;
    const ratio = (count: number, denominator = total) => denominator ? count / denominator : 0;
    const score = total ? Math.round(40 * ratio(automatic) + 15 * (1 - ratio(sealed)) + 15 * (1 - ratio(duplicate)) + 15 * (1 - ratio(missing)) + 10 * (1 - ratio(manualDeploys, inv.services.length)) + (canaries ? 5 : 0)) : 0;
    return safe({ score: Math.max(0, Math.min(100, score)), elapsedMs: Math.round(performance.now() - start), reasons: [
      `${automatic}/${total} clusters are currently auto-rotatable: automatic, atomic-roll, or generated (40 points).`,
      `${sealed}/${total} clusters are sealed (15 points).`, `${duplicate}/${total} clusters have duplicate consumers (15 points).`,
      `${missing}/${total} clusters lack configured admin credentials (15 points).`,
      `${manualDeploys}/${inv.services.length} services require manual activation or have no redeploy support (10 points).`,
      `${canaries} canaries configured (5 points).`,
    ], report });
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
      grace: interactive ? grace : undefined };
  }

  async function recover(mode: 'resume' | 'finish', id?: string, now = false) {
    assertHuman(mode === 'resume' ? 'resume a rotation' : 'finish a rotation');
    const input = await recoveryInput(id);
    const deps = await recoveryDeps();
    const opts = { ...config.rotation, dryRun: false, early: now };
    const report = mode === 'resume' ? await resumeRotation(input, deps, opts) : await finishRotation(input, deps, opts);
    await store.writeJson('report', join(paths.dir, 'rotation-report.json'), safe(report));
    await rememberKeyRefs(report, input.plan);
    await scan();
    return safe(report);
  }

  function credentialName(name: string, role: TokenRole) {
    if (!CREDENTIAL_NAMES.includes(name)) throw new CliError('Unknown credential name. Run keysentry vault status for supported names.');
    if (role !== 'read' && role !== 'write') throw new CliError('Credential role must be read or write.');
    return credentialVaultName(name, role);
  }

  async function vaultList() {
    const names = new Set(await vault.list('cred/'));
    return CREDENTIAL_NAMES.flatMap(name => (['read', 'write'] as const).filter(role => names.has(credentialVaultName(name, role))).map(role => ({ name, role })));
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
    assertHuman('reset saved state');
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
    config, paths, redactor, providers, safe, humanize, vault, store, inflight, audit, credentials, http, receipt, rules, userDir, interactive, assertHuman, mutationContext, assertStateResetSafe,
    scan: command(scan), inventory: command(inventory), plan: command(plan), loadPlan, rotate: command(rotate),
    monitorOnce: command(monitorOnce), monitor, reviewAction, checkpoint: () => audit.checkpoint(),
    createCanary: command(plant), drill: command(readiness),
    resume: command((id?: string) => recover('resume', id)), finish: command((id?: string, now: boolean = false) => recover('finish', id, now)),
    undo: command(async (id: string, clusterIds?: string[]) => {
      assertHuman('undo a rotation');
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
      await scan(); return safe(report);
    }),
    resetState: command(resetState), vaultList,
    async vaultStatus() { return { backend: vault.backend, ...(vault.weakness ? { weakness: vault.weakness } : {}), credentials: await vaultList(), supportedNames: [...CREDENTIAL_NAMES] }; },
    vaultSet: command(async (name: string, value: string, role: TokenRole = 'write') => {
      assertHuman('store a credential'); const item = credentialName(name, role);
      if (!value) throw new CliError('The credential value was empty. Nothing was stored.');
      redactor.register(value); const bytes = Buffer.from(value);
      try { await vault.set(item, bytes); } finally { bytes.fill(0); }
      await audit.append({ kind: 'vault-set', summary: 'Credential stored.', data: { name, role } });
      return { name, role, stored: true };
    }),
    vaultRemove: command(async (name: string, role: TokenRole = 'write') => {
      assertHuman('remove a credential'); const removed = await vault.delete(credentialName(name, role));
      await audit.append({ kind: 'vault-remove', summary: 'Credential removed.', data: { name, role } }); return { name, role, removed };
    }),
    vaultImportEnv: command(async () => {
      assertHuman('import credentials');
      for (const name of CREDENTIAL_NAMES) if (env[name]) redactor.register(env[name]!);
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
        sandboxed: env.KEYSENTRY_SANDBOXED === '1' || !!process.permission });
      if (probe) await store.writeJson('doctor', path, result.fingerprints);
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
      if (execute) assertHuman('remove a canary');
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
    async dismiss(id: string) { await dismiss(id, await actionContext()); return { id, status: 'dismissed' }; },
    async writeRunbook(path: string, text: string) {
      const target = resolve(config.cwd, path);
      await writeFile(target, redactor.redact(text), { mode: 0o600, flag: 'wx' });
      return target;
    },
  };
}

export type KeysentryRuntime = Awaited<ReturnType<typeof createRuntime>>;
