import { CliError } from './errors.js';
import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import {
  buildPlan, classify, createFileJournal, createLogger, createRedactor, loadInventory,
  loadOrCreateFingerprintKey, readJson, renderBlastRadius, renderRunbook, saveInventory,
  scanHosts, serviceKey, statePaths, writeJsonAtomic,
} from '../core/index.js';
import { getProvider, PROVIDER_CREDENTIALS } from '../providers/index.js';
import { executePlan, type RotateOptions } from '../rotate/index.js';
import {
  approve, createCanary, createFileMonitorStateStore, dismiss, listCanaries, removeCanary,
  runMonitorOnce, type BreachFeed, type DetectorContext, type MonitorState, type MonitorStateStore, type RotateExecutor,
} from '../monitor/index.js';
import type {
  GuidedPrompt, HostAdapter, HostId, HttpClient, Inventory, Logger, Policy, ProviderAdapter,
  ProviderId, Redactor, RotationPlan, RotationReport, ServiceRef,
} from '../types.js';
import { loadConfig } from './config.js';
import { inventorySchema, planIdSchema, planSchema } from './schemas.js';
import { humanizeServices, serviceLabel } from './display.js';
import { hasInteractiveTerminal, promptSecret, revealSecret, type RevealInfo } from './prompts.js';
import { RotationAbortedError } from '../types.js';

export type PlanFilters = NonNullable<Parameters<typeof buildPlan>[1]>;
type Reveal = (info: RevealInfo, value: string) => Promise<boolean>;
export interface RuntimeOptions {
  cwd?: string; config?: string; env?: NodeJS.ProcessEnv; http?: HttpClient;
  hosts?: HostAdapter[]; providers?: (id: ProviderId) => ProviderAdapter;
  policy?: Policy; feeds?: BreachFeed[]; fingerprintKey?: Buffer;
  prompt?: (p: GuidedPrompt) => Promise<string | null>; log?: Logger;
  reveal?: Reveal;
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
  const redactor = outputRedactor();
  const knownServices = new Map<string, ServiceRef>();
  const remember = (services: ServiceRef[]) => { for (const service of services) knownServices.set(serviceKey(service), service); };
  const humanize = (text: string) => humanizeServices(text, [...knownServices.values()]);
  const baseLog = options.log ?? createLogger({ redactor, level: options.verbose ? 'debug' : 'info', json: options.json });
  const logValue = (input: unknown): unknown => {
    if (typeof input === 'string') return humanize(input);
    if (Array.isArray(input)) return input.map(logValue);
    if (input && typeof input === 'object') return Object.fromEntries(Object.entries(input).map(([key, value]) => [key, logValue(value)]));
    return input;
  };
  const log: Logger = Object.fromEntries((['info', 'warn', 'error', 'debug'] as const).map(level => [level,
    (message: string, data?: Record<string, unknown>) => baseLog[level](humanize(message), data === undefined ? undefined : logValue(data) as Record<string, unknown>),
  ])) as unknown as Logger;
  const config = await loadConfig({ ...options, redactor, log });
  if (options.policy) config.monitor.policy = options.policy;
  if (options.feeds) config.monitor.feeds = options.feeds;
  const paths = statePaths(config.cwd);
  const fingerprintKey = options.fingerprintKey ?? await loadOrCreateFingerprintKey(paths.dir);
  const providers = options.providers ?? getProvider;
  const stateStore = createFileMonitorStateStore(config.cwd);
  const journal = createFileJournal(paths.journal);

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
  const hosts = (options.hosts ?? config.hosts).map((host): HostAdapter => ({
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
  config.hosts = hosts;
  if (options.hosts) config.disabledHosts = [];
  const hostMap = Object.fromEntries(hosts.map(host => [host.id, host])) as Partial<Record<HostId, HostAdapter>>;
  const providerList = () => (Object.keys(PROVIDER_CREDENTIALS) as ProviderId[]).map(providers);

  async function scan(): Promise<Inventory> {
    const inventory = await scanHosts(hosts, fingerprintKey, log);
    if (!options.hosts) inventory.errors.push(...config.disabledHosts.map(item => ({ host: item.host, message: item.reason })));
    // Retain only fingerprint metadata for unavailable hosts. Dropping a known
    // consumer would let a later partial scan understate a shared key's scope.
    const failedHosts = new Set(inventory.errors.map(error => error.host));
    if (failedHosts.size) {
      const previous = inventorySchema.safeParse(await loadInventory(config.cwd));
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
    await saveInventory(clean, config.cwd);
    return clean;
  }

  async function inventory(): Promise<Inventory> {
    const stored = await loadInventory(config.cwd);
    if (!stored) return scan();
    const result = inventorySchema.safeParse(stored);
    if (!result.success) throw new CliError('Invalid inventory file; run scan to rebuild it.');
    remember(result.data.services);
    return safe(result.data);
  }

  async function plan(filters?: PlanFilters): Promise<RotationPlan> {
    const result = buildPlan(await inventory(), filters);
    await writeJsonAtomic(join(paths.plans, `${result.id}.json`), safe(result));
    return result;
  }

  async function loadPlan(id: string): Promise<RotationPlan> {
    if (!planIdSchema.safeParse(id).success) throw new CliError('Invalid plan identifier.');
    const stored = await readJson(join(paths.plans, `${id}.json`));
    const result = planSchema.safeParse(stored);
    if (!result.success) throw new CliError('Saved plan is missing or invalid; create a new plan.');
    remember(result.data.services);
    return safe(result.data);
  }

  async function execute(rotationPlan: RotationPlan, inv: Inventory, opts: ExecutionOptions, inheritInteraction = true): Promise<RotationReport> {
    remember(rotationPlan.services);
    if (opts.execute === true) assertPlanScan(rotationPlan, inv);
    let aborted: RotationAbortedError | undefined;
    const prompt = opts.prompt ?? (inheritInteraction ? options.prompt : undefined) ?? (async () => null);
    const reveal = Object.hasOwn(opts, 'reveal') ? opts.reveal : inheritInteraction ? options.reveal : undefined;
    const ensureActive = () => { if (aborted) throw aborted; };
    const preserveAbort = async <T>(operation: () => Promise<T>): Promise<T> => {
      ensureActive();
      try { return await operation(); }
      catch (error) { if (error instanceof RotationAbortedError) aborted = error; throw error; }
    };
    // A downstream error boundary must not turn operator cancellation into
    // permission to continue another host write, deployment, or revocation.
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
    const executionHosts = Object.fromEntries(Object.entries(hostMap).map(([id, host]) => [id, guardMutations(host, ['writeVariables', 'redeploy'])]));
    const report = await executePlan(rotationPlan, inv, {
      hosts: executionHosts, providers: id => guardMutations(providers(id), ['rotate', 'revoke', 'cap']), providerCtx: config.providerCtx, journal,
      prompt: p => preserveAbort(() => prompt(p)), fingerprintKey, redactor, log,
      sleep: async ms => { ensureActive(); await (options.sleep ? options.sleep(ms) : new Promise<void>(done => setTimeout(done, ms))); }, now: options.now,
      reveal: reveal ? (info, value) => preserveAbort(() => reveal(info, value)) : undefined,
    }, { ...config.rotation, dryRun: opts.execute !== true,
      ...(opts.revoke ? { revoke: opts.revoke } : {}), ...(opts.redeploy !== undefined ? { redeploy: opts.redeploy } : {}),
      ...(opts.revokeUnconfirmed !== undefined ? { revokeUnconfirmed: opts.revokeUnconfirmed } : {}),
      ...(opts.acceptUnplannedSealed !== undefined ? { acceptUnplannedSealed: opts.acceptUnplannedSealed } : {}),
      ...(opts.allowGenerate !== undefined ? { allowGenerate: opts.allowGenerate } : {}),
      ...(opts.verifyRetries !== undefined ? { verifyRetries: opts.verifyRetries } : {}),
    });
    await writeJsonAtomic(join(paths.dir, 'rotation-report.json'), safe(report));
    if (aborted) throw aborted;
    return report;
  }

  async function rotate(rotationPlan: RotationPlan, opts: ExecutionOptions = {}): Promise<RotationReport> {
    const inv = await inventory();
    const report = await execute(rotationPlan, inv, opts);
    if (!report.dryRun) {
      const state = await stateStore.load();
      for (const step of report.steps) if (step.newFingerprint && step.newKeyRef && ['written', 'deployed', 'verified', 'revoked'].includes(step.status)) {
        state.keyRefs[step.newFingerprint] = step.newKeyRef;
        delete state.keyRefs[step.clusterId];
        if (inv.clusters.find(cluster => cluster.id === step.clusterId)?.fingerprint === null) state.keyRefs[step.clusterId] = step.newKeyRef;
      }
      await stateStore.save(state);
      await scan();
    }
    return safe(report);
  }

  function detector(inv: Inventory, state: MonitorState): DetectorContext {
    return { inventory: inv, hosts, providers: providerList(), providerCtx: config.providerCtx, state, fingerprintKey, log, clock: options.now };
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

  async function monitored(rotationPlan: RotationPlan, inv: Inventory, opts: Parameters<RotateExecutor>[1], interaction: Pick<ExecutionOptions, 'prompt' | 'reveal'> = {}): Promise<RotationReport> {
    const report = await execute(rotationPlan, inv, { execute: true,
      revoke: 'after-deploy', redeploy: true, acceptUnplannedSealed: false,
      revokeUnconfirmed: opts.revokeUnconfirmed, allowGenerate: false, ...interaction,
    }, false);
    // Engine 'deployed' means new-key verification, all writes and activation succeeded,
    // while monitor's completion contract accepts 'verified'/'revoked'. Preserve the
    // exact engine report on disk and every warning about manual old-key revocation.
    return { ...report, steps: report.steps.map(step => step.status === 'deployed' ? { ...step, status: 'verified' as const } : step) };
  }

  async function monitorOnce() {
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
      try { const result = await monitorOnce(); onPoll?.(result); } catch { log.error('Monitor poll failed; inspect configuration and state.'); }
      if (signal.aborted) break;
      await new Promise<void>(done => {
        const finish = () => { clearTimeout(timer); signal.removeEventListener('abort', finish); done(); };
        const timer = setTimeout(finish, intervalMs);
        signal.addEventListener('abort', finish, { once: true });
        if (signal.aborted) finish();
      });
    }
  }

  async function actionContext(interaction: Pick<ExecutionOptions, 'prompt' | 'reveal'> = {}, interactive = false) {
    const inv = await inventory();
    const state = await stateStore.load();
    return { ...detector(inv, state), policy: config.monitor.policy, notifier: config.monitor.notifier, interactive,
      rotate: (rotationPlan: RotationPlan, opts: Parameters<RotateExecutor>[1]) => monitored(rotationPlan, inv, opts, interaction),
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
    const interactive = opts.interactive ?? hasInteractiveTerminal();
    const diagnostic = (text: string) => process.stderr.write(`${redactor.redact(humanize(text))}\n`);
    const interaction = interactive ? {
      prompt: opts.prompt ?? options.prompt ?? ((p: GuidedPrompt) => promptSecret(p, diagnostic)),
      reveal: opts.reveal ?? options.reveal ?? ((info: RevealInfo, value: string) => revealSecret(info, value, diagnostic)),
    } : {};
    const ctx = await actionContext(interaction, interactive);
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
    if (aborted) throw aborted;
    await scan();
    return safe(result);
  }

  async function plant(opts: { host: HostId; service: string; varName?: string; execute?: boolean }) {
    const host = hostMap[opts.host];
    if (!host) throw new CliError('Requested host is not enabled.');
    const services = (await host.listServices()).filter(service => [serviceKey(service), serviceLabel(service), service.serviceId, service.serviceName].includes(opts.service));
    if (services.length !== 1) throw new CliError('Service must identify exactly one service; use its full project/service label from scan.');
    const inv = await inventory();
    await host.readVariables(services[0]!);
    if (JSON.stringify(safe(services[0])) !== JSON.stringify(services[0]) || opts.varName && safe(opts.varName) !== opts.varName) {
      throw new CliError('Canary destination metadata contains credential-like text; choose a safe service and variable name.');
    }
    const state = await stateStore.load();
    const result = await createCanary({ provider: 'openrouter', host, service: services[0]!, varName: opts.varName, dryRun: opts.execute !== true }, detector(inv, state));
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

  return {
    config, paths, redactor, providers, safe, humanize, scan, inventory, plan, loadPlan, rotate, monitorOnce, monitor, reviewAction,
    createCanary: plant, drill: readiness,
    async init() {
      await stateStore.save(await stateStore.load());
      let created = false;
      try { await writeFile(config.configPath, '# Host tokens and provider admin credentials come from environment variables.\nhosts:\n  dotenv:\n    roots: [.]\nmonitor:\n  autoExecute: false\n', { flag: 'wx', mode: 0o600 }); created = true; }
      catch (error) { if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw new CliError('Unable to create sample configuration.'); }
      return { stateDirectory: paths.dir, configPath: config.configPath, configCreated: created };
    },
    async report() { return redactor.redact(humanize(renderBlastRadius(await inventory()))); },
    async runbook(rotationPlan: RotationPlan) { remember(rotationPlan.services); return redactor.redact(humanize(renderRunbook(rotationPlan, await inventory()))); },
    async canaries() { return safe(listCanaries(await stateStore.load())); },
    async removeCanary(id: string, execute = false) {
      const state = await stateStore.load();
      await removeCanary(id, detector(await inventory(), state), { dryRun: !execute });
      if (execute) await stateStore.save(state);
      return { id, dryRun: !execute, removed: execute };
    },
    async pendingActions() { return safe((await stateStore.load()).pendingActions.filter(action => action.status === 'pending')); },
    async monitorStatus() {
      const state = await stateStore.load();
      return safe({ policy: config.monitor.policy, canaries: listCanaries(state), pendingActions: state.pendingActions, cooldowns: state.cooldowns, autoRotations: state.autoRotations });
    },
    approve: approveAction,
    async dismiss(id: string) { await dismiss(id, await actionContext()); return { id, status: 'dismissed' }; },
    async writeRunbook(path: string, text: string) {
      const target = resolve(config.cwd, path);
      await writeFile(target, redactor.redact(text), { mode: 0o600, flag: 'wx' });
      return target;
    },
  };
}

export type KeysentryRuntime = Awaited<ReturnType<typeof createRuntime>>;
