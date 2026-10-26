import { CliError } from './errors.js';
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
  runMonitorOnce, type BreachFeed, type DetectorContext, type MonitorState, type MonitorStateStore,
} from '../monitor/index.js';
import type {
  GuidedPrompt, HostAdapter, HostId, HttpClient, Inventory, Logger, Policy, ProviderAdapter,
  ProviderId, Redactor, RotationPlan, RotationReport,
} from '../types.js';
import { loadConfig } from './config.js';
import { inventorySchema, planIdSchema, planSchema } from './schemas.js';

export type PlanFilters = NonNullable<Parameters<typeof buildPlan>[1]>;
export interface RuntimeOptions {
  cwd?: string; config?: string; env?: NodeJS.ProcessEnv; http?: HttpClient;
  hosts?: HostAdapter[]; providers?: (id: ProviderId) => ProviderAdapter;
  policy?: Policy; feeds?: BreachFeed[]; fingerprintKey?: Buffer;
  prompt?: (p: GuidedPrompt) => Promise<string | null>; log?: Logger;
  verbose?: boolean; json?: boolean; sleep?: (ms: number) => Promise<void>; now?: () => Date;
}
export interface ExecutionOptions {
  execute?: boolean; prompt?: (p: GuidedPrompt) => Promise<string | null>;
  revoke?: RotateOptions['revoke']; redeploy?: boolean;
}

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
  const log = options.log ?? createLogger({ redactor, level: options.verbose ? 'debug' : 'info', json: options.json });
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
    const state = await stateStore.load();
    // Decoys are monitored separately. Never rotate one into a fully privileged production key.
    const decoys = new Set(state.canaries.map(canary => `${serviceKey(canary.service)}\0${canary.varName}`));
    const realConsumer = (consumer: Inventory['findings'][number] | Inventory['clusters'][number]['consumers'][number]) => !decoys.has(`${serviceKey(consumer.service)}\0${consumer.varName}`);
    inventory.findings = inventory.findings.filter(realConsumer);
    inventory.clusters = inventory.clusters.map(cluster => ({ ...cluster, consumers: cluster.consumers.filter(realConsumer) })).filter(cluster => cluster.consumers.length > 0);
    if (!options.hosts) inventory.errors.push(...config.disabledHosts.map(item => ({ host: item.host, message: item.reason })));
    const clean = safe(inventorySchema.parse(inventory));
    await saveInventory(clean, config.cwd);
    return clean;
  }

  async function inventory(): Promise<Inventory> {
    const stored = await loadInventory(config.cwd);
    if (!stored) return scan();
    const result = inventorySchema.safeParse(stored);
    if (!result.success) throw new CliError('Invalid inventory file; run scan to rebuild it.');
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
    return safe(result.data);
  }

  async function execute(rotationPlan: RotationPlan, inv: Inventory, opts: ExecutionOptions): Promise<RotationReport> {
    if (opts.execute === true) assertCompleteScan(inv);
    const report = await executePlan(rotationPlan, inv, {
      hosts: hostMap, providers, providerCtx: config.providerCtx, journal,
      prompt: opts.prompt ?? options.prompt ?? (async () => null), fingerprintKey, redactor, log,
      sleep: options.sleep, now: options.now,
    }, { ...config.rotation, dryRun: opts.execute !== true, ...(opts.revoke ? { revoke: opts.revoke } : {}), ...(opts.redeploy !== undefined ? { redeploy: opts.redeploy } : {}) });
    await writeJsonAtomic(join(paths.dir, 'rotation-report.json'), safe(report));
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

  function assertCompleteScan(inv: Inventory): void {
    if (inv.errors.some(error => hostMap[error.host])) {
      throw new CliError('Enabled host scans failed; execution is blocked because consumers may be missing. Run scan successfully before retrying.');
    }
  }

  async function unattended(rotationPlan: RotationPlan, inv: Inventory): Promise<RotationReport> {
    const report = await execute(rotationPlan, inv, { execute: true, prompt: async () => null });
    // Engine 'deployed' means new-key verification, all writes and activation succeeded,
    // while monitor's completion contract accepts 'verified'/'revoked'. Preserve the
    // exact engine report on disk and every warning about manual old-key revocation.
    return { ...report, steps: report.steps.map(step => step.status === 'deployed' ? { ...step, status: 'verified' as const } : step) };
  }

  async function monitorOnce() {
    const inv = await scan();
    // A partial refresh can hide another copy of a shared credential. Do not
    // run containment or rotation against that incomplete consumer set.
    assertCompleteScan(inv);
    const ctx = { ...detector(inv, await stateStore.load()), state: stateStore as MonitorStateStore,
      ...config.monitor, policy: config.monitor.policy, notifier: config.monitor.notifier,
      rotate: (rotationPlan: RotationPlan) => unattended(rotationPlan, inv),
    };
    const result = await runMonitorOnce(ctx);
    await scan();
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

  async function actionContext() {
    const inv = await inventory();
    const state = await stateStore.load();
    return { ...detector(inv, state), policy: config.monitor.policy, notifier: config.monitor.notifier,
      rotate: (rotationPlan: RotationPlan) => unattended(rotationPlan, inv),
      saveState: () => stateStore.save(state),
    };
  }

  async function plant(opts: { host: HostId; service: string; varName?: string; execute?: boolean }) {
    const host = hostMap[opts.host];
    if (!host) throw new CliError('Requested host is not enabled.');
    const services = (await host.listServices()).filter(service => [serviceKey(service), service.serviceId, service.serviceName].includes(opts.service));
    if (services.length !== 1) throw new CliError('Service must identify exactly one service; use its full service key from scan.');
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
    config, paths, redactor, providers, safe, scan, inventory, plan, loadPlan, rotate, monitorOnce, monitor,
    createCanary: plant, drill: readiness,
    async init() {
      await stateStore.save(await stateStore.load());
      let created = false;
      try { await writeFile(config.configPath, '# Host tokens and provider admin credentials come from environment variables.\nhosts:\n  dotenv:\n    roots: [.]\nmonitor:\n  autoExecute: false\n', { flag: 'wx', mode: 0o600 }); created = true; }
      catch (error) { if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw new CliError('Unable to create sample configuration.'); }
      return { stateDirectory: paths.dir, configPath: config.configPath, configCreated: created };
    },
    async report() { return redactor.redact(renderBlastRadius(await inventory())); },
    async runbook(rotationPlan: RotationPlan) { return redactor.redact(renderRunbook(rotationPlan, await inventory())); },
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
    async approve(id: string) { const result = await approve(id, await actionContext()); await scan(); return safe(result); },
    async dismiss(id: string) { await dismiss(id, await actionContext()); return { id, status: 'dismissed' }; },
    async writeRunbook(path: string, text: string) {
      const target = resolve(config.cwd, path);
      await writeFile(target, redactor.redact(text), { mode: 0o600, flag: 'wx' });
      return target;
    },
  };
}

export type KeysentryRuntime = Awaited<ReturnType<typeof createRuntime>>;
