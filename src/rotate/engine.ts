import { classify, fingerprint, serviceKey } from '../core/index.js';
import { RotationAbortedError } from '../types.js';
import type {
  Consumer, GuidedPrompt, HostAdapter, HostId, Inventory, Journal, JournalEntry, Logger, PlanStep,
  ProviderAdapter, ProviderContext, ProviderId, RawVariable, Redactor, RotationPlan,
  RotationReport, RotationResult, ServiceRef, StepReport, StepStatus,
} from '../types.js';

export interface EngineDeps {
  hosts: Partial<Record<HostId, HostAdapter>>;
  providers: (id: ProviderId) => ProviderAdapter;
  providerCtx: ProviderContext;
  journal: Journal;
  prompt: (p: GuidedPrompt) => Promise<string | null>;
  fingerprintKey: Buffer;
  redactor: Redactor;
  log: Logger;
  sleep?: (ms: number) => Promise<void>;
  now?: () => Date;
  /** True only when the replacement was actually presented to a human. */
  reveal?: (info: { clusterId: string; provider: ProviderId; hint: string | null; reason: string }, value: string) => Promise<boolean>;
}

export interface RotateOptions {
  dryRun: boolean;
  revoke: 'after-deploy' | 'immediately' | 'never';
  redeploy: boolean;
  deployTimeoutMs: number;
  pollIntervalMs: number;
  revokeUnconfirmed: boolean;
  acceptUnplannedSealed: boolean;
  allowGenerate: boolean;
  verifyRetries: number;
}

interface ServiceWork {
  service: ServiceRef;
  host?: HostAdapter;
  variables: RawVariable[];
  readFailed: boolean;
  vars: Record<string, string>;
  steps: Set<StepWork>;
  written: boolean;
  activation: 'pending' | 'success' | 'failed' | 'unconfirmed' | 'skipped';
}

interface StepWork {
  step: PlanStep;
  report: StepReport;
  services: Set<string>;
  contextService?: string;
  ctx?: ProviderContext;
  newCtx?: ProviderContext;
  provider?: ProviderAdapter;
  oldValue?: string;
  oldRevoked?: boolean;
  result?: RotationResult;
  ready: boolean;
  guided?: boolean;
  atomicRoll?: boolean;
  unwritten?: Set<string>;
  delivered?: Set<string>;
  revealed?: boolean;
  referenceTargets?: Map<string, Consumer>;
}

class JournalFailure extends Error {
  constructor() { super('Unable to record rotation journal; execution stopped.'); }
}

/** Values stay in local execution state; only sanitized metadata crosses the journal/report boundary. */
export async function executePlan(
  plan: RotationPlan, inv: Inventory, deps: EngineDeps, opts: RotateOptions,
): Promise<RotationReport> {
  // Only an explicit false authorizes mutations, including for callers supplying incomplete JS options.
  const dryRun = opts?.dryRun !== false;
  const redeploy = opts?.redeploy ?? true;
  const revoke = opts?.revoke ?? 'after-deploy';
  const revokeUnconfirmed = opts?.revokeUnconfirmed === true;
  const acceptUnplannedSealed = opts?.acceptUnplannedSealed === true;
  const allowGenerate = opts?.allowGenerate !== false;
  const verifyRetries = Number.isInteger(opts?.verifyRetries) && opts.verifyRetries >= 0 ? opts.verifyRetries : 4;
  const timeout = Number.isFinite(opts?.deployTimeoutMs) && opts.deployTimeoutMs >= 0 ? opts.deployTimeoutMs : 600_000;
  const interval = Number.isFinite(opts?.pollIntervalMs) && opts.pollIntervalMs > 0 ? opts.pollIntervalMs : 5_000;
  const now = deps.now ?? (() => new Date());
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms)));
  const knownValues = new Set<string>();
  const sensitiveValues = new Set<string>();
  const publicKeyRefs = new Set<string>();
  function register(value: string, sensitive = true): void {
    if (value.length === 0) return;
    knownValues.add(value);
    if (sensitive) sensitiveValues.add(value);
    deps.redactor.register(value);
  }
  function clean(text: string): string {
    // Core intentionally ignores short secrets. Exact replacement also protects those in metadata.
    for (const value of [...knownValues].sort((a, b) => b.length - a.length)) text = text.split(value).join('«redacted»');
    return deps.redactor.redact(text);
  }
  function sanitize<T>(data: T, preserveRefs = false): T {
    // Sanitize strings independently: an arbitrary secret can contain JSON punctuation.
    if (typeof data === 'string') return clean(data) as T;
    if (Array.isArray(data)) return data.map(value => sanitize(value, preserveRefs)) as T;
    if (data !== null && typeof data === 'object') {
      const result = Object.create(null) as Record<string, unknown>;
      for (const [key, value] of Object.entries(data)) {
        // IAM access key IDs are public identifiers needed for monitoring/revocation.
        // Keep their typed reference fields, while freeform logging still masks companions.
        const publicRef = preserveRefs && ['keyRef', 'oldKeyRef', 'newKeyRef'].includes(key)
          && typeof value === 'string' && publicKeyRefs.has(value) && !sensitiveValues.has(value);
        result[clean(key)] = publicRef ? value : sanitize(value, preserveRefs);
      }
      return result as T;
    }
    return data;
  }
  const safeLogger = (logger: Logger): Logger => ({
    info: (msg, data) => logger.info(clean(msg), data === undefined ? undefined : sanitize(data)),
    warn: (msg, data) => logger.warn(clean(msg), data === undefined ? undefined : sanitize(data)),
    error: (msg, data) => logger.error(clean(msg), data === undefined ? undefined : sanitize(data)),
    debug: (msg, data) => logger.debug(clean(msg), data === undefined ? undefined : sanitize(data)),
  });
  const log = safeLogger(deps.log);
  for (const value of Object.values(deps.providerCtx.credentials)) if (value !== undefined) register(value);
  for (const [name, value] of Object.entries(deps.providerCtx.siblingVars ?? {})) if (classify(name, value).isSecret) register(value);
  const report: RotationReport = {
    planId: plan.id, dryRun, startedAt: now().toISOString(), finishedAt: '',
    steps: [], deployments: [], diff: [],
  };
  const works: StepWork[] = plan.steps.map(step => {
    const stepReport: StepReport = { clusterId: step.clusterId, status: 'pending', warnings: [] };
    report.steps.push(stepReport);
    return { step, report: stepReport, services: new Set(step.consumers.map(c => serviceKey(c.service))), ready: false };
  });
  const services = new Map<string, ServiceWork>();
  let railwayNamespace: Promise<ServiceRef[]> | undefined;
  const plannedLocations = new Set(plan.steps.flatMap(step => step.consumers.map(c => `${serviceKey(c.service)}\0${c.varName}`)));
  const referenceLocations = new Set([...inv.findings, ...inv.clusters.flatMap(cluster => cluster.consumers)]
    .filter(c => c.reference).map(c => `${serviceKey(c.service)}\0${c.varName}`));
  function blockedBySealed(work: StepWork): boolean {
    if (acceptUnplannedSealed) return false;
    const names = new Set(work.step.consumers.map(c => c.varName));
    const locations = [...new Set(inv.findings.filter(f => f.sealed
      && !plannedLocations.has(`${serviceKey(f.service)}\0${f.varName}`)
      && (f.provider === work.step.provider || names.has(f.varName)))
      .map(f => `${f.service.host}/${f.service.serviceName}:${f.varName}`))];
    if (locations.length === 0) return false;
    warn(work, `Old key retained: unplanned sealed consumers may still use it: ${locations.join(', ')}.`);
    return true;
  }
  async function journal(event: JournalEntry['event'], fields: Omit<JournalEntry, 'event' | 'at' | 'planId'> = {}): Promise<void> {
    try {
      await deps.journal.append(sanitize({ at: now().toISOString(), planId: plan.id, event, ...fields }, true));
    } catch { throw new JournalFailure(); }
  }
  function warn(work: StepWork, message: string): void {
    work.report.warnings.push(clean(message));
    log.warn(message, { clusterId: work.step.clusterId });
  }
  async function fail(work: StepWork, message: string): Promise<void> {
    work.report.status = 'failed';
    work.report.error = clean(message);
    await journal('failed', { clusterId: work.step.clusterId, data: { error: message, oldRevoked: work.oldRevoked } });
    log.error(message, { clusterId: work.step.clusterId });
  }
  async function transition(work: StepWork, status: StepStatus, event: JournalEntry['event']): Promise<void> {
    work.report.status = status;
    await journal(event, {
      clusterId: work.step.clusterId,
      data: {
        newFingerprint: work.report.newFingerprint, oldKeyRef: work.result?.oldKeyRef,
        newKeyRef: work.result?.newKeyRef, oldRevoked: work.oldRevoked,
      },
    });
  }
  function siblingValues(service: ServiceWork): Record<string, string> {
    const values: Record<string, string> = Object.create(null);
    for (const variable of service.variables) if (!variable.sealed && variable.value !== undefined) values[variable.name] = variable.value;
    return values;
  }
  function providerSiblings(work: StepWork, values: Record<string, string>): Record<string, string> {
    if (work.step.provider !== 'aws') return values;
    // AWS's adapter prefers the standard pair. An unrelated AWS_* pair must not
    // override the custom pair belonging to the consumer being rotated.
    const secretName = work.step.consumers.find(c => !c.reference)!.varName;
    const prefix = secretName.replace(/_SECRET_ACCESS_KEY$/, '');
    return Object.fromEntries(Object.entries(values).filter(([name]) =>
      !/_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)$/.test(name)
      || name === secretName || name === `${prefix}_ACCESS_KEY_ID` || name === `${prefix}_SESSION_TOKEN`));
  }
  async function cleanupUnused(work: StepWork): Promise<void> {
    const result = work.result!;
    if (work.atomicRoll || result.oldRevoked) return;
    if (!result.newKeyRef || result.newKeyRef === result.oldKeyRef || !work.provider!.revoke
      || inv.clusters.some(cluster => cluster.fingerprint === work.report.newFingerprint)) {
      warn(work, 'Unused replacement cannot be cleaned up automatically; revoke it manually.');
      return;
    }
    try {
      // A not-yet-propagated AWS key cannot sign its own cleanup request.
      await work.provider!.revoke!(result.newKeyRef, work.ctx!);
      await journal('revoked', { clusterId: work.step.clusterId, data: { keyRef: result.newKeyRef, cleanup: true } });
    } catch (error) {
      if (error instanceof JournalFailure) throw error;
      warn(work, 'Unused replacement cleanup failed; revoke the new key manually.');
    }
  }
  async function readService(ref: ServiceRef): Promise<ServiceWork> {
    const key = serviceKey(ref);
    const cached = services.get(key);
    if (cached) return cached;
    const service: ServiceWork = {
      service: ref, host: deps.hosts[ref.host], variables: [], readFailed: false,
      vars: Object.create(null) as Record<string, string>, steps: new Set(), written: false, activation: 'pending',
    };
    services.set(key, service);
    try {
      if (!service.host) throw new Error('Host unavailable.');
      service.variables = await service.host.readVariables(ref);
      const secretNames = new Set(inv.findings.filter(finding => serviceKey(finding.service) === key).map(finding => finding.varName));
      for (const variable of service.variables) {
        if (!variable.sealed && variable.value !== undefined && (secretNames.has(variable.name) || classify(variable.name, variable.value).isSecret)) register(variable.value);
      }
    } catch { service.readFailed = true; }
    return service;
  }
  function isRailwayShared(service: ServiceRef): boolean {
    return service.host === 'railway' && service.serviceId === '';
  }
  function referenceServiceKeys(work: StepWork, sourceKey: string): string[] {
    const references = work.step.consumers.filter(consumer => {
      if (!consumer.reference || isRailwayShared(consumer.service)) return false;
      let current: Consumer | undefined = consumer;
      const visited = new Set<string>();
      while (current?.reference) {
        const location: string = `${serviceKey(current.service)}\0${current.varName}`;
        if (visited.has(location)) return false;
        visited.add(location);
        current = work.referenceTargets?.get(location);
        if (current && serviceKey(current.service) === sourceKey) return true;
      }
      return false;
    });
    return [...new Set(references.map(consumer => serviceKey(consumer.service)))];
  }
  function cannotConfirmActivation(work: StepWork, key: string): boolean {
    const service = services.get(key)!;
    if (isRailwayShared(service.service)) {
      const references = referenceServiceKeys(work, key);
      return references.length === 0 || references.some(ref => cannotConfirmActivation(work, ref));
    }
    return !redeploy || !service.host?.capabilities.redeploy
      || ['dotenv', 'github-actions', 'fly'].includes(service.service.host)
      || (service.service.host === 'vercel' && service.service.environmentId !== 'production');
  }
  async function referenceIsCurrent(work: StepWork, consumer: Consumer, visited = new Set<string>()): Promise<boolean> {
    const key = serviceKey(consumer.service);
    const location = `${key}\0${consumer.varName}`;
    if (consumer.service.host !== 'railway' || visited.has(location)) return false;
    visited.add(location);
    const service = await readService(consumer.service);
    const variables = service.variables.filter(variable => variable.name === consumer.varName);
    const variable = variables[0];
    if (variables.length !== 1 || !variable || variable.sealed || variable.value === undefined) return false;
    // Inventory stores the resolved secret fingerprint, not the template. Check
    // that the current whole-value reference still resolves inside this cluster.
    const match = /^\s*\$\{\{\s*([^{}]+?)\s*\.\s*([^.\s{}]+)\s*\}\}\s*$/.exec(variable.value);
    if (!match) return false;
    // Railway resolves names at runtime. A saved name can now belong to a
    // different service; refresh the namespace once and fail closed on errors.
    railwayNamespace ??= (async () => {
      try { return await deps.hosts.railway?.listServices() ?? []; }
      catch { return []; }
    })();
    const targets = new Set((await railwayNamespace).filter(candidate => candidate.host === 'railway'
      && candidate.projectId === consumer.service.projectId && candidate.environmentId === consumer.service.environmentId
      && candidate.serviceName === match[1]!.trim()).map(candidate => serviceKey(candidate)));
    if (targets.size !== 1) return false;
    const target = work.step.consumers.find(candidate => targets.has(serviceKey(candidate.service)) && candidate.varName === match[2]);
    if (!target || (target.reference && !await referenceIsCurrent(work, target, visited))) return false;
    work.referenceTargets ??= new Map();
    work.referenceTargets.set(location, target);
    return true;
  }
  function activationFor(work: StepWork, key: string): ServiceWork['activation'] {
    const service = services.get(key)!;
    if (!isRailwayShared(service.service)) return service.activation;
    if (!service.written) return 'skipped';
    const references = referenceServiceKeys(work, key);
    return references.length > 0 && references.every(ref => services.get(ref)!.activation === 'success') ? 'success' : 'unconfirmed';
  }
  async function reportUnwritten(work: StepWork, missing: string[], context = '', bestEffort = false): Promise<void> {
    const locations = missing.map(key => {
      const service = services.get(key)!.service;
      return `${service.host}/${service.serviceName} (${key})`;
    });
    const reason = `URGENT: ROLLED VALUE UNWRITTEN${context} at ${locations.join(', ')}; the old key is already revoked.`;
    // Resolving a callback is not proof of delivery: unattended/no-op callbacks
    // must never suppress the lost-value warning.
    if (!work.revealed && deps.reveal) try {
      work.revealed = await deps.reveal({ clusterId: work.step.clusterId, provider: work.step.provider, hint: work.step.hint, reason: clean(reason) }, work.result!.newValue) === true;
    } catch { work.revealed = false; }
    const message = work.revealed
      ? `${reason} The replacement was revealed; paste it manually and restart/deploy these services.`
      : `${reason} ROLLED VALUE LOST: manual recovery requires the provider dashboard to roll again, then update and restart/deploy these services.`;
    work.report.status = 'failed';
    work.report.error = clean(message);
    try { warn(work, message); } catch { /* failed logging must not suppress recovery metadata */ }
    try { await journal('failed', { clusterId: work.step.clusterId, data: {
      phase: 'value-unwritten', serviceKeys: missing, newFingerprint: work.report.newFingerprint, oldRevoked: true,
      revealed: work.revealed === true, valueLost: work.revealed !== true, error: message,
    } }); } catch (error) { if (!bestEffort) throw error; }
  }
  // Deliver earlier rolls before a late human prompt or after execution stops.
  // Emergency recovery is deliberately independent of failing injected facilities.
  async function preserveRolledValues(reason: 'execution-failure' | 'guided-fallback'): Promise<void> {
    const rolled = works.filter(work => work.atomicRoll && work.result);
    for (const [key, service] of services) {
      const pending = rolled.filter(work => work.services.has(key) && !work.delivered?.has(key));
      if (pending.length === 0) continue;
      const payload: Record<string, string> = Object.create(null);
      const expected = new Map<StepWork, Record<string, string>>();
      // Include previously delivered rolls so recovery never replaces one with a
      // conflicting older batch. Incompatible values require human recovery.
      for (const work of rolled) {
        const additions: Record<string, string> = Object.create(null);
        const direct = work.step.consumers.filter(c => !c.reference && serviceKey(c.service) === key);
        if (direct.length > 0) Object.assign(additions, work.result!.companions);
        for (const c of direct) additions[c.varName] = work.result!.newValue;
        expected.set(work, additions);
        for (const [name, value] of Object.entries(additions)) if (!referenceLocations.has(`${key}\0${name}`)) payload[name] = value;
      }
      for (const work of rolled) for (const c of work.step.consumers) {
        if (!c.reference && serviceKey(c.service) === key && !referenceLocations.has(`${key}\0${c.varName}`)) payload[c.varName] = work.result!.newValue;
      }
      let written = Object.keys(payload).length === 0;
      for (let attempt = 0; !written && attempt < 4; attempt++) {
        try { await service.host!.writeVariables(service.service, payload, { skipDeploy: true }); written = true; }
        catch { /* fixed recovery diagnostic below; never expose adapter errors */ }
        if (!written && attempt < 3) try { await sleep(1_000 * 2 ** attempt); } catch { /* still retry */ }
      }
      if (written) for (const work of pending) {
        if (Object.entries(expected.get(work)!).every(([name, value]) => !referenceLocations.has(`${key}\0${name}`) && payload[name] === value)) {
          work.delivered ??= new Set();
          work.delivered.add(key);
        }
      }
    }
    for (const work of rolled) {
      const missing = [...work.services].filter(key => !work.delivered?.has(key));
      if (missing.length === 0) {
        if (reason === 'guided-fallback') {
          for (const key of work.services) await journal('written', { clusterId: work.step.clusterId, serviceKey: key, data: {
            phase: 'before-guided-fallback', newFingerprint: work.report.newFingerprint, oldRevoked: true,
          } });
          continue;
        }
        try { warn(work, `URGENT: Rolled replacement was preserved after execution stopped; confirm activation or manually restart/deploy: ${[...work.services].join(', ')}.`); }
        catch { /* a broken logger must not undo successful recovery */ }
        continue;
      }
      await reportUnwritten(work, missing, reason === 'guided-fallback' ? ' before guided rotation' : ' after execution failure', true);
    }
  }
  try {
    await journal('plan-start', { data: { dryRun, steps: works.length } });

    // Preflight the entire plan before creating credentials, checking secondary copies too.
    for (const work of works) {
      const cluster = inv.clusters.find(candidate => candidate.id === work.step.clusterId);
      const locations = new Set(work.step.consumers.map(c => `${serviceKey(c.service)}\0${c.varName}`));
      if (!cluster || locations.size === 0 || cluster.consumers.some(c => !locations.has(`${serviceKey(c.service)}\0${c.varName}`))
        || work.step.consumers.some(c => !cluster.consumers.some(original => serviceKey(original.service) === serviceKey(c.service)
          && original.varName === c.varName && !!original.reference === !!c.reference))) {
        work.report.status = 'skipped';
        warn(work, 'Plan does not cover the inventory cluster completely; rebuild the plan.');
        continue;
      }
      let stale = false;
      let unreadable = false;
      for (const consumer of work.step.consumers) {
        const service = await readService(consumer.service);
        if (service.readFailed) { unreadable = true; continue; }
        const variable = service.variables.find(candidate => candidate.name === consumer.varName);
        if (!variable) { stale = true; continue; }
        // A reference contains a template, not the rendered secret fingerprint.
        if (consumer.reference) {
          if (!await referenceIsCurrent(work, consumer)) stale = true;
          continue;
        }
        const value = variable.sealed ? undefined : variable.value;
        if (consumer.fingerprint !== null && (value === undefined || fingerprint(value, deps.fingerprintKey) !== consumer.fingerprint)) {
          stale = true;
        }
        if (cluster.fingerprint !== null && value !== undefined && fingerprint(value, deps.fingerprintKey) !== cluster.fingerprint) stale = true;
        if (value !== undefined && work.oldValue === undefined) {
          work.oldValue = value;
          work.contextService = serviceKey(consumer.service);
        }
      }
      if (unreadable) { await fail(work, 'Unable to read every consumer service; no credentials were changed.'); continue; }
      if (stale) {
        work.report.status = 'skipped';
        warn(work, 'Stale inventory: a consumer value changed or is missing; scan again before rotating.');
        continue;
      }
      if (work.step.provider === 'aws') {
        const writable = work.step.consumers.filter(consumer => !consumer.reference);
        const names = new Set(writable.map(consumer => consumer.varName));
        const secretName = writable[0]?.varName ?? '';
        const idName = secretName.replace(/_SECRET_ACCESS_KEY$/, '_ACCESS_KEY_ID');
        const accessIds = writable.map(c => siblingValues(services.get(serviceKey(c.service))!)[idName]);
        if (names.size !== 1 || !secretName.endsWith('_SECRET_ACCESS_KEY') || accessIds.some(id => !id || id !== accessIds[0])) {
          await fail(work, 'AWS credential pair names or access key IDs are missing or inconsistent across consumers; rotate complete matching pairs.');
          continue;
        }
      }
      work.contextService ??= serviceKey(work.step.consumers[0]!.service);
      work.ctx = {
        ...deps.providerCtx,
        credentials: { ...deps.providerCtx.credentials },
        siblingVars: providerSiblings(work, { ...deps.providerCtx.siblingVars, ...siblingValues(services.get(work.contextService)!) }),
        log: safeLogger(deps.providerCtx.log),
      };
      work.ready = true;
      for (const consumer of work.step.consumers) {
        if (consumer.reference) {
          report.diff.push(`Redeploy reference ${serviceKey(consumer.service)}: ${consumer.varName}`);
          continue;
        }
        report.diff.push(`${serviceKey(consumer.service)}: ${consumer.varName}: ${consumer.hint ?? work.step.hint ?? '(sealed)'} → (new)`);
      }
    }

    if (dryRun) {
      for (const [key, service] of services) {
        if (!works.some(work => work.ready && work.services.has(key))) continue;
        if (redeploy && service.host?.capabilities.redeploy && !isRailwayShared(service.service)) report.diff.push(`Redeploy ${key}`);
        report.deployments.push({ serviceKey: key, deploymentId: null, state: 'skipped' });
      }
    } else {
      // Resolve effective methods before any provider mutation: sealed/missing-rotate
      // fallbacks can require a person even when the plan labels them automatic.
      for (const work of works) {
        if (!work.ready) continue;
        try {
          const provider = deps.providers(work.step.provider);
          work.provider = provider;
          work.guided = work.step.provider === 'encryption-key' || work.step.method === 'guided' || provider.method === 'guided' || !provider.rotate
            || (work.oldValue === undefined && (work.step.method === 'auto' || work.step.method === 'atomic-roll'));
          work.atomicRoll = !work.guided && (work.step.method === 'atomic-roll' || provider.method === 'atomic-roll');
          if (work.atomicRoll) {
            let blocked = blockedBySealed(work);
            if (!deps.reveal) { warn(work, 'atomic roll needs an interactive run'); blocked = true; }
            if (revoke === 'never') { warn(work, 'Atomic roll skipped: revoke is never, but rolling would immediately revoke the old key.'); blocked = true; }
            const unconfirmed = [...work.services].filter(key => cannotConfirmActivation(work, key));
            if (unconfirmed.length > 0) {
              if (!revokeUnconfirmed) {
                warn(work, `Atomic roll skipped: activation would be unconfirmed for ${unconfirmed.join(', ')}; revokeUnconfirmed must explicitly accept this risk.`);
                blocked = true;
              } else warn(work, `Atomic roll will revoke the old key despite unconfirmed activation because revokeUnconfirmed is enabled: ${unconfirmed.join(', ')}.`);
            }
            if (blocked) { work.report.status = 'skipped'; work.ready = false; }
          } else if (work.step.provider !== 'encryption-key' && !allowGenerate && (work.step.method === 'generate' || provider.method === 'generate')) {
            work.report.status = 'skipped';
            work.ready = false;
            warn(work, 'self-generated secret: rotate it deliberately; sessions signed with it become invalid');
          }
        } catch { work.ready = false; await fail(work, 'Unable to prepare the replacement credential; no consumer was changed.'); }
      }
      const preparation = [
        ...works.filter(work => work.ready && work.guided),
        ...works.filter(work => work.ready && !work.guided && !work.atomicRoll),
        ...works.filter(work => work.ready && work.atomicRoll),
      ];
      function invalidGuidedValue(work: StepWork, value: string): boolean {
        if (work.step.provider !== 'unknown' && work.step.consumers.some(c => !c.reference && classify(c.varName, value).provider !== work.step.provider)) return true;
        const text = value.trim();
        if (!text || (work.oldValue !== undefined && text !== work.oldValue.trim() && work.oldValue.trim().startsWith(text))) return true;
        const pem = /-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY)-----/.exec(text);
        if (pem && !text.includes(`-----END ${pem[1]}-----`)) return true;
        const oldPem = work.oldValue && /-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY)-----/.exec(work.oldValue);
        if (oldPem && (!pem || !text.includes(`-----END ${pem![1]}-----`))) return true;
        // Name-based classification alone can accept a truncated service-account JSON.
        if (work.oldValue && /^[\s]*[\[{]/.test(work.oldValue)) {
          let wasJson = false;
          try { JSON.parse(work.oldValue); wasJson = true; } catch { /* not JSON */ }
          if (wasJson) try { JSON.parse(value); } catch { return true; }
        }
        return false;
      }
      async function guidedReplacement(work: StepWork, permissionsFallback = false): Promise<RotationResult | null> {
        const provider = work.provider!;
        if (work.oldValue === undefined) warn(work, 'Old value is sealed; guided rotation is required and automatic old-key revocation may be unavailable.');
        const value = await deps.prompt({
          clusterId: work.step.clusterId, provider: work.step.provider, hint: work.step.hint,
          guidance: provider.guidance(), consumers: work.step.consumers,
        });
        if (value === null) {
          work.report.status = 'skipped';
          if (permissionsFallback) warn(work, "automatic rotation would change this key's permissions; rotate it by hand");
          return null;
        }
        register(value);
        if (invalidGuidedValue(work, value)) {
          work.report.status = 'skipped';
          warn(work, 'Pasted replacement has a different provider or is incomplete/truncated; no consumer was changed.');
          return null;
        }
        // A pasted replacement must never become the OLD ref.
        const oldKeyRef = work.oldValue !== undefined && provider.resolveKeyRef ? await provider.resolveKeyRef(work.oldValue, work.ctx!) : null;
        return { newValue: value, oldKeyRef, newKeyRef: null, oldRevoked: false };
      }
      for (const work of preparation) {
        work.ready = false;
        try {
          const provider = work.provider!;
          const ctx = work.ctx!;
          let result: RotationResult;
          if (work.guided) {
            const replacement = await guidedReplacement(work);
            if (!replacement) continue;
            result = replacement;
          } else {
            try { result = await provider.rotate!(work.oldValue ?? '', ctx); }
            catch (error) {
              if (typeof error !== 'object' || error === null || !('code' in error) || error.code !== 'GUIDED_ROTATION_REQUIRED') throw error;
              // This code guarantees rotate rejected before mutation, even for
              // an adapter or stale plan that advertised an atomic roll.
              work.guided = true;
              work.atomicRoll = false;
              const atomicRollsAlreadyRan = works.some(previous => previous.atomicRoll && previous.result);
              if (atomicRollsAlreadyRan) await preserveRolledValues('guided-fallback');
              await journal('created', { clusterId: work.step.clusterId, data: {
                phase: 'guided-fallback', code: 'GUIDED_ROTATION_REQUIRED', atomicRollsAlreadyRan,
              } });
              const replacement = await guidedReplacement(work, true);
              if (!replacement) continue;
              result = replacement;
            }
            // Save before invoking any injected registration/logging/journal code.
            work.result = result;
            work.atomicRoll ||= result.oldRevoked;
            work.oldRevoked = result.oldRevoked || work.atomicRoll;
            register(result.newValue);
          }
          // No log or journal call may precede registering every returned value.
          for (const [name, value] of Object.entries(result.companions ?? {})) register(value, classify(name, value).isSecret);
          work.result = result;
          work.atomicRoll ||= result.oldRevoked;
          work.oldRevoked = result.oldRevoked || work.atomicRoll;
          if (result.notes) warn(work, result.notes);
          if (work.step.provider === 'aws') {
            const idName = work.step.consumers.find(c => !c.reference)!.varName.replace(/_SECRET_ACCESS_KEY$/, '_ACCESS_KEY_ID');
            const oldId = ctx.siblingVars?.[idName];
            const newId = result.companions?.[idName];
            for (const id of [oldId, newId]) if (id && /^(?:AKIA|ASIA)[A-Z0-9]{16}$/.test(id) && !sensitiveValues.has(id)) publicKeyRefs.add(id);
          }
          work.report.newFingerprint = fingerprint(result.newValue, deps.fingerprintKey);
          work.report.oldKeyRef = result.oldKeyRef;
          work.report.newKeyRef = result.newKeyRef;
          const newSiblings = { ...ctx.siblingVars, ...result.companions };
          for (const consumer of work.step.consumers) if (!consumer.reference && serviceKey(consumer.service) === work.contextService) newSiblings[consumer.varName] = result.newValue;
          // Verification uses new companions; cleanup authenticates using the old context.
          const newCtx: ProviderContext = { ...ctx, siblingVars: providerSiblings(work, newSiblings) };
          work.newCtx = newCtx;
          await transition(work, 'created', 'created');
          log.info('Replacement credential created.', { clusterId: work.step.clusterId });
          if (work.oldRevoked) warn(work, 'Provider rolled the credential atomically; the old key is already revoked.');
          if (result.newValue.length === 0 || inv.clusters.some(cluster => cluster.fingerprint === work.report.newFingerprint)) {
            if (work.atomicRoll) warn(work, 'URGENT: Rolled replacement is empty or reuses an inventoried credential; attempting delivery because the old key is already revoked.');
            else {
              await fail(work, 'Replacement is empty or reuses an inventoried credential; rotation stopped.');
              await cleanupUnused(work);
              continue;
            }
          }
          let verified = false;
          for (let attempt = 0; attempt <= verifyRetries; attempt++) {
            let definitive = false;
            try {
              const verification = await provider.verify(result.newValue, newCtx);
              verified = verification.ok;
              definitive = verification.status === 401;
            } catch { /* fixed diagnostic below */ }
            if (verified || definitive || attempt === verifyRetries) break;
            await sleep(2_000 * 2 ** attempt);
          }
          if (!verified) {
            if (work.atomicRoll) warn(work, 'URGENT: Rolled credential verification failed; writing it anyway because the old key is already revoked.');
            else {
              await fail(work, 'New credential verification failed; no consumer was changed.');
              await cleanupUnused(work);
              continue;
            }
          }
          if (work.guided && provider.resolveKeyRef) {
            try { result.newKeyRef = await provider.resolveKeyRef(result.newValue, newCtx); } catch { warn(work, 'The new key reference could not be resolved for future monitoring.'); }
            work.report.newKeyRef = result.newKeyRef;
          }
          if (verified) await transition(work, 'verified', 'verified');
          work.ready = true;
        } catch (error) {
          if (error instanceof JournalFailure || error instanceof RotationAbortedError) throw error;
          if (work.atomicRoll && work.result) {
            work.ready = true;
            warn(work, 'URGENT: Rolled credential preparation could not finish; attempting delivery because the old key is already revoked.');
            continue;
          }
          await fail(work, 'Unable to prepare the replacement credential; no consumer was changed.');
        }
      }

      function populateBatches(): Set<StepWork> {
        const conflicts = new Set<StepWork>();
        for (const service of services.values()) { service.vars = Object.create(null) as Record<string, string>; service.steps.clear(); }
        for (const work of works) {
          if (!work.ready) continue;
          const result = work.result!;
          for (const key of work.services) {
            const service = services.get(key)!;
            service.steps.add(work);
            const additions = additionsFor(work, key);
            if (work.step.consumers.some(c => !c.reference && serviceKey(c.service) === key
              && Object.hasOwn(result.companions ?? {}, c.varName) && result.companions![c.varName] !== result.newValue)) conflicts.add(work);
            for (const [name, value] of Object.entries(additions)) {
              if (referenceLocations.has(`${key}\0${name}`)) { conflicts.add(work); continue; }
              if (Object.hasOwn(service.vars, name) && service.vars[name] !== value) {
                conflicts.add(work);
                for (const owner of service.steps) {
                  if (Object.hasOwn(additionsFor(owner, key), name)) conflicts.add(owner);
                }
              }
              service.vars[name] = value;
            }
          }
        }
        return conflicts;
      }
      const conflicts = populateBatches();
      for (const work of conflicts) {
        if (work.atomicRoll) {
          warn(work, 'URGENT: A write conflict affects a rolled credential; preserving its replacement and retrying delivery.');
          continue;
        }
        work.ready = false;
        await fail(work, 'Conflicting replacement values target the same service variable; no values for this step were written.');
        await cleanupUnused(work);
      }
      if (conflicts.size > 0) populateBatches();
      // Primary rolled values take precedence over companions of other rolls.
      for (const work of works) if (work.ready && work.atomicRoll) for (const c of work.step.consumers) {
        const key = serviceKey(c.service);
        if (!c.reference && !referenceLocations.has(`${key}\0${c.varName}`)) services.get(key)!.vars[c.varName] = work.result!.newValue;
      }
      function additionsFor(work: StepWork, key: string): Record<string, string> {
        const additions: Record<string, string> = Object.create(null);
        const direct = work.step.consumers.filter(c => !c.reference && serviceKey(c.service) === key);
        if (direct.length > 0) Object.assign(additions, work.result!.companions);
        for (const c of direct) additions[c.varName] = work.result!.newValue;
        return additions;
      }
      async function valueUnwritten(work: StepWork): Promise<void> {
        // The shared journal event union has no value-unwritten event; record it as
        // an explicit failure phase without ever serializing the replacement.
        await reportUnwritten(work, [...work.unwritten!]);
      }
      for (const [key, service] of services) {
        if (service.steps.size === 0) continue;
        const atomics = [...service.steps].filter(work => work.atomicRoll && Object.keys(additionsFor(work, key)).length > 0);
        // A companion must never replace its own atomic primary value. Other
        // incompatible atomic additions remain visible as unwritten recovery work.
        const mismatched = atomics.filter(work => Object.entries(additionsFor(work, key)).some(([name, value]) => service.vars[name] !== value));
        let written = Object.keys(service.vars).length === 0;
        const attempts = atomics.length > 0 ? 4 : 1;
        for (let attempt = 0; !written && attempt < attempts; attempt++) {
          try {
            await service.host!.writeVariables(service.service, service.vars, { skipDeploy: true });
            written = true;
          } catch { /* retry atomically rolled credentials before giving up */ }
          if ((!written || mismatched.length > 0) && attempt < attempts - 1) {
            await sleep(1_000 * 2 ** attempt);
            // Conflicting atomic outputs cannot all inhabit one variable, but still
            // retry the surviving batch before handing recovery to a human.
            if (mismatched.length > 0) written = false;
          }
        }
        for (const work of atomics) if (!written || mismatched.includes(work)) {
          work.unwritten ??= new Set();
          work.unwritten.add(key);
        }
        if (!written) {
          for (const work of service.steps) if (!work.atomicRoll) await fail(work, 'A consumer service write failed; the old key will be retained.');
          await journal('failed', { serviceKey: key, data: { phase: 'write', partialWritePossible: true } });
          continue;
        }
        service.written = true;
        for (const work of service.steps) if (work.atomicRoll && !mismatched.includes(work)) {
          work.delivered ??= new Set();
          work.delivered.add(key);
        }
        for (const work of service.steps) await journal('written', {
          clusterId: work.step.clusterId, serviceKey: key,
          data: { newFingerprint: work.report.newFingerprint, variableNames: Object.keys(service.vars) },
        });
        log.info('Service variables written.', { serviceKey: key });
      }
      for (const work of works) if (work.unwritten?.size) await valueUnwritten(work);
      for (const work of works) if (work.ready && work.report.status !== 'failed') work.report.status = 'written';

      async function revokeOld(work: StepWork): Promise<void> {
        if (!work.ready || work.report.status === 'failed' || ![...work.services].every(key => services.get(key)!.written)) return;
        if (work.report.status === 'revoked') return;
        const result = work.result!;
        if (work.oldRevoked) { await transition(work, 'revoked', 'revoked'); return; }
        if (revoke === 'never') return;
        if (blockedBySealed(work)) return;
        if (!result.oldKeyRef || !work.provider!.revoke) {
          warn(work, 'Old key could not be identified or revoked automatically; revoke it manually after confirming every consumer.');
          return;
        }
        try {
          const contextService = services.get(work.contextService!)!;
          const ctx: ProviderContext = { ...work.ctx!, siblingVars: providerSiblings(work, { ...work.ctx!.siblingVars, ...contextService.vars }) };
          await work.provider!.revoke!(result.oldKeyRef, ctx);
          work.oldRevoked = true;
          await transition(work, 'revoked', 'revoked');
          log.info('Old credential revoked.', { clusterId: work.step.clusterId });
        } catch (error) {
          if (error instanceof JournalFailure) throw error;
          await fail(work, 'Old credential revocation failed; check the provider before retrying.');
        }
      }
      if (revoke === 'immediately') for (const work of works) await revokeOld(work);

      async function deployService(key: string, service: ServiceWork): Promise<void> {
        if (service.steps.size === 0) return;
        let deploymentId: string | null = null;
        let state: ServiceWork['activation'] = 'failed';
        let timedOut = false;
        if (!service.written) state = 'skipped';
        else if (!redeploy || !service.host!.capabilities.redeploy) state = 'unconfirmed';
        else try {
          deploymentId = await service.host!.redeploy(service.service);
          await journal('redeploy', { serviceKey: key, data: { deploymentId } });
          if (deploymentId === null) state = 'unconfirmed';
          else {
            const start = now().getTime();
            let waited = 0;
            while (true) {
              const polled = await service.host!.deploymentStatus(service.service, deploymentId);
              if (polled !== 'pending') { state = polled; break; }
              const elapsed = Math.max(0, now().getTime() - start, waited);
              if (elapsed >= timeout) { timedOut = true; break; }
              const delay = Math.min(interval, timeout - elapsed);
              await sleep(delay);
              waited += delay;
            }
          }
        } catch (error) { if (error instanceof JournalFailure) throw error; }
        service.activation = state;
        report.deployments.push({ serviceKey: key, deploymentId, state });
        await journal('deploy-result', { serviceKey: key, data: { deploymentId, state, timedOut } });
        if (state === 'failed') for (const work of service.steps) {
          warn(work, `Consumer deployment failed: ${service.service.host}/${service.service.serviceName} (${key})${timedOut ? ' (timed out)' : ''}; activation failed.`);
          await fail(work, timedOut ? 'Consumer deployment timed out.' : 'Consumer deployment failed.');
          if (work.oldRevoked) {
            warn(work, 'The old credential may already be revoked; restore service using the replacement.');
          }
        }
        if (state === 'unconfirmed') for (const work of service.steps) {
          warn(work, `Consumer activation unconfirmed: ${service.service.host}/${service.service.serviceName} (${key}) requires a manual restart/next deploy.`);
        }
      }
      // Fixed worker count bounds both starting deployments and polling them.
      const deploymentServices = [...services].filter(([, service]) => !isRailwayShared(service.service));
      let nextService = 0;
      let deploymentStopped = false;
      const deploymentTasks = Array.from({ length: Math.min(8, deploymentServices.length) }, async () => {
        while (!deploymentStopped && nextService < deploymentServices.length) {
          const [key, service] = deploymentServices[nextService++]!;
          try { await deployService(key, service); }
          catch (error) { deploymentStopped = true; throw error; }
        }
      });
      const deploymentResults = await Promise.allSettled(deploymentTasks);
      for (const result of deploymentResults) if (result.status === 'rejected') throw result.reason;
      // Shared variables activate through their referring services. Derive each
      // step independently so an unrelated shared key cannot block revocation.
      for (const [key, service] of services) {
        if (!isRailwayShared(service.service) || service.steps.size === 0) continue;
        service.activation = !service.written ? 'skipped'
          : [...service.steps].every(work => activationFor(work, key) === 'success') ? 'success' : 'unconfirmed';
        report.deployments.push({ serviceKey: key, deploymentId: null, state: service.activation });
        await journal('deploy-result', { serviceKey: key, data: { deploymentId: null, state: service.activation, shared: true } });
        for (const work of service.steps) if (activationFor(work, key) === 'unconfirmed') {
          warn(work, `Consumer activation unconfirmed: ${service.service.host}/${service.service.serviceName} (${key}) requires at least one reference service and successful deployments of every reference service.`);
        }
      }
      for (const work of works) {
        if (!work.ready || work.report.status === 'failed') continue;
        const deployed = [...work.services].every(key => activationFor(work, key) === 'success');
        const activatedOrUnconfirmed = [...work.services].every(key => ['success', 'unconfirmed'].includes(activationFor(work, key)));
        if (deployed) {
          if (work.report.status !== 'revoked') work.report.status = 'deployed';
          if (revoke === 'after-deploy' || work.oldRevoked) await revokeOld(work);
        } else {
          if (work.oldRevoked) warn(work, 'URGENT: Activation remains unconfirmed and the old key is already revoked; complete the listed manual restarts/next deploys.');
          else if (revoke === 'after-deploy' && revokeUnconfirmed && activatedOrUnconfirmed) {
            warn(work, 'Revoking the old key despite unconfirmed activation because revokeUnconfirmed is enabled; complete the listed manual restarts/next deploys.');
            await journal('deploy-result', { clusterId: work.step.clusterId, data: { state: 'unconfirmed', revokeUnconfirmed: true } });
            await revokeOld(work);
          } else if (!work.oldRevoked && work.report.status !== 'revoked') {
            warn(work, 'Activation is unconfirmed; the old key is retained for the services needing a manual restart/next deploy.');
          }
        }
      }
    }
    report.finishedAt = now().toISOString();
    await journal('plan-end', { data: { dryRun, steps: report.steps } });
    return sanitize(report, true);
  } catch (error) {
    if (error instanceof RotationAbortedError) {
      // Cancellation must bypass cleanup and emergency host delivery as well:
      // after Ctrl-C no provider or host may be mutated again.
      for (const work of works) {
        if (['pending', 'created', 'verified'].includes(work.report.status)) {
          work.ready = false;
          work.report.status = 'skipped';
          warn(work, 'Rotation aborted by the operator; no further changes were made.');
          if (work.result) warn(work, work.atomicRoll
            ? 'The old key was already rolled before cancellation; confirm the previously staged replacement and restart/deploy manually.'
            : 'A replacement was prepared before cancellation; revoke the unused replacement manually.');
        }
      }
      report.finishedAt = now().toISOString();
      await journal('plan-end', { data: { dryRun, aborted: true, steps: report.steps } });
      return sanitize(report, true);
    }
    await preserveRolledValues('execution-failure');
    throw error;
  }
}
