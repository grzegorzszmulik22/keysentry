import { classify, fingerprint, serviceKey } from '../core/index.js';
import type {
  GuidedPrompt, HostAdapter, HostId, Inventory, Journal, JournalEntry, Logger, PlanStep,
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
}

export interface RotateOptions {
  dryRun: boolean;
  revoke: 'after-deploy' | 'immediately' | 'never';
  redeploy: boolean;
  deployTimeoutMs: number;
  pollIntervalMs: number;
}

interface ServiceWork {
  service: ServiceRef;
  host?: HostAdapter;
  variables: RawVariable[];
  readFailed: boolean;
  vars: Record<string, string>;
  steps: Set<StepWork>;
  written: boolean;
  deploymentSucceeded: boolean;
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
    const secretName = work.step.consumers[0]!.varName;
    const prefix = secretName.replace(/_SECRET_ACCESS_KEY$/, '');
    return Object.fromEntries(Object.entries(values).filter(([name]) =>
      !/_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)$/.test(name)
      || name === secretName || name === `${prefix}_ACCESS_KEY_ID` || name === `${prefix}_SESSION_TOKEN`));
  }
  async function cleanupUnused(work: StepWork): Promise<void> {
    const result = work.result!;
    if (result.oldRevoked) return;
    if (!result.newKeyRef || result.newKeyRef === result.oldKeyRef || !work.provider!.revoke
      || inv.clusters.some(cluster => cluster.fingerprint === work.report.newFingerprint)) {
      warn(work, 'Unused replacement cannot be cleaned up automatically; revoke it manually.');
      return;
    }
    try {
      await work.provider!.revoke!(result.newKeyRef, work.newCtx!);
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
      vars: Object.create(null) as Record<string, string>, steps: new Set(), written: false, deploymentSucceeded: false,
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
  await journal('plan-start', { data: { dryRun, steps: works.length } });

  // Preflight the entire plan before creating credentials, checking secondary copies too.
  for (const work of works) {
    const cluster = inv.clusters.find(candidate => candidate.id === work.step.clusterId);
    const locations = new Set(work.step.consumers.map(c => `${serviceKey(c.service)}\0${c.varName}`));
    if (!cluster || locations.size === 0 || cluster.consumers.some(c => !locations.has(`${serviceKey(c.service)}\0${c.varName}`))
      || work.step.consumers.some(c => !cluster.consumers.some(original => serviceKey(original.service) === serviceKey(c.service) && original.varName === c.varName))) {
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
      const names = new Set(work.step.consumers.map(consumer => consumer.varName));
      const secretName = work.step.consumers[0]!.varName;
      const idName = secretName.replace(/_SECRET_ACCESS_KEY$/, '_ACCESS_KEY_ID');
      const accessIds = [...work.services].map(key => siblingValues(services.get(key)!)[idName]);
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
      report.diff.push(`${serviceKey(consumer.service)}: ${consumer.varName}: ${consumer.hint ?? work.step.hint ?? '(sealed)'} → (new)`);
    }
  }

  if (dryRun) {
    for (const [key, service] of services) {
      if (!works.some(work => work.ready && work.services.has(key))) continue;
      if (redeploy && service.host?.capabilities.redeploy) report.diff.push(`Redeploy ${key}`);
      report.deployments.push({ serviceKey: key, deploymentId: null, state: 'skipped' });
    }
  } else {
    for (const work of works) {
      if (!work.ready) continue;
      work.ready = false;
      try {
        const provider = deps.providers(work.step.provider);
        work.provider = provider;
        const ctx = work.ctx!;
        const needsGuidance = work.step.method === 'guided' || provider.method === 'guided' || !provider.rotate
          || (work.oldValue === undefined && (work.step.method === 'auto' || work.step.method === 'atomic-roll'));
        let result: RotationResult;
        if (needsGuidance) {
          if (work.oldValue === undefined) warn(work, 'Old value is sealed; guided rotation is required and automatic old-key revocation may be unavailable.');
          const value = await deps.prompt({
            clusterId: work.step.clusterId, provider: work.step.provider, hint: work.step.hint,
            guidance: provider.guidance(), consumers: work.step.consumers,
          });
          if (value === null) { work.report.status = 'skipped'; continue; }
          register(value);
          // Resolve these independently: a pasted replacement must never become the OLD ref.
          const oldKeyRef = work.oldValue !== undefined && provider.resolveKeyRef ? await provider.resolveKeyRef(work.oldValue, ctx) : null;
          result = { newValue: value, oldKeyRef, newKeyRef: null, oldRevoked: false };
        } else {
          result = await provider.rotate!(work.oldValue ?? '', ctx);
          register(result.newValue);
        }
        // No log or journal call may precede registering every returned value.
        for (const [name, value] of Object.entries(result.companions ?? {})) register(value, classify(name, value).isSecret);
        work.result = result;
        work.oldRevoked = result.oldRevoked;
        if (work.step.provider === 'aws') {
          const idName = work.step.consumers[0]!.varName.replace(/_SECRET_ACCESS_KEY$/, '_ACCESS_KEY_ID');
          const oldId = ctx.siblingVars?.[idName];
          const newId = result.companions?.[idName];
          for (const id of [oldId, newId]) if (id && /^(?:AKIA|ASIA)[A-Z0-9]{16}$/.test(id) && !sensitiveValues.has(id)) publicKeyRefs.add(id);
        }
        work.report.newFingerprint = fingerprint(result.newValue, deps.fingerprintKey);
        work.report.oldKeyRef = result.oldKeyRef;
        work.report.newKeyRef = result.newKeyRef;
        const newSiblings = { ...ctx.siblingVars, ...result.companions };
        for (const consumer of work.step.consumers) if (serviceKey(consumer.service) === work.contextService) newSiblings[consumer.varName] = result.newValue;
        // Verification and cleanup must authenticate paired credentials using the NEW companions.
        const newCtx: ProviderContext = { ...ctx, siblingVars: providerSiblings(work, newSiblings) };
        work.newCtx = newCtx;
        await transition(work, 'created', 'created');
        log.info('Replacement credential created.', { clusterId: work.step.clusterId });
        if (result.oldRevoked) warn(work, 'Provider rolled the credential atomically; the old key is already revoked.');
        if (result.newValue.length === 0 || inv.clusters.some(cluster => cluster.fingerprint === work.report.newFingerprint)) {
          await fail(work, 'Replacement is empty or reuses an inventoried credential; rotation stopped.');
          await cleanupUnused(work);
          continue;
        }
        let verified = false;
        try { verified = (await provider.verify(result.newValue, newCtx)).ok; } catch { /* fixed diagnostic below */ }
        if (!verified) {
          await fail(work, 'New credential verification failed; no consumer was changed.');
          await cleanupUnused(work);
          continue;
        }
        if (needsGuidance && provider.resolveKeyRef) {
          try { result.newKeyRef = await provider.resolveKeyRef(result.newValue, newCtx); } catch { warn(work, 'The new key reference could not be resolved for future monitoring.'); }
          work.report.newKeyRef = result.newKeyRef;
        }
        await transition(work, 'verified', 'verified');
        work.ready = true;
      } catch (error) {
        if (error instanceof JournalFailure) throw error;
        await fail(work, 'Unable to prepare the replacement credential; no consumer was changed.');
      }
    }

    function populateBatches(): Set<StepWork> {
      const conflicts = new Set<StepWork>();
      for (const service of services.values()) { service.vars = Object.create(null) as Record<string, string>; service.steps.clear(); }
      for (const work of works) {
        if (!work.ready) continue;
        const result = work.result!;
        for (const consumer of work.step.consumers) {
          const service = services.get(serviceKey(consumer.service))!;
          const additions = { ...result.companions, [consumer.varName]: result.newValue };
          if (result.companions && Object.hasOwn(result.companions, consumer.varName) && result.companions[consumer.varName] !== result.newValue) conflicts.add(work);
          for (const [name, value] of Object.entries(additions)) {
            if (Object.hasOwn(service.vars, name) && service.vars[name] !== value) {
              conflicts.add(work);
              for (const owner of service.steps) {
                if (owner.step.consumers.some(c => serviceKey(c.service) === serviceKey(consumer.service) && c.varName === name)
                  || Object.hasOwn(owner.result?.companions ?? {}, name)) conflicts.add(owner);
              }
            }
            service.vars[name] = value;
          }
          service.steps.add(work);
        }
      }
      return conflicts;
    }
    const conflicts = populateBatches();
    for (const work of conflicts) {
      work.ready = false;
      await fail(work, 'Conflicting replacement values target the same service variable; no values for this step were written.');
      await cleanupUnused(work);
    }
    if (conflicts.size > 0) populateBatches();
    for (const [key, service] of services) {
      if (service.steps.size === 0) continue;
      try { await service.host!.writeVariables(service.service, service.vars, { skipDeploy: true }); }
      catch {
        for (const work of service.steps) await fail(work, 'A consumer service write failed; the old key will be retained.');
        await journal('failed', { serviceKey: key, data: { phase: 'write', partialWritePossible: true } });
        continue;
      }
      service.written = true;
      for (const work of service.steps) await journal('written', {
        clusterId: work.step.clusterId, serviceKey: key,
        data: { newFingerprint: work.report.newFingerprint, variableNames: Object.keys(service.vars) },
      });
      log.info('Service variables written.', { serviceKey: key });
    }
    for (const work of works) if (work.ready && work.report.status !== 'failed') work.report.status = 'written';

    async function revokeOld(work: StepWork): Promise<void> {
      if (!work.ready || work.report.status === 'failed' || ![...work.services].every(key => services.get(key)!.written)) return;
      if (work.report.status === 'revoked') return;
      const result = work.result!;
      if (result.oldRevoked) { await transition(work, 'revoked', 'revoked'); return; }
      if (revoke === 'never') return;
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

    for (const [key, service] of services) {
      if (service.steps.size === 0) continue;
      if (!service.written || !redeploy || !service.host!.capabilities.redeploy) {
        service.deploymentSucceeded = service.written && !service.host!.capabilities.redeploy;
        report.deployments.push({ serviceKey: key, deploymentId: null, state: 'skipped' });
        continue;
      }
      let deploymentId: string | null = null;
      let state: 'success' | 'failed' | 'skipped' = 'failed';
      let timedOut = false;
      try {
        deploymentId = await service.host!.redeploy(service.service);
        await journal('redeploy', { serviceKey: key, data: { deploymentId } });
        if (deploymentId === null) state = 'skipped';
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
      service.deploymentSucceeded = state === 'success';
      report.deployments.push({ serviceKey: key, deploymentId, state });
      await journal('deploy-result', { serviceKey: key, data: { deploymentId, state, timedOut } });
      if (state === 'failed') for (const work of service.steps) {
        await fail(work, timedOut ? 'Consumer deployment timed out.' : 'Consumer deployment failed.');
        if (work.oldRevoked) {
          warn(work, 'The old credential may already be revoked; restore service using the replacement.');
        }
      }
    }
    for (const work of works) {
      if (!work.ready || work.report.status === 'failed') continue;
      const deployed = [...work.services].every(key => services.get(key)!.deploymentSucceeded);
      if (deployed) {
        if (work.report.status !== 'revoked') work.report.status = 'deployed';
        if (revoke === 'after-deploy' || work.result!.oldRevoked) await revokeOld(work);
      } else {
        warn(work, 'A required deployment was not confirmed; the old key is retained unless it was already revoked.');
      }
    }
  }
  report.finishedAt = now().toISOString();
  await journal('plan-end', { data: { dryRun, steps: report.steps } });
  return sanitize(report, true);
}
