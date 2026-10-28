import { buildInventory, fingerprint, isPublicGoogleKeyStep, serviceKey } from '../core/index.js';
import type { EngineDeps, RotateOptions } from './engine.js';
import { crash, createRecoverySafety, isCrash, unresolvedOrphans } from './recovery.js';
import { withStopChecks } from './stop.js';
import type { Inventory, JournalEntry, PlanStep, ProviderAdapter, ProviderContext, RawVariable, RotationPlan, RotationReport, ServiceRef, StepReport } from '../types.js';

interface FinishInput {
  plan: RotationPlan;
  inventory: Inventory;
  entries: JournalEntry[];
}

function metadata(entries: JournalEntry[], clusterId: string): Record<string, unknown> {
  const data: Record<string, unknown> = {};
  for (const entry of entries) {
    if (entry.clusterId !== clusterId || !['created', 'value-stored', 'verified', 'revoked'].includes(entry.event)
      || entry.data?.cleanup === true || entry.data?.undo === true) continue;
    Object.assign(data, entry.data);
  }
  return data;
}

function ended(entries: JournalEntry[], clusterId: string): boolean {
  return entries.some(entry => entry.clusterId === clusterId && (entry.event === 'undo'
    || (entry.event === 'revoked' && entry.data?.cleanup !== true && entry.data?.undo !== true)));
}

function unfinishedUndo(entries: JournalEntry[], step: PlanStep): boolean {
  if (entries.some(entry => entry.clusterId === step.clusterId && entry.event === 'undo')) return false;
  // Modern journals record the cluster's direction before restoring anything.
  // Service-level effects can touch shared services without changing their
  // other clusters, so scoped intent owns those otherwise unscoped records.
  const scopedIntent = entries.some(entry => entry.event === 'resume' && entry.data?.undo === true
    && (entry.clusterId !== undefined || Array.isArray(entry.data.clusterIds)));
  const services = new Set(step.consumers.map(consumer => serviceKey(consumer.service)));
  return entries.some(entry => {
    if (entry.data?.undo !== true) return false;
    if (entry.clusterId !== undefined) return entry.clusterId === step.clusterId;
    if (Array.isArray(entry.data.clusterIds)) return entry.data.clusterIds.includes(step.clusterId);
    if (entry.serviceKey !== undefined) return !scopedIntent && services.has(entry.serviceKey);
    return true;
  });
}

function graceDeadline(entries: JournalEntry[], clusterId: string): string | undefined {
  for (let i = entries.length - 1; i >= 0; i--) {
    const entry = entries[i]!;
    if (entry.event !== 'grace-start' || typeof entry.data?.deadline !== 'string') continue;
    if (entry.clusterId === clusterId) return entry.data.deadline;
    if (entry.clusterId !== undefined) continue;
    const clusters = entry.data.clusters;
    if (!Array.isArray(clusters) || clusters.some(cluster => cluster === clusterId
      || (cluster !== null && typeof cluster === 'object' && cluster.clusterId === clusterId))) return entry.data.deadline;
  }
  return undefined;
}

function nextDeployRules(entries: JournalEntry[], clusterId: string): { host: string; revokeAfterMax: boolean }[] | undefined {
  const entry = [...entries].reverse().find(candidate => candidate.clusterId === clusterId && candidate.event === 'grace-start');
  if (entry?.data?.reason !== 'next-deploy') return undefined;
  const rules = entry.data.nextDeployAcceptance;
  if (!Array.isArray(rules)) return [];
  return rules.filter((rule): rule is { host: string; revokeAfterMax: boolean } => rule !== null && typeof rule === 'object'
    && typeof rule.host === 'string' && typeof rule.revokeAfterMax === 'boolean');
}

function ref(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function deployments(entries: JournalEntry[]): RotationReport['deployments'] {
  const latest = new Map<string, RotationReport['deployments'][number]>();
  for (const entry of entries) {
    if (entry.event !== 'deploy-result' || entry.serviceKey === undefined || entry.data?.undo === true) continue;
    const state = entry.data?.state;
    if (state !== 'success' && state !== 'failed' && state !== 'pending' && state !== 'skipped' && state !== 'unconfirmed') continue;
    latest.set(entry.serviceKey, { serviceKey: entry.serviceKey, deploymentId: ref(entry.data?.deploymentId), state });
  }
  return [...latest.values()];
}

function savedStep(entries: JournalEntry[], clusterId: string): { step: StepReport; index: number } | undefined {
  const statuses = ['pending', 'created', 'written', 'deployed', 'verified', 'revoked', 'skipped', 'failed'];
  for (let index = entries.length - 1; index >= 0; index--) {
    const entry = entries[index]!;
    if (entry.event !== 'plan-end') continue;
    const saved = entry.data?.report;
    const steps = saved !== null && typeof saved === 'object' && 'steps' in saved ? saved.steps : entry.data?.steps;
    if (!Array.isArray(steps)) continue;
    const step = steps.find(candidate => candidate !== null && typeof candidate === 'object'
      && candidate.clusterId === clusterId && statuses.includes(candidate.status)
      && Array.isArray(candidate.warnings) && candidate.warnings.every((warning: unknown) => typeof warning === 'string'));
    if (step) return { step: structuredClone(step) as StepReport, index };
  }
  return undefined;
}

function unpreparedSkip(entries: JournalEntry[], step: PlanStep, report: StepReport, storedSlots: Set<string>): boolean {
  return report.status === 'skipped' && !storedSlots.has(`new:${step.clusterId}`)
    && report.newFingerprint === undefined && !report.newKeyRef && !unfinishedUndo(entries, step)
    && !entries.some(entry => entry.clusterId === step.clusterId && entry.data?.undo !== true
      && (entry.event === 'value-stored' || (entry.event === 'created' && entry.data?.phase !== 'guided-fallback')));
}

function baseReport(input: FinishInput, entries: JournalEntry[], now: () => Date, dryRun: boolean): RotationReport {
  return {
    planId: input.plan.id, dryRun, status: dryRun ? 'dry-run' : 'partial',
    startedAt: entries.find(entry => entry.event === 'plan-start')?.at ?? now().toISOString(),
    finishedAt: now().toISOString(), diff: [], deployments: deployments(entries),
    steps: input.plan.steps.map(step => {
      const saved = savedStep(entries, step.clusterId);
      const data = metadata(entries, step.clusterId);
      const undone = entries.some(entry => entry.clusterId === step.clusterId && entry.event === 'undo');
      const revoked = ended(entries, step.clusterId);
      const changedSinceSaved = saved && entries.slice(saved.index + 1).some(entry => entry.clusterId === step.clusterId
        && entry.data?.undo !== true && ['created', 'value-stored', 'written', 'verified', 'failed', 'revoked', 'undo'].includes(entry.event));
      if (saved && !changedSinceSaved && !undone && !revoked) return saved.step;
      const written = entries.some(entry => entry.clusterId === step.clusterId && entry.event === 'written' && entry.data?.undo !== true);
      const verified = entries.some(entry => entry.clusterId === step.clusterId && entry.event === 'verified' && entry.data?.undo !== true);
      const result: StepReport = {
        ...saved?.step,
        clusterId: step.clusterId, status: undone ? 'skipped' : revoked ? 'revoked' : written ? 'deployed' : verified ? 'verified' : 'created',
        oldKeyRef: ref(data.oldKeyRef), newKeyRef: ref(data.newKeyRef), warnings: [...(saved?.step.warnings ?? [])],
      };
      if (result.status !== 'failed') delete result.error;
      if (typeof data.newFingerprint === 'string') result.newFingerprint = data.newFingerprint;
      if (undone) result.warnings.push('The old credential was restored.');
      return result;
    }),
  };
}

function sealedConsumerBlocks(step: PlanStep, input: FinishInput, opts: RotateOptions): boolean {
  if (opts.acceptUnplannedSealed === true) return false;
  const planned = new Set(input.plan.steps.flatMap(s => s.consumers.map(c => `${serviceKey(c.service)}\0${c.varName}`)));
  const names = new Set(step.consumers.map(c => c.varName));
  return input.inventory.findings.some(finding => finding.sealed
    && !planned.has(`${serviceKey(finding.service)}\0${finding.varName}`)
    && (finding.provider === step.provider || names.has(finding.varName)));
}

/** Settle deferred old-key revocations only after the saved deployment and current verification checks pass. */
export async function finishRotation(
  input: FinishInput, deps: EngineDeps, opts: RotateOptions & { early?: boolean },
): Promise<RotationReport> {
  deps = withStopChecks(deps);
  const entries = input.entries.filter(entry => entry.planId === input.plan.id);
  const now = deps.now ?? (() => new Date());
  const dryRun = opts?.dryRun !== false;
  const report = baseReport(input, entries, now, dryRun);
  const orphans = unresolvedOrphans(input.plan, entries);
  const orphanClusters = new Set(orphans.map(orphan => orphan.clusterId));
  const knownOrphans = orphans.filter((orphan): orphan is typeof orphan & { keyRef: string } => orphan.keyRef !== null);
  if (knownOrphans.length > 0) report.orphanSuspects = knownOrphans;
  for (const step of report.steps) if (orphanClusters.has(step.clusterId)) {
    step.status = 'failed';
    step.warnings.push('An unused replacement may still be active at the provider; check it before finishing this rotation.');
  }
  const pendingSteps = input.plan.steps.filter(step => !orphanClusters.has(step.clusterId)
    && graceDeadline(entries, step.clusterId) !== undefined && !ended(entries, step.clusterId));
  const finalEntry = [...entries].reverse().find(entry => entry.event === 'plan-end');
  if (orphans.length === 0 && pendingSteps.length === 0 && finalEntry && finalEntry.data?.pending !== true) {
    const saved = finalEntry.data?.report;
    if (saved !== null && typeof saved === 'object' && 'planId' in saved && saved.planId === input.plan.id) return saved as RotationReport;
    const status = finalEntry.data?.status;
    if (status === 'complete' || status === 'failed' || status === 'dry-run' || status === 'partial') report.status = status;
    else report.status = input.plan.steps.every(step => ended(entries, step.clusterId)
      || unpreparedSkip(entries, step, report.steps.find(result => result.clusterId === step.clusterId)!, new Set())) ? 'complete' : 'partial';
    return report;
  }
  const safety = await createRecoverySafety(input, deps);
  const { sanitize, journal, ctx } = safety;
  if (dryRun) return sanitize(report);
  const storedSlots = new Set(deps.inflight ? await deps.inflight.slots(input.plan.id) : []);
  const skipped = new Set(input.plan.steps.filter(step => unpreparedSkip(entries, step,
    report.steps.find(result => result.clusterId === step.clusterId)!, storedSlots)).map(step => step.clusterId));
  const settled = new Set(input.plan.steps.filter(step => ended(entries, step.clusterId)).map(step => step.clusterId));
  const pending: NonNullable<RotationReport['pendingRevocations']> = [];
  let blocked = false;
  // Check the entire due wave before the first revocation. Otherwise a later
  // failed health check could arrive after an earlier old key was retired.
  const dueServices = new Set(pendingSteps.filter(step => {
    if (unfinishedUndo(entries, step)) return false;
    const deadline = graceDeadline(entries, step.clusterId)!;
    return Number.isFinite(Date.parse(deadline)) && (now().getTime() >= Date.parse(deadline)
      || opts.early === true && nextDeployRules(entries, step.clusterId) === undefined);
  }).flatMap(step => step.consumers.map(consumer => serviceKey(consumer.service))));
  const currentVariables = new Map<string, RawVariable[] | null>();
  let railwayNamespace: ServiceRef[] | null | undefined;
  const consumerFailures = new Map<string, string>();
  for (const step of pendingSteps) {
    if (unfinishedUndo(entries, step)) continue;
    if (!step.consumers.some(consumer => dueServices.has(serviceKey(consumer.service)))) continue;
    const clusterId = step.clusterId;
    const data = metadata(entries, clusterId);
    const replacement = deps.inflight ? await deps.inflight.get(input.plan.id, `new:${clusterId}`) : null;
    const expected = typeof data.newFingerprint === 'string' ? data.newFingerprint
      : replacement === null ? null : fingerprint(replacement, deps.fingerprintKey);
    const old = deps.inflight ? await deps.inflight.get(input.plan.id, `old:${clusterId}`) : null;
    const oldFingerprint = old === null ? step.consumers.find(consumer => consumer.fingerprint !== null)?.fingerprint
      : fingerprint(old, deps.fingerprintKey);
    const companions = new Map<string, string>();
    if (deps.inflight) for (const slot of await deps.inflight.slots(input.plan.id)) {
      const prefix = `companion:${clusterId}:`;
      if (!slot.startsWith(prefix)) continue;
      const value = await deps.inflight.get(input.plan.id, slot);
      if (value !== null) companions.set(slot.slice(prefix.length), fingerprint(value, deps.fingerprintKey));
    }
    // Reference consumers can be changed into literal credentials or redirected
    // during grace. Read their current variables along with the direct copies.
    for (const consumer of step.consumers) {
      const key = serviceKey(consumer.service);
      if (!currentVariables.has(key)) {
        try {
          const host = deps.hosts[consumer.service.host];
          currentVariables.set(key, host ? await host.readVariables(consumer.service) : null);
        } catch (error) { if (isCrash(error)) throw error; currentVariables.set(key, null); }
      }
    }
    if (step.consumers.some(consumer => consumer.reference) && railwayNamespace === undefined) {
      try { railwayNamespace = await deps.hosts.railway?.listServices() ?? null; }
      catch (error) { if (isCrash(error)) throw error; railwayNamespace = null; }
    }
    // Use the current namespace, including unplanned names, so a renamed or
    // ambiguous reference source cannot resolve through saved service names.
    const scans = railwayNamespace ? buildInventory([{ host: 'railway', services: railwayNamespace.map(service => ({
      service, vars: currentVariables.get(serviceKey(service)) ?? [],
    })) }], deps.fingerprintKey, now()) : undefined;
    let changedAt: string | undefined;
    let usingOldAt: string | undefined;
    for (const consumer of step.consumers) {
      const key = serviceKey(consumer.service);
      if (consumer.reference) {
        const matches = currentVariables.get(key)?.filter(variable => variable.name === consumer.varName) ?? [];
        const current = matches[0];
        if (current && !current.sealed && current.value !== undefined && oldFingerprint
          && fingerprint(current.value, deps.fingerprintKey) === oldFingerprint) usingOldAt ??= key;
        const resolved = scans?.findings.some(finding => finding.reference && finding.fingerprint === expected
          && serviceKey(finding.service) === key && finding.varName === consumer.varName);
        if (matches.length !== 1 || !current || current.sealed || current.value === undefined
          || expected === null || fingerprint(current.value, deps.fingerprintKey) !== expected && !resolved) changedAt ??= key;
        continue;
      }
      const recordedWrite = entries.some(entry => entry.event === 'written' && entry.data?.undo !== true
        && entry.clusterId === clusterId && entry.serviceKey === key);
      const expectedValues = new Map<string, string | null>(companions);
      expectedValues.set(consumer.varName, expected);
      for (const [name, expectedFingerprint] of expectedValues) {
        const matches = currentVariables.get(key)?.filter(variable => variable.name === name) ?? [];
        const current = matches[0];
        if (name === consumer.varName && current && !current.sealed && current.value !== undefined && oldFingerprint
          && fingerprint(current.value, deps.fingerprintKey) === oldFingerprint) usingOldAt ??= key;
        if (matches.length !== 1 || !current || (current.sealed
          ? !consumer.sealed || !recordedWrite
          : current.value === undefined || expectedFingerprint === null
            || fingerprint(current.value, deps.fingerprintKey) !== expectedFingerprint)) changedAt ??= key;
      }
    }
    const planned = new Set(input.plan.steps.flatMap(plannedStep => plannedStep.consumers
      .map(consumer => `${serviceKey(consumer.service)}\0${consumer.varName}`)));
    const unplanned = oldFingerprint ? [...input.inventory.findings, ...input.inventory.clusters.flatMap(cluster => cluster.consumers)]
      .find(consumer => consumer.fingerprint === oldFingerprint && !planned.has(`${serviceKey(consumer.service)}\0${consumer.varName}`)) : undefined;
    if (!changedAt && !unplanned && expected !== null) continue;
    const warning = usingOldAt ? `A consumer changed at ${usingOldAt} and still uses the old key; it is retained.`
      : changedAt ? `A consumer changed at ${changedAt} or its replacement could not be confirmed; the old key is retained.`
      : unplanned ? `A consumer outside this plan at ${serviceKey(unplanned.service)} still uses the old key; it is retained.`
        : 'The saved replacement fingerprint is unavailable; the old key is retained.';
    consumerFailures.set(clusterId, warning);
    const stepReport = report.steps.find(result => result.clusterId === clusterId)!;
    stepReport.status = 'failed';
    stepReport.error = warning;
    stepReport.warnings.push(warning);
    await journal('failed', { clusterId, data: { phase: 'finish-consumers', error: warning } });
  }
  const healthFailures = new Map<string, string>();
  if (deps.healthCheck) for (const deployment of report.deployments) {
    if (deployment.state !== 'success' || !dueServices.has(deployment.serviceKey)) continue;
    let health: { ok: boolean; detail: string };
    try { health = await deps.healthCheck(deployment.serviceKey); }
    catch (error) { if (isCrash(error)) throw error; health = { ok: false, detail: 'Health check could not be completed.' }; }
    if (health.ok) continue;
    healthFailures.set(deployment.serviceKey, health.detail);
    deployment.state = 'failed';
    await journal('deploy-result', { serviceKey: deployment.serviceKey,
      data: { deploymentId: deployment.deploymentId, state: 'failed', phase: 'finish-health' } });
    for (const step of pendingSteps.filter(candidate => candidate.consumers.some(consumer => serviceKey(consumer.service) === deployment.serviceKey))) {
      const stepReport = report.steps.find(result => result.clusterId === step.clusterId)!;
      stepReport.status = 'failed';
      stepReport.warnings.push(health.detail);
      await journal('failed', { clusterId: step.clusterId, data: { phase: 'finish-health', error: 'Consumer health check failed.' } });
    }
  }
  const checkedReplacements = new Map<string, { provider: ProviderAdapter; verified: boolean }>();
  if (opts.holdRevocationOnAnyFailure === true) for (const step of pendingSteps) {
    if (unfinishedUndo(entries, step)) continue;
    if (!step.consumers.some(consumer => dueServices.has(serviceKey(consumer.service)))) continue;
    const clusterId = step.clusterId;
    let provider: ProviderAdapter | undefined;
    let verified = false;
    try {
      provider = deps.providers(step.provider);
      const value = deps.inflight ? await deps.inflight.get(input.plan.id, `new:${clusterId}`) : null;
      if (value !== null) {
        let siblingVars = { ...ctx.siblingVars };
        if (deps.inflight) for (const slot of await deps.inflight.slots(input.plan.id)) {
          const prefix = `companion:${clusterId}:`;
          if (!slot.startsWith(prefix)) continue;
          const companion = await deps.inflight.get(input.plan.id, slot);
          if (companion !== null) siblingVars[slot.slice(prefix.length)] = companion;
        }
        for (const consumer of step.consumers) if (!consumer.reference) siblingVars[consumer.varName] = value;
        if (step.provider === 'aws') {
          const secretName = step.consumers.find(consumer => !consumer.reference)?.varName ?? '';
          const prefix = secretName.replace(/_SECRET_ACCESS_KEY$/, '');
          siblingVars = Object.fromEntries(Object.entries(siblingVars).filter(([name]) =>
            !/_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)$/.test(name)
            || name === secretName || name === `${prefix}_ACCESS_KEY_ID` || name === `${prefix}_SESSION_TOKEN`));
        }
        verified = (await provider.verify(value, { ...ctx, siblingVars })).ok;
      }
    } catch (error) { if (isCrash(error)) throw error; }
    if (provider) checkedReplacements.set(clusterId, { provider, verified });
    if (!verified) {
      const stepReport = report.steps.find(result => result.clusterId === clusterId)!;
      stepReport.status = 'failed';
      stepReport.warnings.push('The replacement credential no longer verifies; the old key is retained.');
      await journal('failed', { clusterId, data: { phase: 'finish-verification', error: 'Replacement verification failed.' } });
    }
  }
  let waveFailure = opts.holdRevocationOnAnyFailure === true && (healthFailures.size > 0
    || report.steps.some(step => step.status === 'failed') || report.deployments.some(deployment => deployment.state === 'failed'
      || deployment.state === 'unconfirmed' && !pendingSteps.some(step => step.consumers.some(consumer => serviceKey(consumer.service) === deployment.serviceKey)
        && nextDeployRules(entries, step.clusterId)?.some(rule => rule.host === step.consumers.find(consumer => serviceKey(consumer.service) === deployment.serviceKey)!.service.host))));
  for (const step of pendingSteps) {
    const clusterId = step.clusterId;
    const stepReport = report.steps.find(s => s.clusterId === clusterId)!;
    const data = metadata(entries, clusterId);
    const deadline = graceDeadline(entries, clusterId)!;
    const oldValue = deps.inflight ? await deps.inflight.get(input.plan.id, `old:${clusterId}`) : null;
    const newValue = deps.inflight ? await deps.inflight.get(input.plan.id, `new:${clusterId}`) : null;
    const undoAvailable = oldValue !== null && data.oldRevoked !== true && step.method !== 'atomic-roll';
    const item = { clusterId, deadline, undoAvailable };
    const acceptedNextDeploy = nextDeployRules(entries, clusterId);
    let warning: string | undefined;
    let expired = false;
    if (consumerFailures.has(clusterId)) {
      warning = consumerFailures.get(clusterId)!;
      blocked = true;
    }
    else if (unfinishedUndo(entries, step)) {
      warning = 'Undo was started but did not finish. Resume undo before finishing this rotation; the old key is retained.';
      blocked = true;
    }
    else if (!Number.isFinite(Date.parse(deadline))) { warning = 'The saved grace deadline is unavailable; the old key is retained.'; blocked = true; }
    else if (now().getTime() < Date.parse(deadline) && (opts.early !== true || acceptedNextDeploy !== undefined)) warning = 'The grace period deadline has not passed; the old key is retained.';
    else expired = true;
    if (expired && acceptedNextDeploy !== undefined && (acceptedNextDeploy.length === 0 || acceptedNextDeploy.some(rule => !rule.revokeAfterMax))) {
      warning = 'The next deploy has not been confirmed and the armed plan did not authorize revocation after the maximum; the old key is retained.';
      blocked = true;
    }
    const successful = step.consumers.length > 0 && step.consumers.every(consumer => report.deployments.some(d => d.serviceKey === serviceKey(consumer.service)
      && (d.state === 'success' || d.state === 'unconfirmed' && acceptedNextDeploy?.some(rule => rule.host === consumer.service.host && rule.revokeAfterMax))));
    if (expired && !successful && !warning) { warning = 'A consumer deployment did not succeed; the old key is retained.'; blocked = true; }
    if (expired && waveFailure) {
      warning = 'A failure in this wave holds further old-key revocations; finish the successful clusters manually.';
      blocked = true;
    }
    const healthFailure = step.consumers.map(consumer => healthFailures.get(serviceKey(consumer.service))).find(detail => detail !== undefined);
    if (expired && healthFailure !== undefined) { warning = healthFailure; blocked = true; }
    if (expired && successful && sealedConsumerBlocks(step, input, opts)) {
      warning = 'Unplanned sealed consumers may still use the old key; it is retained.';
      blocked = true;
    }
    if (expired && successful && !warning && newValue === null) {
      warning = 'The stored replacement value is unavailable, so it cannot be verified; the old key is retained.';
      blocked = true;
    }
    if (!warning) {
      let provider;
      try { provider = checkedReplacements.get(clusterId)?.provider ?? deps.providers(step.provider); }
      catch (error) {
        if (isCrash(error)) throw error;
        warning = 'The credential provider is unavailable; the old key is retained.';
        blocked = true;
      }
      if (provider) {
        const siblingVars = { ...ctx.siblingVars };
        const oldSiblings = { ...ctx.siblingVars };
        if (deps.inflight) for (const slot of await deps.inflight.slots(input.plan.id)) {
          const prefix = `companion:${clusterId}:`;
          const oldPrefix = `old-companion:${clusterId}:`;
          if (slot.startsWith(prefix)) {
            const value = await deps.inflight.get(input.plan.id, slot);
            if (value !== null) siblingVars[slot.slice(prefix.length)] = value;
          }
          if (slot.startsWith(oldPrefix)) {
            const value = await deps.inflight.get(input.plan.id, slot);
            if (value !== null) oldSiblings[slot.slice(oldPrefix.length)] = value;
          }
        }
        for (const consumer of step.consumers) if (!consumer.reference) {
          siblingVars[consumer.varName] = newValue!;
          if (oldValue !== null) oldSiblings[consumer.varName] = oldValue;
        }
        function providerSiblings(values: Record<string, string>): Record<string, string> {
          if (step.provider !== 'aws') return values;
          const secretName = step.consumers.find(consumer => !consumer.reference)?.varName ?? '';
          const prefix = secretName.replace(/_SECRET_ACCESS_KEY$/, '');
          return Object.fromEntries(Object.entries(values).filter(([name]) =>
            !/_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)$/.test(name)
            || name === secretName || name === `${prefix}_ACCESS_KEY_ID` || name === `${prefix}_SESSION_TOKEN`));
        }
        const newCtx: ProviderContext = { ...ctx, siblingVars: providerSiblings(siblingVars) };
        const oldCtx: ProviderContext = { ...ctx, siblingVars: providerSiblings(oldSiblings) };
        let verified = false;
        try { verified = checkedReplacements.get(clusterId)?.verified ?? (await provider.verify(newValue!, newCtx)).ok; }
        catch (error) { if (isCrash(error)) throw error; }
        if (!verified) {
          warning = 'The replacement credential no longer verifies; the old key is retained.';
          blocked = true;
          stepReport.status = 'failed';
        } else {
          crash(deps, 'after-verify', { clusterId });
          await journal('verified', { clusterId, data: { ...data, phase: 'finish' } });
          const oldKeyRef = ref(data.oldKeyRef);
          // Local signing secrets have no provider key to revoke: successful
          // activation of the replacement retires the old value at consumers.
          const local = step.method === 'generate' && oldKeyRef === null && ref(data.newKeyRef) === null && !provider.revoke;
          let alreadyRevoked = local || data.oldRevoked === true || step.method === 'atomic-roll';
          if (!alreadyRevoked && oldValue !== null) {
            try { const result = await provider.verify(oldValue, oldCtx); alreadyRevoked = !result.ok && result.status === 401; }
            catch (error) { if (isCrash(error)) throw error; }
          }
          // A key that ships inside web pages or mobile apps is never deleted by keysentry (fix-phase6 H1).
          const retained = isPublicGoogleKeyStep(step)
            || entries.some(entry => entry.clusterId === clusterId && entry.data?.retainOldKey === true);
          if (!alreadyRevoked && retained) {
            warning = 'The old key was kept because it ships inside web pages or mobile apps: delete it yourself in the provider console once every shipped client uses the replacement.';
            blocked = true;
          } else if (!alreadyRevoked && (!oldKeyRef || !provider.revoke)) {
            warning = 'The old key cannot be identified or revoked automatically; it is retained.';
            blocked = true;
          } else {
            let revoked = alreadyRevoked;
            if (!alreadyRevoked) {
              crash(deps, 'before-revoke', { clusterId });
              try { await provider.revoke!(oldKeyRef!, newCtx); revoked = true; }
              catch (error) {
                if (isCrash(error)) throw error;
                warning = 'The old credential could not be revoked; check the provider before retrying.';
                blocked = true;
                stepReport.status = 'failed';
                stepReport.error = warning;
                if (opts.holdRevocationOnAnyFailure === true) waveFailure = true;
                await journal('failed', { clusterId, data: { phase: 'finish-revocation', error: warning } });
              }
              if (revoked) crash(deps, 'after-revoke', { clusterId });
            }
            if (revoked) {
              await journal('revoked', { clusterId, data: { ...data, oldRevoked: true,
                ...(local ? { local: true } : alreadyRevoked ? { alreadyRevoked: true } : {}) } });
              stepReport.status = 'revoked';
              delete stepReport.error;
              settled.add(clusterId);
            }
          }
        }
      }
    }
    if (warning) {
      stepReport.warnings.push(warning);
      pending.push(item);
    }
    await journal('grace-end', { clusterId, data: { deadline, pending: !settled.has(clusterId), kept: !settled.has(clusterId),
      ...(warning ? { reason: warning } : {}) } });
  }
  if (pending.length > 0) report.pendingRevocations = pending;
  const everySettled = orphans.length === 0 && input.plan.steps.every(step => settled.has(step.clusterId) || skipped.has(step.clusterId));
  const delivered = entries.some(entry => entry.event === 'written' || entry.data?.partialWritePossible === true);
  const progressed = delivered || entries.some(entry => entry.event === 'verified' && entry.data?.undo !== true)
    || report.steps.some(step => ['written', 'deployed', 'verified', 'revoked'].includes(step.status))
    || input.plan.steps.some(step => unfinishedUndo(entries, step));
  report.status = orphans.length > 0 ? 'partial' : everySettled ? 'complete'
    : pending.length > 0 && !blocked ? 'grace-pending' : progressed ? 'partial' : 'failed';
  report.finishedAt = now().toISOString();
  if (deps.inflight && (everySettled || report.status === 'failed' && !delivered)) {
    await deps.inflight.shred(input.plan.id);
    await journal('shredded');
  }
  await journal('plan-end', { data: { status: report.status,
    pending: report.status === 'partial' || report.status === 'grace-pending', report: sanitize(report) } });
  return sanitize(report);
}
