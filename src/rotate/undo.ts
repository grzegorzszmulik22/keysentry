import { fingerprint, serviceKey } from '../core/index.js';
import type {
  Consumer, Inventory, JournalEntry, PlanStep, ProviderAdapter, ProviderContext, RawVariable, RotationPlan, ServiceRef,
} from '../types.js';
import type { EngineDeps, RotateOptions } from './engine.js';
import { crash, isCrash } from './recovery.js';
import { withStopChecks } from './stop.js';

interface UndoInput {
  plan: RotationPlan;
  inventory: Inventory;
  entries: JournalEntry[];
  clusterIds?: string[];
}

export interface UndoReport {
  restored: { clusterId: string; services: string[] }[];
  unavailable: { clusterId: string; reason: string }[];
  newKeysRevoked: string[];
}

interface UndoWork {
  step: PlanStep;
  oldValue: string;
  newValue: string | null;
  newFingerprint: string | null;
  oldCompanions: Record<string, string>;
  newCompanions: Record<string, string>;
  provider: ProviderAdapter;
  ctx: ProviderContext;
  newKeyRef: string | null;
  services: Set<string>;
  restore: Map<string, Record<string, string>>;
  undoStarted: boolean;
  unavailable?: string;
}

class UndoJournalFailure extends Error {
  constructor() { super('Unable to record the undo journal; execution stopped.'); }
}

/** Restore every consumer before retiring a replacement. All values stay in memory or InFlightStore. */
export async function undoRotation(input: UndoInput, deps: EngineDeps, opts: RotateOptions): Promise<UndoReport> {
  deps = withStopChecks(deps);
  const { plan } = input;
  const entries = input.entries.filter(entry => entry.planId === plan.id);
  const report: UndoReport = { restored: [], unavailable: [], newKeysRevoked: [] };
  const now = deps.now ?? (() => new Date());
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms)));
  const timeout = Number.isFinite(opts?.deployTimeoutMs) && opts.deployTimeoutMs >= 0 ? opts.deployTimeoutMs : 600_000;
  const interval = Number.isFinite(opts?.pollIntervalMs) && opts.pollIntervalMs > 0 ? opts.pollIntervalMs : 5_000;
  const secrets = new Set<string>();
  const sensitiveValues = new Set<string>();
  const publicKeyRefs = new Set<string>();
  const values = new Map<string, string>();
  function register(value: string, sensitive = true): void {
    if (!value) return;
    secrets.add(value);
    if (sensitive) sensitiveValues.add(value);
    deps.redactor.register(value);
  }
  function registerNamed(name: string, value: string): void {
    const publicId = name.endsWith('_ACCESS_KEY_ID') && /^(?:AKIA|ASIA)[A-Z0-9]{16}$/.test(value);
    if (publicId) publicKeyRefs.add(value);
    register(value, !publicId);
  }
  function publicRef(value: unknown): value is string {
    return typeof value === 'string' && publicKeyRefs.has(value) && !sensitiveValues.has(value);
  }
  function clean(text: string): string {
    for (const value of [...secrets].sort((a, b) => b.length - a.length)) text = text.split(value).join('«redacted»');
    return deps.redactor.redact(text);
  }
  function sanitize<T>(value: T, preserveRefs = false): T {
    if (typeof value === 'string') return clean(value) as T;
    if (Array.isArray(value)) return value.map(item => sanitize(item, preserveRefs)) as T;
    if (value !== null && typeof value === 'object') return Object.fromEntries(
      Object.entries(value).map(([name, item]) => {
        if (preserveRefs && ['keyRef', 'oldKeyRef', 'newKeyRef'].includes(name) && publicRef(item)) return [clean(name), item];
        if (preserveRefs && name === 'newKeysRevoked' && Array.isArray(item)) return [clean(name),
          item.map(ref => publicRef(ref) ? ref : sanitize(ref, preserveRefs))];
        return [clean(name), sanitize(item, preserveRefs)];
      }),
    ) as T;
    return value;
  }
  async function journal(event: JournalEntry['event'], fields: Omit<JournalEntry, 'event' | 'at' | 'planId'> = {}): Promise<void> {
    const entry = sanitize({ at: now().toISOString(), planId: plan.id, event, ...fields }, true);
    try { await deps.journal.append(entry); }
    catch (error) {
      if (isCrash(error)) throw error;
      throw new UndoJournalFailure();
    }
    entries.push(entry);
  }
  function unavailable(clusterId: string, reason: string): void {
    if (!report.unavailable.some(item => item.clusterId === clusterId)) report.unavailable.push({ clusterId, reason });
  }
  for (const value of Object.values(deps.providerCtx.credentials)) if (value !== undefined) register(value);
  for (const [name, value] of Object.entries(deps.providerCtx.siblingVars ?? {})) registerNamed(name, value);
  if (opts?.dryRun !== false) return report;
  if (deps.inflight) for (const slot of await deps.inflight.slots(plan.id)) {
    const value = await deps.inflight.get(plan.id, slot);
    if (value !== null) {
      values.set(slot, value);
      if (slot.startsWith('companion:') || slot.startsWith('old-companion:')) registerNamed(slot, value);
      else register(value);
    }
  }
  const selected = plan.steps.filter(step => !input.clusterIds || input.clusterIds.includes(step.clusterId));
  const works: UndoWork[] = [];
  const currentVariables = new Map<string, RawVariable[]>();
  let fullHistory: JournalEntry[] | undefined;
  const referenceTargets = new Map<string, Consumer[]>();
  let namespace: ServiceRef[] | undefined;
  async function read(service: ServiceRef): Promise<RawVariable[]> {
    const key = serviceKey(service);
    const cached = currentVariables.get(key);
    if (cached) return cached;
    const host = deps.hosts[service.host];
    if (!host) throw new Error('Host unavailable.');
    const variables = await host.readVariables(service);
    for (const variable of variables) if (variable.value !== undefined) registerNamed(variable.name, variable.value);
    currentVariables.set(key, variables);
    return variables;
  }
  async function sealedWriteCurrent(work: UndoWork, consumer: Consumer, name: string): Promise<boolean> {
    if (!consumer.sealed) return false;
    // Sealed values cannot be compared. Their provenance must still belong to
    // this rotation, including when the caller supplied only this plan's entries.
    try { fullHistory ??= await deps.journal.read(); }
    catch (error) { if (isCrash(error)) throw error; return false; }
    const key = serviceKey(consumer.service);
    let ownWrite = -1;
    for (let index = 0; index < fullHistory.length; index++) {
      const entry = fullHistory[index]!;
      if (entry.planId === plan.id && entry.clusterId === work.step.clusterId && entry.serviceKey === key
        && entry.event === 'written' && entry.data?.undo !== true
        && (!Array.isArray(entry.data?.variableNames) || entry.data.variableNames.includes(name))
        && (entry.data?.newFingerprint === undefined || entry.data.newFingerprint === work.newFingerprint)) ownWrite = index;
    }
    if (ownWrite < 0) return false;
    const later = fullHistory.slice(ownWrite + 1);
    const unfinished = new Set<string>();
    for (const entry of later) {
      if (entry.planId === plan.id) continue;
      if ((entry.event === 'plan-start' || entry.event === 'resume') && entry.data?.dryRun !== true) unfinished.add(entry.planId);
      if (entry.event === 'plan-end') unfinished.delete(entry.planId);
    }
    // These invocation records carry no consumer identities. An unfinished
    // later plan might have stopped between a sealed write and its journal entry.
    if (unfinished.size > 0) return false;
    return !later.some(entry => entry.planId !== plan.id && entry.serviceKey === key
      && (entry.event === 'written' || (entry.event === 'failed' && entry.data?.phase === 'write'))
      && (!Array.isArray(entry.data?.variableNames) || entry.data.variableNames.includes(name)));
  }
  async function referenceCurrent(work: UndoWork, consumer: Consumer, visited = new Set<string>()): Promise<boolean> {
    const location = `${serviceKey(consumer.service)}\0${consumer.varName}`;
    if (consumer.service.host !== 'railway' || visited.has(location)) return false;
    visited.add(location);
    const variables = (await read(consumer.service)).filter(variable => variable.name === consumer.varName);
    const variable = variables[0];
    if (variables.length !== 1 || !variable || variable.sealed || variable.value === undefined) return false;
    const matches = [...variable.value.matchAll(/\$\{\{\s*([^{}]+?)\s*\.\s*([^.\s{}]+)\s*\}\}/g)];
    if (matches.length === 0) return false;
    namespace ??= await deps.hosts.railway!.listServices();
    const resolved = new Map<string, Consumer>();
    for (const match of matches) {
      const candidates = new Set(namespace.filter(service => service.host === 'railway'
        && service.projectId === consumer.service.projectId && service.environmentId === consumer.service.environmentId
        && service.serviceName === match[1]!.trim()).map(service => serviceKey(service)));
      if (candidates.size !== 1) continue;
      const target = work.step.consumers.find(item => candidates.has(serviceKey(item.service)) && item.varName === match[2]);
      if (!target || (target.reference && !await referenceCurrent(work, target, new Set(visited)))) continue;
      resolved.set(`${serviceKey(target.service)}\0${target.varName}`, target);
    }
    if (resolved.size === 0) return false;
    referenceTargets.set(location, [...resolved.values()]);
    return true;
  }
  function referenceDependsOn(consumer: Consumer, source: string, visited = new Set<string>()): boolean {
    const location = `${serviceKey(consumer.service)}\0${consumer.varName}`;
    if (visited.has(location)) return false;
    visited.add(location);
    return (referenceTargets.get(location) ?? []).some(target => serviceKey(target.service) === source
      || (target.reference && referenceDependsOn(target, source, visited)));
  }
  for (const step of selected) {
    const history = entries.filter(entry => entry.clusterId === step.clusterId);
    if (history.some(entry => entry.event === 'undo')) continue;
    if (step.method === 'atomic-roll' || history.some(entry => entry.data?.oldRevoked === true)
      || history.some(entry => entry.event === 'revoked' && entry.data?.cleanup !== true && entry.data?.undo !== true)) {
      unavailable(step.clusterId, 'The old key was already revoked; an atomic roll or earlier revocation cannot be undone.');
      continue;
    }
    const oldValue = values.get(`old:${step.clusterId}`);
    if (oldValue === undefined) {
      unavailable(step.clusterId, 'The old value was sealed or was not stored; undo is unavailable.');
      continue;
    }
    let newKeyRef: string | null = null;
    let newFingerprint: string | null = null;
    for (const entry of history) if (typeof entry.data?.newKeyRef === 'string') newKeyRef = entry.data.newKeyRef;
    for (const entry of history) if (typeof entry.data?.newFingerprint === 'string') newFingerprint = entry.data.newFingerprint;
    const prefix = `old-companion:${step.clusterId}:`;
    const oldCompanions = Object.fromEntries([...values].filter(([slot]) => slot.startsWith(prefix))
      .map(([slot, value]) => [slot.slice(prefix.length), value]));
    const newPrefix = `companion:${step.clusterId}:`;
    const newCompanions = Object.fromEntries([...values].filter(([slot]) => slot.startsWith(newPrefix))
      .map(([slot, value]) => [slot.slice(newPrefix.length), value]));
    let provider: ProviderAdapter;
    try { provider = deps.providers(step.provider); }
    catch (error) {
      if (isCrash(error)) throw error;
      unavailable(step.clusterId, 'The provider is unavailable; the replacement key is retained.');
      continue;
    }
    const ctx: ProviderContext = {
      ...deps.providerCtx,
      credentials: { ...deps.providerCtx.credentials },
      siblingVars: { ...deps.providerCtx.siblingVars, ...oldCompanions },
      log: {
        info: (message, data) => deps.providerCtx.log.info(clean(message), sanitize(data)),
        warn: (message, data) => deps.providerCtx.log.warn(clean(message), sanitize(data)),
        error: (message, data) => deps.providerCtx.log.error(clean(message), sanitize(data)),
        debug: (message, data) => deps.providerCtx.log.debug(clean(message), sanitize(data)),
      },
    };
    works.push({ step, oldValue, newValue: values.get(`new:${step.clusterId}`) ?? null, newFingerprint, oldCompanions, newCompanions,
      provider, ctx, newKeyRef, services: new Set(step.consumers.map(consumer => serviceKey(consumer.service))),
      restore: new Map(), undoStarted: history.some(entry => entry.event === 'resume' && entry.data?.undo === true
        && entry.data?.phase === 'start') });
  }
  const services = new Map<string, {
    service: ServiceRef; vars: Record<string, string>; works: Set<UndoWork>; ok: boolean;
  }>();
  // Read siblings and validate the old key before restoring anything, then verify it again after activation.
  for (const work of works) {
    try {
      const consumer = work.step.consumers.find(item => !item.reference);
      if (!consumer || !deps.hosts[consumer.service.host]) throw new Error('Host unavailable.');
      const siblings = await read(consumer.service);
      // Undo may retry an already restored consumer, but never overwrite a
      // later manual rotation or a value installed by a different plan.
      for (const direct of work.step.consumers.filter(item => !item.reference)) {
        const key = serviceKey(direct.service);
        const changed = `A newer value is in place at ${key}; keysentry won't overwrite it.`;
        const variables = (await read(direct.service)).filter(variable => variable.name === direct.varName);
        const variable = variables[0];
        const current = variable?.value === undefined ? null : fingerprint(variable.value, deps.fingerprintKey);
        const alreadyRestored = !variable?.sealed && work.undoStarted && current === fingerprint(work.oldValue, deps.fingerprintKey);
        if (variables.length !== 1 || !variable || (variable.sealed ? !await sealedWriteCurrent(work, direct, direct.varName)
          : current === null || (current !== work.newFingerprint && !alreadyRestored))) {
          work.unavailable = changed;
          break;
        }
        let restore = work.restore.get(key);
        if (!restore) work.restore.set(key, restore = Object.create(null) as Record<string, string>);
        if (!alreadyRestored) restore[direct.varName] = work.oldValue;
        for (const [name, newValue] of Object.entries(work.newCompanions)) {
          const companions = (await read(direct.service)).filter(candidate => candidate.name === name);
          const companion = companions[0];
          const previous = work.oldCompanions[name];
          const currentCompanion = companion?.value === undefined ? null : fingerprint(companion.value, deps.fingerprintKey);
          const companionRestored = !companion?.sealed && work.undoStarted && previous !== undefined
            && currentCompanion === fingerprint(previous, deps.fingerprintKey);
          if (companions.length !== 1 || !companion || (companion.sealed ? !await sealedWriteCurrent(work, direct, name)
            : currentCompanion === null || (currentCompanion !== fingerprint(newValue, deps.fingerprintKey) && !companionRestored))) {
            work.unavailable = changed;
            break;
          }
          if (previous !== undefined && !companionRestored) restore[name] = previous;
        }
        if (work.unavailable) break;
      }
      if (work.unavailable) continue;
      for (const reference of work.step.consumers.filter(item => item.reference)) if (!await referenceCurrent(work, reference)) {
        work.unavailable = 'A saved reference changed or no longer resolves to its source; the replacement key is retained.';
        break;
      }
      if (work.unavailable) continue;
      for (const shared of work.step.consumers.filter(item => item.service.host === 'railway' && item.service.serviceId === '')) {
        const references = work.step.consumers.filter(item => item.reference && item.service.serviceId !== ''
          && referenceDependsOn(item, serviceKey(shared.service)));
        if (references.length === 0) work.unavailable = 'Shared-variable activation has no valid reference service to confirm it; the replacement key is retained.';
      }
      if (work.unavailable) continue;
      work.ctx.siblingVars = { ...work.ctx.siblingVars,
        ...Object.fromEntries(siblings.filter(variable => !variable.sealed && variable.value !== undefined)
          .map(variable => [variable.name, variable.value!])), ...work.oldCompanions,
      };
      for (const item of work.step.consumers) if (!item.reference) work.ctx.siblingVars[item.varName] = work.oldValue;
      if (work.step.provider === 'aws') {
        const secretName = consumer.varName;
        const prefix = secretName.replace(/_SECRET_ACCESS_KEY$/, '');
        work.ctx.siblingVars = Object.fromEntries(Object.entries(work.ctx.siblingVars).filter(([name]) =>
          !/_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)$/.test(name)
          || name === secretName || name === `${prefix}_ACCESS_KEY_ID` || name === `${prefix}_SESSION_TOKEN`));
      }
      const verification = await work.provider.verify(work.oldValue, work.ctx);
      if (!verification.ok) work.unavailable = verification.status === 401
        ? 'The old key was already revoked; the replacement key is retained.'
        : 'The old key could not be verified; the replacement key is retained.';
    } catch (error) {
      if (isCrash(error)) throw error;
      work.unavailable = 'The old key could not be read or verified; the replacement key is retained.';
    }
  }
  for (const work of works) {
    if (work.unavailable) continue;
    for (const consumer of work.step.consumers) {
      const key = serviceKey(consumer.service);
      let service = services.get(key);
      if (!service) services.set(key, service = { service: consumer.service, vars: Object.create(null), works: new Set(), ok: false });
      service.works.add(work);
      const additions = work.restore.get(key) ?? {};
      for (const [name, value] of Object.entries(additions)) {
        if (Object.hasOwn(service.vars, name) && service.vars[name] !== value) {
          for (const owner of service.works) owner.unavailable = 'Conflicting old values target a consumer; the replacement keys are retained.';
        }
        service.vars[name] = value;
      }
    }
  }
  // Persist direction before the first restore effect so finish/resume cannot later retire the restored old key.
  for (const work of works) if (!work.unavailable) await journal('resume', {
    clusterId: work.step.clusterId, data: { undo: true, phase: 'start' },
  });
  for (const [key, service] of services) {
    const ready = [...service.works].filter(work => !work.unavailable);
    if (ready.length === 0) continue;
    const payload: Record<string, string> = Object.create(null);
    for (const work of ready) {
      Object.assign(payload, work.restore.get(key));
    }
    try {
      const host = deps.hosts[service.service.host];
      if (!host) throw new Error('Host unavailable.');
      if (Object.keys(payload).length > 0) {
        await host.writeVariables(service.service, payload, { skipDeploy: true });
        crash(deps, 'after-write', { serviceKey: key });
      }
      for (const work of ready) await journal('written', { clusterId: work.step.clusterId, serviceKey: key,
        data: { undo: true, variableNames: Object.keys(payload) } });
      service.ok = true;
    } catch (error) {
      if (isCrash(error)) throw error;
      if (error instanceof UndoJournalFailure) throw error;
      for (const work of ready) work.unavailable = 'A consumer write failed; the replacement key is retained.';
      await journal('failed', { serviceKey: key,
        data: { undo: true, phase: 'write', clusterIds: ready.map(work => work.step.clusterId) } });
    }
  }
  // Deploy written services even if another consumer failed: the surviving writes still need activation.
  for (const [key, service] of services) {
    if (!service.ok) continue;
    if (service.service.host === 'railway' && service.service.serviceId === '') continue;
    try {
      const host = deps.hosts[service.service.host];
      if (!host || opts?.redeploy === false || !host.capabilities.redeploy) throw new Error('Activation unconfirmed.');
      const deploymentId = await host.redeploy(service.service);
      crash(deps, 'after-redeploy', { serviceKey: key });
      await journal('redeploy', { serviceKey: key,
        data: { undo: true, deploymentId, clusterIds: [...service.works].map(work => work.step.clusterId) } });
      if (!deploymentId) throw new Error('Activation unconfirmed.');
      const started = now().getTime();
      let waited = 0;
      let state: 'pending' | 'success' | 'failed';
      while (true) {
        state = await host.deploymentStatus(service.service, deploymentId);
        if (state !== 'pending') { crash(deps, 'after-deploy-result', { serviceKey: key }); break; }
        const elapsed = Math.max(0, now().getTime() - started, waited);
        if (elapsed >= timeout) { state = 'failed'; break; }
        const delay = Math.min(interval, timeout - elapsed);
        await sleep(delay);
        waited += delay;
      }
      await journal('deploy-result', { serviceKey: key,
        data: { undo: true, deploymentId, state, clusterIds: [...service.works].map(work => work.step.clusterId) } });
      if (state !== 'success') throw new Error('Deployment failed.');
    } catch (error) {
      if (isCrash(error)) throw error;
      if (error instanceof UndoJournalFailure) throw error;
      service.ok = false;
      for (const work of service.works) work.unavailable = 'A consumer deployment failed or activation is unconfirmed; the replacement key is retained.';
      await journal('failed', { serviceKey: key,
        data: { undo: true, phase: 'deployment', clusterIds: [...service.works].map(work => work.step.clusterId) } });
    }
  }
  for (const work of works) {
    if (work.unavailable) { unavailable(work.step.clusterId, work.unavailable); continue; }
    if ([...work.services].some(key => !services.get(key)?.ok)) {
      unavailable(work.step.clusterId, 'A consumer write or deployment failed; the replacement key is retained.');
      continue;
    }
    try {
      const verification = await work.provider.verify(work.oldValue, work.ctx);
      if (!verification.ok) {
        unavailable(work.step.clusterId, 'The restored old key could not be verified; the replacement key is retained.');
        continue;
      }
      crash(deps, 'after-verify', { clusterId: work.step.clusterId });
      await journal('verified', { clusterId: work.step.clusterId, data: { undo: true } });
      const newCtx: ProviderContext = { ...work.ctx,
        siblingVars: { ...work.ctx.siblingVars, ...work.newCompanions },
      };
      for (const consumer of work.step.consumers) if (!consumer.reference && work.newValue !== null) {
        newCtx.siblingVars![consumer.varName] = work.newValue;
      }
      let newKeyRef = work.newKeyRef;
      if (!newKeyRef && work.newValue !== null && work.provider.resolveKeyRef) newKeyRef = await work.provider.resolveKeyRef(work.newValue, newCtx);
      if (newKeyRef && work.provider.revoke) {
        // A crash may have occurred after revocation but before its journal entry.
        let alreadyRevoked = false;
        if (work.newValue !== null) {
          const checked = await work.provider.verify(work.newValue, newCtx);
          alreadyRevoked = !checked.ok && checked.status === 401;
        }
        if (!alreadyRevoked) {
          crash(deps, 'before-revoke', { clusterId: work.step.clusterId });
          await work.provider.revoke(newKeyRef, work.ctx);
          crash(deps, 'after-revoke', { clusterId: work.step.clusterId });
        }
        report.newKeysRevoked.push(newKeyRef);
        await journal('revoked', { clusterId: work.step.clusterId,
          data: { undo: true, keyRef: newKeyRef, newKeyRef, alreadyRevoked } });
      } else if (work.step.method !== 'generate') {
        unavailable(work.step.clusterId, 'Old values were restored, but the replacement could not be identified or revoked automatically.');
        continue;
      }
      const touched = [...work.services];
      await journal('undo', { clusterId: work.step.clusterId, data: { services: touched, newKeyRef } });
      report.restored.push({ clusterId: work.step.clusterId, services: touched });
    } catch (error) {
      if (isCrash(error)) throw error;
      if (error instanceof UndoJournalFailure) throw error;
      unavailable(work.step.clusterId, 'Undo could not verify the old key or retire the replacement; check the provider before retrying.');
    }
  }
  const settled = (clusterId: string): boolean => entries.some(entry => entry.clusterId === clusterId
    && (entry.event === 'undo' || (entry.event === 'revoked' && entry.data?.cleanup !== true && entry.data?.undo !== true)));
  if (plan.steps.every(step => settled(step.clusterId))) {
    if (deps.inflight && !entries.some(entry => entry.event === 'shredded')) {
      await deps.inflight.shred(plan.id);
      await journal('shredded');
    }
    await journal('plan-end', { data: { status: 'complete', undone: true } });
  }
  return sanitize(report, true);
}
