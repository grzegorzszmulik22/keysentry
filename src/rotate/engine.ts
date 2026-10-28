import { classify, fingerprint, isPublicGoogleKeyStep, serviceKey } from '../core/index.js';
import { RotationAbortedError } from '../types.js';
import { crash, isCrash, unresolvedOrphans } from './recovery.js';
import { undoRotation } from './undo.js';
import { StopRequestedError, withStopChecks } from './stop.js';
import { activationMode, needsManualActivation } from '../hosts/activation.js';
import { hasReadOnlyServices } from '../hosts/read-only.js';
import { hasPublicKeyIds, isPublicKeyId } from './public-refs.js';
import { secretCredentialValues } from '../providers/credential-kinds.js';
import { twilioKeySidFor } from '../providers/twilio.js';
import { publicGoogleKeyGuidance } from '../providers/google.js';
import { hasCredentialForms, PLANNED_FORM_PREFIX, type CredentialForms } from '../providers/shared.js';
import type {
  ArmedPlan, Consumer, CrashPoint, GraceDecision, GraceInfo, GuidedPrompt, HostAdapter, HostId, InFlightStore, Inventory, Journal, JournalEntry, Logger, PlanStep,
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
  inflight?: InFlightStore;
  grace?: (info: GraceInfo) => Promise<GraceDecision>;
  crashHook?: (point: CrashPoint, detail: { clusterId?: string; serviceKey?: string }) => void;
  healthCheck?: (serviceKey: string) => Promise<{ ok: boolean; detail: string }>;
  /** Poll remote disarm before effects. True or a failed poll stops further mutations. */
  shouldStop?: () => Promise<boolean>;
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
  /** Omitted by legacy callers; defaults to zero. */
  graceMs?: number;
  deployConcurrency?: number;
  stopOnFirstFailure?: boolean;
  holdRevocationOnAnyFailure?: boolean;
  nextDeployAcceptance?: ArmedPlan['nextDeployAcceptance'];
  /** Supervised adoption supplies the previous provider reference for write-only clusters. */
  adoptedKeyRefs?: Record<string, string>;
  /**
   * A team policy's minimum grace period (`rotation.minGraceSeconds`): an interactive "revoke now" and `finish --now`
   * do not revoke an old key that has been kept for less than this, counted from its first grace-start.
   */
  minGraceMs?: number;
}

interface ServiceWork {
  service: ServiceRef;
  host?: HostAdapter;
  variables: RawVariable[];
  readFailed: boolean;
  /** Why keysentry reads but never writes this service (a controller-managed Kubernetes Secret), else null. */
  readOnly: string | null;
  vars: Record<string, string>;
  steps: Set<StepWork>;
  written: boolean;
  rewritten?: boolean;
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
  byRef?: boolean;
  oldRevoked?: boolean;
  result?: RotationResult;
  ready: boolean;
  guided?: boolean;
  atomicRoll?: boolean;
  unwritten?: Set<string>;
  delivered?: Set<string>;
  revealed?: boolean;
  revealAttempted?: boolean;
  recoveryMessage?: string;
  referenceTargets?: Map<string, Consumer[]>;
  recovered?: boolean;
  undone?: boolean;
  oldCompanions?: Record<string, string>;
  unusedCleanupAttempted?: boolean;
  unusedCleanupSucceeded?: boolean;
  /** The old key lives in shipped clients (a public Google API key): never revoke it automatically. */
  retainOldKey?: boolean;
  /** Grouped atomic roll: the step whose provider call rolls the shared credential for this step too. */
  groupPrimary?: StepWork;
  /** Grouped atomic roll: other planned forms of the credential this step's provider call rolls. */
  groupMembers?: StepWork[];
  /** Grouped atomic roll (primary only): each member's new value, by cluster id, as the provider returned it. */
  groupForms?: Map<string, string>;
  /** The provider call may have changed something without a known result (see uncertainMutation). */
  uncertain?: boolean;
  /** Consumers in services keysentry reads but never writes: they keep the old key, so it is never revoked here. */
  readOnlyHolders?: string[];
}

/** Variables that may hold a form of an Upstash credential (REST token, password, Redis URL, QStash token). */
const UPSTASH_FORM_NAME = /UPSTASH|QSTASH|REDIS|^KV_/i;

/** A provider call that may have changed something, with an unknown outcome (see ProviderMutationUncertainError). */
function mutationUncertain(error: unknown): error is { code: 'MUTATION_UNCERTAIN'; atomic?: unknown; keyRef?: unknown } {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'MUTATION_UNCERTAIN';
}

/**
 * The Twilio API key SID paired with a secret held under `holders` in one service, and every variable holding it.
 * The adapter's own pairing rule (src/providers/twilio.ts), so the engine and the adapter always agree: a
 * conventionally named SID, else the only SK… value unless it is the conventional partner of another secret.
 */
function twilioKeySid(holders: string[], siblings: Record<string, string>): { sid: string | null; names: string[] } {
  const sid = twilioKeySidFor(holders, siblings);
  return { sid, names: sid === null ? [] : Object.keys(siblings).filter(name => siblings[name] === sid).sort() };
}

class JournalFailure extends Error {
  constructor() { super('Unable to record rotation journal; execution stopped.'); }
}

/** Values stay in local execution state; only sanitized metadata crosses the journal/report boundary. */
export async function executePlan(
  plan: RotationPlan, inv: Inventory, deps: EngineDeps, opts: RotateOptions,
): Promise<RotationReport> {
  return runRotation(plan, inv, deps, opts);
}

/** Shared execution path keeps recovery subject to the normal preflight and activation checks. */
export async function runRotation(
  plan: RotationPlan, inv: Inventory, deps: EngineDeps, opts: RotateOptions, resumeEntries?: JournalEntry[],
): Promise<RotationReport> {
  deps = withStopChecks(deps);
  // Only an explicit false authorizes mutations, including for callers supplying incomplete JS options.
  const dryRun = opts?.dryRun !== false;
  const redeploy = opts?.redeploy ?? true;
  const holdRevocation = opts?.holdRevocationOnAnyFailure === true;
  // A wave-wide hold needs every deployment result before any old-key revocation.
  const revoke = holdRevocation && opts?.revoke === 'immediately' ? 'after-deploy' : opts?.revoke ?? 'after-deploy';
  const stopOnFirstFailure = opts?.stopOnFirstFailure === true;
  const deployConcurrency = Number.isFinite(opts?.deployConcurrency)
    ? Math.max(1, Math.floor(opts.deployConcurrency!)) : 8;
  const graceMs = Number.isFinite(opts?.graceMs) && opts.graceMs! > 0 ? opts.graceMs! : 0;
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
  for (const value of secretCredentialValues(deps.providerCtx.credentials)) register(value);
  for (const [name, value] of Object.entries(deps.providerCtx.siblingVars ?? {})) if (classify(name, value).isSecret) register(value);
  const report: RotationReport = {
    planId: plan.id, dryRun, startedAt: now().toISOString(), finishedAt: '',
    steps: [], deployments: [], diff: [],
  };
  const history = (resumeEntries ?? []).filter(entry => entry.planId === plan.id);
  const recorded = [...history];
  let waveStopped = stopOnFirstFailure && history.some(entry => entry.data?.undo !== true
    && (entry.event === 'failed' || entry.event === 'deploy-result' && entry.data?.state === 'failed'));
  let writesBegan = history.some(entry => entry.event === 'written' || entry.data?.partialWritePossible === true);
  const clusterHistory = (id: string) => history.filter(entry => entry.clusterId === id && entry.data?.undo !== true);
  const works: StepWork[] = plan.steps.map(step => {
    const stepReport: StepReport = { clusterId: step.clusterId, status: 'pending', warnings: [] };
    report.steps.push(stepReport);
    return { step, report: stepReport, services: new Set(step.consumers.map(c => serviceKey(c.service))), ready: false,
      retainOldKey: isPublicGoogleKeyStep(step) || clusterHistory(step.clusterId).some(entry => entry.data?.retainOldKey === true) };
  });
  function adoptedRef(work: StepWork): string | undefined {
    const refs = opts?.adoptedKeyRefs;
    if (!refs || !Object.hasOwn(refs, work.step.clusterId)) return undefined;
    const value = refs[work.step.clusterId];
    return typeof value === 'string' && value.length > 0 ? value : undefined;
  }
  function canPrepareByRef(work: StepWork, provider: ProviderAdapter): boolean {
    return work.step.method === 'auto' && provider.method === 'auto'
      && adoptedRef(work) !== undefined && typeof provider.rotateByRef === 'function';
  }
  const pendingOrphans = unresolvedOrphans(plan, history);
  const orphanClusters = new Set(pendingOrphans.map(suspect => suspect.clusterId));
  const cleanedOrphanClusters = new Set(history.filter(entry => entry.event === 'orphan-suspected'
    && entry.clusterId && !orphanClusters.has(entry.clusterId)).map(entry => entry.clusterId));
  for (const suspect of pendingOrphans) if (suspect.keyRef
    && isPublicKeyId(suspect.keyRef, suspect.provider)) publicKeyRefs.add(suspect.keyRef);
  if (pendingOrphans.length > 0) report.orphanSuspects = pendingOrphans
    .filter((suspect): suspect is typeof suspect & { keyRef: string } => suspect.keyRef !== null);
  const services = new Map<string, ServiceWork>();
  let aborted = false;
  let graceUndid = false;
  let deliveryUncertain = false;
  let providerProducedResult = false;
  let unusedReplacementMayBeLive = pendingOrphans.length > 0;
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
  /**
   * A consumer in a service keysentry reads but never writes (a Kubernetes Secret that a controller restores from its
   * own source) keeps the old key: never roll it (that ends the old key at once) and never revoke it automatically.
   */
  function heldByReadOnly(work: StepWork, atomic = false): boolean {
    if (!work.readOnlyHolders?.length) return false;
    const holders = work.readOnlyHolders.join('; ');
    const message = atomic
      ? `Not rolled: a roll ends the old key at once, but ${holders} also holds it and keysentry does not write there. Roll it by hand in the provider console and update that controller's source (the store it syncs from) at the same time.`
      : `Old key kept: ${holders} also holds this key, and keysentry does not write there. Update the key in that controller's source (the store it syncs from), let it sync and restart what uses it, then revoke the old key yourself in the provider console.`;
    if (!work.report.warnings.includes(clean(message))) warn(work, message);
    return true;
  }
  async function journal(event: JournalEntry['event'], fields: Omit<JournalEntry, 'event' | 'at' | 'planId'> = {}): Promise<void> {
    try {
      const entry = sanitize({ at: now().toISOString(), planId: plan.id, event, ...fields }, true);
      await deps.journal.append(entry);
      recorded.push(entry);
    } catch (error) { if (isCrash(error)) throw error; throw new JournalFailure(); }
  }
  function warn(work: StepWork, message: string): void {
    work.report.warnings.push(clean(message));
    log.warn(message, { clusterId: work.step.clusterId });
  }
  async function fail(work: StepWork, message: string): Promise<void> {
    if (stopOnFirstFailure) waveStopped = true;
    if (work.recoveryMessage) message += ` ${work.recoveryMessage}`;
    work.report.status = 'failed';
    work.report.error = clean(message);
    await journal('failed', { clusterId: work.step.clusterId, data: { error: message, oldRevoked: work.oldRevoked } });
    log.error(message, { clusterId: work.step.clusterId });
  }
  async function transition(work: StepWork, status: StepStatus, event: JournalEntry['event'], data: Record<string, unknown> = {}): Promise<void> {
    work.report.status = status;
    await journal(event, {
      clusterId: work.step.clusterId,
      data: {
        newFingerprint: work.report.newFingerprint, oldKeyRef: work.result?.oldKeyRef,
        newKeyRef: work.result?.newKeyRef, oldRevoked: work.oldRevoked, ...data,
      },
    });
  }
  function siblingValues(service: ServiceWork): Record<string, string> {
    const values: Record<string, string> = Object.create(null);
    for (const variable of service.variables) if (!variable.sealed && variable.value !== undefined) values[variable.name] = variable.value;
    return values;
  }
  async function conclude(): Promise<RotationReport> {
    report.finishedAt = now().toISOString();
    const delivered = deliveryUncertain || [...services.values()].some(service => service.written)
      || history.some(entry => entry.event === 'written' || entry.data?.partialWritePossible === true);
    const progressed = delivered || recorded.some(entry => entry.event === 'verified' && entry.data?.undo !== true);
    const settled = works.every(work => work.undone || work.report.status === 'revoked'
      || work.report.status === 'skipped' && !work.result
      || revoke === 'never' && work.ready && work.report.status !== 'failed' && [...work.services].every(key => services.get(key)?.written));
    if (dryRun) report.status = 'dry-run';
    else if (unusedReplacementMayBeLive) report.status = 'partial';
    else if (stopOnFirstFailure && waveStopped && !delivered && !report.orphanSuspects?.length) report.status = 'failed';
    else if (report.status !== 'grace-pending' && report.status !== 'partial') {
      report.status = !aborted && settled && !works.some(work => work.report.status === 'failed') ? 'complete' : progressed ? 'partial' : 'failed';
    }
    if (!dryRun && deps.inflight && !graceUndid && (report.status === 'complete' || report.status === 'failed' && !delivered)) {
      await deps.inflight.shred(plan.id);
      await journal('shredded');
    }
    await journal('plan-end', { data: { dryRun, aborted, steps: report.steps, status: report.status,
      pending: report.status === 'partial' || report.status === 'grace-pending', report: sanitize(report, true) } });
    return sanitize(report, true);
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
  /**
   * Like the AWS pair check: every writable consumer of a Twilio API key secret must hold the same key SID under the
   * same variable names, so the replacement SID the adapter returns (as companions) fits every consumer. Auth Tokens
   * have no SID and stay with the adapter, which rotates them only as guided.
   */
  function twilioPairsConsistent(work: StepWork): boolean {
    const writable = work.step.consumers.filter(consumer => !consumer.reference);
    const holders = [...new Set(writable.map(consumer => consumer.varName))];
    if (holders.some(name => /AUTH_TOKEN$/.test(name))) return true;
    if (!holders.some(name => /SECRET$/.test(name)) && work.oldValue !== undefined && /^[0-9a-f]{32}$/.test(work.oldValue)) return true;
    const pairs = [...new Set(writable.map(consumer => serviceKey(consumer.service)))].map(key => twilioKeySid(
      writable.filter(consumer => serviceKey(consumer.service) === key).map(consumer => consumer.varName),
      siblingValues(services.get(key)!)));
    // Without any SID the adapter cannot pair the secret and falls back to guided rotation before any change.
    if (pairs.every(pair => pair.sid === null)) return true;
    const expected = new Set([work.result?.oldKeyRef, ...Object.values(work.result?.companions ?? {}), ...Object.values(work.oldCompanions ?? {})]
      .filter((value): value is string => typeof value === 'string'));
    const first = pairs[0]!;
    return pairs.every(pair => pair.sid !== null && pair.names.join('\0') === first.names.join('\0')
      && (work.recovered ? expected.has(pair.sid) : pair.sid === first.sid));
  }
  async function storeOld(work: StepWork): Promise<void> {
    if (!deps.inflight || work.oldValue === undefined) return;
    try {
      await deps.inflight.put(plan.id, `old:${work.step.clusterId}`, work.oldValue);
      for (const name of Object.keys(work.result?.companions ?? {})) {
        const slot = `old-companion:${work.step.clusterId}:${name}`;
        if (await deps.inflight.get(plan.id, slot) === null) {
          const value = work.ctx?.siblingVars?.[name];
          if (value !== undefined) await deps.inflight.put(plan.id, slot, value);
        }
      }
    } catch (error) {
      if (isCrash(error)) throw error;
      if (!work.atomicRoll) throw new Error('Unable to save values needed for recovery; rotation stopped.');
      warn(work, 'The old value could not be saved. The rolled replacement still needs delivery because the old key is already revoked.');
    }
  }
  function localGeneration(work: StepWork): boolean {
    return work.step.method === 'generate' && work.result?.oldKeyRef === null && work.result.newKeyRef === null && !work.provider?.revoke;
  }
  async function cleanupUnused(work: StepWork): Promise<void> {
    if (work.unusedCleanupAttempted) return;
    work.unusedCleanupAttempted = true;
    if (aborted) {
      warn(work, 'Cancellation blocks provider cleanup; revoke the unused replacement manually.');
      return;
    }
    const result = work.result!;
    if (work.atomicRoll || result.oldRevoked) return;
    if (!result.newKeyRef || result.newKeyRef === result.oldKeyRef || !work.provider!.revoke
      || inv.clusters.some(cluster => cluster.fingerprint === work.report.newFingerprint)) {
      warn(work, 'Unused replacement cannot be cleaned up automatically; revoke it manually.');
      return;
    }
    try {
      // A not-yet-propagated AWS key cannot sign its own cleanup request.
      crash(deps, 'before-revoke', { clusterId: work.step.clusterId });
      await work.provider!.revoke!(result.newKeyRef, work.ctx!);
      crash(deps, 'after-revoke', { clusterId: work.step.clusterId });
      await journal('revoked', { clusterId: work.step.clusterId, data: { keyRef: result.newKeyRef, cleanup: true } });
      work.unusedCleanupSucceeded = true;
    } catch (error) {
      if (isCrash(error)) throw error;
      if (error instanceof StopRequestedError) throw error;
      if (error instanceof JournalFailure) throw error;
      warn(work, 'Unused replacement cleanup failed; revoke the new key manually.');
    }
  }
  /**
   * A provider call may have changed something (created a key, reset or rolled a credential) without a known result.
   * Record a possible stray key with the orphan-suspect mechanism, keep the in-flight data, and say what to check:
   * for an atomic roll the old credential may already be invalid while every consumer still uses it.
   */
  async function uncertainMutation(work: StepWork, error: { atomic?: unknown; keyRef?: unknown }): Promise<void> {
    const atomic = work.atomicRoll === true || error.atomic === true;
    work.uncertain = true;
    unusedReplacementMayBeLive = true;
    const keyRef = typeof error.keyRef === 'string' && error.keyRef.length > 0 ? error.keyRef : null;
    if (keyRef && hasPublicKeyIds(work.step.provider) && isPublicKeyId(keyRef, work.step.provider) && !sensitiveValues.has(keyRef)) publicKeyRefs.add(keyRef);
    const suspect = { clusterId: work.step.clusterId, provider: work.step.provider, keyRef };
    if (keyRef) (report.orphanSuspects ??= []).push({ ...suspect, keyRef });
    await journal('orphan-suspected', { clusterId: work.step.clusterId, data: { ...suspect, reason: 'mutation-uncertain', atomic } });
    let where = `the ${work.step.provider} console`;
    try { const url = work.provider?.guidance().url; if (url) where = url; }
    catch (failure) { if (isCrash(failure)) throw failure; /* keep the generic location */ }
    if (atomic) {
      await fail(work, `URGENT: the ${work.step.provider} reset may already have happened, but keysentry could not confirm it. If it did, the old credential is already invalid while every consumer of this step still uses it. Check it at ${where} now; if it changed, copy the new value to every consumer and redeploy, then scan again. keysentry changed no consumer.`);
    } else {
      await fail(work, `${work.step.provider} may already have created a replacement key, but keysentry could not confirm it. Check ${where} for an unused keysentry key and delete it if you do not use it. Every consumer still uses the old key, which stays active.`);
    }
  }
  /**
   * An Upstash reset changes every form of the credential at once: the password, the REST token, every Redis URL and
   * possibly the read-only token. Each form has a different value, so each is its own inventory cluster. Before any
   * reset, the adapter lists every current form of the same database (or QStash user), and keysentry looks for each
   * one across the whole inventory by fingerprint, whatever the value was classified as and whatever its name:
   * - forms in this plan become one group, rolled by one provider call that returns each form's new value;
   * - forms the plan does not update (and that the primary's companions will not rewrite) stop that reset;
   * - places keysentry cannot read (an Upstash-like variable that is sealed or unreadable, any sealed or unreadable
   *   value in a service that holds a form, an incomplete scan, forms the adapter cannot list) make the reset guided.
   */
  async function groupUpstashForms(): Promise<void> {
    const rolls = works.filter(work => work.ready && work.atomicRoll && !work.guided && work.step.provider === 'upstash'
      && !work.recovered && work.oldValue !== undefined && work.provider !== undefined && work.ctx !== undefined);
    if (rolls.length === 0) return;
    const provider = rolls[0]!.provider!;
    const ctx = rolls[0]!.ctx!;
    const passOn = (error: unknown) => isCrash(error) || error instanceof RotationAbortedError;
    async function resolve(value: string): Promise<string | null | undefined> {
      if (typeof provider.resolveKeyRef !== 'function') return undefined;
      try { return await provider.resolveKeyRef(value, ctx); }
      catch (error) { if (passOn(error)) throw error; return undefined; }
    }
    const refs = new Map<StepWork, string>();
    // A value the adapter cannot identify is refused by rotate() before any reset, so it needs no grouping.
    for (const work of rolls) { const ref = await resolve(work.oldValue!); if (typeof ref === 'string') refs.set(work, ref); }
    if (refs.size === 0) return;
    const groups = new Map<string, StepWork[]>();
    for (const [work, ref] of refs) groups.set(ref, [...(groups.get(ref) ?? []), work]);
    // Every current form of each credential, from the management API. Without that list nothing can be checked, so
    // that reset is guided.
    const forms = new Map<string, CredentialForms>();
    for (const [ref, group] of [...groups]) {
      let listed: CredentialForms | null = null;
      if (hasCredentialForms(provider)) {
        try { listed = await provider.credentialForms(ref, ctx); }
        catch (error) { if (passOn(error)) throw error; listed = null; }
      }
      if (listed) {
        for (const value of listed.values) register(value);
        forms.set(ref, listed);
        continue;
      }
      groups.delete(ref);
      for (const work of group) {
        refs.delete(work);
        work.guided = true;
        work.atomicRoll = false;
        warn(work, 'Guided reset: an Upstash reset changes every form of this credential (password, REST token, Redis URLs), and keysentry could not list those forms with UPSTASH_ADMIN_KEY to look for every place that holds one. Reset it in the Upstash console and update every form yourself.');
      }
    }
    if (groups.size === 0) return;
    // A read-only form cannot drive the reset (the adapter refuses it), so a writable form goes first.
    const readOnly = (work: StepWork) => work.step.consumers.some(consumer => /READ_?ONLY/i.test(consumer.varName));
    const primaries = new Map([...groups].map(([ref, group]) => [ref, [...group].sort((a, b) => Number(readOnly(a)) - Number(readOnly(b)))[0]!]));
    const owner = (value: string): string | undefined => [...forms].find(([, listed]) => listed.holds(value))?.[0];
    const byFingerprint = new Map<string, string>();
    for (const listed of forms.values()) for (const value of listed.values) byFingerprint.set(fingerprint(value, deps.fingerprintKey), value);
    const label = (service: ServiceRef, name: string) => `${service.host}/${service.serviceName || service.serviceId || 'shared'}:${name}`;
    const where = (key: string, name: string) => `${key}\0${name}`;
    const unseen = new Set<string>();
    const outside = new Map<string, Set<string>>();
    /** Services that hold some form of a credential being reset: a sealed or unreadable value there may be another. */
    const holders = new Map<string, ServiceRef>();
    /** Locations already accounted for: planned in a group, or checked with their inventoried cluster. */
    const handled = new Set<string>();
    // The primary's companions rewrite a form only where companionsFor delivers them: a consumer service of the
    // primary that holds the same value under the same name as the primary's context service.
    function covered(primary: StepWork, value: string, locations: { service: ServiceRef; varName: string; reference?: boolean }[]): boolean {
      const context = primary.contextService ? services.get(primary.contextService) : undefined;
      return context !== undefined && locations.every(location => {
        const key = serviceKey(location.service);
        const holder = services.get(key);
        return !location.reference && primary.services.has(key) && holder !== undefined
          && siblingValues(context)[location.varName] === value && siblingValues(holder)[location.varName] === value;
      });
    }
    function check(value: string, locations: { service: ServiceRef; varName: string; reference?: boolean }[], name: string): void {
      for (const location of locations) handled.add(where(serviceKey(location.service), location.varName));
      const ref = owner(value);
      if (ref === undefined) return;
      for (const location of locations) holders.set(serviceKey(location.service), location.service);
      if (covered(primaries.get(ref)!, value, locations)) return;
      const places = outside.get(ref) ?? new Set<string>();
      for (const location of locations) places.add(`${label(location.service, location.varName)}${name}`);
      outside.set(ref, places);
    }
    for (const error of inv.errors) unseen.add(`services on ${error.host} (its last scan was incomplete)`);
    const grouped = new Set([...refs.keys()].map(work => work.step.clusterId));
    for (const work of refs.keys()) for (const consumer of work.step.consumers) {
      handled.add(where(serviceKey(consumer.service), consumer.varName));
      holders.set(serviceKey(consumer.service), consumer.service);
    }
    for (const cluster of inv.clusters) {
      if (grouped.has(cluster.id)) continue;
      // A form found by fingerprint, whatever the value was classified as and whatever its name (CACHE_PASSWORD).
      const match = cluster.fingerprint === null ? undefined : byFingerprint.get(cluster.fingerprint);
      if (match !== undefined) { check(match, cluster.consumers, ` (cluster ${cluster.id})`); continue; }
      // A form may also be spelled differently (a Redis URL with another port or path): read every cluster with an
      // Upstash classification or an Upstash/Redis-like name, and treat one that cannot be read as a possible form.
      if (cluster.provider !== 'upstash' && !cluster.consumers.some(consumer => UPSTASH_FORM_NAME.test(consumer.varName))) continue;
      let value: string | undefined;
      for (const consumer of cluster.consumers.filter(candidate => !candidate.reference && !candidate.sealed)) {
        const service = await readService(consumer.service);
        const variable = service.readFailed ? undefined : service.variables.find(candidate => candidate.name === consumer.varName);
        if (variable && !variable.sealed && variable.value !== undefined
          && (cluster.fingerprint === null || fingerprint(variable.value, deps.fingerprintKey) === cluster.fingerprint)) { value = variable.value; break; }
      }
      if (value === undefined) {
        for (const consumer of cluster.consumers) {
          unseen.add(label(consumer.service, consumer.varName));
          handled.add(where(serviceKey(consumer.service), consumer.varName));
        }
        continue;
      }
      check(value, cluster.consumers, ` (cluster ${cluster.id})`);
    }
    // Every service that holds a form: a value keysentry did not inventory (a password under REDIS_PW) may be one more
    // form, and so may any value it cannot read there.
    for (const [key, ref] of [...holders].sort(([a], [b]) => a.localeCompare(b))) {
      const service = services.get(key) ?? await readService(ref);
      if (service.readFailed) { unseen.add(`${label(service.service, '*')} (its variables could not be read)`); continue; }
      for (const variable of service.variables) {
        if (handled.has(where(key, variable.name))) continue;
        if (variable.sealed || variable.value === undefined) { unseen.add(label(service.service, variable.name)); continue; }
        check(variable.value, [{ service: service.service, varName: variable.name }], '');
      }
    }
    if (unseen.size > 0) {
      const places = [...unseen].sort().join(', ');
      for (const work of refs.keys()) {
        work.guided = true;
        work.atomicRoll = false;
        warn(work, `Guided reset: an Upstash reset changes every form of this credential (password, REST token, Redis URLs), and keysentry cannot read every place that may hold one: ${places}. Reset it in the Upstash console and update every form yourself.`);
      }
      return;
    }
    for (const [ref, group] of groups) {
      const places = outside.get(ref);
      if (places) {
        const list = [...places].sort().join(', ');
        for (const work of group) {
          work.ready = false;
          work.report.status = 'skipped';
          warn(work, `Not reset: an Upstash reset also changes the same credential at ${list}, which this plan does not update. Plan those clusters together with this one (keysentry rotate --cluster for each) so one reset updates every form, or reset it in the Upstash console and update every form yourself.`);
        }
        continue;
      }
      const primary = primaries.get(ref)!;
      if (group.length < 2) continue;
      primary.groupMembers = group.filter(work => work !== primary);
      for (const member of primary.groupMembers) member.groupPrimary = primary;
    }
  }
  /** The primary of a grouped roll returns each member's form under PLANNED_FORM_PREFIX names: keep them apart. */
  function takeGroupForms(work: StepWork, result: RotationResult): RotationResult {
    const forms = new Map<string, string>();
    const companions: Record<string, string> = Object.create(null);
    for (const [name, value] of Object.entries(result.companions ?? {})) {
      if (!name.startsWith(PLANNED_FORM_PREFIX)) { companions[name] = value; continue; }
      register(value);
      forms.set(name.slice(PLANNED_FORM_PREFIX.length), value);
    }
    work.groupForms = forms;
    // Members are rolled by this call: their results exist from now on, so recovery delivers them too.
    for (const member of work.groupMembers ?? []) {
      const value = forms.get(member.step.clusterId);
      if (value === undefined || value === member.oldValue) continue;
      member.result = { newValue: value, oldKeyRef: result.oldKeyRef, newKeyRef: result.newKeyRef, oldRevoked: true };
      member.atomicRoll = true;
      member.oldRevoked = true;
    }
    const { companions: _all, ...rest } = result;
    return Object.keys(companions).length > 0 ? { ...rest, companions } : rest;
  }
  /** A member of a grouped roll: its form of the primary's result, or a clear account of why there is none. */
  async function groupMemberResult(work: StepWork, guidedReplacement: (work: StepWork) => Promise<RotationResult | null>): Promise<RotationResult | null> {
    const primary = work.groupPrimary!;
    const named = `cluster ${primary.step.clusterId}`;
    if (work.result) { register(work.result.newValue); return work.result; }
    let where = 'the Upstash console';
    try { const url = work.provider?.guidance().url; if (url) where = url; }
    catch (failure) { if (isCrash(failure)) throw failure; /* keep the generic location */ }
    if (primary.result && !primary.guided) {
      if (primary.groupForms?.get(work.step.clusterId) === work.oldValue) {
        work.report.status = 'skipped';
        warn(work, `The reset (${named}) left this form of the credential unchanged; nothing to update.`);
        return null;
      }
      work.atomicRoll = true;
      work.oldRevoked = true;
      await fail(work, `URGENT: the reset (${named}) also changed this form of the credential, but the provider did not return its new value. Copy it from ${where} and update every consumer of this step now.`);
      return null;
    }
    if (primary.guided && primary.result) {
      // A person reset the credential by hand: this form changed too, so ask for it as well.
      work.guided = true;
      work.atomicRoll = false;
      return guidedReplacement(work);
    }
    if (primary.uncertain) {
      await fail(work, `URGENT: the reset of this credential (${named}) may already have happened, but keysentry could not confirm it. If it did, this form is already invalid too. Check it at ${where} and update every consumer of this step.`);
      return null;
    }
    work.report.status = 'skipped';
    warn(work, `Not reset: the reset of this credential (${named}) did not run, so this form did not change.`);
    return null;
  }
  async function readService(ref: ServiceRef): Promise<ServiceWork> {
    const key = serviceKey(ref);
    const cached = services.get(key);
    if (cached) return cached;
    const service: ServiceWork = {
      service: ref, host: deps.hosts[ref.host], variables: [], readFailed: false, readOnly: null,
      vars: Object.create(null) as Record<string, string>, steps: new Set(), written: false, activation: 'pending',
    };
    services.set(key, service);
    try {
      if (!service.host) throw new Error('Host unavailable.');
      service.variables = await service.host.readVariables(ref);
      // A service the host only reads (a controller-managed Kubernetes Secret) is a consumer that is never written.
      if (hasReadOnlyServices(service.host)) service.readOnly = await service.host.readOnlyReason(ref);
      const secretNames = new Set(inv.findings.filter(finding => serviceKey(finding.service) === key).map(finding => finding.varName));
      for (const variable of service.variables) {
        if (!variable.sealed && variable.value !== undefined && (secretNames.has(variable.name) || classify(variable.name, variable.value).isSecret)) register(variable.value);
      }
    } catch (error) { if (isCrash(error)) throw error; service.readFailed = true; }
    return service;
  }
  function isRailwayShared(service: ServiceRef): boolean {
    return service.host === 'railway' && service.serviceId === '';
  }
  function referenceServiceKeys(work: StepWork, sourceKey: string): string[] {
    const references = work.step.consumers.filter(consumer => {
      if (!consumer.reference || isRailwayShared(consumer.service)) return false;
      const pending = [consumer];
      const visited = new Set<string>();
      while (pending.length > 0) {
        const current = pending.pop()!;
        const location = `${serviceKey(current.service)}\0${current.varName}`;
        if (visited.has(location)) continue;
        visited.add(location);
        for (const target of work.referenceTargets?.get(location) ?? []) {
          if (serviceKey(target.service) === sourceKey) return true;
          if (target.reference) pending.push(target);
        }
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
    return !service.host || needsManualActivation(service.service, service.host, redeploy);
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
    // Inventory stores the resolved secret fingerprint, not the template. A
    // dependency can appear anywhere in an interpolated value, including among
    // references to other clusters. Keep every valid path for activation checks.
    const matches = [...variable.value.matchAll(/\$\{\{\s*([^{}]+?)\s*\.\s*([^.\s{}]+)\s*\}\}/g)];
    if (matches.length === 0) return false;
    // Railway resolves names at runtime. A saved name can now belong to a
    // different service; refresh the namespace once and fail closed on errors.
    railwayNamespace ??= (async () => {
      try { return await deps.hosts.railway?.listServices() ?? []; }
      catch (error) { if (isCrash(error)) throw error; return []; }
    })();
    const namespace = await railwayNamespace;
    const resolved = new Map<string, Consumer>();
    for (const match of matches) {
      const targets = new Set(namespace.filter(candidate => candidate.host === 'railway'
        && candidate.projectId === consumer.service.projectId && candidate.environmentId === consumer.service.environmentId
        && candidate.serviceName === match[1]!.trim()).map(candidate => serviceKey(candidate)));
      if (targets.size !== 1) continue;
      const target = work.step.consumers.find(candidate => targets.has(serviceKey(candidate.service)) && candidate.varName === match[2]);
      if (!target || (target.reference && !await referenceIsCurrent(work, target, new Set(visited)))) continue;
      resolved.set(`${serviceKey(target.service)}\0${target.varName}`, target);
    }
    if (resolved.size === 0) return false;
    work.referenceTargets ??= new Map();
    work.referenceTargets.set(location, [...resolved.values()]);
    return true;
  }
  function activationFor(work: StepWork, key: string): ServiceWork['activation'] {
    const service = services.get(key)!;
    if (!isRailwayShared(service.service)) return service.activation;
    if (!service.written) return 'skipped';
    const references = referenceServiceKeys(work, key);
    return references.length > 0 && references.every(ref => services.get(ref)!.activation === 'success') ? 'success' : 'unconfirmed';
  }
  function acceptanceFor(key: string): ArmedPlan['nextDeployAcceptance'][number] | undefined {
    const service = services.get(key)!;
    return opts?.nextDeployAcceptance?.find(rule => rule.host === service.service.host
      && Number.isFinite(rule.maxHours) && rule.maxHours > 0);
  }
  function acceptedActivation(work: StepWork, key: string): boolean {
    const activation = activationFor(work, key);
    return activation === 'success' || activation === 'unconfirmed' && acceptanceFor(key) !== undefined;
  }
  function anyFailure(): boolean {
    return works.some(work => work.report.status === 'failed') || report.deployments.some(deployment => deployment.state === 'failed'
      || deployment.state === 'unconfirmed' && acceptanceFor(deployment.serviceKey) === undefined);
  }
  function stopped(work: StepWork): void {
    work.ready = false;
    if (work.report.status !== 'failed') work.report.status = 'skipped';
    if (!work.report.warnings.includes('Stopped after an earlier failure in this wave.')) warn(work, 'Stopped after an earlier failure in this wave.');
  }
  async function reportUnwritten(work: StepWork, missing: string[], context = '', bestEffort = false): Promise<void> {
    const locations = missing.map(key => {
      const service = services.get(key)!.service;
      return `${service.host}/${service.serviceName} (${key})`;
    });
    const reason = `URGENT: ROLLED VALUE UNWRITTEN${context} at ${locations.join(', ')}; the old key is already revoked.`;
    // Resolving a callback is not proof of delivery: unattended/no-op callbacks
    // must never suppress the lost-value warning.
    if (!work.revealAttempted && deps.reveal) try {
      work.revealAttempted = true;
      work.revealed = await deps.reveal({ clusterId: work.step.clusterId, provider: work.step.provider, hint: work.step.hint, reason: clean(reason) }, work.result!.newValue) === true;
    } catch (error) {
      if (isCrash(error)) throw error;
      if (error instanceof RotationAbortedError) aborted = true;
      work.revealed = false;
    }
    const message = work.revealed
      ? `${reason} The replacement was revealed; paste it manually and restart/deploy these services.`
      : `${reason} ROLLED VALUE LOST: manual recovery requires the provider dashboard to roll again, then update and restart/deploy these services.`;
    if (work.recoveryMessage) work.report.warnings = work.report.warnings.filter(warning => warning !== work.recoveryMessage);
    work.recoveryMessage = clean(message);
    work.report.status = 'failed';
    work.report.error = clean(message);
    try { warn(work, message); } catch (error) { if (isCrash(error)) throw error; /* failed logging must not suppress recovery metadata */ }
    try { await journal('failed', { clusterId: work.step.clusterId, data: {
      phase: 'value-unwritten', serviceKeys: missing, newFingerprint: work.report.newFingerprint, oldRevoked: true,
      revealed: work.revealed === true, valueLost: work.revealed !== true, error: message,
    } }); } catch (error) { if (isCrash(error)) throw error; if (!bestEffort) throw error; }
  }
  /**
   * Companion values (an AWS access key id, a Twilio key SID, other forms of an Upstash credential) belong to the
   * credential the provider rotated in the context service. Another consumer service receives a companion only when it
   * already defines that variable with the same old value (or already holds the new one); keysentry never adds
   * variables there or overwrites a value that belongs to a different credential.
   */
  function companionsFor(work: StepWork, key: string): Record<string, string> {
    const result: Record<string, string> = Object.create(null);
    const companions = work.result?.companions ?? {};
    if (Object.keys(companions).length === 0) return result;
    const context = work.contextService ? services.get(work.contextService) : undefined;
    const contextValues = context ? siblingValues(context) : {};
    const service = services.get(key);
    for (const [name, value] of Object.entries(companions)) {
      if (key === work.contextService) { result[name] = value; continue; }
      const current = service?.variables.filter(variable => variable.name === name) ?? [];
      const readable = current.length === 1 && !current[0]!.sealed ? current[0]!.value : undefined;
      const old = work.oldCompanions?.[name] ?? contextValues[name];
      if (readable !== undefined && (readable === old || readable === value)) { result[name] = value; continue; }
      if (current.length > 0 && readable === undefined) {
        const message = `Companion ${name} at ${key} is write-only and was not changed; update it by hand if it belongs to the rotated credential.`;
        if (!work.report.warnings.includes(clean(message))) warn(work, message);
      }
    }
    return result;
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
        if (direct.length > 0) Object.assign(additions, companionsFor(work, key));
        for (const c of direct) additions[c.varName] = work.result!.newValue;
        expected.set(work, additions);
        for (const [name, value] of Object.entries(additions)) if (!referenceLocations.has(`${key}\0${name}`)) payload[name] = value;
      }
      for (const work of rolled) for (const c of work.step.consumers) {
        if (!c.reference && serviceKey(c.service) === key && !referenceLocations.has(`${key}\0${c.varName}`)) payload[c.varName] = work.result!.newValue;
      }
      let written = Object.keys(payload).length === 0;
      for (const work of pending) await storeOld(work);
      for (let attempt = 0; !written && attempt < 4; attempt++) {
        try {
          await service.host!.writeVariables(service.service, payload, { skipDeploy: true });
          crash(deps, 'after-write', { serviceKey: key });
          written = true;
        }
        catch (error) { if (isCrash(error)) throw error; /* fixed recovery diagnostic below; never expose adapter errors */ }
        if (!written && attempt < 3) try { await sleep(1_000 * 2 ** attempt); } catch (error) { if (isCrash(error)) throw error; /* still retry */ }
      }
      if (written) {
        // This staging succeeded even if a later redundant batch write fails.
        // Running instances still need the one deployment for this service.
        service.written = true;
        for (const work of pending) {
          if (Object.entries(expected.get(work)!).every(([name, value]) => !referenceLocations.has(`${key}\0${name}`) && payload[name] === value)) {
            work.delivered ??= new Set();
            work.delivered.add(key);
          }
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
        catch (error) { if (isCrash(error)) throw error; /* a broken logger must not undo successful recovery */ }
        continue;
      }
      await reportUnwritten(work, missing, reason === 'guided-fallback' ? ' before guided rotation' : ' after execution failure', true);
    }
  }
  try {
    await journal(resumeEntries ? 'resume' : 'plan-start', { data: { dryRun, steps: works.length, revoke } });
    if (resumeEntries && works.some(work => history.some(entry => entry.clusterId === work.step.clusterId && entry.data?.undo === true)
      && !history.some(entry => entry.clusterId === work.step.clusterId && entry.event === 'undo'))) {
      report.status = dryRun ? 'dry-run' : 'partial';
      for (const work of works) work.report.warnings.push('An undo was interrupted. Run keysentry undo for this plan to finish restoring the old credentials.');
      return await conclude();
    }
    if (resumeEntries && !dryRun && deps.inflight) {
      const slots = await deps.inflight.slots(plan.id);
      for (const slot of slots) {
        const value = await deps.inflight.get(plan.id, slot);
        if (value !== null) register(value, !slot.startsWith('companion:') && !slot.startsWith('old-companion:'));
      }
      for (const work of works) {
        const entries = clusterHistory(work.step.clusterId);
        work.undone = history.some(entry => entry.clusterId === work.step.clusterId && entry.event === 'undo');
        const value = await deps.inflight.get(plan.id, `new:${work.step.clusterId}`);
        const old = await deps.inflight.get(plan.id, `old:${work.step.clusterId}`);
        if (old !== null) work.oldValue = old;
        if (value === null || work.undone) continue;
        const metadata = Object.assign({}, ...entries.filter(entry => ['value-stored', 'created', 'verified', 'revoked'].includes(entry.event)).map(entry => entry.data));
        const companions: Record<string, string> = Object.create(null);
        work.oldCompanions = Object.create(null) as Record<string, string>;
        const prefix = `companion:${work.step.clusterId}:`;
        for (const slot of slots.filter(slot => slot.startsWith(prefix))) {
          const companion = await deps.inflight.get(plan.id, slot);
          if (companion !== null) companions[slot.slice(prefix.length)] = companion;
        }
        const oldPrefix = `old-companion:${work.step.clusterId}:`;
        for (const slot of slots.filter(slot => slot.startsWith(oldPrefix))) {
          const companion = await deps.inflight.get(plan.id, slot);
          if (companion !== null) work.oldCompanions[slot.slice(oldPrefix.length)] = companion;
        }
        work.recovered = true;
        work.oldRevoked = metadata.oldRevoked === true || work.step.method === 'atomic-roll'
          || entries.some(entry => entry.event === 'revoked' && !entry.data?.cleanup);
        work.result = { newValue: value, oldKeyRef: typeof metadata.oldKeyRef === 'string' ? metadata.oldKeyRef : null,
          newKeyRef: typeof metadata.newKeyRef === 'string' ? metadata.newKeyRef : null, oldRevoked: work.oldRevoked, companions };
        work.report.newFingerprint = fingerprint(value, deps.fingerprintKey);
      }
    }

    // Preflight the entire plan before creating credentials, checking secondary copies too.
    for (const work of works) {
      if (work.undone) { work.report.status = 'skipped'; continue; }
      if (orphanClusters.has(work.step.clusterId)) {
        await fail(work, 'An unused replacement may still be live at the provider. Check it and complete cleanup before resuming this cluster.');
        continue;
      }
      if (cleanedOrphanClusters.has(work.step.clusterId)) {
        await fail(work, 'The recorded unused replacement was revoked. Scan again before starting another rotation.');
        continue;
      }
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
      let referenceChanged = false;
      let unreadable = false;
      let adoptedWriteOnly = false;
      if (adoptedRef(work)) {
        try { adoptedWriteOnly = canPrepareByRef(work, deps.providers(work.step.provider)); }
        catch (error) { if (isCrash(error)) throw error; }
      }
      for (const consumer of work.step.consumers) {
        const service = await readService(consumer.service);
        if (service.readFailed) { unreadable = true; continue; }
        const variable = service.variables.find(candidate => candidate.name === consumer.varName);
        if (!variable) {
          if (consumer.reference) referenceChanged = true;
          else stale = true;
          continue;
        }
        // A reference contains a template, not the rendered secret fingerprint.
        if (consumer.reference) {
          if (!await referenceIsCurrent(work, consumer)) referenceChanged = true;
          continue;
        }
        const value = variable.sealed ? undefined : variable.value;
        const alreadyNew = work.recovered && value !== undefined && fingerprint(value, deps.fingerprintKey) === work.report.newFingerprint;
        if (alreadyNew) writesBegan = true;
        // A supervised fingerprint cannot be read back from a planned sealed
        // consumer. Its adopted provider reference supplies the preparation path;
        // readable mismatches and unexpectedly sealed consumers still fail closed.
        const adoptedSealed = adoptedWriteOnly && consumer.sealed && variable.sealed;
        if (!alreadyNew && consumer.fingerprint !== null && (value === undefined ? !adoptedSealed : fingerprint(value, deps.fingerprintKey) !== consumer.fingerprint)) {
          stale = true;
        }
        if (!alreadyNew && cluster.fingerprint !== null && value !== undefined && fingerprint(value, deps.fingerprintKey) !== cluster.fingerprint) stale = true;
        if (value !== undefined && !alreadyNew && work.oldValue === undefined) {
          work.oldValue = value;
          work.contextService = serviceKey(consumer.service);
        }
      }
      if (unreadable) { await fail(work, 'Unable to read every consumer service; no credentials were changed.'); continue; }
      if (stale || referenceChanged) {
        work.report.status = 'skipped';
        if (referenceChanged) warn(work, 'Railway reference removed since scan or no longer resolves to the scanned source; scan again before rotating.');
        if (stale) warn(work, 'Stale inventory: a consumer value changed or is missing; scan again before rotating.');
        continue;
      }
      // Copies in services keysentry never writes stay as they are, and they hold the old key's revocation.
      const readOnlyKeys = [...work.services].filter(key => typeof services.get(key)?.readOnly === 'string');
      if (readOnlyKeys.length > 0) {
        work.readOnlyHolders = work.step.consumers.filter(consumer => readOnlyKeys.includes(serviceKey(consumer.service)))
          .map(consumer => `${consumer.service.host}/${consumer.service.projectName ? `${consumer.service.projectName}/` : ''}${consumer.service.serviceName}:${consumer.varName} (${services.get(serviceKey(consumer.service))!.readOnly})`);
        for (const key of readOnlyKeys) work.services.delete(key);
        if (work.services.size === 0) {
          work.report.status = 'skipped';
          warn(work, `Not rotated: every copy of this key is in a place keysentry reads but does not write: ${work.readOnlyHolders.join('; ')}. Rotate it in that controller's source (the store it syncs from).`);
          continue;
        }
      }
      if (work.step.provider === 'aws') {
        const writable = work.step.consumers.filter(consumer => !consumer.reference);
        const names = new Set(writable.map(consumer => consumer.varName));
        const secretName = writable[0]?.varName ?? '';
        const idName = secretName.replace(/_SECRET_ACCESS_KEY$/, '_ACCESS_KEY_ID');
        const accessIds = writable.map(c => siblingValues(services.get(serviceKey(c.service))!)[idName]);
        if (work.recovered && !work.result?.companions?.[idName]) {
          await fail(work, 'The replacement AWS access key ID was not saved. The old pair is retained; remove the unused replacement in the AWS dashboard before rotating again.');
          continue;
        }
        const expectedIds = new Set([work.result?.oldKeyRef, work.result?.companions?.[idName], work.oldCompanions?.[idName]].filter(Boolean));
        if (names.size !== 1 || !secretName.endsWith('_SECRET_ACCESS_KEY')
          || accessIds.some(id => !id || (work.recovered ? !expectedIds.has(id) : id !== accessIds[0]))) {
          await fail(work, 'AWS credential pair names or access key IDs are missing or inconsistent across consumers; rotate complete matching pairs.');
          continue;
        }
      }
      if (work.step.provider === 'twilio' && !twilioPairsConsistent(work)) {
        await fail(work, 'Twilio API key SIDs are missing or held under different variable names across consumers; rotate complete matching pairs.');
        continue;
      }
      work.contextService ??= serviceKey(work.step.consumers[0]!.service);
      work.ctx = {
        ...deps.providerCtx,
        credentials: { ...deps.providerCtx.credentials },
        siblingVars: providerSiblings(work, { ...deps.providerCtx.siblingVars, ...siblingValues(services.get(work.contextService)!), ...work.oldCompanions }),
        log: safeLogger(deps.providerCtx.log),
      };
      if (work.recovered) {
        for (const consumer of work.step.consumers) if (!consumer.reference && work.oldValue !== undefined) work.ctx.siblingVars![consumer.varName] = work.oldValue;
        if (work.step.provider === 'aws') {
          const idName = work.step.consumers.find(consumer => !consumer.reference)!.varName.replace(/_SECRET_ACCESS_KEY$/, '_ACCESS_KEY_ID');
          work.result!.oldKeyRef ??= work.oldCompanions?.[idName] ?? work.ctx.siblingVars?.[idName] ?? null;
          work.result!.newKeyRef ??= work.result!.companions?.[idName] ?? null;
        }
      }
      if (resumeEntries && !dryRun && !work.recovered && ['auto', 'atomic-roll'].includes(work.step.method)) {
        let provider: ProviderAdapter;
        try { provider = deps.providers(work.step.provider); }
        catch (error) {
          if (isCrash(error)) throw error;
          report.status = 'partial';
          await fail(work, 'The provider is unavailable. A replacement may exist there; check the provider before continuing.');
          continue;
        }
        let oldRef: string | null = work.oldValue === undefined ? adoptedRef(work) ?? null : null;
        try { if (work.oldValue !== undefined && provider.resolveKeyRef) oldRef = await provider.resolveKeyRef(work.oldValue, work.ctx); }
        catch (error) { if (isCrash(error)) throw error; }
        const known = new Set(history.filter(entry => plan.steps.some(step => step.provider === work.step.provider && step.clusterId === entry.clusterId))
          .flatMap(entry => [entry.data?.oldKeyRef, entry.data?.newKeyRef]).filter((ref): ref is string => typeof ref === 'string'));
        if (oldRef) known.add(oldRef);
        const started = history.find(entry => entry.event === 'plan-start')?.at ?? plan.createdAt;
        let suspects: Awaited<ReturnType<NonNullable<ProviderAdapter['listKeys']>>> = [];
        try { suspects = provider.listKeys ? await provider.listKeys(work.ctx) : []; }
        catch (error) { if (isCrash(error)) throw error; }
        for (const key of suspects.filter(key => key.createdAt && Date.parse(key.createdAt) >= Date.parse(started) && !known.has(key.keyRef))) {
          const suspect = { clusterId: work.step.clusterId, provider: work.step.provider, keyRef: key.keyRef, createdAt: key.createdAt };
          (report.orphanSuspects ??= []).push(suspect);
          await journal('orphan-suspected', { clusterId: work.step.clusterId, data: suspect });
        }
        report.status = 'partial';
        await fail(work, `A new key may have been created at ${work.step.provider} before keysentry could save it. Check ${provider.guidance().url} and delete it if you don't use it.`);
        continue;
      }
      work.ready = true;
      for (const consumer of work.step.consumers) {
        if (!work.services.has(serviceKey(consumer.service))) {
          report.diff.push(`${serviceKey(consumer.service)}: ${consumer.varName}: kept (keysentry does not write it; the old key is not revoked)`);
          continue;
        }
        if (consumer.reference) {
          report.diff.push(`Redeploy reference ${serviceKey(consumer.service)}: ${consumer.varName}`);
          continue;
        }
        report.diff.push(`${serviceKey(consumer.service)}: ${consumer.varName}: ${consumer.hint ?? work.step.hint ?? '(sealed)'} → (new)`);
      }
    }

    if (!dryRun && stopOnFirstFailure && !waveStopped) {
      const unprepared = works.find(work => !work.undone && work.report.status === 'skipped');
      if (unprepared) await fail(unprepared, 'A cluster could not be prepared safely; no consumer was changed.');
    }
    if (dryRun) {
      for (const [key, service] of services) {
        if (!works.some(work => work.ready && work.services.has(key))) continue;
        const mode = service.host ? activationMode(service.service, service.host) : 'manual';
        if (mode === 'on-write') report.diff.push(`Writing deploys ${key}; keysentry confirms that deployment`);
        else if (mode === 'immediate') report.diff.push(`Live once written ${key}; no deployment needed`);
        else if (redeploy && service.host?.capabilities.redeploy && !isRailwayShared(service.service)) report.diff.push(`Redeploy ${key}`);
        report.deployments.push({ serviceKey: key, deploymentId: null, state: 'skipped' });
      }
    } else {
      // Resolve effective methods before any provider mutation: sealed/missing-rotate
      // fallbacks can require a person even when the plan labels them automatic.
      for (const work of works) {
        if (!work.ready) continue;
        if (waveStopped) { stopped(work); continue; }
        try {
          const provider = deps.providers(work.step.provider);
          work.provider = provider;
          work.byRef = work.oldValue === undefined && canPrepareByRef(work, provider);
          work.guided = work.step.provider === 'encryption-key' || work.step.method === 'guided' || provider.method === 'guided' || !provider.rotate && !work.byRef
            || isPublicGoogleKeyStep(work.step)
            || (work.oldValue === undefined && (work.step.method === 'auto' || work.step.method === 'atomic-roll') && !work.byRef);
          work.atomicRoll = !work.guided && (work.step.method === 'atomic-roll' || provider.method === 'atomic-roll');
          if (work.atomicRoll) {
            let blocked = blockedBySealed(work);
            if (heldByReadOnly(work, true)) blocked = true;
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
        } catch (error) { if (isCrash(error)) throw error; work.ready = false; await fail(work, 'Unable to prepare the replacement credential; no consumer was changed.'); }
      }
      await groupUpstashForms();
      const preparation = [
        ...works.filter(work => work.ready && work.guided),
        ...works.filter(work => work.ready && !work.guided && !work.atomicRoll),
        // Members of a grouped roll follow their primary, whose single provider call rolls them too.
        ...works.filter(work => work.ready && work.atomicRoll && !work.groupPrimary)
          .flatMap(work => [work, ...(work.groupMembers ?? []).filter(member => member.ready)]),
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
          try { JSON.parse(work.oldValue); wasJson = true; } catch (error) { if (isCrash(error)) throw error; /* not JSON */ }
          if (wasJson) try { JSON.parse(value); } catch (error) { if (isCrash(error)) throw error; return true; }
        }
        return false;
      }
      async function guidedReplacement(work: StepWork, permissionsFallback = false): Promise<RotationResult | null> {
        if (aborted) throw new RotationAbortedError();
        const provider = work.provider!;
        if (work.oldValue === undefined) warn(work, 'Old value is sealed; guided rotation is required and automatic old-key revocation may be unavailable.');
        const value = await deps.prompt({
          clusterId: work.step.clusterId, provider: work.step.provider, hint: work.step.hint,
          guidance: isPublicGoogleKeyStep(work.step) ? publicGoogleKeyGuidance() : provider.guidance(), consumers: work.step.consumers,
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
        if (deps.inflight) {
          await deps.inflight.put(plan.id, `new:${work.step.clusterId}`, value);
          crash(deps, 'after-store', { clusterId: work.step.clusterId });
          await journal('value-stored', { clusterId: work.step.clusterId, data: { newFingerprint: fingerprint(value, deps.fingerprintKey) } });
        }
        // A pasted replacement must never become the OLD ref. A retained old key gets no ref, so nothing revokes it.
        const oldKeyRef = !work.retainOldKey && work.oldValue !== undefined && provider.resolveKeyRef ? await provider.resolveKeyRef(work.oldValue, work.ctx!) : null;
        return { newValue: value, oldKeyRef, newKeyRef: null, oldRevoked: false };
      }
      for (const work of preparation) {
        work.ready = false;
        // A member already rolled by its primary must still be delivered, like any rolled credential.
        const rolledByPrimary = work.groupPrimary !== undefined && work.result !== undefined;
        if (waveStopped && !rolledByPrimary) { stopped(work); continue; }
        if (aborted && !rolledByPrimary) {
          work.report.status = 'skipped';
          warn(work, 'Rotation interrupted by the operator; no new provider mutation or replacement prompt was started.');
          continue;
        }
        try {
          const provider = work.provider!;
          const ctx = work.ctx!;
          let result: RotationResult;
          if (work.recovered) {
            result = work.result!;
            // The store can be durable even when the following metadata entry
            // was never appended. Recover references without creating another key.
            if (!result.oldKeyRef && !work.retainOldKey && work.oldValue !== undefined && provider.resolveKeyRef) result.oldKeyRef = await provider.resolveKeyRef(work.oldValue, ctx);
            if (!result.oldKeyRef && work.byRef) result.oldKeyRef = adoptedRef(work) ?? null;
          } else if (work.guided) {
            const replacement = await guidedReplacement(work);
            if (!replacement) {
              if (stopOnFirstFailure) await fail(work, 'A replacement needs human input; no consumer was changed.');
              continue;
            }
            result = replacement;
          } else if (work.groupPrimary) {
            const derived = await groupMemberResult(work, guidedReplacement);
            if (!derived) continue;
            result = derived;
          } else {
            try {
              // A grouped roll passes the other planned forms so the adapter returns each one's new value.
              const rollCtx: ProviderContext = work.groupMembers?.length ? { ...ctx, siblingVars: { ...ctx.siblingVars,
                ...Object.fromEntries(work.groupMembers.map(member => [`${PLANNED_FORM_PREFIX}${member.step.clusterId}`, member.oldValue!])) } } : ctx;
              result = work.byRef ? await provider.rotateByRef!(adoptedRef(work)!, ctx)
                : await provider.rotate!(work.oldValue ?? '', rollCtx);
              if (work.groupMembers?.length) result = takeGroupForms(work, result);
              providerProducedResult = true;
              work.result = result;
              work.atomicRoll ||= result.oldRevoked;
              work.oldRevoked = result.oldRevoked || work.atomicRoll;
              crash(deps, 'after-create', { clusterId: work.step.clusterId });
              if (deps.inflight) {
                await deps.inflight.put(plan.id, `new:${work.step.clusterId}`, result.newValue);
                crash(deps, 'after-store', { clusterId: work.step.clusterId });
                for (const [name, value] of Object.entries(result.companions ?? {})) await deps.inflight.put(plan.id, `companion:${work.step.clusterId}:${name}`, value);
                for (const member of work.groupMembers ?? []) if (member.result) await deps.inflight.put(plan.id, `new:${member.step.clusterId}`, member.result.newValue);
              }
            }
            catch (error) {
              if (isCrash(error)) throw error;
              // Only a rejected provider call promises no mutation. A store
              // error carrying the same code cannot authorize guided fallback.
              if (work.result) throw error;
              if (typeof error !== 'object' || error === null || !('code' in error) || error.code !== 'GUIDED_ROTATION_REQUIRED') throw error;
              // This code guarantees rotate rejected before mutation, even for
              // an adapter or stale plan that advertised an atomic roll.
              work.guided = true;
              work.atomicRoll = false;
              if ('retainOldKey' in error && error.retainOldKey === true) {
                work.retainOldKey = true;
                warn(work, 'This key ships inside web pages or mobile apps that keysentry cannot redeploy. keysentry will not delete the old key: delete it yourself once those clients have updated.');
              }
              const atomicRollsAlreadyRan = works.some(previous => previous.atomicRoll && previous.result);
              if (atomicRollsAlreadyRan) await preserveRolledValues('guided-fallback');
              await journal('created', { clusterId: work.step.clusterId, data: {
                phase: 'guided-fallback', code: 'GUIDED_ROTATION_REQUIRED', atomicRollsAlreadyRan,
                ...(work.retainOldKey ? { retainOldKey: true } : {}),
              } });
              const replacement = await guidedReplacement(work, true);
              if (!replacement) {
                if (stopOnFirstFailure) await fail(work, 'A replacement needs human input; no consumer was changed.');
                continue;
              }
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
            for (const id of [oldId, newId]) if (id && isPublicKeyId(id, 'aws') && !sensitiveValues.has(id)) publicKeyRefs.add(id);
          }
          // Twilio key references are the public SK… SIDs; finish and grace revocation read them back from the journal.
          if (work.step.provider === 'twilio') for (const id of [result.oldKeyRef, result.newKeyRef]) {
            if (id && isPublicKeyId(id, 'twilio') && !sensitiveValues.has(id)) publicKeyRefs.add(id);
          }
          work.report.newFingerprint = fingerprint(result.newValue, deps.fingerprintKey);
          work.report.oldKeyRef = result.oldKeyRef;
          work.report.newKeyRef = result.newKeyRef;
          const newSiblings = { ...ctx.siblingVars, ...result.companions };
          for (const consumer of work.step.consumers) if (!consumer.reference && serviceKey(consumer.service) === work.contextService) newSiblings[consumer.varName] = result.newValue;
          // Verification uses new companions; cleanup authenticates using the old context.
          const newCtx: ProviderContext = { ...ctx, siblingVars: providerSiblings(work, newSiblings) };
          work.newCtx = newCtx;
          if (work.recovered && !result.newKeyRef && provider.resolveKeyRef) {
            result.newKeyRef = await provider.resolveKeyRef(result.newValue, newCtx);
            work.report.newKeyRef = result.newKeyRef;
          }
          if (deps.inflight) await journal('value-stored', { clusterId: work.step.clusterId, data: {
            newFingerprint: work.report.newFingerprint, oldKeyRef: result.oldKeyRef, newKeyRef: result.newKeyRef, oldRevoked: work.oldRevoked,
          } });
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
          let verified = work.recovered === true && clusterHistory(work.step.clusterId).some(entry => entry.event === 'verified');
          for (let attempt = 0; !verified && attempt <= verifyRetries; attempt++) {
            let definitive = false;
            try {
              const verification = await provider.verify(result.newValue, newCtx);
              verified = verification.ok;
              definitive = verification.status === 401;
            } catch (error) { if (isCrash(error)) throw error; /* fixed diagnostic below */ }
            if (verified) crash(deps, 'after-verify', { clusterId: work.step.clusterId });
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
            try { result.newKeyRef = await provider.resolveKeyRef(result.newValue, newCtx); } catch (error) { if (isCrash(error)) throw error; warn(work, 'The new key reference could not be resolved for future monitoring.'); }
            work.report.newKeyRef = result.newKeyRef;
          }
          if (verified) await transition(work, 'verified', 'verified');
          work.ready = true;
        } catch (error) {
          if (isCrash(error)) throw error;
          if (error instanceof StopRequestedError) throw error;
          if (error instanceof RotationAbortedError) {
            aborted = true;
            if (!providerProducedResult) throw error;
            work.report.status = 'skipped';
            warn(work, 'Rotation interrupted by the operator; completing delivery and activation of already prepared values.');
            continue;
          }
          if (error instanceof JournalFailure) throw error;
          if (work.atomicRoll && work.result) {
            register(work.result.newValue);
            for (const [name, value] of Object.entries(work.result.companions ?? {})) register(value, classify(name, value).isSecret);
            work.report.newFingerprint = fingerprint(work.result.newValue, deps.fingerprintKey);
            work.report.oldKeyRef = work.result.oldKeyRef;
            work.report.newKeyRef = work.result.newKeyRef;
            work.ready = true;
            warn(work, 'URGENT: Rolled credential preparation could not finish; attempting delivery because the old key is already revoked.');
            continue;
          }
          if (work.result) {
            // Ordinary storage errors can occur after the provider created a
            // key. Record its references and clean it up instead of losing it.
            register(work.result.newValue);
            for (const [name, value] of Object.entries(work.result.companions ?? {})) register(value, classify(name, value).isSecret);
            if (hasPublicKeyIds(work.step.provider)) for (const keyRef of [work.result.oldKeyRef, work.result.newKeyRef]) {
              if (keyRef && isPublicKeyId(keyRef, work.step.provider) && !sensitiveValues.has(keyRef)) publicKeyRefs.add(keyRef);
            }
            work.report.newFingerprint = fingerprint(work.result.newValue, deps.fingerprintKey);
            work.report.oldKeyRef = work.result.oldKeyRef;
            work.report.newKeyRef = work.result.newKeyRef;
            let preparationJournalFailure: JournalFailure | undefined;
            try {
              await journal('created', { clusterId: work.step.clusterId, data: {
                phase: 'preparation-failed', newFingerprint: work.report.newFingerprint,
                oldKeyRef: work.result.oldKeyRef, newKeyRef: work.result.newKeyRef, oldRevoked: false,
              } });
            } catch (error) {
              if (isCrash(error)) throw error;
              if (!(error instanceof JournalFailure)) throw error;
              // Losing the metadata write cannot suppress cleanup of a known,
              // unused provider key. Stop execution after the cleanup attempt.
              preparationJournalFailure = error;
            }
            await cleanupUnused(work);
            if (!work.unusedCleanupSucceeded && !localGeneration(work)) {
              // The value may never have reached durable storage. Preserve all
              // remaining recovery data while the provider key may still live.
              unusedReplacementMayBeLive = true;
              const suspect = { clusterId: work.step.clusterId, provider: work.step.provider, keyRef: work.result.newKeyRef };
              if (suspect.keyRef) (report.orphanSuspects ??= []).push({ ...suspect, keyRef: suspect.keyRef });
              await journal('orphan-suspected', { clusterId: work.step.clusterId, data: { ...suspect, reason: 'unused-key-cleanup' } });
            }
            if (preparationJournalFailure) throw preparationJournalFailure;
          }
          if (mutationUncertain(error) && !work.result) {
            await uncertainMutation(work, error);
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
        if (waveStopped) { stopped(work); continue; }
        if (work.atomicRoll) {
          warn(work, 'URGENT: A write conflict affects a rolled credential; preserving its replacement and retrying delivery.');
          continue;
        }
        work.ready = false;
        await fail(work, 'Conflicting replacement values target the same service variable; no values for this step were written.');
        await cleanupUnused(work);
      }
      if (conflicts.size > 0) populateBatches();
      if (waveStopped && !writesBegan) {
        // Every preparation must succeed before an unattended wave can stage any values.
        for (const work of works) {
          if (work.result && !work.oldRevoked) await cleanupUnused(work);
          if (work.report.status !== 'failed') stopped(work);
          else work.ready = false;
        }
        populateBatches();
      }
      // Primary rolled values take precedence over companions of other rolls.
      for (const work of works) if (work.ready && work.atomicRoll) for (const c of work.step.consumers) {
        const key = serviceKey(c.service);
        if (!c.reference && !referenceLocations.has(`${key}\0${c.varName}`)) services.get(key)!.vars[c.varName] = work.result!.newValue;
      }
      function additionsFor(work: StepWork, key: string): Record<string, string> {
        const additions: Record<string, string> = Object.create(null);
        const direct = work.step.consumers.filter(c => !c.reference && serviceKey(c.service) === key);
        if (direct.length > 0) Object.assign(additions, companionsFor(work, key));
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
        if (waveStopped && ![...service.steps].some(work => work.atomicRoll)) continue;
        const atomics = [...service.steps].filter(work => work.atomicRoll && Object.keys(additionsFor(work, key)).length > 0);
        // A companion must never replace its own atomic primary value. Other
        // incompatible atomic additions remain visible as unwritten recovery work.
        const mismatched = atomics.filter(work => Object.entries(additionsFor(work, key)).some(([name, value]) => service.vars[name] !== value));
        for (const work of service.steps) await storeOld(work);
        let written = Object.keys(service.vars).length === 0;
        let resumed = false;
        if (resumeEntries && Object.keys(service.vars).length > 0) {
          let current: RawVariable[] = [];
          try { current = await service.host!.readVariables(service.service); }
          catch (error) {
            if (isCrash(error)) throw error;
            for (const work of service.steps) await fail(work, 'A consumer could not be re-read during recovery; its old key is retained.');
            continue;
          }
          const recordedWrite = [...service.steps].every(work => history.some(entry => entry.event === 'written'
            && entry.serviceKey === key && entry.clusterId === work.step.clusterId && entry.data?.undo !== true));
          resumed = Object.entries(service.vars).every(([name, value]) => current.some(variable => variable.name === name
            && (variable.sealed ? recordedWrite : variable.value !== undefined
              && fingerprint(variable.value, deps.fingerprintKey) === fingerprint(value, deps.fingerprintKey))));
          written ||= resumed;
        }
        const attempts = atomics.length > 0 ? 4 : 1;
        for (let attempt = 0; !written && attempt < attempts; attempt++) {
          try {
            writesBegan = true;
            await service.host!.writeVariables(service.service, service.vars, { skipDeploy: true });
            crash(deps, 'after-write', { serviceKey: key });
            service.rewritten = resumeEntries !== undefined;
            written = true;
          } catch (error) { if (isCrash(error) || error instanceof StopRequestedError) throw error; /* retry atomically rolled credentials before giving up */ }
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
          // An API error can arrive after the host applied some variables. Keep
          // the one-time values unless a read confirms none was delivered.
          try {
            const current = await service.host!.readVariables(service.service);
            deliveryUncertain ||= Object.entries(service.vars).some(([name, value]) => {
              const variable = current.find(variable => variable.name === name);
              return variable?.sealed === true || variable?.value === value;
            });
          } catch (error) { if (isCrash(error)) throw error; deliveryUncertain = true; }
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
          data: { newFingerprint: work.report.newFingerprint, variableNames: Object.keys(service.vars), ...(resumed ? { resumed: true } : {}) },
        });
        log.info('Service variables written.', { serviceKey: key });
      }
      for (const work of works) if (work.unwritten?.size) await valueUnwritten(work);
      // Early preservation can fail before a fallback prompt, then final batched
      // delivery can succeed. Keep that history in the journal, but report the
      // final delivery state so a recovered value is never declared lost.
      for (const work of works) if (work.recoveryMessage && [...work.services].every(key => work.delivered?.has(key))) {
        work.report.warnings = work.report.warnings.filter(warning => warning !== work.recoveryMessage);
        if (work.report.error === work.recoveryMessage) {
          delete work.report.error;
          work.report.status = 'written';
        }
        work.recoveryMessage = undefined;
        warn(work, 'The previously unwritten rolled replacement is now staged for every consumer; no value was lost.');
      }
      for (const work of works) if (work.ready && work.report.status !== 'failed') work.report.status = 'written';

      async function revokeOld(work: StepWork): Promise<void> {
        if (!work.ready || work.report.status === 'failed' || ![...work.services].every(key => services.get(key)!.written)) return;
        if (work.report.status === 'revoked') return;
        const result = work.result!;
        if (work.oldRevoked) { await transition(work, 'revoked', 'revoked'); return; }
        if (revoke === 'never') return;
        if (holdRevocation && anyFailure()) {
          warn(work, 'A failure in this wave holds further old-key revocations; finish the successful clusters manually.');
          return;
        }
        if (aborted) {
          warn(work, 'Cancellation blocks old-key revocation; the old key is retained.');
          return;
        }
        if (heldByReadOnly(work)) return;
        if (blockedBySealed(work)) return;
        if (work.retainOldKey) {
          const message = 'The old key was kept because it ships inside web pages or mobile apps: delete it yourself in the provider console once every shipped client uses the replacement.';
          if (!work.report.warnings.includes(message)) warn(work, message);
          return;
        }
        if (localGeneration(work)) {
          if ([...work.services].every(key => activationFor(work, key) === 'success')) {
            work.oldRevoked = true;
            await transition(work, 'revoked', 'revoked', { local: true });
          }
          return;
        }
        if (!result.oldKeyRef || !work.provider!.revoke) {
          warn(work, 'Old key could not be identified or revoked automatically; revoke it manually after confirming every consumer.');
          return;
        }
        try {
          const contextService = services.get(work.contextService!)!;
          const ctx: ProviderContext = { ...work.ctx!, siblingVars: providerSiblings(work, { ...work.ctx!.siblingVars, ...contextService.vars }) };
          if (resumeEntries && work.oldValue !== undefined) {
            const previous = await work.provider!.verify(work.oldValue, work.ctx!);
            if (!previous.ok && previous.status === 401) {
              work.oldRevoked = true;
              await transition(work, 'revoked', 'revoked', { alreadyRevoked: true });
              return;
            }
          }
          crash(deps, 'before-revoke', { clusterId: work.step.clusterId });
          await work.provider!.revoke!(result.oldKeyRef, ctx);
          crash(deps, 'after-revoke', { clusterId: work.step.clusterId });
          work.oldRevoked = true;
          await transition(work, 'revoked', 'revoked');
          log.info('Old credential revoked.', { clusterId: work.step.clusterId });
        } catch (error) {
          if (isCrash(error)) throw error;
          if (error instanceof StopRequestedError) throw error;
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
        const mode = activationMode(service.service, service.host!);
        if (service.written && mode === 'on-write' && !redeploy) for (const work of service.steps) {
          warn(work, `${service.service.host}/${service.service.serviceName} (${key}) deploys on every write, so the new values went live without a separate redeploy.`);
        }
        if (!service.written) state = 'skipped';
        // The write itself made the values live (Supabase Edge Function secrets): there is no deployment to wait for.
        else if (mode === 'immediate') state = 'success';
        // An on-write host already deployed with the write; its redeploy() only reports that deployment, so it is
        // confirmed even when redeploys are turned off.
        else if (mode !== 'on-write' && (!redeploy || !service.host!.capabilities.redeploy)) state = 'unconfirmed';
        else try {
          const previous = history.filter(entry => entry.serviceKey === key && entry.event === 'redeploy' && entry.data?.undo !== true).at(-1);
          if (!service.rewritten && previous && typeof previous.data?.deploymentId === 'string') deploymentId = previous.data.deploymentId;
          else {
            deploymentId = await service.host!.redeploy(service.service);
            crash(deps, 'after-redeploy', { serviceKey: key });
            await journal('redeploy', { serviceKey: key, data: { deploymentId } });
          }
          if (deploymentId === null) state = 'unconfirmed';
          else {
            const start = now().getTime();
            let waited = 0;
            while (true) {
              const polled = await service.host!.deploymentStatus(service.service, deploymentId);
              if (polled !== 'pending') { state = polled; crash(deps, 'after-deploy-result', { serviceKey: key }); break; }
              const elapsed = Math.max(0, now().getTime() - start, waited);
              if (elapsed >= timeout) { timedOut = true; break; }
              const delay = Math.min(interval, timeout - elapsed);
              await sleep(delay);
              waited += delay;
            }
          }
        } catch (error) { if (isCrash(error) || error instanceof StopRequestedError) throw error; if (error instanceof JournalFailure) throw error; }
        if (state === 'success' && deps.healthCheck) {
          let health: { ok: boolean; detail: string };
          try { health = await deps.healthCheck(key); }
          catch (error) { if (isCrash(error)) throw error; health = { ok: false, detail: 'Health check could not be completed.' }; }
          if (!health.ok) {
            state = 'failed';
            for (const work of service.steps) warn(work, health.detail);
          }
        }
        // Latch before awaiting persistence: another worker may otherwise start
        // a deployment while this known failure is still being journalled.
        if (state === 'failed' && stopOnFirstFailure) waveStopped = true;
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
      // Bound both deployment starts and their polling; a failed wave starts no further deployments.
      const deploymentServices = [...services].filter(([, service]) => !isRailwayShared(service.service));
      let nextService = 0;
      let deploymentStopped = false;
      const deploymentTasks = Array.from({ length: Math.min(deps.crashHook ? 1 : deployConcurrency, deploymentServices.length) }, async () => {
        while (!deploymentStopped && !waveStopped && nextService < deploymentServices.length) {
          const [key, service] = deploymentServices[nextService++]!;
          try { await deployService(key, service); }
          catch (error) { if (isCrash(error)) throw error; deploymentStopped = true; throw error; }
        }
      });
      const deploymentResults = await Promise.allSettled(deploymentTasks);
      for (const result of deploymentResults) if (result.status === 'rejected') throw result.reason;
      if (waveStopped) for (const [key, service] of deploymentServices.slice(nextService)) {
        if (service.steps.size === 0) continue;
        service.activation = 'skipped';
        report.deployments.push({ serviceKey: key, deploymentId: null, state: 'skipped' });
        await journal('deploy-result', { serviceKey: key, data: { deploymentId: null, state: 'skipped', stopped: true } });
        for (const work of service.steps) warn(work, 'Stopped after an earlier failure in this wave.');
      }
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
      const graceHeld = new Set<StepWork>();
      const graceEndings = new Map<StepWork, string>();
      const waveFailure = holdRevocation && anyFailure();
      async function holdSuccessfulClusters(): Promise<void> {
        report.status = 'partial';
        report.pendingRevocations = (report.pendingRevocations ?? []).filter(item =>
          works.find(work => work.step.clusterId === item.clusterId)?.report.status !== 'failed');
        for (const work of works) {
          if (!work.ready || work.oldRevoked || work.report.status === 'failed'
            || ![...work.services].every(key => acceptedActivation(work, key))) continue;
          const nextDeployAcceptance = [...new Map([...work.services].filter(key => activationFor(work, key) === 'unconfirmed')
            .map(key => { const rule = acceptanceFor(key)!; return [rule.host, rule] as const; })).values()];
          const duration = nextDeployAcceptance.length > 0 ? Math.max(...nextDeployAcceptance.map(rule => rule.maxHours)) * 3_600_000 : graceMs;
          const saved = clusterHistory(work.step.clusterId).filter(entry => entry.event === 'grace-start').at(-1)?.data?.deadline;
          const deadline = report.pendingRevocations.find(item => item.clusterId === work.step.clusterId)?.deadline
            ?? graceEndings.get(work) ?? (typeof saved === 'string' ? saved : new Date(now().getTime() + duration).toISOString());
          graceHeld.add(work);
          if (!report.pendingRevocations.some(item => item.clusterId === work.step.clusterId)) {
            report.pendingRevocations.push({ clusterId: work.step.clusterId, deadline,
              undoAvailable: work.oldValue !== undefined && !work.oldRevoked });
            await journal('grace-start', { clusterId: work.step.clusterId, data: { deadline,
              reason: nextDeployAcceptance.length > 0 ? 'next-deploy' : 'wave-failure', waveFailure: true,
              ...(nextDeployAcceptance.length > 0 ? { nextDeployAcceptance } : {}),
            } });
          }
          warn(work, 'A failure in this wave holds further old-key revocations; finish the successful clusters manually.');
        }
      }
      if (waveFailure) await holdSuccessfulClusters();
      if (!aborted && !waveFailure && revoke === 'after-deploy' && (deps.grace || graceMs > 0 || opts.nextDeployAcceptance?.length
        || history.some(entry => entry.event === 'grace-start'))) {
        const eligible = works.filter(work => work.ready && !work.oldRevoked && work.report.status !== 'failed'
          && [...work.services].every(key => acceptedActivation(work, key)) && !heldByReadOnly(work) && !blockedBySealed(work));
        // Each cluster may have a different signed next-deploy maximum.
        const groups = new Map<string, { works: StepWork[]; deadline: string; nextDeploy: ArmedPlan['nextDeployAcceptance'] }>();
        for (const work of eligible) {
          const nextDeploy = [...new Map([...work.services].filter(key => activationFor(work, key) === 'unconfirmed')
            .map(key => { const rule = acceptanceFor(key)!; return [rule.host, rule] as const; })).values()];
          const saved = clusterHistory(work.step.clusterId).filter(entry => entry.event === 'grace-start').at(-1)?.data?.deadline;
          const duration = nextDeploy.length > 0 ? Math.max(...nextDeploy.map(rule => rule.maxHours)) * 3_600_000 : graceMs;
          if (duration === 0 && typeof saved !== 'string' && !deps.grace) continue;
          const deadline = typeof saved === 'string' && Number.isFinite(Date.parse(saved)) ? saved : new Date(now().getTime() + duration).toISOString();
          const groupKey = `${deadline}:${nextDeploy.length > 0 ? 'next-deploy' : 'grace'}`;
          const group = groups.get(groupKey) ?? { works: [], deadline, nextDeploy: [] };
          group.works.push(work);
          group.nextDeploy.push(...nextDeploy);
          groups.set(groupKey, group);
        }
        for (const group of groups.values()) {
          const eligible = group.works;
          const savedDeadlines = eligible.map(work => clusterHistory(work.step.clusterId).filter(entry => entry.event === 'grace-start').at(-1)?.data?.deadline)
            .filter((value): value is string => typeof value === 'string' && Number.isFinite(Date.parse(value)));
          const deadline = savedDeadlines.length > 0 ? savedDeadlines.sort()[0]! : group.deadline;
          const info: GraceInfo = { planId: plan.id, deadline, clusters: eligible.map(work => ({
            clusterId: work.step.clusterId, hint: work.step.hint, undoAvailable: work.oldValue !== undefined && !work.oldRevoked,
          })) };
          for (const work of eligible) {
            const nextDeployAcceptance = [...new Map([...work.services].filter(key => activationFor(work, key) === 'unconfirmed')
              .map(key => { const rule = acceptanceFor(key)!; return [rule.host, rule] as const; })).values()];
            await journal('grace-start', { clusterId: work.step.clusterId, data: {
              deadline, ...(nextDeployAcceptance.length > 0 ? { reason: 'next-deploy', nextDeployAcceptance } : {}),
            } });
          }
          let decision: GraceDecision;
          if (deps.grace) {
            decision = await deps.grace(sanitize(info, true));
            if (decision === 'revoke' && (opts.minGraceMs ?? 0) > 0) {
              // Review M1: the team policy's minimum grace counts from each old key's first grace-start.
              const started = Math.min(...eligible.map(work => {
                const at = Date.parse(clusterHistory(work.step.clusterId).find(entry => entry.event === 'grace-start')?.at ?? '');
                return Number.isFinite(at) ? at : now().getTime();
              }));
              if (now().getTime() < started + opts.minGraceMs!) {
                decision = 'defer';
                for (const work of eligible) warn(work, 'The team policy keeps old keys for a minimum grace period. Finish this rotation after it has passed.');
              }
            }
          }
          else if (group.nextDeploy.length > 0) decision = 'defer';
          else {
            await sleep(Math.max(0, Date.parse(deadline) - now().getTime()));
            decision = 'revoke';
            if (deps.healthCheck) for (const key of new Set(eligible.flatMap(work => [...work.services]))) {
              const service = services.get(key)!;
              if (service.activation !== 'success') continue;
              let health: { ok: boolean; detail: string };
              try { health = await deps.healthCheck(key); }
              catch (error) { if (isCrash(error)) throw error; health = { ok: false, detail: 'Health check could not be completed.' }; }
              if (health.ok) continue;
              service.activation = 'failed';
              const deployment = report.deployments.find(item => item.serviceKey === key);
              if (deployment) deployment.state = 'failed';
              await journal('deploy-result', { serviceKey: key,
                data: { deploymentId: deployment?.deploymentId ?? null, state: 'failed', phase: 'grace-health' } });
              for (const work of service.steps) {
                warn(work, health.detail);
                graceHeld.add(work);
                await fail(work, 'Consumer health check failed; the old key is retained.');
              }
            }
            for (const work of eligible) {
              if (work.report.status === 'failed') { graceHeld.add(work); continue; }
              let verified = false;
              try { verified = (await work.provider!.verify(work.result!.newValue, work.newCtx!)).ok; }
              catch (error) { if (isCrash(error)) throw error; }
              if (!verified) { graceHeld.add(work); await fail(work, 'The replacement credential no longer verifies; the old key is retained.'); }
              else { crash(deps, 'after-verify', { clusterId: work.step.clusterId }); await transition(work, 'verified', 'verified'); }
            }
          }
          if (decision === 'defer') {
            report.status = 'grace-pending';
            (report.pendingRevocations ??= []).push(...info.clusters.map(cluster => ({ clusterId: cluster.clusterId, deadline, undoAvailable: cluster.undoAvailable })));
            for (const work of eligible) graceHeld.add(work);
          } else if (decision === 'undo') {
            const values = new Map<string, string>();
            if (!deps.inflight) for (const work of works) {
              if (work.oldValue !== undefined) values.set(`old:${work.step.clusterId}`, work.oldValue);
              if (work.result) {
                values.set(`new:${work.step.clusterId}`, work.result.newValue);
                for (const [name, value] of Object.entries(work.result.companions ?? {})) {
                  values.set(`companion:${work.step.clusterId}:${name}`, value);
                  const old = work.ctx?.siblingVars?.[name];
                  if (old !== undefined) values.set(`old-companion:${work.step.clusterId}:${name}`, old);
                }
              }
            }
            const memory: InFlightStore = { async get(_id, slot) { return values.get(slot) ?? null; },
              async put(_id, slot, value) { values.set(slot, value); }, async slots() { return [...values.keys()]; }, async shred() { values.clear(); } };
            const undone = await undoRotation({ plan, inventory: inv, entries: recorded, clusterIds: eligible.map(work => work.step.clusterId) },
              { ...deps, inflight: deps.inflight ?? memory }, opts);
            for (const work of eligible) {
              graceHeld.add(work);
              if (undone.restored.some(item => item.clusterId === work.step.clusterId)) {
                work.undone = true;
                work.report.status = 'skipped';
                warn(work, 'The old credential was restored.');
              } else await fail(work, undone.unavailable.find(item => item.clusterId === work.step.clusterId)?.reason ?? 'The old credential could not be restored.');
            }
            graceUndid = works.every(work => work.undone || work.report.status === 'revoked');
          }
          if (group.nextDeploy.length > 0 && decision === 'revoke') {
            for (const work of eligible) {
              graceHeld.add(work);
              (report.pendingRevocations ??= []).push({ clusterId: work.step.clusterId, deadline, undoAvailable: work.oldValue !== undefined });
              warn(work, 'Next-deploy activation has not been confirmed; finish this rotation after the accepted maximum.');
            }
            report.status = 'grace-pending';
          }
          if (decision !== 'defer') for (const work of eligible) graceEndings.set(work, deadline);
        }
      }
      if (!waveFailure && holdRevocation && anyFailure()) await holdSuccessfulClusters();
      for (const work of works) {
        if (graceHeld.has(work)) continue;
        if (!work.ready || work.report.status === 'failed') continue;
        const deployed = [...work.services].every(key => activationFor(work, key) === 'success');
        const activatedOrUnconfirmed = [...work.services].every(key => ['success', 'unconfirmed'].includes(activationFor(work, key)));
        if (deployed) {
          if (work.report.status !== 'revoked') work.report.status = 'deployed';
          if (revoke === 'after-deploy' || work.oldRevoked || localGeneration(work)) await revokeOld(work);
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
      if (holdRevocation && anyFailure() && works.some(work => work.ready && !work.oldRevoked
        && work.report.status !== 'failed' && !graceHeld.has(work))) await holdSuccessfulClusters();
      for (const [work, deadline] of graceEndings) await journal('grace-end', { clusterId: work.step.clusterId,
        data: { deadline, pending: work.report.status !== 'revoked' && !work.undone } });
    }
    if (aborted) for (const work of works) if (work.result) {
      warn(work, 'Rotation interrupted: delivery and activation attempts for prepared values finished; no further provider mutations or replacement prompts were started.');
    }
    return await conclude();
  } catch (error) {
    if (isCrash(error)) throw error;
    if (error instanceof RotationAbortedError) {
      // A remote stop forbids cleanup too. Keep prepared values available for
      // manual reconciliation rather than shredding an unused live key.
      if (error instanceof StopRequestedError && works.some(work => work.result && !work.oldRevoked)) {
        unusedReplacementMayBeLive = true;
      }
      // No provider result exists yet: cancel all delivery as well as creation.
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
      aborted = true;
      return await conclude();
    }
    await preserveRolledValues('execution-failure');
    throw error;
  }
}
