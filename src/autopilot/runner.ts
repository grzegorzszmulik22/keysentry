import { createHash } from 'node:crypto';
import { buildPlan } from '../core/index.js';
import { canonicalJson } from '../security/index.js';
import { executePlan, finishRotation, resumeRotation, type EngineDeps, type RotateOptions } from '../rotate/index.js';
import { RotationAbortedError } from '../types.js';
import type {
  ArmedPlan, AuditLog, HostAdapter, HostId, Incident, Inventory, JournalEntry, NotifyMessage,
  ProviderAdapter, RotationPlan, RotationReport,
} from '../types.js';
import { verifyArmedPlan } from './armed-plan.js';
import { checkScope } from './scope.js';
import { isAlertOnly, type SelfCheckResult } from './kill-switch.js';

export interface AutopilotWave {
  id: string; incidentId: string; planId: string; startedAt: string;
  status: 'running' | 'grace' | 'done' | 'stopped';
  /** Recovery metadata lives in the caller's encrypted state, never in notification/audit text. */
  deadline?: string;
  /** Persisted before finish, since a crash can follow revocation but precede its journal record. */
  settlementStarted?: boolean;
  plan?: RotationPlan;
  inventory?: Inventory;
  armed?: ArmedPlan;
}

export interface AutopilotState {
  armedPlanId: string | null; disarmed: boolean; disarmedAt?: string; waves: AutopilotWave[];
  /** Observed replacements, retained in encrypted watcher state until a local re-arm. Never signed here. */
  adoptionUpdates?: Record<string, { fingerprint: string; keyRef: string; at: string }>;
  adoptionUpdatesPlanId?: string;
  adoptionNoticeSent?: boolean;
}

export interface AutopilotDeps {
  engine: EngineDeps;
  options: RotateOptions & { showHints?: boolean };
  notify: (message: NotifyMessage) => Promise<void>;
  /** Use the proposed id, or return the approval service's actual id. Two-argument callbacks remain valid. */
  requestApproval: (clusterIds: string[], reasons: string[], actionId?: string) => Promise<void | string | { actionId: string }>;
  audit: AuditLog;
  saveState: (state: AutopilotState) => Promise<void>;
}

export interface AutopilotInput {
  incident: Incident; armed: unknown; trustedKeyIds: string[]; inventory: Inventory; state: AutopilotState;
  selfCheck: SelfCheckResult; env: NodeJS.ProcessEnv; now: Date;
}

export interface WaveRecoveryDeps extends AutopilotDeps {
  trustedKeyIds: string[];
  env?: NodeJS.ProcessEnv;
  selfCheck?: SelfCheckResult;
}

export interface WaveRecoveryInput { state: AutopilotState; now: Date; disarmed: boolean }
export interface WaveSettlementInput extends WaveRecoveryInput { inventory: Inventory }
export interface WaveRecoveryResult {
  resumed: string[]; settled: string[]; reports: RotationReport[];
  adoptionUpdates?: NonNullable<AutopilotState['adoptionUpdates']>;
}

const PLATFORM: Record<HostId, string> = {
  railway: 'Railway', vercel: 'Vercel', render: 'Render', fly: 'Fly', 'github-actions': 'GitHub Actions', dotenv: 'Your local environment',
};
const queues = new WeakMap<AutopilotState, Promise<void>>();

/** A watcher serializes ticks; this additionally serializes overlapping callers sharing the same state object. */
async function serialize<T>(state: AutopilotState, operation: () => Promise<T>): Promise<T> {
  const previous = queues.get(state) ?? Promise.resolve();
  const running = previous.catch(() => {}).then(operation);
  const tail = running.then(() => {}, () => {});
  queues.set(state, tail);
  try { return await running; }
  finally { if (queues.get(state) === tail) queues.delete(state); }
}

function digest(value: string): string { return createHash('sha256').update(value).digest('hex').slice(0, 24); }

/** The tick timestamp is authoritative; elapsed time comes from the engine's injected clock. */
function operationClock(at: Date, deps: AutopilotDeps): () => Date {
  const start = at.getTime();
  const clock = deps.engine.now ?? (() => new Date());
  const baseline = clock().getTime();
  return () => new Date(start + Math.max(0, clock().getTime() - baseline));
}

function reporter(deps: AutopilotDeps, incidentId: string, waveId: string, clusterIds: string[], now: () => Date) {
  let sequence = 0;
  async function audit(step: string, counts: Record<string, number> = {}): Promise<void> {
    await deps.audit.append({ kind: `autopilot:${step}`, summary: `Autopilot ${step}.`,
      data: { incidentId, waveId, clusterIds: [...clusterIds], counts: { clusters: clusterIds.length, ...counts } } });
  }
  async function notify(kind: string, severity: NotifyMessage['severity'], title: string,
    lines: string[] = [], actionId?: string): Promise<void> {
    const at = now().toISOString();
    await deps.notify({ id: `notify-${digest(`${waveId}:${kind}:${at}:${sequence++}`)}`, at,
      kind: `autopilot:${kind}`, severity, title, lines, ...(actionId === undefined ? {} : { actionId }) });
  }
  return { audit, notify };
}

type Reporter = ReturnType<typeof reporter>;

async function ask(deps: AutopilotDeps, r: Reporter, incidentId: string, clusterIds: string[], reasons: string[]): Promise<void> {
  if (clusterIds.length === 0) return;
  const proposed = `approval-${digest(JSON.stringify([incidentId, clusterIds, reasons]))}`;
  await r.audit('ask', { asked: clusterIds.length });
  const result = await deps.requestApproval(clusterIds, reasons, proposed);
  const actionId = typeof result === 'string' ? result : result?.actionId ?? proposed;
  await r.notify('ask', 'warning', `${clusterIds.length} keys need your approval.`, [], actionId);
}

function options(deps: AutopilotDeps, armed: ArmedPlan): RotateOptions {
  return { ...deps.options, revoke: 'after-deploy', redeploy: true, revokeUnconfirmed: false,
    acceptUnplannedSealed: false, allowGenerate: true, deployConcurrency: 1,
    stopOnFirstFailure: true, holdRevocationOnAnyFailure: true,
    graceMs: armed.graceSeconds * 1_000, nextDeployAcceptance: armed.nextDeployAcceptance,
    // Caller options cannot supply unsigned provider identities to unattended execution.
    adoptedKeyRefs: Object.fromEntries(armed.clusters.filter(cluster => cluster.adopted?.keyRef)
      .map(cluster => [cluster.clusterId, cluster.adopted!.keyRef!])) };
}

function engineDeps(deps: AutopilotDeps, armed: ArmedPlan, state: AutopilotState, env: NodeJS.ProcessEnv,
  selfCheck: SelfCheckResult, now: () => Date, r: Reporter, trustedKeyIds: string[], forcedDisarm = false,
  settling = false, priorRevocationPossible = false) {
  let failed = false;
  let healthFailed = false;
  let oldRevocationAttempted = priorRevocationPossible;
  const blocked = () => forcedDisarm || isAlertOnly({ env, state, selfCheck }).alertOnly
    || state.armedPlanId !== armed.id || !verifyArmedPlan(armed, { now: now(), trustedKeyIds }).ok;
  function active(): void { if (blocked()) throw new RotationAbortedError(); }
  async function firstFailure(reason: string): Promise<void> {
    if (failed) return;
    failed = true;
    await r.audit('stopped', { failed: 1 });
    await r.notify('failure', 'urgent', `Stopped: ${reason}. ${oldRevocationAttempted
      ? 'Some old keys may already be revoked.' : 'Every old key is still valid.'}`);
  }
  const hosts: EngineDeps['hosts'] = {};
  for (const [id, host] of Object.entries(deps.engine.hosts) as [HostId, HostAdapter][]) {
    if (!host) continue;
    hosts[id] = { id: host.id, capabilities: host.capabilities,
      listServices: () => host.listServices(), readVariables: service => host.readVariables(service),
      async writeVariables(service, vars, opts) { active(); await host.writeVariables(service, vars, opts); },
      async redeploy(service) { active(); return host.redeploy(service); },
      deploymentStatus: (service, id) => host.deploymentStatus(service, id),
    };
  }
  const providers: EngineDeps['providers'] = id => {
    const provider = deps.engine.providers(id);
    return new Proxy(provider, {
      get(target, property) {
        const value: unknown = Reflect.get(target, property, target);
        if (typeof value !== 'function') return value;
        return (...args: unknown[]) => {
          if (property === 'rotate' || property === 'rotateByRef' || property === 'revoke' || property === 'cap') active();
          if (settling && property === 'revoke') oldRevocationAttempted = true;
          return Reflect.apply(value, target, args);
        };
      },
    }) as ProviderAdapter;
  };
  const sleep = deps.engine.sleep ?? (ms => new Promise<void>(resolve => setTimeout(resolve, ms)));
  const engine: EngineDeps = { ...deps.engine, hosts, providers, now, prompt: async () => null, reveal: undefined,
    providerCtx: { ...deps.engine.providerCtx, http: {
      async request(request) {
        // A reference lookup can await I/O before creation; authorization must
        // still hold at the subsequent HTTP effect, not just at adapter entry.
        if (request.method !== 'GET') active();
        return deps.engine.providerCtx.http.request(request);
      },
    } },
    journal: {
      async read(planId) { return deps.engine.journal.read(planId); },
      async append(entry) {
        await deps.engine.journal.append(entry);
        if (entry.event === 'revoked' && entry.data?.cleanup !== true && entry.data?.undo !== true) oldRevocationAttempted = true;
        await r.audit(entry.event, { ...(entry.clusterId ? { affected: 1 } : {}),
          ...(entry.event === 'deploy-result' ? { deployments: 1 } : {}) });
        if (entry.event === 'failed' || entry.event === 'deploy-result' && entry.data?.state === 'failed') {
          const reason = healthFailed ? 'health check failed'
            : entry.event === 'deploy-result' ? 'deployment failed'
              : entry.data?.phase === 'write' ? 'a service could not be updated' : 'a rotation step failed';
          await firstFailure(reason);
        }
      },
    },
    grace: async () => 'defer',
    async healthCheck(serviceKey) {
      const checks = armed.healthChecks.filter(check => check.serviceKey === serviceKey);
      for (const check of checks) {
        let allOk = true;
        let detail = 'Health check passed.';
        for (let attempt = 0; attempt < 3; attempt++) {
          if (attempt > 0) await sleep(20_000);
          try {
            const response = await deps.engine.providerCtx.http.request({ method: 'GET', url: check.url });
            const ok = check.expectStatus === undefined ? response.status >= 200 && response.status < 300 : response.status === check.expectStatus;
            if (!ok) {
              allOk = false;
              detail = Number.isInteger(response.status) && response.status >= 100 && response.status <= 599
                ? `Health check failed (HTTP ${response.status}).` : 'Health check failed.';
            }
          } catch { allOk = false; detail = 'Health check request failed.'; }
        }
        if (!allOk) { healthFailed = true; return { ok: false, detail }; }
      }
      if (deps.engine.healthCheck) {
        try {
          if (!(await deps.engine.healthCheck(serviceKey)).ok) {
            healthFailed = true; return { ok: false, detail: 'Health check failed.' };
          }
        } catch { healthFailed = true; return { ok: false, detail: 'Health check request failed.' }; }
      }
      return { ok: true, detail: 'Health check passed.' };
    },
  };
  return { engine, firstFailure, blocked };
}

async function outcome(state: AutopilotState, wave: AutopilotWave, report: RotationReport, deps: AutopilotDeps, r: Reporter,
  firstFailure: (reason: string) => Promise<void>, blocked: () => boolean): Promise<void> {
  const failed = report.steps.filter(step => step.status === 'failed' || step.status === 'skipped').length;
  const pending = report.pendingRevocations ?? [];
  const stopped = failed > 0 || report.status === 'partial' || report.status === 'failed' || blocked();
  wave.status = stopped ? 'stopped' : pending.length > 0 ? 'grace' : 'done';
  if (pending.length > 0) wave.deadline = pending.map(item => item.deadline).sort().at(-1);
  else delete wave.deadline;
  await deps.saveState(state);
  if (stopped) await firstFailure(blocked() ? 'automatic rotation is no longer authorized' : 'a rotation step failed');
  if (wave.status === 'grace') {
    await r.audit('grace', { pending: pending.length });
    const time = new Date(wave.deadline!).toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
    await r.notify('grace', 'warning', `New keys are live. Old keys stay valid until ${time}.`);
  }
  await r.audit('end', { total: report.steps.length, failed, pending: pending.length,
    revoked: report.steps.filter(step => step.status === 'revoked').length });
  await r.notify('end', 'info', 'Rotation results.', [
    `${report.steps.length} keys processed. ${failed} failed or skipped. ${pending.length} pending revocations.`,
  ]);
}

async function recordAdoptions(state: AutopilotState, armed: ArmedPlan, report: RotationReport,
  deps: AutopilotDeps, r: Reporter, now: () => Date): Promise<NonNullable<AutopilotState['adoptionUpdates']>> {
  const updates: NonNullable<AutopilotState['adoptionUpdates']> = {};
  const pending = new Set(report.pendingRevocations?.map(item => item.clusterId));
  const entries = await deps.engine.journal.read(report.planId);
  for (const step of report.steps) {
    const cluster = armed.clusters.find(cluster => cluster.clusterId === step.clusterId && cluster.adopted);
    if (!cluster || !step.newFingerprint || !step.newKeyRef) continue;
    // A failed deployment or an ambiguous write response can leave the new key
    // in a write-only consumer. Retain its identity and require local review.
    const delivered = entries.some(entry => entry.data?.undo !== true && (entry.event === 'written' && entry.clusterId === step.clusterId
      || entry.data?.partialWritePossible === true && cluster.consumers.some(consumer => consumer.serviceKey === entry.serviceKey)));
    if (!delivered && !['deployed', 'revoked'].includes(step.status)
      && !(step.status === 'written' && pending.has(step.clusterId))) continue;
    const prior = state.adoptionUpdatesPlanId === armed.id ? state.adoptionUpdates?.[step.clusterId] : undefined;
    updates[step.clusterId] = prior?.keyRef === step.newKeyRef && prior.fingerprint === step.newFingerprint
      ? { ...prior } : { fingerprint: step.newFingerprint, keyRef: step.newKeyRef, at: now().toISOString() };
  }
  if (Object.keys(updates).length === 0) return updates;
  if (state.adoptionUpdatesPlanId !== armed.id) {
    state.adoptionUpdates = {};
    state.adoptionUpdatesPlanId = armed.id;
    state.adoptionNoticeSent = false;
  }
  state.adoptionUpdates = { ...state.adoptionUpdates, ...updates };
  const notify = state.adoptionNoticeSent !== true;
  await deps.saveState(state);
  if (notify) {
    await r.audit('adoption-updated', { updated: Object.keys(updates).length });
    await r.notify('adoption-rearm', 'info', 'Adopted keys changed. Re-arm on your own computer before another automatic rotation.',
      ['The replacement references are saved. The armed plan needs a new local signature.']);
    state.adoptionNoticeSent = true;
    await deps.saveState(state);
  }
  return updates;
}

export async function runAutopilot(input: AutopilotInput, deps: AutopilotDeps): Promise<{
  executed: string[]; asked: string[]; report?: RotationReport;
  adoptionUpdates?: NonNullable<AutopilotState['adoptionUpdates']>;
}> {
  // Authentication is the first operation, before scope, persistence, notification, or audit I/O.
  const verified = verifyArmedPlan(input.armed, { now: input.now, trustedKeyIds: input.trustedKeyIds });
  const now = operationClock(input.now, deps);
  return serialize(input.state, async () => {
    const { state } = input;
    const incident = structuredClone(input.incident);
    const inventory = structuredClone(input.inventory);
    const candidates = inventory.clusters.filter(cluster => cluster.consumers.some(c => c.service.host === incident.host)).map(c => c.id);
    const waveId = `wave-${incident.id}`;
    const r = reporter(deps, incident.id, waveId, candidates, now);
    if (!verified.ok) {
      await r.audit('verification-failed', { asked: candidates.length });
      await r.notify('verification-failed', 'urgent', `Your armed plan could not be verified (${verified.reason}); nothing was rotated.`);
      await ask(deps, r, incident.id, candidates, [verified.reason]);
      return { executed: [], asked: candidates };
    }
    await r.audit('verified');
    if (state.waves.some(wave => wave.incidentId === incident.id)) {
      await r.audit('duplicate');
      return { executed: [], asked: [] };
    }
    const gate = isAlertOnly({ env: input.env, state, selfCheck: input.selfCheck });
    const wrongPlan = state.armedPlanId !== null && state.armedPlanId !== verified.plan.id;
    if (gate.alertOnly || wrongPlan || incident.status !== 'triggered' || !incident.trigger) {
      const reasons = gate.alertOnly ? gate.reasons : [wrongPlan ? 'The active armed plan changed.' : 'This incident does not authorize automatic rotation.'];
      await r.audit('alert-only', { asked: candidates.length });
      await r.notify('alert', 'warning', `${PLATFORM[incident.host]} incident: ${candidates.length} keys need review.`);
      await ask(deps, r, incident.id, candidates, reasons);
      return { executed: [], asked: candidates };
    }
    const armed = verified.plan;
    const scope = checkScope({ plan: armed, inventory, candidateClusterIds: candidates, host: incident.host });
    const pendingAdoptions = state.adoptionUpdatesPlanId === armed.id ? state.adoptionUpdates : undefined;
    const unavailable = scope.execute.filter(id => {
      const cluster = inventory.clusters.find(cluster => cluster.id === id)!;
      return cluster.method === 'auto' && !cluster.consumers.some(consumer => !consumer.reference && !consumer.sealed
        && deps.engine.hosts[consumer.service.host]?.capabilities.readValues)
        && !(armed.clusters.find(cluster => cluster.clusterId === id)?.adopted?.keyRef
          && typeof deps.engine.providers(cluster.provider).rotateByRef === 'function');
    });
    const needsRearm = scope.execute.filter(id => pendingAdoptions?.[id] !== undefined);
    scope.execute = scope.execute.filter(id => !unavailable.includes(id) && !needsRearm.includes(id));
    scope.ask.push(...unavailable.map(clusterId => ({ clusterId,
      reasons: ['The previous key value is unavailable; this provider needs a supervised rotation.'] })));
    scope.ask.push(...needsRearm.filter(id => !unavailable.includes(id)).map(clusterId => ({ clusterId,
      reasons: ['The adopted key changed; re-arm on your own computer before another automatic rotation.'] })));
    await r.audit('scope', { execute: scope.execute.length, asked: scope.ask.length });
    const asked = scope.ask.map(item => item.clusterId);
    await ask(deps, r, incident.id, asked, [...new Set(scope.ask.flatMap(item => item.reasons))]);
    if (scope.execute.length === 0) return { executed: [], asked };
    const currentVerification = verifyArmedPlan(armed, { now: now(), trustedKeyIds: input.trustedKeyIds });
    const currentGate = isAlertOnly({ env: input.env, state, selfCheck: input.selfCheck });
    if (!currentVerification.ok || currentGate.alertOnly || state.armedPlanId !== null && state.armedPlanId !== armed.id) {
      const reason = !currentVerification.ok ? currentVerification.reason : 'Automatic rotation is no longer authorized.';
      await r.audit('authorization-changed', { asked: scope.execute.length });
      await ask(deps, r, incident.id, scope.execute, [reason]);
      return { executed: [], asked: [...asked, ...scope.execute] };
    }
    const plan = buildPlan(inventory, { clusterIds: scope.execute });
    const wave: AutopilotWave = { id: waveId, incidentId: incident.id, planId: plan.id,
      startedAt: now().toISOString(), status: 'running', plan: structuredClone(plan),
      inventory: structuredClone(inventory), armed: structuredClone(armed) };
    state.waves.push(wave);
    state.armedPlanId = armed.id;
    await deps.saveState(state);
    await r.audit('start', { execute: scope.execute.length });
    const hints = deps.options.showHints ? plan.steps.map(step => step.hint)
      .filter((hint): hint is string => hint !== null && /^[A-Za-z0-9_-]{1,7}…[A-Za-z0-9_-]{4}$/.test(hint)) : [];
    await r.notify('start', 'info', `${PLATFORM[incident.host]} reported a security incident. Rotating ${scope.execute.length} keys you armed for this.`, hints);
    const execution = engineDeps(deps, armed, state, input.env, input.selfCheck, now, r, input.trustedKeyIds);
    const report = await executePlan(plan, inventory, execution.engine, options(deps, armed));
    const adoptionUpdates = await recordAdoptions(state, armed, report, deps, r, now);
    await outcome(state, wave, report, deps, r, execution.firstFailure, execution.blocked);
    return { executed: scope.execute, asked, report,
      ...(Object.keys(adoptionUpdates).length ? { adoptionUpdates } : {}) };
  });
}

async function recoverWaves(mode: 'resume' | 'settle', input: WaveRecoveryInput & { inventory?: Inventory }, deps: WaveRecoveryDeps): Promise<WaveRecoveryResult> {
  const now = operationClock(input.now, deps);
  return serialize(input.state, async () => {
    const result: WaveRecoveryResult = { resumed: [], settled: [], reports: [] };
    const latestInventory = mode === 'settle' && input.inventory ? structuredClone(input.inventory) : undefined;
    const state = input.state;
    const env = deps.env ?? process.env;
    const selfCheck = deps.selfCheck ?? { ok: false, reasons: ['The watcher self-check is unavailable.'] };
    if (input.disarmed || isAlertOnly({ state, env, selfCheck }).alertOnly) {
      for (const wave of state.waves.filter(wave => wave.status === (mode === 'resume' ? 'running' : 'grace'))) {
        await reporter(deps, wave.incidentId, wave.id, wave.plan?.steps.map(step => step.clusterId) ?? [], now)
          .audit(`${mode}-alert-only`);
      }
      return result;
    }
    for (const wave of state.waves) {
      if (wave.status !== (mode === 'resume' ? 'running' : 'grace')) continue;
      if (mode === 'settle' && (!wave.deadline || Date.parse(wave.deadline) > now().getTime()
        || !Number.isFinite(Date.parse(wave.deadline)))) continue;
      const ids = wave.plan?.steps.map(step => step.clusterId) ?? [];
      const r = reporter(deps, wave.incidentId, wave.id, ids, now);
      const verified = verifyArmedPlan(wave.armed, { now: now(), trustedKeyIds: deps.trustedKeyIds });
      if (!verified.ok || state.armedPlanId !== verified.plan.id || !wave.plan || !wave.inventory
        || mode === 'settle' && !latestInventory
        || wave.plan.id !== wave.planId || !recoveryScopeValid(wave, verified.plan)) {
        await r.audit(`${mode}-blocked`);
        continue;
      }
      const entries: JournalEntry[] = await deps.engine.journal.read(wave.planId);
      const priorRevocationPossible = wave.settlementStarted === true || entries.some(entry => entry.event === 'revoked'
        && entry.data?.cleanup !== true && entry.data?.undo !== true);
      if (mode === 'settle') {
        wave.settlementStarted = true;
        await deps.saveState(state);
      }
      const execution = engineDeps(deps, verified.plan, state, env, selfCheck, now, r, deps.trustedKeyIds,
        input.disarmed, mode === 'settle', priorRevocationPossible);
      await r.audit(mode);
      // Null scan fingerprints stay null in signed scope and saved recovery
      // metadata. For finish only, the signed adoption supplies the known old
      // fingerprint needed to detect its reappearance in the latest inventory.
      const plan = mode === 'settle' ? structuredClone(wave.plan) : wave.plan;
      if (mode === 'settle') for (const step of plan.steps) {
        const adopted = verified.plan.clusters.find(cluster => cluster.clusterId === step.clusterId)?.adopted;
        if (!adopted?.keyRef) continue;
        for (const consumer of step.consumers) {
          if (consumer.sealed && consumer.fingerprint === null) consumer.fingerprint = adopted.fingerprint;
        }
      }
      const recovery = { plan, inventory: mode === 'settle' ? latestInventory! : wave.inventory, entries };
      const report = mode === 'resume'
        ? await resumeRotation(recovery, execution.engine, options(deps, verified.plan))
        : await finishRotation(recovery, execution.engine, options(deps, verified.plan));
      const adoptionUpdates = await recordAdoptions(state, verified.plan, report, deps, r, now);
      if (Object.keys(adoptionUpdates).length) result.adoptionUpdates = { ...result.adoptionUpdates, ...adoptionUpdates };
      await outcome(state, wave, report, deps, r, execution.firstFailure, execution.blocked);
      result.reports.push(report);
      if (mode === 'resume') result.resumed.push(wave.id);
      else result.settled.push(wave.id);
    }
    return result;
  });
}

/** Resume an interrupted execution, using the exact plan saved before its first effect. */
export function resumeWaves(input: WaveRecoveryInput, deps: WaveRecoveryDeps): Promise<WaveRecoveryResult> {
  return recoverWaves('resume', input, deps);
}

/** Settle due grace periods without ever sleeping through one. Disarm and alert-only skip all engine work. */
export function settleWaves(input: WaveSettlementInput, deps: WaveRecoveryDeps): Promise<WaveRecoveryResult> {
  return recoverWaves('settle', input, deps);
}

/** Recovery metadata is never an independent authorization to widen a signed plan. */
function recoveryScopeValid(wave: AutopilotWave, armed: ArmedPlan): boolean {
  if (!wave.plan || !wave.inventory) return false;
  try {
    const inventory = wave.inventory;
    const ids = wave.plan.steps.map(step => step.clusterId);
    if (ids.length === 0 || new Set(ids).size !== ids.length) return false;
    const host = armed.hosts.find(host => ids.every(id => inventory.clusters.find(cluster => cluster.id === id)
      ?.consumers.some(consumer => consumer.service.host === host)));
    if (!host) return false;
    const scope = checkScope({ plan: armed, inventory, candidateClusterIds: ids, host });
    if (scope.ask.length > 0 || scope.execute.length !== ids.length) return false;
    const rebuilt = buildPlan(inventory, { clusterIds: ids });
    return canonicalJson({ steps: wave.plan.steps, services: wave.plan.services })
      === canonicalJson({ steps: rebuilt.steps, services: rebuilt.services });
  } catch { return false; }
}
