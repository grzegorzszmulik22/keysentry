import { createHash } from 'node:crypto';
import { buildPlan } from '../core/index.js';
import { actionDigest } from '../approvals/service.js';
import type { ApprovalAction } from '../approvals/service.js';
import { CREDENTIAL_NAMES } from '../vault/credentials.js';
import { canonicalJson } from '../security/index.js';
import { executePlan, finishRotation, resumeRotation, type EngineDeps, type RotateOptions } from '../rotate/index.js';
import { StopRequestedError } from '../rotate/stop.js';
import type {
  ApprovalGrant, ArmedPlan, AuditLog, Cluster, HostAdapter, HostId, Incident, Inventory, JournalEntry, NotifyMessage,
  ProviderAdapter, RotationPlan, RotationReport,
} from '../types.js';
import { autopilotEligibility, verifyArmedPlan } from './armed-plan.js';
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
  /** False means only the start notification was attempted; no provider work could have begun. */
  executionStarted?: boolean;
  approval?: { grant: ApprovalGrant; action: PendingAutopilotAction };
}

export interface PendingAutopilotAction extends ApprovalAction { kind: 'autopilot'; planHash: string }
export interface PendingAsk {
  actionId: string; incidentId: string; clusterIds: string[]; reasons: string[];
  action: PendingAutopilotAction; attempts: number; nextAttemptAt: string;
}

export interface AutopilotState {
  armedPlanId: string | null; disarmed: boolean; disarmedAt?: string; waves: AutopilotWave[];
  /** Observed replacements, retained in encrypted watcher state until a local re-arm. Never signed here. */
  adoptionUpdates?: Record<string, { fingerprint: string; keyRef: string; at: string }>;
  adoptionUpdatesPlanId?: string;
  adoptionNoticeSent?: boolean;
  pendingAsks?: PendingAsk[];
}

export interface AutopilotDeps {
  engine: EngineDeps;
  options: RotateOptions & { showHints?: boolean };
  notify: (message: NotifyMessage) => Promise<void>;
  /** Use the proposed id, or return the approval service's actual id. Two-argument callbacks remain valid. */
  requestApproval: (clusterIds: string[], reasons: string[], actionId?: string, action?: PendingAutopilotAction) => Promise<void | string | { actionId: string }>;
  audit: AuditLog;
  saveState: (state: AutopilotState) => Promise<void>;
  shouldStop?: () => Promise<boolean>;
}

export interface AutopilotInput {
  incident: Incident; armed: unknown; trustedKeyIds: string[]; inventory: Inventory; state: AutopilotState;
  selfCheck: SelfCheckResult; env: NodeJS.ProcessEnv; now: Date;
  ownTokenNames?: string[];
  watcherHost?: HostId | null;
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
  netlify: 'Netlify', 'cloudflare-workers': 'Cloudflare Workers', 'supabase-functions': 'Supabase Edge Functions',
  heroku: 'Heroku', digitalocean: 'DigitalOcean App Platform', coolify: 'Coolify', zeabur: 'Zeabur',
  kubernetes: 'Kubernetes', 'aws-secrets-manager': 'AWS Secrets Manager', 'vault-kv': 'HashiCorp Vault', doppler: 'Doppler', infisical: 'Infisical',
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

/** Stable execution content only: random plan ids and timestamps are not authorization. */
export function planHashFor(plan: RotationPlan): string {
  return createHash('sha256').update(canonicalJson({ steps: plan.steps, services: plan.services })).digest('hex');
}

function scanErrorReason(inventory: Inventory): string {
  const hosts = [...new Set(inventory.errors.map(error => PLATFORM[error.host] ?? 'Unknown platform'))].sort().join(', ');
  return `Some platforms could not be scanned (${hosts}); keysentry won't rotate automatically until every copy can be checked.`;
}

const ownName = (name: string, extra: readonly string[] = []) => CREDENTIAL_NAMES.includes(name)
  || name.startsWith('KEYSENTRY_') || extra.includes(name);
const keyNames = (inventory: Inventory, ids: string[]) => [...new Set(inventory.clusters.filter(cluster => ids.includes(cluster.id))
  .flatMap(cluster => cluster.consumers.map(consumer => consumer.varName)))].filter(name => /^[A-Z][A-Z0-9_]{0,199}$/.test(name)).sort();

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

function queueAsk(state: AutopilotState, incidentId: string, clusterIds: string[], reasons: string[], inventory: Inventory, now: Date): void {
  if (!clusterIds.length) return;
  const planHash = planHashFor(buildPlan(inventory, { clusterIds }));
  const actionId = `approval-${digest(canonicalJson([incidentId, clusterIds, planHash]))}`;
  const pending = state.pendingAsks ??= [];
  if (pending.some(item => item.actionId === actionId)) return;
  pending.push({ actionId, incidentId, clusterIds: [...clusterIds], reasons: [...reasons],
    action: { id: actionId, kind: 'autopilot', clusterIds: [...clusterIds], planHash }, attempts: 0, nextAttemptAt: now.toISOString() });
}

async function sendPendingAsks(state: AutopilotState, deps: AutopilotDeps, now: () => Date): Promise<void> {
  for (const pending of [...state.pendingAsks ?? []]) {
    if (Date.parse(pending.nextAttemptAt) > now().getTime()) continue;
    const r = reporter(deps, pending.incidentId, `wave-${pending.incidentId}`, pending.clusterIds, now);
    // The exact proposed action is durable before an external request or notification.
    pending.attempts++;
    pending.nextAttemptAt = new Date(now().getTime() + Math.min(3_600_000, 60_000 * 2 ** Math.min(6, pending.attempts - 1))).toISOString();
    await deps.saveState(state);
    try {
      await r.audit('ask', { asked: pending.clusterIds.length });
      const result = await deps.requestApproval([...pending.clusterIds], [...pending.reasons], pending.actionId, structuredClone(pending.action));
      const actionId = typeof result === 'string' ? result : result?.actionId ?? pending.actionId;
      await r.notify('ask', 'warning', `${pending.clusterIds.length} keys need your approval.`, [...pending.reasons], actionId);
    } catch {
      await r.audit('ask-pending', { asked: pending.clusterIds.length, attempts: pending.attempts });
      continue;
    }
    state.pendingAsks = state.pendingAsks!.filter(item => item.actionId !== pending.actionId);
    await deps.saveState(state);
  }
}

/** Call on every watcher tick, including ticks with no newly triggered incident. */
export function retryPendingAsks(input: { state: AutopilotState; now: Date }, deps: AutopilotDeps): Promise<void> {
  return serialize(input.state, () => sendPendingAsks(input.state, deps, operationClock(input.now, deps)));
}

type WavePolicy = Pick<ArmedPlan, 'clusters' | 'healthChecks' | 'graceSeconds' | 'nextDeployAcceptance'>;
const defaultPolicy = (): WavePolicy => ({ clusters: [], healthChecks: [], graceSeconds: 900, nextDeployAcceptance: [] });

function options(deps: AutopilotDeps, armed: WavePolicy): RotateOptions {
  return { ...deps.options, revoke: 'after-deploy', redeploy: true, revokeUnconfirmed: false,
    acceptUnplannedSealed: false, allowGenerate: true, deployConcurrency: 1,
    stopOnFirstFailure: true, holdRevocationOnAnyFailure: true,
    graceMs: armed.graceSeconds * 1_000, nextDeployAcceptance: armed.nextDeployAcceptance,
    // Caller options cannot supply unsigned provider identities to unattended execution.
    adoptedKeyRefs: Object.fromEntries(armed.clusters.filter(cluster => cluster.adopted?.keyRef)
      .map(cluster => [cluster.clusterId, cluster.adopted!.keyRef!])) };
}

function engineDeps(deps: AutopilotDeps, armed: WavePolicy, state: AutopilotState, env: NodeJS.ProcessEnv,
  selfCheck: SelfCheckResult, now: () => Date, r: Reporter, trustedKeyIds: string[], forcedDisarm = false,
  settling = false, priorRevocationPossible = false, authorized?: () => boolean) {
  let failed = false;
  let healthFailed = false;
  let oldRevocationAttempted = priorRevocationPossible;
  let polledStop = false;
  const blocked = () => forcedDisarm || isAlertOnly({ env, state, selfCheck }).alertOnly
    || polledStop || (authorized ? !authorized() : !('id' in armed) || state.armedPlanId !== armed.id
      || !verifyArmedPlan(armed, { now: now(), trustedKeyIds }).ok);
  async function shouldStop(): Promise<boolean> {
    if (!polledStop) {
      try {
        const stopped = Boolean(await deps.shouldStop?.()) || Boolean(await deps.engine.shouldStop?.());
        polledStop ||= stopped;
      }
      catch { polledStop = true; }
      if (polledStop) { state.disarmed = true; state.disarmedAt = now().toISOString(); await deps.saveState(state); }
    }
    return blocked();
  }
  async function active(): Promise<void> { if (await shouldStop()) throw new StopRequestedError(); }
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
      async writeVariables(service, vars, opts) { await active(); await host.writeVariables(service, vars, opts); },
      async redeploy(service) { await active(); return host.redeploy(service); },
      deploymentStatus: (service, id) => host.deploymentStatus(service, id),
    };
  }
  const providers: EngineDeps['providers'] = id => {
    const provider = deps.engine.providers(id);
    return new Proxy(provider, {
      get(target, property) {
        const value: unknown = Reflect.get(target, property, target);
        if (typeof value !== 'function') return value;
        if (!['rotate', 'rotateByRef', 'revoke', 'cap'].includes(String(property))) return value.bind(target);
        return async (...args: unknown[]) => {
          await active();
          if (settling && property === 'revoke') oldRevocationAttempted = true;
          return Reflect.apply(value, target, args);
        };
      },
    }) as ProviderAdapter;
  };
  const sleep = deps.engine.sleep ?? (ms => new Promise<void>(resolve => setTimeout(resolve, ms)));
  const engine: EngineDeps = { ...deps.engine, hosts, providers, now, shouldStop, prompt: async () => null, reveal: undefined,
    providerCtx: { ...deps.engine.providerCtx, http: {
      async request(request) {
        // A reference lookup can await I/O before creation; authorization must
        // still hold at the subsequent HTTP effect, not just at adapter entry.
        if (request.method !== 'GET') await active();
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
    const hostClusters = inventory.clusters.filter(cluster => cluster.consumers.some(c => c.service.host === incident.host));
    const skipped = hostClusters.filter(cluster => cluster.consumers.some(c => ownName(c.varName, input.ownTokenNames)));
    const candidates = hostClusters.filter(cluster => !skipped.includes(cluster)).map(c => c.id);
    const waveId = `wave-${incident.id}`;
    const r = reporter(deps, incident.id, waveId, candidates, now);
    const ask = async (ids: string[], reasons: string[]) => {
      queueAsk(state, incident.id, ids, reasons, inventory, now());
      await deps.saveState(state);
      await sendPendingAsks(state, deps, now);
    };
    if (!verified.ok) {
      await r.audit('verification-failed', { asked: candidates.length });
      await r.notify('verification-failed', 'urgent', `Your armed plan could not be verified (${verified.reason}); nothing was rotated.`);
      await ask(candidates, [verified.reason]);
      return { executed: [], asked: candidates };
    }
    await r.audit('verified');
    if (state.waves.some(wave => wave.incidentId === incident.id)) {
      await r.audit('duplicate');
      await sendPendingAsks(state, deps, now);
      return { executed: [], asked: [] };
    }
    const ownLines = skipped.length || input.watcherHost === incident.host ? [
      `Keys handled by rotation or approval: ${keyNames(inventory, candidates).join(', ') || 'none'}.`,
      `Watcher credentials skipped: ${[...new Set([...keyNames(inventory, skipped.map(cluster => cluster.id)), ...input.ownTokenNames ?? []])]
        .filter(name => /^[A-Z][A-Z0-9_]{0,199}$/.test(name)).join(', ') || 'the configured watcher credentials'}. Rotate these on your own computer.`,
    ] : [];
    if (ownLines.length) await r.notify('own-credentials', 'warning', 'Incident rotation coverage.', ownLines);
    if (inventory.errors.length) {
      const reason = scanErrorReason(inventory);
      await r.audit('scan-incomplete', { asked: candidates.length });
      await ask(candidates, [reason]);
      return { executed: [], asked: candidates };
    }
    const gate = isAlertOnly({ env: input.env, state, selfCheck: input.selfCheck });
    const wrongPlan = state.armedPlanId !== null && state.armedPlanId !== verified.plan.id;
    if (gate.alertOnly || wrongPlan || incident.status !== 'triggered' || !incident.trigger) {
      const reasons = gate.alertOnly ? gate.reasons : [wrongPlan ? 'The active armed plan changed.' : 'This incident does not authorize automatic rotation.'];
      await r.audit('alert-only', { asked: candidates.length });
      await r.notify('alert', 'warning', `${PLATFORM[incident.host]} incident: ${candidates.length} keys need review.`);
      await ask(candidates, reasons);
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
    queueAsk(state, incident.id, asked, [...new Set(scope.ask.flatMap(item => item.reasons))], inventory, now());
    if (scope.execute.length === 0) {
      await deps.saveState(state);
      await sendPendingAsks(state, deps, now);
      return { executed: [], asked };
    }
    const currentVerification = verifyArmedPlan(armed, { now: now(), trustedKeyIds: input.trustedKeyIds });
    const currentGate = isAlertOnly({ env: input.env, state, selfCheck: input.selfCheck });
    if (!currentVerification.ok || currentGate.alertOnly || state.armedPlanId !== null && state.armedPlanId !== armed.id) {
      const reason = !currentVerification.ok ? currentVerification.reason : 'Automatic rotation is no longer authorized.';
      await r.audit('authorization-changed', { asked: scope.execute.length });
      await ask(scope.execute, [reason]);
      return { executed: [], asked: [...asked, ...scope.execute] };
    }
    const plan = buildPlan(inventory, { clusterIds: scope.execute });
    const wave: AutopilotWave = { id: waveId, incidentId: incident.id, planId: plan.id,
      startedAt: now().toISOString(), status: 'running', plan: structuredClone(plan),
      inventory: structuredClone(inventory), armed: structuredClone(armed), executionStarted: false };
    state.waves.push(wave);
    state.armedPlanId = armed.id;
    await deps.saveState(state);
    await r.audit('start', { execute: scope.execute.length });
    await deps.engine.journal.append({ planId: plan.id, at: now().toISOString(), event: 'plan-start',
      data: { dryRun: deps.options.dryRun, steps: plan.steps.length, autopilot: true } });
    const hints = deps.options.showHints ? plan.steps.map(step => step.hint)
      .filter((hint): hint is string => hint !== null && /^[A-Za-z0-9_-]{1,7}…[A-Za-z0-9_-]{4}$/.test(hint)) : [];
    await r.notify('start', 'info', `${PLATFORM[incident.host]} reported a security incident. Rotating ${scope.execute.length} keys you armed for this.`, hints);
    wave.executionStarted = true;
    await deps.saveState(state);
    const execution = engineDeps(deps, armed, state, input.env, input.selfCheck, now, r, input.trustedKeyIds);
    const report = await executePlan(plan, inventory, execution.engine, options(deps, armed));
    const adoptionUpdates = await recordAdoptions(state, armed, report, deps, r, now);
    await outcome(state, wave, report, deps, r, execution.firstFailure, execution.blocked);
    await sendPendingAsks(state, deps, now);
    return { executed: scope.execute, asked, report,
      ...(Object.keys(adoptionUpdates).length ? { adoptionUpdates } : {}) };
  });
}

export interface ApprovedActionInput {
  /** Obtain this grant from the trusted approval service, never directly from a relay or HTTP body. */
  grant: ApprovalGrant;
  action: PendingAutopilotAction;
  inventory: Inventory;
  armed?: ArmedPlan;
  state: AutopilotState;
  now: Date;
}

function validGrant(grant: ApprovalGrant, action: PendingAutopilotAction, now: Date, trustedKeyIds: string[]): boolean {
  try {
    return action.kind === 'autopilot' && action.clusterIds.length > 0
      && new Set(action.clusterIds).size === action.clusterIds.length && /^[a-f0-9]{64}$/.test(action.planHash)
      && grant.actionId === action.id && grant.digest === actionDigest(action)
      && Number.isFinite(Date.parse(grant.at)) && Date.parse(grant.at) <= now.getTime() + 300_000
      && Number.isFinite(now.getTime()) && (grant.by.kind === 'passkey'
        ? typeof grant.by.credentialId === 'string' && grant.by.credentialId.length > 0
        : grant.by.kind === 'device' && trustedKeyIds.includes(grant.by.keyId));
  } catch { return false; }
}

function approvedIds(inventory: Inventory, ids: string[], armed: ArmedPlan | undefined, deps: AutopilotDeps): string[] {
  return ids.filter(id => {
    const cluster = inventory.clusters.find(cluster => cluster.id === id);
    if (!cluster || cluster.consumers.some(consumer => ownName(consumer.varName))) return false;
    const signed = armed?.clusters.find(item => item.clusterId === id && item.provider === cluster.provider && item.method === cluster.method);
    // A signed reference must still identify the current old key. Inventory adoption is never authority.
    const adopted = signed?.adopted && cluster.consumers.every(consumer => consumer.fingerprint === null
      || consumer.fingerprint === signed.adopted!.fingerprint) ? signed.adopted : undefined;
    const effective: Cluster & { adopted?: typeof adopted } = { ...cluster, adopted };
    if (!autopilotEligibility(effective).eligible) return false;
    const provider = deps.engine.providers(cluster.provider);
    if (provider.method !== cluster.method || typeof provider.rotate !== 'function' || typeof provider.verify !== 'function'
      || cluster.method === 'auto' && typeof provider.revoke !== 'function') return false;
    return cluster.method !== 'auto' || cluster.consumers.some(consumer => !consumer.reference && !consumer.sealed
      && deps.engine.hosts[consumer.service.host]?.capabilities.readValues)
      || Boolean(adopted?.keyRef && typeof provider.rotateByRef === 'function');
  });
}

function approvedPolicy(armed: ArmedPlan | undefined, inventory: Inventory): WavePolicy {
  if (!armed) return defaultPolicy();
  return { ...armed, clusters: armed.clusters.map(signed => {
    const current = inventory.clusters.find(cluster => cluster.id === signed.clusterId
      && cluster.provider === signed.provider && cluster.method === signed.method);
    const adopted = signed.adopted && current?.consumers.every(consumer => consumer.fingerprint === null
      || consumer.fingerprint === signed.adopted!.fingerprint) ? signed.adopted : undefined;
    return { ...signed, adopted };
  }) };
}

/** Execute one service-verified grant under the same mutation and settlement rails as an armed wave. */
export async function executeApprovedAction(input: ApprovedActionInput, deps: WaveRecoveryDeps): Promise<{
  executed: string[]; asked: string[]; guided: string[]; report?: RotationReport; reason?: string;
  adoptionUpdates?: NonNullable<AutopilotState['adoptionUpdates']>;
}> {
  const now = operationClock(input.now, deps);
  const snapshot = structuredClone({ grant: input.grant, action: input.action, inventory: input.inventory, armed: input.armed });
  return serialize(input.state, async () => {
    const { state } = input;
    const { grant, action, inventory } = snapshot;
    const empty = { executed: [] as string[], asked: [] as string[], guided: [] as string[] };
    const waveId = `wave-approved-${action.id}`;
    const r = reporter(deps, action.id, waveId, action.clusterIds, now);
    if (!validGrant(grant, action, now(), deps.trustedKeyIds)) {
      await r.audit('approval-rejected');
      return { ...empty, reason: 'This approval does not match the proposed action.' };
    }
    if (state.waves.some(wave => wave.approval?.action.id === action.id)) {
      await r.audit('duplicate');
      return empty;
    }
    const env = deps.env ?? process.env;
    const selfCheck = deps.selfCheck ?? { ok: false, reasons: ['The watcher self-check is unavailable.'] };
    if (isAlertOnly({ state, env, selfCheck }).alertOnly) {
      await r.audit('approval-paused');
      return { ...empty, reason: 'Approved rotation is paused by the watcher checks.' };
    }
    let armed: ArmedPlan | undefined;
    if (snapshot.armed) {
      const verified = verifyArmedPlan(snapshot.armed, { now: now(), trustedKeyIds: deps.trustedKeyIds });
      if (!verified.ok || state.armedPlanId !== null && state.armedPlanId !== verified.plan.id) {
        await r.audit('approval-plan-rejected');
        return { ...empty, reason: 'The armed plan could not be verified for this approval.' };
      }
      armed = verified.plan;
    }
    const fullPlan = buildPlan(inventory, { clusterIds: action.clusterIds });
    if (inventory.errors.length || fullPlan.steps.length !== action.clusterIds.length || planHashFor(fullPlan) !== action.planHash) {
      const reason = inventory.errors.length ? scanErrorReason(inventory)
        : 'The inventory changed since this approval was requested. Review a new request before rotating.';
      await r.audit('approval-inventory-changed');
      queueAsk(state, action.id, action.clusterIds, [reason], inventory, now());
      await deps.saveState(state);
      await sendPendingAsks(state, deps, now);
      return { ...empty, asked: [...action.clusterIds], reason };
    }
    const execute = approvedIds(inventory, action.clusterIds, armed, deps);
    const guided = action.clusterIds.filter(id => !execute.includes(id));
    const plan = buildPlan(inventory, { clusterIds: execute });
    const wave: AutopilotWave = { id: waveId, incidentId: action.id, planId: plan.id,
      startedAt: now().toISOString(), status: execute.length ? 'running' : 'done', plan, inventory,
      ...(armed ? { armed } : {}), executionStarted: false, approval: { grant, action } };
    state.waves.push(wave);
    await deps.saveState(state);
    if (guided.length) {
      await r.audit('guided', { guided: guided.length });
      await r.notify('guided', 'warning', `${guided.length} approved keys need you for a guided rotation.`,
        [`Keys needing you: ${keyNames(inventory, guided).join(', ') || 'the selected keys'}.`]);
    }
    if (!execute.length) return { ...empty, guided };
    await r.audit('start', { execute: execute.length });
    await deps.engine.journal.append({ planId: plan.id, at: now().toISOString(), event: 'plan-start',
      data: { dryRun: deps.options.dryRun, steps: plan.steps.length, autopilot: true } });
    await r.notify('start', 'info', `Rotating ${execute.length} keys you approved.`);
    wave.executionStarted = true;
    await deps.saveState(state);
    const authorized = () => approvedWaveValid(wave, deps, now())
      && (!armed || state.armedPlanId === null || state.armedPlanId === armed.id);
    const policy = approvedPolicy(armed, inventory);
    const execution = engineDeps(deps, policy, state, env, selfCheck, now, r, deps.trustedKeyIds, false, false, false, authorized);
    const report = await executePlan(plan, inventory, execution.engine, options(deps, policy));
    const adoptionUpdates = armed ? await recordAdoptions(state, armed, report, deps, r, now) : {};
    await outcome(state, wave, report, deps, r, execution.firstFailure, execution.blocked);
    return { executed: execute, asked: [], guided, report,
      ...(Object.keys(adoptionUpdates).length ? { adoptionUpdates } : {}) };
  });
}

function approvedWaveValid(wave: AutopilotWave, deps: WaveRecoveryDeps, now: Date): boolean {
  try {
    if (!wave.approval || !wave.plan || !wave.inventory || wave.inventory.errors.length || wave.plan.id !== wave.planId) return false;
    const { action, grant } = wave.approval;
    if (!validGrant(grant, action, now, deps.trustedKeyIds)) return false;
    if (wave.armed && (!verifyArmedPlan(wave.armed, { now, trustedKeyIds: deps.trustedKeyIds }).ok)) return false;
    const fullPlan = buildPlan(wave.inventory, { clusterIds: action.clusterIds });
    if (fullPlan.steps.length !== action.clusterIds.length || planHashFor(fullPlan) !== action.planHash) return false;
    const ids = approvedIds(wave.inventory, action.clusterIds, wave.armed, deps);
    return ids.length > 0 && planHashFor(buildPlan(wave.inventory, { clusterIds: ids })) === planHashFor(wave.plan);
  } catch { return false; }
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
      const approved = wave.approval !== undefined;
      const armed = verified.ok ? verified.plan : undefined;
      const authorized = approved ? approvedWaveValid(wave, deps, now())
        && (!armed || state.armedPlanId === null || state.armedPlanId === armed.id)
        : armed !== undefined && state.armedPlanId === armed.id && recoveryScopeValid(wave, armed);
      if (!authorized || !wave.plan || !wave.inventory || wave.inventory.errors.length
        || mode === 'settle' && !latestInventory
        || wave.plan.id !== wave.planId) {
        await r.audit(`${mode}-blocked`);
        continue;
      }
      if (mode === 'settle' && latestInventory!.errors.length) {
        await r.audit('settle-scan-incomplete');
        await r.notify('settle-scan-incomplete', 'warning', scanErrorReason(latestInventory!));
        continue;
      }
      const entries: JournalEntry[] = await deps.engine.journal.read(wave.planId);
      const priorRevocationPossible = wave.settlementStarted === true || entries.some(entry => entry.event === 'revoked'
        && entry.data?.cleanup !== true && entry.data?.undo !== true);
      if (mode === 'settle') {
        wave.settlementStarted = true;
        await deps.saveState(state);
      }
      const policy = approved ? approvedPolicy(armed, wave.inventory) : armed!;
      const execution = engineDeps(deps, policy, state, env, selfCheck, now, r, deps.trustedKeyIds,
        input.disarmed, mode === 'settle', priorRevocationPossible,
        approved ? () => approvedWaveValid(wave, deps, now())
          && (!armed || state.armedPlanId === null || state.armedPlanId === armed.id) : undefined);
      await r.audit(mode);
      // Null scan fingerprints stay null in signed scope and saved recovery
      // metadata. For finish only, the signed adoption supplies the known old
      // fingerprint needed to detect its reappearance in the latest inventory.
      const plan = mode === 'settle' ? structuredClone(wave.plan) : wave.plan;
      if (mode === 'settle') for (const step of plan.steps) {
        const adopted = policy.clusters.find(cluster => cluster.clusterId === step.clusterId)?.adopted;
        if (!adopted?.keyRef) continue;
        for (const consumer of step.consumers) {
          if (consumer.sealed && consumer.fingerprint === null) consumer.fingerprint = adopted.fingerprint;
        }
      }
      const recovery = { plan, inventory: mode === 'settle' ? latestInventory! : wave.inventory, entries };
      // This marker is persisted only after start notification succeeds, before any engine effects.
      // A notification-only interruption therefore cannot have orphaned a provider key.
      const notificationOnly = mode === 'resume' && wave.executionStarted === false;
      if (notificationOnly) {
        await r.notify('start', 'info', `Starting the saved rotation of ${ids.length} keys.`);
        wave.executionStarted = true;
        await deps.saveState(state);
      }
      const report = mode === 'resume'
        ? notificationOnly
          ? await executePlan(plan, wave.inventory, execution.engine, options(deps, policy))
          : await resumeRotation(recovery, execution.engine, options(deps, policy))
        : await finishRotation(recovery, execution.engine, options(deps, policy));
      const adoptionUpdates = armed ? await recordAdoptions(state, armed, report, deps, r, now) : {};
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
