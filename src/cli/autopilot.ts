import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import type { StateStore } from '../core/store.js';
import { serviceKey } from '../core/index.js';
import {
  adoptionNeeded, autopilotEligibility, buildArmedPlan, isAlertOnly, signArmedPlan, verifyArmedPlan,
  type AutopilotState, type SelfCheckResult,
} from '../autopilot/index.js';
import { DISARM_PREFIX, type SignedDisarm } from '../approvals/index.js';
import { canonicalJson, signDetached, type DeviceKey } from '../security/index.js';
import type { ArmedCluster, ArmedPlan, AuditLog, Cluster, HostId, Inventory, RotationReport } from '../types.js';
import { CliError } from './errors.js';

export interface EligibilityRow { clusterId: string; hint: string | null; provider: string; eligible: boolean; reason?: string }
export interface ArmOptions {
  clusterIds?: string[]; hosts?: HostId[]; graceMinutes?: number; maxServices?: number; validDays?: number;
  healthChecks?: ArmedPlan['healthChecks']; nextDeployAcceptance?: ArmedPlan['nextDeployAcceptance'];
  refresh?: boolean; relay?: boolean; remote?: boolean;
}
export type AdoptionUpdates = NonNullable<AutopilotState['adoptionUpdates']>;
/** Local recovery observations; these never widen the signed runner contract. */
export type CliAutopilotState = AutopilotState & { manualAdoptionPending?: Record<string, string> };
export interface AutopilotManagerOptions {
  store: StateStore; audit: AuditLog; projectId: string; deviceKey: () => Promise<DeviceKey>;
  scan: () => Promise<Inventory>; rotateCluster: (clusterId: string) => Promise<RotationReport>;
  assertHuman: (action: string) => void;
  confirmAdoption?: (question: string) => Promise<boolean>;
  emitEligibility?: (rows: EligibilityRow[]) => void;
  settings?: { graceMinutes?: number; maxServices?: number; healthChecks?: ArmedPlan['healthChecks'] };
  relayDisarm?: (signed: SignedDisarm) => Promise<void>;
  selfCheck?: () => Promise<SelfCheckResult>;
  lastNotificationSuccess?: () => Promise<string | null>;
  env?: NodeJS.ProcessEnv; now?: () => Date;
}

export async function recordDrill(store: StateStore, result: { passed: boolean; at: Date }): Promise<void> {
  await store.writeJson('plan', join(store.paths.dir, 'drill.json'), { passed: result.passed, at: result.at.toISOString() });
}

function identities(cluster: Cluster): string[] {
  return cluster.consumers.map(c => `${serviceKey(c.service)}\n${c.varName}`).sort();
}
function currentCluster(original: Cluster, inventory: Inventory): Cluster | undefined {
  const expected = identities(original);
  return inventory.clusters.find(cluster => {
    const actual = identities(cluster);
    return cluster.provider === original.provider && actual.length === expected.length && actual.every((v, i) => v === expected[i]);
  });
}
function unfinished(state: AutopilotState): boolean {
  return state.waves.some(w => w.status !== 'done') || Object.keys((state as CliAutopilotState).manualAdoptionPending ?? {}).length > 0;
}
function completeReport(report: RotationReport): boolean {
  return !report.dryRun && report.status === 'complete' && !report.pendingRevocations?.length
    && report.steps.length > 0 && report.steps.every(step => ['deployed', 'verified', 'revoked'].includes(step.status))
    && report.deployments.every(deploy => deploy.state === 'success');
}

/** CLI-owned persistence and supervised authorization. The watcher never receives this signer. */
export function createAutopilotManager(opts: AutopilotManagerOptions) {
  const now = opts.now ?? (() => new Date());
  const planPath = join(opts.store.paths.dir, 'armed-plan.json');
  const statePath = join(opts.store.paths.dir, 'autopilot.json');
  async function loadPlan(): Promise<ArmedPlan | null> { return opts.store.readJson<ArmedPlan>('plan', planPath); }
  async function loadState(): Promise<CliAutopilotState> {
    const state = await opts.store.readJson<CliAutopilotState>('plan', statePath);
    if (!state) return { armedPlanId: null, disarmed: true, waves: [] };
    if (!Array.isArray(state.waves) || typeof state.disarmed !== 'boolean' || !(typeof state.armedPlanId === 'string' || state.armedPlanId === null)) {
      throw new CliError('Saved autopilot state is invalid. Restore it before changing autopilot.');
    }
    if (state.manualAdoptionPending !== undefined && (!state.manualAdoptionPending || typeof state.manualAdoptionPending !== 'object'
      || Array.isArray(state.manualAdoptionPending) || Object.values(state.manualAdoptionPending).some(id => typeof id !== 'string' || !id))) {
      throw new CliError('Saved adoption recovery state is invalid. Restore it before changing autopilot.');
    }
    return state;
  }
  async function saveState(state: AutopilotState): Promise<void> { await opts.store.writeJson('plan', statePath, state); }
  function localOnly(options: { relay?: boolean; remote?: boolean }): void {
    if (options.relay || options.remote) throw new CliError('Arming is a local change. Run this command on your registered computer.');
  }
  async function requireDrill(): Promise<void> {
    const drill = await opts.store.readJson<{ passed?: unknown; at?: unknown }>('plan', join(opts.store.paths.dir, 'drill.json'));
    const time = typeof drill?.at === 'string' ? Date.parse(drill.at) : NaN;
    const age = now().getTime() - time;
    if (drill?.passed !== true || !Number.isFinite(age) || age < 0 || age >= 86_400_000) {
      throw new CliError('Run a passing keysentry drill within the last 24 hours before arming.');
    }
  }
  async function trustedPlan(): Promise<ArmedPlan> {
    const key = await opts.deviceKey();
    const checked = verifyArmedPlan(await loadPlan(), { now: now(), trustedKeyIds: [key.keyId] });
    if (!checked.ok) throw new CliError(`The armed plan cannot be refreshed: ${checked.reason}`);
    if (checked.plan.projectId !== opts.projectId) throw new CliError('The armed plan belongs to another project.');
    return checked.plan;
  }
  async function saveSigned(body: Omit<ArmedPlan, 'signer' | 'sig'>, state: AutopilotState, kind: string, activate = true): Promise<ArmedPlan> {
    const signed = signArmedPlan(body, await opts.deviceKey());
    await opts.store.writeJson('plan', planPath, signed);
    state.armedPlanId = signed.id;
    if (activate) { state.disarmed = false; delete state.disarmedAt; }
    delete state.adoptionUpdates; delete state.adoptionUpdatesPlanId; delete state.adoptionNoticeSent;
    await saveState(state);
    await opts.audit.append({ kind: `autopilot:${kind}`, summary: kind === 'arm' ? 'Autopilot armed.' : 'Autopilot plan replaced.',
      data: { planId: signed.id, clusters: signed.clusters.length, hosts: signed.hosts.length } });
    return signed;
  }

  async function refreshAdoptionUpdates(updates: AdoptionUpdates, options: { inventory?: Inventory; reports?: RotationReport[] } = {}, activate = false): Promise<ArmedPlan | null> {
    const state = await loadState();
    const current = await loadPlan();
    updates = state.adoptionUpdatesPlanId === current?.id ? { ...state.adoptionUpdates, ...updates } : { ...updates };
    if (!Object.keys(updates).length) return current;
    const plan = await trustedPlan();
    if (state.armedPlanId !== plan.id) throw new CliError('The active armed plan changed. Review it before refreshing adopted keys.');
    if (unfinished(state)) throw new CliError('Finish pending or stopped waves before refreshing adopted keys.');
    if (options.reports && options.reports.some(report => !completeReport(report))) {
      throw new CliError('Finish the rotation and confirm activation before refreshing adopted keys.');
    }
    const inventory = options.inventory ?? await opts.scan();
    if (inventory.errors.length) throw new CliError('The scan was incomplete. Resolve its errors before refreshing adopted keys.');
    const clusters: ArmedCluster[] = plan.clusters.map(cluster => {
      const update = updates[cluster.clusterId];
      if (!update) return structuredClone(cluster);
      if (!cluster.adopted || !update.keyRef || !update.fingerprint || !Number.isFinite(Date.parse(update.at))) {
        throw new CliError('An adoption update does not match the signed plan. Re-arm after reviewing the key.');
      }
      const consumerIds = cluster.consumers.map(c => `${c.serviceKey}\n${c.varName}`).sort();
      const fresh = inventory.clusters.find(candidate => {
        const actual = identities(candidate);
        return candidate.provider === cluster.provider && actual.length === consumerIds.length && actual.every((id, i) => id === consumerIds[i]);
      });
      if (!fresh || fresh.consumers.some(c => c.fingerprint !== null && c.fingerprint !== update.fingerprint)) {
        throw new CliError('An adopted key changed or its consumers changed. Review and re-arm it.');
      }
      return { ...structuredClone(cluster), clusterId: fresh.id, adopted: { ...update },
        consumers: fresh.consumers.map(c => ({ serviceKey: serviceKey(c.service), varName: c.varName, fingerprint: c.fingerprint })) };
    });
    if (Object.keys(updates).some(id => !plan.clusters.some(c => c.clusterId === id && c.adopted))) {
      throw new CliError('An adoption update does not match the signed plan. Re-arm after reviewing the key.');
    }
    const { signer: _signer, sig: _sig, ...body } = plan;
    body.id = `arm-${now().toISOString().slice(0, 10).replaceAll('-', '')}-${randomBytes(4).toString('hex')}`;
    body.createdAt = now().toISOString(); body.clusters = clusters;
    return saveSigned(body, state, 'refresh', activate);
  }
  const applyAdoptionUpdates = (updates: AdoptionUpdates, options: { inventory?: Inventory; reports?: RotationReport[] } = {}) => refreshAdoptionUpdates(updates, options);

  async function arm(options: ArmOptions = {}): Promise<{ plan: ArmedPlan; refused: { clusterId: string; reason: string }[] }> {
    opts.assertHuman('arm automatic rotations'); localOnly(options);
    let inventory = structuredClone(await opts.scan());
    const previous = await loadPlan();
    const state = await loadState();
    const existingAdoptions = new Map<string, ArmedCluster['adopted']>();
    if (previous) {
      const key = await opts.deviceKey();
      const checked = verifyArmedPlan(previous, { now: now(), trustedKeyIds: [key.keyId] });
      if (checked.ok && checked.plan.projectId === opts.projectId) {
        for (const cluster of inventory.clusters) {
          const signed = checked.plan.clusters.find(c => c.clusterId === cluster.id);
          if (!signed?.adopted || state.adoptionUpdatesPlanId === previous.id && state.adoptionUpdates?.[cluster.id]) continue;
          const current = cluster.consumers.map(c => ({ serviceKey: serviceKey(c.service), varName: c.varName, fingerprint: c.fingerprint }));
          const order = (items: typeof current) => items.map(c => canonicalJson(c)).sort();
          if (canonicalJson(order(current)) !== canonicalJson(order(signed.consumers))) continue;
          Object.assign(cluster, { adopted: { ...signed.adopted } });
          existingAdoptions.set(cluster.id, { ...signed.adopted });
        }
      }
    }
    const rows = inventory.clusters.map(cluster => ({ clusterId: cluster.id, hint: cluster.hint, provider: cluster.provider, ...autopilotEligibility(cluster) }));
    opts.emitEligibility?.(rows);
    await requireDrill();
    if (inventory.errors.length) throw new CliError('The scan was incomplete. Resolve its errors before arming.');
    if (unfinished(state)) throw new CliError('Finish pending or stopped waves before re-arming.');
    if (options.refresh) {
      const plan = await trustedPlan();
      if (!state.adoptionUpdates || state.adoptionUpdatesPlanId !== plan.id) throw new CliError('There are no adopted-key updates for this armed plan.');
      const refreshed = await refreshAdoptionUpdates(state.adoptionUpdates, { inventory }, true);
      return { plan: refreshed!, refused: [] };
    }
    const graceMinutes = options.graceMinutes ?? opts.settings?.graceMinutes ?? 15;
    if (!Number.isFinite(graceMinutes) || graceMinutes < 0) throw new CliError('Grace minutes must be a finite nonnegative number.');
    const resolvedOptions = {
      graceSeconds: Math.round(graceMinutes * 60), maxServicesPerWave: options.maxServices ?? opts.settings?.maxServices ?? 10,
      validDays: options.validDays, healthChecks: options.healthChecks ?? opts.settings?.healthChecks ?? [],
      nextDeployAcceptance: options.nextDeployAcceptance,
    };
    // Validate all authorization settings before adoption can change a provider or host.
    buildArmedPlan({ projectId: opts.projectId, inventory, clusterIds: [], hosts: options.hosts ?? inventory.hosts, now: now(), options: resolvedOptions });
    const selected = options.clusterIds ?? inventory.clusters.map(c => c.id);
    const selectedIds: string[] = []; const adopted = existingAdoptions;
    for (const id of new Set(selected)) {
      const cluster = inventory.clusters.find(c => c.id === id);
      if (!cluster || !adoptionNeeded(cluster)) { selectedIds.push(id); continue; }
      // A placeholder tests all other eligibility gates before offering a real write.
      const potential = { ...cluster, adopted: { fingerprint: 'pending-adoption', keyRef: 'pending-adoption', at: now().toISOString() } };
      if (!autopilotEligibility(potential).eligible) { selectedIds.push(id); continue; }
      const hint = cluster.hint ?? cluster.consumers[0]?.varName ?? cluster.provider;
      if (!await opts.confirmAdoption?.(`This will rotate ${hint} now so keysentry knows the new value. Rotate now? [y/N]`)) { selectedIds.push(id); continue; }
      const report = await opts.rotateCluster(id);
      const step = report.steps.find(s => s.clusterId === id);
      if (!completeReport(report) || !step?.newFingerprint || !step.newKeyRef
        || cluster.consumers.some(c => !report.deployments.some(d => d.serviceKey === serviceKey(c.service) && d.state === 'success'))) {
        throw new CliError('Finish the supervised rotation and confirm activation before arming this key.');
      }
      const freshInventory = structuredClone(await opts.scan());
      if (freshInventory.errors.length) throw new CliError('The scan after adoption was incomplete. Scan again before arming.');
      const fresh = currentCluster(cluster, freshInventory);
      if (!fresh || fresh.consumers.some(c => c.fingerprint !== null && c.fingerprint !== step.newFingerprint)) {
        throw new CliError('The adopted key or its consumers changed. Scan and review before arming.');
      }
      adopted.set(fresh.id, { fingerprint: step.newFingerprint, keyRef: step.newKeyRef, at: now().toISOString() });
      for (const candidate of freshInventory.clusters) {
        const record = adopted.get(candidate.id);
        if (record) Object.assign(candidate, { adopted: record });
      }
      selectedIds.push(fresh.id); inventory = freshInventory;
    }
    for (const cluster of inventory.clusters) {
      const record = adopted.get(cluster.id);
      if (record) Object.assign(cluster, { adopted: record });
    }
    const built = buildArmedPlan({ projectId: opts.projectId, inventory, clusterIds: selectedIds,
      hosts: options.hosts ?? inventory.hosts, now: now(), options: resolvedOptions });
    if (!built.plan.clusters.length) throw new CliError('No selected keys are eligible for autopilot. Review the eligibility reasons.');
    const existed = await loadPlan();
    const plan = await saveSigned(built.plan, state, existed ? 'rearm' : 'arm');
    return { plan, refused: built.refused };
  }

  async function disarm(options: { relay?: boolean } = {}): Promise<{ disarmed: true; relay: boolean }> {
    opts.assertHuman('disarm automatic rotations');
    const state = await loadState(); state.disarmed = true; state.disarmedAt = now().toISOString();
    await saveState(state);
    await opts.audit.append({ kind: 'autopilot:disarm', summary: 'Autopilot disarmed.', data: { relay: options.relay === true } });
    if (options.relay) {
      if (!opts.relayDisarm) throw new CliError('Autopilot is disarmed locally. Configure the watcher relay to also disarm it remotely.');
      const key = await opts.deviceKey(); const body = { keyId: key.keyId, at: now().toISOString() };
      const signed = { ...body, sig: signDetached(key.privateKeyDer, Buffer.from(DISARM_PREFIX + canonicalJson(body))).toString('base64') };
      try { await opts.relayDisarm(signed); }
      catch { throw new CliError('Autopilot is disarmed locally. The relay delivery failed; disarm the watcher directly or try again.'); }
    }
    return { disarmed: true, relay: options.relay === true };
  }

  async function status() {
    const plan = await loadPlan(); const state = await loadState();
    const selfCheck = opts.selfCheck ? await opts.selfCheck() : { ok: false, reasons: ['The watcher self-check has not run.'] };
    const alert = isAlertOnly({ env: opts.env ?? process.env, state, selfCheck });
    const reasons = [...alert.reasons];
    if (Object.keys(state.manualAdoptionPending ?? {}).length) reasons.push('Finish pending manual adopted-key rotations before re-arming.');
    if (!plan) reasons.push('No armed plan is saved.');
    else {
      const key = await opts.deviceKey(); const checked = verifyArmedPlan(plan, { now: now(), trustedKeyIds: [key.keyId] });
      if (!checked.ok) reasons.push(checked.reason);
      if (state.armedPlanId !== plan.id) reasons.push('The saved plan is not the active armed plan.');
    }
    const deadlines = state.waves.filter(w => w.status === 'grace' && w.deadline).map(w => w.deadline!).sort();
    return {
      armedPlan: plan ? { id: plan.id, keys: plan.clusters.length, expiresAt: plan.expiresAt, hosts: plan.hosts } : null,
      disarmed: state.disarmed, alertOnly: reasons.length > 0, reasons,
      waves: state.waves.map(w => ({ id: w.id, incident: w.incidentId, status: w.status, deadline: w.deadline ?? null })),
      lastNotificationSuccess: await opts.lastNotificationSuccess?.() ?? null, nextSettleTime: deadlines[0] ?? null,
      adoptionNotice: state.adoptionUpdates && Object.keys(state.adoptionUpdates).length ? 're-arm to refresh adopted keys' : null,
    };
  }
  return { arm, disarm, status, loadPlan, loadState, saveState, applyAdoptionUpdates };
}
