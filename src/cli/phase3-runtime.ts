import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';
import { createHygieneStateStore, hygieneReport, planSpendLimits, applySpendLimits, buildDigest } from '../hygiene/index.js';
import { createFileMonitorStateStore } from '../monitor/index.js';
import { buildTimeline, readinessScore, renderCard, renderTimelineMarkdown, type TimelineAuditEntry } from '../report/index.js';
import { createDispatcher, signMessage } from '../notify/index.js';
import { createNotificationChannels, notificationEgress, cacheNotificationMessage } from './notifications.js';
import { providerIdSchema } from './schemas.js';
import { runFirstRun } from './first-run.js';
import { CliError } from './errors.js';
import type { KeysentryRuntime } from './runtime.js';
import type { FirstRunResult, Incident, Inventory, NotifyMessage, RotationReport, Signal, ProviderKeyInfo, KeyHygiene } from '../types.js';

const DAY = 86_400_000;
const settingsSchema = z.object({
  graceMinutes: z.number().finite().nonnegative().max(525600),
  rotateEveryDays: z.number().int().positive().max(36500),
  spendCapsUsd: z.partialRecord(providerIdSchema, z.number().finite().nonnegative()),
  digestDay: z.enum(['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun', 'off']),
  showHints: z.boolean(),
}).strict();
export const dashboardSettingsSchema = settingsSchema;
export type DashboardSettings = z.infer<typeof settingsSchema>;

/** The same application operations back terminal commands and the passkey-gated dashboard. */
export function createPhase3Runtime(rt: KeysentryRuntime) {
  const clock = () => rt.now();
  const settingsPath = join(rt.paths.dir, 'dashboard-settings.json');
  const hygieneStore = createHygieneStateStore(rt.store);
  const monitorStore = createFileMonitorStateStore(rt.config.cwd, rt.store);
  let firstRunResult: Promise<FirstRunResult> | undefined;

  async function settings(): Promise<DashboardSettings> {
    const stored = await rt.store.readJson<unknown>('monitor', settingsPath);
    const state = await hygieneStore.load();
    const parsed = settingsSchema.safeParse(stored ?? {
      graceMinutes: (rt.config.rotation.graceMs ?? 120000) / 60000,
      rotateEveryDays: state.settings.rotateEveryDays,
      spendCapsUsd: state.settings.spendCapsUsd,
      digestDay: 'off', showHints: rt.config.settings.autopilot.showHints,
    });
    if (!parsed.success) throw new CliError('Saved dashboard settings are invalid. Restore them before making changes.');
    rt.config.rotation.graceMs = parsed.data.graceMinutes * 60000;
    rt.config.settings.autopilot.graceMinutes = parsed.data.graceMinutes;
    rt.config.settings.autopilot.showHints = parsed.data.showHints;
    return parsed.data;
  }

  async function updateSettings(patch: Partial<DashboardSettings>): Promise<DashboardSettings> {
    rt.assertHuman('change settings');
    const input = settingsSchema.partial().safeParse(patch);
    if (!input.success) throw new CliError('Choose valid settings before saving.');
    const updated = settingsSchema.parse({ ...await settings(), ...input.data });
    const state = await hygieneStore.load();
    state.settings = { rotateEveryDays: updated.rotateEveryDays, spendCapsUsd: updated.spendCapsUsd };
    // Both files contain metadata only and are encrypted by the shared state store.
    await hygieneStore.save(state);
    await rt.store.writeJson('monitor', settingsPath, updated);
    await settings();
    await rt.audit.append({ kind: 'settings:update', summary: 'Dashboard settings updated.' });
    await rt.checkpoint();
    return updated;
  }

  async function hygiene(): Promise<KeyHygiene[]> {
    await settings();
    return rt.safe(hygieneReport({ inventory: await rt.inventory(), state: await hygieneStore.load(),
      monitor: await monitorStore.load(), now: clock() }));
  }

  function firstRun(): Promise<FirstRunResult> {
    // Initial unsaved scans have per-run identifiers. Rebuild against this project's
    // vault fingerprint key, then reuse the in-memory result for this dashboard.
    firstRunResult ??= runFirstRun({ cwd: rt.config.cwd, noSave: true, runtime: rt, git: rt.firstRunGit }).then(scan => scan.result);
    return firstRunResult;
  }

  async function timeline(id: string) {
    if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(id)) throw new CliError('Choose a valid plan or wave identifier.');
    if (!(await rt.audit.verify()).ok) throw new CliError('The audit log could not be verified. Restore its matching vault before exporting a timeline.');
    const waves = (await rt.autopilotManager().loadState()).waves;
    const wave = waves.find(item => item.id === id || item.planId === id);
    const planId = wave?.planId ?? id;
    const entries = (await rt.store.journal().read()).filter(entry => entry.planId === planId);
    const audit: TimelineAuditEntry[] = [];
    try {
      for (const line of (await readFile(rt.paths.audit, 'utf8')).split('\n').filter(Boolean)) {
        const entry = JSON.parse(line) as TimelineAuditEntry;
        if (entry.data?.planId === planId || wave && entry.data?.waveId === wave.id) audit.push(entry);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new CliError('The audit log could not be read for this timeline.');
    }
    if (!entries.length && !audit.length) throw new CliError('That plan or wave has no recorded timeline.');
    const events = buildTimeline(entries, audit, { redactor: rt.redactor });
    return { events, markdown: renderTimelineMarkdown(events) };
  }

  async function card(optIn: { platform: boolean; counts: boolean }) {
    if (typeof optIn?.platform !== 'boolean' || typeof optIn?.counts !== 'boolean') throw new CliError('Choose which card details to share.');
    const inventory = await rt.store.loadInventory() ?? { version: 1, scannedAt: clock().toISOString(), hosts: [], services: [], findings: [], clusters: [], errors: [] } satisfies Inventory;
    const monitor = await monitorStore.load();
    const redeploy = Object.fromEntries(rt.config.hosts.map(host => [host.id, host.capabilities.redeploy]));
    const score = readinessScore({ inventory, configuredCredentials: Object.keys(rt.config.providerCtx.credentials).filter(name => !!rt.config.providerCtx.credentials[name]), redeploy, canaries: monitor.canaries.length }).score;
    const report = await rt.store.readJson<RotationReport>('report', join(rt.paths.dir, 'rotation-report.json'));
    let rotated: { keys: number; seconds: number; platform?: string } | undefined;
    if (report && !report.dryRun) {
      const entries = (await rt.store.journal().read()).filter(entry => entry.planId === report.planId);
      const completed = new Set(entries.filter(entry => entry.event === 'revoked' && !entry.data?.cleanup && !entry.data?.undo && entry.clusterId).map(entry => entry.clusterId));
      if (completed.size) {
        const times = entries.map(entry => Date.parse(entry.at)).filter(Number.isFinite);
        const hosts = [...new Set(inventory.services.map(service => service.host).filter(host => host !== 'dotenv'))];
        rotated = { keys: completed.size, seconds: times.length ? Math.max(0, (Math.max(...times) - Math.min(...times)) / 1000) : 0,
          ...(hosts.length === 1 ? { platform: hosts[0] } : {}) };
      }
    }
    return { svg: renderCard({ score, optIn, ...(rotated ? { rotated } : {}) }), score };
  }

  async function spendLimits(apply: boolean, clusterIds?: string[]) {
    if (typeof apply !== 'boolean' || clusterIds && (!Array.isArray(clusterIds) || clusterIds.some(id => typeof id !== 'string' || !id))) throw new CliError('Choose valid keys for spending limits.');
    if (apply) rt.assertHuman('apply spending limits');
    await settings();
    const inventory = await rt.inventory();
    if (clusterIds?.some(id => !inventory.clusters.some(cluster => cluster.id === id))) throw new CliError('A selected key is no longer in the inventory. Scan and try again.');
    const selected = { ...inventory, clusters: inventory.clusters.filter(cluster => !clusterIds || clusterIds.includes(cluster.id)) };
    const state = await hygieneStore.load(), monitor = await monitorStore.load();
    const skipped: { clusterId: string; reason: string }[] = [];
    const keys: ProviderKeyInfo[] = [];
    const freshSpend: Record<string, number> = {};
    const readCtx = await rt.providerContext('read');
    const provider = rt.providers('openrouter');
    const candidates = selected.clusters.filter(cluster => cluster.provider === 'openrouter' && state.settings.spendCapsUsd.openrouter !== undefined && monitor.keyRefs[cluster.id]);
    if (candidates.length && readCtx.credentials.OPENROUTER_PROVISIONING_KEY && provider.listKeys && provider.usage) {
      keys.push(...await provider.listKeys(readCtx));
      for (const cluster of candidates) {
        const ref = monitor.keyRefs[cluster.id]!;
        if (!keys.some(key => key.keyRef === ref && key.disabled !== true)) continue;
        const sample = await provider.usage(ref, { from: new Date(clock().getTime() - DAY), to: clock() }, readCtx);
        if (typeof sample.cumulativeCostUsd === 'number' && Number.isFinite(sample.cumulativeCostUsd) && sample.cumulativeCostUsd >= 0) freshSpend[cluster.id] = sample.cumulativeCostUsd;
      }
    }
    const allowed = { ...selected, clusters: selected.clusters.filter(cluster => Object.hasOwn(freshSpend, cluster.id)) };
    const input = { inventory: allowed, state, monitor, providerKeys: { openrouter: keys }, currentPeriodSpendUsd: freshSpend };
    const plans = planSpendLimits(input);
    for (const cluster of selected.clusters) if (!plans.some(plan => plan.clusterId === cluster.id)) skipped.push({ clusterId: cluster.id,
      reason: cluster.provider !== 'openrouter' ? 'not available from this provider' : 'No change planned; a configured cap, fresh usage, and a higher or absent provider limit are required.' });
    const applied: string[] = [];
    if (apply) {
      const writeCtx = await rt.providerContext('write');
      for (const plan of plans) {
        const single = { ...input, inventory: { ...allowed, clusters: allowed.clusters.filter(cluster => cluster.id === plan.clusterId) } };
        try {
          await applySpendLimits(single, writeCtx, { dryRun: false });
        } catch {
          await rt.audit.append({ kind: 'spend-limits:failed', summary: 'A spending limit could not be applied. Remaining keys were kept.', data: { clusterId: plan.clusterId } });
          await rt.checkpoint();
          throw new CliError('A spending limit could not be applied. Remaining keys were kept.');
        }
        applied.push(plan.clusterId);
        await rt.audit.append({ kind: 'spend-limits:applied', summary: 'A spending limit was applied.', data: { clusterId: plan.clusterId, limitUsd: plan.limitUsd } });
        await rt.checkpoint();
      }
    }
    return { plans, applied: plans.filter(plan => applied.includes(plan.clusterId)).map(({ clusterId, limitUsd }) => ({ clusterId, limitUsd })), skipped };
  }

  async function digest(send: boolean): Promise<{ message: NotifyMessage; delivered?: string[]; failed?: { id: string; reason: string }[] }> {
    if (send) rt.assertHuman('send the digest');
    const prefs = await settings(), now = clock();
    const inventory = await rt.inventory();
    const incidents = await rt.store.readJson<{ incidents: Incident[] }>('plan', join(rt.paths.dir, 'watcher-incidents.json'));
    const waves = (await rt.autopilotManager().loadState()).waves;
    const first = await firstRun();
    // Persisted monitor approvals do not retain complete signals; include known spend anomalies from their metadata.
    const monitor = await monitorStore.load();
    const signals: Signal[] = monitor.pendingActions.filter(action => action.signalId.startsWith('usage-')).map(action => ({ id: action.signalId, kind: 'usage_anomaly', at: action.createdAt,
      confidence: 'medium', clusterIds: action.clusterIds, summary: '', evidence: {} }));
    const message = buildDigest({ since: new Date(now.getTime() - 7 * DAY).toISOString(), now: now.toISOString(), inventory,
      hygiene: await hygiene(), incidents: incidents?.incidents ?? [], waves, signals, findings: first.findings, showHints: prefs.showHints });
    if (!send) return { message };
    const channelSettings = rt.config.settings.notify.channels;
    const egress = await notificationEgress(channelSettings, rt.vault);
    const http = rt.httpForUrls(egress.trustedUrls, 'notification channel you configured');
    const channels = await createNotificationChannels(channelSettings, { vault: rt.vault, http, redactor: rt.redactor, receipt: rt.receipt });
    const key = await rt.signingKey();
    try {
      const signed = signMessage(message, key);
      const delivery = await createDispatcher(channels, { log: rt.log, now: clock, retries: 1 }).send(signed);
      await cacheNotificationMessage({ store: rt.store, now: clock }, signed, delivery.delivered.length > 0, delivery.delivered);
      await rt.audit.append({ kind: 'notify:digest', summary: 'Weekly digest send completed.', data: { delivered: delivery.delivered.length, failed: delivery.failed.length } });
      await rt.checkpoint();
      return { message, ...delivery };
    } finally { key.privateKeyDer.fill(0); }
  }

  return { settings, updateSettings, hygiene, firstRun, timeline, card, spendLimits, digest };
}
