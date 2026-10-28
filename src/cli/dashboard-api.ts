import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';
import { classify, fingerprint } from '../core/index.js';
import { TOKEN_CAPABILITIES } from '../doctor/index.js';
import { describeRuleSource } from '../net/index.js';
import { adoptionNeeded, autopilotEligibility } from '../autopilot/index.js';
import { transactApprovals } from '../approvals/store.js';
import { canonicalJson } from '../security/index.js';
import type { StateStore } from '../core/store.js';
import { createPasskeyStore } from './passkey-store.js';
import { actionDigest } from '../approvals/index.js';
import type { ApprovalAction, StoredApproval } from '../approvals/store.js';
import { providerName } from './provider-names.js';
import { executeLocalApprovedAction } from './phase2.js';
import { CREDENTIAL_NAMES } from '../vault/index.js';
import type { DashboardApi } from '../dashboard/server/api.js';
import type { PasskeyStore } from '../dashboard/server/passkey-gate.js';
import { DashboardError } from '../dashboard/server/security.js';
import type { ApprovalRequest, HostId, RotationPlan, Vault } from '../types.js';
import type { KeysentryRuntime } from './runtime.js';
import { createPhase3Runtime } from './phase3-runtime.js';
import { planIdSchema } from './schemas.js';
import { serviceLabel } from './display.js';
import { saveNotificationSettings } from './config.js';
import { addNotificationChannel, removeNotificationChannel, testNotificationChannels, verifyNotification, notificationEgress, type NotificationContext, type NotifyChannelSettings } from './notifications.js';
import { approveAutopilot } from './autopilot-approvals.js';
import { createCliAutopilotManager } from './phase2.js';
import { trustedWatcherKeys } from './watcher-keys.js';

const text = z.string().min(1).max(1024).refine(value => !/[\x00-\x1f\x7f]/.test(value));
const id = text;
const ids = z.array(id).min(1).max(10_000).refine(values => new Set(values).size === values.length);
const empty = z.object({}).strict();
const credential = z.object({ name: z.enum(CREDENTIAL_NAMES as [string, ...string[]]), role: z.enum(['read', 'write']) }).strict();
const planInput = z.object({ planId: planIdSchema }).strict();
const settingsInput = z.object({
  graceMinutes: z.number().finite().min(0).max(525_600).optional(),
  rotateEveryDays: z.number().int().min(1).max(36_500).optional(),
  spendCapsUsd: z.partialRecord(z.enum(['openai', 'anthropic', 'openrouter', 'stripe', 'resend', 'cloudflare', 'github', 'aws', 'supabase', 'database', 'slack', 'sendgrid', 'twilio', 'google', 'private-key', 'crypto-wallet', 'app-secret', 'encryption-key', 'unknown']), z.number().finite().nonnegative()).optional(),
  digestDay: z.enum(['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun', 'off']).optional(),
  showHints: z.boolean().optional(),
}).strict();
const channelKind = z.enum(['telegram', 'discord', 'slack', 'ntfy', 'webhook', 'resend', 'smtp', 'console']);
const channelInput = z.object({ kind: channelKind, label: text.max(80), settings: z.record(z.string(), text.max(16_384)) }).strict();

function parse<S extends z.ZodType>(schema: S, value: unknown): z.output<S> {
  const result = schema.safeParse(value);
  if (!result.success) throw new DashboardError(400, 'Check the fields for this action and try again.');
  return result.data;
}
const planHash = (plan: RotationPlan) => createHash('sha256').update(canonicalJson(plan)).digest('hex');
const hostCredentials: Partial<Record<HostId, string[]>> = {
  railway: ['RAILWAY_TOKEN', 'RAILWAY_PROJECT_TOKEN'], vercel: ['VERCEL_TOKEN'], render: ['RENDER_API_KEY'], fly: ['FLY_API_TOKEN'], 'github-actions': ['GITHUB_TOKEN'],
};

/** The CLI ceremony and dashboard assertions use the same encrypted state record. */
export function createDashboardPasskeyStore(store: StateStore, vault?: Vault): PasskeyStore {
  return createPasskeyStore(store, vault);
}

/** Route handlers adapt the shared runtime; the dashboard server verifies the passkey before invoking a change. */
export function createDashboardApi(runtime: KeysentryRuntime): DashboardApi {
  const phase3 = createPhase3Runtime(runtime);
  const passkeys = createDashboardPasskeyStore(runtime.store, runtime.vault);
  let armingEpoch = 0;
  const api: DashboardApi = {};
  const read = (name: string, handler: () => Promise<unknown>) => { api[name] = { method: 'GET', mutating: false, handler: async () => runtime.safe(await handler()) }; };
  function post<S extends z.ZodType>(name: string, schema: S, mutating: boolean, handler: (body: z.output<S>) => Promise<unknown>) {
    api[name] = { method: 'POST', mutating, handler: async body => {
      const input = parse(schema, body);
      if (!mutating) return runtime.safe(await handler(input));
      return runtime.dashboardAction(async () => { try { const result = await handler(input); return name === 'reveal' ? result : runtime.safe(result); } finally { await runtime.checkpoint(); } });
    } };
  }
  async function autopilot() {
    const manager = createCliAutopilotManager(runtime);
    const status = await manager.status(); const plan = await manager.loadPlan();
    return {
      state: !plan ? 'off' as const : status.disarmed ? 'disarmed' as const : status.alertOnly ? 'alert-only' as const : 'armed' as const,
      reasons: status.reasons,
      ...(plan ? { plan: { id: plan.id, keys: plan.clusters.length, hosts: plan.hosts, expiresAt: plan.expiresAt, graceMinutes: plan.graceSeconds / 60 } } : {}),
      waves: status.waves.map(wave => ({ id: wave.id, incident: wave.incident, status: wave.status, ...(wave.deadline ? { deadline: wave.deadline } : {}) })),
      lastNotificationAt: status.lastNotificationSuccess, needsRefresh: status.adoptionNotice !== null,
    };
  }
  read('overview', async () => {
    const result = await phase3.firstRun();
    const inv = await runtime.inventory(); const status = await autopilot();
    return { firstRun: result, connectedPlatforms: inv.hosts.filter(host => host !== 'dotenv'), keys: inv.clusters.length,
      inGitHistory: result.findings.filter(item => item.inGitHistory).length,
      needsRotation: inv.clusters.filter(cluster => cluster.fingerprint === null || cluster.consumers.length > 1).length,
      autopilot: status.state, nextSteps: result.nextSteps };
  });
  read('keys', async () => {
    const firstRun = await phase3.firstRun();
    const inv = await runtime.inventory(); const hygiene = await phase3.hygiene(); const manager = createCliAutopilotManager(runtime);
    const plan = await manager.loadPlan(); const armed = !(await manager.loadState()).disarmed;
    return { keys: inv.clusters.map(cluster => {
      const age = hygiene.find(item => item.clusterId === cluster.id);
      const history = firstRun?.findings.some(item => item.id === cluster.id && item.inGitHistory) ?? false;
      const attention = history || cluster.fingerprint === null || cluster.consumers.length > 1;
      return { id: cluster.id, provider: cluster.provider, tier: cluster.tier, hint: cluster.hint, method: cluster.method,
        places: cluster.consumers.map(consumer => ({ label: serviceLabel(consumer.service), host: consumer.service.host, variable: consumer.varName, writeOnly: consumer.sealed })),
        inGitHistory: history, ...(age ? { ageDays: age.ageDays, ...(age.rotateBy ? { rotateBy: age.rotateBy } : {}) } : {}),
        armed: armed && (plan?.clusters.some(item => item.clusterId === cluster.id) ?? false),
        state: attention ? 'attention' : 'ok', stateText: history ? 'Found in git history. Review a rotation.' : cluster.fingerprint === null ? 'This value cannot be read back.' : attention ? 'Used in more than one place.' : 'No current inventory concern.' };
    }) };
  });
  read('platforms', async () => {
    const platforms = [];
    for (const host of Object.keys(hostCredentials) as HostId[]) {
      let source: 'vault' | 'env' | undefined;
      const roles: ('read' | 'write')[] = [];
      for (const role of ['read', 'write'] as const) for (const name of hostCredentials[host]!) {
        const credential = await runtime.credentials.get(name, role);
        if (credential) { runtime.redactor.register(credential.value); source ??= credential.source; if (!roles.includes(role)) roles.push(role); }
      }
      const info = TOKEN_CAPABILITIES[host]!;
      platforms.push({ host, name: info.platform, connected: roles.length > 0, ...(source ? { source } : {}), availableRoles: ['read', ...(info.tokens.some(token => token.canWrite) ? ['write'] : [])], storedRoles: roles, tokens: info.tokens, keysentryUses: info.keysentryUses });
    }
    return { platforms };
  });
  read('access', async () => ({ items: (await runtime.doctor()).items }));
  read('network', async () => ({ allowed: runtime.rules.map(rule => ({ host: rule.host, purpose: rule.purpose, source: describeRuleSource(rule) })), receipt: await runtime.receipt.summarize() }));
  read('rotations', async () => {
    const entries = await runtime.store.journal().read();
    const inv = await runtime.inventory(); const active = [];
    for (const planId of new Set(entries.map(entry => entry.planId))) {
      const own = entries.filter(entry => entry.planId === planId); const end = own.filter(entry => entry.event === 'plan-end').at(-1);
      if (end?.data?.status === 'complete' || end?.data?.status === 'dry-run') continue;
      const grace = own.filter(entry => entry.event === 'grace-start').at(-1);
      const report = await runtime.rotationReport(planId);
      active.push({ planId, status: report?.status ?? (grace ? 'grace-pending' : 'partial'), startedAt: own[0]!.at,
        ...(typeof grace?.data?.deadline === 'string' ? { deadline: grace.data.deadline } : {}),
        steps: (report?.steps ?? []).map(step => ({ clusterId: step.clusterId, hint: inv.clusters.find(cluster => cluster.id === step.clusterId)?.hint ?? null, status: step.status, warnings: step.warnings })) });
    }
    return runtime.safe({ active });
  });
  read('autopilot', autopilot);
  read('autopilot/eligibility', async () => {
    const inv = await runtime.inventory(); const eligible = []; const ineligible = [];
    for (const cluster of inv.clusters) {
      const needsAdoption = adoptionNeeded(cluster);
      const candidate = needsAdoption ? { ...cluster, adopted: { fingerprint: 'pending-adoption', keyRef: 'pending-adoption', at: runtime.now().toISOString() } } : cluster;
      const result = autopilotEligibility(candidate);
      if (result.eligible) eligible.push({ id: cluster.id, hint: cluster.hint, provider: cluster.provider, needsAdoption });
      else ineligible.push({ id: cluster.id, hint: cluster.hint, reason: result.reason ?? 'This key needs supervised rotation.' });
    }
    const drill = await runtime.store.readJson<{ passed: boolean; at: string }>('plan', join(runtime.paths.dir, 'drill.json'));
    return { eligible, ineligible, lastDrillAt: drill?.passed ? drill.at : null };
  });
  read('activity', async () => {
    const verify = await runtime.audit.verify(); let lines: string;
    try { lines = await readFile(runtime.paths.audit, 'utf8'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; lines = ''; }
    const entries = lines.split('\n').filter(Boolean).slice(-200).reverse().map(line => {
      try { const entry = JSON.parse(line) as Record<string, unknown>; return typeof entry.at === 'string' && typeof entry.kind === 'string' && typeof entry.summary === 'string' ? { at: entry.at, kind: entry.kind, summary: entry.summary } : null; } catch { return null; }
    }).filter(entry => entry !== null);
    return runtime.safe({ verify: { ok: verify.ok, ...(verify.problem ? { problem: verify.problem } : {}) }, entries });
  });
  const labelsPath = join(runtime.paths.dir, 'dashboard-notification-labels.json');
  const messagesPath = join(runtime.paths.dir, 'notification-messages.json');
  read('notifications', async () => {
    const labels = await runtime.store.readJson<Record<string, string>>('plan', labelsPath) ?? {};
    const cache = await runtime.store.readJson<{ channelSuccessAt?: Record<string, string> }>('plan', messagesPath);
    const key = await runtime.signingKey();
    try { return { channels: runtime.config.settings.notify.channels.map(channel => ({ id: channel.id, kind: channel.kind, label: labels[channel.id] ?? channel.kind, lastSuccessAt: cache?.channelSuccessAt?.[channel.id] ?? null })), deviceKeyId: key.keyId }; }
    finally { key.privateKeyDer.fill(0); }
  });
  read('approvals', async () => {
    const monitor = await runtime.pendingActions();
    const pending = await Promise.all(monitor.map(async action => {
      const review = await runtime.reviewAction(action.id);
      const rotation = action.action === 'rotate' || action.action === 'breach-mode';
      const changes = [rotation ? 'Create replacement keys, write their consumers and redeploy supported services, then revoke old keys after deployment.'
        : 'Disable or cap the selected keys at the provider. Their consumers may stop working.',
        ...review.plan.steps.map(step => `${providerName(step.provider)} (${step.method}): ${step.consumers.map(consumer => `${serviceLabel(consumer.service)}:${consumer.varName}`).join(', ')}.`),
        ...(rotation ? [review.revokeUnconfirmed ? 'Old keys may be revoked before manual restarts or other unconfirmed activation.' : 'Keep old keys when activation is unconfirmed.',
          ...(review.requiresInteractive ? ['This action requires recovery in an interactive terminal.'] : []),
          ...(review.manualRestarts.length ? [`Restart or activate manually: ${review.manualRestarts.map(serviceLabel).join(', ')}.`] : [])] : []),
      ];
      return { id: action.id, kind: action.action, summary: `${rotation ? 'Rotate' : 'Disable or cap'} ${action.clusterIds.length} selected ${action.clusterIds.length === 1 ? 'key' : 'keys'}.`, changes, reviewHash: review.reviewHash, createdAt: action.createdAt, source: 'monitor' as const };
    }));
    const requests = await transactApprovals(runtime.store, async state => state.requests.filter(request => request.status === 'pending' && Date.parse(request.expiresAt) > runtime.now().getTime()));
    return { pending: [...pending, ...await Promise.all(requests.map(autopilotReview))] };
  });
  async function autopilotReview(request: StoredApproval) {
    const saved = await runtime.store.readJson<{ actions: { action: ApprovalAction; request: ApprovalRequest }[] }>('pending', join(runtime.paths.dir, 'watcher-approvals.json'));
    const action = request.action ?? saved?.actions.find(entry => entry.action?.id === request.actionId && entry.request?.digest === request.digest)?.action;
    if (!action || action.kind !== 'autopilot' || actionDigest(action) !== request.digest) throw new DashboardError(409, 'This approval has no current action details. Review it in your terminal.');
    const inv = await runtime.inventory();
    const changes = ['Autopilot will rotate these selected keys, write replacement values and redeploy supported services. Old keys are revoked after deployment and the configured grace period.',
      ...action.clusterIds.map(id => {
        const cluster = inv.clusters.find(cluster => cluster.id === id);
        return cluster ? `${providerName(cluster.provider)} (${cluster.method}): ${cluster.consumers.map(consumer => `${serviceLabel(consumer.service)}:${consumer.varName}`).join(', ')}.` : `Selected key: ${id}.`;
      }), `Rotation plan: ${action.planHash ?? 'unavailable'}.`];
    return { id: request.actionId, kind: request.kind, summary: `Rotate ${request.keyCount} selected ${request.keyCount === 1 ? 'key' : 'keys'} with autopilot.`, changes,
      reviewHash: createHash('sha256').update(canonicalJson({ action, digest: request.digest, expiresAt: request.expiresAt, changes })).digest('hex'),
      createdAt: request.createdAt, expiresAt: request.expiresAt, source: 'autopilot' as const };
  }
  read('settings', () => phase3.settings());
  read('hygiene', async () => ({ keys: await phase3.hygiene() }));
  post('rotate/preview', z.object({ clusterIds: ids }).strict(), false, async body => {
    const inv = await runtime.inventory();
    if (body.clusterIds.some(id => !inv.clusters.some(cluster => cluster.id === id))) throw new DashboardError(400, 'Select keys from the current inventory.');
    const plan = await runtime.plan({ clusterIds: body.clusterIds }, { preview: true }); const preview = await runtime.rotate(plan);
    return { planId: plan.id, planHash: planHash(plan), changes: preview.diff,
      steps: plan.steps.map(step => ({ clusterId: step.clusterId, hint: step.hint, method: step.method, services: step.consumers.map(consumer => serviceLabel(consumer.service)) })),
      warnings: preview.steps.flatMap(step => step.warnings) };
  });
  post('drill', empty, false, async () => { const start = Date.now(); const drill = await runtime.drill(); return { score: drill.score, reasons: drill.reasons, elapsedMs: Date.now() - start }; });
  post('timeline', z.object({ id }).strict(), false, body => phase3.timeline(body.id));
  post('card', z.object({ platform: z.boolean(), counts: z.boolean() }).strict(), false, body => phase3.card(body));
  post('notifications/verify', z.object({ code: z.string().regex(/^[A-Za-z2-7]{4}-[A-Za-z2-7]{4}$/) }).strict(), false, async body => {
    try { await verifyNotification(await notificationContext(), { code: body.code }); return { valid: true, message: 'Notification signature verified.' }; }
    catch { return { valid: false, message: 'This code could not be verified with a trusted local key.' }; }
  });
  post('autopilot/disarm', empty, false, async () => { armingEpoch++; await runtime.dashboardDisarm(); return { state: 'disarmed' }; });
  post('vault/store', credential.extend({ value: z.string().min(1).max(1_048_576).refine(value => !/[\x00\r\n]/.test(value)) }).strict(), true, async body => { await runtime.vaultSet(body.name, body.value, body.role); await runtime.scan(); return { stored: true }; });
  post('vault/remove', credential, true, async body => ({ removed: (await runtime.vaultRemove(body.name, body.role)).removed }));
  post('rotate/execute', planInput.extend({ planHash: z.string().regex(/^[a-f0-9]{64}$/) }).strict(), true, async body => {
    const plan = await runtime.loadPlan(body.planId);
    if (planHash(plan) !== body.planHash) throw new DashboardError(409, 'The plan changed. Preview it again before rotating.');
    return { report: await runtime.rotate(plan, { execute: true, prompt: async () => null }) };
  });
  post('rotation/finish', planInput.extend({ early: z.boolean() }).strict(), true, async body => ({ report: await runtime.finish(body.planId, body.early) }));
  post('rotation/undo', planInput.extend({ clusterIds: ids.optional() }).strict(), true, async body => {
    const result = await runtime.undo(body.planId, body.clusterIds);
    return { restored: result.restored.map(item => item.clusterId), unavailable: result.unavailable };
  });
  post('autopilot/arm', z.object({ clusterIds: ids, adopt: z.array(id).max(10_000), graceMinutes: z.number().finite().min(0).max(525_600), maxServices: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER), validDays: z.number().int().min(1).max(365) }).strict(), true, async body => {
    if (new Set(body.adopt).size !== body.adopt.length || body.adopt.some(id => !body.clusterIds.includes(id))) throw new DashboardError(400, 'Adoption choices must belong to the selected keys.');
    const generation = armingEpoch; const inv = await runtime.inventory();
    const adoptionOrder = body.clusterIds.filter(id => { const cluster = inv.clusters.find(cluster => cluster.id === id); if (!cluster || !adoptionNeeded(cluster)) return false; const candidate = { ...cluster, adopted: { fingerprint: 'pending-adoption', keyRef: 'pending-adoption', at: runtime.now().toISOString() } }; return autopilotEligibility(candidate).eligible; });
    const assertActive = () => { if (generation !== armingEpoch) throw new DashboardError(409, 'Arming was cancelled because autopilot was disarmed.'); };
    const manager = createCliAutopilotManager(runtime, { assertActive, confirmAdoption: async () => { assertActive(); return body.adopt.includes(adoptionOrder.shift() ?? ''); } });
    try {
      const result = await manager.arm(body); assertActive();
      return { planId: result.plan.id, expiresAt: result.plan.expiresAt, refused: result.refused.map(item => ({ id: item.clusterId, reason: item.reason })) };
    } catch (error) { if (generation !== armingEpoch) await runtime.dashboardDisarm(); throw error; }
  });
  post('notifications/add', channelInput, true, async body => {
    const channel = await addNotification(body);
    return { id: channel.id };
  });
  post('notifications/remove', z.object({ id }).strict(), true, async body => {
    return { removed: await removeNotificationChannel(await notificationContext(), body.id) };
  });
  post('notifications/test', empty, true, async () => {
    const result = await testNotificationChannels(await notificationContext());
    return { delivered: result.delivered, failed: result.failed };
  });
  post('approvals/approve', z.object({ id, reviewHash: z.string().regex(/^[a-f0-9]{64}$/) }).strict(), true, async body => {
    const pending = await transactApprovals(runtime.store, async state => state.requests.find(request => request.actionId === body.id && request.status === 'pending' && Date.parse(request.expiresAt) > runtime.now().getTime()));
    if (pending) {
      const review = await autopilotReview(pending);
      if (review.reviewHash !== body.reviewHash) throw new DashboardError(409, 'The action changed. Review it again before approving.');
    }
    const deviceKeys = async () => { const key = await runtime.signingKey(); try { return [{ keyId: key.keyId, publicKeyDer: key.publicKeyDer }]; } finally { key.privateKeyDer.fill(0); } };
    const result = pending ? await approveAutopilot(body.id, { reviewDigest: pending.digest }, { store: runtime.store, audit: runtime.audit, http: runtime.http, deviceKey: runtime.signingKey,
      deviceKeys, watcherPublicKeys: async () => [], passkeys: () => passkeys.list(), assertHuman: runtime.assertHuman,
      now: runtime.now, confirm: async () => true, executeApprovedAction: actionId => executeLocalApprovedAction(runtime, actionId) }) : null;
    if (result) return { result: result.status };
    const review = await runtime.reviewAction(body.id);
    if (review.reviewHash !== body.reviewHash) throw new DashboardError(409, 'The action changed. Review it again before approving.');
    const approved = await runtime.approve(body.id, { interactive: false, reviewHash: body.reviewHash, prompt: async () => null });
    const action = approved ? undefined : (await runtime.monitorStatus()).pendingActions.find(action => action.id === body.id);
    return { result: approved?.status ?? action?.status ?? 'not-available' };
  });
  post('approvals/dismiss', z.object({ id }).strict(), true, async body => {
    const dismissed = await transactApprovals(runtime.store, async (state, commit) => { const request = state.requests.find(request => request.actionId === body.id && request.status === 'pending'); if (!request) return false; request.status = 'rejected'; await commit(); return true; });
    if (!dismissed) await runtime.dismiss(body.id);
    else await runtime.audit.append({ kind: 'approval-dismiss', summary: 'Pending action dismissed.' });
    return { dismissed: true };
  });
  post('settings/update', settingsInput, true, body => phase3.updateSettings(body));
  post('spend-limits/apply', z.object({ clusterIds: ids }).strict(), true, async body => { const result = await phase3.spendLimits(true, body.clusterIds); return { applied: result.applied, skipped: result.skipped }; });
  post('reveal', z.object({ clusterId: id }).strict(), true, async body => {
    const inv = await runtime.inventory(); const cluster = inv.clusters.find(cluster => cluster.id === body.clusterId);
    if (cluster?.fingerprint) for (const consumer of cluster.consumers) {
      if (consumer.sealed) continue;
      const host = runtime.config.hosts.find(host => host.id === consumer.service.host);
      if (!host?.capabilities.readValues) continue;
      const variables = await host.readVariables(consumer.service);
      const variable = variables.find(variable => variable.name === consumer.varName && !variable.sealed && typeof variable.value === 'string');
      if (variable?.value !== undefined && fingerprint(variable.value, runtime.fingerprintKey) === cluster.fingerprint) {
        runtime.redactor.register(variable.value);
        await runtime.audit.append({ kind: 'reveal', summary: 'A readable value was revealed.', data: { name: consumer.varName, clusterId: cluster.id } });
        return { value: variable.value };
      }
    }
    throw new DashboardError(409, 'This value cannot be read back. Scan again if it has changed.');
  });

  async function notificationContext(): Promise<NotificationContext> {
    const egress = await notificationEgress(runtime.config.settings.notify.channels, runtime.vault);
    const http = runtime.httpForUrls(egress.trustedUrls, 'notification channel you configured');
    return { settings: runtime.config.settings.notify.channels, vault: runtime.vault, http, redactor: runtime.redactor,
      log: runtime.log, store: runtime.store, deviceKey: runtime.signingKey, now: runtime.now, receipt: runtime.receipt, audit: runtime.audit,
      watcherPublicKeys: () => trustedWatcherKeys(runtime.vault),
      saveSettings: async settings => { await saveNotificationSettings(runtime.config.configPath, settings); runtime.config.settings.notify.channels = settings; },
    };
  }
  async function addNotification(body: z.output<typeof channelInput>): Promise<NotifyChannelSettings> {
    if (runtime.redactor.redact(body.label) !== body.label || classify('NOTIFICATION_SECRET', body.label).isSecret) throw new DashboardError(400, 'Choose a notification label without a secret value.');
    const fields: Record<z.output<typeof channelKind>, { required: string[]; optional?: string[] }> = {
      telegram: { required: ['botToken', 'chatId'] }, discord: { required: ['webhookUrl'] }, slack: { required: ['webhookUrl'] },
      ntfy: { required: ['server', 'topic'], optional: ['token'] }, webhook: { required: ['url'] }, resend: { required: ['apiKey', 'from', 'to'] },
      smtp: { required: ['host', 'port', 'username', 'password', 'from', 'to'] }, console: { required: [] },
    };
    const rule = fields[body.kind]; const allowed = [...rule.required, ...rule.optional ?? []];
    if (rule.required.some(name => !body.settings[name]) || Object.keys(body.settings).some(name => !allowed.includes(name))) throw new DashboardError(400, 'Complete the settings for this notification channel.');
    if (runtime.config.settings.notify.channels.length >= 50) throw new DashboardError(409, 'Remove a channel before adding another.');
    const id = `channel-${randomUUID()}`; const setting: NotifyChannelSettings = { id, kind: body.kind };
    const secrets = new Map<string, string>();
    for (const [name, value] of Object.entries(body.settings)) {
      if (['server', 'host', 'port', 'from', 'to'].includes(name)) {
        if (name === 'to') setting.to = value.split(',').map(item => item.trim()).filter(Boolean);
        else if (name === 'port') { if (value !== '465' && value !== '587') throw new DashboardError(400, 'SMTP port must be 465 or 587.'); setting.port = Number(value) as 465 | 587; }
        else setting[name as 'server' | 'host' | 'from'] = value;
      } else { secrets.set(name, value); runtime.redactor.register(value); }
    }
    try {
      const labels = await runtime.store.readJson<Record<string, string>>('plan', labelsPath) ?? {};
      await runtime.store.writeJson('plan', labelsPath, { ...labels, [id]: body.label });
      await addNotificationChannel(await notificationContext(), setting, secrets);
    } catch { throw new DashboardError(409, 'The notification channel could not be saved.'); }
    return setting;
  }
  return api;
}
