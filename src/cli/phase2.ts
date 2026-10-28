import type { Command } from 'commander';
import { randomBytes, randomUUID } from 'node:crypto';
import { join, resolve } from 'node:path';
import type { KeysentryRuntime } from './runtime.js';
import type { ArmedPlan, FeedSource } from '../types.js';
import type { WatcherConfig } from '../watcher/index.js';
import { createWatcherResumeRelay, detectPlatform, selfCheck } from '../watcher/index.js';
import { createNotificationChannels, registerNotificationCommands } from './notifications.js';
import { saveNotificationSettings, saveNotificationRelay } from './config.js';
import { createPasskeyLauncher, createPasskeyManager, listPasskeys, openPasskeyBrowser } from './passkeys.js';
import { buildWatcherSetupConfig, createWatchRuntime, runWatch, setupWatcher, watcherStatus, type WatcherPlatform } from './watcher.js';
import { WATCHER_NETWORK_PROBLEM } from './watcher-setup.js';
import { createWatcherStateStore } from './watcher-state.js';
import { prepareWatcherDeployment } from './watcher-bootstrap.js';
import { promptVaultValue, type PromptIO } from './prompts.js';
import { BUILD_VERSION, checkLocalIntegrity } from '../release/index.js';
import { DEFAULT_SOURCES, verifyArmedPlan } from '../autopilot/index.js';
import { CliError } from './errors.js';
import { buildTeamBundle } from '../policy/index.js';
import { governanceBundle } from './team-governance.js';
import { assertHumanForMutation } from '../safety/index.js';
import { providerName } from './display.js';
import { trustedWatcherKeys } from './watcher-keys.js';
import { offlineNotice, selectFeedSources } from '../feeds/index.js';
import { runAuditExportForRuntime } from './audit-export.js';
import { createKeyWrapper, createKmsHttp, wrapWatcherStateKey } from '../kms/index.js';

export interface Phase2CommandsOptions {
  getRuntime(watcher?: boolean): Promise<KeysentryRuntime>;
  watcherConfig(): WatcherConfig | undefined;
  human(action: string): void; emit(value: unknown, text?: string): void; diagnostic(text: string): void;
  interactive(): boolean; json(): boolean; setExit(code: number): void;
  env: NodeJS.ProcessEnv; now?: () => Date; promptIO?: PromptIO;
  confirmAdoption?: (question: string) => Promise<boolean>;
  openBrowser?: (url: string) => Promise<void>;
  signal?: AbortSignal;
}
const collect = (value: string, previous: string[] = []) => [...previous, ...value.split(',').map(item => item.trim()).filter(Boolean)];
function number(value: string): number {
  const result = Number(value); if (!Number.isFinite(result) || result < 0) throw new CliError('Use a nonnegative number.'); return result;
}
function health(values: string[] | undefined): ArmedPlan['healthChecks'] | undefined {
  return values?.map(value => {
    const at = value.indexOf('='); if (at < 1) throw new CliError('Use --health <serviceKey>=<https-url>.');
    return { serviceKey: value.slice(0, at), url: value.slice(at + 1) };
  });
}
export async function relaySettings(rt: KeysentryRuntime): Promise<{ server: string; topic: string; token?: string } | null> {
  const server = rt.config.settings.notify.relay?.server;
  if (!server) return null;
  const topic = await rt.vault.get('notify/relay/topic'), token = await rt.vault.get('notify/relay/token');
  try {
    if (!topic || !/^[A-Za-z0-9_-]{1,64}$/.test(topic.toString())) return null;
    rt.redactor.register(topic.toString()); if (token) rt.redactor.register(token.toString());
    return { server, topic: topic.toString(), ...(token ? { token: token.toString() } : {}) };
  } finally { topic?.fill(0); token?.fill(0); }
}
export async function localDeviceKeys(rt: KeysentryRuntime) {
  const key = await rt.signingKey();
  try { return [{ keyId: key.keyId, publicKeyDer: key.publicKeyDer }]; }
  finally { key.privateKeyDer.fill(0); }
}

export async function configureApprovalRelay(rt: KeysentryRuntime, server: string): Promise<void> {
  rt.assertHuman('configure an approval relay');
  try {
    const url = new URL(server);
    if (url.origin !== server.replace(/\/$/, '') || url.protocol !== 'https:' || url.username || url.password || url.port) throw new Error();
    // Reuse the guarded egress URL validator before touching settings or credentials.
    rt.httpForUrls([server], 'approval relay you configured');
  } catch { throw new CliError('Use an HTTPS relay origin without a path or credentials.'); }
  let topic = await rt.vault.get('notify/relay/topic');
  try {
    if (!topic) {
      topic = Buffer.from(Array.from(randomBytes(32), value => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[value & 31]).join(''));
      await rt.vault.set('notify/relay/topic', topic);
    }
    await saveNotificationRelay(rt.config.configPath, server);
    rt.config.settings.notify.relay = { server };
    await rt.audit.append({ kind: 'watcher:relay-setup', summary: 'Approval relay configured.' });
  } finally { topic?.fill(0); }
}

/** Shared local status and relay adapters for the terminal and dashboard. */
export function createCliAutopilotManager(rt: KeysentryRuntime,
  overrides: NonNullable<Parameters<KeysentryRuntime['autopilotManager']>[0]> = {}) {
  return rt.autopilotManager({
    relayResume: async signed => {
      const relay = await relaySettings(rt); if (!relay) throw new CliError('Configure the watcher relay before using --relay.');
      await createWatcherResumeRelay({ ...relay, watcherId: rt.projectId,
        http: rt.httpForUrls([relay.server], 'approval relay you configured'),
        trustedKeyIds: (await localDeviceKeys(rt)).map(key => key.keyId), deviceKeys: () => localDeviceKeys(rt), now: rt.now }).publishResume(signed);
    },
    relayDisarm: async signed => {
      const relay = await relaySettings(rt); if (!relay) throw new CliError('Configure the watcher relay before using --relay.');
      const response = await rt.httpForUrls([relay.server], 'approval relay you configured').request({ method: 'POST', url: `${relay.server.replace(/\/$/, '')}/${relay.topic}`,
        headers: { 'Content-Type': 'application/json', ...(relay.token ? { Authorization: `Bearer ${relay.token}` } : {}) }, body: JSON.stringify({ ...signed, type: 'keysentry-disarm', v: 2 }) });
      if (response.status < 200 || response.status >= 300) throw new CliError('Relay delivery did not succeed.');
    },
    lastNotificationSuccess: async () => (await rt.store.readJson<{ lastSuccessAt: string | null }>('plan', join(rt.paths.dir, 'notification-messages.json')))?.lastSuccessAt ?? null,
    selfCheck: async () => {
      const tick = await rt.store.readJson<{ startedAt?: string; lastExternalSuccessAt?: string | null }>('plan', join(rt.paths.dir, 'watcher-tick.json'));
      if (!tick?.startedAt) return { ok: false, reasons: ['The watcher self-check has not run.'] };
      const plan = await rt.store.readJson('plan', join(rt.paths.dir, 'armed-plan.json'));
      const keys = await localDeviceKeys(rt); const at = rt.now();
      return selfCheck({ startedAt: new Date(tick.startedAt), now: at, lastExternalSuccessAt: tick.lastExternalSuccessAt ?? null,
        stateWritable: true, armedValid: verifyArmedPlan(plan, { now: at, trustedKeyIds: keys.map(k => k.keyId) }).ok });
    }, ...overrides,
  });
}

/** The terminal's local approval uses the same executor, inventory checks and deferred-grace rails as watch. */
export async function executeLocalApprovedAction(rt: KeysentryRuntime, actionId: string): Promise<{ executed: boolean; reason?: string }> {
  const watcher = await createWatchRuntime({ store: rt.store, audit: rt.audit, http: rt.http, log: rt.log,
    saveRotationReport: rt.saveRotationReport,
    rotation: rt.config.rotation, fingerprintKey: rt.fingerprintKey, projectId: rt.projectId,
    signingKey: rt.signingKey, deviceKeys: () => localDeviceKeys(rt), passkeys: () => listPasskeys(rt.store, rt.vault),
    channels: () => createNotificationChannels(rt.config.settings.notify.channels,
      { vault: rt.vault, http: rt.http, redactor: rt.redactor, receipt: rt.receipt }),
    engine: async () => { const engine = await rt.recoveryDeps(); return { ...engine, prompt: async () => null, reveal: undefined, grace: undefined }; },
    freshInventory: rt.freshInventory, monitor: async () => {}, assertHuman: rt.assertHuman,
    sources: [], env: rt.mutationContext.env, now: rt.now, showHints: rt.config.settings.autopilot.showHints,
    applyAdoptionUpdates: async updates => { await rt.autopilotManager().applyAdoptionUpdates(updates); },
    integrityCheck: async () => {
      const result = await checkLocalIntegrity(); const ok = result.status === 'dev' || result.status === 'ok';
      return { ok, reasons: ok ? [] : ['The watcher installation integrity could not be verified.'] };
    },
    // Team mode: the same quorum and policy as the approval that granted this action.
    team: governanceBundle(rt.governance), quorum: rt.teamQuorum(),
  });
  return watcher.executeApprovedAction(actionId);
}

export function registerPhase2Commands(program: Command, opts: Phase2CommandsOptions): void {
  const channels = (rt: KeysentryRuntime) => createNotificationChannels(rt.config.settings.notify.channels,
    { vault: rt.vault, http: rt.http, redactor: rt.redactor, receipt: rt.receipt, write: opts.diagnostic });
  const manager = (rt: KeysentryRuntime) => createCliAutopilotManager(rt, {
    confirmAdoption: opts.confirmAdoption ?? (async question => {
      opts.diagnostic(question); const answer = await promptVaultValue('y to rotate now', opts.diagnostic, opts.promptIO); return answer?.toLowerCase() === 'y';
    }),
    emitEligibility: rows => { if (!opts.json()) for (const row of rows) opts.diagnostic(`${row.clusterId} (${providerName(row.provider)}): ${row.eligible ? 'eligible' : row.reason}`); },
  });
  program.command('arm').description('Review keys and sign a local automatic-rotation plan')
    .option('--cluster <ids>', 'Cluster ids', collect).option('--hosts <ids>', 'Incident hosts', collect)
    .option('--grace <minutes>', 'Grace minutes', number).option('--max-services <n>', 'Maximum services per wave', number)
    .option('--valid-days <n>', 'Plan lifetime in days', number).option('--health <serviceKey=url>', 'Health check', (value: string, previous: string[] = []) => [...previous, value])
    .option('--refresh', 'Re-sign observed adopted-key updates').option('--relay', 'Remote arming is unavailable').option('--remote', 'Remote arming is unavailable')
    .action(async options => {
      opts.human('arm automatic rotations'); const rt = await opts.getRuntime();
      const result = await manager(rt).arm({ clusterIds: options.cluster, hosts: options.hosts, graceMinutes: options.grace,
        maxServices: options.maxServices, validDays: options.validDays, healthChecks: health(options.health),
        refresh: options.refresh, relay: options.relay, remote: options.remote });
      opts.emit(result, `Autopilot armed for ${result.plan.clusters.length} keys. Plan expires ${result.plan.expiresAt}.`);
    });
  program.command('disarm').description('Pause automatic rotations; no passkey needed').option('--relay', 'Also send a signed disarm to the watcher')
    .action(async options => { opts.human('disarm automatic rotations'); const rt = await opts.getRuntime();
      opts.emit(await manager(rt).disarm(options), options.relay ? 'Autopilot disarmed locally. The signed disarm was published; the watcher applies it on its next check.' : 'Autopilot disarmed locally.'); });
  program.command('autopilot').description('Inspect armed plans and waves').command('status').action(async () => {
    const rt = await opts.getRuntime(); opts.emit(await manager(rt).status());
  });
  registerNotificationCommands(program, { human: opts.human, emit: opts.emit, promptIO: opts.promptIO, write: opts.diagnostic,
    getContext: async () => {
      const rt = await opts.getRuntime();
      return { settings: rt.config.settings.notify.channels, vault: rt.vault, http: rt.http, redactor: rt.redactor,
        log: rt.log, store: rt.store, deviceKey: rt.signingKey, audit: rt.audit, receipt: rt.receipt, now: opts.now, write: opts.diagnostic,
        watcherPublicKeys: () => trustedWatcherKeys(rt.vault),
        // Channels a team policy hides stay in keysentry.yaml when the visible list is saved.
        saveSettings: async settings => { await saveNotificationSettings(rt.config.configPath, rt.withHiddenChannels(settings)); rt.config.settings.notify.channels = settings; },
      };
    } });
  const passkey = program.command('passkey').description('Manage local passkey credentials');
  const passkeys = (rt: KeysentryRuntime) => createPasskeyManager({ store: rt.store, vault: rt.vault, audit: rt.audit, assertHuman: opts.human, now: opts.now });
  passkey.command('register').option('--origin <url>', 'Watcher public approval origin').option('--label <text>', 'Credential label')
    .option('--relay', 'Remote enrollment is unavailable').option('--remote', 'Remote enrollment is unavailable').action(async options => {
      opts.human('register a passkey'); const rt = await opts.getRuntime();
      let launcher: Awaited<ReturnType<typeof createPasskeyLauncher>> | undefined;
      try {
        const result = await passkeys(rt).register({ ...options,
          onReady: async ({ url }) => {
            launcher = await createPasskeyLauncher(url, rt.userDir);
            opts.diagnostic(`Open ${launcher.path} to register your passkey. This page closes after five minutes.`);
          },
          open: async () => {
            if (!launcher) throw new CliError('The passkey launcher could not be created.');
            if (opts.openBrowser) await opts.openBrowser(launcher.path);
            else if (!await openPasskeyBrowser(launcher.path, { env: opts.env })) opts.diagnostic('The browser could not be opened. Open the passkey file shown above in your browser.');
          } });
        opts.emit(result);
      } finally { await launcher?.remove(); }
    });
  passkey.command('list').action(async () => { const rt = await opts.getRuntime(); opts.emit(await passkeys(rt).list()); });
  passkey.command('remove <id>').option('--relay', 'Remote removal is unavailable').option('--remote', 'Remote removal is unavailable')
    .action(async (id, options) => { opts.human('remove a passkey'); const rt = await opts.getRuntime(); opts.emit(await passkeys(rt).remove(id, options)); });

  const watcher = program.command('watcher').description('Prepare and inspect a self-hosted watcher');
  watcher.command('setup').option('--platform <id>', 'compose, railway, fly, render, or github-actions', 'compose')
    .option('--output <path>', 'New deployment-artifact directory').option('--origin <url>', 'Public approval origin')
    .option('--relay-server <url>', 'Approval relay HTTPS origin').option('--relay', 'Remote setup is unavailable').option('--remote', 'Remote setup is unavailable')
    .action(async options => {
      opts.human('set up a watcher'); const rt = await opts.getRuntime();
      if (options.relay || options.remote || opts.json() || !opts.interactive()) throw new CliError('Watcher setup needs a local interactive terminal and cannot print secrets in JSON.');
      // The verified roster and policy travel sealed with the watcher; setup refuses while governance blocks changes.
      const team = await buildTeamBundle({ store: rt.store, settings: rt.rawSettings, cwd: rt.config.cwd, env: opts.env, anchors: rt.teamAnchors });
      if (options.relayServer) await configureApprovalRelay(rt, options.relayServer);
      const config = await buildWatcherSetupConfig({ projectId: rt.projectId, store: rt.store, vault: rt.vault, team,
        notifications: rt.config.settings.notify.channels, deviceKeys: () => localDeviceKeys(rt), passkeys: () => listPasskeys(rt.store, rt.vault),
        intervalSeconds: rt.config.monitor.intervalMs / 1000, publicOrigin: options.origin,
        relayServer: options.relayServer ?? rt.config.settings.notify.relay?.server,
        // Offline mode travels in the sealed config, so a deployed watcher stays offline without keysentry.yaml.
        ...(rt.network.feedMode.offline ? { sources: { disabled: DEFAULT_SOURCES.map(source => source.id), extra: [] } } : {}) });
      const kms = rt.config.settings.kms;
      const outputDir = resolve(rt.config.cwd, options.output ?? `.keysentry/watcher-setup-${Date.now()}`);
      const result = await setupWatcher({ assertHuman: opts.human, interactive: opts.interactive(), json: opts.json(), vault: rt.vault, audit: rt.audit,
        config, outputDir, writeTerminal: text => (opts.promptIO?.output ?? process.stdout).write(`${text}\n`),
        // With a kms section the watcher receives KEYSENTRY_STATE_KEY_WRAPPED (notes/kms.md).
        ...(kms ? { wrapStateKey: (key: Buffer, projectId: string) => wrapWatcherStateKey({ projectId, stateKey: key,
          wrapper: createKeyWrapper(kms, { http: createKmsHttp(rt.network.transport, kms, { receipt: rt.receipt, log: rt.log }),
            credentials: rt.credentials, now: rt.now }) }) } : {}),
        prepareDeployment: secrets => prepareWatcherDeployment({ sourceVault: rt.vault, credentials: rt.credentials, settings: rt.config.settings, outputDir,
          // network.caFile is relative to the project; its certificates and the proxy credential travel with the deployment.
          cwd: rt.config.cwd, env: opts.env,
          confirmEnvironmentCredential: async name => {
            opts.diagnostic(`Copy ${name} from your environment into the hosted watcher? [y/N]`);
            const answer = await promptVaultValue(`y to copy ${name}`, opts.diagnostic, opts.promptIO);
            return /^(?:y|yes)$/i.test(answer ?? '');
          } }, secrets),
      }, { platform: options.platform as WatcherPlatform });
      opts.emit(result, `Watcher deployment prepared. Template: ${result.template}`);
    });
  watcher.command('status <url>').action(async url => {
    const rt = await opts.getRuntime();
    const http = rt.httpForUrls([url], 'watcher status you requested');
    const status = await watcherStatus(http, url, BUILD_VERSION);
    opts.emit(status, [`The watcher is healthy (version ${status.version}${status.versionMatches ? ', the same as this computer' : `; this computer runs ${status.localVersion}`}).`,
      ...(status.feeds === 'offline' ? ['Offline mode is on in the watcher: it does not poll breach feeds or security news.'] : [])].join('\n'));
  });
  program.command('watch').description('Run the armed watcher with local or sealed deployment state')
    .option('--once', 'Poll once and settle eligible waves').option('--port <n>', 'Serve approval pages on this port', number)
    .action(async options => {
      // Services may run without a terminal. Their authority is the signed armed
      // plan or an approval, while an agent-marked process is always refused.
      const watcherGuard = (action: string) => assertHumanForMutation({ env: opts.env,
        stdinIsTTY: true, stdoutIsTTY: true, action });
      watcherGuard('run the watcher');
      const rt = await opts.getRuntime(true); const sealed = opts.watcherConfig();
      // Team governance (sealed: from the authenticated config): an untrusted roster, an invalid policy or an unmet
      // policy requirement (for example audit.exportRequired with no export) stops the watcher before it starts.
      await rt.assertGovernance();
      const actions = detectPlatform(opts.env).platform === 'github-actions';
      const watchStore = createWatcherStateStore(rt.store, actions);
      if (!sealed) await rt.prepareExecution(opts.diagnostic);
      if (sealed) {
        const existing = await watchStore.readJson<ArmedPlan>('plan', join(rt.paths.dir, 'armed-plan.json'));
        if (existing && existing.id !== sealed.armed?.id) throw new CliError('This state directory belongs to another armed plan. Finish or undo its rotations using the original setup, then deploy the new setup with a fresh private state directory.');
        if (!existing && sealed.armed) {
          await watchStore.writeJson('plan', join(rt.paths.dir, 'armed-plan.json'), sealed.armed);
          if (!actions) await watchStore.writeJson('plan', join(rt.paths.dir, 'autopilot.json'), { armedPlanId: sealed.armed.id, disarmed: false, waves: [] });
        }
      }
      const publicKeys = sealed ? async () => sealed.devicePublicKeys.map(key => ({ keyId: key.keyId, publicKeyDer: Buffer.from(key.publicKeyDer, 'base64') })) : () => localDeviceKeys(rt);
      // Offline mode (keysentry.yaml or a signed team policy) polls no feed at all.
      const sources: FeedSource[] = selectFeedSources([...DEFAULT_SOURCES.filter(source => !sealed?.sources.disabled.includes(source.id)),
        ...sealed?.sources.extra ?? []], rt.network.feedMode);
      const offline = offlineNotice(rt.network.feedMode);
      if (offline) rt.log.info(offline);
      // A refusing transport (broken proxy or CA settings) makes every request fail: say so once, and in /healthz.
      if (rt.network.problem) rt.log.error(`${WATCHER_NETWORK_PROBLEM} ${rt.network.problem}`);
      opts.setExit(await runWatch({ store: watchStore, audit: rt.audit, http: rt.http, log: rt.log, rotation: rt.config.rotation, projectId: rt.projectId,
        saveRotationReport: rt.saveRotationReport,
        signingKey: rt.signingKey, fingerprintKey: rt.fingerprintKey, deviceKeys: publicKeys,
        passkeys: () => sealed ? Promise.resolve(sealed.passkeys) : listPasskeys(rt.store, rt.vault), channels: () => channels(rt),
        engine: async () => { const engine = await rt.recoveryDeps(); return { ...engine, prompt: async () => null, reveal: undefined, grace: undefined }; },
        freshInventory: rt.freshInventory, monitor: (context, notify, assertActive) => rt.watcherMonitor(context, { notify: async (_title, _body, signal) => {
          await notify({ id: randomUUID(), at: (opts.now ?? (() => new Date()))().toISOString(), kind: 'monitor', severity: 'warning',
            title: 'A monitor check needs your review', lines: signal ? [`Signal: ${signal.kind}.`] : ['Inspect pending actions on your registered computer.'] });
        } }, assertActive), assertHuman: watcherGuard,
        sources, env: opts.env, now: opts.now, intervalSeconds: sealed?.intervalSeconds ?? rt.config.monitor.intervalMs / 1000,
        publicOrigin: sealed?.approvals.publicOrigin, relay: sealed?.approvals.relay ?? await relaySettings(rt),
        showHints: rt.config.settings.autopilot.showHints, sealed: !!sealed,
        integrityCheck: async () => {
          const result = await checkLocalIntegrity();
          const ok = result.status === 'dev' || result.status === 'ok';
          return { ok, reasons: ok ? [] : ['The watcher installation integrity could not be verified.'] };
        },
        ...(!sealed ? { applyAdoptionUpdates: async updates => { await rt.autopilotManager().applyAdoptionUpdates(updates); } } : {}),
        // Audit export after each cycle (notes/audit-export.md); unforced, so a failing target waits out its cooldown.
        afterCycle: async () => {
          const result = await runAuditExportForRuntime(rt, { env: opts.env });
          for (const target of result?.targets ?? []) {
            if (target.status === 'failed' || target.status === 'refused') rt.log.warn(`Audit export to ${target.id} did not complete: ${target.error ?? 'delivery failed'}`);
          }
        },
        health: () => ({ problem: rt.network.problem ? { code: 'network' as const, reason: WATCHER_NETWORK_PROBLEM } : null,
          feedsOffline: rt.network.feedMode.offline }),
        // Team mode: the sealed roster and policy, or this computer's (whose quorum re-reads the saved roster each time).
        ...(sealed ? { team: sealed.team ?? null } : { team: governanceBundle(rt.governance), quorum: rt.teamQuorum() }),
      }, { ...options, ...(opts.signal ? { signal: opts.signal } : {}) }));
    });
}
