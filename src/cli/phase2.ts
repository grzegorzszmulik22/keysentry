import type { Command } from 'commander';
import { randomBytes, randomUUID } from 'node:crypto';
import { join, resolve } from 'node:path';
import type { KeysentryRuntime } from './runtime.js';
import type { ArmedPlan, FeedSource } from '../types.js';
import type { WatcherConfig } from '../watcher/index.js';
import { selfCheck } from '../watcher/index.js';
import { createNotificationChannels, registerNotificationCommands } from './notifications.js';
import { saveNotificationSettings, saveNotificationRelay } from './config.js';
import { createPasskeyManager, listPasskeys, openPasskeyBrowser } from './passkeys.js';
import { buildWatcherSetupConfig, runWatch, setupWatcher, watcherStatus, type WatcherPlatform } from './watcher.js';
import { prepareWatcherDeployment } from './watcher-bootstrap.js';
import { promptVaultValue, type PromptIO } from './prompts.js';
import { BUILD_VERSION, checkLocalIntegrity } from '../release/index.js';
import { DEFAULT_SOURCES, verifyArmedPlan } from '../autopilot/index.js';
import { CliError } from './errors.js';

export interface Phase2CommandsOptions {
  getRuntime(watcher?: boolean): Promise<KeysentryRuntime>;
  watcherConfig(): WatcherConfig | undefined;
  human(action: string): void; emit(value: unknown, text?: string): void; diagnostic(text: string): void;
  interactive(): boolean; json(): boolean; setExit(code: number): void;
  env: NodeJS.ProcessEnv; now?: () => Date; promptIO?: PromptIO;
  confirmAdoption?: (question: string) => Promise<boolean>;
  openBrowser?: (url: string) => Promise<void>;
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

export function registerPhase2Commands(program: Command, opts: Phase2CommandsOptions): void {
  const channels = (rt: KeysentryRuntime) => createNotificationChannels(rt.config.settings.notify.channels,
    { vault: rt.vault, http: rt.http, redactor: rt.redactor, receipt: rt.receipt, write: opts.diagnostic });
  const manager = (rt: KeysentryRuntime) => rt.autopilotManager({
    confirmAdoption: opts.confirmAdoption ?? (async question => {
      opts.diagnostic(question); const answer = await promptVaultValue('y to rotate now', opts.diagnostic, opts.promptIO); return answer?.toLowerCase() === 'y';
    }),
    emitEligibility: rows => { if (!opts.json()) for (const row of rows) opts.diagnostic(`${row.clusterId} (${row.provider}): ${row.eligible ? 'eligible' : row.reason}`); },
    relayDisarm: async signed => {
      const relay = await relaySettings(rt); if (!relay) throw new CliError('Configure the watcher relay before using --relay.');
      const response = await rt.httpForUrls([relay.server], 'approval relay you configured').request({ method: 'POST', url: `${relay.server.replace(/\/$/, '')}/${relay.topic}`,
        headers: { 'Content-Type': 'application/json', ...(relay.token ? { Authorization: `Bearer ${relay.token}` } : {}) }, body: JSON.stringify({ ...signed, type: 'keysentry-disarm', v: 1 }) });
      if (response.status < 200 || response.status >= 300) throw new CliError('Relay delivery did not succeed.');
    },
    lastNotificationSuccess: async () => (await rt.store.readJson<{ lastSuccessAt: string | null }>('plan', join(rt.paths.dir, 'notification-messages.json')))?.lastSuccessAt ?? null,
    selfCheck: async () => {
      const tick = await rt.store.readJson<{ startedAt?: string; lastNotifySuccessAt?: string | null }>('plan', join(rt.paths.dir, 'watcher-tick.json'));
      if (!tick?.startedAt) return { ok: false, reasons: ['The watcher self-check has not run.'] };
      const plan = await rt.store.readJson('plan', join(rt.paths.dir, 'armed-plan.json'));
      const keys = await localDeviceKeys(rt); const at = (opts.now ?? (() => new Date()))();
      return selfCheck({ startedAt: new Date(tick.startedAt), now: at, lastNotifySuccessAt: tick.lastNotifySuccessAt ?? null,
        stateWritable: true, armedValid: verifyArmedPlan(plan, { now: at, trustedKeyIds: keys.map(k => k.keyId) }).ok });
    },
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
      opts.emit(await manager(rt).disarm(options), options.relay ? 'Autopilot disarmed locally and on the watcher relay.' : 'Autopilot disarmed locally.'); });
  program.command('autopilot').description('Inspect armed plans and waves').command('status').action(async () => {
    const rt = await opts.getRuntime(); opts.emit(await manager(rt).status());
  });
  registerNotificationCommands(program, { human: opts.human, emit: opts.emit, promptIO: opts.promptIO, write: opts.diagnostic,
    getContext: async () => {
      const rt = await opts.getRuntime();
      return { settings: rt.config.settings.notify.channels, vault: rt.vault, http: rt.http, redactor: rt.redactor,
        log: rt.log, store: rt.store, deviceKey: rt.signingKey, audit: rt.audit, receipt: rt.receipt, now: opts.now, write: opts.diagnostic,
        watcherPublicKeys: async () => { const key = await rt.vault.get('watcher/signing/public'); return key ? [key] : []; },
        saveSettings: async settings => { await saveNotificationSettings(rt.config.configPath, settings); rt.config.settings.notify.channels = settings; },
      };
    } });
  const passkey = program.command('passkey').description('Manage local passkey credentials');
  const passkeys = (rt: KeysentryRuntime) => createPasskeyManager({ store: rt.store, audit: rt.audit, assertHuman: opts.human, now: opts.now });
  passkey.command('register').option('--origin <url>', 'Watcher public approval origin').option('--label <text>', 'Credential label')
    .option('--relay', 'Remote enrollment is unavailable').option('--remote', 'Remote enrollment is unavailable').action(async options => {
      opts.human('register a passkey'); const rt = await opts.getRuntime();
      const result = await passkeys(rt).register({ ...options, open: opts.openBrowser ?? (async url => { await openPasskeyBrowser(url, { env: opts.env }); }),
        onReady: ({ url }) => opts.diagnostic(`Open ${url} to register your passkey. This page closes after five minutes.`) });
      opts.emit(result);
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
      if (options.relayServer) await configureApprovalRelay(rt, options.relayServer);
      const config = await buildWatcherSetupConfig({ projectId: rt.projectId, store: rt.store, vault: rt.vault,
        notifications: rt.config.settings.notify.channels, deviceKeys: () => localDeviceKeys(rt), passkeys: () => listPasskeys(rt.store),
        intervalSeconds: rt.config.monitor.intervalMs / 1000, publicOrigin: options.origin,
        relayServer: options.relayServer ?? rt.config.settings.notify.relay?.server });
      const outputDir = resolve(rt.config.cwd, options.output ?? `.keysentry/watcher-setup-${Date.now()}`);
      const result = await setupWatcher({ assertHuman: opts.human, interactive: opts.interactive(), json: opts.json(), vault: rt.vault, audit: rt.audit,
        config, outputDir, writeTerminal: text => (opts.promptIO?.output ?? process.stdout).write(`${text}\n`),
        prepareDeployment: secrets => prepareWatcherDeployment({ sourceVault: rt.vault, credentials: rt.credentials, settings: rt.config.settings, outputDir }, secrets),
      }, { platform: options.platform as WatcherPlatform });
      opts.emit(result, `Watcher deployment prepared. Template: ${result.template}`);
    });
  watcher.command('status <url>').action(async url => {
    const rt = await opts.getRuntime();
    const http = rt.httpForUrls([url], 'watcher status you requested');
    opts.emit(await watcherStatus(http, url, BUILD_VERSION));
  });
  program.command('watch').description('Run the armed watcher with local or sealed deployment state')
    .option('--once', 'Poll once and settle eligible waves').option('--port <n>', 'Serve approval pages on this port', number)
    .action(async options => {
      const sealedRequested = !!(opts.env.KEYSENTRY_WATCHER_CONFIG || opts.env.KEYSENTRY_WATCHER_CONFIG_FILE);
      if (!sealedRequested) opts.human('run the watcher');
      const rt = await opts.getRuntime(true); const sealed = opts.watcherConfig();
      if (!sealed) await rt.prepareExecution(opts.diagnostic);
      if (sealed) {
        const existing = await rt.store.readJson<ArmedPlan>('plan', join(rt.paths.dir, 'armed-plan.json'));
        if (existing && existing.id !== sealed.armed?.id) throw new CliError('This state directory belongs to another armed plan. Finish or undo its rotations using the original setup, then deploy the new setup with a fresh private state directory.');
        if (!existing && sealed.armed) {
          await rt.store.writeJson('plan', join(rt.paths.dir, 'armed-plan.json'), sealed.armed);
          await rt.store.writeJson('plan', join(rt.paths.dir, 'autopilot.json'), { armedPlanId: sealed.armed.id, disarmed: false, waves: [] });
        }
      }
      const publicKeys = sealed ? async () => sealed.devicePublicKeys.map(key => ({ keyId: key.keyId, publicKeyDer: Buffer.from(key.publicKeyDer, 'base64') })) : () => localDeviceKeys(rt);
      const sources: FeedSource[] = [...DEFAULT_SOURCES.filter(source => !sealed?.sources.disabled.includes(source.id)), ...sealed?.sources.extra ?? []];
      opts.setExit(await runWatch({ store: rt.store, audit: rt.audit, http: rt.http, log: rt.log, rotation: rt.config.rotation,
        signingKey: rt.signingKey, fingerprintKey: rt.fingerprintKey, deviceKeys: publicKeys,
        passkeys: () => sealed ? Promise.resolve(sealed.passkeys) : listPasskeys(rt.store), channels: () => channels(rt),
        engine: async () => { const engine = await rt.recoveryDeps(); return { ...engine, prompt: async () => null, reveal: undefined, grace: undefined }; },
        freshInventory: rt.freshInventory, monitor: (context, notify, assertActive) => rt.watcherMonitor(context, { notify: async (_title, _body, signal) => {
          await notify({ id: randomUUID(), at: (opts.now ?? (() => new Date()))().toISOString(), kind: 'monitor', severity: 'warning',
            title: 'A monitor check needs your review', lines: signal ? [`Signal: ${signal.kind}.`] : ['Inspect pending actions on your registered computer.'] });
        } }, assertActive), assertHuman: opts.human,
        sources, env: opts.env, now: opts.now, intervalSeconds: sealed?.intervalSeconds ?? rt.config.monitor.intervalMs / 1000,
        publicOrigin: sealed?.approvals.publicOrigin, relay: sealed?.approvals.relay ?? await relaySettings(rt),
        showHints: rt.config.settings.autopilot.showHints, sealed: !!sealed,
        integrityCheck: async () => {
          const result = await checkLocalIntegrity();
          const ok = result.status === 'dev' || result.status === 'ok';
          return { ok, reasons: ok ? [] : ['The watcher installation integrity could not be verified.'] };
        },
        ...(!sealed ? { applyAdoptionUpdates: async updates => { await rt.autopilotManager().applyAdoptionUpdates(updates); } } : {}),
      }, options));
    });
}
