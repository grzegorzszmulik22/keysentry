#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { realpathSync } from 'node:fs';
import { basename } from 'node:path';
import { Command, CommanderError, InvalidArgumentError } from 'commander';
import { createRedactor, renderBlastRadius } from '../core/index.js';
import type { GuidedPrompt, Inventory, RotationReport, TokenRole } from '../types.js';
import { RotationAbortedError } from '../types.js';
import { confirmAction, confirmRotation, confirmStateReset, hasInteractiveTerminal, promptGrace, promptSecret, promptVaultValue, revealSecret, type PromptIO } from './prompts.js';
import { createRuntime, type KeysentryRuntime, type PlanFilters, type RuntimeOptions } from './runtime.js';
import { hostIdSchema, tierSchema } from './schemas.js';
import { CliError, RotationInterruptedError } from './errors.js';
import { providerName, serviceLabel } from './display.js';
import { loadConfigMetadata } from './config.js';
import { inspectAudit, inspectNetwork, inspectRelease } from './inspection.js';
import { AgentRefusalError, assertHumanForMutation, maybeReexecWithPermissions } from '../safety/index.js';
import { BUILD_VERSION, checkLocalIntegrity } from '../release/index.js';
import { permissionOptionsForBin } from './sandbox-grants.js';
export { permissionOptionsForBin } from './sandbox-grants.js';
import { StateLockedError } from '../core/index.js';
import { createCliAutopilotManager, executeLocalApprovedAction, registerPhase2Commands, relaySettings, localDeviceKeys } from './phase2.js';
import { registerPhase3Commands } from './phase3.js';
import type { GitRunner } from '../firstrun/index.js';
import { approveAutopilot } from './autopilot-approvals.js';
import { approvedOutcome } from '../approvals/index.js';
import { listPasskeys } from './passkeys.js';
import { bootstrapWatcher } from './watcher-bootstrap.js';
import { CREDENTIAL_NAMES, VaultLockedError, VaultReadOnlyError, VaultUnavailableError } from '../vault/index.js';

export { createRuntime } from './runtime.js';
export type { KeysentryRuntime, RuntimeOptions } from './runtime.js';
export { loadConfig, configSchema } from './config.js';
export type { RuntimeConfig, ConfigSettings, LoadConfigOptions } from './config.js';
export interface CliOptions extends RuntimeOptions {
  runtime?: KeysentryRuntime;
  output?: (line: string) => void;
  error?: (line: string) => void;
  confirm?: (count: number) => Promise<boolean>;
  confirmAction?: (id: string) => Promise<boolean>;
  promptIO?: PromptIO;
  confirmAdoption?: (question: string) => Promise<boolean>;
  openBrowser?: (url: string) => Promise<void>;
  firstRunGit?: GitRunner;
  guardGit?: GitRunner;
  confirmFirstRunSave?: () => Promise<boolean>;
  confirmDashboard?: () => Promise<boolean>;
}

function role(value: string): TokenRole {
  if (value !== 'read' && value !== 'write') throw new InvalidArgumentError('Role must be read or write.');
  return value;
}
function credentialName(name: string): void {
  if (!CREDENTIAL_NAMES.includes(name)) throw new CliError('Unknown credential name. Run keysentry vault status for supported names.');
}
async function readPipedValue(io?: PromptIO): Promise<string> {
  const input = io?.input ?? process.stdin;
  if (input.isTTY) throw new CliError('--stdin requires piped input.');
  const chunks: Buffer[] = []; let bytes = 0;
  for await (const chunk of input) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
    bytes += buffer.length;
    if (bytes > 1024 * 1024) throw new CliError('Credential input is too large.');
    chunks.push(buffer);
  }
  const value = Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '');
  if (!value || /[\x00\r\n]/.test(value)) throw new CliError('Provide one nonempty credential value on stdin.');
  return value;
}

const collect = (value: string, previous: string[] = []) => [...previous, ...value.split(',').map(item => item.trim()).filter(Boolean)];
function positive(value: string): number {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) throw new InvalidArgumentError('Expected a positive number of seconds.');
  return number;
}
function filters(opts: { tier?: string[]; cluster?: string[]; host?: string[] }): PlanFilters {
  const tiers = opts.tier?.map(value => { const result = tierSchema.safeParse(value); if (!result.success) throw new CliError('Invalid risk tier.'); return result.data; });
  const hosts = opts.host?.map(value => { const result = hostIdSchema.safeParse(value); if (!result.success) throw new CliError('Invalid host.'); return result.data; });
  return { ...(tiers ? { tiers } : {}), ...(hosts ? { hosts } : {}), ...(opts.cluster ? { clusterIds: opts.cluster } : {}) };
}
function addSelectors(command: Command) {
  return command.option('--tier <tiers>', 'Risk tiers, comma-separated or repeatable', collect)
    .option('--cluster <ids>', 'Cluster IDs, comma-separated or repeatable', collect)
    .option('--host <hosts>', 'Hosts, comma-separated or repeatable; retain every copy', collect);
}
function attention(inv: Inventory) {
  return inv.clusters.some(cluster => cluster.fingerprint === null || cluster.consumers.length > 1 && !['app', 'unknown'].includes(cluster.tier));
}
function summary(report: RotationReport, journal: string) {
  return [report.dryRun ? 'Dry run: no host or provider changes.' : 'Rotation summary',
    'Cluster                           Status       Warnings',
    ...report.steps.map(step => `${step.clusterId.padEnd(33)} ${step.status.padEnd(12)} ${[step.error, ...step.warnings].filter(Boolean).join('; ')}`),
    `Journal: ${journal}`].join('\n');
}

/** No process.exit or real network is required by this entry point: inject a runtime for embedding/tests. */
export async function runCli(args: string[] = process.argv.slice(2), options: CliOptions = {}): Promise<number> {
  let runtime = options.runtime;
  let deployment: Awaited<ReturnType<typeof bootstrapWatcher>> | undefined;
  let exitCode = 0;
  const initialRedactor = createRedactor();
  const output = options.output ?? ((line: string) => process.stdout.write(`${line}\n`));
  const errorOutput = options.error ?? ((line: string) => process.stderr.write(`${line}\n`));
  const redact = (text: string) => (runtime?.redactor ?? initialRedactor).redact(text);
  const write = (text: string) => output(redact(runtime?.humanize(text) ?? text));
  const diagnostic = (text: string) => errorOutput(redact(runtime?.humanize(text) ?? text));
  const interactive = () => options.stdinIsTTY !== undefined || options.stdoutIsTTY !== undefined
    ? (options.stdinIsTTY ?? process.stdin.isTTY === true) && (options.stdoutIsTTY ?? process.stdout.isTTY === true)
    : runtime?.interactive ?? hasInteractiveTerminal(options.promptIO);
  const human = (action: string, allowPipedStdin = false) => {
    const context = runtime?.mutationContext;
    assertHumanForMutation({ env: options.env ?? context?.env ?? process.env, action, allowPipedStdin,
      stdinIsTTY: options.stdinIsTTY ?? context?.stdinIsTTY ?? process.stdin.isTTY === true,
      stdoutIsTTY: options.stdoutIsTTY ?? context?.stdoutIsTTY ?? process.stdout.isTTY === true });
  };
  const program = new Command();
  program.name('keysentry').description('Local-first secret inventory, breach response, rotation, and monitoring.')
    .version(BUILD_VERSION).option('--cwd <path>', 'Project directory', options.cwd ?? runtime?.config.cwd ?? process.cwd())
    .option('--config <path>', 'Configuration path relative to cwd')
    .option('--json', 'Print secret-free JSON').option('--verbose', 'Enable redacted debug logs')
    .option('--fail-on-findings', 'Exit 2 when findings require attention')
    .showSuggestionAfterError(false).exitOverride()
    .configureOutput({ writeOut: text => write(text.trimEnd()), writeErr: () => {}, outputError: () => {} });

  const effectiveOptions = (): RuntimeOptions => {
    const globals = program.opts<{ cwd: string; config?: string; json?: boolean; verbose?: boolean }>();
    return { ...options, cwd: globals.cwd, config: globals.config ?? options.config, json: globals.json, verbose: globals.verbose,
      vault: options.vault ?? runtime?.vault, audit: options.audit ?? runtime?.audit,
      ...(interactive() ? { grace: options.grace ?? (info => promptGrace(info, diagnostic, options.promptIO, options.now)) } : {}),
    };
  };
  const getRuntime = async (watcher = false) => {
    if (!runtime) {
      const effective = effectiveOptions();
      if (watcher && (effective.env ?? process.env).KEYSENTRY_WATCHER_KEY) {
        deployment = await bootstrapWatcher(effective.env ?? process.env, { cwd: effective.cwd });
      }
      runtime = await createRuntime({ ...effective, ...deployment?.options, watcherAuthorized: !!deployment });
    }
    return runtime;
  };
  const emit = (value: unknown, human?: string) => {
    if (program.opts().json) output(JSON.stringify(runtime ? runtime.safe(value) : value, null, 2));
    else write(human ?? JSON.stringify(runtime ? runtime.safe(value) : value, null, 2));
  };
  const findingsExit = (inv: Inventory) => {
    if (inv.errors.some(error => runtime?.config.hosts.some(host => host.id === error.host))) exitCode = 1;
    else if (program.opts().failOnFindings && attention(inv)) exitCode = 2;
  };
  const reportExit = (report: RotationReport) => {
    if (report.steps.some(step => step.status === 'failed') || report.deployments.some(deployment => deployment.state === 'failed')) exitCode = 1;
    else if (program.opts().failOnFindings && !report.dryRun && report.steps.some(step => ['skipped', 'written'].includes(step.status))) exitCode = 2;
  };

  registerPhase2Commands(program, { getRuntime, watcherConfig: () => deployment?.config,
    human, emit, diagnostic, interactive, json: () => !!program.opts().json, setExit: code => { exitCode = code; },
    env: options.env ?? process.env, now: options.now, promptIO: options.promptIO,
    confirmAdoption: options.confirmAdoption, openBrowser: options.openBrowser });
  program.commands.find(command => command.name() === 'autopilot')!.command('resume')
    .description('Publish a signed recovery message for a paused Actions watcher')
    .option('--relay', 'Send recovery through the configured watcher relay')
    .action(async (opts: { relay?: boolean }) => {
      human('resume the watcher through its relay'); const rt = await getRuntime();
      emit(await createCliAutopilotManager(rt).resume(opts),
        'Signed resume message published. The watcher checks it on its next check; local disarm and other holds still apply.');
    });
  registerPhase3Commands(program, { getRuntime, peekRuntime: () => runtime,
    firstRunSettings: () => ({ vault: options.vault ?? runtime?.vault, userDir: options.userDir,
      env: options.env ?? runtime?.mutationContext.env ?? process.env, passphrase: options.passphrase }),
    cwd: () => program.opts<{ cwd: string }>().cwd, human, emit, diagnostic, interactive,
    json: () => !!program.opts().json, setExit: code => { exitCode = code; },
    env: options.env ?? runtime?.mutationContext.env ?? process.env, promptIO: options.promptIO,
    firstRunGit: options.firstRunGit, guardGit: options.guardGit,
    confirmFirstRunSave: options.confirmFirstRunSave, confirmDashboard: options.confirmDashboard,
    openBrowser: options.openBrowser });

  program.command('init').description('Create private local state and sample config without overwriting files').action(async () => {
    const rt = await getRuntime(); const result = await rt.init();
    emit(result, `State: ${result.stateDirectory}\nConfiguration: ${result.configPath}${result.configCreated ? ' (created)' : ' (already exists)'}`);
  });
  program.command('scan').description('Scan enabled hosts and report disabled hosts and blast radius').action(async () => {
    const rt = await getRuntime(); const inv = await rt.scan(); emit(inv, renderBlastRadius(inv)); findingsExit(inv);
  });
  program.command('report').description('Read the saved inventory and report blast radius').action(async () => {
    const rt = await getRuntime(); const inv = await rt.inventory(); emit(inv, await rt.report()); findingsExit(inv);
  });
  addSelectors(program.command('plan').description('Save a complete ordered rotation plan'))
    .option('-o, --output <path>', 'Write a Markdown runbook to a new file')
    .action(async opts => {
      const rt = await getRuntime(); const rotationPlan = await rt.plan(filters(opts)); const runbook = await rt.runbook(rotationPlan);
      const path = opts.output ? await rt.writeRunbook(opts.output, runbook) : undefined;
      emit({ plan: rotationPlan, runbook, ...(path ? { path } : {}) }, `${runbook}\nPlan saved: ${rotationPlan.id}${path ? `\nRunbook: ${path}` : ''}`);
    });
  addSelectors(program.command('rotate').description('Preview rotation; writes require --execute'))
    .option('--plan <id>', 'Use a saved plan').option('--execute', 'Execute after reviewing the preview')
    .option('--yes', 'Skip the confirmation question; an interactive terminal is still required')
    .option('--revoke <policy>', 'after-deploy, immediately, or never')
    .option('--no-redeploy', 'Leave activation to the operator')
    .option('--revoke-unconfirmed', 'Revoke old keys even when consumer activation is unconfirmed')
    .option('--accept-unplanned-sealed', 'Accept sealed consumers outside this plan that may use the old key')
    .option('--no-generate', 'Skip generated application secrets')
    .action(async (opts, command: Command) => {
      if (opts.execute) human('rotate keys');
      let developmentAlreadyReported = false;
      if (opts.execute) {
        const integrity = await checkLocalIntegrity();
        if (integrity.status === 'mismatch') throw new CliError('The installed copy does not match its local manifest. Reinstall keysentry before rotating keys.');
        if (integrity.status === 'dev') {
          diagnostic('Development copy: release integrity has not been checked.'); developmentAlreadyReported = true;
        }
      }
      const rt = await getRuntime();
      if (opts.revoke && !['after-deploy', 'immediately', 'never'].includes(opts.revoke)) throw new CliError('Invalid revocation policy; use after-deploy, immediately, or never.');
      if (opts.plan && (opts.tier || opts.cluster || opts.host)) throw new CliError('Select a saved plan or filters.');
      const rotationPlan = opts.plan ? await rt.loadPlan(opts.plan) : await rt.plan(filters(opts));
      const redeploy = command.getOptionValueSource('redeploy') === 'cli' ? opts.redeploy as boolean : undefined;
      const rotationOptions = { revoke: opts.revoke, redeploy,
        revokeUnconfirmed: command.getOptionValueSource('revokeUnconfirmed') === 'cli' ? opts.revokeUnconfirmed as boolean : undefined,
        acceptUnplannedSealed: command.getOptionValueSource('acceptUnplannedSealed') === 'cli' ? opts.acceptUnplannedSealed as boolean : undefined,
        allowGenerate: command.getOptionValueSource('generate') === 'cli' ? opts.generate as boolean : undefined,
      };
      const preview = await rt.rotate(rotationPlan, rotationOptions);
      if (!opts.execute) { emit({ report: preview, journal: rt.paths.journal }, `${preview.diff.join('\n')}\n${summary(preview, rt.paths.journal)}`); reportExit(preview); return; }
      diagnostic(`Rotation preview (${rotationPlan.steps.length} secret clusters):\n${preview.diff.join('\n')}`);
      await rt.prepareExecution(diagnostic, developmentAlreadyReported);
      const isInteractive = interactive();
      if (rotationPlan.steps.some(step => step.method === 'atomic-roll') && !isInteractive) {
        throw new CliError('Atomic-roll rotation requires an interactive terminal for replacement recovery. Run rotate --execute in a terminal.');
      }
      if (rotationPlan.steps.length && !opts.yes && !await (options.confirm ?? (count => confirmRotation(count, diagnostic, options.promptIO)))(rotationPlan.steps.length)) {
        emit({ cancelled: true, report: preview, journal: rt.paths.journal }, 'Rotation cancelled. No host or provider changes.'); return;
      }
      const prompt = options.prompt ?? ((p: GuidedPrompt) => promptSecret(p, diagnostic, options.promptIO));
      const reveal = options.reveal ?? (isInteractive ? ((info, value) => revealSecret(info, value, diagnostic, options.promptIO)) : undefined);
      const report = await rt.rotate(rotationPlan, { ...rotationOptions, execute: true, prompt, reveal });
      emit({ preview, report, journal: rt.paths.journal }, summary(report, rt.paths.journal)); reportExit(report);
    });

  const canary = program.command('canary').description('Manage low-budget OpenRouter decoys');
  canary.command('create').requiredOption('--host <id>', 'Destination host').requiredOption('--service <id>', 'Project/service label or unique service ID/name')
    .option('--provider <id>', 'Canary provider', 'openrouter').option('--var <name>', 'Destination variable name')
    .option('--execute', 'Create and plant the canary').action(async opts => {
      if (opts.execute) human('create a canary');
      if (opts.provider !== 'openrouter') throw new CliError('Canaries currently support OpenRouter only.');
      const host = hostIdSchema.safeParse(opts.host); if (!host.success) throw new CliError('Invalid host.');
      const rt = await getRuntime();
      if (opts.execute) await rt.prepareExecution(diagnostic);
      const result = await rt.createCanary({ host: host.data, service: opts.service, varName: opts.var, execute: opts.execute });
      emit({ dryRun: !opts.execute, canary: result }, result ? `Canary ${result.id} planted in ${serviceLabel(result.service)}:${result.varName}.` : 'Dry run: would plant a $0.01 OpenRouter canary. Pass --execute to plant it.');
    });
  canary.command('list').action(async () => {
    const rt = await getRuntime(); const canaries = await rt.canaries();
    emit(canaries, canaries.length ? canaries.map(canary => `${canary.id}: ${serviceLabel(canary.service)}:${canary.varName}`).join('\n') : 'No canaries configured.');
  });
  canary.command('remove <id>').option('--execute', 'Revoke the canary and remove monitoring metadata').action(async (id, opts) => {
    if (opts.execute) human('remove a canary');
    const rt = await getRuntime();
    if (opts.execute) await rt.prepareExecution(diagnostic);
    emit(await rt.removeCanary(id, opts.execute), opts.execute ? 'Canary revoked; inert host variable remains.' : 'Dry run: would revoke the canary. Pass --execute to remove it.');
  });

  program.command('monitor').description('Poll signals; rotations follow configured policy, guided steps are skipped')
    .option('--once', 'Run one poll and exit').option('--interval <seconds>', 'Polling interval in seconds', positive)
    .action(async opts => {
      const settings = runtime?.config.settings ?? (await loadConfigMetadata(effectiveOptions())).settings;
      const policy = options.policy ?? runtime?.config.monitor.policy;
      if ((policy?.autoExecute ?? settings.monitor.autoExecute) || (policy?.autoContain ?? settings.monitor.autoContain)) human('run automatic monitor actions');
      const rt = await getRuntime();
      if (rt.config.monitor.policy.autoExecute || rt.config.monitor.policy.autoContain) await rt.prepareExecution(diagnostic);
      if (opts.once) { const result = await rt.monitorOnce(); emit(result, `Monitor: ${result.signals.length} signals, ${result.decisions.length} decisions. Guided steps require human remediation.`); return; }
      const controller = new AbortController(); const stop = () => controller.abort();
      process.once('SIGINT', stop); process.once('SIGTERM', stop);
      try {
        diagnostic('Monitoring started. Press Ctrl-C to stop.');
        await rt.monitor(controller.signal, opts.interval ? opts.interval * 1000 : rt.config.monitor.intervalMs,
          result => emit(result, `Monitor: ${result.signals.length} signals, ${result.decisions.length} decisions.`));
      } finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
    });
  program.command('actions').description('List pending monitor actions').action(async () => { const rt = await getRuntime(); emit(await rt.pendingActions()); });
  program.command('approve <id>').description('Review and execute a pending action, or publish watcher approval with --relay')
    .option('--yes', 'Skip typing the action id after reviewing the action')
    .option('--relay', 'Publish a signed approval to the configured watcher relay')
    .action(async (id: string, opts: { yes?: boolean; relay?: boolean }) => {
    human('approve a key change');
    const rt = await getRuntime();
    const relay = await relaySettings(rt);
    const approved = await approveAutopilot(id, opts, { store: rt.store, audit: rt.audit,
      http: relay ? rt.httpForUrls([relay.server], 'approval relay you configured') : rt.http,
      deviceKey: rt.signingKey, deviceKeys: () => localDeviceKeys(rt), passkeys: () => listPasskeys(rt.store),
      watcherPublicKeys: async () => { const key = await rt.vault.get('watcher/signing/public'); return key ? [key] : []; },
      now: options.now, relay, assertHuman: human,
      review: request => diagnostic([`Autopilot action ${request.actionId}:`,
        ...request.clusters.map(cluster => `  ${cluster.clusterId}${cluster.hint ? ` (${cluster.hint})` : ''}`)].join('\n')),
      confirm: actionId => opts.yes && !opts.relay ? Promise.resolve(true)
        : (options.confirmAction ?? (id => confirmAction(id, diagnostic, options.promptIO)))(actionId),
      executeApprovedAction: async actionId => {
        await rt.prepareExecution(diagnostic);
        return executeLocalApprovedAction(rt, actionId);
      } });
    if (approved) {
      const text = approved.status === 'cancelled' ? 'Approval cancelled.'
        : approved.status === 'published' ? `Signed approval published to the watcher relay. ${approvedOutcome(approved.watcherCheckMinutes ?? 10)}`
          : approved.status === 'executed' ? 'Autopilot action executed.'
            : `Autopilot action approved. ${approved.reason ?? 'The grant remains available for the watcher.'}`;
      emit(approved, text); return;
    }
    const review = await rt.reviewAction(id);
    await rt.prepareExecution(diagnostic);
    const rotation = review.action.action === 'rotate' || review.action.action === 'breach-mode';
    diagnostic([`Action ${review.action.id}: ${review.action.action} ${review.action.clusterIds.length} secret cluster(s).`,
      ...review.plan.steps.map(step => `${providerName(step.provider)} (${step.method}): ${step.consumers.map(consumer => `${serviceLabel(consumer.service)}:${consumer.varName}`).join(', ')}`),
      rotation ? 'Creates replacements, writes consumers, redeploys supported services, then revokes old keys after deployment.' : 'Disables or caps the selected keys at the provider; consumers may stop working.',
      `revokeUnconfirmed: ${review.revokeUnconfirmed}${review.revokeUnconfirmed ? ' — old keys may be revoked before manual restarts or other unconfirmed activation.' : ' — old keys are retained when activation is unconfirmed.'}`,
      review.requiresInteractive ? 'Interactive atomic-roll recovery is required; the old key dies when its replacement is created.' : '',
      review.manualRestarts.length ? `Manual restart / activation required:\n${review.manualRestarts.map(service => `  ${serviceLabel(service)}`).join('\n')}` : 'Manual restart / activation required: none known.',
    ].filter(Boolean).join('\n'));
    const isInteractive = interactive();
    if (review.requiresInteractive && !isInteractive) throw new CliError('This action requires an interactive terminal for atomic-roll recovery; --yes only skips confirmation.');
    if (!opts.yes) {
      if (!isInteractive && !options.confirmAction) throw new CliError('Approval confirmation requires an interactive terminal. Pass --yes after reviewing the action.');
      if (!await (options.confirmAction ?? (actionId => confirmAction(actionId, diagnostic, options.promptIO)))(review.action.id)) {
        emit({ cancelled: true, action: review.action }, 'Approval cancelled. No host or provider changes.'); return;
      }
    }
    const prompt = options.prompt ?? ((p: GuidedPrompt) => promptSecret(p, diagnostic, options.promptIO));
    const reveal = options.reveal ?? ((info, value) => revealSecret(info, value, diagnostic, options.promptIO));
    const report = await rt.approve(id, { interactive: isInteractive, reviewHash: review.reviewHash, ...(isInteractive ? { prompt, reveal } : {}) });
    if (report) { emit({ report, journal: rt.paths.journal }, summary(report, rt.paths.journal)); reportExit(report); }
    else {
      const action = (await rt.monitorStatus()).pendingActions.find(action => action.id === id);
      const executed = action?.status === 'executed';
      emit({ action, journal: rt.paths.journal }, executed ? 'Containment action executed.' : 'Action did not execute; inspect actions and journal.');
      if (!executed) exitCode = 1;
    }
  });
  program.command('dismiss <id>').description('Dismiss a pending monitor action').action(async id => { human('dismiss a pending action'); const rt = await getRuntime(); emit(await rt.dismiss(id)); });
  program.command('drill').description('Time a full dry run and explain readiness from 0 to 100').action(async () => {
    const rt = await getRuntime(); const result = await rt.drill();
    emit(result, `Readiness: ${result.score}/100 (${result.elapsedMs} ms)\n${result.reasons.join('\n')}\n${summary(result.report, rt.paths.journal)}`); reportExit(result.report);
  });
  const vault = program.command('vault').description('Store credentials in your local credential store');
  vault.command('status').description('Show the backend and stored credential names by role').action(async () => {
    const rt = await getRuntime(); emit(await rt.vaultStatus());
  });
  vault.command('list').description('List stored credential names without values').action(async () => {
    const rt = await getRuntime(); const names = [...new Set((await rt.vaultList()).map(item => item.name))];
    emit(names, names.length ? names.join('\n') : 'No credentials stored.');
  });
  vault.command('set <NAME>').description('Read a credential through hidden input or --stdin')
    .option('--role <role>', 'read or write', role, 'write').option('--stdin', 'Read one value from piped stdin')
    .action(async (name: string, opts: { role: TokenRole; stdin?: boolean }) => {
      human('store a credential', opts.stdin === true); credentialName(name);
      const value = opts.stdin ? await readPipedValue(options.promptIO) : await promptVaultValue(name, diagnostic, options.promptIO);
      if (value === null) { emit({ cancelled: true }, 'Credential entry cancelled.'); return; }
      initialRedactor.register(value);
      const rt = await getRuntime(); rt.redactor.register(value);
      emit(await rt.vaultSet(name, value, opts.role, { stdin: opts.stdin }), `Stored ${name} (${opts.role}).`);
    });
  vault.command('remove <NAME>').description('Remove one credential role')
    .option('--role <role>', 'read or write', role, 'write').action(async (name: string, opts: { role: TokenRole }) => {
      human('remove a credential'); credentialName(name);
      const rt = await getRuntime(); emit(await rt.vaultRemove(name, opts.role), `Removed ${name} (${opts.role}) if stored.`);
    });
  vault.command('import-env').description('Copy present environment credentials into the vault').action(async () => {
    human('import credentials'); const rt = await getRuntime(); const result = await rt.vaultImportEnv();
    emit(result, 'Present environment credentials were copied to the vault. You can now remove them from the environment.');
  });
  program.command('doctor').description('Explain local protections and credential capabilities')
    .option('--probe', 'Check documented token permissions through the guarded client').action(async opts => {
      const rt = await getRuntime(); const result = await rt.doctor(opts.probe === true);
      emit(result, result.items.map(item => `${item.status}: ${item.title}\n  ${item.detail}${item.fix ? `\n  ${item.fix}` : ''}`).join('\n'));
      if (result.items.some(item => item.status === 'fail')) exitCode = 1;
    });
  program.command('network').description('Show permitted hosts and the host-only network receipt')
    .option('--since <iso>', 'Include contacts at or after an ISO timestamp').action(async opts => {
      const result = await inspectNetwork(effectiveOptions(), opts.since);
      const groups = new Map<string, string[]>();
      for (const rule of result.rules) {
        const group = groups.get(rule.purpose) ?? [];
        const host = `${rule.host}${rule.owner === 'user' ? ' (added by you)' : ''}`;
        if (!group.includes(host)) group.push(host); groups.set(rule.purpose, group);
      }
      emit(result, ['Allowed hosts', ...[...groups].map(([purpose, hosts]) => `${purpose}:\n  ${hosts.join('\n  ')}`),
        'Network receipt: host | purpose | requests | blocked | last contact',
        ...result.receipt.map(row => `${row.host} | ${row.purpose} | ${row.count} | ${row.blocked} | ${row.lastAt}`),
        ...(result.receipt.length ? [] : ['No contacts recorded.'])].join('\n'));
    });
  const audit = program.command('audit').description('Check the local tamper-evident audit log');
  audit.command('verify').action(async () => {
    const result = await inspectAudit(effectiveOptions());
    emit(result, result.ok ? result.anchorChecked ? `Audit check passed: ${result.entries} entries, ${result.checkpoints} checkpoints.`
      : `Local audit chain checked: ${result.entries} entries, ${result.checkpoints} checkpoints; the independent vault anchor was not checked.`
      : `Audit check failed: ${result.problem ?? 'the recorded chain did not verify.'}`);
    if (!result.ok) exitCode = 1;
  });
  program.command('verify').description('Check this installation locally and against signed release checksums')
    .option('--offline', 'Run only the local integrity check').action(async opts => {
      const result = await inspectRelease(effectiveOptions(), opts.offline === true);
      const local = result.local.status === 'dev' ? 'Local check: development copy; no release manifest was checked.'
        : `Local integrity: ${result.local.status}.`;
      const online = result.release?.status === 'unconfigured'
        ? 'Release signing keys are not published yet; only the local check ran.'
        : result.release ? `Release signature: ${result.release.status}.` : '';
      emit(result, [local, online].filter(Boolean).join('\n'));
      if (result.local.status === 'mismatch' || result.release && !['verified', 'unconfigured'].includes(result.release.status)) exitCode = 1;
    });
  program.command('resume [planId]').description('Continue the latest unfinished rotation, or a selected plan').action(async planId => {
    human('resume a rotation'); const rt = await getRuntime(); await rt.prepareExecution(diagnostic); const report = await rt.resume(planId);
    emit({ report, journal: rt.paths.journal }, summary(report, rt.paths.journal)); reportExit(report);
  });
  program.command('finish [planId]').description('Re-verify and revoke old keys after the grace period')
    .option('--now', 'End the grace period now after re-verification').action(async (planId, opts) => {
      human('finish a rotation'); const rt = await getRuntime(); await rt.prepareExecution(diagnostic); const report = await rt.finish(planId, opts.now === true);
      emit({ report, journal: rt.paths.journal }, summary(report, rt.paths.journal)); reportExit(report);
    });
  program.command('undo <planId>').description('Restore readable old values during an unfinished rotation')
    .option('--cluster <id>', 'Restore only this cluster').action(async (planId, opts) => {
      human('undo a rotation'); const rt = await getRuntime(); await rt.prepareExecution(diagnostic); const result = await rt.undo(planId, opts.cluster ? [opts.cluster] : undefined);
      emit(result); if (result.unavailable.length) exitCode = 1;
    });
  const state = program.command('state').description('Manage encrypted saved project state');
  state.command('reset').description('Delete encrypted state and in-flight records; keep the audit log')
    .option('--force', 'Allow resetting unfinished rotations with saved in-flight values').action(async opts => {
      human('reset saved state');
      const rt = await getRuntime(); await rt.assertStateResetSafe(opts.force === true);
      if (!await confirmStateReset(diagnostic, options.promptIO)) { emit({ cancelled: true }, 'State reset cancelled.'); return; }
      emit(await rt.resetState(opts.force === true), 'Saved state reset. The audit log was kept.');
    });

  try { await program.parseAsync(args, { from: 'user' }); }
  catch (error) {
    if (error instanceof CommanderError) {
      if (error.exitCode === 0) return 0;
      diagnostic('Invalid command or option. Run keysentry --help for usage.');
    } else if (error instanceof RotationAbortedError) {
      if (error instanceof RotationInterruptedError && error.report.steps.some(step => step.newFingerprint && step.status !== 'skipped')) {
        const report = error.report;
        const staged = report.deployments.filter(deployment => deployment.state !== 'skipped');
        diagnostic('Rotation interrupted. New provider mutations and replacement prompts stopped; delivery and deployment of prepared values finished.');
        diagnostic(summary(report, runtime!.paths.journal));
        diagnostic(`Staged services: ${staged.map(deployment => deployment.serviceKey).join(', ') || '(none)'}`);
        diagnostic(`Redeployed services: ${staged.filter(deployment => deployment.deploymentId !== null).map(deployment => `${deployment.serviceKey} (${deployment.state})`).join(', ') || '(none)'}`);
        diagnostic(`Staged-but-not-deployed services: ${staged.filter(deployment => deployment.state !== 'success').map(deployment => deployment.serviceKey).join(', ') || '(none)'}`);
        const lost = report.steps.filter(step => step.error?.includes('ROLLED VALUE LOST')).map(step => step.clusterId);
        diagnostic(`Rolled values lost: ${lost.join(', ') || '(none)'}`);
        if (program.opts().json) emit({ aborted: true, report });
      } else diagnostic('aborted, no further changes');
    } else {
      // Only local fixed errors are surfaced; arbitrary adapters can include unregistered secrets.
      diagnostic(error instanceof StateLockedError
        ? 'Saved state cannot be read on this computer. Run "keysentry scan" interactively to rebuild inventory and monitor state, or "keysentry state reset" to start over. Scan keeps journals, plans and in-flight values.'
        : error instanceof CliError || error instanceof AgentRefusalError
        || error instanceof VaultLockedError || error instanceof VaultReadOnlyError || error instanceof VaultUnavailableError
        ? error.message : 'Command failed. Check configuration, enabled hosts, and the redacted rotation journal.');
    }
    return 1;
  } finally {
    try { await runtime?.checkpoint(); }
    catch { diagnostic('The audit checkpoint could not be saved. Run keysentry audit verify to inspect the log.'); exitCode = 1; }
    deployment?.dispose();
  }
  return exitCode;
}

/** npm's bin links resolve to the same module; importing this file does not start the CLI. */
export function isExecutableEntry(entry: string | undefined, modulePath = fileURLToPath(import.meta.url)): boolean {
  if (!entry) return false;
  try { return realpathSync(entry) === modulePath; }
  catch { return ['keysentry', 'keysentry.mjs'].includes(basename(entry)); }
}

if (isExecutableEntry(process.argv[1])) {
  const main = async () => {
    const bundlePath = fileURLToPath(import.meta.url);
    const permissions = await permissionOptionsForBin(process.argv, process.env, bundlePath);
    const result = await maybeReexecWithPermissions({ argv: process.argv, env: process.env, execPath: process.execPath,
      nodeVersion: process.versions.node, bundlePath, ...permissions,
    });
    return result.reexeced ? result.exitCode ?? 1 : runCli();
  };
  main().then(code => { process.exitCode = code; }).catch(() => { process.stderr.write('keysentry failed.\n'); process.exitCode = 1; });
}
