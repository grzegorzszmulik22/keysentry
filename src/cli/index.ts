#!/usr/bin/env node
import { pathToFileURL } from 'node:url';
import { Command, CommanderError, InvalidArgumentError } from 'commander';
import { createRedactor, renderBlastRadius } from '../core/index.js';
import type { GuidedPrompt, Inventory, RotationReport } from '../types.js';
import { RotationAbortedError } from '../types.js';
import { startMcpServer } from '../mcp/server.js';
import { confirmAction, confirmRotation, hasInteractiveTerminal, promptSecret, revealSecret, type PromptIO } from './prompts.js';
import { createRuntime, type KeysentryRuntime, type PlanFilters, type RuntimeOptions } from './runtime.js';
import { hostIdSchema, tierSchema } from './schemas.js';
import { CliError, RotationInterruptedError } from './errors.js';
import { serviceLabel } from './display.js';

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
  let exitCode = 0;
  const initialRedactor = createRedactor();
  const output = options.output ?? ((line: string) => process.stdout.write(`${line}\n`));
  const errorOutput = options.error ?? ((line: string) => process.stderr.write(`${line}\n`));
  const redact = (text: string) => (runtime?.redactor ?? initialRedactor).redact(text);
  const write = (text: string) => output(redact(runtime?.humanize(text) ?? text));
  const diagnostic = (text: string) => errorOutput(redact(runtime?.humanize(text) ?? text));
  const program = new Command();
  program.name('keysentry').description('Local-first secret inventory, breach response, rotation, and monitoring.')
    .version('0.1.0').option('--cwd <path>', 'Project directory', options.cwd ?? process.cwd())
    .option('--config <path>', 'Configuration path relative to cwd')
    .option('--json', 'Print secret-free JSON').option('--verbose', 'Enable redacted debug logs')
    .option('--fail-on-findings', 'Exit 2 when findings require attention')
    .showSuggestionAfterError(false).exitOverride()
    .configureOutput({ writeOut: text => write(text.trimEnd()), writeErr: () => {}, outputError: () => {} });

  const getRuntime = async () => {
    if (!runtime) {
      const globals = program.opts<{ cwd: string; config?: string; json?: boolean; verbose?: boolean }>();
      runtime = await createRuntime({ ...options, cwd: globals.cwd, config: globals.config ?? options.config, json: globals.json, verbose: globals.verbose });
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
    .option('--yes', 'Confirm execution without a terminal prompt')
    .option('--revoke <policy>', 'after-deploy, immediately, or never')
    .option('--no-redeploy', 'Leave activation to the operator')
    .option('--revoke-unconfirmed', 'Revoke old keys even when consumer activation is unconfirmed')
    .option('--accept-unplanned-sealed', 'Accept sealed consumers outside this plan that may use the old key')
    .option('--no-generate', 'Skip generated application secrets')
    .action(async (opts, command: Command) => {
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
      const interactive = hasInteractiveTerminal(options.promptIO);
      if (rotationPlan.steps.some(step => step.method === 'atomic-roll') && !interactive) {
        throw new CliError('Atomic-roll rotation requires an interactive terminal for replacement recovery. Run rotate --execute in a terminal.');
      }
      if (rotationPlan.steps.length && !opts.yes && !await (options.confirm ?? (count => confirmRotation(count, diagnostic)))(rotationPlan.steps.length)) {
        emit({ cancelled: true, report: preview, journal: rt.paths.journal }, 'Rotation cancelled. No host or provider changes.'); return;
      }
      const prompt = options.prompt ?? ((p: GuidedPrompt) => promptSecret(p, diagnostic, options.promptIO));
      const reveal = options.reveal ?? (interactive ? ((info, value) => revealSecret(info, value, diagnostic, options.promptIO)) : undefined);
      const report = await rt.rotate(rotationPlan, { ...rotationOptions, execute: true, prompt, reveal });
      emit({ preview, report, journal: rt.paths.journal }, summary(report, rt.paths.journal)); reportExit(report);
    });

  const canary = program.command('canary').description('Manage low-budget OpenRouter decoys');
  canary.command('create').requiredOption('--host <id>', 'Destination host').requiredOption('--service <id>', 'Project/service label or unique service ID/name')
    .option('--provider <id>', 'Canary provider', 'openrouter').option('--var <name>', 'Destination variable name')
    .option('--execute', 'Create and plant the canary').action(async opts => {
      if (opts.provider !== 'openrouter') throw new CliError('Canaries currently support OpenRouter only.');
      const host = hostIdSchema.safeParse(opts.host); if (!host.success) throw new CliError('Invalid host.');
      const rt = await getRuntime(); const result = await rt.createCanary({ host: host.data, service: opts.service, varName: opts.var, execute: opts.execute });
      emit({ dryRun: !opts.execute, canary: result }, result ? `Canary ${result.id} planted in ${serviceLabel(result.service)}:${result.varName}.` : 'Dry run: would plant a $0.01 OpenRouter canary. Pass --execute to plant it.');
    });
  canary.command('list').action(async () => {
    const rt = await getRuntime(); const canaries = await rt.canaries();
    emit(canaries, canaries.length ? canaries.map(canary => `${canary.id}: ${serviceLabel(canary.service)}:${canary.varName}`).join('\n') : 'No canaries configured.');
  });
  canary.command('remove <id>').option('--execute', 'Revoke the canary and remove monitoring metadata').action(async (id, opts) => {
    const rt = await getRuntime(); emit(await rt.removeCanary(id, opts.execute), opts.execute ? 'Canary revoked; inert host variable remains.' : 'Dry run: would revoke the canary. Pass --execute to remove it.');
  });

  program.command('monitor').description('Poll signals; rotations follow configured policy, guided steps are skipped')
    .option('--once', 'Run one poll and exit').option('--interval <seconds>', 'Polling interval in seconds', positive)
    .action(async opts => {
      const rt = await getRuntime();
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
  program.command('approve <id>').description('Review, confirm, and execute a pending rotation or containment action')
    .option('--yes', 'Skip typing the action id after reviewing the action')
    .action(async (id: string, opts: { yes?: boolean }) => {
    const rt = await getRuntime(); const review = await rt.reviewAction(id);
    const rotation = review.action.action === 'rotate' || review.action.action === 'breach-mode';
    diagnostic([`Action ${review.action.id}: ${review.action.action} ${review.action.clusterIds.length} secret cluster(s).`,
      ...review.plan.steps.map(step => `${step.provider} (${step.method}): ${step.consumers.map(consumer => `${serviceLabel(consumer.service)}:${consumer.varName}`).join(', ')}`),
      rotation ? 'Creates replacements, writes consumers, redeploys supported services, then revokes old keys after deployment.' : 'Disables or caps the selected keys at the provider; consumers may stop working.',
      `revokeUnconfirmed: ${review.revokeUnconfirmed}${review.revokeUnconfirmed ? ' — old keys may be revoked before manual restarts or other unconfirmed activation.' : ' — old keys are retained when activation is unconfirmed.'}`,
      review.requiresInteractive ? 'Interactive atomic-roll recovery is required; the old key dies when its replacement is created.' : '',
      review.manualRestarts.length ? `Manual restart / activation required:\n${review.manualRestarts.map(service => `  ${serviceLabel(service)}`).join('\n')}` : 'Manual restart / activation required: none known.',
    ].filter(Boolean).join('\n'));
    const interactive = hasInteractiveTerminal(options.promptIO);
    if (review.requiresInteractive && !interactive) throw new CliError('This action requires an interactive terminal for atomic-roll recovery; --yes only skips confirmation.');
    if (!opts.yes) {
      if (!interactive && !options.confirmAction) throw new CliError('Approval confirmation requires an interactive terminal. Pass --yes after reviewing the action.');
      if (!await (options.confirmAction ?? (actionId => confirmAction(actionId, diagnostic, options.promptIO)))(review.action.id)) {
        emit({ cancelled: true, action: review.action }, 'Approval cancelled. No host or provider changes.'); return;
      }
    }
    const prompt = options.prompt ?? ((p: GuidedPrompt) => promptSecret(p, diagnostic, options.promptIO));
    const reveal = options.reveal ?? ((info, value) => revealSecret(info, value, diagnostic, options.promptIO));
    const report = await rt.approve(id, { interactive, reviewHash: review.reviewHash, ...(interactive ? { prompt, reveal } : {}) });
    if (report) { emit({ report, journal: rt.paths.journal }, summary(report, rt.paths.journal)); reportExit(report); }
    else {
      const action = (await rt.monitorStatus()).pendingActions.find(action => action.id === id);
      const executed = action?.status === 'executed';
      emit({ action, journal: rt.paths.journal }, executed ? 'Containment action executed.' : 'Action did not execute; inspect actions and journal.');
      if (!executed) exitCode = 1;
    }
  });
  program.command('dismiss <id>').description('Dismiss a pending monitor action').action(async id => { const rt = await getRuntime(); emit(await rt.dismiss(id)); });
  program.command('drill').description('Time a full dry run and explain readiness from 0 to 100').action(async () => {
    const rt = await getRuntime(); const result = await rt.drill();
    emit(result, `Readiness: ${result.score}/100 (${result.elapsedMs} ms)\n${result.reasons.join('\n')}\n${summary(result.report, rt.paths.journal)}`); reportExit(result.report);
  });
  program.command('mcp').description('Serve MCP tools over stdio').action(async () => { await startMcpServer(await getRuntime()); });

  try { if (!args.length) { program.outputHelp(); return 0; } await program.parseAsync(args, { from: 'user' }); }
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
      diagnostic(error instanceof CliError ? error.message : 'Command failed. Check configuration, enabled hosts, and the redacted rotation journal.');
    }
    return 1;
  }
  return exitCode;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCli().then(code => { process.exitCode = code; }).catch(() => { process.stderr.write('keysentry failed.\n'); process.exitCode = 1; });
}
