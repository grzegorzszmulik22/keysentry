import type { Command } from 'commander';
import { lstat, unlink, writeFile } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { createInterface } from 'node:readline/promises';
import { execFile } from 'node:child_process';
import { win32 } from 'node:path';
import type { KeysentryRuntime } from './runtime.js';
import type { PromptIO } from './prompts.js';
import type { GitRunner } from '../firstrun/index.js';
import { guardStaged, formatGuardStaged, installHook, uninstallHook } from '../guard/index.js';
import { detectAgentEnvironment } from '../safety/index.js';
import { startDashboard } from '../dashboard/server/index.js';
import { createDashboardApi, createDashboardPasskeyStore } from './dashboard-api.js';
import { createPhase3Runtime } from './phase3-runtime.js';
import { runFirstRun, formatFirstRun, type FirstRunOptions } from './first-run.js';
import { CliError } from './errors.js';

export interface Phase3CommandsOptions {
  getRuntime(): Promise<KeysentryRuntime>;
  peekRuntime(): KeysentryRuntime | undefined;
  cwd(): string;
  firstRunSettings(): Pick<FirstRunOptions, 'vault' | 'userDir' | 'env' | 'passphrase'>;
  human(action: string): void;
  emit(value: unknown, text?: string): void;
  diagnostic(text: string): void;
  interactive(): boolean;
  json(): boolean;
  setExit(code: number): void;
  env: NodeJS.ProcessEnv;
  promptIO?: PromptIO;
  firstRunGit?: GitRunner;
  guardGit?: GitRunner;
  confirmFirstRunSave?: () => Promise<boolean>;
  confirmDashboard?: () => Promise<boolean>;
  openBrowser?: (url: string) => Promise<void>;
}

async function ask(question: string, opts: Phase3CommandsOptions, defaultYes = false): Promise<boolean> {
  if (!opts.interactive()) return false;
  const input = opts.promptIO?.input ?? process.stdin;
  const output = opts.promptIO?.output ?? process.stderr;
  const prompt = createInterface({ input, terminal: false });
  try {
    output.write(`${question} `);
    const answer = (await prompt.question('')).trim();
    return answer === '' ? defaultYes : /^(?:y|yes)$/i.test(answer);
  } finally { prompt.close(); }
}

/** Open a local launcher file, without putting the sign-in token in child arguments. */
export async function openDashboardBrowser(value: string, env: NodeJS.ProcessEnv = process.env): Promise<boolean> {
  if (!isAbsolute(value) || !value.endsWith('.html') || /[\x00-\x1f\x7f]/.test(value)) return false;
  try { const info = await lstat(value); if (!info.isFile() || info.isSymbolicLink()) return false; } catch { return false; }
  const childEnv: NodeJS.ProcessEnv = {};
  let file: string, args: string[];
  if (process.platform === 'win32') {
    const systemRoot = env.SystemRoot ?? env.SYSTEMROOT ?? 'C:\\Windows';
    if (!/^[A-Za-z]:\\[^\u0000-\u001f\u007f]*$/.test(systemRoot)) return false;
    file = win32.join(systemRoot, 'System32', 'rundll32.exe');
    args = ['url.dll,FileProtocolHandler', value];
    childEnv.SystemRoot = systemRoot; childEnv.WINDIR = systemRoot; childEnv.PATH = win32.join(systemRoot, 'System32');
  } else if (process.platform === 'darwin' || process.platform === 'linux') {
    file = process.platform === 'darwin' ? '/usr/bin/open' : '/usr/bin/xdg-open';
    args = [value]; childEnv.PATH = '/usr/bin:/bin';
    const names = process.platform === 'linux'
      ? ['HOME', 'DISPLAY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR', 'XDG_CURRENT_DESKTOP', 'DESKTOP_SESSION', 'DBUS_SESSION_BUS_ADDRESS'] : ['HOME'];
    for (const name of names) {
      const field = env[name];
      if (field && field.length <= 4096 && !/[\u0000-\u001f\u007f]/.test(field)) childEnv[name] = field;
    }
  } else return false;
  return new Promise<boolean>(resolve => {
    try { execFile(file, args, { env: childEnv, shell: false, windowsHide: true, timeout: 5000, maxBuffer: 1024 }, error => resolve(error === null)); }
    catch { resolve(false); }
  });
}

async function writeNew(cwd: string, file: string, text: string): Promise<string> {
  const path = resolve(cwd, file);
  try { await writeFile(path, text, { encoding: 'utf8', mode: 0o600, flag: 'wx' }); }
  catch { throw new CliError('The output file could not be created. Choose a new path in an existing directory.'); }
  return path;
}

export function registerPhase3Commands(program: Command, opts: Phase3CommandsOptions): void {
  const reports = async () => createPhase3Runtime(await opts.getRuntime());
  const openDashboard = async (readOnly = false, printUrl = false) => {
    if (printUrl && (!opts.interactive() || detectAgentEnvironment(opts.env))) throw new CliError('--print-url requires an interactive human terminal.');
    const rt = await opts.getRuntime();
    let path: string | undefined;
    let used = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const removeLauncher = async () => { used = true; clearTimeout(timer); if (path) await unlink(path).catch(() => {}); };
    const dashboardOptions = { api: createDashboardApi(rt),
      readOnly: readOnly || detectAgentEnvironment(opts.env) !== null,
      passkeys: createDashboardPasskeyStore(rt.store, rt.vault),
      onTokenUsed: removeLauncher,
      onError: (name: string) => {
        const errorClass = /^[A-Za-z][A-Za-z0-9_]{0,79}$/.test(name) ? name : 'Error';
        opts.diagnostic(`Dashboard request failed: ${errorClass}`);
      },
    };
    const dashboard = await startDashboard(dashboardOptions);
    const url = new URL(dashboard.url);
    if (url.protocol !== 'http:' || url.hostname !== 'localhost' || url.pathname !== '/' || url.hash || url.searchParams.size !== 1
      || !/^[A-Za-z0-9_-]{43}$/.test(url.searchParams.get('t') ?? '') || url.username || url.password) {
      await dashboard.close(); throw new CliError('The dashboard sign-in link could not be created.');
    }
    path = join(rt.userDir, `dashboard-${randomUUID()}.html`);
    const target = dashboard.url.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;');
    try {
      await writeFile(path, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta http-equiv="refresh" content="0;url=${target}"><title>Open keysentry</title></head><body><p><a href="${target}" rel="noreferrer">Open keysentry</a></p></body></html>\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    } catch { await dashboard.close(); throw new CliError(`The dashboard launcher could not be created in ${rt.userDir}. Set KEYSENTRY_USER_DIR to a writable directory.`); }
    if (used) await removeLauncher();
    else { timer = setTimeout(() => { void removeLauncher(); }, 120_000); timer.unref(); }
    opts.emit({ path, port: dashboard.port, ...(printUrl ? { url: dashboard.url } : {}) }, printUrl ? `Dashboard: ${dashboard.url}` : `Dashboard: ${path}`);
    try {
      if (opts.openBrowser) await opts.openBrowser(path);
      else if (!await openDashboardBrowser(path, opts.env)) throw new Error();
    }
    catch { opts.diagnostic('The browser could not be opened. Open the dashboard file shown above in your browser within two minutes.'); }
  };

  program.option('--no-save', 'Scan without saving any first-run state').allowExcessArguments(false);
  program.action(async () => {
    const noSave = program.opts<{ save: boolean }>().save === false;
    const agent = detectAgentEnvironment(opts.env) !== null;
    const initialized = await lstat(join(opts.cwd(), '.keysentry', 'project.json')).then(info => info.isFile() && !info.isSymbolicLink(), error => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
      throw new CliError('The saved project identifier could not be read. Nothing was changed.');
    });
    let emitted = false;
    const first = await runFirstRun({ ...opts.firstRunSettings(), cwd: opts.cwd(), noSave, runtime: opts.peekRuntime(), git: opts.firstRunGit,
      saveResult: initialized ? async result => {
        const rt = await opts.getRuntime();
        await rt.store.writeJson('report', join(rt.paths.dir, 'first-run.json'), result);
      } : undefined,
      confirmSave: !noSave && !agent && opts.interactive() && !opts.json()
        ? async result => {
          opts.emit(result, formatFirstRun(result)); emitted = true;
          const accepted = await (opts.confirmFirstRunSave ?? (() => ask('Save this summary in .keysentry/? [y/N]', opts)))();
          if (accepted) opts.human('save first-run state');
          return accepted;
        } : async () => false });
    if (!emitted) opts.emit(first.result, formatFirstRun(first.result));
    if (!noSave && first.saved && !agent && opts.interactive() && !opts.json()
      && await (opts.confirmDashboard ?? (() => ask('Open the dashboard? [Y/n]', opts, true)))()) await openDashboard();
  });

  program.command('ui').description('Open the local dashboard; changes require a passkey')
    .option('--read-only', 'Browse with no key changes')
    .option('--print-url', 'Print the one-time URL at an interactive human terminal')
    .action(async options => { await openDashboard(options.readOnly === true, options.printUrl === true); });

  const guard = program.command('guard').description('Check the working tree for keys; --history includes git history')
    .option('--staged', 'Check only the staged diff and stop commits containing keys')
    .option('--history', 'Include git history')
    .action(async options => {
      if (options.staged && options.history) throw new CliError('Use --staged or --history for this check.');
      if (options.staged) {
        const result = await guardStaged(opts.cwd(), opts.guardGit);
        const formatted = formatGuardStaged(result);
        if (formatted.output || opts.json()) opts.emit(result, formatted.output.trimEnd());
        opts.setExit(formatted.exitCode);
      } else {
        const first = await runFirstRun({ ...opts.firstRunSettings(), cwd: opts.cwd(), noSave: true, includeHistory: options.history === true, runtime: opts.peekRuntime(), git: opts.firstRunGit });
        opts.emit(first.result, formatFirstRun(first.result, options.history === true));
        if (first.result.findings.length) opts.setExit(1);
      }
    });
  guard.command('install-hook').description('Install a readable pre-commit check; never downloads anything')
    .option('--force', 'Keep a backup and replace a foreign hook')
    .action(async options => {
      opts.human('install the pre-commit hook');
      const result = await installHook(opts.cwd(), { force: options.force === true, binPath: 'keysentry', git: opts.guardGit });
      opts.emit(result,
        'Pre-commit check installed. Run keysentry guard uninstall-hook to remove it.');
      if (!result.onPath) opts.diagnostic('The hook calls keysentry from your PATH; install it with npm install -g keysentry so commits are checked.');
    });
  guard.command('uninstall-hook').description('Remove only the unmodified keysentry pre-commit hook')
    .action(async () => {
      opts.human('remove the pre-commit hook');
      await uninstallHook(opts.cwd(), opts.guardGit);
      opts.emit({ removed: true }, 'The keysentry pre-commit hook was removed if present.');
    });

  program.command('hygiene').description('Show key age, copies and rotation reminders').action(async () => {
    const result = await (await reports()).hygiene();
    opts.emit(result, result.length ? result.map(key => `${key.clusterId}: ${key.ageDays} days old, ${key.copies} copies${key.rotateBy ? `; rotate by ${key.rotateBy}` : ''}`).join('\n') : 'No keys in the saved inventory.');
  });
  program.command('spend-limits').description('Preview supported provider spend limits')
    .option('--apply', 'Apply the configured limits to supported keys')
    .action(async options => {
      if (options.apply) opts.human('apply spend limits');
      opts.emit(await (await reports()).spendLimits(options.apply === true));
    });
  program.command('digest').description('Summarize the last week in one calm message')
    .option('--send', 'Send through your configured notification channels')
    .action(async options => {
      if (options.send) opts.human('send the weekly digest');
      const result = await (await reports()).digest(options.send === true);
      opts.emit(result, [result.message.title, ...result.message.lines,
        ...(result.delivered ? [`Delivered to ${result.delivered.length} notification channels.`] : []),
        ...(result.failed?.length ? [`${result.failed.length} notification channels could not deliver the digest.`] : []),
      ].join('\n'));
      if (options.send && !result.delivered?.length) opts.setExit(1);
    });
  program.command('card').description('Create a secret-free readiness card')
    .option('--out <file.svg>', 'Create a new SVG file')
    .option('--share-platform', 'Include the platform from the completed rotation')
    .option('--share-counts', 'Include the completed rotation key count and duration')
    .action(async options => {
      if (options.out) opts.human('write a readiness card');
      const result = await (await reports()).card({ platform: options.sharePlatform === true, counts: options.shareCounts === true });
      if (options.out) {
        const path = await writeNew(opts.cwd(), options.out, result.svg);
        opts.emit({ path, score: result.score }, `Readiness card: ${path}`);
      } else opts.emit(result, result.svg);
    });
  program.command('timeline <planId|waveId>').description('Show a value-free incident or rotation timeline')
    .option('--out <file.md>', 'Create a new Markdown file')
    .action(async (id, options) => {
      if (options.out) opts.human('write a timeline');
      const result = await (await reports()).timeline(id);
      if (options.out) {
        const path = await writeNew(opts.cwd(), options.out, result.markdown);
        opts.emit({ path, events: result.events }, `Timeline: ${path}`);
      } else opts.emit(result, result.markdown);
    });
}
