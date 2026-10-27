import { homedir } from 'node:os';
import { execFile } from 'node:child_process';
import { lstat, readFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Inventory, Logger, Vault } from '../types.js';
import { createStateCipher, createStateStore, statePaths } from '../core/store.js';
import { openVault } from '../vault/index.js';
import { loadConfigMetadata, type ConfigMetadata } from './config.js';
import { inventorySchema } from './schemas.js';

interface GrantDependencies {
  userDir?: string;
  loadInventory?: (metadata: ConfigMetadata, env: NodeJS.ProcessEnv, userDir: string) => Promise<Inventory | null>;
  resolveHooksDirectory?: (cwd: string, env: NodeJS.ProcessEnv) => Promise<string>;
}

const silentLog: Logger = { debug() {}, info() {}, warn() {}, error() {} };

/** A missing key is not a reason to create a new project identity or state key here. */
async function readExistingInventory(metadata: ConfigMetadata, env: NodeJS.ProcessEnv, userDir: string): Promise<Inventory | null> {
  const paths = statePaths(metadata.cwd);
  const content = await readFile(paths.inventory, 'utf8');
  if (!content.startsWith('keysentry-encrypted:v1\n')) return null;
  const project: unknown = JSON.parse(await readFile(join(paths.dir, 'project.json'), 'utf8'));
  const projectId = project && typeof project === 'object' && 'id' in project ? project.id : undefined;
  if (typeof projectId !== 'string' || !/^[0-9a-f]{16}$/.test(projectId)) return null;
  // The state reader maintains .gitignore on reads. Only use it when that protection
  // is already present, so calculating grants cannot create or amend project files.
  const ignore = await readFile(join(paths.dir, '.gitignore'), 'utf8');
  if (ignore.trimEnd().split(/\r?\n/).at(-1) !== '*') return null;
  const vault = await openVault({ env, userDir, log: silentLog, allowFileFallback: async () => false,
    ...(env.KEYSENTRY_VAULT_PASSPHRASE ? { passphrase: async () => Buffer.from(env.KEYSENTRY_VAULT_PASSPHRASE!) } : {}),
  });
  const key = await vault.get(`project/${projectId}/key/state`);
  if (!key) return null;
  try {
    if (key.length !== 32) return null;
    // These optional binding fields are also consumed by the state hardening fix.
    const readOnlyVault: Vault = { backend: vault.backend, get: name => vault.get(name), list: prefix => vault.list(prefix),
      async set() { throw new Error('Grant calculation cannot create a vault binding.'); },
      async delete() { throw new Error('Grant calculation cannot delete a vault value.'); },
    };
    const storeOptions = { cwd: metadata.cwd, cipher: createStateCipher(key), vault: readOnlyVault, projectId };
    const saved = inventorySchema.safeParse(await createStateStore(storeOptions).loadInventory());
    return saved.success ? saved.data : null;
  } finally { key.fill(0); }
}

function commandName(args: string[]): string | undefined {
  for (let index = 0; index < args.length; index++) {
    const value = args[index]!;
    if (value === '--cwd' || value === '--config') { index++; continue; }
    if (!value.startsWith('-')) return value;
  }
  return undefined;
}

function consumerFiles(inventory: Inventory, roots: string[]): string[] {
  const consumers = [...inventory.findings, ...inventory.clusters.flatMap(cluster => cluster.consumers)];
  return [...new Set(consumers.flatMap(consumer => {
    if (consumer.service.host !== 'dotenv' || !isAbsolute(consumer.service.serviceId)) return [];
    const path = resolve(consumer.service.serviceId);
    return roots.some(root => {
      const rel = relative(root, path);
      return rel !== '' && rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
    }) ? [path] : [];
  }))];
}

async function needsVaultHelper(env: NodeJS.ProcessEnv, userDir: string): Promise<boolean> {
  let selected = env.KEYSENTRY_VAULT;
  if (selected === undefined) {
    try {
      const choice: unknown = JSON.parse(await readFile(join(userDir, 'vault-backend.json'), 'utf8'));
      if (choice && typeof choice === 'object' && 'backend' in choice && typeof choice.backend === 'string') selected = choice.backend;
    } catch { /* Runtime will explain invalid or unavailable backend choices. */ }
  }
  return !['env', 'encrypted-file', 'memory'].includes(selected ?? '');
}

async function resolveHooksDirectory(cwd: string, env: NodeJS.ProcessEnv): Promise<string> {
  // A first-run project need not be a repository. Avoid a child process when no
  // repository metadata exists; the command itself will explain that condition.
  let ancestor = cwd;
  let repository = false;
  while (true) {
    try { await lstat(join(ancestor, '.git')); repository = true; break; }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    const parent = dirname(ancestor);
    if (parent === ancestor) break;
    ancestor = parent;
  }
  if (!repository && !env.GIT_DIR) return join(cwd, '.git', 'hooks');
  const childEnv: NodeJS.ProcessEnv = {
    GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0', GIT_PAGER: 'cat',
    GIT_OPTIONAL_LOCKS: '0', LC_ALL: 'C',
  };
  for (const name of ['PATH', 'SystemRoot', 'HOME', 'USERPROFILE', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR']) {
    const entry = Object.entries(env).find(([key]) => key.toLowerCase() === name.toLowerCase());
    if (entry) childEnv[name] = entry[1];
  }
  const output = await new Promise<string>((fulfil, reject) => {
    execFile('git', ['-c', 'diff.external=', '-c', 'core.fsmonitor=false', 'rev-parse', '--git-path', 'hooks'],
      { cwd, env: childEnv, shell: false, windowsHide: true, timeout: 5_000, maxBuffer: 32_768, encoding: 'utf8' },
      (error, stdout) => error ? reject(new Error('Git hooks directory could not be read.')) : fulfil(stdout));
  });
  const path = output.replace(/\r?\n$/, '');
  if (!path || /[\r\n\0]/.test(path)) throw new Error('Git returned an unsupported hooks path.');
  return resolve(cwd, path);
}

/** Calculate filesystem grants before the executable enters Node's permission model. */
export async function permissionOptionsForBin(argv: string[], env: NodeJS.ProcessEnv = process.env,
  bundlePath = fileURLToPath(import.meta.url), dependencies: GrantDependencies = {}) {
  const args = argv.slice(2);
  const argument = (...names: string[]) => {
    let selected: string | undefined;
    // Commander retains the final scalar option, including mixed aliases and
    // `--name=value` spelling. Grants must authorize that same destination.
    for (let index = 0; index < args.length; index++) {
      const value = args[index]!;
      if (names.includes(value)) selected = args[++index];
      else {
        const name = names.find(name => value.startsWith(`${name}=`));
        if (name) selected = value.slice(name.length + 1);
      }
    }
    return selected;
  };
  const metadata = await loadConfigMetadata({ cwd: argument('--cwd'), config: argument('--config'), env });
  const userDir = resolve(metadata.cwd, dependencies.userDir ?? env.KEYSENTRY_USER_DIR
    ?? (env.KEYSENTRY_STATE_DIR ? join(env.KEYSENTRY_STATE_DIR, 'user') : join(homedir(), '.keysentry')));
  const directory = (path: string) => path.endsWith(sep) ? path : `${path}${sep}`;
  const bundle = resolve(bundlePath);
  const command = commandName(args);
  const writePaths = [directory(join(metadata.cwd, '.keysentry')), directory(userDir)];
  const extraReads: string[] = [];
  if (command === 'init') writePaths.push(metadata.configPath);
  if (command === 'guard' && (args.includes('install-hook') || args.includes('uninstall-hook'))) {
    const hooks = directory(resolve(await (dependencies.resolveHooksDirectory ?? resolveHooksDirectory)(metadata.cwd, env)));
    writePaths.push(hooks); extraReads.push(hooks);
  }
  if (command === 'notify' && (args.includes('add') || args.includes('remove'))) writePaths.push(metadata.configPath);
  if (command === 'watcher' && args.includes('setup') && args.some(value => value === '--relay-server' || value.startsWith('--relay-server='))) writePaths.push(metadata.configPath);
  if (command === 'watch' && env.KEYSENTRY_WATCHER_KEY) {
    const stateDir = resolve(metadata.cwd, env.KEYSENTRY_STATE_DIR ?? '.keysentry');
    writePaths.push(directory(stateDir)); extraReads.push(directory(stateDir));
    if (env.KEYSENTRY_WATCHER_CONFIG_FILE) extraReads.push(resolve(metadata.cwd, env.KEYSENTRY_WATCHER_CONFIG_FILE));
  }
  const output = argument('--output', '-o');
  if (command === 'plan' && output) writePaths.push(resolve(metadata.cwd, output));
  const reportOutput = argument('--out');
  if ((command === 'card' || command === 'timeline') && reportOutput) writePaths.push(resolve(metadata.cwd, reportOutput));
  if (command === 'watcher' && args.includes('setup') && output) writePaths.push(directory(resolve(metadata.cwd, output)));
  const writesDotenv = ['approve', 'resume', 'finish', 'undo'].includes(command ?? '')
    || command === 'rotate' && args.includes('--execute')
    || command === 'arm' || command === 'watch'
    || command === 'monitor' && (metadata.settings.monitor.autoExecute || metadata.settings.monitor.autoContain);
  if (writesDotenv && metadata.settings.hosts.dotenv.enabled !== false) {
    let inventory: Inventory | null = null;
    try { inventory = await (dependencies.loadInventory ?? readExistingInventory)(metadata, env, userDir); }
    catch { /* A locked or unavailable inventory receives the configured scan roots. */ }
    if (inventory) {
      for (const file of consumerFiles(inventory, metadata.dotenvRoots)) {
        writePaths.push(file);
        // The dotenv adapter replaces this file through a private sibling temp.
        // Node treats the first wildcard as a prefix grant, including any suffix.
        writePaths.push(`${file}.keysentry-*`);
      }
    } else writePaths.push(...metadata.dotenvRoots.map(directory));
  }
  return {
    readPaths: [directory(metadata.cwd), directory(userDir), bundle, join(dirname(bundle), 'release-manifest.json'), metadata.configPath, ...metadata.dotenvRoots.map(directory), ...extraReads],
    writePaths: [...new Set(writePaths)],
    allowChildProcess: command === undefined || ['guard', 'ui', 'watch'].includes(command)
      || command === 'passkey' && args.includes('register') || await needsVaultHelper(env, userDir),
  };
}
