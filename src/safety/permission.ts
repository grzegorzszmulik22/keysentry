import { spawn, type ChildProcess } from 'node:child_process';

export type SpawnLike = (
  command: string,
  args: readonly string[],
  options: { env: NodeJS.ProcessEnv; stdio: 'inherit'; shell: false },
) => Pick<ChildProcess, 'once'>;

export interface SandboxSupport {
  supported: boolean;
  minimum?: string;
  reason?: string;
}

// October 2026 permission-model fixes: https://nodejs.org/dist/index.json
const MINIMUMS: Readonly<Record<number, readonly [number, number, number]>> = {
  22: [22, 23, 4],
  24: [24, 22, 1],
  26: [26, 12, 1],
};

/** Only known, patched even-numbered release lines are eligible. */
export function sandboxSupport(nodeVersion: string): SandboxSupport {
  const match = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(nodeVersion);
  const parts = match?.slice(1).map(Number);
  const minimumParts = parts && parts.every(Number.isSafeInteger) ? MINIMUMS[parts[0]!] : undefined;
  if (!parts || !minimumParts) {
    return { supported: false, reason: `Node ${nodeVersion} line is not supported for the sandbox` };
  }
  const minimum = minimumParts.join('.');
  if (parts[1]! < minimumParts[1] || (parts[1] === minimumParts[1] && parts[2]! < minimumParts[2])) {
    return { supported: false, minimum, reason: `Node ${nodeVersion} is older than ${minimum} for its line` };
  }
  return { supported: true, minimum };
}

export interface PermissionOptions {
  nodeVersion: string;
  /** Absolute paths; a trailing slash or backslash marks a directory. Include the bundle itself. */
  readPaths: string[];
  /** Absolute paths; a trailing slash or backslash marks a directory. */
  writePaths: string[];
  allowChildProcess: boolean;
}

function permissionPath(path: string): string {
  return /[\\/]$/.test(path) ? `${path}*` : path;
}

export function permissionArgs(opts: PermissionOptions): string[] | null {
  if (!sandboxSupport(opts.nodeVersion).supported) return null;
  return [
    '--permission',
    ...opts.readPaths.map(path => `--allow-fs-read=${permissionPath(path)}`),
    ...opts.writePaths.map(path => `--allow-fs-write=${permissionPath(path)}`),
    ...(opts.allowChildProcess ? ['--allow-child-process'] : []),
  ];
}

const PERMISSION_SWITCHES = new Set([
  '--permission', '--experimental-permission', '--allow-child-process', '--allow-worker',
  '--allow-addons', '--allow-wasi', '--allow-inspector',
]);
/** Do not let inherited grants widen the new process's requested permissions. */
function withoutPermissionFlags(args: readonly string[]): string[] {
  const retained: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    const name = arg.split('=', 1)[0]!.replace(/^--no-/, '--');
    if (PERMISSION_SWITCHES.has(name)) continue;
    if (name.startsWith('--allow-')) {
      if (!arg.includes('=') && args[i + 1] && !args[i + 1]!.startsWith('-')) i++;
      continue;
    }
    retained.push(arg);
  }
  return retained;
}

/** NODE_OPTIONS uses whitespace-separated arguments with double-quoted values. */
function sanitizedNodeOptions(value: string): string {
  const args: string[] = [];
  let arg = '';
  let quoted = false;
  let started = false;
  for (let i = 0; i < value.length; i++) {
    const char = value[i]!;
    if (char === '\\' && quoted && (value[i + 1] === '"' || value[i + 1] === '\\')) {
      arg += value[++i]!;
      started = true;
    } else if (char === '"') {
      quoted = !quoted;
      started = true;
    } else if (/\s/.test(char) && !quoted) {
      if (started) args.push(arg);
      arg = '';
      started = false;
    } else {
      arg += char;
      started = true;
    }
  }
  // An invalid option string cannot safely be retained in the child.
  if (quoted) return '';
  if (started) args.push(arg);
  return withoutPermissionFlags(args).map(value => /[\s"\\]/.test(value)
    ? `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
    : value).join(' ');
}

export async function maybeReexecWithPermissions(opts: PermissionOptions & {
  argv: string[];
  env: NodeJS.ProcessEnv;
  execPath: string;
  /** The CLI passes its own fileURLToPath(import.meta.url), not npm's bin link. */
  bundlePath?: string;
  spawnImpl?: SpawnLike;
}): Promise<{ reexeced: boolean; exitCode?: number; reason?: string }> {
  if ((process as NodeJS.Process & { permission?: unknown }).permission) {
    return { reexeced: false, reason: 'already sandboxed' };
  }
  // This marker prevents a re-exec loop only. Runtime diagnostics must consult
  // process.permission; the marker is not evidence that permissions are active.
  if (opts.env.KEYSENTRY_SANDBOXED === '1') return { reexeced: false, reason: 'already sandboxed' };
  if (opts.env.KEYSENTRY_NO_SANDBOX === '1') {
    return { reexeced: false, reason: 'opted out with KEYSENTRY_NO_SANDBOX=1' };
  }
  const support = sandboxSupport(opts.nodeVersion);
  if (!support.supported) return { reexeced: false, reason: support.reason };
  const bundlePath = opts.bundlePath ?? opts.argv[1];
  if (!bundlePath?.endsWith('.mjs')) {
    return { reexeced: false, reason: 'running from TypeScript sources' };
  }

  const readPaths = opts.readPaths.includes(bundlePath) ? opts.readPaths : [...opts.readPaths, bundlePath];
  const args = [...permissionArgs({ ...opts, readPaths })!, ...withoutPermissionFlags(process.execArgv), bundlePath, ...opts.argv.slice(2)];
  const env: NodeJS.ProcessEnv = { ...opts.env, KEYSENTRY_SANDBOXED: '1' };
  if (env.NODE_OPTIONS !== undefined) env.NODE_OPTIONS = sanitizedNodeOptions(env.NODE_OPTIONS);
  const spawnImpl: SpawnLike = opts.spawnImpl ?? ((command, argv, options) => spawn(command, argv, options));
  return new Promise(resolve => {
    let child: Pick<ChildProcess, 'once'>;
    try {
      child = spawnImpl(opts.execPath, args, { env, stdio: 'inherit', shell: false });
    } catch {
      resolve({ reexeced: true, exitCode: 1 });
      return;
    }
    // Child error messages can contain environment values; only return a status.
    child.once('error', () => resolve({ reexeced: true, exitCode: 1 }));
    const ended = (code: number | null, signal: NodeJS.Signals | null): void => {
      resolve({ reexeced: true, exitCode: signal || code === null ? 1 : code });
    };
    child.once('exit', ended);
    child.once('close', ended);
  });
}
