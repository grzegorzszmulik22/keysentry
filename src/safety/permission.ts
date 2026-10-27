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
const PERMISSION_VALUE_FLAGS = new Set(['--allow-fs-read', '--allow-fs-write', '--allow-net']);

/** Do not let inherited grants widen the new process's requested permissions. */
function withoutPermissionFlags(args: readonly string[]): string[] {
  const retained: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    const name = arg.split('=', 1)[0]!.replace(/^--no-/, '--');
    if (PERMISSION_SWITCHES.has(name)) continue;
    if (PERMISSION_VALUE_FLAGS.has(name)) {
      if (!arg.includes('=') && args[i + 1] && !args[i + 1]!.startsWith('-')) i++;
      continue;
    }
    retained.push(arg);
  }
  return retained;
}

export async function maybeReexecWithPermissions(opts: PermissionOptions & {
  argv: string[];
  env: NodeJS.ProcessEnv;
  execPath: string;
  spawnImpl?: SpawnLike;
}): Promise<{ reexeced: boolean; exitCode?: number; reason?: string }> {
  if ((process as NodeJS.Process & { permission?: unknown }).permission || opts.env.KEYSENTRY_SANDBOXED === '1') {
    return { reexeced: false, reason: 'already sandboxed' };
  }
  if (opts.env.KEYSENTRY_NO_SANDBOX === '1') {
    return { reexeced: false, reason: 'opted out with KEYSENTRY_NO_SANDBOX=1' };
  }
  const support = sandboxSupport(opts.nodeVersion);
  if (!support.supported) return { reexeced: false, reason: support.reason };
  if (!opts.argv[1]?.endsWith('.mjs')) {
    return { reexeced: false, reason: 'running from TypeScript sources' };
  }

  const args = [...permissionArgs(opts)!, ...withoutPermissionFlags(process.execArgv), ...opts.argv.slice(1)];
  const spawnImpl: SpawnLike = opts.spawnImpl ?? ((command, argv, options) => spawn(command, argv, options));
  return new Promise(resolve => {
    let child: Pick<ChildProcess, 'once'>;
    try {
      child = spawnImpl(opts.execPath, args, { env: { ...opts.env, KEYSENTRY_SANDBOXED: '1' }, stdio: 'inherit', shell: false });
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
