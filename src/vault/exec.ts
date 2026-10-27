import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { StringDecoder } from 'node:string_decoder';

type HelperProcess = Pick<ChildProcessWithoutNullStreams, 'stdin' | 'stdout' | 'stderr' | 'kill' | 'once'>;

/** The spawn surface used by credential helpers; injectable without starting a real helper in tests. */
export type SpawnLike = (
  command: string,
  args: readonly string[],
  options: { shell: false; windowsHide: true; env: NodeJS.ProcessEnv; stdio: 'pipe' },
) => HelperProcess;

const ENV_NAMES = ['PATH', 'SystemRoot', 'HOME', 'USERPROFILE', 'DBUS_SESSION_BUS_ADDRESS', 'XDG_RUNTIME_DIR'] as const;
const MAX_STDERR_BYTES = 64 * 1024;

export function runHelper(
  cmd: string,
  args: string[],
  opts: { stdin?: Buffer; timeoutMs?: number; spawnImpl?: SpawnLike } = {},
): Promise<{ code: number; stdout: Buffer; stderr: string }> {
  return new Promise((resolve, reject) => {
    const env: NodeJS.ProcessEnv = {};
    for (const name of ENV_NAMES) {
      const value = process.env[name];
      if (value !== undefined) env[name] = value;
    }
    const spawnImpl: SpawnLike = opts.spawnImpl ?? ((command, argv, options) => spawn(command, argv, options));
    let child: HelperProcess;
    try {
      child = spawnImpl(cmd, args, { shell: false, windowsHide: true, env, stdio: 'pipe' });
    } catch {
      reject(new Error(`Could not run ${cmd}. Check that the command is available.`));
      return;
    }

    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stderrBytes = 0;
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const fail = (message: string, kill = false): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      // Never forward child-process errors: helpers can echo their stdin in them.
      reject(new Error(message));
      if (kill) {
        try { child.kill(); } catch { /* The process may have already exited. */ }
      }
    };

    child.once('error', () => fail(`Could not run ${cmd}. Check that the command is available.`));
    child.stdin.once('error', () => fail(`Could not send input to ${cmd}.`, true));
    child.stdout.once('error', () => fail(`Could not read output from ${cmd}.`, true));
    child.stderr.once('error', () => fail(`Could not read output from ${cmd}.`, true));
    child.stdout.on('data', (chunk: Buffer | string) => {
      if (!settled) stdout.push(Buffer.from(chunk));
    });
    child.stderr.on('data', (chunk: Buffer | string) => {
      if (settled || stderrBytes >= MAX_STDERR_BYTES) return;
      const bytes = Buffer.from(chunk).subarray(0, MAX_STDERR_BYTES - stderrBytes);
      stderr.push(bytes);
      stderrBytes += bytes.length;
    });
    child.once('close', (code: number | null) => {
      if (settled) return;
      if (code === null) {
        fail(`${cmd} ended without an exit code.`);
        return;
      }
      settled = true;
      clearTimeout(timer);
      // Normalize malformed UTF-8, then cap the text as well as the collected bytes.
      const normalized = Buffer.from(Buffer.concat(stderr).toString('utf8')).subarray(0, MAX_STDERR_BYTES);
      const decoder = new StringDecoder('utf8');
      resolve({ code, stdout: Buffer.concat(stdout), stderr: decoder.write(normalized) });
    });
    timer = setTimeout(() => fail(`${cmd} timed out. Check that the command can run.`, true), opts.timeoutMs ?? 15_000);
    try {
      child.stdin.end(opts.stdin);
    } catch {
      fail(`Could not send input to ${cmd}.`, true);
    }
  });
}
