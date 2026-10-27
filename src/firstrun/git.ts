import { spawn, type ChildProcessByStdio } from 'node:child_process';
import type { Readable } from 'node:stream';

interface GitVersion { major: number; minor: number; display: string }
const VERSION_ERROR = 'Git version could not be read.';
let cachedVersion: Promise<GitVersion | null> | undefined;

/** This message contains only the validated numeric Git version, never process output. */
export class GitVersionError extends Error {
  constructor(version: string) {
    super(`Git ${version} is too old to scan history; install Git 2.20 or newer.`);
    this.name = 'GitVersionError';
  }
}

function readVersion(cwd: string): Promise<GitVersion | null> {
  return new Promise((resolve) => {
    const env: NodeJS.ProcessEnv = {};
    for (const name of ['PATH', 'SystemRoot', 'HOME', 'USERPROFILE']) {
      const key = Object.keys(process.env).find((key) => key.toLowerCase() === name.toLowerCase());
      if (key !== undefined) env[name] = process.env[key];
    }
    Object.assign(env, {
      GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0', GIT_PAGER: 'cat',
      GIT_OPTIONAL_LOCKS: '0', LC_ALL: 'C',
    });
    let child: ChildProcessByStdio<null, Readable, null>;
    try {
      child = spawn('git', ['version'], {
        cwd, env, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'],
      });
    } catch { resolve(null); return; }
    let settled = false;
    let output = Buffer.alloc(0);
    let killTimer: ReturnType<typeof setTimeout> | undefined;
    const timer = setTimeout(stop, 5_000);
    timer.unref();
    function finish(version: GitVersion | null): void {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      output = Buffer.alloc(0);
      resolve(version);
    }
    function stop(): void {
      if (settled) return;
      finish(null);
      child.kill();
      killTimer = setTimeout(() => child.kill('SIGKILL'), 100);
      killTimer.unref();
    }
    child.stdout.on('data', (chunk: Buffer) => {
      if (settled) return;
      if (output.length + chunk.length > 1_024) { stop(); return; }
      output = Buffer.concat([output, chunk]);
    });
    child.stdout.once('error', stop);
    child.once('error', stop);
    child.once('close', (code) => {
      clearTimeout(killTimer);
      // Apple Git, Git for Windows and release-candidate suffixes do not change the numeric comparison.
      const match = /^git version (\d{1,6})\.(\d{1,6})(?:\.(\d{1,6}))?(?:[-.][A-Za-z0-9.-]+| \(Apple Git-[A-Za-z0-9.-]+\))?\r?\n?$/.exec(output.toString('utf8'));
      const version = code === 0 && match ? {
        major: Number(match[1]), minor: Number(match[2]),
        display: `${match[1]}.${match[2]}${match[3] === undefined ? '' : `.${match[3]}`}`,
      } : null;
      finish(version);
    });
  });
}

/** Both local scans share one bounded, process-cached Git capability query. */
export async function gitScanOptions(opts: { cwd: string; signal: AbortSignal }): Promise<string[]> {
  if (opts.signal.aborted) throw new Error(VERSION_ERROR);
  cachedVersion ??= readVersion(opts.cwd);
  let onAbort: () => void = () => undefined;
  const aborted = new Promise<null>((resolve) => {
    onAbort = () => resolve(null);
    opts.signal.addEventListener('abort', onAbort, { once: true });
    if (opts.signal.aborted) onAbort();
  });
  let version: GitVersion | null;
  try { version = await Promise.race([cachedVersion, aborted]); }
  finally { opts.signal.removeEventListener('abort', onAbort); }
  if (!version || opts.signal.aborted) throw new Error(VERSION_ERROR);
  if (version.major < 2 || (version.major === 2 && version.minor < 20)) throw new GitVersionError(version.display);
  return version.major > 2 || version.minor >= 45 ? ['--no-lazy-fetch'] : ['-c', 'protocol.allow=never'];
}
