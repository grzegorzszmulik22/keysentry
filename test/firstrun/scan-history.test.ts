import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { defaultGitRunner, scanHistory, type GitRunner } from '../../src/firstrun/scan-history.js';

const spawn = vi.hoisted(() => vi.fn());
vi.mock('node:child_process', () => ({ spawn }));
const key = 'sk-proj-HistoryKey0123456789abcdef';
const hash = 'a'.repeat(40);
const header = (id = hash) => `\x00${id}\x002026-10-27T12:00:00+00:00`;
function stream(lines: string[], code = 0): GitRunner {
  return async (_args, opts) => {
    for (const line of lines) {
      if (opts.signal.aborted) break;
      opts.onLine(line);
    }
    return { code };
  };
}
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); spawn.mockReset(); });

describe('first-run history', () => {
  it('classifies only added lines and records the path, line, commit and time', async () => {
    const git: GitRunner = async (args, opts) => {
      expect(args).toEqual(['log', '--all', '-p', '--no-color', '--no-ext-diff', '--no-textconv', '--no-show-signature', '--src-prefix=a/', '--dst-prefix=b/', '-U0', '--diff-filter=AM', '--format=%x00%H%x00%cI']);
      expect(opts.cwd).toBe('/project');
      return stream([header(), 'diff --git a/.env b/.env', '--- a/.env', '+++ b/.env', '@@ -0,0 +7,3 @@',
        `-REMOVED=${key}`, `+export OPENAI_API_KEY="${key}" # inline`, '+PORT=3000', '+API_TOKEN=${API_TOKEN}',
        'diff --git a/config.json b/config.json', '+++ b/config.json', '@@ -0,0 +1 @@', `+{"API_KEY": "${key}"}`])(args, opts);
    };
    const result = await scanHistory('/project', { git });
    expect(result).toMatchObject({ commits: 1, complete: true });
    expect(result.hits).toHaveLength(2);
    expect(result.hits[0]).toMatchObject({ kind: 'history', path: '.env', line: 7, commit: hash, committedAt: '2026-10-27T12:00:00+00:00', provider: 'openai', value: key });
    expect(result.hits[1]?.path).toBe('config.json');
  });

  it('history scan stops at the budget and says how far it got even when the runner ignores cancellation', async () => {
    vi.useFakeTimers();
    let signal: AbortSignal | undefined;
    const git: GitRunner = async (_args, opts) => {
      signal = opts.signal;
      opts.onLine(header());
      opts.onLine('+++ b/.env');
      opts.onLine('@@ -0,0 +1 @@');
      opts.onLine(`+KEY=${key}`);
      return new Promise(() => undefined);
    };
    const pending = scanHistory('/project', { git, budgetMs: 25 });
    await vi.advanceTimersByTimeAsync(25);
    const result = await pending;
    expect(signal?.aborted).toBe(true);
    expect(result).toMatchObject({ commits: 1, complete: false });
    expect(result.hits).toHaveLength(1);
    expect(result.note).toMatch(/last 1 commit/);
  });

  it('caps commits and does not classify later output from a runner that ignores the signal', async () => {
    const git: GitRunner = async (_args, { onLine }) => {
      onLine(header()); onLine('+++ b/.env'); onLine('@@ -0,0 +1 @@'); onLine(`+KEY=${key}`);
      onLine(header('b'.repeat(40))); onLine('+++ b/.env'); onLine(`+KEY=${key}`);
      return { code: 0 };
    };
    const result = await scanHistory('/project', { git, maxCommits: 1 });
    expect(result).toMatchObject({ commits: 1, complete: false });
    expect(result.hits).toHaveLength(1);
  });

  it('uses the working-tree dotenv grammar for inline comments and escaped values in history', async () => {
    const result = await scanHistory('/project', { git: stream([
      header(), '+++ b/.env', '@@ -0,0 +1 @@', `+OPENAI_API_KEY=${key}#comment`,
    ]) });
    expect(result.hits).toHaveLength(1);
    expect(result.hits[0]).toMatchObject({ provider: 'openai', value: key });
  });

  it('finds multiline private keys in contiguous added dotenv lines without joining removed lines', async () => {
    const pem = '-----BEGIN PRIVATE KEY-----\nabc123DEF456\n-----END PRIVATE KEY-----';
    const result = await scanHistory('/project', { git: stream([
      header(), '+++ b/.env', '@@ -0,0 +1,4 @@', '+PRIVATE_KEY="-----BEGIN PRIVATE KEY-----', '+abc123DEF456', '+-----END PRIVATE KEY-----"', `+OPENAI_API_KEY=${key}`,
      '@@ -7,3 +10,2 @@', '+OTHER_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----', '-not-added-content', '+-----END PRIVATE KEY-----"',
    ]) });
    expect(result.hits).toHaveLength(2);
    expect(result.hits[0]).toMatchObject({ provider: 'private-key', value: pem, line: 1 });
    expect(result.hits[1]).toMatchObject({ provider: 'openai', value: key, line: 4 });
  });

  it('does not include a quoted inline config comment in a history value', async () => {
    const result = await scanHistory('/project', { git: stream([
      header(), '+++ b/wrangler.toml', '@@ -0,0 +1 @@', `+OPENAI_API_KEY="${key}" # "example"`,
    ]) });
    expect(result.hits[0]?.value).toBe(key);
  });

  it('binary and huge diffs are skipped without losing following valid changes', async () => {
    const result = await scanHistory('/project', { git: stream([
      header(), 'diff --git a/blob b/blob', '+++ b/blob', 'GIT binary patch', `+KEY=${key}`,
      'diff --git a/.env b/.env', '+++ b/.env', '@@ -0,0 +1,3 @@', `+KEY=${key}${'a'.repeat(4096)}`,
      `+OTHER=${key}`, 'Binary files a/b and b/b differ', `+ANOTHER=${key}`,
    ]) });
    expect(result.hits).toHaveLength(1);
    expect(result.hits[0]).toMatchObject({ path: '.env', line: 2 });
  });

  it('returns an incomplete local scan when git is missing or fails without reflecting errors', async () => {
    const result = await scanHistory('/project', { git: async () => { throw new Error(key); } });
    expect(result).toMatchObject({ commits: 0, complete: false, hits: [] });
    expect(result.note).toMatch(/unavailable/);
    expect(JSON.stringify(result)).not.toContain(key);
    expect((await scanHistory('/project', { git: stream([], 128) })).complete).toBe(false);
  });

  it('decodes git quoted paths and rejects traversal or invalid commit metadata', async () => {
    const result = await scanHistory('/project', { git: stream([
      header(), '+++ "b/config/with\\040space.json"', '@@ -0,0 +4 @@', `+"KEY": "${key}"`,
      'diff --git a/../outside b/../outside', '+++ b/../outside', `+KEY=${key}`,
      `\0${key}\0${key}`, '+++ b/.env', `+KEY=${key}`,
    ]) });
    expect(result.hits).toHaveLength(1);
    expect(result.hits[0]?.path).toBe('config/with space.json');
  });

  it('streams a large synthetic history without losing commit counts', async () => {
    const git: GitRunner = async (_args, { onLine }) => {
      for (let index = 0; index < 10_000; index++) {
        onLine(header(index.toString(16).padStart(40, '0')));
        onLine('diff --git a/app.ts b/app.ts'); onLine('+++ b/app.ts');
        onLine('@@ -0,0 +1 @@'); onLine('+PORT=3000');
      }
      return { code: 0 };
    };
    const start = performance.now();
    const result = await scanHistory('/project', { git });
    expect(result).toMatchObject({ commits: 10_000, complete: true, hits: [] });
    expect(performance.now() - start).toBeLessThan(5000);
  });
});

describe('default git runner', () => {
  function child() {
    const process = Object.assign(new EventEmitter(), { stdout: new PassThrough(), stderr: new PassThrough(), kill: vi.fn(() => true) });
    spawn.mockReturnValue(process);
    return process;
  }

  it('uses a minimal environment, no shell and streamed bounded lines', async () => {
    const proc = child();
    vi.stubEnv('SECRET_TOKEN', key);
    const lines: string[] = [];
    const promise = defaultGitRunner(['log', '--all'], { cwd: '/project', onLine: (line) => lines.push(line), signal: new AbortController().signal });
    proc.stdout.write('one\r\ntw'); proc.stdout.write('o\n');
    for (let index = 0; index < 100; index++) proc.stdout.write('x'.repeat(4096));
    proc.stdout.end('\nlast'); proc.stderr.end(key);
    await new Promise<void>((resolve) => setImmediate(resolve));
    proc.emit('close', 0);
    expect(await promise).toEqual({ code: 0 });
    expect(lines).toEqual(['one', 'two', 'last']);
    const [command, args, opts] = spawn.mock.calls[0]!;
    expect(command).toBe('git');
    expect(args).toEqual(['--no-lazy-fetch', '-c', 'core.hooksPath=/dev/null', '-c', 'diff.external=', '-c', 'core.fsmonitor=false', 'log', '--all']);
    expect(opts).toMatchObject({ cwd: '/project', shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    expect(opts.env.SECRET_TOKEN).toBeUndefined();
    expect(opts.env).toMatchObject({ GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0', GIT_PAGER: 'cat', GIT_OPTIONAL_LOCKS: '0', LC_ALL: 'C' });
    expect(Object.keys(opts.env).every((name) => ['PATH', 'SystemRoot', 'HOME', 'USERPROFILE', 'GIT_CONFIG_NOSYSTEM', 'GIT_TERMINAL_PROMPT', 'GIT_PAGER', 'GIT_OPTIONAL_LOCKS', 'LC_ALL'].includes(name))).toBe(true);
    vi.unstubAllEnvs();
  });

  it('terminates git when aborted and suppresses process errors and stderr', async () => {
    const proc = child();
    const controller = new AbortController();
    const promise = defaultGitRunner(['log'], { cwd: '/project', onLine: () => undefined, signal: controller.signal });
    controller.abort();
    proc.emit('error', new Error(key));
    expect(await promise).toEqual({ code: 1 });
    expect(proc.kill).toHaveBeenCalled();
  });

  it('preserves added-line numbers after skipping oversized streamed diff lines', async () => {
    const proc = child();
    const promise = scanHistory('/project');
    proc.stdout.write(`${header()}\n+++ b/.env\n@@ -0,0 +1,2 @@\n+KEY=`);
    for (let index = 0; index < 10; index++) proc.stdout.write('x'.repeat(4096));
    proc.stdout.end(`\n+KEY=${key}\n`);
    await new Promise<void>((resolve) => setImmediate(resolve));
    proc.emit('close', 0);
    const result = await promise;
    expect(result.hits).toHaveLength(1);
    expect(result.hits[0]?.line).toBe(2);
  });
});
