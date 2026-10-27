import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const spawn = vi.hoisted(() => vi.fn());
vi.mock('node:child_process', () => ({ spawn }));

const key = 'sk-proj-HistoryKey0123456789abcdef';
const patch = [`\0${'a'.repeat(40)}\x002026-10-27T12:00:00+00:00`, 'diff --git a/.env b/.env',
  '--- /dev/null', '+++ b/.env', '@@ -0,0 +1 @@', `+OPENAI_API_KEY=${key}`, ''].join('\n');

function child() {
  return Object.assign(new EventEmitter(), {
    stdout: new PassThrough(), stderr: new PassThrough(), kill: vi.fn(() => true),
  });
}

function git(version: string, versionCode = 0) {
  spawn.mockImplementation((_command: string, args: string[]) => {
    const process = child();
    setImmediate(() => {
      const versionQuery = args.includes('version');
      const unsupported = /^git version 2\.(?:[0-9]|[1-3][0-9]|4[0-4])\./.test(version) && args.includes('--no-lazy-fetch');
      process.stdout.end(versionQuery ? `${version}\n` : unsupported ? '' : patch);
      process.stderr.end();
      setImmediate(() => process.emit('close', versionQuery ? versionCode : unsupported ? 129 : 0));
    });
    return process;
  });
}

beforeEach(() => { vi.resetModules(); spawn.mockReset(); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });

describe('Git scan compatibility', () => {
  it.each(['2.20.0', '2.39.5 (Apple Git-154)', '2.43.0', '2.44.9.windows.1'])(
    'finds a removed working-tree key in history with Git %s with the prescribed transport restriction', async (version) => {
      git(`git version ${version}`);
      const { scanHistory } = await import('../../src/firstrun/scan-history.js');
      const result = await scanHistory('/project');
      expect(result).toMatchObject({ commits: 1, complete: true });
      expect(result.hits).toMatchObject([{ kind: 'history', path: '.env', provider: 'openai', value: key }]);
      const queries = spawn.mock.calls.map(([, args]) => args as string[]);
      expect(queries.filter((args) => args.includes('version'))).toHaveLength(1);
      const log = queries.find((args) => args.includes('log'))!;
      expect(log).not.toContain('--no-lazy-fetch');
      expect(log).toEqual(expect.arrayContaining(['-c', 'protocol.allow=never']));
    },
  );

  it.each(['2.45.0', '2.50.1.windows.1', '3.0.0'])(
    'uses no-lazy-fetch on Git %s', async (version) => {
      git(`git version ${version}`);
      const { scanHistory } = await import('../../src/firstrun/scan-history.js');
      expect((await scanHistory('/project')).complete).toBe(true);
      const args = spawn.mock.calls.find(([, args]) => (args as string[]).includes('log'))![1];
      expect(args).toContain('--no-lazy-fetch');
      expect(args).not.toContain('protocol.allow=never');
    },
  );

  it('shares a single cached version query across concurrent and later scans', async () => {
    git('git version 2.43.0');
    const { scanHistory } = await import('../../src/firstrun/scan-history.js');
    const results = await Promise.all([scanHistory('/one'), scanHistory('/two')]);
    results.push(await scanHistory('/three'));
    expect(results.every((result) => result.complete && result.commits === 1)).toBe(true);
    expect(spawn.mock.calls.filter(([, args]) => (args as string[]).includes('version'))).toHaveLength(1);
    expect(spawn.mock.calls.filter(([, args]) => (args as string[]).includes('log'))).toHaveLength(3);
  });

  it.each(['1.9.5', '2.19.6.windows.1'])(
    'explains that Git %s is too old without running a scan', async (version) => {
      git(`git version ${version}`);
      const { scanHistory } = await import('../../src/firstrun/scan-history.js');
      const result = await scanHistory('/project');
      expect(result).toEqual({ commits: 0, complete: false, hits: [],
        note: `Git ${version.split('.windows')[0]} is too old to scan history; install Git 2.20 or newer.` });
      expect(spawn.mock.calls).toHaveLength(1);
    },
  );

  it.each([['unknown', 0], [`git version 2.43.0\n${key}`, 0], ['git version 2.43.0', 1]])(
    'fails closed for an unrecognized or failed version query', async (output, code) => {
      git(String(output), Number(code));
      const { scanHistory } = await import('../../src/firstrun/scan-history.js');
      const result = await scanHistory('/project');
      expect(result).toMatchObject({ commits: 0, complete: false, hits: [] });
      expect(result.note).toMatch(/unavailable/);
      expect(JSON.stringify(result)).not.toContain(key);
      expect(spawn.mock.calls).toHaveLength(1);
    },
  );

  it('bounds version output and discards it without reflecting values', async () => {
    git(`git version 2.43.0${key.repeat(100)}`);
    const { scanHistory } = await import('../../src/firstrun/scan-history.js');
    const result = await scanHistory('/project');
    expect(result.complete).toBe(false);
    expect(JSON.stringify(result)).not.toContain(key);
    expect(spawn.mock.calls).toHaveLength(1);
  });

  it('stops a hung version query within its own timeout', async () => {
    vi.useFakeTimers();
    const process = child();
    spawn.mockReturnValue(process);
    const { scanHistory } = await import('../../src/firstrun/scan-history.js');
    const pending = scanHistory('/project');
    await vi.advanceTimersByTimeAsync(5_000);
    expect(await pending).toMatchObject({ commits: 0, complete: false, hits: [] });
    expect(process.kill).toHaveBeenCalled();
    expect(spawn.mock.calls).toHaveLength(1);
  });

  it('honors a scan budget shorter than the version timeout', async () => {
    vi.useFakeTimers();
    const process = child();
    spawn.mockReturnValue(process);
    const { scanHistory } = await import('../../src/firstrun/scan-history.js');
    const pending = scanHistory('/project', { budgetMs: 10 });
    await vi.advanceTimersByTimeAsync(10);
    expect(await pending).toMatchObject({ commits: 0, complete: false, hits: [] });
    // A canceled subscriber cannot cancel the one process-wide capability query.
    expect(process.kill).not.toHaveBeenCalled();
    expect(spawn.mock.calls).toHaveLength(1);
    process.stdout.end('git version 2.43.0\n');
    process.emit('close', 0);
  });

  it('does not let the first caller timeout poison concurrent or later scans', async () => {
    vi.useFakeTimers();
    const version = child();
    spawn.mockImplementation((_command: string, args: string[]) => {
      if (args.includes('version')) return version;
      const process = child();
      queueMicrotask(() => { process.stdout.end(patch); process.stderr.end(); process.emit('close', 0); });
      return process;
    });
    const { scanHistory } = await import('../../src/firstrun/scan-history.js');
    const first = scanHistory('/first', { budgetMs: 10 });
    const second = scanHistory('/second');
    await vi.advanceTimersByTimeAsync(10);
    expect(await first).toMatchObject({ commits: 0, complete: false });
    version.stdout.end('git version 2.43.0\n');
    version.emit('close', 0);
    expect(await second).toMatchObject({ commits: 1, complete: true });
    expect(await scanHistory('/later')).toMatchObject({ commits: 1, complete: true });
    expect(version.kill).not.toHaveBeenCalled();
    expect(spawn.mock.calls.filter(([, args]) => (args as string[]).includes('version'))).toHaveLength(1);
  });

  it('does not forward credential or Git configuration overrides into version queries', async () => {
    vi.stubEnv('SECRET_TOKEN', key);
    vi.stubEnv('GIT_CONFIG_COUNT', '1');
    vi.stubEnv('GIT_CONFIG_KEY_0', 'protocol.allow');
    vi.stubEnv('GIT_CONFIG_VALUE_0', 'always');
    git('git version 2.43.0');
    const { scanHistory } = await import('../../src/firstrun/scan-history.js');
    await scanHistory('/project');
    const [, args, opts] = spawn.mock.calls.find(([, args]) => (args as string[]).includes('version'))!;
    expect(args).toEqual(['version']);
    expect(opts).toMatchObject({ shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
    expect(opts.env.SECRET_TOKEN).toBeUndefined();
    expect(opts.env.GIT_CONFIG_COUNT).toBeUndefined();
    expect(opts.env.GIT_CONFIG_KEY_0).toBeUndefined();
    expect(opts.env.GIT_CONFIG_VALUE_0).toBeUndefined();
  });
});
