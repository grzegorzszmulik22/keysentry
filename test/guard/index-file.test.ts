import { EventEmitter } from 'node:events';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { spawn } = vi.hoisted(() => ({ spawn: vi.fn() }));
vi.mock('node:child_process', () => ({ spawn }));

const key = 'sk-proj-IndexRegression0123456789abcdef';
const patch = ['diff --git a/.env b/.env', '--- a/.env', '+++ b/.env', '@@ -1 +1 @@',
  '-PORT=3000', `+OPENAI_API_KEY=${key}`, ''].join('\n');
const gitNames = ['GIT_INDEX_FILE', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR',
  'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES'];

describe('hook Git context', () => {
  let root: string;
  beforeEach(async () => {
    vi.resetModules();
    spawn.mockReset();
    root = await mkdtemp(join(tmpdir(), 'keysentry-index-'));
    await mkdir(join(root, '.git'));
    await writeFile(join(root, '.git', 'index'), '');
    for (const name of gitNames) vi.stubEnv(name, undefined);
    spawn.mockImplementation((_command: string, args: string[], opts: { env: NodeJS.ProcessEnv }) => {
      const child = Object.assign(new EventEmitter(), {
        stdout: new PassThrough(), stderr: new PassThrough(), kill: vi.fn(() => true),
      });
      setImmediate(async () => {
        const source = args.includes('version') ? 'git version 2.43.0\n'
          : await readFile(opts.env.GIT_INDEX_FILE ?? join(root, '.git', 'index'), 'utf8');
        child.stdout.end(source);
        child.stderr.end();
        setImmediate(() => child.emit('close', 0));
      });
      return child;
    });
  });
  afterEach(async () => {
    vi.unstubAllEnvs();
    await rm(root, { recursive: true, force: true });
  });

  it.each(['index.lock', 'next-index-123.lock'])('checks the temporary %s used by commit -a and path commits', async (name) => {
    const committing = join(root, '.git', name);
    await writeFile(committing, patch);
    vi.stubEnv('GIT_INDEX_FILE', committing);
    for (const variable of gitNames.slice(1)) vi.stubEnv(variable, join(root, variable.toLowerCase()));
    vi.stubEnv('GIT_CONFIG_COUNT', '1');
    vi.stubEnv('GIT_CONFIG_KEY_0', 'diff.external');
    vi.stubEnv('GIT_CONFIG_VALUE_0', 'untrusted-program');
    vi.stubEnv('GIT_EXEC_PATH', 'untrusted-program');
    vi.stubEnv('GIT_SSH_COMMAND', 'untrusted-program');
    vi.stubEnv('KEYSENTRY_TEST_SECRET', 'fake-private-value');
    const { guardStaged } = await import('../../src/guard/guard.js');
    const result = await guardStaged(root);
    expect(result.blocked.map(({ path, line, provider }) => ({ path, line, provider })))
      .toEqual([{ path: '.env', line: 1, provider: 'openai' }]);
    expect(JSON.stringify(result)).not.toContain(key);
    const [, args, options] = spawn.mock.calls.find(([, args]) => args.includes('--cached'))!;
    expect(args).toContain('--text');
    for (const variable of gitNames) expect(options.env[variable]).toBe(process.env[variable]);
    const allowed = new Set([...gitNames, 'PATH', 'SystemRoot', 'HOME', 'USERPROFILE', 'GIT_CONFIG_NOSYSTEM',
      'GIT_TERMINAL_PROMPT', 'GIT_PAGER', 'GIT_OPTIONAL_LOCKS', 'LC_ALL']);
    expect(Object.keys(options.env).every((variable) => allowed.has(variable))).toBe(true);
    expect(JSON.stringify(options.env)).not.toMatch(/fake-private-value|untrusted-program/);
  });

  it('shares one version query between both scans and blocks all transports on older Git', async () => {
    const { guardStaged } = await import('../../src/guard/guard.js');
    const { scanHistory } = await import('../../src/firstrun/scan-history.js');
    await Promise.all([guardStaged(root), scanHistory(root)]);
    expect(spawn.mock.calls.filter(([, args]) => args.includes('version'))).toHaveLength(1);
    for (const [, args] of spawn.mock.calls.filter(([, args]) => args.includes('log') || args.includes('diff'))) {
      expect(args).not.toContain('--no-lazy-fetch');
      expect(args).toEqual(expect.arrayContaining(['-c', 'protocol.allow=never']));
    }
  });
});
