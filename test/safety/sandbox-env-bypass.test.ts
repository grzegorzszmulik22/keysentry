// Review M7 regression: the loop guard is not proof of active permissions, and
// inherited NODE_OPTIONS must not widen the child's explicit permission grants.
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, test } from 'vitest';
import { createRuntime } from '../../src/cli/runtime.js';
import { maybeReexecWithPermissions } from '../../src/safety/permission.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });

test('doctor does not report the sandbox as on just because KEYSENTRY_SANDBOXED=1 is set', async () => {
  expect((process as NodeJS.Process & { permission?: unknown }).permission).toBeUndefined();
  const cwd = await mkdtemp(join(tmpdir(), 'ks-probe-sandbox-')); dirs.push(cwd);
  const env = { KEYSENTRY_VAULT: 'memory', KEYSENTRY_SANDBOXED: '1' };
  const skipped = await maybeReexecWithPermissions({ argv: ['node', join(cwd, 'keysentry.mjs')], env, execPath: process.execPath,
    nodeVersion: '24.22.1', readPaths: [], writePaths: [], allowChildProcess: false, spawnImpl: () => { throw new Error('not reached'); } });
  expect(skipped).toEqual({ reexeced: false, reason: 'already sandboxed' });

  const runtime = await createRuntime({ cwd, userDir: join(cwd, 'user'), vault: createFakeVault(), inflight: createFakeInFlight(), fingerprintKey: Buffer.alloc(32, 9),
    env, http: new FakeHttp(), hosts: [], log: silentLogger, stdinIsTTY: false, stdoutIsTTY: false });
  const result = await runtime.doctor(false);
  const node = result.items.find(item => item.area === 'node')!;
  expect(node.detail).not.toMatch(/sandbox is on/);
});

test('the sandboxed child does not inherit permission grants through NODE_OPTIONS', async () => {
  let childEnv: NodeJS.ProcessEnv | undefined;
  let childArgs: readonly string[] = [];
  await maybeReexecWithPermissions({
    argv: ['node', '/opt/keysentry/keysentry.mjs', 'scan'], env: { NODE_OPTIONS: '--allow-fs-write=* --allow-child-process' },
    execPath: process.execPath, nodeVersion: '24.22.1', readPaths: ['/work/'], writePaths: ['/work/.keysentry/'], allowChildProcess: false,
    spawnImpl: (_command, args, options) => {
      childArgs = args; childEnv = options.env;
      return { once(event: string, listener: (code: number, signal: null) => void) { if (event === 'exit') setImmediate(() => listener(0, null)); return this; } } as never;
    },
  });
  expect(childArgs).toContain('--permission');
  expect(childEnv?.NODE_OPTIONS ?? '').not.toMatch(/--allow-(?:fs-write|fs-read|child-process)/);
});
