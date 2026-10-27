import { EventEmitter } from 'node:events';
import { afterEach, describe, expect, test } from 'vitest';
import { maybeReexecWithPermissions, permissionArgs, sandboxSupport, type SpawnLike } from '../../src/safety/index.js';

const permissionDescriptor = Object.getOwnPropertyDescriptor(process, 'permission');
const execArgvDescriptor = Object.getOwnPropertyDescriptor(process, 'execArgv');
afterEach(() => {
  if (permissionDescriptor) Object.defineProperty(process, 'permission', permissionDescriptor);
  else Reflect.deleteProperty(process, 'permission');
  if (execArgvDescriptor) Object.defineProperty(process, 'execArgv', execArgvDescriptor);
});

const paths = { readPaths: ['/project/', '/install/keysentry.mjs'], writePaths: ['/project/.keysentry/'], allowChildProcess: false };
const options = () => ({ ...paths, argv: ['/node', '/install/keysentry.mjs', 'doctor'], env: { PATH: '/bin' }, execPath: '/node', nodeVersion: '22.23.4' });

describe('permission arguments', () => {
  test('formats paths with spaces as separate arguments and marks directories', () => {
    expect(permissionArgs({ nodeVersion: 'v22.23.4', readPaths: ['/project with space/', '/install/keysentry.mjs'], writePaths: ['/state with space/'], allowChildProcess: true }))
      .toEqual(['--permission', '--allow-fs-read=/project with space/*', '--allow-fs-read=/install/keysentry.mjs', '--allow-fs-write=/state with space/*', '--allow-child-process']);
  });

  test('preserves Windows drive letters and backslashes', () => {
    expect(permissionArgs({ nodeVersion: '24.22.1', readPaths: ['C:\\Users\\Human Name\\', 'E:\\keysentry\\dist\\keysentry.mjs'], writePaths: ['E:\\keysentry\\.keysentry\\'], allowChildProcess: false }))
      .toEqual(['--permission', '--allow-fs-read=C:\\Users\\Human Name\\*', '--allow-fs-read=E:\\keysentry\\dist\\keysentry.mjs', '--allow-fs-write=E:\\keysentry\\.keysentry\\*']);
  });

  test.each(['20.18.0', '22.12.0', '22.23.3', '24.22.0', '26.12.0', '23.99.99', '25.99.99', '28.0.0', '99.0.0', 'garbage', '22.23', '22.23.4-rc.1'])('does not enable permissions on unsupported or unpatched Node %s', nodeVersion => {
    expect(permissionArgs({ ...paths, nodeVersion })).toBeNull();
  });

  test.each(['22.23.4', 'v22.24.0', '24.22.1', 'v24.23.0', '26.12.1', 'v26.13.0'])('enables permissions on patched supported Node %s', nodeVersion => {
    expect(permissionArgs({ ...paths, nodeVersion })?.[0]).toBe('--permission');
  });

  test('reports the minimum and exact reason for an outdated line', () => {
    expect(sandboxSupport('v24.14.1')).toEqual({ supported: false, minimum: '24.22.1', reason: 'Node v24.14.1 is older than 24.22.1 for its line' });
    expect(sandboxSupport('26.12.1')).toEqual({ supported: true, minimum: '26.12.1' });
    expect(sandboxSupport('99.0.0')).toEqual({ supported: false, reason: 'Node 99.0.0 line is not supported for the sandbox' });
  });
});

describe('permission re-exec', () => {
  test.each([
    [{ KEYSENTRY_SANDBOXED: '1' }, 'already sandboxed'],
    [{ KEYSENTRY_NO_SANDBOX: '1' }, 'opted out with KEYSENTRY_NO_SANDBOX=1'],
  ])('is a no-op with env %j', async (env, reason) => {
    const spawnImpl: SpawnLike = () => { throw new Error('must not spawn'); };
    expect(await maybeReexecWithPermissions({ ...options(), env, spawnImpl })).toEqual({ reexeced: false, reason });
  });

  test('is a no-op when process.permission is active', async () => {
    Object.defineProperty(process, 'permission', { value: { has: () => true }, configurable: true });
    expect(await maybeReexecWithPermissions(options())).toEqual({ reexeced: false, reason: 'already sandboxed' });
  });

  test.each([
    ['22.23.3', 'Node 22.23.3 is older than 22.23.4 for its line'],
    ['24.22.0', 'Node 24.22.0 is older than 24.22.1 for its line'],
    ['26.12.0', 'Node 26.12.0 is older than 26.12.1 for its line'],
    ['25.99.0', 'Node 25.99.0 line is not supported for the sandbox'],
  ])('explains unsupported Node %s without spawning', async (nodeVersion, reason) => {
    expect(await maybeReexecWithPermissions({ ...options(), nodeVersion })).toEqual({ reexeced: false, reason });
  });

  test.each(['/project/src/cli/index.ts', '/project/dist/cli/index.js', ''])('does not re-exec sources at %s', async entry => {
    expect(await maybeReexecWithPermissions({ ...options(), argv: ['/node', entry] }))
      .toEqual({ reexeced: false, reason: 'running from TypeScript sources' });
  });

  test('re-execs the bundle with sanitized inherited permission flags and preserves other execArgv', async () => {
    Object.defineProperty(process, 'execArgv', { value: ['--permission', '--allow-fs-read=*', '--allow-fs-write', '/old/*', '--allow-child-process', '--allow-worker', '--allow-addons', '--allow-wasi', '--allow-net=*', '--experimental-permission', '--no-warnings', '--stack-trace-limit=20'], configurable: true });
    const env = { PATH: '/bin', USERPROFILE: 'C:\\Users\\Human', KEYSENTRY_SANDBOXED: '0' };
    const observed: unknown[][] = [];
    const spawnImpl: SpawnLike = (command, args, spawnOptions) => {
      observed.push([command, args, spawnOptions]);
      const child = new EventEmitter();
      queueMicrotask(() => child.emit('close', 7, null));
      return child;
    };
    expect(await maybeReexecWithPermissions({ ...options(), env, spawnImpl })).toEqual({ reexeced: true, exitCode: 7 });
    expect(observed).toEqual([['/node', ['--permission', '--allow-fs-read=/project/*', '--allow-fs-read=/install/keysentry.mjs', '--allow-fs-write=/project/.keysentry/*', '--no-warnings', '--stack-trace-limit=20', '/install/keysentry.mjs', 'doctor'], { env: { ...env, KEYSENTRY_SANDBOXED: '1' }, stdio: 'inherit', shell: false }]]);
    expect(env.KEYSENTRY_SANDBOXED).toBe('0');
  });

  test.each([
    '--permission --allow-fs-read=* --allow-fs-write="/old path/*" --allow-child-process --no-warnings',
    '--experimental-permission --allow-fs-read "/old path/*" --allow-fs-write /old/* --allow-worker --stack-trace-limit=20',
    '--allow-future-permission=* --no-allow-child-process --no-permission --no-warnings',
  ])('strips permission grants from NODE_OPTIONS: %s', async NODE_OPTIONS => {
    let observed: NodeJS.ProcessEnv | undefined;
    const env = { NODE_OPTIONS };
    const spawnImpl: SpawnLike = (_command, _args, childOptions) => {
      observed = childOptions.env;
      const child = new EventEmitter();
      queueMicrotask(() => child.emit('exit', 0, null));
      return child;
    };
    expect(await maybeReexecWithPermissions({ ...options(), env, spawnImpl })).toEqual({ reexeced: true, exitCode: 0 });
    expect(observed?.NODE_OPTIONS).not.toMatch(/--(?:no-)?(?:allow-|(?:experimental-)?permission)/);
    expect(observed?.NODE_OPTIONS).toMatch(/--no-warnings|--stack-trace-limit=20/);
    expect(env.NODE_OPTIONS).toBe(NODE_OPTIONS);
  });

  test('uses the actual bundle path for an npm bin link and grants read access to it', async () => {
    let observed: readonly string[] = [];
    const spawnImpl: SpawnLike = (_command, args) => {
      observed = args;
      const child = new EventEmitter();
      queueMicrotask(() => child.emit('exit', 0, null));
      return child;
    };
    await maybeReexecWithPermissions({ ...options(), readPaths: ['/project/'], argv: ['/node', '/prefix/bin/keysentry', '--help'], bundlePath: '/prefix/lib/keysentry/keysentry.mjs', spawnImpl });
    expect(observed).toContain('--allow-fs-read=/prefix/lib/keysentry/keysentry.mjs');
    expect(observed.slice(-2)).toEqual(['/prefix/lib/keysentry/keysentry.mjs', '--help']);
  });

  test('maps a child signal to exit code 1', async () => {
    const spawnImpl: SpawnLike = () => {
      const child = new EventEmitter();
      queueMicrotask(() => child.emit('close', null, 'SIGTERM'));
      return child;
    };
    expect(await maybeReexecWithPermissions({ ...options(), spawnImpl })).toEqual({ reexeced: true, exitCode: 1 });
  });

  test('returns the child exit code when the inherited-stdio child exits', async () => {
    const spawnImpl: SpawnLike = () => {
      const child = new EventEmitter();
      queueMicrotask(() => child.emit('exit', 3, null));
      return child;
    };
    expect(await maybeReexecWithPermissions({ ...options(), spawnImpl })).toEqual({ reexeced: true, exitCode: 3 });
  });

  test('does not expose a child startup error', async () => {
    const spawnImpl: SpawnLike = () => {
      const child = new EventEmitter();
      queueMicrotask(() => child.emit('error', new Error('unique-secret-from-environment')));
      return child;
    };
    expect(await maybeReexecWithPermissions({ ...options(), spawnImpl })).toEqual({ reexeced: true, exitCode: 1 });
  });
});
