import { execFile, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { request } from 'node:http';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { afterEach, expect, test } from 'vitest';
import { createStateCipher, createStateStore } from '../../src/core/store.js';
import { createAuditLog, generateDeviceKey } from '../../src/security/index.js';
import { sandboxSupport } from '../../src/safety/index.js';
import { deviceKey } from '../../src/vault/index.js';
import { environmentVariableForName } from '../../src/vault/backends/env.js';
import { createFakeVault } from '../helpers/fake-vault.js';

// This is deliberately separate from the fake-only source tests. Run on a patched
// Node release outside the Codex sandbox: KEYSENTRY_TEST_BUNDLE=1 ...
// npm pack is offline; git is used only in the temporary smoke-test repository.
const enabled = process.env.KEYSENTRY_TEST_BUNDLE === '1' && sandboxSupport(process.versions.node).supported;
const exec = promisify(execFile);
const dirs: string[] = [];
afterEach(async () => { for (const path of dirs.splice(0)) await rm(path, { recursive: true, force: true }); });
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const active = 'keysentry-smoke-permission-model-active';

async function npmCli(): Promise<string> {
  for (const path of [process.env.npm_execpath,
    join(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js'),
    resolve(dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js'),
    resolve(dirname(process.execPath), '../share/nodejs/npm/bin/npm-cli.js')]) {
    if (!path?.endsWith('npm-cli.js')) continue;
    try { await access(path); return path; } catch { /* Try the next installed npm location. */ }
  }
  throw new Error('The bundle smoke test needs an installed npm CLI.');
}

async function packedBundle(root: string): Promise<string> {
  const source = join(root, 'source'); await mkdir(source);
  const bundle = join(source, 'keysentry.mjs');
  const { buildBundle } = await import(pathToFileURL(join(repoRoot, 'scripts/build-bundle.mjs')).href);
  await buildBundle({ outFile: bundle });
  await writeFile(join(source, 'package.json'), JSON.stringify({ name: 'keysentry-bundle-smoke', version: '0.0.0',
    type: 'module', bin: { keysentry: 'keysentry.mjs' }, files: ['keysentry.mjs'] }));
  await exec(process.execPath, [await npmCli(), 'pack', '--offline', '--ignore-scripts', '--pack-destination', root],
    { cwd: source, timeout: 30_000 });
  const tarball = (await readdir(root)).find(name => name.endsWith('.tgz'));
  if (!tarball) throw new Error('The bundle smoke package was not created.');
  const unpacked = join(root, 'unpacked'); await mkdir(unpacked);
  await exec('tar', ['-xzf', join(root, tarball), '-C', unpacked], { timeout: 10_000 });
  return join(unpacked, 'package', 'keysentry.mjs');
}

async function localGet(port: number, path: string, cookie?: string): Promise<{ status: number; body: string; cookie?: string }> {
  return new Promise((resolveReply, reject) => {
    const req = request({ hostname: '127.0.0.1', port, path, headers: { Host: `localhost:${port}`,
      ...(cookie ? { Cookie: cookie } : {}) } }, res => {
      let body = ''; res.setEncoding('utf8'); res.on('data', chunk => { body += chunk; });
      res.on('end', () => resolveReply({ status: res.statusCode!, body, cookie: res.headers['set-cookie']?.[0]?.split(';')[0] }));
    });
    req.setTimeout(5_000, () => req.destroy(new Error('The smoke dashboard did not respond.')));
    req.once('error', reject); req.end();
  });
}

test.skipIf(!enabled)('the packed executable grants phase 3 commands their required permissions', async () => {
  const root = await mkdtemp(join(tmpdir(), 'keysentry-bundle-permissions-')); dirs.push(root);
  const bundle = await packedBundle(root);
  const cwd = join(root, 'project'), home = join(root, 'home'); await mkdir(cwd); await mkdir(home);
  const userDir = join(home, '.keysentry'); const stateKey = Buffer.alloc(32, 17);
  const key = generateDeviceKey();
  const auditMac = Buffer.alloc(32, 65);
  const fixtureVault = createFakeVault({ 'audit/mac': auditMac, 'key/device-ed25519': key.privateKeyDer });
  const env: NodeJS.ProcessEnv = { HOME: home, USERPROFILE: home, KEYSENTRY_USER_DIR: userDir,
    KEYSENTRY_VAULT: 'env', KEYSENTRY_STATE_KEY: stateKey.toString('base64'),
    KEYSENTRY_FINGERPRINT_KEY: Buffer.alloc(32, 19).toString('base64'),
    KEYSENTRY_DEVICE_KEY: key.privateKeyDer.toString('base64'),
    [environmentVariableForName('audit/mac')]: auditMac.toString('utf8'),
    KEYSENTRY_TEST_STOP_FILE: join(cwd, 'stop-ui') };
  key.privateKeyDer.fill(0);
  for (const name of ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP']) {
    if (process.env[name] !== undefined) env[name] = process.env[name];
  }
  // Test TTY flags permit human-gated commands without a PTY dependency. This
  // preload survives the bundle's real permission re-exec, where it reports the
  // active permission model. It also prevents opening a desktop browser.
  const preload = join(cwd, 'smoke-tty.cjs');
  await writeFile(preload, `
const cp = require('node:child_process');
const original = cp.execFile;
cp.execFile = function(file, args, options, callback) {
  if (/(?:xdg-open|open|rundll32\\.exe)$/.test(file)) { queueMicrotask(() => callback(null, '', '')); return; }
  return original.apply(this, arguments);
};
require('node:module').syncBuiltinESMExports();
Object.defineProperty(process.stdin, 'isTTY', { value: true });
Object.defineProperty(process.stdout, 'isTTY', { value: true });
if (process.permission) {
  process.stderr.write('${active}\\n');
  if (process.argv.includes('ui')) {
    const timer = setInterval(() => { if (require('node:fs').existsSync(process.env.KEYSENTRY_TEST_STOP_FILE)) process.exit(0); }, 25);
    setTimeout(() => { clearInterval(timer); process.exit(2); }, 15000).unref();
  }
}
`);
  await writeFile(join(cwd, 'keysentry.yaml'), 'hosts:\n  dotenv:\n    enabled: false\n');
  await exec('git', ['init', '--quiet'], { cwd, env, timeout: 5_000 });
  const projectId = '0123456789abcdef'; const stateDir = join(cwd, '.keysentry'); await mkdir(stateDir);
  await writeFile(join(stateDir, 'project.json'), JSON.stringify({ id: projectId }));
  const store = createStateStore({ cwd, cipher: createStateCipher(stateKey), vault: createFakeVault(), projectId });
  stateKey.fill(0);
  await store.saveInventory({ version: 1, scannedAt: '2026-10-27T12:00:00.000Z', hosts: [], services: [], findings: [], clusters: [], errors: [] });
  await store.journal().append({ at: '2026-10-27T12:00:00.000Z', planId: 'bundle-plan', event: 'plan-start', data: { dryRun: true } });
  await store.journal().append({ at: '2026-10-27T12:00:01.000Z', planId: 'bundle-plan', event: 'plan-end', data: { dryRun: true, status: 'dry-run' } });
  // Supply a stable test MAC and the public audit head across subprocesses. The
  // ordinary env backend deliberately keeps new heads process-local, so an
  // unseeded fixture could make timeline fail before reaching its output write.
  const audit = createAuditLog({ path: store.paths.audit, vault: fixtureVault, deviceKey: () => deviceKey(fixtureVault) });
  await audit.append({ kind: 'bundle-smoke', summary: 'Bundle smoke fixture prepared.', data: { planId: 'bundle-plan' } });
  await audit.checkpoint();
  const auditHeadVariable = environmentVariableForName(`audit/head/${createHash('sha256').update(resolve(store.paths.audit)).digest('hex').slice(0, 16)}`);
  const retainAuditHead = async () => {
    const line = (await readFile(store.paths.audit, 'utf8')).trimEnd().split('\n').at(-1)!;
    const head = JSON.parse(line) as { seq: number; hash: string };
    env[auditHeadVariable] = JSON.stringify({ seq: head.seq, hash: head.hash });
  };
  await retainAuditHead();

  const args = (...command: string[]) => ['--require', preload, bundle, '--cwd', cwd, ...command];
  const run = async (...command: string[]) => {
    const result = await exec(process.execPath, args(...command), { cwd, env, timeout: 20_000, maxBuffer: 1024 * 1024 });
    expect(result.stderr).toContain(active);
    expect(result.stderr).not.toContain('ERR_ACCESS_DENIED');
    await retainAuditHead();
    return result.stdout;
  };
  await run('--no-save', '--json');
  await run('guard', '--staged');
  await run('guard', '--history');
  for (const hooks of [join(cwd, '.git', 'hooks'), join(root, 'custom-hooks')]) {
    if (hooks.endsWith('custom-hooks')) await exec('git', ['config', 'core.hooksPath', hooks], { cwd, env, timeout: 5_000 });
    await run('guard', 'install-hook');
    expect(await readFile(join(hooks, 'pre-commit'), 'utf8')).toContain('keysentry guard --staged');
    await run('guard', 'uninstall-hook');
    await expect(access(join(hooks, 'pre-commit'))).rejects.toMatchObject({ code: 'ENOENT' });
  }
  const card = join(root, 'readiness.svg'), timeline = join(root, 'timeline.md');
  await run('card', '--out', card); expect(await readFile(card, 'utf8')).toContain('<svg');
  await run('timeline', 'bundle-plan', '--out', timeline); expect(await readFile(timeline, 'utf8')).toContain('# Incident timeline');

  const child = spawn(process.execPath, args('--json', 'ui', '--read-only'), { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  const ended = new Promise<number | null>((resolveExit, reject) => { child.once('error', reject); child.once('close', resolveExit); });
  child.stdout.on('data', chunk => { stdout += chunk.toString(); }); child.stderr.on('data', chunk => { stderr += chunk.toString(); });
  try {
    const dashboard = await new Promise<{ path: string; port: number }>((resolveOutput, reject) => {
      const deadline = setTimeout(() => { clearInterval(poll); reject(new Error('The packed dashboard did not start.')); }, 10_000);
      const poll = setInterval(() => {
        try {
          const value = JSON.parse(stdout);
          if (typeof value.path === 'string' && Number.isInteger(value.port)) { clearInterval(poll); clearTimeout(deadline); resolveOutput(value); }
        } catch { /* Wait for the complete JSON response. */ }
      }, 20);
    });
    expect(stderr).toContain(active);
    const launcher = await readFile(dashboard.path, 'utf8');
    const link = /http:\/\/localhost:\d+\/\?t=[A-Za-z0-9_-]{43}/.exec(launcher)?.[0];
    expect(Boolean(link)).toBe(true);
    const exchanged = await localGet(dashboard.port, `/${new URL(link!).search}`);
    expect(exchanged.status).toBe(303);
    const overview = await localGet(dashboard.port, '/api/overview', exchanged.cookie);
    expect(overview.status).toBe(200);
    expect(JSON.parse(overview.body).firstRun).toHaveProperty('historyComplete');
  } finally {
    await writeFile(env.KEYSENTRY_TEST_STOP_FILE!, 'stop');
    expect(await ended).toBe(0);
  }
}, 120_000);
