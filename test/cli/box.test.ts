import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import * as localBoxModule from '../../packages/control-plane/src/local-box.js';
import type { LocalBox } from '../../packages/control-plane/src/local-box.js';
import { ALLOWLIST_GENESIS_HASH, createAllowListEntry, createAllowListHead } from '../../src/box/index.js';
import { BOX_HONEST_CLAIM } from '../../src/cli/box-flow.js';
import type { LocalBoxRunner } from '../../src/cli/box.js';
import { runCli, type CliOptions } from '../../src/cli/index.js';
import { createRuntime } from '../../src/cli/runtime.js';
import { generateDeviceKey } from '../../src/security/index.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });

async function fixture() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-box-cli-')); dirs.push(cwd);
  const vault = createFakeVault();
  const runtime = await createRuntime({ cwd, userDir: join(cwd, 'user'), vault, hosts: [], env: {}, http: new FakeHttp(), log: silentLogger, stdinIsTTY: true, stdoutIsTTY: true });
  const output: string[] = [], errors: string[] = [];
  const watchers: Record<string, string>[] = [];
  let local: LocalBox | undefined;
  const runner: LocalBoxRunner = { startLocalBox: async options => (local = await localBoxModule.startLocalBox(options as never)) as never };
  const options = (extra: Partial<CliOptions> = {}): CliOptions => ({ runtime, stdinIsTTY: true, stdoutIsTTY: true, env: {},
    output: line => output.push(line), error: line => errors.push(line),
    box: { loadLocalBox: async () => runner, sessionTimeoutMs: 8_000, pollMs: 20,
      startWatcher: async (env, signal) => { watchers.push(env); await new Promise(resolve => signal.addEventListener('abort', resolve)); } },
    ...extra });
  expect(await runCli(['init'], options())).toBe(0);
  expect(await runCli(['scan'], options())).toBe(0);
  output.length = 0;
  return { cwd, vault, runtime, output, errors, watchers, options, local: () => local! };
}

/** Runs `box provision --emulator` and, while it is up, the given steps; then stops it the way Ctrl+C would. */
async function withEmulator(f: Awaited<ReturnType<typeof fixture>>, args: string[], steps: (restart: () => Promise<void>) => Promise<void>): Promise<number> {
  let failure: unknown;
  const code = await runCli(['box', 'provision', '--emulator', ...args], f.options({ box: { ...f.options().box,
    emulatorControl: async restart => { try { await steps(restart); } catch (error) { failure = error; } } } }));
  if (failure) throw failure;
  return code;
}

describe('keysentry box', () => {
  it('says the hosted box is not launched and creates nothing without --emulator', async () => {
    const f = await fixture();
    expect(await runCli(['box', 'provision'], f.options())).toBe(1);
    expect(f.errors.join('\n')).toContain('The hosted cloud box is not launched yet, so nothing was created.');
    expect(await f.runtime.store.readJson('plan', join(f.runtime.paths.dir, 'boxes.json'))).toBeNull();
  });

  it('lists its commands in help but not the agent entry point', async () => {
    const f = await fixture();
    await runCli(['box', '--help'], f.options());
    const help = f.output.join('\n');
    for (const name of ['provision', 'check', 'send-tokens', 'unlock', 'allowlist']) expect(help).toContain(name);
    expect(help).not.toContain('agent');
  });

  it('checks, sends tokens, pauses after a restart and unlocks, all against the local emulator', async () => {
    const f = await fixture();
    const code = await withEmulator(f, ['--mode', 'unlock-on-restart', '--name', 'demo-box'], async restart => {
      expect(f.output.join('\n')).toContain('Local emulated box demo-box is running (unlock-on-restart)');
      f.output.length = 0;
      expect(await runCli(['box', 'check', 'demo-box'], f.options())).toBe(0);
      const check = f.output.join('\n');
      expect(check).toContain('Box demo-box: every check passed');
      for (const name of ['box-signature', 'signature', 'nonce-box-key', 'nonce-challenge', 'debug', 'image-digest', 'project', 'service-account']) {
        expect(check).toMatch(new RegExp(`pass {2}${name} `));
      }
      expect(check).toContain('Local emulator: these checks use the emulator\'s test signing keys and test digests');
      expect(check).toContain(BOX_HONEST_CLAIM);

      f.output.length = 0;
      expect(await runCli(['box', 'send-tokens', 'demo-box'], f.options())).toBe(0);
      expect(f.output.join('\n')).toContain('Box demo-box verified every check and confirmed it sealed the tokens (unlock-on-restart).');
      expect(await f.vault.get('box/demo-box/share-b')).toHaveLength(32);
      expect(Object.keys(f.watchers[0]!).sort()).toEqual(['KEYSENTRY_STATE_DIR', 'KEYSENTRY_STATE_KEY', 'KEYSENTRY_VAULT_PASSPHRASE',
        'KEYSENTRY_WATCHER_CONFIG', 'KEYSENTRY_WATCHER_KEY', 'KEYSENTRY_WATCHER_VAULT']);

      await restart();
      f.output.length = 0;
      expect(await runCli(['box', 'unlock', 'demo-box'], f.options())).toBe(0);
      expect(f.output.join('\n')).toContain('received the device share');
      expect(f.watchers).toHaveLength(2);
    });
    expect(code).toBe(0);
    // Stopping the emulator removes its record and relay credential.
    expect(await f.runtime.store.readJson('plan', join(f.runtime.paths.dir, 'boxes.json'))).toEqual({ v: 1, boxes: [] });
    expect(await f.vault.get('box/demo-box/relay-token')).toBeNull();
  }, 60_000);

  it('the deployment the box receives boots the real deployed watcher', async () => {
    const f = await fixture();
    let watchExit: number | undefined;
    await withEmulator(f, [], async () => {
      expect(await runCli(['box', 'send-tokens', 'local-box'], f.options())).toBe(0);
      const env = f.watchers[0]!;
      const errors: string[] = [];
      watchExit = await runCli(['watch', '--once'], { env, cwd: join(f.cwd, 'watch-check'), http: new FakeHttp(), stdinIsTTY: false, stdoutIsTTY: false,
        output: () => {}, error: line => errors.push(line) });
      expect(watchExit).toBe(2); // alert-only: nothing is armed in this project
      expect(errors.join('\n')).not.toMatch(/KEYSENTRY_[A-Z_]+ (?:must|is not)|Set KEYSENTRY_/);
      // The bootstrap opened the sealed config and the portable vault, and bound this project's identity.
      const bound = JSON.parse(await readFile(join(env.KEYSENTRY_STATE_DIR!, '.keysentry', 'project.json'), 'utf8')) as { id: string };
      expect(bound.id).toBe(f.runtime.projectId);
    });
  }, 60_000);

  it('refuses to send tokens to a box that fails a check and names it', async () => {
    const f = await fixture();
    await withEmulator(f, [], async () => {
      f.local().emulator.setSwitches({ debugImage: true });
      f.output.length = 0; f.errors.length = 0;
      expect(await runCli(['box', 'send-tokens', 'local-box'], f.options())).toBe(1);
      expect(f.errors.join('\n')).toContain('Nothing was sent. The box failed these checks:');
      expect(f.errors.join('\n')).toMatch(/FAIL {2}debug /);
      expect(f.watchers).toHaveLength(0);
      expect(await runCli(['box', 'check', 'local-box'], f.options())).toBe(1);
    });
  }, 60_000);

  it('refuses mutating box commands from an AI agent or without a terminal', async () => {
    const f = await fixture();
    for (const args of [['box', 'send-tokens', 'local-box'], ['box', 'unlock', 'local-box'], ['box', 'provision', '--emulator']]) {
      f.errors.length = 0;
      expect(await runCli(args, f.options({ env: { CLAUDE_CODE_CHILD_SESSION: '1' } }))).not.toBe(0);
      expect(f.errors.join('\n')).toContain('AI coding agent');
      expect(await runCli(args, f.options({ stdinIsTTY: false }))).not.toBe(0);
    }
  });

  it('explains a box that does not exist', async () => {
    const f = await fixture();
    expect(await runCli(['box', 'check', 'missing-box'], f.options())).toBe(1);
    expect(f.errors.join('\n')).toContain('There is no box named missing-box in this project.');
  });

  it('verifies the allow-list against pinned keys and keeps a checkpoint', async () => {
    const f = await fixture();
    expect(await runCli(['box', 'allowlist', 'verify'], f.options())).toBe(1);
    expect(f.errors.join('\n')).toContain('no pinned release signing key yet');
    const key = generateDeviceKey();
    const entry = createAllowListEntry({ seq: 1, digest: `sha256:${'c'.repeat(64)}`, reference: 'box@1.0.0', addedAt: '2026-10-28T00:00:00.000Z',
      reason: 'release 1.0.0', prev: ALLOWLIST_GENESIS_HASH }, key.privateKeyDer);
    const head = createAllowListHead({ seq: 1, hash: entry.hash, at: '2026-10-28T00:00:00.000Z' }, key.privateKeyDer);
    await mkdir(join(f.cwd, 'allowlist'));
    await writeFile(join(f.cwd, 'allowlist', 'log.jsonl'), `${JSON.stringify(entry)}\n`);
    await writeFile(join(f.cwd, 'allowlist', 'head.json'), JSON.stringify(head));
    const keyed = f.options({ box: { allowListKeys: [{ keyId: head.keyId, publicKeyDer: key.publicKeyDer }] } });
    f.output.length = 0; f.errors.length = 0;
    const verifiedCode = await runCli(['box', 'allowlist', 'verify'], keyed);
    expect(verifiedCode).toBe(0);
    expect(f.output.join('\n')).toContain(`sha256:${'c'.repeat(64)}`);
    expect(await f.runtime.store.readJson('plan', join(f.runtime.paths.dir, 'box-allowlist-head.json'))).toEqual({ seq: 1, hash: entry.hash });
    await writeFile(join(f.cwd, 'allowlist', 'log.jsonl'), `${JSON.stringify({ ...entry, reason: 'edited quietly' })}\n`);
    f.output.length = 0;
    expect(await runCli(['box', 'allowlist', 'verify'], keyed)).toBe(1);
    expect(f.output.join('\n')).toContain('The allow-list did not verify.');
  });
});
