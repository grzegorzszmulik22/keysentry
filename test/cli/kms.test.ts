import { randomBytes } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Command } from 'commander';
import { afterEach, describe, expect, it } from 'vitest';
import { configSchema } from '../../src/cli/config.js';
import { registerKmsCommands, type KmsCommandsOptions } from '../../src/cli/kms.js';
import { createRuntime, type KeysentryRuntime } from '../../src/cli/runtime.js';
import { bootstrapWatcher, prepareWatcherDeployment } from '../../src/cli/watcher-bootstrap.js';
import { createVaultTransitWrapper, KmsError, wrapWatcherStateKey } from '../../src/kms/index.js';
import { assertHumanForMutation } from '../../src/safety/index.js';
import { generateDeviceKey } from '../../src/security/index.js';
import type { AuditEvent, AuditLog } from '../../src/types.js';
import { createEncryptedFileVault } from '../../src/vault/index.js';
import { sealWatcherConfig, type WatcherConfig } from '../../src/watcher/index.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { credentialSource, failure, fakeVaultTransit, now, secretFree, VAULT_ADDR } from '../kms/fakes.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
const TOKEN = 'hvs.vault-token-planted';
const KMS_YAML = `kms:\n  provider: vault-transit\n  address: ${VAULT_ADDR}\n  keyName: state\n`;

async function fixture() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-kms-cli-')); dirs.push(cwd);
  const vault = createFakeVault();
  const fake = fakeVaultTransit();
  const events: AuditEvent[] = [];
  const audit: AuditLog = { append: async event => { events.push(event); }, checkpoint: async () => {}, verify: async () => ({ ok: true } as never) };
  const runtime = (env: NodeJS.ProcessEnv = { VAULT_TOKEN: TOKEN }, http = fake.http) => createRuntime({ cwd, userDir: join(cwd, 'user'), vault, audit,
    hosts: [], env, http, log: silentLogger, stdinIsTTY: true, stdoutIsTTY: true, now });
  // A project that already has a plain state key and some encrypted state.
  const first = await runtime();
  await first.store.writeJson('plan', join(first.paths.dir, 'kms-probe.json'), { kept: 'encrypted state' });
  const plain = Buffer.from((await vault.get(`project/${first.projectId}/key/state`))!);
  await writeFile(join(cwd, 'keysentry.yaml'), KMS_YAML);
  return { cwd, vault, fake, events, runtime, projectId: first.projectId, plain };
}

async function run(rt: KeysentryRuntime, args: string[], extra: Partial<KmsCommandsOptions> & { env?: NodeJS.ProcessEnv; tty?: boolean } = {}) {
  const output: string[] = [], errors: string[] = [];
  let exitCode = 0;
  const program = new Command().exitOverride().option('--json');
  registerKmsCommands(program, {
    getRuntime: async () => rt,
    human: action => assertHumanForMutation({ env: extra.env ?? {}, action, stdinIsTTY: extra.tty ?? true, stdoutIsTTY: extra.tty ?? true }),
    emit: (value, text) => output.push(program.opts().json ? JSON.stringify(rt.safe(value)) : text ?? JSON.stringify(value)),
    diagnostic: text => errors.push(text), json: () => !!program.opts().json, setExit: code => { exitCode = code; },
    transport: extra.transport ?? undefined, now, confirm: async () => true, ...extra,
  });
  try { await program.parseAsync(args, { from: 'user' }); }
  catch (error) { return { output, errors, exitCode: 1, error: error as Error }; }
  return { output, errors, exitCode, error: undefined };
}

describe('keysentry kms', () => {
  it('reports, migrates and rotates, and the next start unwraps the same state key', async () => {
    const f = await fixture();
    const rt = await f.runtime();
    const before = await run(rt, ['kms', 'status'], { transport: f.fake.http });
    expect(before.exitCode).toBe(1);
    expect(before.output.join('\n')).toContain('KMS: Vault Transit, key https://vault.acme.example/v1/transit/keys/state');
    expect(before.output.join('\n')).toContain('State key: not wrapped');
    expect(before.output.join('\n')).toContain('Run "keysentry kms migrate"');

    const migrate = await run(rt, ['kms', 'migrate', '--yes'], { transport: f.fake.http });
    expect(migrate.error).toBeUndefined();
    expect(migrate.output.join('\n')).toContain('now wrapped with your KMS key');
    expect(await f.vault.get(`project/${f.projectId}/key/state`)).toBeNull();
    expect(await f.vault.get(`project/${f.projectId}/key/state.wrapped`)).not.toBeNull();
    expect(f.events.map(event => event.kind)).toContain('kms:migrate');

    const after = await run(rt, ['--json', 'kms', 'status'], { transport: f.fake.http });
    expect(after.exitCode).toBe(0);
    const status = JSON.parse(after.output[0]!);
    expect(status).toMatchObject({ plainCopy: false, wrapped: { matchesConfig: true, keyVersion: 'v1' }, check: { ok: true } });
    expect(after.output[0]).not.toContain(TOKEN);
    expect(after.output[0]).not.toContain(f.plain.toString('base64'));

    f.fake.state.versions.push(randomBytes(32));
    const rotate = await run(rt, ['kms', 'rotate'], { transport: f.fake.http });
    expect(rotate.output.join('\n')).toBe('Rewrapped under the current key version (v2).');
    expect(f.events.map(event => event.kind)).toContain('kms:rotate');

    const decryptsBefore = f.fake.http.callsTo('POST', /decrypt/).length;
    const restarted = await f.runtime();
    expect(f.fake.http.callsTo('POST', /decrypt/).length).toBe(decryptsBefore + 1);
    expect(await restarted.store.readJson('plan', join(restarted.paths.dir, 'kms-probe.json'))).toEqual({ kept: 'encrypted state' });
    expect(await f.vault.get(`project/${f.projectId}/key/state`)).toBeNull();
  });

  it('refuses migration for an AI agent, off a terminal, or without confirmation, and changes nothing', async () => {
    const f = await fixture();
    const rt = await f.runtime();
    const agent = await run(rt, ['kms', 'migrate', '--yes'], { transport: f.fake.http, env: { CLAUDE_CODE_CHILD_SESSION: '1' } });
    expect(agent.error?.message).toMatch(/AI coding agent/);
    const piped = await run(rt, ['kms', 'rotate'], { transport: f.fake.http, tty: false });
    expect(piped.error?.message).toMatch(/interactive terminal/);
    const declined = await run(rt, ['kms', 'migrate'], { transport: f.fake.http, confirm: async () => false });
    expect(declined.error?.message).toBe('Migration cancelled. Nothing was changed.');
    expect(declined.errors.join('\n')).toContain('saved state opens only while Vault Transit key');
    expect(f.fake.http.callsTo('POST', /encrypt/)).toHaveLength(0);
    expect((await f.vault.get(`project/${f.projectId}/key/state`))!.equals(f.plain)).toBe(true);
    expect(await f.vault.get(`project/${f.projectId}/key/state.wrapped`)).toBeNull();
  });

  it('crash before the plain copy is removed leaves both copies; the next migrate finishes', async () => {
    const f = await fixture();
    const rt = await f.runtime();
    const crashed = await run(rt, ['kms', 'migrate', '--yes'], { transport: f.fake.http,
      migrationCheckpoint: point => { if (point === 'wrapped-saved') throw new Error('simulated crash'); } });
    expect(crashed.error?.message).toBe('simulated crash');
    expect(await f.vault.get(`project/${f.projectId}/key/state`)).not.toBeNull();
    expect(await f.vault.get(`project/${f.projectId}/key/state.wrapped`)).not.toBeNull();
    const again = await run(await f.runtime(), ['kms', 'migrate', '--yes'], { transport: f.fake.http });
    expect(again.output.join('\n')).toContain('Finished an earlier migration');
    expect(await f.vault.get(`project/${f.projectId}/key/state`)).toBeNull();
  });

  it('refuses to start when the KMS cannot unwrap, without creating a key or echoing secrets', async () => {
    const f = await fixture();
    await run(await f.runtime(), ['kms', 'migrate', '--yes'], { transport: f.fake.http });
    const unreachable = new FakeHttp();
    const error = await failure(f.runtime({ VAULT_TOKEN: TOKEN }, unreachable));
    expect(error).toBeInstanceOf(KmsError);
    expect(error.message).toContain('Vault Transit');
    expect(error.message).toContain('did not create a new state key');
    f.fake.state.token = 'hvs.revoked';
    const revoked = await failure(f.runtime());
    expect(revoked.message).toContain('refused the request');
    expect(await f.vault.get(`project/${f.projectId}/key/state`)).toBeNull();
    for (const item of [error, revoked]) expect(secretFree(item, [TOKEN, f.plain.toString('base64'), f.plain.toString('hex')])).toBe(true);

    // Removing the kms section afterwards must not create a fresh key that would orphan the encrypted state.
    await writeFile(join(f.cwd, 'keysentry.yaml'), '{}\n');
    const unconfigured = await failure(f.runtime());
    expect(unconfigured.message).toContain('no kms section');
    expect(await f.vault.get(`project/${f.projectId}/key/state`)).toBeNull();
  });

  it('needs a kms section for migrate and rotate', async () => {
    const f = await fixture();
    await writeFile(join(f.cwd, 'keysentry.yaml'), '{}\n');
    const rt = await f.runtime();
    expect((await run(rt, ['kms', 'migrate', '--yes'])).error?.message).toBe('No KMS is configured. Add a kms section to keysentry.yaml first.');
    const status = await run(rt, ['kms', 'status']);
    expect(status.output.join('\n')).toContain('KMS: not configured');
    expect(status.exitCode).toBe(0);
  });
});

describe('watcher with KEYSENTRY_STATE_KEY_WRAPPED', () => {
  const fastVault: typeof createEncryptedFileVault = options => createEncryptedFileVault({ ...options, scrypt: { N: 1024, r: 8, p: 1 } });

  async function deployment(withKms = true) {
    const dir = await mkdtemp(join(tmpdir(), 'keysentry-kms-watcher-')); dirs.push(dir);
    const key = generateDeviceKey(), device = generateDeviceKey();
    const config: WatcherConfig = {
      v: 1, projectId: '1234567890abcdef', armed: null,
      trustedKeyIds: [device.keyId], devicePublicKeys: [{ keyId: device.keyId, publicKeyDer: device.publicKeyDer.toString('base64') }],
      passkeys: [], notify: { channels: [] }, sources: { disabled: [], extra: [] },
      approvals: { publicOrigin: null, relay: null }, intervalSeconds: 300,
    };
    const state = randomBytes(32), deploy = randomBytes(32);
    const sourceVault = createFakeVault({ [`project/${config.projectId}/key/fingerprint`]: randomBytes(32), 'key/device-ed25519': device.privateKeyDer });
    const settings = configSchema.parse(withKms ? { kms: { provider: 'vault-transit', address: VAULT_ADDR, keyName: 'state' } } : {});
    const prepared = await prepareWatcherDeployment({ sourceVault, settings, outputDir: join(dir, 'deploy'), openVault: fastVault }, {
      config, watcherKey: key, stateKey: state, vaultPassphrase: Buffer.from('planted-vault-passphrase') });
    const fake = fakeVaultTransit();
    const wrapper = createVaultTransitWrapper({ provider: 'vault-transit', address: VAULT_ADDR, mount: 'transit', keyName: 'state' },
      { http: fake.http, credentials: credentialSource({ VAULT_TOKEN: TOKEN }), now });
    const env: NodeJS.ProcessEnv = {
      KEYSENTRY_WATCHER_KEY: deploy.toString('base64'), KEYSENTRY_STATE_KEY_WRAPPED: await wrapWatcherStateKey({ wrapper, projectId: config.projectId, stateKey: state, now }),
      KEYSENTRY_VAULT_PASSPHRASE: 'planted-vault-passphrase', KEYSENTRY_WATCHER_CONFIG: sealWatcherConfig(config, deploy),
      KEYSENTRY_WATCHER_VAULT: prepared.vaultBlob, KEYSENTRY_STATE_DIR: join(dir, 'state'), VAULT_TOKEN: TOKEN,
    };
    return { config, state, env, fake, wrapper };
  }

  it('unwraps the state key at bootstrap and hands the runtime the key, not the kms settings', async () => {
    const d = await deployment();
    const opened = await bootstrapWatcher(d.env, { platform: process.platform, openVault: fastVault, http: d.fake.http, now });
    try {
      expect(await opened.options.vault!.get(`project/${d.config.projectId}/key/state`)).toEqual(d.state);
      expect(opened.options.settings?.kms).toBeUndefined();
      expect(d.fake.http.callsTo('POST', /decrypt/).length).toBeGreaterThan(0);
    } finally { opened.dispose(); }
  });

  it('refuses both variables, a deployment without kms settings, an unreachable KMS and another project\'s key', async () => {
    const d = await deployment();
    await expect(bootstrapWatcher({ ...d.env, KEYSENTRY_STATE_KEY: d.state.toString('base64') }, { platform: process.platform, openVault: fastVault, http: d.fake.http }))
      .rejects.toThrow('Set KEYSENTRY_STATE_KEY or KEYSENTRY_STATE_KEY_WRAPPED, not both.');
    const down = await failure(bootstrapWatcher(d.env, { platform: process.platform, openVault: fastVault, http: new FakeHttp(), now }));
    expect(down.message).toContain('did not create a new state key');
    expect(secretFree(down, [TOKEN, d.state.toString('base64')])).toBe(true);
    const other = await wrapWatcherStateKey({ wrapper: d.wrapper, projectId: 'abcdef1234567890', stateKey: d.state, now });
    const foreign = await failure(bootstrapWatcher({ ...d.env, KEYSENTRY_STATE_KEY_WRAPPED: other }, { platform: process.platform, openVault: fastVault, http: d.fake.http, now }));
    expect(foreign.message).toContain('could not unwrap the state key');

    const plain = await deployment(false);
    const missing = await failure(bootstrapWatcher(plain.env, { platform: process.platform, openVault: fastVault, http: plain.fake.http, now }));
    expect(missing.message).toContain('needs the kms settings from watcher setup');
  });
});
