import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, test } from 'vitest';
import { setupWatcher, watcherStatus } from '../../src/cli/watcher-setup.js';
import { openWatcherConfig, type WatcherConfig } from '../../src/watcher/index.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { FakeHttp, json } from '../helpers/fake-http.js';

const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map(dir => rm(dir, { recursive: true, force: true }))); });
const config = (): WatcherConfig => ({ v: 1, projectId: '0123456789abcdef', armed: null, trustedKeyIds: [],
  devicePublicKeys: [], passkeys: [], notify: { channels: [] }, sources: { disabled: [], extra: [] },
  approvals: { publicOrigin: null, relay: null }, intervalSeconds: 300 });
async function fixture() {
  const outputDir = await mkdtemp(join(tmpdir(), 'keysentry-setup-')); dirs.push(outputDir);
  const output: string[] = [], vault = createFakeVault(), events: unknown[] = [];
  const prepared: { stateKey: Buffer; vaultPassphrase: Buffer; watcherKeyId: string }[] = [];
  let checked = 0;
  return { output, vault, prepared, get checked() { return checked; }, deps: {
    outputDir, config: config(), vault, interactive: true, json: false,
    assertHuman() { checked++; }, writeTerminal(text: string) { output.push(text); },
    audit: { async append(event: unknown) { events.push(event); }, async checkpoint() {}, async verify() { return { ok: true, entries: events.length, checkpoints: 0 }; } },
    async prepareDeployment(input: { stateKey: Buffer; vaultPassphrase: Buffer; watcherKey: { keyId: string } }) {
      prepared.push({ stateKey: Buffer.from(input.stateKey), vaultPassphrase: Buffer.from(input.vaultPassphrase), watcherKeyId: input.watcherKey.keyId });
    },
  } };
}

test('watcher setup refuses JSON and noninteractive output before generating or exporting secrets', async () => {
  const f = await fixture();
  await expect(setupWatcher({ ...f.deps, json: true }, {})).rejects.toThrow(/interactive|JSON/i);
  await expect(setupWatcher({ ...f.deps, interactive: false }, {})).rejects.toThrow(/interactive/i);
  expect(f.prepared).toHaveLength(0); expect(f.output).toHaveLength(0); expect(await f.vault.list()).toEqual([]);
});

test('watcher setup refuses remote and relay forms', async () => {
  const f = await fixture();
  await expect(setupWatcher(f.deps, { remote: true })).rejects.toThrow(/local/i);
  await expect(setupWatcher(f.deps, { relay: true })).rejects.toThrow(/local/i);
  expect(f.output).toHaveLength(0); expect(f.prepared).toHaveLength(0);
});

test('watcher setup prints deploy variables once, seals config, and returns only metadata', async () => {
  const f = await fixture();
  const result = await setupWatcher(f.deps, { platform: 'fly' });
  expect(f.checked).toBe(1); expect(f.prepared).toHaveLength(1);
  const text = f.output.join('\n');
  for (const name of ['KEYSENTRY_WATCHER_KEY', 'KEYSENTRY_STATE_KEY', 'KEYSENTRY_VAULT_PASSPHRASE', 'KEYSENTRY_WATCHER_CONFIG']) {
    expect(text.match(new RegExp(`^${name}=`, 'gm'))).toHaveLength(1);
  }
  expect(text).toContain('secret settings'); expect(text).toContain('App deploy token');
  const deployKey = text.match(/^KEYSENTRY_WATCHER_KEY=(.+)$/m)![1]!;
  const sealed = await readFile(result.sealedConfigPath, 'utf8');
  expect(openWatcherConfig(sealed.trim(), Buffer.from(deployKey, 'base64')).projectId).toBe('0123456789abcdef');
  expect(JSON.stringify(result)).not.toContain(deployKey);
  expect(JSON.stringify(result)).not.toContain(f.prepared[0]!.vaultPassphrase.toString());
  expect(result.template).toContain('deploy/fly');
  expect(await f.vault.get('watcher/signing/private')).not.toBeNull();
});

test('watcher setup warns when the deployment platform protects the same host', async () => {
  const f = await fixture();
  await setupWatcher({ ...f.deps, protectedHosts: ['railway'] }, { platform: 'railway' });
  expect(f.output.join('\n')).toMatch(/runs on a platform it protects/i);
  expect(f.output.join('\n')).toContain('Project token');
});

test('failed deployment preparation reveals no generated secrets and clears temporary keys', async () => {
  const f = await fixture();
  let captured: { stateKey: Buffer; vaultPassphrase: Buffer; watcherKey: { privateKeyDer: Buffer } } | undefined;
  await expect(setupWatcher({ ...f.deps, async prepareDeployment(input) {
    captured = input; throw new Error('planted-credential-value');
  } }, {})).rejects.toThrow('Watcher setup could not finish. No deployment was started.');
  expect(f.output).toHaveLength(0); expect(await f.vault.list()).toEqual([]);
  expect(captured!.stateKey.every(byte => byte === 0)).toBe(true);
  expect(captured!.vaultPassphrase.every(byte => byte === 0)).toBe(true);
  expect(captured!.watcherKey.privateKeyDer.every(byte => byte === 0)).toBe(true);
});

test('watcher setup selects an existing GitHub Actions deployment template', async () => {
  const f = await fixture();
  const result = await setupWatcher(f.deps, { platform: 'github-actions' });
  expect(await readFile(result.template, 'utf8')).toContain('watch --once');
});

test('watcher setup prints the encrypted vault bootstrap once without returning it', async () => {
  const f = await fixture();
  const vaultBlob = 'encrypted-portable-vault-bootstrap';
  const result = await setupWatcher({ ...f.deps, async prepareDeployment() { return { vaultBlob }; } }, {});
  expect(f.output.filter(line => line === `KEYSENTRY_WATCHER_VAULT=${vaultBlob}`)).toHaveLength(1);
  expect(f.output.join('\n')).toContain('initializes the encrypted vault');
  expect(f.output.join('\n')).not.toContain('Copy the encrypted deployment vault');
  expect(JSON.stringify(result)).not.toContain(vaultBlob);
});

test('hosted watcher setup removes console channels from both sealed and prepared configuration', async () => {
  const f = await fixture();
  f.deps.config.notify.channels = [{ kind: 'console', settings: { id: 'terminal' } }, { kind: 'ntfy', settings: { id: 'phone', server: 'https://ntfy.sh', topic: 'private-topic' } }];
  let preparedKinds: string[] = [];
  const result = await setupWatcher({ ...f.deps, async prepareDeployment(input) { preparedKinds = input.config.notify.channels.map(channel => channel.kind); } });
  const deployKey = f.output.join('\n').match(/^KEYSENTRY_WATCHER_KEY=(.+)$/m)![1]!;
  const sealed = openWatcherConfig((await readFile(result.sealedConfigPath, 'utf8')).trim(), Buffer.from(deployKey, 'base64'));
  expect(sealed.notify.channels.map(channel => channel.kind)).toEqual(['ntfy']);
  expect(preparedKinds).toEqual(['ntfy']);
  expect(f.deps.config.notify.channels.map(channel => channel.kind)).toEqual(['console', 'ntfy']);
});

test('watcher setup names exported credentials without exposing their values', async () => {
  const f = await fixture();
  await setupWatcher({ ...f.deps, async prepareDeployment() { return { vaultBlob: 'encrypted-vault', exportedCredentialNames: ['OPENAI_ADMIN_KEY', 'RAILWAY_TOKEN@read'] }; } });
  const output = f.output.join('\n');
  expect(output).toContain('Exported credential names: OPENAI_ADMIN_KEY, RAILWAY_TOKEN@read.');
});

test('watcher status reads health through the injected HTTP client and compares versions', async () => {
  const http = new FakeHttp().on('GET', /^https:\/\/watcher\.example\/healthz$/, () => json(200, { ok: true, version: '1.0.0' }));
  expect(await watcherStatus(http, 'https://watcher.example', '1.0.0')).toEqual({ healthy: true, version: '1.0.0', localVersion: '1.0.0', versionMatches: true, feeds: 'polled' });
  expect(http.calls).toHaveLength(1);
});

test('watcher status reports a watcher whose network settings refuse every request, and offline mode (review H1, L9)', async () => {
  const sick = new FakeHttp().on('GET', /^https:\/\/watcher\.example\/healthz$/, () => json(503, { ok: false, version: '1.0.0', problem: 'network', reason: 'planted-remote-text' }));
  const error = await watcherStatus(sick, 'https://watcher.example', '1.0.0').then(() => null, (failure: Error) => failure);
  expect(error?.message).toContain('The watcher is running but unhealthy.');
  expect(error?.message).toContain('proxy or certificate settings');
  expect(error?.message).not.toContain('planted-remote-text');
  const offline = new FakeHttp().on('GET', /^https:\/\/watcher\.example\/healthz$/, () => json(200, { ok: true, version: '1.0.0', feeds: 'offline' }));
  expect((await watcherStatus(offline, 'https://watcher.example', '1.0.0')).feeds).toBe('offline');
});

test('watcher status never reflects a response body or URL secrets in errors', async () => {
  const http = new FakeHttp().on('GET', /^https:\/\/watcher\.example\/healthz$/, () => json(503, { error: 'planted-value' }));
  await expect(watcherStatus(http, 'https://watcher.example', '1.0.0')).rejects.toThrow('The watcher health check did not succeed.');
  await expect(watcherStatus(http, 'https://user:planted-value@watcher.example', '1.0.0')).rejects.toThrow('Use an HTTPS watcher origin without credentials.');
});

test('with a kms section, watcher setup prints only the wrapped state key and names the KMS credentials', async () => {
  const f = await fixture();
  const wrapped: { key: string; projectId: string }[] = [];
  const result = await setupWatcher({ ...f.deps, wrapStateKey: async (stateKey: Buffer, projectId: string) => {
    wrapped.push({ key: stateKey.toString('base64'), projectId }); return 'd3JhcHBlZC1zdGF0ZS1rZXk=';
  } }, { platform: 'compose' });
  const text = f.output.join('\n');
  expect(wrapped).toEqual([{ key: f.prepared[0]!.stateKey.toString('base64'), projectId: '0123456789abcdef' }]);
  expect(text).toMatch(/^KEYSENTRY_STATE_KEY_WRAPPED=d3JhcHBlZC1zdGF0ZS1rZXk=$/m);
  expect(text).not.toMatch(/^KEYSENTRY_STATE_KEY=/m);
  expect(text).not.toContain(wrapped[0]!.key);
  expect(text).toContain('KMS credentials');
  expect(JSON.stringify(result)).not.toContain('d3JhcHBlZC1zdGF0ZS1rZXk=');
});

test('a KMS failure stops watcher setup before any deploy secret is shown', async () => {
  const f = await fixture();
  const { KmsError } = await import('../../src/kms/index.js');
  await expect(setupWatcher({ ...f.deps, wrapStateKey: async () => { throw new KmsError('unreachable', 'The KMS could not be reached. Saved state stays locked, and keysentry did not create a new state key.'); } }, {}))
    .rejects.toThrow(/KMS could not be reached/);
  expect(f.output.some(line => line.startsWith('KEYSENTRY_'))).toBe(false);
});
