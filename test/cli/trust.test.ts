import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { afterEach, describe, expect, it } from 'vitest';
import { runCli } from '../../src/cli/index.js';
import { createRuntime, type RuntimeOptions } from '../../src/cli/runtime.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { FakeHttp, json, silentLogger } from '../helpers/fake-http.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { getProvider } from '../../src/providers/index.js';
import { EGRESS_RULES } from '../../src/net/index.js';
import { promptGrace } from '../../src/cli/prompts.js';
import { createMonitorState, type MonitorState } from '../../src/monitor/index.js';
import { createEnvVault } from '../../src/vault/index.js';
import { generateDeviceKey } from '../../src/security/index.js';
import type { RotationReport } from '../../src/types.js';

const directories: string[] = [];
afterEach(async () => { for (const path of directories.splice(0)) await rm(path, { recursive: true, force: true }); });

async function fixture() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-trust-')); directories.push(cwd);
  const vault = createFakeVault(); const inflight = createFakeInFlight(); const http = new FakeHttp();
  const output: string[] = []; const errors: string[] = [];
  // Phase 1 embeddings explicitly supply their vault and terminal state; tests never use an OS store.
  const options = { cwd, userDir: join(cwd, '.user'), vault, inflight, http, env: {}, stdinIsTTY: true, stdoutIsTTY: true,
    feeds: [], log: silentLogger, output: (line: string) => output.push(line), error: (line: string) => errors.push(line) };
  return { cwd, vault, inflight, http, output, errors, options };
}

async function rotationFixture(extra: Partial<RuntimeOptions> = {}) {
  const f = await fixture();
  const host = new FakeHost('railway'); host.pendingPolls = 0;
  const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-0123456789abcdef');
  const old = provider.issue(); host.addService('api', { OPENROUTER_API_KEY: old.value });
  const runtime = await createRuntime({ ...f.options, hosts: [host], providers: id => id === provider.id ? provider : getProvider(id),
    sleep: async () => {}, ...extra });
  runtime.config.rotation.graceMs = 0;
  return { ...f, host, provider, old, runtime, io: { ...f.options, runtime } };
}

async function filesUnder(dir: string): Promise<string[]> {
  const paths: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) paths.push(...await filesUnder(path)); else paths.push(path);
  }
  return paths;
}

describe('phase 1 CLI trust boundaries', () => {
  it('rejects an unknown vault credential name before reading or storing a value', async () => {
    const f = await fixture();
    expect(await runCli(['vault', 'set', 'NOT_A_KEYSENTRY_CREDENTIAL', '--stdin'], f.options)).toBe(1);
    expect([...f.vault.dump().keys()].some(name => name.startsWith('cred/'))).toBe(false);
    expect(f.errors.join('\n')).toMatch(/credential name/i);
  });

  it('never accepts a vault value from argv', async () => {
    const f = await fixture(); const value = 'opaque-test-argument-value';
    expect(await runCli(['vault', 'set', 'RAILWAY_TOKEN', value], f.options)).toBe(1);
    expect(await f.vault.get('cred/RAILWAY_TOKEN')).toBeNull();
    expect([...f.output, ...f.errors].join('\n').includes(value)).toBe(false);
  });

  it('stores piped vault input only with --stdin and reports names and roles without values', async () => {
    const f = await fixture(); const value = 'opaque-piped-test-credential';
    const input = new PassThrough(); input.end(`${value}\n`);
    expect(await runCli(['vault', 'set', 'RAILWAY_TOKEN', '--role', 'read', '--stdin'], { ...f.options,
      promptIO: { input: input as unknown as NodeJS.ReadStream } })).toBe(0);
    expect((await f.vault.get('cred/RAILWAY_TOKEN@read'))?.equals(Buffer.from(value))).toBe(true);
    expect(await runCli(['vault', 'status'], f.options)).toBe(0);
    expect(f.output.join('\n')).toContain('RAILWAY_TOKEN'); expect(f.output.join('\n')).toContain('read');
    expect([...f.output, ...f.errors].join('\n').includes(value)).toBe(false);
    const audit = await readFile(join(f.cwd, '.keysentry', 'audit.jsonl'), 'utf8');
    expect(audit.includes(value)).toBe(false);
    expect(audit).toContain('RAILWAY_TOKEN'); expect(audit).toContain('read');
  });

  it('scan uses the read-role host token when both roles are stored', async () => {
    const f = await fixture(); const read = 'opaque-railway-read-token'; const write = 'opaque-railway-write-token';
    await f.vault.set('cred/RAILWAY_TOKEN@read', Buffer.from(read)); await f.vault.set('cred/RAILWAY_TOKEN', Buffer.from(write));
    await writeFile(join(f.cwd, 'keysentry.yaml'), 'hosts:\n  dotenv:\n    enabled: false\nmonitor:\n  feeds: []\n');
    f.http.on('POST', /^https:\/\/backboard\.railway\.com\/graphql\/v2$/, request => {
      expect(request.headers?.Authorization === `Bearer ${read}`).toBe(true);
      return json(200, { data: { projects: { edges: [], pageInfo: { hasNextPage: false, endCursor: null } } } });
    });
    expect(await runCli(['scan', '--json'], f.options)).toBe(0);
    expect(f.http.calls.length).toBeGreaterThan(0);
    expect([...f.output, ...f.errors].some(text => text.includes(read) || text.includes(write))).toBe(false);
  });

  it.each([
    ['rotate', '--execute', '--yes'], ['approve', 'pending'], ['resume'], ['finish'], ['undo', 'saved-plan'],
    ['canary', 'create', '--host', 'railway', '--service', 'api', '--execute'], ['canary', 'remove', 'canary-id', '--execute'],
    ['vault', 'set', 'RAILWAY_TOKEN', '--stdin'], ['vault', 'remove', 'RAILWAY_TOKEN'], ['vault', 'import-env'], ['state', 'reset'],
  ].map(args => ({ args })))('refuses an agent before any host call: $args', async ({ args }) => {
    const f = await fixture(); const host = new FakeHost('railway'); let calls = 0;
    host.listServices = async () => { calls++; return []; };
    expect(await runCli(args, { ...f.options, hosts: [host], env: { AI_AGENT: 'test-agent' } })).toBe(1);
    expect(calls).toBe(0); expect(f.http.calls).toHaveLength(0);
    expect(f.errors.join('\n')).toMatch(/AI coding agent|normal terminal/);
  });

  it('--yes does not remove the human terminal requirement', async () => {
    const f = await fixture(); const host = new FakeHost('railway'); let calls = 0;
    host.listServices = async () => { calls++; return []; };
    expect(await runCli(['rotate', '--execute', '--yes'], { ...f.options, hosts: [host], stdinIsTTY: false, stdoutIsTTY: false })).toBe(1);
    expect(calls).toBe(0); expect(f.errors.join('\n')).toMatch(/interactive terminal/);
  });

  it.each(['autoExecute', 'autoContain'])('refuses agent monitor startup with %s before detecting on hosts', async policy => {
    const f = await fixture(); const host = new FakeHost('railway'); let calls = 0;
    host.listServices = async () => { calls++; return []; };
    await writeFile(join(f.cwd, 'keysentry.yaml'), `monitor:\n  ${policy}: true\n  feeds: []\n`);
    expect(await runCli(['monitor', '--once'], { ...f.options, hosts: [host], env: { AI_AGENT: 'test-agent' } })).toBe(1);
    expect(calls).toBe(0); expect(f.http.calls).toHaveLength(0);
    expect(f.errors.join('\n')).toMatch(/AI coding agent|normal terminal/);
  });

  it('init, scan, plan and execute save encrypted state and a valid audit chain', async () => {
    const f = await rotationFixture();
    expect(await runCli(['init'], f.io)).toBe(0);
    expect(await runCli(['scan'], f.io)).toBe(0);
    expect(await runCli(['plan', '--json'], f.io)).toBe(0);
    const plan = JSON.parse(f.output.at(-1)!).plan;
    expect(await runCli(['rotate', '--plan', plan.id, '--execute', '--yes', '--json'], f.io)).toBe(0);
    expect(JSON.parse(f.output.at(-1)!).report.status).toBe('complete');
    for (const path of [f.runtime.paths.inventory, f.runtime.paths.monitor, f.runtime.paths.journal,
      join(f.runtime.paths.plans, `${plan.id}.json`), join(f.runtime.paths.dir, 'rotation-report.json')]) {
      expect((await readFile(path, 'utf8')).startsWith('keysentry-encrypted:v1\n')).toBe(true);
    }
    const verification = await f.runtime.audit.verify(); expect(verification.ok).toBe(true); expect(verification.checkpoints).toBeGreaterThan(0);
    const audit = await readFile(f.runtime.paths.audit, 'utf8');
    for (const kind of ['scan', 'plan', 'journal:plan-start', 'journal:created', 'journal:plan-end']) expect(audit).toContain(kind);
    for (const path of await filesUnder(f.runtime.paths.dir)) {
      const bytes = await readFile(path);
      for (const key of f.provider.keys.values()) expect(bytes.includes(Buffer.from(key.value))).toBe(false);
    }
  });

  it('records scan and rotation requests only by allowed host and purpose', async () => {
    const f = await rotationFixture();
    f.http.on('GET', /^https:\/\/backboard\.railway\.com\/private\/path$/, () => json(200, {}));
    f.http.on('GET', /^https:\/\/openrouter\.ai\/private\/path$/, () => json(200, {}));
    const list = f.host.listServices.bind(f.host); const rotate = f.provider.rotate.bind(f.provider);
    f.host.listServices = async () => { await f.runtime.config.providerCtx.http.request({ method: 'GET', url: 'https://backboard.railway.com/private/path' }); return list(); };
    f.provider.rotate = async (value, ctx) => { await ctx.http.request({ method: 'GET', url: 'https://openrouter.ai/private/path' }); return rotate(value, ctx); };
    expect(await runCli(['scan'], f.io)).toBe(0);
    expect(await runCli(['rotate', '--execute', '--yes'], f.io)).toBe(0);
    const receipt = (await readFile(join(f.runtime.paths.dir, 'network.jsonl'), 'utf8')).trim().split('\n').map(line => JSON.parse(line));
    expect(receipt.length).toBeGreaterThan(1);
    expect(receipt.every(entry => EGRESS_RULES.some(rule => rule.host === entry.host))).toBe(true);
    expect(JSON.stringify(receipt)).not.toContain('/private/path');
    expect(await runCli(['network'], f.io)).toBe(0);
    expect(f.output.at(-1)).toContain('openrouter.ai'); expect(f.output.at(-1)).not.toContain('/private/path');
  });

  it('migrates plaintext 0.1 state once and reports the number of encrypted files', async () => {
    const f = await fixture(); await mkdir(join(f.cwd, '.keysentry'));
    const inventory = { version: 1, scannedAt: new Date().toISOString(), hosts: [], services: [], findings: [], clusters: [], errors: [] };
    await writeFile(join(f.cwd, '.keysentry', 'inventory.json'), JSON.stringify(inventory));
    const notices: string[] = [];
    const runtime = await createRuntime({ ...f.options, hosts: [], log: { ...silentLogger, info: message => notices.push(message) } });
    expect(await runtime.inventory()).toEqual(inventory);
    expect((await readFile(runtime.paths.inventory, 'utf8')).startsWith('keysentry-encrypted:v1\n')).toBe(true);
    expect(notices.join('\n')).toContain('Encrypted 1 files saved by keysentry 0.1. Nothing else changed.');
  });

  it('keeps grace-pending state when reset is requested without --force', async () => {
    const f = await rotationFixture({ grace: async () => 'defer' }); f.runtime.config.rotation.graceMs = 120_000;
    const plan = await f.runtime.plan(); const report = await f.runtime.rotate(plan, { execute: true });
    expect(report.status).toBe('grace-pending'); expect(await f.inflight.slots(plan.id)).not.toEqual([]);
    const before = await readFile(f.runtime.paths.inventory);
    expect(await runCli(['state', 'reset'], f.io)).toBe(1);
    expect(f.errors.join('\n')).toMatch(/grace-pending|unfinished|in.flight/i);
    expect((await readFile(f.runtime.paths.inventory)).equals(before)).toBe(true);
  });

  it('forced reset needs typed RESET, deletes encrypted state and keeps the audit chain', async () => {
    const f = await rotationFixture({ grace: async () => 'defer' }); f.runtime.config.rotation.graceMs = 120_000;
    const plan = await f.runtime.plan(); await f.runtime.rotate(plan, { execute: true });
    const input = Object.assign(new PassThrough(), { isTTY: true, isRaw: false, setRawMode(value: boolean) { this.isRaw = value; return this; } });
    expect(await runCli(['state', 'reset', '--force'], { ...f.io,
      promptIO: { input: input as unknown as NodeJS.ReadStream, output: { isTTY: true, write: () => true } },
      error: text => { f.errors.push(text); if (text.includes('RESET')) queueMicrotask(() => input.write('RESET\r')); },
    })).toBe(0);
    await expect(readFile(f.runtime.paths.inventory)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(f.runtime.paths.journal)).rejects.toMatchObject({ code: 'ENOENT' });
    expect((await f.runtime.audit.verify()).ok).toBe(true);
    expect(await readFile(f.runtime.paths.audit, 'utf8')).toContain('state-reset');
    expect(await f.inflight.slots(plan.id)).toEqual([]);
  });

  it('resumes a crash after storing the new value without creating another key', async () => {
    let crashed = false;
    const f = await rotationFixture({ crashHook: point => { if (!crashed && point === 'after-store') { crashed = true; throw new Error('simulated-crash'); } } });
    const plan = await f.runtime.plan();
    const before = createMonitorState(); before.keyRefs[plan.steps[0]!.clusterId] = f.old.ref;
    await f.runtime.store.writeJson('monitor', f.runtime.paths.monitor, before);
    await expect(f.runtime.rotate(plan, { execute: true })).rejects.toThrow('simulated-crash');
    expect(f.provider.keys.size).toBe(2); expect(f.host.writes).toHaveLength(0);
    expect(await runCli(['resume', plan.id, '--json'], f.io)).toBe(0);
    const report = JSON.parse(f.output.at(-1)!).report as RotationReport;
    expect(report.status).toBe('complete'); expect(f.provider.keys.size).toBe(2);
    expect(f.provider.revoked).toEqual([f.old.ref]); expect(f.inflight.shredded.has(plan.id)).toBe(true);
    const state = (await f.runtime.store.readJson<MonitorState>('monitor', f.runtime.paths.monitor))!;
    expect(state.keyRefs[report.steps[0]!.newFingerprint!]).toBe(report.steps[0]!.newKeyRef);
    expect(state.keyRefs[plan.steps[0]!.clusterId]).toBeUndefined();
  });

  it('resume restores monitor references for a sealed consumer after a guided value was stored', async () => {
    const f = await fixture(); const host = new FakeHost('github-actions', { readValues: false, redeploy: false });
    const provider = new FakeProvider('github', 'guided', 'ghp_0123456789abcdef0123456789');
    const original = provider.issue(); const replacement = provider.issue('human-created');
    host.addService('acme/repo', { GITHUB_API_TOKEN: original.value }); let crashed = false;
    const runtime = await createRuntime({ ...f.options, hosts: [host], providers: id => id === provider.id ? provider : getProvider(id),
      prompt: async () => replacement.value, reveal: async () => true, sleep: async () => {},
      crashHook: point => { if (!crashed && point === 'after-store') { crashed = true; throw new Error('sealed-crash'); } },
    });
    runtime.config.rotation.graceMs = 0;
    const plan = await runtime.plan(); expect(plan.steps[0]!.clusterId).toMatch(/^sealed:/);
    await expect(runtime.rotate(plan, { execute: true })).rejects.toThrow('sealed-crash');
    const report = await runtime.resume(plan.id); const step = report.steps[0]!;
    expect(host.peek('acme/repo', 'GITHUB_API_TOKEN') === replacement.value).toBe(true);
    expect(step.newFingerprint).toBeDefined(); expect(step.newKeyRef).toBe(replacement.ref);
    const state = (await runtime.store.readJson<MonitorState>('monitor', runtime.paths.monitor))!;
    expect(state?.keyRefs[step.newFingerprint!]).toBe(replacement.ref);
    expect(state?.keyRefs[plan.steps[0]!.clusterId]).toBe(replacement.ref);
  });

  it('undo restores the old monitor reference and removes the replacement reference', async () => {
    const f = await rotationFixture({ grace: async () => 'defer' }); f.runtime.config.rotation.graceMs = 120_000;
    const plan = await f.runtime.plan(); const originalClusterId = plan.steps[0]!.clusterId;
    const state = createMonitorState(); state.keyRefs[originalClusterId] = f.old.ref;
    await f.runtime.store.writeJson('monitor', f.runtime.paths.monitor, state);
    const rotation = await f.runtime.rotate(plan, { execute: true });
    expect(rotation.status).toBe('grace-pending'); const step = rotation.steps[0]!;
    expect((await f.runtime.store.readJson<MonitorState>('monitor', f.runtime.paths.monitor))!.keyRefs[step.newFingerprint!]).toBe(step.newKeyRef);
    const undone = await f.runtime.undo(plan.id); expect(undone.restored).toHaveLength(1);
    expect(f.host.peek('api', 'OPENROUTER_API_KEY') === f.old.value).toBe(true);
    const restored = (await f.runtime.store.readJson<MonitorState>('monitor', f.runtime.paths.monitor))!;
    expect(restored.keyRefs[originalClusterId]).toBe(f.old.ref);
    expect(restored.keyRefs[step.newFingerprint!]).toBeUndefined();
  });

  it('interactive manual approval can defer old-key revocation through the grace prompt', async () => {
    let prompts = 0;
    const f = await rotationFixture({ grace: async () => { prompts++; return 'defer'; } });
    f.runtime.config.rotation.graceMs = 120_000;
    const plan = await f.runtime.plan(); const state = createMonitorState();
    state.pendingActions.push({ id: 'approved-grace', createdAt: new Date().toISOString(), signalId: 'reviewed-signal', action: 'rotate',
      clusterIds: plan.steps.map(step => step.clusterId), status: 'pending' });
    await f.runtime.store.writeJson('monitor', f.runtime.paths.monitor, state);
    const report = await f.runtime.approve('approved-grace', { interactive: true });
    expect(prompts).toBe(1); expect(report?.status).toBe('grace-pending');
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true); expect(f.provider.revoked).toEqual([]);
    expect(await f.inflight.slots(report!.planId)).not.toEqual([]);
  });

  it('environment vault can scan and verify signed audit records without a persistent head', async () => {
    const f = await fixture(); const device = generateDeviceKey();
    const env = { KEYSENTRY_STATE_KEY: Buffer.alloc(32, 0x71).toString('base64'),
      KEYSENTRY_FINGERPRINT_KEY: Buffer.alloc(32, 0x72).toString('base64'), KEYSENTRY_DEVICE_KEY: device.privateKeyDer.toString('base64') };
    const vault = createEnvVault(env); const host = new FakeHost('railway'); host.addService('api', { PORT: '3000' });
    const runtime = await createRuntime({ ...f.options, vault, env, hosts: [host] });
    await runtime.scan();
    const verification = await runtime.audit.verify(); expect(verification.ok).toBe(true); expect(verification.checkpoints).toBeGreaterThan(0);
    expect((await vault.list('audit/head/')).length).toBe(0);
    const audit = (await readFile(runtime.paths.audit, 'utf8')).trim().split('\n').map(line => JSON.parse(line));
    expect(audit.some(entry => entry.kind === 'checkpoint' && typeof entry.data?.sig === 'string')).toBe(true);
    const reopened = await createRuntime({ ...f.options, vault: createEnvVault(env), env, hosts: [host] });
    expect((await reopened.audit.verify()).ok).toBe(true);
  });

  it('grace prompt l keeps old keys valid, then finish settles the latest plan after its deadline', async () => {
    let time = new Date('2026-10-27T12:00:00Z').getTime();
    const input = Object.assign(new PassThrough(), { isTTY: true, isRaw: false, setRawMode(value: boolean) { this.isRaw = value; return this; } });
    const messages: string[] = [];
    const f = await rotationFixture({ now: () => new Date(time), grace: info => promptGrace(info, text => {
      messages.push(text); if (text.includes('Enter: revoke now')) queueMicrotask(() => input.write('l\r'));
    }, { input: input as unknown as NodeJS.ReadStream, output: { isTTY: true, write: () => true } }, () => new Date(time)) });
    f.runtime.config.rotation.graceMs = 120_000;
    const plan = await f.runtime.plan(); const rotation = await f.runtime.rotate(plan, { execute: true });
    expect(rotation.status).toBe('grace-pending'); expect(f.provider.revoked).toEqual([]);
    expect(messages.join('\n')).toContain('New keys are live. Old keys stay valid for 2 minutes so you can undo.');
    // A process can stop after journalling grace but before saving monitor metadata.
    const stale = (await f.runtime.store.readJson<MonitorState>('monitor', f.runtime.paths.monitor))!;
    stale.keyRefs = { [plan.steps[0]!.clusterId]: f.old.ref };
    await f.runtime.store.writeJson('monitor', f.runtime.paths.monitor, stale);
    time += 120_001;
    expect(await runCli(['finish', '--json'], f.io)).toBe(0);
    expect(JSON.parse(f.output.at(-1)!).report.status).toBe('complete'); expect(f.provider.revoked).toEqual([f.old.ref]);
    expect(f.inflight.shredded.has(plan.id)).toBe(true);
    const settled = (await f.runtime.store.readJson<MonitorState>('monitor', f.runtime.paths.monitor))!;
    expect(settled.keyRefs[rotation.steps[0]!.newFingerprint!]).toBe(rotation.steps[0]!.newKeyRef);
    expect(settled.keyRefs[plan.steps[0]!.clusterId]).toBeUndefined();
  });
});
