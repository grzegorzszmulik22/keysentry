import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { PassThrough } from 'node:stream';
import { afterEach, describe, expect, it } from 'vitest';
import { runCli } from '../../src/cli/index.js';
import { createRuntime } from '../../src/cli/runtime.js';
import { createMonitorState, defaultPolicy } from '../../src/monitor/index.js';
import { getProvider } from '../../src/providers/index.js';
import { createDotenvHost } from '../../src/hosts/index.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';

const directories: string[] = [];
afterEach(async () => { for (const path of directories.splice(0)) await rm(path, { recursive: true, force: true }); });
async function fixture(guided = false, yaml?: string) {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-command-'));
  directories.push(cwd);
  if (yaml) await writeFile(join(cwd, 'keysentry.yaml'), yaml);
  const host = new FakeHost('railway'); host.pendingPolls = 0;
  const provider = new FakeProvider(guided ? 'stripe' : 'openrouter', guided ? 'guided' : 'auto', guided ? 'sk_live_0123456789abcdef' : 'sk-or-v1-0123456789abcdef');
  const key = provider.issue();
  host.addService('one', { [guided ? 'STRIPE_SECRET_KEY' : 'OPENROUTER_API_KEY']: key.value });
  host.addService('two', { [guided ? 'STRIPE_SECRET_KEY' : 'OPENROUTER_API_KEY']: key.value });
  const runtime = await createRuntime({ cwd, env: { OPENROUTER_PROVISIONING_KEY: 'test-management-credential' }, hosts: [host], providers: id => id === provider.id ? provider : getProvider(id), http: new FakeHttp(), log: silentLogger, feeds: [], sleep: async () => {} });
  const output: string[] = []; const errors: string[] = [];
  const io = { runtime, output: (line: string) => output.push(line), error: (line: string) => errors.push(line) };
  return { cwd, host, provider, key, runtime, output, errors, io };
}

describe('CLI commands', () => {
  it('creates private local state and preserves existing configuration', async () => {
    const f = await fixture();
    expect(await runCli(['init', '--json'], f.io)).toBe(0);
    const initial = await readFile(join(f.cwd, 'keysentry.yaml'), 'utf8');
    expect(initial).toContain('autoExecute: false');
    expect(await runCli(['init', '--json'], f.io)).toBe(0);
    expect(await readFile(join(f.cwd, 'keysentry.yaml'), 'utf8')).toBe(initial);
    expect((await readFile(join(f.runtime.paths.dir, 'fingerprint.key'))).length).toBe(32);
  });

  it('gates findings exit status and produces parseable secret-free JSON', async () => {
    const f = await fixture();
    expect(await runCli(['scan', '--json'], f.io)).toBe(0);
    const inventory = JSON.parse(f.output.at(-1)!);
    expect(inventory.clusters[0].consumers).toHaveLength(2);
    expect(await runCli(['scan', '--json', '--fail-on-findings'], f.io)).toBe(2);
    expect(await runCli(['--fail-on-findings', 'report', '--json'], f.io)).toBe(2);
    expect(f.output.join('\n').includes(f.key.value)).toBe(false);
    expect(f.output.join('\n').includes('test-management-credential')).toBe(false);
  });

  it('saves selectable plans and Markdown runbooks while retaining every shared consumer', async () => {
    const f = await fixture(); await f.runtime.scan();
    expect(await runCli(['plan', '--host', 'railway', '--tier', 'ai', '-o', 'runbook.md', '--json'], f.io)).toBe(0);
    const result = JSON.parse(f.output.at(-1)!);
    expect(result.plan.steps).toHaveLength(1);
    expect(result.plan.services).toHaveLength(2);
    expect((await f.runtime.loadPlan(result.plan.id)).id).toBe(result.plan.id);
    expect((await readFile(join(f.cwd, 'runbook.md'), 'utf8')).includes(f.key.value)).toBe(false);
    expect(await runCli(['rotate', '--plan', result.plan.id, '--json'], f.io)).toBe(0);
    expect(JSON.parse(f.output.at(-1)!).report.dryRun).toBe(true);
    expect(f.host.writes).toHaveLength(0);
  });

  it('shows the dry-run diff before numeric confirmation and cancels without mutation', async () => {
    const f = await fixture();
    expect(await runCli(['rotate', '--execute', '--json'], { ...f.io, confirm: async count => {
      expect(count).toBe(1);
      expect(f.errors.join('\n')).toContain('Rotation preview');
      expect(f.errors.join('\n')).toContain('OPENROUTER_API_KEY');
      expect(f.host.writes).toHaveLength(0);
      expect(f.provider.keys.size).toBe(1);
      return false;
    } })).toBe(0);
    expect(JSON.parse(f.output.at(-1)!).cancelled).toBe(true);
    expect(f.host.writes).toHaveLength(0);
    expect(f.provider.revoked).toHaveLength(0);
  });

  it('executes explicitly, honors --yes, and prints summary and journal location', async () => {
    const f = await fixture();
    expect(await runCli(['rotate', '--execute', '--yes'], { ...f.io, confirm: async () => { throw new Error('confirmation must be bypassed'); } })).toBe(0);
    expect(f.host.writes).toHaveLength(2);
    expect(f.host.redeploys).toEqual(['one', 'two']);
    expect(f.provider.revoked).toEqual([f.key.ref]);
    expect(f.output.at(-1)).toContain('Rotation summary');
    expect(f.output.at(-1)).toContain(f.runtime.paths.journal);
  });

  it('uses the injected hidden-input seam for guided values and supports empty skips', async () => {
    const f = await fixture(true);
    expect(await runCli(['rotate', '--execute', '--yes', '--json'], { ...f.io, prompt: async () => null })).toBe(0);
    expect(JSON.parse(f.output.at(-1)!).report.steps[0].status).toBe('skipped');
    expect(f.host.writes).toHaveLength(0);
    const replacement = f.provider.issue('human-created');
    expect(await runCli(['rotate', '--execute', '--yes', '--json'], { ...f.io, prompt: async prompt => {
      expect(prompt.guidance.url).toContain('stripe'); expect(prompt.guidance.steps.length).toBeGreaterThan(0);
      return replacement.value;
    } })).toBe(0);
    expect(f.host.writes).toHaveLength(2);
    expect(f.provider.revoked).toEqual([f.key.ref]);
    expect(f.output.join('\n').includes(replacement.value)).toBe(false);
  });

  it('preserves rotation defaults from YAML and honors no-redeploy and revoke flags', async () => {
    const f = await fixture(false, 'rotation:\n  redeploy: false\n  revoke: never\n');
    expect(await runCli(['rotate', '--execute', '--yes'], f.io)).toBe(0);
    expect(f.host.redeploys).toHaveLength(0); expect(f.provider.revoked).toHaveLength(0);
    const g = await fixture();
    expect(await runCli(['rotate', '--execute', '--yes', '--no-redeploy', '--revoke', 'never'], g.io)).toBe(0);
    expect(g.host.redeploys).toHaveLength(0); expect(g.provider.revoked).toHaveLength(0);
  });

  it('fails on a real write failure, retaining the old key', async () => {
    const f = await fixture(); f.host.failWritesFor.add('two');
    expect(await runCli(['rotate', '--execute', '--yes', '--json'], f.io)).toBe(1);
    expect(f.provider.revoked).toHaveLength(0);
    expect(JSON.parse(f.output.at(-1)!).report.steps[0].status).toBe('failed');
  });

  it('runs drills without mutations and explains all six readiness factors', async () => {
    const f = await fixture();
    expect(await runCli(['drill', '--json'], f.io)).toBe(0);
    const result = JSON.parse(f.output.at(-1)!);
    expect(result.score).toBeGreaterThanOrEqual(0); expect(result.score).toBeLessThanOrEqual(100);
    expect(result.reasons).toHaveLength(6); expect(result.elapsedMs).toBeGreaterThanOrEqual(0);
    expect(result.report.dryRun).toBe(true); expect(f.host.writes).toHaveLength(0); expect(f.provider.keys.size).toBe(1);
  });

  it('lists, dismisses, and explicitly approves persisted pending actions', async () => {
    const f = await fixture(); const inv = await f.runtime.scan(); const state = createMonitorState();
    state.pendingActions.push(...['dismiss-me', 'approve-me'].map(id => ({ id, createdAt: new Date().toISOString(), signalId: 'signal-test', action: 'rotate' as const, clusterIds: inv.clusters.map(cluster => cluster.id), status: 'pending' as const })));
    await writeFile(f.runtime.paths.monitor, JSON.stringify(state));
    expect(await runCli(['actions', '--json'], f.io)).toBe(0); expect(JSON.parse(f.output.at(-1)!)).toHaveLength(2);
    expect(await runCli(['dismiss', 'dismiss-me'], f.io)).toBe(0); expect(f.host.writes).toHaveLength(0);
    expect(await runCli(['approve', 'approve-me', '--yes', '--json'], f.io)).toBe(0); expect(f.host.writes).toHaveLength(2);
    expect(await runCli(['actions', '--json'], f.io)).toBe(0); expect(JSON.parse(f.output.at(-1)!)).toEqual([]);
  });

  it('skips guided steps in the monitor executor and leaves remediation pending', async () => {
    const f = await fixture(true); const inv = await f.runtime.scan();
    const state = createMonitorState();
    state.canaries.push({ id: 'decoy-test', provider: 'openrouter', keyRef: 'decoy-ref', service: inv.services[0]!, varName: 'DECOY_KEY', createdAt: new Date().toISOString() });
    // Non-TTY approval skips guided input; TTY approval is covered separately.
    state.pendingActions.push({ id: 'guided-action', createdAt: new Date().toISOString(), signalId: 'canary-signal', action: 'rotate', clusterIds: inv.clusters.map(cluster => cluster.id), status: 'pending' });
    await writeFile(f.runtime.paths.monitor, JSON.stringify(state));
    expect(await runCli(['approve', 'guided-action', '--yes', '--json'], { ...f.io, prompt: async () => { throw new Error('must never prompt'); } })).toBe(0);
    expect(f.host.writes).toHaveLength(0); expect((await f.runtime.pendingActions())[0]?.status).toBe('pending');
  });

  it('reports successful approval of pending containment as executed', async () => {
    const f = await fixture(); const inv = await f.runtime.scan(); const state = createMonitorState();
    state.pendingActions.push({ id: 'approve-cap', createdAt: new Date().toISOString(), signalId: 'usage-signal', action: 'cap', clusterIds: inv.clusters.map(cluster => cluster.id), status: 'pending' });
    await writeFile(f.runtime.paths.monitor, JSON.stringify(state));
    expect(await runCli(['approve', 'approve-cap', '--yes', '--json'], f.io)).toBe(0);
    expect(f.provider.capped).toEqual([f.key.ref]);
    expect(JSON.parse(f.output.at(-1)!).action.status).toBe('executed');
    expect(await f.runtime.pendingActions()).toEqual([]);
  });

  it('rejects invalid selectors and command arguments without echoing their values', async () => {
    const f = await fixture(); const secret = 'opaque-value-supplied-as-an-unknown-option';
    expect(await runCli([`--${secret}`], f.io)).toBe(1);
    expect(await runCli(['plan', '--tier', secret], f.io)).toBe(1);
    expect(await runCli(['rotate', '--revoke', secret], f.io)).toBe(1);
    expect(await runCli(['rotate', '--plan', '../outside'], f.io)).toBe(1);
    expect(f.errors.join('\n').includes(secret)).toBe(false); expect(f.host.writes).toHaveLength(0);
  });

  it('redacts multiline and short values structurally without invalidating JSON', async () => {
    const f = await fixture();
    for (const secret of ['abc', 'opaque\nvalue"with\\escape']) f.runtime.redactor.register(secret);
    const clean = f.runtime.safe({ name: 'abc', value: 'opaque\nvalue"with\\escape' });
    expect(clean).toEqual({ name: '«redacted»', value: '«redacted»' });
    expect(JSON.parse(JSON.stringify(clean))).toEqual(clean);
  });

  it('does not redact JSON syntax after sanitizing its string values', async () => {
    const f = await fixture(); f.runtime.redactor.register('\": ');
    expect(await runCli(['scan', '--json'], f.io)).toBe(0);
    expect(() => JSON.parse(f.output.at(-1)!)).not.toThrow();
  });

  it('does not let a registered prefix conceal an otherwise recognizable complete key', async () => {
    const f = await fixture(); f.runtime.redactor.register('sk-');
    const unregistered = `sk-proj-${'Q'.repeat(48)}`;
    const clean = f.runtime.redactor.redact(unregistered);
    expect(clean.includes('Q'.repeat(12))).toBe(false);
  });

  it('polls in embedded monitor loops even without an output callback', async () => {
    const f = await fixture(); const controller = new AbortController();
    const list = f.host.listServices.bind(f.host); let polls = 0;
    f.host.listServices = async () => { polls++; controller.abort(); return list(); };
    const timeout = setTimeout(() => controller.abort(), 30);
    try { await f.runtime.monitor(controller.signal, 1); } finally { clearTimeout(timeout); }
    expect(polls).toBeGreaterThan(0);
  });

  it('stops the CLI monitor on Ctrl-C and removes its process listeners', async () => {
    const f = await fixture(); const before = process.listenerCount('SIGINT');
    f.runtime.monitor = async signal => { process.emit('SIGINT'); expect(signal.aborted).toBe(true); };
    expect(await runCli(['monitor', '--interval', '1'], f.io)).toBe(0);
    expect(process.listenerCount('SIGINT')).toBe(before);
  });

  it('reports operational errors on enabled hosts with exit 1 while preserving partial inventory', async () => {
    const f = await fixture(); f.host.listServices = async () => { throw new Error('arbitrary upstream diagnostic'); };
    expect(await runCli(['scan', '--json'], f.io)).toBe(1);
    expect(JSON.parse(f.output.at(-1)!).errors).toHaveLength(1);
  });

  it('never trusts adapter errors that happen to start like a local diagnostic', async () => {
    const f = await fixture(); const opaque = 'opaque-unregistered-upstream-credential';
    f.host.listServices = async () => { throw new Error(`Canary ${opaque}`); };
    expect(await runCli(['canary', 'create', '--host', 'railway', '--service', 'one'], f.io)).toBe(1);
    expect(f.errors.join('\n').includes(opaque)).toBe(false);
  });

  it('rejects secret-bearing canary destination metadata before creating or planting a key', async () => {
    const f = await fixture(); const list = f.host.listServices.bind(f.host);
    f.host.listServices = async () => (await list()).map(service => ({ ...service, projectName: f.key.value }));
    expect(await runCli(['canary', 'create', '--host', 'railway', '--service', 'one', '--execute'], f.io)).toBe(1);
    expect(f.errors.at(-1)).toContain('destination metadata');
    expect(f.errors.join('\n').includes(f.key.value)).toBe(false);
    expect(f.provider.keys.size).toBe(1); expect(f.host.writes).toHaveLength(0);
  });

  it('persists replacement references for sealed stable cluster IDs', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'keysentry-sealed-command-')); directories.push(cwd);
    const host = new FakeHost('github-actions', { readValues: false, redeploy: false });
    const provider = new FakeProvider('github', 'guided', 'ghp_0123456789abcdef0123456789');
    const old = provider.issue(); host.addService('acme/repo', { GITHUB_API_TOKEN: old.value });
    const runtime = await createRuntime({ cwd, env: {}, http: new FakeHttp(), hosts: [host], providers: id => id === 'github' ? provider : getProvider(id), log: silentLogger, feeds: [] });
    const inv = await runtime.scan(); const replacement = provider.issue('human');
    const report = await runtime.rotate(await runtime.plan(), { execute: true, prompt: async () => replacement.value });
    expect(report.steps[0]?.status).toBe('written');
    expect(report.deployments[0]?.state).toBe('unconfirmed');
    expect(provider.revoked).toHaveLength(0);
    const state = JSON.parse(await readFile(runtime.paths.monitor, 'utf8'));
    expect(state.keyRefs[inv.clusters[0]!.id]).toBe(replacement.ref);
    expect(state.keyRefs[report.steps[0]!.newFingerprint!]).toBe(replacement.ref);
  });

  it('marks deployed monitored replacements completed while retaining old-key warnings', async () => {
    const f = await fixture(); const originalRotate = f.provider.rotate.bind(f.provider);
    f.provider.rotate = async (value, ctx) => ({ ...await originalRotate(value, ctx), oldKeyRef: null });
    const inv = await f.runtime.scan(); const state = createMonitorState();
    state.pendingActions.push({ id: 'no-old-ref', createdAt: new Date().toISOString(), signalId: 'signal-test', action: 'rotate', clusterIds: inv.clusters.map(cluster => cluster.id), status: 'pending' });
    await writeFile(f.runtime.paths.monitor, JSON.stringify(state));
    const report = await f.runtime.approve('no-old-ref');
    expect(report?.steps[0]?.status).toBe('verified');
    expect(report?.steps[0]?.warnings.length).toBeGreaterThan(0);
    const persisted = JSON.parse(await readFile(f.runtime.paths.monitor, 'utf8'));
    expect(persisted.pendingActions[0].status).toBe('executed');
    const engineReport = JSON.parse(await readFile(join(f.runtime.paths.dir, 'rotation-report.json'), 'utf8'));
    expect(engineReport.steps[0].status).toBe('deployed');
    expect(f.provider.revoked).toHaveLength(0);
  });

  it('keeps canary detection running while blocking a shared cluster on a failed host', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'keysentry-partial-command-')); directories.push(cwd);
    const railway = new FakeHost('railway'); const vercel = new FakeHost('vercel');
    const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-0123456789abcdef');
    const key = provider.issue(); const decoy = provider.issue('decoy', 0.01);
    const service = railway.addService('api', { OPENROUTER_API_KEY: key.value });
    vercel.addService('web', { OPENROUTER_API_KEY: key.value });
    const runtime = await createRuntime({ cwd, env: {}, hosts: [railway, vercel], providers: id => id === provider.id ? provider : getProvider(id), http: new FakeHttp(), log: silentLogger, feeds: [], policy: { ...defaultPolicy(), autoExecute: true } });
    expect((await runtime.scan()).clusters[0]?.consumers).toHaveLength(2);
    const state = createMonitorState();
    state.canaries.push({ id: 'canary-partial', provider: 'openrouter', keyRef: decoy.ref, service, varName: 'DECOY_KEY', createdAt: new Date().toISOString() });
    await writeFile(runtime.paths.monitor, JSON.stringify(state)); provider.spend(decoy.ref, 0.001);
    vercel.listServices = async () => { throw new Error('upstream inaccessible'); };
    const poll = await runtime.monitorOnce();
    expect(poll.signals.some(signal => signal.kind === 'canary_triggered')).toBe(true);
    expect((await runtime.inventory()).clusters[0]?.consumers).toHaveLength(2);
    const plan = await runtime.plan();
    await expect(runtime.rotate(plan, { execute: true })).rejects.toThrow(/scan.*failed/i);
    expect(provider.keys.size).toBe(2); expect(provider.revoked).toHaveLength(0); expect(provider.capped).toHaveLength(0);
    expect(railway.writes).toHaveLength(0); expect(vercel.writes).toHaveLength(0);
    expect(JSON.parse(await readFile(runtime.paths.monitor, 'utf8')).canaries[0].triggeredAt).toBeDefined();
  });

  it('executes an unaffected plan with a partial-scan warning', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'keysentry-unaffected-command-')); directories.push(cwd);
    const railway = new FakeHost('railway'); railway.pendingPolls = 0;
    const vercel = new FakeHost('vercel');
    const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-0123456789abcdef');
    const key = provider.issue(); railway.addService('api', { OPENROUTER_API_KEY: key.value });
    vercel.addService('web', { STRIPE_SECRET_KEY: `sk_live_${'B'.repeat(40)}` });
    const warnings: string[] = [];
    const runtime = await createRuntime({ cwd, env: {}, hosts: [railway, vercel], providers: id => id === provider.id ? provider : getProvider(id), http: new FakeHttp(), log: { ...silentLogger, warn: message => warnings.push(message) }, feeds: [] });
    await runtime.scan();
    vercel.listServices = async () => { throw new Error('upstream inaccessible'); };
    await runtime.scan();
    const plan = await runtime.plan({ hosts: ['railway'] });
    const report = await runtime.rotate(plan, { execute: true });
    expect(report.steps[0]?.status).toBe('revoked');
    expect(provider.revoked).toEqual([key.ref]);
    expect(warnings.some(warning => /outside this plan|unaffected/i.test(warning))).toBe(true);
  });

  it('retains a known shared consumer when its host credentials become unavailable', async () => {
    const f = await fixture();
    await writeFile(join(f.cwd, '.env'), `OPENROUTER_API_KEY=${f.key.value}\n`);
    const dotenv = createDotenvHost({ roots: [f.cwd], log: silentLogger });
    const makeRuntime = (hosts?: NonNullable<Parameters<typeof createRuntime>[0]>['hosts']) => createRuntime({ cwd: f.cwd, env: {}, ...(hosts ? { hosts } : {}), providers: id => id === f.provider.id ? f.provider : getProvider(id), http: new FakeHttp(), log: silentLogger, feeds: [] });
    const connected = await makeRuntime([f.host, dotenv]);
    expect((await connected.scan()).clusters[0]?.consumers).toHaveLength(3);
    const disconnected = await makeRuntime();
    const inventory = await disconnected.scan();
    expect(inventory.clusters[0]?.consumers).toHaveLength(3);
    expect(inventory.errors.some(error => error.host === 'railway')).toBe(true);
    await expect(disconnected.rotate(await disconnected.plan(), { execute: true })).rejects.toThrow(/scan.*failed/i);
    expect(f.provider.revoked).toHaveLength(0);
  });

  it('forwards explicit safety overrides to the dry run', async () => {
    const f = await fixture();
    const rotate = f.runtime.rotate;
    const received: unknown[] = [];
    f.runtime.rotate = async (plan, opts) => { received.push(opts); return rotate(plan, opts); };
    expect(await runCli(['rotate', '--no-generate', '--revoke-unconfirmed', '--accept-unplanned-sealed'], f.io)).toBe(0);
    expect(received[0]).toMatchObject({ allowGenerate: false, revokeUnconfirmed: true, acceptUnplannedSealed: true });
    expect(f.host.writes).toHaveLength(0);
  });

  it('skips generated application secrets with --no-generate', async () => {
    const f = await fixture();
    const original = 'e5ce1c5590aa97cf6f1e6caee65c29326c8289eb667dd46b43e9e5d7c769c8b4';
    f.host.addService('session', { SESSION_SECRET: original });
    expect(await runCli(['rotate', '--tier', 'app', '--execute', '--yes', '--no-generate', '--json'], f.io)).toBe(0);
    expect(JSON.parse(f.output.at(-1)!).report.steps[0]?.status).toBe('skipped');
    expect(f.host.peek('session', 'SESSION_SECRET') === original).toBe(true);
    expect(f.host.writes).toHaveLength(0);
  });

  it('requires the sealed-consumer override before revoking a selectively planned key', async () => {
    const f = await fixture();
    f.host.addService('sealed', { OPENROUTER_API_KEY: f.key.value }, ['OPENROUTER_API_KEY']);
    const inv = await f.runtime.scan();
    const cluster = inv.clusters.find(item => item.fingerprint !== null)!;
    expect(await runCli(['rotate', '--cluster', cluster.id, '--execute', '--yes', '--json'], f.io)).toBe(0);
    expect(f.provider.revoked).toHaveLength(0);
    const refreshed = await f.runtime.inventory();
    const current = refreshed.clusters.find(item => item.fingerprint !== null)!;
    expect(await runCli(['rotate', '--cluster', current.id, '--execute', '--yes', '--accept-unplanned-sealed', '--json'], f.io)).toBe(0);
    expect(f.provider.revoked).toHaveLength(1);
  });

  it('wires emergency reveal for an atomic roll whose replacement cannot be delivered', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'keysentry-reveal-command-')); directories.push(cwd);
    const host = new FakeHost('railway'); host.pendingPolls = 0;
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'cf-f9G7k6R2a4D0p8W5b3H1j9C6e2M4x7U8-');
    const old = provider.issue(); host.addService('api', { CLOUDFLARE_API_TOKEN: old.value }); host.failWritesFor.add('api');
    const runtime = await createRuntime({ cwd, env: {}, hosts: [host], providers: id => id === provider.id ? provider : getProvider(id), http: new FakeHttp(), log: silentLogger, feeds: [], sleep: async () => {} });
    expect((await runtime.scan()).clusters[0]?.provider).toBe('cloudflare');
    const output: string[] = []; const errors: string[] = []; let reveals = 0;
    const input = Object.assign(new PassThrough(), { isTTY: true, setRawMode() { return this; } });
    expect(await runCli(['rotate', '--execute', '--yes'], { runtime, promptIO: { input: input as unknown as NodeJS.ReadStream, output: { isTTY: true, write: () => true } }, output: line => output.push(line), error: line => errors.push(line), reveal: async (info, value) => {
      reveals++; expect(info.provider).toBe('cloudflare'); expect(info.reason).toMatch(/unwritten/i);
      expect(provider.refOf(value) !== null).toBe(true);
      expect(output.some(line => line.includes(value)) || errors.some(line => line.includes(value))).toBe(false);
      return true;
    } })).toBe(1);
    expect(reveals).toBe(1);
    const stored = await readFile(join(runtime.paths.dir, 'rotation-report.json'), 'utf8');
    expect([...provider.keys.values()].some(key => stored.includes(key.value))).toBe(false);
  });

  it('includes provider notes in the human summary', async () => {
    const f = await fixture(); const rotate = f.provider.rotate.bind(f.provider);
    f.provider.rotate = async (value, ctx) => ({ ...await rotate(value, ctx), notes: 'Provider migration notice: review scopes in the dashboard.' });
    expect(await runCli(['rotate', '--execute', '--yes'], f.io)).toBe(0);
    expect(f.output.at(-1)).toContain('Provider migration notice: review scopes in the dashboard.');
  });

  it('uses project/service/environment labels in human reports and previews', async () => {
    const f = await fixture();
    expect(await runCli(['scan'], f.io)).toBe(0);
    expect(f.output.at(-1)).toContain('railway:proj1/one@production');
    expect(await runCli(['rotate', '--execute', '--yes'], f.io)).toBe(0);
    expect(f.errors.join('\n')).toContain('railway:proj1/two@production');
    expect(f.errors.join('\n')).not.toContain('railway:proj1/production/two');
  });

  it('shows dotenv files relative to their scan root in reports and runbooks', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'keysentry-label-command-')); directories.push(cwd);
    await writeFile(join(cwd, '.env'), `OPENROUTER_API_KEY=sk-or-v1-${'D'.repeat(48)}\n`);
    const host = createDotenvHost({ roots: [cwd], log: silentLogger });
    const runtime = await createRuntime({ cwd, env: {}, hosts: [host], http: new FakeHttp(), log: silentLogger, feeds: [] });
    await runtime.scan();
    const report = await runtime.report();
    const runbook = await runtime.runbook(await runtime.plan());
    for (const text of [report, runbook]) {
      expect(text).toContain(`dotenv:${basename(cwd)}/.env`);
      expect(text.includes(join(cwd, '.env'))).toBe(false);
      expect(text.includes(`dotenv:${cwd}`)).toBe(false);
    }
  });

  it('keeps encryption-key classifications and reference consumers through persistence', async () => {
    const f = await fixture();
    f.host.addService('encrypted', { ENCRYPTION_KEY: '9f7e3d2a6c4b8e019f7e3d2a6c4b8e01' });
    const inv = await f.runtime.scan();
    expect(inv.clusters.find(cluster => cluster.provider === 'encryption-key')?.method).toBe('guided');
    const plan = await f.runtime.plan();
    const step = plan.steps[0]!;
    step.consumers[0]!.reference = true;
    await writeFile(join(f.runtime.paths.plans, `${plan.id}.json`), JSON.stringify(plan));
    expect((await f.runtime.loadPlan(plan.id)).steps[0]?.consumers[0]?.reference).toBe(true);
  });

  it('loads --cwd and --config through normal CLI wiring and prints safe YAML errors', async () => {
    const f = await fixture(); const errors: string[] = [];
    await writeFile(join(f.cwd, 'custom.yaml'), 'hosts:\n  dotenv:\n    enabled: false\nmonitor:\n  feeds: []\n');
    const output: string[] = [];
    expect(await runCli(['--cwd', f.cwd, '--config', 'custom.yaml', 'scan', '--json'], { env: {}, http: new FakeHttp(), log: silentLogger, output: line => output.push(line), error: line => errors.push(line) })).toBe(0);
    expect(JSON.parse(output.at(-1)!).errors).toHaveLength(6);
    await writeFile(join(f.cwd, 'bad.yaml'), 'hosts: [opaque-secret-in-invalid-yaml\n');
    expect(await runCli(['--cwd', f.cwd, '--config', 'bad.yaml', 'scan'], { env: {}, output: line => output.push(line), error: line => errors.push(line) })).toBe(1);
    expect(errors.at(-1)).toMatch(/Invalid YAML.*line/); expect(errors.join('\n')).not.toContain('opaque-secret-in-invalid-yaml');
  });
});
