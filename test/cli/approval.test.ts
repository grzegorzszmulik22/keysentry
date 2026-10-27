import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { afterEach, describe, expect, it } from 'vitest';
import { runCli } from '../../src/cli/index.js';
import { createRuntime as productionCreateRuntime } from '../../src/cli/runtime.js';
import { RotationAbortedError } from '../../src/types.js';
import { createMonitorState } from '../../src/monitor/index.js';
import { getProvider } from '../../src/providers/index.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';

// Phase 1 uses an injected vault and encrypted state; tests never open the OS store.
const vaults = new Map<string, ReturnType<typeof createFakeVault>>();
async function createRuntime(options: NonNullable<Parameters<typeof productionCreateRuntime>[0]> = {}) {
  const cwd = options.cwd ?? process.cwd();
  const vault = vaults.get(cwd) ?? createFakeVault();
  vaults.set(cwd, vault);
  const runtime = await productionCreateRuntime({
    vault, inflight: createFakeInFlight(), userDir: join(cwd, '.user'),
    stdinIsTTY: true, stdoutIsTTY: true, grace: async () => 'revoke', ...options,
  });
  // Existing behavioral tests settle immediately; grace/recovery have focused coverage.
  runtime.config.rotation.graceMs = 0;
  return runtime;
}

const directories: string[] = [];
afterEach(async () => { for (const path of directories.splice(0)) await rm(path, { recursive: true, force: true }); });

function tty() {
  const stream = Object.assign(new PassThrough(), { isTTY: true, isRaw: false, setRawMode(value: boolean) { this.isRaw = value; return this; } });
  return { input: stream as unknown as NodeJS.ReadStream, output: { isTTY: true, write: (_value: string) => true } };
}

async function fixture(method: 'auto' | 'guided' | 'atomic-roll' = 'auto', manual = false) {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-approval-')); directories.push(cwd);
  const host = new FakeHost(manual ? 'dotenv' : 'railway', { redeploy: !manual }); host.pendingPolls = 0;
  const provider = new FakeProvider(method === 'atomic-roll' ? 'cloudflare' : method === 'guided' ? 'stripe' : 'openrouter', method,
    method === 'atomic-roll' ? 'cf-f9G7k6R2a4D0p8W5b3H1j9C6e2M4x7U8-' : method === 'guided' ? 'sk_live_0123456789abcdef' : 'sk-or-v1-0123456789abcdef');
  const original = provider.issue();
  host.addService('api', { [method === 'atomic-roll' ? 'CLOUDFLARE_API_TOKEN' : method === 'guided' ? 'STRIPE_SECRET_KEY' : 'OPENROUTER_API_KEY']: original.value });
  const runtime = await createRuntime({ cwd, env: {}, hosts: [host], providers: id => id === provider.id ? provider : getProvider(id),
    http: new FakeHttp(), log: silentLogger, feeds: [], sleep: async () => {} });
  const inv = await runtime.scan(); const state = createMonitorState();
  expect(inv.clusters).toHaveLength(1); expect(inv.clusters[0]?.provider).toBe(provider.id);
  state.pendingActions.push({ id: 'review-this-action', createdAt: new Date().toISOString(), signalId: 'signal-test', action: 'rotate',
    clusterIds: inv.clusters.map(cluster => cluster.id), status: 'pending', highConfidence: true, revokeUnconfirmed: true });
  await runtime.store.writeJson('monitor', runtime.paths.monitor, state);
  const output: string[] = []; const errors: string[] = [];
  return { runtime, host, provider, original, state, output, errors,
    io: { runtime, output: (line: string) => output.push(line), error: (line: string) => errors.push(line) } };
}

describe('pending action approval safety', () => {
  it('shows revocation and manual activation before requesting the action id, then cancels safely', async () => {
    const f = await fixture('auto', true); let confirmations = 0;
    expect(await runCli(['approve', 'review-this-action', '--json'], { ...f.io, confirmAction: async id => {
      confirmations++; expect(id).toBe('review-this-action');
      expect(f.errors.join('\n')).toContain('revokeUnconfirmed: true');
      expect(f.errors.join('\n')).toContain('Manual restart');
      expect(f.errors.join('\n')).toContain('dotenv:');
      expect(f.host.writes).toHaveLength(0); expect(f.provider.revoked).toHaveLength(0);
      return false;
    } })).toBe(0);
    expect(confirmations).toBe(1); expect(f.host.writes).toHaveLength(0);
    expect(JSON.parse(f.output.at(-1)!).cancelled).toBe(true);
  });

  it('requires a human TTY even with --yes and still prints the reviewed action on a TTY', async () => {
    const f = await fixture();
    // --yes only skips the question in phase 1; it never bypasses the human TTY gate.
    expect(await runCli(['approve', 'review-this-action', '--yes'], { ...f.io, stdinIsTTY: false, stdoutIsTTY: false })).toBe(1);
    expect(f.host.writes).toHaveLength(0);
    expect(await runCli(['approve', 'review-this-action', '--yes'], { ...f.io, confirmAction: async () => { throw new Error('must bypass'); } })).toBe(0);
    expect(f.host.writes).toHaveLength(1);
    expect(f.errors.join('\n')).toContain('revokeUnconfirmed: true');
  });

  it('refuses atomic-roll approvals on a non-TTY even with --yes before invalidating the old token', async () => {
    const f = await fixture('atomic-roll');
    expect(await runCli(['approve', 'review-this-action', '--yes'], { ...f.io, stdinIsTTY: false, stdoutIsTTY: false })).toBe(1);
    expect(f.errors.join('\n')).toMatch(/interactive terminal/i);
    expect(f.provider.keys.size).toBe(1); expect(f.provider.keys.get(f.original.ref)?.active).toBe(true);
    expect(f.host.writes).toHaveLength(0);
    expect((await f.runtime.pendingActions())[0]?.status).toBe('pending');
  });

  it('honors the recorded interactive requirement even when the current plan has no atomic roll', async () => {
    const f = await fixture(); f.state.pendingActions[0]!.requiresInteractive = true;
    await f.runtime.store.writeJson('monitor', f.runtime.paths.monitor, f.state);
    await expect(f.runtime.approve('review-this-action', { interactive: false })).rejects.toThrow(/interactive terminal/i);
    expect(f.provider.keys.size).toBe(1); expect(f.host.writes).toHaveLength(0);
  });

  it('shows the recorded revocation choice and never broadens legacy actions', async () => {
    const f = await fixture(); delete f.state.pendingActions[0]!.revokeUnconfirmed;
    await f.runtime.store.writeJson('monitor', f.runtime.paths.monitor, f.state);
    expect((await f.runtime.reviewAction('review-this-action')).revokeUnconfirmed).toBe(false);
    f.state.pendingActions[0]!.revokeUnconfirmed = true;
    await f.runtime.store.writeJson('monitor', f.runtime.paths.monitor, f.state);
    f.runtime.config.monitor.policy.revokeUnconfirmedOnHighConfidence = false;
    expect((await f.runtime.reviewAction('review-this-action')).revokeUnconfirmed).toBe(false);
  });

  it('accepts the typed action-id confirmation before execution', async () => {
    const f = await fixture(); let confirmations = 0;
    expect(await runCli(['approve', 'review-this-action'], { ...f.io, confirmAction: async id => {
      confirmations++; expect(id).toBe('review-this-action'); expect(f.host.writes).toHaveLength(0); return true;
    } })).toBe(0);
    expect(confirmations).toBe(1); expect(f.host.writes).toHaveLength(1);
  });

  it('refuses an action whose revocation choice changed while the human confirmed it', async () => {
    const f = await fixture('auto', true); f.state.pendingActions[0]!.revokeUnconfirmed = false;
    await f.runtime.store.writeJson('monitor', f.runtime.paths.monitor, f.state);
    expect(await runCli(['approve', 'review-this-action'], { ...f.io, confirmAction: async () => {
      expect(f.errors.join('\n')).toContain('revokeUnconfirmed: false');
      f.state.pendingActions[0]!.revokeUnconfirmed = true;
      await f.runtime.store.writeJson('monitor', f.runtime.paths.monitor, f.state); return true;
    } })).toBe(1);
    expect(f.errors.join('\n')).toMatch(/changed after review/i);
    expect(f.host.writes).toHaveLength(0); expect(f.provider.revoked).toHaveLength(0);
  });

  it('uses interactive guided input for approval', async () => {
    const f = await fixture('guided'); const replacement = f.provider.issue('human-created'); let prompts = 0;
    expect(await runCli(['approve', 'review-this-action', '--yes'], { ...f.io, promptIO: tty(), prompt: async () => { prompts++; return replacement.value; } })).toBe(0);
    expect(prompts).toBe(1); expect(f.host.writes).toHaveLength(1); expect(f.provider.revoked).toEqual([f.original.ref]);
  });

  it('uses interactive reveal when an approved atomic roll cannot deliver the replacement', async () => {
    const f = await fixture('atomic-roll'); f.host.failWritesFor.add('api'); let reveals = 0;
    expect(await runCli(['approve', 'review-this-action', '--yes'], { ...f.io, promptIO: tty(), reveal: async (_info, value) => {
      reveals++; expect(f.provider.refOf(value) !== null).toBe(true); return true;
    } })).toBe(1);
    expect(reveals).toBe(1);
    expect([...f.output, ...f.errors].some(line => [...f.provider.keys.values()].some(key => line.includes(key.value)))).toBe(false);
  });

  it('reports operator cancellation during approval and stops without writes', async () => {
    const f = await fixture('guided');
    expect(await runCli(['approve', 'review-this-action', '--yes'], { ...f.io, promptIO: tty(), prompt: async () => { throw new RotationAbortedError(); } })).toBe(1);
    expect(f.errors.join('\n')).toContain('aborted, no further changes'); expect(f.host.writes).toHaveLength(0);
  });

  it('reports operator cancellation during rotate with exit status one', async () => {
    const f = await fixture('guided');
    expect(await runCli(['rotate', '--execute', '--yes'], { ...f.io, prompt: async () => { throw new RotationAbortedError(); } })).toBe(1);
    expect(f.errors.join('\n')).toContain('aborted, no further changes'); expect(f.host.writes).toHaveLength(0);
  });

  it('scans hosts once per monitor poll and reuses that inventory', async () => {
    const f = await fixture(); let scans = 0; const list = f.host.listServices.bind(f.host);
    f.host.listServices = async () => { scans++; return list(); };
    await f.runtime.monitorOnce(); expect(scans).toBe(1);
    const saved = (await f.runtime.store.loadInventory())!;
    expect(saved.clusters).toHaveLength(1);
  });

  it('honors an explicit disabled reveal instead of inheriting a runtime callback', async () => {
    const f = await fixture('atomic-roll'); let reveals = 0;
    const runtime = await createRuntime({ cwd: f.runtime.config.cwd, hosts: [f.host], env: {}, http: new FakeHttp(), log: silentLogger, feeds: [],
      providers: id => id === f.provider.id ? f.provider : getProvider(id), reveal: async () => { reveals++; return true; }, sleep: async () => {} });
    const report = await runtime.rotate(await runtime.plan(), { execute: true, reveal: undefined });
    expect(reveals).toBe(0); expect(f.provider.keys.size).toBe(1); expect(report.steps[0]?.status).toBe('skipped');
  });
});
