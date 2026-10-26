import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createRuntime } from '../../src/cli/runtime.js';
import { runCli } from '../../src/cli/index.js';
import { RotationAbortedError, type RotationReport } from '../../src/types.js';
import { getProvider } from '../../src/providers/index.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';

const directories: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
});

async function fixture(method: 'auto' | 'atomic-roll' | 'guided' = 'atomic-roll') {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-abort-round3-')); directories.push(cwd);
  const host = new FakeHost('railway'); host.pendingPolls = 1;
  const provider = new FakeProvider(method === 'atomic-roll' ? 'cloudflare' : method === 'guided' ? 'stripe' : 'openrouter', method,
    method === 'atomic-roll' ? 'cf-f9G7k6R2a4D0p8W5b3H1j9C6e2M4x7U8-' : method === 'guided' ? 'sk_live_0123456789abcdef' : 'sk-or-v1-0123456789abcdef');
  const variable = method === 'atomic-roll' ? 'CLOUDFLARE_API_TOKEN' : method === 'guided' ? 'STRIPE_SECRET_KEY' : 'OPENROUTER_API_KEY';
  const originals = ['a', 'b', 'c'].map(service => {
    const key = provider.issue(); host.addService(service, { [variable]: key.value }); return key;
  });
  const runtime = await createRuntime({ cwd, env: {}, hosts: [host], providers: id => id === provider.id ? provider : getProvider(id),
    http: new FakeHttp(), log: silentLogger, feeds: [], sleep: async () => {} });
  const inv = await runtime.scan();
  const plan = await runtime.plan({ clusterIds: inv.clusters.map(cluster => cluster.id) });
  plan.steps.sort((left, right) => left.consumers[0]!.service.serviceId.localeCompare(right.consumers[0]!.service.serviceId));
  const report = async () => JSON.parse(await readFile(join(runtime.paths.dir, 'rotation-report.json'), 'utf8')) as RotationReport;
  const assertSecretFree = async (extra: unknown) => {
    const metadata = JSON.stringify(extra) + await readFile(join(runtime.paths.dir, 'rotation-report.json'), 'utf8') + await readFile(runtime.paths.journal, 'utf8');
    for (const key of provider.keys.values()) expect(metadata.includes(key.value)).toBe(false);
  };
  return { runtime, host, provider, originals, variable, plan, report, assertSecretFree };
}

function tty() {
  const stream = Object.assign(new PassThrough(), { isTTY: true, isRaw: false, setRawMode(value: boolean) { this.isRaw = value; return this; } });
  return { input: stream as unknown as NodeJS.ReadStream, output: { isTTY: true, write: () => true } };
}

describe('round 3 cancellation drains already-created replacements', () => {
  it('offers the second unwritten roll after Ctrl-C declines only the first reveal', async () => {
    const f = await fixture(); f.host.failWritesFor.add('a'); f.host.failWritesFor.add('b');
    const reveals: string[] = [];
    await expect(f.runtime.rotate(f.plan, { execute: true, reveal: async info => {
      reveals.push(info.clusterId);
      if (reveals.length === 1) throw new RotationAbortedError();
      return true;
    } })).rejects.toBeInstanceOf(RotationAbortedError);

    expect(reveals).toEqual([f.plan.steps[0]!.clusterId, f.plan.steps[1]!.clusterId]);
    expect(f.provider.keys.size).toBe(6);
    expect(f.host.writes.map(write => write.serviceId)).toEqual(['c']);
    expect(f.host.redeploys).toEqual(['c']);
    const report = await f.report();
    expect(report.steps[0]!.error).toMatch(/ROLLED VALUE LOST/);
    expect(report.steps[1]!.error).toMatch(/replacement was revealed/i);
    expect(report.deployments).toContainEqual(expect.objectContaining({ serviceKey: 'railway:proj1/production/c', state: 'success' }));
    await f.assertSecretFree(report);
  });

  it('redeploys both services already staged when the other rolled value is declined', async () => {
    const f = await fixture(); f.host.failWritesFor.add('a');
    await expect(f.runtime.rotate(f.plan, { execute: true, reveal: async () => { throw new RotationAbortedError(); } }))
      .rejects.toBeInstanceOf(RotationAbortedError);

    expect(f.host.writes.map(write => write.serviceId).sort()).toEqual(['b', 'c']);
    expect(f.host.writes.every(write => write.skipDeploy)).toBe(true);
    expect([...f.host.redeploys].sort()).toEqual(['b', 'c']);
    expect((await f.report()).deployments.filter(deploy => deploy.state === 'success')).toHaveLength(2);
    await f.assertSecretFree(await f.report());
  });

  it.each(['auto', 'atomic-roll'] as const)('delivers an earlier %s result after Ctrl-C at a late guided fallback, without another provider mutation', async method => {
    const f = await fixture(method);
    const rotate = f.provider.rotate.bind(f.provider);
    const attempts: string[] = [];
    vi.spyOn(f.provider, 'rotate').mockImplementation(async (old, ctx) => {
      attempts.push(old);
      if (old === f.originals[1]!.value) throw Object.assign(new Error('manual rotation required'), { code: 'GUIDED_ROTATION_REQUIRED' });
      return rotate(old, ctx);
    });
    let prompts = 0;
    await expect(f.runtime.rotate(f.plan, { execute: true, prompt: async () => { prompts++; throw new RotationAbortedError(); }, reveal: async () => true }))
      .rejects.toBeInstanceOf(RotationAbortedError);

    expect(prompts).toBe(1);
    expect(attempts).toEqual([f.originals[0]!.value, f.originals[1]!.value]);
    expect(f.provider.keys.size).toBe(4);
    expect(f.provider.revoked).toEqual([]);
    expect(f.provider.capped).toEqual([]);
    expect(f.host.writes.length).toBeGreaterThan(0);
    expect(f.host.writes.every(write => write.serviceId === 'a' && write.skipDeploy)).toBe(true);
    expect(f.host.redeploys).toEqual(['a']);
    expect(f.host.peek('a', f.variable)).not.toBe(f.originals[0]!.value);
    expect(f.provider.keys.get(f.originals[2]!.ref)!.active).toBe(true);
    expect((await f.report()).steps.slice(1).map(step => step.status)).toEqual(['skipped', 'skipped']);
    await f.assertSecretFree(await f.report());
  });

  it('skips the fallback prompt and later provider rolls when preservation reveal is cancelled', async () => {
    const f = await fixture(); f.host.failWritesFor.add('a');
    const rotate = f.provider.rotate.bind(f.provider);
    const attempts: string[] = [];
    vi.spyOn(f.provider, 'rotate').mockImplementation(async (old, ctx) => {
      attempts.push(old);
      if (old === f.originals[1]!.value) throw Object.assign(new Error('manual rotation required'), { code: 'GUIDED_ROTATION_REQUIRED' });
      return rotate(old, ctx);
    });
    let prompts = 0; let reveals = 0;
    await expect(f.runtime.rotate(f.plan, { execute: true, prompt: async () => { prompts++; return null; },
      reveal: async () => { reveals++; throw new RotationAbortedError(); } })).rejects.toBeInstanceOf(RotationAbortedError);

    expect(prompts).toBe(0);
    expect(reveals).toBe(1);
    expect(attempts).toEqual([f.originals[0]!.value, f.originals[1]!.value]);
    expect(f.provider.keys.size).toBe(4);
    expect(f.host.redeploys).toEqual([]);
    expect((await f.report()).steps[0]!.error).toMatch(/ROLLED VALUE LOST/);
    await f.assertSecretFree(await f.report());
  });

  it('clears final value-loss accounting when delivery succeeds after a cancelled preservation reveal', async () => {
    const f = await fixture();
    const rotate = f.provider.rotate.bind(f.provider);
    vi.spyOn(f.provider, 'rotate').mockImplementation(async (old, ctx) => {
      if (old === f.originals[1]!.value) throw Object.assign(new Error('manual rotation required'), { code: 'GUIDED_ROTATION_REQUIRED' });
      return rotate(old, ctx);
    });
    const write = f.host.writeVariables.bind(f.host);
    let attempts = 0;
    vi.spyOn(f.host, 'writeVariables').mockImplementation(async (...args) => {
      if (args[0].serviceId === 'a' && ++attempts <= 4) throw new Error('transient write failure');
      await write(...args);
    });
    let reveals = 0; let prompts = 0;
    await expect(f.runtime.rotate(f.plan, { execute: true,
      prompt: async () => { prompts++; return null; },
      reveal: async () => { reveals++; throw new RotationAbortedError(); },
    })).rejects.toBeInstanceOf(RotationAbortedError);

    expect(attempts).toBe(5);
    expect(prompts).toBe(0); expect(reveals).toBe(1);
    expect(f.host.writes.map(write => write.serviceId)).toEqual(['a']);
    expect(f.host.redeploys).toEqual(['a']);
    const report = await f.report();
    expect(report.steps[0]!.error).toBeUndefined();
    expect(report.steps[0]!.status).not.toBe('failed');
    expect(report.steps.filter(step => step.error?.includes('ROLLED VALUE LOST'))).toEqual([]);
    expect(report.deployments).toContainEqual(expect.objectContaining({ serviceKey: 'railway:proj1/production/a', state: 'success' }));
    await f.assertSecretFree(report);
  });

  it('deploys a preserved roll even when redundant writes fail after cancellation at the fallback prompt', async () => {
    const f = await fixture();
    const rotate = f.provider.rotate.bind(f.provider);
    const rotations: string[] = [];
    vi.spyOn(f.provider, 'rotate').mockImplementation(async (old, ctx) => {
      rotations.push(old);
      if (old === f.originals[1]!.value) throw Object.assign(new Error('manual rotation required'), { code: 'GUIDED_ROTATION_REQUIRED' });
      return rotate(old, ctx);
    });
    const write = f.host.writeVariables.bind(f.host);
    let cancelled = false; let failedRedundantWrites = 0;
    vi.spyOn(f.host, 'writeVariables').mockImplementation(async (...args) => {
      if (cancelled) { failedRedundantWrites++; throw new Error('redundant write failed'); }
      await write(...args);
    });
    await expect(f.runtime.rotate(f.plan, { execute: true,
      prompt: async () => { cancelled = true; throw new RotationAbortedError(); },
      reveal: async () => true,
    })).rejects.toBeInstanceOf(RotationAbortedError);

    expect(cancelled).toBe(true);
    expect(failedRedundantWrites).toBeGreaterThan(0);
    expect(f.host.writes.map(write => write.serviceId)).toEqual(['a']);
    expect(f.host.peek('a', f.variable)).not.toBe(f.originals[0]!.value);
    expect(f.host.redeploys).toEqual(['a']);
    expect(rotations).toEqual([f.originals[0]!.value, f.originals[1]!.value]);
    expect(f.provider.keys.size).toBe(4);
    expect(f.provider.keys.get(f.originals[2]!.ref)!.active).toBe(true);
    const report = await f.report();
    expect(report.steps[0]!.error).toBeUndefined();
    expect(report.steps.filter(step => step.error?.includes('ROLLED VALUE LOST'))).toEqual([]);
    expect(report.deployments).toContainEqual(expect.objectContaining({ serviceKey: 'railway:proj1/production/a', state: 'success' }));
    await f.assertSecretFree(report);
  });

  it('accepts SHOW on the remaining actual terminal reveal after Ctrl-C, without leaking either value to metadata', async () => {
    const f = await fixture(); f.host.failWritesFor.add('a'); f.host.failWritesFor.add('b');
    const input = Object.assign(new PassThrough(), { isTTY: true, isRaw: false, setRawMode(value: boolean) { this.isRaw = value; return this; } });
    const terminal: string[] = []; const output: string[] = []; const diagnostics: string[] = [];
    let reveals = 0;
    expect(await runCli(['rotate', '--execute', '--yes'], {
      runtime: f.runtime,
      promptIO: { input: input as unknown as NodeJS.ReadStream, output: { isTTY: true, write: text => { terminal.push(text); return true; } } },
      output: text => output.push(text),
      error: text => {
        diagnostics.push(text);
        if (text.includes('Type SHOW')) {
          reveals++;
          queueMicrotask(() => input.write(reveals === 1 ? '\x03' : 'SHOW\r'));
        }
      },
    })).toBe(1);

    expect(reveals).toBe(2);
    const replacements = [...f.provider.keys.values()].filter(key => key.name.startsWith('rotated'));
    expect(replacements).toHaveLength(3);
    const visible = replacements.filter(key => terminal.join('').includes(key.value));
    expect(visible).toHaveLength(1);
    expect(terminal.filter(text => text.includes(visible[0]!.value))).toHaveLength(1);
    const report = await f.report();
    expect(report.steps.find(step => step.error?.includes('replacement was revealed'))!.newKeyRef).toBe(visible[0]!.ref);
    expect(report.steps.find(step => step.error?.includes('ROLLED VALUE LOST'))!.newKeyRef).not.toBe(visible[0]!.ref);
    expect(f.host.redeploys).toEqual(['c']);
    expect(input.isRaw).toBe(false); expect(input.listenerCount('data')).toBe(0);
    await f.assertSecretFree({ output, diagnostics });
  });

  it.each(['failed-deploy', 'no-redeploy'] as const)('prints staged, redeployed, lost values and services awaiting deployment after cancellation (%s)', async failure => {
    const f = await fixture(); f.host.failWritesFor.add('a'); f.host.failWritesFor.add('b');
    if (failure === 'failed-deploy') f.host.failDeploysFor.add('c');
    const output: string[] = []; const diagnostics: string[] = []; let reveals = 0;
    const code = await runCli(['rotate', '--execute', '--yes', ...(failure === 'no-redeploy' ? ['--no-redeploy', '--revoke-unconfirmed'] : [])], {
      runtime: f.runtime, promptIO: tty(), output: text => output.push(text), error: text => diagnostics.push(text),
      reveal: async () => { if (++reveals === 1) throw new RotationAbortedError(); return true; },
    });

    expect(code).toBe(1);
    expect(reveals).toBe(2);
    const text = [...output, ...diagnostics].join('\n');
    expect(text).toMatch(/staged services:[^\n]*c/i);
    expect(text).toMatch(/redeployed services:/i);
    expect(text).toMatch(/staged.but.not.deployed services:[^\n]*c/i);
    expect(text).toMatch(/ROLLED VALUE LOST/);
    expect(text).toContain((await f.report()).steps.find(step => step.error?.includes('ROLLED VALUE LOST'))!.clusterId);
    expect(text).not.toContain('aborted, no further changes');
    await f.assertSecretFree(text);
  });

  it('cancels before any provider result without host writes, deployment, or provider mutation', async () => {
    const f = await fixture('guided'); let prompts = 0;
    await expect(f.runtime.rotate(f.plan, { execute: true, prompt: async () => { prompts++; throw new RotationAbortedError(); } }))
      .rejects.toBeInstanceOf(RotationAbortedError);
    expect(prompts).toBe(1);
    expect(f.host.writes).toEqual([]); expect(f.host.redeploys).toEqual([]);
    expect(f.provider.keys.size).toBe(3); expect(f.provider.revoked).toEqual([]); expect(f.provider.capped).toEqual([]);
    expect((await f.report()).steps.every(step => step.status === 'skipped')).toBe(true);
    await f.assertSecretFree(await f.report());
  });
});
