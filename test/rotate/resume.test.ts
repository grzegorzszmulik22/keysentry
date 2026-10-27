import { describe, expect, it } from 'vitest';
import { executePlan, resumeRotation } from '../../src/rotate/index.js';
import { RotationAbortedError } from '../../src/types.js';
import { recoveryFixture } from './recovery-fixture.js';

describe('resumeRotation', () => {
  it('skips writes already applied and polls the journalled deployment', async () => {
    const f = await recoveryFixture();
    const stopped = new Error('process exit');
    f.deps.crashHook = point => { if (point === 'after-deploy-result') throw stopped; };
    await expect(executePlan(f.plan, f.inventory, f.deps, f.opts)).rejects.toBe(stopped);
    expect(f.host.writes).toHaveLength(2);
    const started = f.journal.entries.filter(entry => entry.event === 'redeploy');
    expect(started.length).toBeGreaterThan(0);
    delete f.deps.crashHook;
    const writes = f.host.writes.length;
    const traceStart = f.trace.length;
    const report = await resumeRotation({ plan: f.plan, inventory: f.inventory, entries: [...f.journal.entries] }, f.deps, f.opts);
    expect(report.status).toBe('complete');
    expect(f.host.writes).toHaveLength(writes);
    for (const entry of started) {
      const service = f.services.find(service => f.serviceKeys[f.services.indexOf(service)] === entry.serviceKey)!;
      expect(f.host.redeploys.filter(id => id === service.serviceId)).toHaveLength(1);
      expect(f.trace.slice(traceStart)).toContain(`poll:${service.serviceId}:${String(entry.data?.deploymentId)}`);
    }
    expect(f.journal.entries.some(entry => entry.event === 'written' && entry.data?.resumed === true)).toBe(true);
  });

  it('resume after after-revoke does not call revoke twice', async () => {
    const f = await recoveryFixture();
    const stopped = { stopped: true };
    f.deps.crashHook = point => { if (point === 'after-revoke') throw stopped; };
    await expect(executePlan(f.plan, f.inventory, f.deps, f.opts)).rejects.toBe(stopped);
    expect(f.provider.revoked).toEqual([f.old.ref]);
    delete f.deps.crashHook;
    const report = await resumeRotation({ plan: f.plan, inventory: f.inventory, entries: [...f.journal.entries] }, f.deps, f.opts);
    expect(report.status).toBe('complete');
    expect(f.provider.revoked).toEqual([f.old.ref]);
    expect(f.journal.entries.some(entry => entry.event === 'revoked' && entry.clusterId === f.clusterId && entry.data?.alreadyRevoked === true)).toBe(true);
  });

  it('plans already ended with nothing pending return their final status without calls', async () => {
    const f = await recoveryFixture();
    const original = await executePlan(f.plan, f.inventory, f.deps, f.opts);
    const trace = [...f.trace];
    const calls = [...f.inflight.calls];
    const report = await resumeRotation({ plan: f.plan, inventory: f.inventory, entries: [...f.journal.entries] }, f.deps, f.opts);
    expect(report.status).toBe(original.status);
    expect(f.trace).toEqual(trace);
    expect(f.inflight.calls).toEqual(calls);
  });

  it('an interrupted prompt keeps abort behavior and sets a status', async () => {
    const f = await recoveryFixture();
    // A guided plan cannot begin creating unrelated credentials after Ctrl-C.
    f.plan.steps[0]!.method = 'guided';
    f.deps.prompt = async () => { throw new RotationAbortedError(); };
    const report = await executePlan(f.plan, f.inventory, f.deps, f.opts);
    expect(report.status).toBe('failed');
    expect(f.host.writes).toEqual([]);
    expect(f.host.redeploys).toEqual([]);
    expect(f.provider.keys.size).toBe(1);
    expect(f.generate.keys.size).toBe(1);
    expect(f.provider.revoked).toEqual([]);
    expect(f.inflight.shredded.has(f.plan.id)).toBe(true);
    expect(f.journal.entries.at(-1)?.event).toBe('plan-end');
  });

  it('a hook error during resume leaves immediately without a failure entry or cleanup', async () => {
    const f = await recoveryFixture();
    const first = { first: true };
    f.deps.crashHook = point => { if (point === 'after-store') throw first; };
    await expect(executePlan(f.plan, f.inventory, f.deps, f.opts)).rejects.toBe(first);
    const stopped = { resumed: true };
    let atCrash: string[] = [];
    f.deps.crashHook = point => { if (point === 'after-write') { atCrash = [...f.trace]; throw stopped; } };
    await expect(resumeRotation({ plan: f.plan, inventory: f.inventory, entries: [...f.journal.entries] }, f.deps, f.opts)).rejects.toBe(stopped);
    expect(f.trace).toEqual(atCrash);
    expect(f.inflight.shredded.has(f.plan.id)).toBe(false);
    expect(f.host.redeploys).toEqual([]);
    expect(f.provider.revoked).toEqual([]);
  });
});
