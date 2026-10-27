import { describe, expect, it } from 'vitest';
import { executePlan, resumeRotation } from '../../src/rotate/index.js';
import type { CrashPoint } from '../../src/types.js';
import { recoveryFixture } from './recovery-fixture.js';

const points: CrashPoint[] = ['after-store', 'after-write', 'after-redeploy', 'after-deploy-result', 'after-verify', 'before-revoke', 'after-revoke'];

describe('rotation crash recovery', () => {
  it.each(points)('crash at %s then resume converges', async point => {
    const f = await recoveryFixture();
    const stopped = { point };
    let atCrash: string[] = [];
    f.deps.crashHook = (current, detail) => {
      if (current !== point) return;
      expect(detail.clusterId ?? detail.serviceKey).toBeDefined();
      atCrash = [...f.trace];
      throw stopped;
    };
    await expect(executePlan(f.plan, f.inventory, f.deps, f.opts)).rejects.toBe(stopped);
    // The hook represents process death: even failure handling must stop here.
    expect(f.trace).toEqual(atCrash);
    expect(f.journal.entries.at(-1)?.event).not.toBe('plan-end');
    expect(f.inflight.shredded.has(f.plan.id)).toBe(false);
    delete f.deps.crashHook;
    const entries = [...f.journal.entries];
    const before = f.journal.entries.length;
    const report = await resumeRotation({ plan: f.plan, inventory: f.inventory, entries }, f.deps, f.opts);
    expect(f.journal.entries[before]?.event).toBe('resume');
    expect(report.status).toBe('complete');
    expect(f.host.writes).toHaveLength(2);
    for (const [name, provider, old] of [
      ['OPENAI_API_KEY', f.provider, f.old], ['SESSION_SECRET', f.generate, f.oldGenerated],
    ] as const) {
      const values = f.services.map(service => f.host.peek(service.serviceId, name));
      expect(values[0]).toBeDefined();
      expect(values[0]).not.toBe(old.value);
      expect(values[1]).toBe(values[0]);
      expect([...provider.keys.values()].filter(key => key.active)).toHaveLength(1);
      expect(provider.keys.get(old.ref)?.active).toBe(false);
      expect(provider.keys.size).toBe(2);
      const revocation = f.revocations.find(item => item.provider === provider.id && item.keyRef === old.ref)!;
      expect(revocation).toBeDefined();
      expect(revocation.deployed.sort()).toEqual(['api', 'worker']);
      expect(revocation.current).toEqual(values);
    }
    expect(f.inflight.shredded.has(f.plan.id)).toBe(true);
    expect(f.journal.entries.at(-1)?.event).toBe('plan-end');
    const serialized = JSON.stringify({ journal: f.journal.entries, report, logs: f.lines });
    for (const value of f.storedValues) expect(serialized).not.toContain(value);
  });

  it('crash at after-create reports an orphan suspect and revokes nothing for that cluster', async () => {
    const f = await recoveryFixture();
    const stopped = new Error('simulated process exit');
    f.deps.crashHook = point => { if (point === 'after-create') throw stopped; };
    await expect(executePlan(f.plan, f.inventory, f.deps, f.opts)).rejects.toBe(stopped);
    expect(await f.inflight.get(f.plan.id, `new:${f.clusterId}`)).toBeNull();
    const unrecorded = [...f.provider.keys.values()].find(key => key.ref !== f.old.ref)!;
    delete f.deps.crashHook;
    const report = await resumeRotation({ plan: f.plan, inventory: f.inventory, entries: [...f.journal.entries] }, f.deps, f.opts);
    expect(report.status).toBe('partial');
    expect(report.orphanSuspects).toContainEqual({ clusterId: f.clusterId, provider: 'openai', keyRef: unrecorded.ref, createdAt: unrecorded.createdAt });
    const step = report.steps.find(step => step.clusterId === f.clusterId)!;
    expect(step.status).toBe('failed');
    expect(step.error).toContain('A new key may have been created at openai before keysentry could save it.');
    expect(step.error).toContain(f.provider.guidance().url);
    expect(f.provider.revoked).toEqual([]);
    expect(f.provider.keys.size).toBe(2);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(true);
    for (const service of f.services) expect(f.host.peek(service.serviceId, 'OPENAI_API_KEY')).toBe(f.old.value);
    expect(f.journal.entries.some(entry => entry.event === 'orphan-suspected' && entry.clusterId === f.clusterId)).toBe(true);
    expect(f.inflight.shredded.has(f.plan.id)).toBe(false);
  });

  it.each([new Error('process stopped'), { stopped: true }, 'process stopped', null, undefined])('hook failures escape unchanged (%j)', async stopped => {
    const f = await recoveryFixture();
    let atCrash: string[] = [];
    f.deps.crashHook = point => { if (point === 'after-store') { atCrash = [...f.trace]; throw stopped; } };
    let caught = false;
    try { await executePlan(f.plan, f.inventory, f.deps, f.opts); }
    catch (error) { caught = true; expect(error).toBe(stopped); }
    expect(caught).toBe(true);
    expect(f.trace).toEqual(atCrash);
  });

  it('inflight.put is the first awaited call after rotate resolves', async () => {
    const f = await recoveryFixture();
    await executePlan(f.plan, f.inventory, f.deps, f.opts);
    for (const [providerId, clusterId] of [['openai', f.clusterId], ['app-secret', f.generatedClusterId]]) {
      const index = f.trace.indexOf(`rotated:${providerId}`);
      expect(index).toBeGreaterThanOrEqual(0);
      expect(f.trace[index + 1]).toBe(`put:new:${clusterId}`);
    }
  });

  it('a hook crash during an atomic roll never starts rolled-value preservation', async () => {
    const f = await recoveryFixture();
    f.plan.steps[0]!.method = 'atomic-roll';
    const rotate = f.provider.rotate.bind(f.provider);
    f.provider.rotate = async (value, ctx) => {
      const result = await rotate(value, ctx);
      f.provider.revokeUpstream(f.old.ref);
      return { ...result, oldRevoked: true };
    };
    const stopped = { stopped: true };
    let atCrash: string[] = [];
    f.deps.crashHook = (point, detail) => {
      if (point === 'after-store' && detail.clusterId === f.clusterId) { atCrash = [...f.trace]; throw stopped; }
    };
    await expect(executePlan(f.plan, f.inventory, f.deps, f.opts)).rejects.toBe(stopped);
    expect(f.trace).toEqual(atCrash);
    expect(f.host.writes).toEqual([]);
    expect(f.host.redeploys).toEqual([]);
    expect(f.provider.keys.get(f.old.ref)?.active).toBe(false);
  });
});
