import { expect, test } from 'vitest';
import { executePlan, finishRotation } from '../../src/rotate/index.js';
import { recoveryFixture } from './recovery-fixture.js';

test.each([false, true])('finish preserves unresolved orphan reports and recovery data after failed storage (stop=%s)', async stopOnFirstFailure => {
  const h = await recoveryFixture();
  h.plan.steps = h.plan.steps.filter(step => step.provider === 'openai');
  await h.inflight.put(h.plan.id, `old:${h.clusterId}`, h.old.value);
  h.inflight.put = async () => { throw new Error('temporary storage unavailable'); };
  h.provider.revoke = async () => { throw new Error('cleanup unavailable'); };
  const options = { ...h.opts, stopOnFirstFailure };
  const failed = await executePlan(h.plan, h.inventory, h.deps, options);
  expect(failed.status).toBe('partial');
  expect(failed.orphanSuspects).toHaveLength(1);

  const report = await finishRotation({ plan: h.plan, inventory: h.inventory, entries: [...h.journal.entries] }, h.deps, options);

  expect(report.status).toBe('partial');
  expect(report.orphanSuspects).toEqual(failed.orphanSuspects);
  expect(h.inflight.shredded.has(h.plan.id)).toBe(false);
  expect(await h.inflight.get(h.plan.id, `old:${h.clusterId}`)).toBe(h.old.value);
  expect(h.host.writes).toEqual([]);
  expect(h.journal.entries.at(-1)?.data?.pending).toBe(true);
});

test('finish may shred after an unused orphan has a recorded successful cleanup', async () => {
  const h = await recoveryFixture();
  h.plan.steps = h.plan.steps.filter(step => step.provider === 'openai');
  const result = await h.provider.rotate(h.old.value, h.deps.providerCtx);
  await h.inflight.put(h.plan.id, `old:${h.clusterId}`, h.old.value);
  await h.journal.append({ at: h.deps.now!().toISOString(), planId: h.plan.id, event: 'orphan-suspected', clusterId: h.clusterId,
    data: { keyRef: result.newKeyRef } });
  await h.provider.revoke(result.newKeyRef!, h.deps.providerCtx);
  await h.journal.append({ at: h.deps.now!().toISOString(), planId: h.plan.id, event: 'revoked', clusterId: h.clusterId,
    data: { keyRef: result.newKeyRef, cleanup: true } });

  const report = await finishRotation({ plan: h.plan, inventory: h.inventory, entries: [...h.journal.entries] }, h.deps, h.opts);

  expect(report.status).toBe('failed');
  expect(report.orphanSuspects ?? []).toEqual([]);
  expect(h.inflight.shredded.has(h.plan.id)).toBe(true);
  expect(h.provider.keys.get(result.newKeyRef!)!.active).toBe(false);
  expect(h.host.writes).toEqual([]);
});
