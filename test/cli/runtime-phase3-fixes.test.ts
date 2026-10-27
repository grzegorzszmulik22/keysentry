import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, test } from 'vitest';
import { createRuntime } from '../../src/cli/runtime.js';
import { createPhase3Runtime } from '../../src/cli/phase3-runtime.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { getProvider } from '../../src/providers/index.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
async function directory() { const cwd = await mkdtemp(join(tmpdir(), 'keysentry-runtime-p3-fix-')); dirs.push(cwd); return cwd; }
async function fixture() {
  const cwd = await directory();
  const host = new FakeHost('railway'); host.pendingPolls = 0;
  const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-0123456789abcdef');
  host.addService('api', { OPENROUTER_API_KEY: provider.issue().value });
  const runtime = await createRuntime({ cwd, userDir: join(cwd, 'user'), vault: createFakeVault(), inflight: createFakeInFlight(),
    env: {}, http: new FakeHttp(), hosts: [host], providers: id => id === provider.id ? provider : getProvider(id),
    log: silentLogger, stdinIsTTY: true, stdoutIsTTY: true, grace: async () => 'defer', sleep: async () => {}, firstRunGit: async () => ({ code: 0 }) });
  await runtime.scan();
  return { cwd, runtime, host };
}

test('preview and drill keep reports for a real rotation waiting in grace', async () => {
  const { runtime: rt } = await fixture();
  const plan = await rt.plan();
  const report = await rt.rotate(plan, { execute: true });
  expect(report.status).toBe('grace-pending');
  const preview = await rt.plan(undefined, { preview: true });
  await rt.rotate(preview);
  await rt.drill();
  expect(await rt.rotationReport(plan.id)).toEqual(report);
  expect(await rt.store.readJson('report', join(rt.paths.dir, 'reports', `${plan.id}.json`))).toEqual(report);
  expect(await rt.store.readJson('report', join(rt.paths.dir, 'rotation-report.json'))).toEqual(report);
});

test('previewing the same saved plan also preserves its real rotation report', async () => {
  const { runtime: rt } = await fixture();
  const plan = await rt.plan();
  const report = await rt.rotate(plan, { execute: true });
  await rt.rotate(plan);
  expect(await rt.rotationReport(plan.id)).toEqual(report);
});

test('a dry-run preview records one previewed audit event and no journal lifecycle', async () => {
  const { runtime: rt } = await fixture();
  const before = (await readFile(rt.paths.audit, 'utf8')).trim().split('\n').length;
  const preview = await rt.plan(undefined, { preview: true });
  await rt.rotate(preview);
  const events = (await readFile(rt.paths.audit, 'utf8')).trim().split('\n').slice(before).map(line => JSON.parse(line));
  // Signed checkpoints protect the audit itself; there is only one action event.
  expect(events.filter(event => event.kind !== 'checkpoint').map(event => event.kind)).toEqual(['previewed']);
  expect((await rt.store.journal().read()).filter(entry => entry.planId === preview.id)).toEqual([]);
});

test('manual rotation cards use a routine platform label without claiming an incident', async () => {
  const { runtime: rt } = await fixture();
  const plan = await rt.plan(); await rt.rotate(plan, { execute: true }); await rt.finish(plan.id, true);
  const card = await createPhase3Runtime(rt).card({ platform: true, counts: true });
  expect(card.svg).toContain('rotated 1 keys');
  expect(card.svg).toContain('rotated on Railway');
  expect(card.svg).not.toMatch(/incident/i);
});

test('a card attributes an incident only to a matching rotation wave and platform', async () => {
  const { runtime: rt } = await fixture();
  const plan = await rt.plan(); await rt.rotate(plan, { execute: true }); await rt.finish(plan.id, true);
  await rt.autopilotManager().saveState({ armedPlanId: null, disarmed: true, waves: [{ id: 'wave-one', planId: plan.id,
    incidentId: 'incident-one', startedAt: new Date().toISOString(), status: 'done' }] });
  const incident = { id: 'incident-one', host: 'railway', openedAt: new Date().toISOString(), evidence: [], status: 'closed' };
  await rt.store.writeJson('plan', join(rt.paths.dir, 'watcher-incidents.json'), { incidents: [incident] });
  expect((await createPhase3Runtime(rt).card({ platform: true, counts: false })).svg).toContain('after the Railway incident');
  await rt.store.writeJson('plan', join(rt.paths.dir, 'watcher-incidents.json'), { incidents: [{ ...incident, host: 'vercel' }] });
  expect((await createPhase3Runtime(rt).card({ platform: true, counts: false })).svg).not.toContain('incident');
  expect((await createPhase3Runtime(rt).card({ platform: false, counts: true })).svg).not.toContain('Railway');
});

test.each([false, true])('container runtime uses writable state/user or the explicit user directory (%s)', async explicit => {
  const cwd = await directory(), state = join(cwd, 'state'), user = join(cwd, 'custom-user');
  const rt = await createRuntime({ cwd, env: { KEYSENTRY_STATE_DIR: state, ...(explicit ? { KEYSENTRY_USER_DIR: user } : {}) },
    vault: createFakeVault(), inflight: createFakeInFlight(), hosts: [], http: new FakeHttp(), log: silentLogger });
  expect(rt.userDir).toBe(explicit ? user : join(state, 'user'));
});

test('directory preparation errors name the path and the setting to change', async () => {
  const cwd = await directory(), invalid = join(cwd, 'blocked'); await writeFile(invalid, 'a file occupies this directory');
  await expect(createRuntime({ cwd, env: { KEYSENTRY_USER_DIR: invalid }, vault: createFakeVault(), hosts: [],
    http: new FakeHttp(), log: silentLogger })).rejects.toThrow(`Could not prepare the directory ${invalid}. Set KEYSENTRY_USER_DIR to a writable directory.`);
  const parent = join(cwd, 'state-parent'); await mkdir(parent); await writeFile(join(parent, '.keysentry'), 'blocked');
  await expect(createRuntime({ cwd: parent, userDir: join(cwd, 'user'), env: {}, vault: createFakeVault(), hosts: [],
    http: new FakeHttp(), log: silentLogger })).rejects.toThrow(`Could not prepare the directory ${join(parent, '.keysentry')}. Set KEYSENTRY_STATE_DIR to a writable directory.`);
});
