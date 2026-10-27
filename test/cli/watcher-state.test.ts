import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, test } from 'vitest';
import { createStateCipher, createStateStore } from '../../src/core/index.js';
import type { StateKind } from '../../src/core/store.js';
import { createWatcherStateStore } from '../../src/cli/watcher-state.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });

async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), 'keysentry-watcher-state-cli-')); dirs.push(dir);
  const raw = createStateStore({ cwd: dir, cipher: createStateCipher(Buffer.alloc(32, 27)) });
  const store = createWatcherStateStore(raw, true);
  return { raw, store, file: (name: string) => join(raw.paths.dir, name) };
}

const records: [string, StateKind][] = [
  ['autopilot.json', 'plan'], ['watcher-tick.json', 'plan'], ['watcher-recovery.json', 'plan'],
  ['watcher-incidents.json', 'plan'], ['watcher-relay.json', 'pending'], ['approvals.json', 'pending'],
  ['watcher-approvals.json', 'pending'], ['watcher-feeds.json', 'plan'], ['watcher-check.json', 'plan'],
  ['watcher-activation.json', 'plan'], ['monitor.json', 'monitor'],
];

test.each(records)('Actions state authenticates an increasing sequence with %s', async (name, kind) => {
  const f = await fixture(); const file = f.file(name);
  expect(await f.store.readJson(kind, file)).toBeNull();
  await f.store.writeJson(kind, file, { marker: 'first' });
  expect(await f.raw.readJson(kind, file)).toEqual({ type: 'keysentry-watcher-state', v: 1, sequence: 1, data: { marker: 'first' } });
  await f.store.writeJson(kind, file, { marker: 'second' });
  expect(await f.raw.readJson(kind, file)).toMatchObject({ sequence: 2, data: { marker: 'second' } });
  expect(await f.store.readJson(kind, file)).toEqual({ marker: 'second' });
  expect(await readFile(file, 'utf8')).not.toContain('marker');
});

test('Actions wrapper and its sequence guards are shared across repeated construction', async () => {
  const f = await fixture();
  expect(createWatcherStateStore(f.raw, true)).toBe(f.store);
  expect(createWatcherStateStore(f.store, true)).toBe(f.store);
  const file = f.file('autopilot.json');
  await f.store.writeJson('plan', file, { disarmed: false });
  const older = await readFile(file);
  await createWatcherStateStore(f.raw, true).writeJson('plan', file, { disarmed: true });
  await writeFile(file, older);
  await expect(createWatcherStateStore(f.raw, true).readJson('plan', file)).rejects.toThrow('Saved watcher state could not be verified. Automatic actions are paused.');
  await expect(createWatcherStateStore(f.store, true).writeJson('plan', file, { disarmed: false })).rejects.toThrow('Saved watcher state could not be verified. Automatic actions are paused.');
  expect(await readFile(file)).toEqual(older);
});

test('Actions wrapper refuses a missing observed record instead of creating empty replacement state', async () => {
  const f = await fixture(); const file = f.file('watcher-relay.json');
  await f.store.writeJson('pending', file, { cursor: 'one', pendingDisarms: [] });
  await rm(file);
  await expect(f.store.readJson('pending', file)).rejects.toThrow(/state could not be verified/);
  await expect(f.store.writeJson('pending', file, { cursor: null })).rejects.toThrow(/state could not be verified/);
  expect(await f.raw.readJson('pending', file)).toBeNull();
});

test.skipIf(process.platform !== 'win32')('Windows path case aliases cannot bypass the same sequence guard', async () => {
  const f = await fixture(); const file = f.file('watcher-tick.json');
  await f.store.writeJson('plan', file, { phase: 'old' });
  const older = await readFile(file);
  await f.store.writeJson('plan', file, { phase: 'new' });
  await writeFile(file, older);
  await expect(f.store.readJson('plan', file.toUpperCase())).rejects.toThrow(/state could not be verified/);
});

test.each([
  { disarmed: false },
  { type: 'keysentry-watcher-state', v: 1, sequence: 0, data: { disarmed: false } },
  { type: 'keysentry-watcher-state', v: 2, sequence: 1, data: { disarmed: false } },
])('Actions wrapper refuses legacy or malformed cached records without overwriting them', async payload => {
  const f = await fixture(); const file = f.file('autopilot.json');
  await f.raw.writeJson('plan', file, payload);
  const original = await readFile(file);
  await expect(f.store.readJson('plan', file)).rejects.toThrow(/state could not be verified/);
  await expect(f.store.writeJson('plan', file, { disarmed: true })).rejects.toThrow(/state could not be verified/);
  expect(await readFile(file)).toEqual(original);
});

test('Actions wrapper does not replace corrupt authenticated state even when replacement is requested', async () => {
  const f = await fixture(); const file = f.file('watcher-recovery.json');
  await f.store.writeJson('plan', file, { requiresResume: false });
  const original = await readFile(file, 'utf8');
  const lines = original.split('\n'); const bytes = Buffer.from(lines[1]!, 'base64'); bytes[bytes.length - 1]! ^= 1;
  lines[1] = bytes.toString('base64'); const corrupted = lines.join('\n');
  await writeFile(file, corrupted);
  await expect(f.store.readJson('plan', file)).rejects.toThrow(/state could not be verified/);
  await expect(f.store.writeJson('plan', file, { requiresResume: false }, { replaceUndecryptable: true })).rejects.toThrow(/state could not be verified/);
  expect(await readFile(file, 'utf8')).toBe(corrupted);
});

test('ordinary local stores and unrelated Actions records keep their original formats and methods', async () => {
  const f = await fixture();
  expect(createWatcherStateStore(f.raw, false)).toBe(f.raw);
  const localFile = f.file('local-approval.json');
  await f.raw.writeJson('pending', localFile, { marker: 'local' });
  expect(await f.store.readJson('pending', localFile)).toEqual({ marker: 'local' });
  await f.store.writeJson('plan', f.file('armed-plan.json'), { id: 'armed-plan' });
  expect(await f.raw.readJson('plan', f.file('armed-plan.json'))).toEqual({ id: 'armed-plan' });
  expect(f.store.paths).toBe(f.raw.paths);
  expect(await f.store.loadInventory()).toBeNull();
  expect(await f.store.journal().read()).toEqual([]);
  expect(await f.store.migratePlaintext()).toEqual({ migrated: [] });
});
