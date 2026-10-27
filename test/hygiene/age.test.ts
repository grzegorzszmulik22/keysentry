import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createStateCipher, createStateStore } from '../../src/core/store.js';
import { createMonitorState } from '../../src/monitor/state.js';
import { createHygieneState, createHygieneStateStore, hygieneReport, updateFirstSeen, updateLastRotation } from '../../src/hygiene/age.js';
import { cluster, FIRST, inventory, NOW, SECOND } from './fixtures.js';

const directories: string[] = [];
afterEach(async () => {
  for (const path of directories.splice(0)) {
    expect(resolve(path).startsWith(resolve(tmpdir()))).toBe(true);
    await rm(path, { recursive: true, force: true });
  }
});

describe('key age and encrypted hygiene state', () => {
  it('first-seen survives rescans, disappearance and new keys get today', () => {
    const state = createHygieneState();
    updateFirstSeen(state, inventory(), '2026-07-01T12:00:00.000Z');
    updateFirstSeen(state, inventory([]), '2026-08-01T12:00:00.000Z');
    updateFirstSeen(state, inventory([cluster(), cluster(SECOND)]), NOW);
    expect(state.firstSeen).toEqual({ [FIRST]: '2026-07-01T12:00:00.000Z', [SECOND]: NOW });
    expect(state.settings).toEqual({ rotateEveryDays: 90, spendCapsUsd: {} });
  });

  it('round-trips its own encrypted monitor-kind file without changing monitor state', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'keysentry-hygiene-'));
    directories.push(cwd);
    const key = randomBytes(32);
    const store = createStateStore({ cwd, cipher: createStateCipher(key) });
    const persistence = createHygieneStateStore(store);
    const state = await persistence.load();
    updateFirstSeen(state, inventory(), NOW);
    state.settings.spendCapsUsd.openrouter = 30;
    const monitor = createMonitorState();
    await store.writeJson('monitor', store.paths.monitor, monitor);
    await persistence.save(state);
    expect(await createHygieneStateStore(store).load()).toEqual(state);
    expect(await store.readJson('monitor', store.paths.monitor)).toEqual(monitor);
    const path = join(store.paths.dir, 'hygiene.json');
    const content = await readFile(path, 'utf8');
    expect(content.startsWith('keysentry-encrypted:v1\n')).toBe(true);
    expect(content.includes(FIRST)).toBe(false);
    expect(await store.readJson('monitor', path)).toEqual(state);
    const locked = createHygieneStateStore(createStateStore({ cwd, cipher: createStateCipher(randomBytes(32)) }));
    await expect(locked.load()).rejects.toMatchObject({ code: 'STATE_LOCKED' });
    await expect(locked.save(state)).rejects.toMatchObject({ code: 'STATE_LOCKED' });
    expect(await readFile(path, 'utf8')).toBe(content);
  });

  it('projects only hygiene fields and rejects invalid settings without echoing input', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'keysentry-hygiene-'));
    directories.push(cwd);
    const store = createStateStore({ cwd, cipher: createStateCipher(randomBytes(32)) });
    const persistence = createHygieneStateStore(store);
    const state = Object.assign(createHygieneState(), { value: 'never-save-this-value' });
    await persistence.save(state);
    expect(await store.readJson('monitor', join(store.paths.dir, 'hygiene.json'))).not.toHaveProperty('value');
    state.settings.rotateEveryDays = 0;
    await expect(persistence.save(state)).rejects.toThrow('Invalid hygiene state.');
    state.settings.rotateEveryDays = 90;
    state.settings.spendCapsUsd.openrouter = Infinity;
    await expect(persistence.save(state)).rejects.toThrow('Invalid hygiene state.');
  });

  it('reports observed age, copies and the default rotate-by without mutating the inputs', () => {
    const state = createHygieneState();
    updateFirstSeen(state, inventory(), '2026-07-01T12:00:00.000Z');
    const key = cluster();
    key.consumers.push({ ...key.consumers[0]!, varName: 'OTHER_KEY' });
    const before = JSON.stringify(state);
    expect(hygieneReport({ state, inventory: inventory([key]), now: NOW })).toEqual([
      { clusterId: FIRST, firstSeen: '2026-07-01T12:00:00.000Z', ageDays: 118,
        copies: 2, rotateBy: '2026-09-29T12:00:00.000Z' },
    ]);
    expect(JSON.stringify(state)).toBe(before);
  });

  it('last rotation comes only from successful revoked events, maps replacement fingerprints and never goes backwards', () => {
    const state = createHygieneState();
    updateFirstSeen(state, inventory(), '2026-07-01T12:00:00.000Z');
    updateLastRotation(state, [
      { at: '2026-10-20T12:00:00.000Z', event: 'revoked', clusterId: FIRST, planId: 'plan', data: { newFingerprint: SECOND } },
      { at: '2026-10-26T12:00:00.000Z', event: 'created', clusterId: FIRST, planId: 'other' },
      { at: '2026-10-26T12:00:00.000Z', event: 'revoked', clusterId: FIRST, planId: 'undo', data: { undo: true } },
      { at: NOW, event: 'revoked', clusterId: FIRST, planId: 'cleanup', data: { cleanup: true } },
      { at: '2026-10-01T12:00:00.000Z', event: 'revoked', clusterId: FIRST, planId: 'older' },
    ]);
    expect(state.lastRotation).toEqual({ [FIRST]: '2026-10-20T12:00:00.000Z', [SECOND]: '2026-10-20T12:00:00.000Z' });
    state.settings.rotateEveryDays = 30;
    expect(hygieneReport({ state, inventory: inventory(), now: NOW })[0]?.rotateBy).toBe('2026-11-19T12:00:00.000Z');
  });

  it('does not persist names or hints for unreadable keys, and does not invent a historical age', () => {
    const key = cluster();
    key.id = 'sealed:railway:project/prod/api:API_KEY';
    key.fingerprint = null;
    const state = createHygieneState();
    updateFirstSeen(state, inventory([key]), NOW);
    expect(state.firstSeen).toEqual({});
    expect(hygieneReport({ state, inventory: inventory([key]), now: NOW })[0]).toMatchObject({ firstSeen: NOW, ageDays: 0 });
  });

  it('uses a known rotation date even if its replacement was first observed in a later scan', () => {
    const state = createHygieneState();
    updateFirstSeen(state, inventory([cluster(SECOND)]), NOW);
    updateLastRotation(state, [{ at: '2026-10-20T12:00:00.000Z', event: 'revoked', clusterId: FIRST,
      planId: 'plan', data: { newFingerprint: SECOND } }]);
    expect(hygieneReport({ state, inventory: inventory([cluster(SECOND)]), now: NOW })[0]?.rotateBy)
      .toBe('2027-01-18T12:00:00.000Z');
  });
});
