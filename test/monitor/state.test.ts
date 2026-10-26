import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createMonitorState, createFileMonitorStateStore, createMemoryMonitorStateStore, pruneUsageHistory, usageKey } from '../../src/monitor/state.js';

describe('monitor state', () => {
  it('round trips only the monitor schema, without arbitrary response fields', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'keysentry-monitor-'));
    try {
      const store = createFileMonitorStateStore(dir);
      const state = createMonitorState();
      state.usageHistory[usageKey('openrouter', 'key_1')] = [{hour:'2026-01-01T00:00:00.000Z',costUsd:1}];
      Object.assign(state, { secret: 'never-save-this-plaintext' });
      await store.save(state);
      expect((await store.load()).usageHistory).toEqual(state.usageHistory);
      expect(await readFile(join(dir,'.keysentry','monitor.json'),'utf8')).not.toContain('never-save');
      expect(await readFile(join(dir,'.keysentry','.gitignore'),'utf8')).toContain('*');
    } finally { await rm(dir,{recursive:true,force:true}); }
  });

  it('isolates snapshots and rejects corrupt state', async () => {
    const store = createMemoryMonitorStateStore();
    const state = await store.load();
    state.autoRotations['2026-01-01'] = 1;
    expect((await store.load()).autoRotations).toEqual({});
    await store.save(state);
    expect((await store.load()).autoRotations['2026-01-01']).toBe(1);
    await expect(store.save({...state,version:2} as never)).rejects.toThrow('Invalid monitor state');
  });

  it('persists feed baselines and loads legacy state without a baseline', async () => {
    const state = createMonitorState();
    state.feedBaselines = { 'feed-fingerprint': '2026-10-26T12:00:00.000Z' };
    const store = createMemoryMonitorStateStore(state);
    expect((await store.load()).feedBaselines).toEqual({ 'feed-fingerprint': '2026-10-26T12:00:00.000Z' });
    const { feedBaselines, ...legacy } = state;
    await store.save(legacy as never);
    expect((await store.load()).feedBaselines).toEqual({});
  });

  it('round trips containment limits and defaults them for legacy state', async () => {
    const state=createMonitorState();
    state.containCooldowns['openrouter:key_1']='2026-10-26T12:00:00.000Z';
    state.autoContainments['2026-10-26']=1;
    const store=createMemoryMonitorStateStore(state);
    expect((await store.load()).containCooldowns).toEqual(state.containCooldowns);
    expect((await store.load()).autoContainments).toEqual(state.autoContainments);
    const {containCooldowns,autoContainments,...legacy}=state;
    await store.save(legacy as never);
    expect((await store.load()).containCooldowns).toEqual({});
    expect((await store.load()).autoContainments).toEqual({});
  });

  it('expires old hourly buckets even for keys no longer inventoried',()=>{
    const state=createMonitorState();
    state.usageHistory.orphan=[{hour:'2026-01-01T00:00:00.000Z',costUsd:1}];
    state.usageHistory.active=[{hour:'2026-02-01T00:00:00.000Z',costUsd:2}];
    pruneUsageHistory(state,new Date('2026-02-02T00:00:00.000Z'));
    expect(state.usageHistory.orphan).toBeUndefined();
    expect(state.usageHistory.active).toHaveLength(1);
  });
});
