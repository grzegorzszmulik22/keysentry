import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createStateCipher, createStateStore } from '../../src/core/store.js';
import { createMonitorState, createFileMonitorStateStore, createMemoryMonitorStateStore, pruneUsageHistory, usageKey } from '../../src/monitor/state.js';

describe('monitor state', () => {
  it('round trips encrypted monitor metadata through the injected state store', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'keysentry-monitor-encrypted-'));
    try {
      const encrypted = createStateStore({ cwd, cipher: createStateCipher(Buffer.alloc(32, 7)) });
      const store = createFileMonitorStateStore(cwd, encrypted);
      expect(await store.load()).toEqual(createMonitorState());
      const state = createMonitorState(); state.keyRefs['fingerprint-private'] = 'private-provider-reference';
      await store.save(state);
      expect(await store.load()).toEqual(state);
      const disk = await readFile(encrypted.paths.monitor, 'utf8');
      expect(disk.startsWith('keysentry-encrypted:v1\n')).toBe(true);
      expect(disk).not.toContain('private-provider-reference');
      expect(disk).not.toContain('fingerprint-private');
    } finally { await rm(cwd, { recursive: true, force: true }); }
  });
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

  it('persists pending approval safety flags while accepting legacy actions without them',async()=>{
    const state=createMonitorState();
    const action={id:'atomic-action',createdAt:'2026-10-26T12:00:00.000Z',signalId:'leak',
      action:'rotate' as const,clusterIds:['cluster'],status:'pending' as const};
    state.pendingActions.push({...action,requiresInteractive:true,revokeUnconfirmed:true});
    const store=createMemoryMonitorStateStore(state);
    expect((await store.load()).pendingActions[0]).toMatchObject({requiresInteractive:true,revokeUnconfirmed:true});
    await store.save({...state,pendingActions:[action]});
    expect((await store.load()).pendingActions[0]).toEqual(action);
    await expect(store.save({...state,pendingActions:[{...action,revokeUnconfirmed:'true'}]} as never))
      .rejects.toThrow('Invalid monitor state');
    await expect(store.save({...state,pendingActions:[{...action,requiresInteractive:'true'}]} as never))
      .rejects.toThrow('Invalid monitor state');
  });
});
