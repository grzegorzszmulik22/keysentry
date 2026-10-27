import { describe, expect, it } from 'vitest';
import { createWatcherTick, runOnce, runWatcherLoop, type WatcherTickDependencies, type WatcherTickState } from '../../src/watcher/loop.js';
import type { Incident, NotifyMessage } from '../../src/types.js';
import { selfCheck } from '../../src/watcher/self-check.js';
import { createActionsRecovery, signWatcherResume } from '../../src/watcher/recovery.js';
import { generateDeviceKey } from '../../src/security/index.js';

const now = new Date('2026-10-27T08:00:00Z');
const incident = (id = 'inc-railway', host: Incident['host'] = 'railway', status: Incident['status'] = 'triggered'): Incident => ({
  id, host, openedAt: now.toISOString(), evidence: [], status,
  ...(status === 'triggered' ? { trigger: { at: now.toISOString(), rule: 'official' as const } } : {}),
});

function fixture() {
  const events: string[] = [];
  const messages: NotifyMessage[] = [];
  const logs: string[] = [];
  let safe = true;
  let firstUpdate = true;
  let instant = now;
  const deps: WatcherTickDependencies = {
    now: () => instant, startedAt: now,
    platform: { platform: 'docker', host: null }, ownTokenNames: ['RAILWAY_TOKEN'],
    log: { warn: message => { logs.push(message); } },
    selfCheck: async () => ({ ok: safe, reasons: safe ? [] : ['Paused for this test.'] }),
    resumeWaves: async () => { events.push('resume'); },
    relay: {
      poll: async () => { events.push('relay'); return { approvals: ['approved'], disarms: [] }; },
      approve: async () => { events.push('approval'); },
      disarm: async () => { safe = false; events.push('disarm'); },
    },
    fetchSources: async () => { events.push('sources'); return []; },
    updateIncidents: async () => {
      events.push('incidents');
      const triggered = firstUpdate ? [incident()] : [];
      firstUpdate = false;
      return { incidents: triggered, changed: triggered, triggered };
    },
    runAutopilot: async (_item, context) => {
      expect(context.excludedTokenNames).toEqual(['RAILWAY_TOKEN']);
      events.push('autopilot');
    },
    settleWaves: async () => { events.push('settle'); },
    requestApproval: async item => { events.push(`request:${item.id}`); },
    runMonitorOnce: async context => { events.push(context.alertOnly ? 'monitor:alert-only' : 'monitor'); },
    lastNotifySuccessAt: () => null,
    notify: async message => { messages.push(message); events.push(`notify:${message.kind}`); },
  };
  return { deps, events, messages, logs, unsafe: () => { safe = false; }, time: (date: Date) => { instant = date; } };
}

describe('one watcher cycle', () => {
  it('handles relay before resuming, then fetches incidents, rotates, settles, monitors, and sends heartbeat', async () => {
    const f = fixture();
    f.time(new Date('2026-10-27T09:00:00Z'));
    const result = await createWatcherTick(f.deps)();
    expect(f.events).toEqual(['relay', 'approval', 'resume', 'sources', 'incidents', 'autopilot', 'settle', 'monitor', 'notify:watcher-heartbeat']);
    expect(result.status).toBe('ok');
  });

  it('checks safety before every automatic step and forces monitor alert-only', async () => {
    const f = fixture(); f.unsafe();
    const result = await createWatcherTick(f.deps)();
    expect(result.status).toBe('alert-only');
    expect(f.events).toEqual(['relay', 'approval', 'sources', 'incidents', 'notify:watcher-incident-paused', 'request:inc-railway', 'monitor:alert-only']);
  });

  it('a relay disarm prevents automatic actions later in the same tick', async () => {
    const f = fixture();
    f.deps.relay!.poll = async () => ({ approvals: [], disarms: ['signed-disarm'] });
    const result = await createWatcherTick(f.deps)();
    expect(f.events).toEqual(['disarm', 'sources', 'incidents', 'notify:watcher-incident-paused', 'request:inc-railway', 'monitor:alert-only']);
    expect(result.status).toBe('alert-only');
  });

  it('one failing step is logged without its error or secrets and the rest continue', async () => {
    const f = fixture();
    f.deps.fetchSources = async () => { throw new Error('plaintext-token'); };
    const result = await createWatcherTick(f.deps)();
    expect(result.status).toBe('error');
    expect(f.events).toContain('monitor');
    expect(f.events).toContain('settle');
    expect(JSON.stringify([result, f.logs])).not.toContain('plaintext-token');
  });

  it('executes granted actions after applying relay approvals and before new incidents', async () => {
    const f = fixture();
    f.deps.executeApprovals = async context => {
      expect(context.alertOnly).toBe(false);
      expect(context.excludedTokenNames).toEqual(['RAILWAY_TOKEN']);
      f.events.push('execute approvals');
    };
    await createWatcherTick(f.deps)();
    expect(f.events.indexOf('execute approvals')).toBeGreaterThan(f.events.indexOf('approval'));
    expect(f.events.indexOf('execute approvals')).toBeLessThan(f.events.indexOf('sources'));
  });

  it('contains approved-action execution failure and continues sources and monitoring', async () => {
    const f = fixture();
    f.deps.executeApprovals = async () => { throw new Error('private-approval-data'); };
    const result = await createWatcherTick(f.deps)();
    expect(result.errors).toContain('execute approved actions');
    expect(f.events).toContain('sources');
    expect(f.events).toContain('monitor');
    expect(JSON.stringify([result, f.logs])).not.toContain('private-approval-data');
  });

  it('does not execute grants while disarmed', async () => {
    const f = fixture(); f.unsafe();
    f.deps.executeApprovals = async () => { f.events.push('execute approvals'); };
    await createWatcherTick(f.deps)();
    expect(f.events).not.toContain('execute approvals');
  });

  it('polls for a mid-wave disarm every thirty seconds and stops before the next effect', async () => {
    const f = fixture(); let polls = 0; const effects: string[] = [];
    f.deps.relay!.poll = async () => ({ approvals: [], disarms: ++polls > 1 ? ['signed-disarm'] : [] });
    f.deps.runAutopilot = async (_incident, context) => {
      for (const ms of [0, 29_999, 30_000, 60_000]) {
        f.time(new Date(now.getTime() + ms));
        if (await context.shouldStop()) break;
        effects.push(String(ms));
      }
    };
    await createWatcherTick(f.deps)();
    expect(effects).toEqual(['0', '29999']);
    expect(polls).toBe(2);
    expect(f.events).toContain('disarm');
    expect(f.events).not.toContain('settle');
  });

  it('checks local disarm between steps without waiting for another relay poll', async () => {
    const f = fixture(); const stopped: boolean[] = [];
    f.deps.runAutopilot = async (_incident, context) => {
      stopped.push(await context.shouldStop()); f.unsafe();
      stopped.push(await context.shouldStop());
    };
    await createWatcherTick(f.deps)();
    expect(stopped).toEqual([false, true]);
  });

  it('concurrent engine checks await the same relay poll before permitting an effect', async () => {
    const f = fixture(); let polls = 0; let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    f.deps.relay!.poll = async () => {
      if (++polls === 1) return { approvals: [] };
      await gate;
      return { approvals: [], disarms: ['signed-disarm'] };
    };
    let stopped: boolean[] = [];
    f.deps.runAutopilot = async (_incident, context) => {
      f.time(new Date(now.getTime() + 30_000));
      const first = context.shouldStop(); const second = context.shouldStop();
      // Give the second check a chance to finish while the first is still polling.
      await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
      release(); stopped = await Promise.all([first, second]);
    };
    await createWatcherTick(f.deps)();
    expect(stopped).toEqual([true, true]);
    expect(polls).toBe(2);
  });

  it('stops a running action if a relay re-poll fails', async () => {
    const f = fixture(); let polls = 0; let stopped = false;
    f.deps.relay!.poll = async () => { if (++polls > 1) throw new Error('private-relay'); return { approvals: [] }; };
    f.deps.runAutopilot = async (_incident, context) => {
      f.time(new Date(now.getTime() + 30_000)); stopped = await context.shouldStop();
    };
    const result = await createWatcherTick(f.deps)();
    expect(stopped).toBe(true);
    expect(result.errors).toContain('relay poll');
    expect(f.events).not.toContain('settle');
  });

  it('uses external delivery history when console deliveries are more recent', async () => {
    const f = fixture();
    f.deps.lastNotifySuccessAt = () => '2026-10-28T08:00:00Z';
    f.deps.lastExternalSuccessAt = () => null;
    f.deps.state = { pendingTriggered: [], pendingAlerted: [], ownPlatformNotified: [], approvalsRequested: [], lastHeartbeatAt: null,
      startedAt: now.toISOString(), lastNotifySuccessAt: '2026-10-28T08:00:00Z' };
    f.time(new Date('2026-10-28T08:00:00Z'));
    const result = await createWatcherTick(f.deps)();
    expect(result.status).toBe('alert-only');
    expect(f.events).not.toContain('autopilot');
    expect(f.events).not.toContain('resume');
  });

  it('starts an Actions cache miss alert-only and sends one urgent recovery message across restarts', async () => {
    const f = fixture(); f.deps.platform = { platform: 'github-actions', host: 'github-actions' };
    let saved: WatcherTickState | undefined;
    f.deps.saveState = async snapshot => { saved = snapshot; };
    const tick = createWatcherTick(f.deps);
    expect((await tick()).status).toBe('alert-only');
    await tick();
    const second = fixture(); second.deps.platform = f.deps.platform; second.deps.state = saved;
    expect((await createWatcherTick(second.deps)()).status).toBe('alert-only');
    expect([...f.messages, ...second.messages].filter(message => message.kind === 'watcher-state-missing')).toEqual([
      expect.objectContaining({ severity: 'urgent', lines: [
        'This watcher started without its saved state, so autopilot is paused. Run `keysentry autopilot resume --relay` on your computer to resume it.',
      ] }),
    ]);
    expect(f.events).not.toContain('autopilot');
    expect(f.events).not.toContain('resume');
    expect(second.events).not.toContain('autopilot');
  });

  it('lets the recovery verifier clear the Actions pause before any automatic actions', async () => {
    const f = fixture(); f.deps.platform = { platform: 'github-actions', host: 'github-actions' };
    let paused = true;
    f.deps.recovery = { alertOnly: () => paused, resume: async message => {
      if (message === 'verified-resume') { paused = false; f.events.push('recovery resume'); }
    } };
    f.deps.relay!.poll = async () => ({ approvals: [], resumes: ['verified-resume'] });
    expect((await createWatcherTick(f.deps)()).status).toBe('ok');
    expect(paused).toBe(false);
    expect(f.events.indexOf('recovery resume')).toBeLessThan(f.events.indexOf('resume'));
    expect(f.events).toContain('autopilot');
  });

  it('a disarm wins over a simultaneous recovery resume', async () => {
    const f = fixture(); f.deps.platform = { platform: 'github-actions', host: 'github-actions' };
    let paused = true;
    f.deps.recovery = { alertOnly: () => paused, resume: async () => { paused = false; } };
    f.deps.relay!.poll = async () => ({ approvals: [], disarms: ['disarm'], resumes: ['resume'] });
    expect((await createWatcherTick(f.deps)()).status).toBe('alert-only');
    expect(paused).toBe(true);
    expect(f.events).not.toContain('resume');
  });

  it('keeps Actions paused for a forged resume and releases queued work only for a trusted signed resume', async () => {
    const f = fixture(); f.deps.platform = { platform: 'github-actions', host: 'github-actions' };
    const device = generateDeviceKey();
    const message = signWatcherResume({ watcherId: 'test-watcher', at: now.toISOString() }, device);
    const recovery = createActionsRecovery({ watcherId: 'test-watcher', trustedKeyIds: [device.keyId],
      deviceKeys: async () => [{ keyId: device.keyId, publicKeyDer: device.publicKeyDer }], now: f.deps.now,
      saveState: async state => { expect(state.usedResumeSignatures).toContain(message.sig); },
    });
    f.deps.recovery = recovery;
    let resumes: unknown[] = [{ ...message, sig: Buffer.alloc(64).toString('base64') }];
    f.deps.relay!.poll = async () => ({ approvals: [], resumes });
    const tick = createWatcherTick(f.deps);
    expect((await tick()).status).toBe('alert-only');
    expect(f.events).not.toContain('autopilot');
    resumes = [message];
    expect((await tick()).status).toBe('ok');
    expect(f.events.filter(event => event === 'autopilot')).toHaveLength(1);
    expect((await recovery.resume(message)).ok).toBe(false);
  });

  it('failure to check safety never allows an automatic action', async () => {
    const f = fixture(); f.deps.selfCheck = async () => { throw new Error('secret'); };
    const result = await createWatcherTick(f.deps)();
    expect(result.status).toBe('error');
    expect(f.events).not.toContain('autopilot');
    expect(f.events).not.toContain('resume');
    expect(f.events).not.toContain('settle');
    expect(f.events).toContain('monitor:alert-only');
  });

  it('sends one urgent guided own-platform message and still runs armed rotation with own tokens excluded', async () => {
    const f = fixture(); f.deps.platform = { platform: 'railway', host: 'railway' };
    const tick = createWatcherTick(f.deps);
    await tick(); await tick();
    expect(f.messages).toHaveLength(1);
    expect(f.messages[0]).toMatchObject({ severity: 'urgent', kind: 'watcher-own-platform' });
    expect(f.messages[0]!.lines.join(' ')).toBe('The platform this watcher runs on reported a security incident. Rotate the tokens you gave keysentry (RAILWAY_TOKEN) by hand, then run `keysentry watcher setup` again.');
    expect(f.events.filter(event => event === 'autopilot')).toHaveLength(1);
  });

  it('news-only alerted incidents request approval once and never rotate', async () => {
    const f = fixture();
    const alerted = incident('news-only', 'railway', 'alerted');
    f.deps.updateIncidents = async () => ({ incidents: [alerted], changed: [alerted], triggered: [] });
    const tick = createWatcherTick(f.deps); await tick(); await tick();
    expect(f.events.filter(event => event === 'request:news-only')).toHaveLength(1);
    expect(f.events).not.toContain('autopilot');
  });

  it('keeps triggered work pending while alert-only and retries after safety recovers', async () => {
    const f = fixture(); f.unsafe();
    let safe = false;
    f.deps.selfCheck = () => ({ ok: safe, reasons: [] });
    const tick = createWatcherTick(f.deps);
    await tick(); safe = true; await tick(); await tick();
    expect(f.events.filter(event => event === 'autopilot')).toHaveLength(1);
  });

  it('paused triggered incidents send an alert and request approval once', async () => {
    const f = fixture(); f.unsafe();
    const tick = createWatcherTick(f.deps); await tick(); await tick();
    expect(f.messages.filter(message => message.kind === 'watcher-incident-paused')).toHaveLength(1);
    expect(f.events.filter(event => event === 'request:inc-railway')).toHaveLength(1);
    expect(f.events).not.toContain('autopilot');
  });

  it('persists the original notification window across fresh once processes', async () => {
    let persisted: WatcherTickState | undefined;
    const first = fixture();
    first.deps.saveState = async state => { persisted = structuredClone(state); };
    await createWatcherTick(first.deps)();
    expect(persisted?.startedAt).toBe('2026-10-27T08:00:00.000Z');
    const next = fixture();
    next.deps.state = persisted;
    next.deps.startedAt = new Date('2026-10-28T08:00:00Z');
    next.time(new Date('2026-10-28T08:00:00Z'));
    const result = await createWatcherTick(next.deps)();
    expect(result.status).toBe('alert-only');
    expect(next.events).not.toContain('resume');
    expect(next.events).not.toContain('autopilot');
    expect(next.messages.some(message => message.kind === 'watcher-heartbeat')).toBe(true);
  });

  it('restores the last actual delivery success for a later scheduled process', async () => {
    let persisted: WatcherTickState | undefined;
    const first = fixture();
    first.deps.lastNotifySuccessAt = () => '2026-10-27T09:00:00Z';
    first.time(new Date('2026-10-27T10:00:00Z'));
    first.deps.saveState = async state => { persisted = structuredClone(state); };
    await createWatcherTick(first.deps)();
    const next = fixture(); next.deps.state = persisted;
    next.time(new Date('2026-10-28T08:30:00Z'));
    next.deps.startedAt = new Date('2026-10-28T08:30:00Z');
    next.deps.selfCheck = input => selfCheck({ ...input, stateWritable: true, armedValid: true });
    expect((await createWatcherTick(next.deps)()).status).toBe('ok');
  });

  it('saves actual notification success from the last monitor step before once exits', async () => {
    const f = fixture();
    let delivered: string | null = null;
    let persisted: WatcherTickState | undefined;
    f.deps.lastNotifySuccessAt = () => delivered;
    f.deps.saveState = async state => { persisted = structuredClone(state); };
    f.deps.runMonitorOnce = async () => { delivered = '2026-10-27T08:00:00Z'; };
    await createWatcherTick(f.deps)();
    expect(persisted?.lastNotifySuccessAt).toBe('2026-10-27T08:00:00Z');
  });

  it('a failed metadata save prevents further automatic actions', async () => {
    const f = fixture(); f.deps.saveState = async () => { throw new Error('secret'); };
    const result = await createWatcherTick(f.deps)();
    expect(result.status).toBe('error');
    expect(f.events).not.toContain('resume');
    expect(f.events).not.toContain('settle');
    expect(f.events).toContain('monitor:alert-only');
  });

  it('recovers a persisted trigger after a crash before the pending queue was saved', async () => {
    const f = fixture();
    f.deps.updateIncidents = async () => ({ incidents: [incident()], changed: [], triggered: [] });
    const tick = createWatcherTick(f.deps);
    await tick(); await tick();
    expect(f.events.filter(event => event === 'autopilot')).toHaveLength(1);
  });

  it('does not execute a queued incident after it has closed', async () => {
    const f = fixture(); let closed = false; let safe = false;
    f.deps.selfCheck = () => ({ ok: safe, reasons: [] });
    f.deps.updateIncidents = async () => ({ incidents: [incident('inc-railway', 'railway', closed ? 'closed' : 'triggered')], changed: [], triggered: closed ? [] : [incident()] });
    const tick = createWatcherTick(f.deps);
    await tick(); closed = true; safe = true; await tick();
    expect(f.events).not.toContain('autopilot');
  });

  it('retries a failed own-platform notification without losing the incident', async () => {
    const f = fixture(); f.deps.platform = { platform: 'railway', host: 'railway' };
    let attempts = 0;
    const notify = f.deps.notify;
    f.deps.notify = async message => { if (++attempts === 1) throw new Error('private-url'); await notify(message); };
    const tick = createWatcherTick(f.deps);
    expect((await tick()).status).toBe('error');
    await tick(); await tick();
    expect(attempts).toBe(2);
    expect(f.messages).toHaveLength(1);
  });

  it('retries an own-token warning independently after the armed action completed, including after restart', async () => {
    const f = fixture(); f.deps.platform = { platform: 'railway', host: 'railway' };
    f.deps.notify = async () => { throw new Error('private-channel'); };
    let snapshot: WatcherTickState | undefined;
    f.deps.saveState = async state => { snapshot = state; };
    expect((await createWatcherTick(f.deps)()).status).toBe('error');
    expect(f.events.filter(event => event === 'autopilot')).toHaveLength(1);
    const second = fixture(); second.deps.platform = f.deps.platform; second.deps.state = snapshot;
    second.deps.updateIncidents = async () => ({ incidents: [{ ...incident(), waveId: 'wave-completed' }], changed: [], triggered: [] });
    await createWatcherTick(second.deps)();
    expect(second.messages.filter(message => message.kind === 'watcher-own-platform')).toHaveLength(1);
    expect(second.events).not.toContain('autopilot');
  });

  it('serializes concurrent calls so a new incident only runs once', async () => {
    const f = fixture(); const tick = createWatcherTick(f.deps);
    await Promise.all([tick(), tick(), tick()]);
    expect(f.events.filter(event => event === 'autopilot')).toHaveLength(1);
  });

  it('a failed state save prevents incident actions while independent steps still run', async () => {
    const f = fixture();
    f.deps.saveState = async () => { throw new Error('secret-path'); };
    const result = await createWatcherTick(f.deps)();
    expect(result.status).toBe('error');
    expect(f.events).not.toContain('autopilot');
    expect(f.events).toContain('monitor:alert-only');
  });

  it('never throws even when the logger and clock fail', async () => {
    const f = fixture();
    f.deps.now = () => { throw new Error('secret'); };
    f.deps.log.warn = () => { throw new Error('other-secret'); };
    expect((await createWatcherTick(f.deps)()).status).toBe('error');
  });
});

describe('watcher scheduling', () => {
  const selfCheck = () => ({ ok: true, reasons: [] });
  it('runs once plus a final settlement, returning 0 for success', async () => {
    const events: string[] = [];
    expect(await runOnce({ selfCheck, tick: async () => { events.push('tick'); }, settleWaves: async () => { events.push('settle'); } })).toBe(0);
    expect(events).toEqual(['tick', 'settle']);
  });

  it('runOnce returns 1 for thrown errors or error tick results and still attempts settlement', async () => {
    let settled = 0;
    expect(await runOnce({ selfCheck, tick: async () => { throw new Error('secret'); }, settleWaves: async () => { settled++; } })).toBe(1);
    expect(settled).toBe(1);
    expect(await runOnce({ selfCheck, tick: async () => ({ status: 'error', errors: ['sources'], reasons: [] }), settleWaves: async () => {} })).toBe(1);
    expect(await runOnce({ selfCheck, tick: async () => {}, settleWaves: async () => { throw new Error('secret'); } })).toBe(1);
  });

  it('runOnce returns 2 and does not settle automatically when alert-only', async () => {
    let settled = false;
    expect(await runOnce({ selfCheck, tick: async () => ({ status: 'alert-only', errors: [], reasons: [] }), settleWaves: async () => { settled = true; } })).toBe(2);
    expect(settled).toBe(false);
  });

  it('runOnce cannot settle without a fresh successful safety check', async () => {
    let settled = false;
    expect(await runOnce({ tick: async () => {}, settleWaves: async () => { settled = true; } } as never)).toBe(1);
    expect(settled).toBe(false);
    expect(await runOnce({ selfCheck: () => ({ ok: false, reasons: ['disarmed'] }), tick: async () => {}, settleWaves: async () => { settled = true; } })).toBe(2);
    expect(settled).toBe(false);
  });

  it('loop runs sequentially, contains a rejected tick, and stops on abort', async () => {
    const controller = new AbortController(); const events: string[] = [];
    let count = 0;
    await runWatcherLoop({
      intervalMs: 100, signal: controller.signal,
      tick: async () => { events.push('tick'); if (++count === 1) throw new Error('secret'); },
      sleep: async (ms, signal) => { expect(ms).toBe(100); expect(signal).toBe(controller.signal); events.push('sleep'); if (count === 2) controller.abort(); },
    });
    expect(events).toEqual(['tick', 'sleep', 'tick', 'sleep']);
  });

  it('already-aborted loops do nothing and default sleep is interruptible', async () => {
    const stopped = new AbortController(); stopped.abort();
    await runWatcherLoop({ tick: async () => { throw new Error('should not run'); }, intervalMs: 100, signal: stopped.signal });
    const controller = new AbortController();
    const running = runWatcherLoop({ tick: async () => { setTimeout(() => controller.abort(), 5); }, intervalMs: 60_000, signal: controller.signal });
    await running;
  });
});
