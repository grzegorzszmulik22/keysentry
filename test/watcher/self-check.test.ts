import { describe, expect, it } from 'vitest';
import { heartbeatDue, selfCheck, trackHttpClock } from '../../src/watcher/self-check.js';
import { FakeHttp, text } from '../helpers/fake-http.js';

const start = new Date('2026-10-27T08:00:00Z');
const healthy = { lastNotifySuccessAt: null, startedAt: start, now: start, stateWritable: true, armedValid: true };

describe('watcher self-check', () => {
  it('allows the first notification window but no success within 24 hours forces alert-only', () => {
    expect(selfCheck(healthy).ok).toBe(true);
    expect(selfCheck({ ...healthy, now: new Date('2026-10-28T07:59:59Z') }).ok).toBe(true);
    expect(selfCheck({ ...healthy, now: new Date('2026-10-28T08:00:00Z') })).toEqual({
      ok: false, reasons: ['No notification has succeeded in the last 24 hours.'],
    });
  });

  it('measures the window from the last successful notification, including after restart', () => {
    const input = { ...healthy, startedAt: new Date('2026-10-28T08:00:00Z'), lastNotifySuccessAt: '2026-10-27T08:00:00Z' };
    expect(selfCheck({ ...input, now: new Date('2026-10-28T08:00:00Z') }).ok).toBe(false);
    expect(selfCheck({ ...input, lastNotifySuccessAt: '2026-10-28T07:59:00Z', now: input.startedAt }).ok).toBe(true);
  });

  it('ignores console success when explicit external delivery history is supplied', () => {
    expect(selfCheck({ ...healthy, now: new Date('2026-10-28T08:00:00Z'),
      lastNotifySuccessAt: '2026-10-28T08:00:00Z', lastExternalSuccessAt: null }).ok).toBe(false);
    expect(selfCheck({ ...healthy, now: new Date('2026-10-28T08:00:00Z'),
      lastExternalSuccessAt: '2026-10-28T07:00:00Z' }).ok).toBe(true);
  });

  it('requires writable state, a valid armed plan, and at most five minutes of clock skew', () => {
    expect(selfCheck({ ...healthy, clockSkewSeconds: -300 }).ok).toBe(true);
    const result = selfCheck({ ...healthy, stateWritable: false, armedValid: false, clockSkewSeconds: 301 });
    expect(result.ok).toBe(false);
    expect(result.reasons).toHaveLength(3);
    expect(selfCheck({ ...healthy, clockSkewSeconds: -301 }).ok).toBe(false);
  });

  it('fails closed on malformed timestamps and clocks', () => {
    expect(selfCheck({ ...healthy, lastNotifySuccessAt: 'invalid' }).ok).toBe(false);
    expect(selfCheck({ ...healthy, now: new Date(NaN) }).ok).toBe(false);
    expect(selfCheck({ ...healthy, clockSkewSeconds: NaN }).ok).toBe(false);
    expect(selfCheck({ ...healthy, lastNotifySuccessAt: '2026-10-28T08:00:00Z' }).ok).toBe(false);
  });

  it('sends the heartbeat at the next 09:00 UTC and once per day', () => {
    expect(heartbeatDue({ startedAt: start, lastNotifySuccessAt: null, lastHeartbeatAt: null, now: start })).toBe(false);
    expect(heartbeatDue({ startedAt: start, lastNotifySuccessAt: null, lastHeartbeatAt: null, now: new Date('2026-10-27T09:00:00Z') })).toBe(true);
    expect(heartbeatDue({ startedAt: start, lastNotifySuccessAt: '2026-10-27T09:00:00Z', lastHeartbeatAt: '2026-10-27T09:00:00Z', now: new Date('2026-10-27T10:00:00Z') })).toBe(false);
    expect(heartbeatDue({ startedAt: start, lastNotifySuccessAt: '2026-10-28T08:59:00Z', lastHeartbeatAt: '2026-10-27T09:00:00Z', now: new Date('2026-10-28T09:00:00Z') })).toBe(true);
  });

  it('also sends a heartbeat 24 hours after the last success', () => {
    expect(heartbeatDue({ startedAt: start, lastNotifySuccessAt: '2026-10-26T08:00:00Z', lastHeartbeatAt: '2026-10-27T07:00:00Z', now: start })).toBe(true);
  });

  it('tracks the last HTTP Date header without making an extra request or growing stale', async () => {
    let now = start;
    const fake = new FakeHttp().on('GET', /^https:\/\/clock\.example\//, () => text(200, '', { Date: 'Tue, 27 Oct 2026 07:54:00 GMT' }));
    const clock = trackHttpClock(fake, () => now);
    expect(clock.clockSkewSeconds()).toBeUndefined();
    await clock.http.request({ method: 'GET', url: 'https://clock.example/' });
    expect(clock.clockSkewSeconds()).toBe(360);
    now = new Date('2026-10-27T10:00:00Z');
    expect(clock.clockSkewSeconds()).toBe(360);
    expect(fake.calls).toHaveLength(1);
  });

  it('retains the last available clock evidence when a later response has no Date header', async () => {
    const fake = new FakeHttp().on('GET', /dated/, () => text(200, '', { date: 'Tue, 27 Oct 2026 08:00:00 GMT' }))
      .on('GET', /missing/, () => text(200, ''));
    const clock = trackHttpClock(fake, () => start);
    await clock.http.request({ method: 'GET', url: 'https://clock.example/dated' });
    expect(clock.clockSkewSeconds()).toBe(0);
    await clock.http.request({ method: 'GET', url: 'https://clock.example/missing' });
    expect(clock.clockSkewSeconds()).toBe(0);
  });
});
