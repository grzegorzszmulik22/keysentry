import { describe, expect, it } from 'vitest';
import { createWatcherResumeRelay, type WatcherResumeRelayOptions } from '../../src/watcher/resume-relay.js';
import { signWatcherResume } from '../../src/watcher/recovery.js';
import { canonicalJson, generateDeviceKey, signDetached } from '../../src/security/index.js';
import { FakeHttp, json, text } from '../helpers/fake-http.js';

const at = '2026-10-27T12:00:00.000Z';
const watcherId = 'watcher-example';
const server = 'https://ntfy.sh';
const topic = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const key = generateDeviceKey();
const publicKeys = [{ keyId: key.keyId, publicKeyDer: key.publicKeyDer }];
const signed = (timestamp = at) => signWatcherResume({ watcherId, at: timestamp }, key);

function wrapper(payload: unknown, id = 'message1', changes: Record<string, unknown> = {}): string {
  return JSON.stringify({ id, time: 1793102400, event: 'message', topic, message: JSON.stringify(payload), ...changes });
}

function fixture(body = '', overrides: Partial<WatcherResumeRelayOptions> = {}) {
  const http = new FakeHttp().on('GET', /\/json\?/, () => text(200, body))
    .on('POST', /ntfy\.sh\//, () => json(200, { id: 'published' }));
  const relay = createWatcherResumeRelay({
    http, server, topic, watcherId, trustedKeyIds: [key.keyId],
    deviceKeys: async () => publicKeys, now: () => new Date(at), ...overrides,
  });
  return { relay, http };
}

describe('watcher resume relay', () => {
  it('publishes the signed resume directly as JSON, with the token only in the header', async () => {
    const { relay, http } = fixture('', { token: 'private-token' });
    await relay.publishResume(signed());
    expect(http.calls).toEqual([{
      method: 'POST', url: server + '/' + topic,
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer private-token' },
      body: JSON.stringify(signed()),
    }]);
  });

  it('polls a 24-hour retained window and returns authenticated watcher-bound resumes', async () => {
    const message = signed('2026-10-26T12:00:00.000Z');
    const { relay, http } = fixture(wrapper(message));
    expect(await relay.poll(null)).toEqual({ resumes: [message], cursor: 'message1', ignored: 0 });
    expect(http.calls[0]?.url).toBe(server + '/' + topic + '/json?poll=1&since=24h');
  });

  it('uses its supplied durable cursor independently of the approval relay and preserves it for an empty response', async () => {
    const { relay, http } = fixture('', { token: 'private-token' });
    expect(await relay.poll('resume-cursor_2')).toEqual({ resumes: [], cursor: 'resume-cursor_2', ignored: 0 });
    expect(http.calls[0]).toEqual({ method: 'GET', url: server + '/' + topic + '/json?poll=1&since=resume-cursor_2', headers: { Authorization: 'Bearer private-token' } });
  });

  it('silently skips approval, disarm and unrelated typed traffic while advancing its cursor', async () => {
    const body = [
      wrapper({ type: 'keysentry-approval', v: 1, approval: {} }, 'approval1'),
      wrapper({ type: 'keysentry-disarm', v: 2, sig: 'irrelevant' }, 'disarm1'),
      wrapper({ type: 'other', v: 1 }, 'other1'), wrapper(signed(), 'resume1'),
    ].join('\n');
    expect(await fixture(body).relay.poll(null)).toEqual({ resumes: [signed()], cursor: 'resume1', ignored: 0 });
  });

  it('leaves replay consumption to the recovery controller', async () => {
    const { relay } = fixture(wrapper(signed()));
    expect((await relay.poll(null)).resumes).toEqual([signed()]);
    expect((await relay.poll(null)).resumes).toEqual([signed()]);
  });

  it('skips structurally valid open and keepalive controls without moving its cursor', async () => {
    const body = ['open', 'keepalive'].map((event, i) => JSON.stringify({ id: 'control' + i, time: 1793102400, event, topic })).join('\r\n');
    expect(await fixture('\n' + body + '\n').relay.poll('prior')).toEqual({ resumes: [], cursor: 'prior', ignored: 0 });
  });

  it.each([
    { watcherId: 'another-watcher' }, { keyId: '0123456789abcdef' }, { sig: 'invalid' },
    { at: '2026-10-27T12:00:00.001Z' }, { v: 2 }, { extra: true },
  ])('rejects forged or malformed resume messages before poll return and publish: %j', async changes => {
    const changed = { ...signed(), ...changes };
    const { relay, http } = fixture(wrapper(changed));
    expect(await relay.poll(null)).toEqual({ resumes: [], cursor: 'message1', ignored: 1 });
    await expect(relay.publishResume(changed as ReturnType<typeof signed>)).rejects.toThrow(/invalid/i);
    expect(http.callsTo('POST', /./)).toEqual([]);
  });

  it('rejects authentic expired and future resumes before returning or publishing them', async () => {
    for (const timestamp of ['2026-10-26T11:59:59.999Z', '2026-10-27T12:00:00.001Z']) {
      const message = signed(timestamp);
      const { relay } = fixture(wrapper(message));
      expect((await relay.poll(null)).ignored).toBe(1);
      await expect(relay.publishResume(message)).rejects.toThrow();
    }
  });

  it('uses current supplied device keys and trust before each poll and publication', async () => {
    let keys = publicKeys;
    const { relay, http } = fixture(wrapper(signed()), { deviceKeys: async () => keys });
    expect((await relay.poll(null)).resumes).toHaveLength(1);
    keys = [];
    expect((await relay.poll(null)).resumes).toEqual([]);
    await expect(relay.publishResume(signed())).rejects.toThrow();
    expect(http.callsTo('POST', /./)).toEqual([]);
    const untrusted = fixture(wrapper(signed()), { trustedKeyIds: [] }).relay;
    expect((await untrusted.poll(null)).resumes).toEqual([]);
    await expect(untrusted.publishResume(signed())).rejects.toThrow();
  });

  it('rejects a key ID that is not bound to its supplied public key', async () => {
    const alias = '0123456789abcdef';
    const body = { watcherId, keyId: alias, at };
    const message = { type: 'keysentry-resume', v: 1, ...body, sig: signDetached(key.privateKeyDer, Buffer.from('keysentry-resume:v1\n' + canonicalJson(body))).toString('base64') };
    const { relay } = fixture(wrapper(message), { trustedKeyIds: [alias], deviceKeys: async () => [{ keyId: alias, publicKeyDer: key.publicKeyDer }] });
    expect((await relay.poll(null)).resumes).toEqual([]);
    await expect(relay.publishResume(message as ReturnType<typeof signed>)).rejects.toThrow();
  });

  it('counts invalid lines, forged controls and wrong-topic wrappers without accepting their cursor', async () => {
    const body = [
      'not-json', wrapper(signed(), 'other-topic', { topic: 'another-topic' }),
      wrapper(signed(), 'bad-time', { time: -1 }), wrapper(signed(), 'bad-event', { event: 'unknown' }),
      JSON.stringify({ id: 'forged', time: 1793102400, topic, event: 'open', message: JSON.stringify(signed()) }),
      wrapper(signed(), 'bad-id/', {}),
    ].join('\n');
    expect(await fixture(body).relay.poll('prior')).toEqual({ resumes: [], cursor: 'prior', ignored: 6 });
  });

  it('counts malformed JSON payloads and missing types and moves past those valid wrappers', async () => {
    const body = [wrapper([], 'array'), wrapper({}, 'object'), wrapper(null, 'null'), wrapper('invalid', 'string'),
      wrapper(signed(), 'last', { message: 'invalid-json' })].join('\n');
    expect(await fixture(body).relay.poll(null)).toEqual({ resumes: [], cursor: 'last', ignored: 5 });
  });

  it('caps response and individual line sizes in UTF-8 bytes', async () => {
    await expect(fixture('x'.repeat(4 * 1024 * 1024 + 1)).relay.poll(null)).rejects.toThrow(/too large/i);
    const body = wrapper({ type: 'other', value: 'é'.repeat(9000) }, 'too-large') + '\n' + wrapper(signed(), 'good');
    expect(await fixture(body).relay.poll(null)).toEqual({ resumes: [signed()], cursor: 'good', ignored: 1 });
  });

  it.each([
    { server: 'http://ntfy.sh' }, { server: 'https://user:secret@ntfy.sh' }, { server: 'https://ntfy.sh/path' },
    { server: 'https://ntfy.sh/?query=secret' }, { server: 'https://ntfy.sh/#secret' }, { server: 'invalid-secret' },
    { topic: 'unsafe/topic' }, { topic: '' }, { token: 'secret\r\nheader' }, { token: 'secret\u0000value' },
    { watcherId: '' },
  ])('refuses invalid relay configuration without reflecting it: %j', overrides => {
    expect(() => fixture('', overrides)).toThrow('Invalid watcher resume relay configuration.');
  });

  it.each(['', '../escape', 'bad/cursor', 'x'.repeat(129)])('rejects invalid cursors before network access: %s', async cursor => {
    const { relay, http } = fixture();
    await expect(relay.poll(cursor)).rejects.toThrow('Invalid watcher resume relay cursor.');
    expect(http.calls).toEqual([]);
  });

  it('keeps HTTP, key-loader and clock failures content-free', async () => {
    const failedHttp = new FakeHttp().on('GET', /./, () => text(500, 'private-server-error'))
      .on('POST', /./, () => { throw new Error('private-server-error'); });
    const failed = fixture('', { http: failedHttp }).relay;
    await expect(failed.poll(null)).rejects.toThrow('Unable to poll the watcher resume relay.');
    await expect(failed.publishResume(signed())).rejects.toThrow('Unable to publish the watcher resume.');
    const missingKeys = fixture('', { deviceKeys: async () => { throw new Error('private-key-error'); } }).relay;
    await expect(missingKeys.poll(null)).rejects.toThrow('Unable to load watcher resume relay device keys.');
    await expect(missingKeys.publishResume(signed())).rejects.toThrow('Unable to load watcher resume relay device keys.');
    const brokenClock = fixture('', { now: () => { throw new Error('private-clock-error'); } }).relay;
    await expect(brokenClock.poll(null)).rejects.toThrow('Unable to read the watcher resume relay clock.');
    await expect(brokenClock.publishResume(signed())).rejects.toThrow('Unable to read the watcher resume relay clock.');
  });
});
