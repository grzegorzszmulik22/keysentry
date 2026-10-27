import { describe, expect, test } from 'vitest';
import { createHash } from 'node:crypto';
import { createRelay } from '../../src/approvals/relay.js';
import { canonicalJson, generateDeviceKey, signDetached } from '../../src/security/index.js';
import type { AuditEvent, AuditLog } from '../../src/types.js';
import { FakeHttp, json, text } from '../helpers/fake-http.js';

const at = '2026-10-27T12:00:00.000Z';
const origin = 'https://ntfy.sh';
const topic = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const key = generateDeviceKey();
const otherKey = generateDeviceKey();
const digest = createHash('sha256').update('action').digest('hex');

function approval(overrides: Record<string, unknown> = {}) {
  const fields = { actionId: 'action-1', digest, at, ...overrides } as { actionId: string; digest: string; at: string };
  return { ...fields, keyId: key.keyId, sig: signDetached(key.privateKeyDer, Buffer.from('keysentry-approval:v1\n' + canonicalJson(fields))).toString('base64') };
}

function disarm(timestamp = at) {
  const body = { watcherId: 'project', keyId: key.keyId, at: timestamp };
  return { ...body, sig: signDetached(key.privateKeyDer, Buffer.from('keysentry-disarm:v2\n' + canonicalJson(body))).toString('base64') };
}

function wrapper(payload: unknown, id = 'message1') {
  return JSON.stringify({ id, time: 1793102400, event: 'message', topic, message: JSON.stringify(payload) });
}

function fixture(body = '', overrides: Record<string, unknown> = {}) {
  const events: AuditEvent[] = [];
  const audit: AuditLog = {
    async append(event) { events.push(event); }, async checkpoint() {},
    async verify() { return { ok: true, entries: events.length, checkpoints: 0 }; },
  };
  const http = new FakeHttp().on('GET', /\/json\?/, () => text(200, body)).on('POST', /ntfy\.sh\//, () => json(200, { id: 'published' }));
  const relay = createRelay({ http, server: origin, topic, trustedKeyIds: [key.keyId], watcherId: 'project',
    deviceKeys: async () => [{ keyId: key.keyId, publicKeyDer: key.publicKeyDer }],
    audit, now: () => new Date(at), ...overrides });
  return { relay, http, events };
}

describe('approval relay', () => {
  test('publishApproval posts the fixed JSON envelope to the topic with token only in a header', async () => {
    const signed = approval();
    const { relay, http } = fixture('', { token: 'token-private' });
    await relay.publishApproval(signed);
    expect(http.calls).toEqual([{ method: 'POST', url: origin + '/' + topic,
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer token-private' },
      body: JSON.stringify({ type: 'keysentry-approval', v: 1, approval: signed }) }]);
  });

  test('poll verifies signed approvals inside ntfy message envelopes and advances the cursor', async () => {
    const signed = approval();
    const { relay, http } = fixture(wrapper({ type: 'keysentry-approval', v: 1, approval: signed }, 'nextMessage'));
    expect(await relay.poll(null)).toEqual({ approvals: [signed], disarms: [], cursor: 'nextMessage', ignored: 0 });
    expect(http.calls[0]?.url).toBe(origin + '/' + topic + '/json?poll=1&since=all');
  });

  test('approval timestamps accept canonical ISO seconds without milliseconds', async () => {
    const signed = approval({ at: '2026-10-27T10:00:00Z' });
    const { relay } = fixture(wrapper({ type: 'keysentry-approval', v: 1, approval: signed }), { now: () => new Date('2026-10-27T10:00:00Z') });
    expect((await relay.poll(null)).approvals).toEqual([signed]);
  });

  test('disarm timestamps accept canonical ISO seconds without milliseconds', async () => {
    const signed = disarm('2026-10-27T10:00:00Z');
    const { relay } = fixture(wrapper({ type: 'keysentry-disarm', v: 2, ...signed }), { now: () => new Date('2026-10-27T10:00:00Z') });
    expect((await relay.poll(null)).disarms).toEqual([signed]);
  });

  test.each(['2026-10-27T12:00:00.0Z', '2026-10-27T12:00:00.00Z', '2026-10-27T12:00:00.0000Z', '2026-02-30T12:00:00Z'])('rejects noncanonical or impossible timestamp %s', async timestamp => {
    const signed = approval({ at: timestamp });
    const { relay } = fixture(wrapper({ type: 'keysentry-approval', v: 1, approval: signed }));
    expect((await relay.poll(null)).ignored).toBe(1);
  });

  test('poll sends an encoded supplied cursor and preserves it on an empty reply', async () => {
    const { relay, http } = fixture();
    expect(await relay.poll('old-message')).toEqual({ approvals: [], disarms: [], cursor: 'old-message', ignored: 0 });
    expect(http.calls[0]?.url).toBe(origin + '/' + topic + '/json?poll=1&since=old-message');
  });

  test('unsigned relay message is ignored, counted and audited without its contents', async () => {
    const { relay, events } = fixture(wrapper({ type: 'keysentry-approval', v: 1, approval: { actionId: 'do-not-audit-this-value', digest, at } }));
    expect(await relay.poll(null)).toEqual({ approvals: [], disarms: [], cursor: 'message1', ignored: 1 });
    expect(events).toHaveLength(1);
    expect(events[0]?.kind).toBe('approvals:relay-ignored');
    expect(JSON.stringify(events)).not.toContain('do-not-audit-this-value');
  });

  test.each([
    ['a modified action', (signed: ReturnType<typeof approval>) => ({ ...signed, actionId: 'action-2' })],
    ['a modified digest', (signed: ReturnType<typeof approval>) => ({ ...signed, digest: 'f'.repeat(64) })],
    ['a modified timestamp', (signed: ReturnType<typeof approval>) => ({ ...signed, at: '2026-10-27T12:01:00.000Z' })],
    ['an unknown key', (signed: ReturnType<typeof approval>) => ({ ...signed, keyId: otherKey.keyId })],
    ['a malformed signature', (signed: ReturnType<typeof approval>) => ({ ...signed, sig: 'not-a-signature' })],
    ['extra unsigned fields', (signed: ReturnType<typeof approval>) => ({ ...signed, unsafe: true })],
  ])('ignores %s', async (_name, mutate) => {
    const { relay, events } = fixture(wrapper({ type: 'keysentry-approval', v: 1, approval: mutate(approval()) }));
    expect((await relay.poll(null)).ignored).toBe(1);
    expect(events).toHaveLength(1);
  });

  test('keys must be both explicitly trusted and supplied by the trusted lookup', async () => {
    const payload = wrapper({ type: 'keysentry-approval', v: 1, approval: approval() });
    expect((await fixture(payload, { trustedKeyIds: [] }).relay.poll(null)).approvals).toEqual([]);
    expect((await fixture(payload, { deviceKeys: undefined }).relay.poll(null)).approvals).toEqual([]);
  });

  test('malformed JSON, unknown types and versions, malformed wrappers, and forged control events count as ignored', async () => {
    const body = [
      'not-json', wrapper('not-an-object', 'second'),
      wrapper({ type: 'unknown', v: 1 }, 'third'),
      wrapper({ type: 'keysentry-approval', v: 2, approval: approval() }, 'fourth'),
      JSON.stringify({ id: 'fifth', event: 'message', message: 'invalid json' }),
      JSON.stringify({ event: 'open', approval: approval() }),
      JSON.stringify({ id: 'sixth', time: 1793102400, event: 'message', topic: 'other-topic', message: JSON.stringify({ type: 'keysentry-approval', v: 1, approval: approval() }) }),
    ].join('\n');
    const { relay, events } = fixture(body);
    const result = await relay.poll(null);
    expect(result.approvals).toEqual([]);
    expect(result.ignored).toBe(7);
    expect(events.reduce((count, event) => count + Number(event.data?.count), 0)).toBe(7);
  });

  test('thousands of invalid lines are counted with a bounded number of audit writes', async () => {
    const { relay, events } = fixture('x\n'.repeat(5_000));
    expect((await relay.poll(null)).ignored).toBe(5_000);
    expect(events).toHaveLength(1);
    expect(events[0]?.data).toEqual({ reason: 'invalid-envelope', count: 5_000 });
  });

  test('ntfy open and keepalive controls are skipped only when structurally valid', async () => {
    const controls = ['open', 'keepalive'].map((event, i) => JSON.stringify({ id: 'control' + i, time: 1793102400, event, topic })).join('\n');
    expect(await fixture(controls).relay.poll('old')).toEqual({ approvals: [], disarms: [], cursor: 'old', ignored: 0 });
  });

  test('signed disarm messages are verified with their own prefix and returned once per relay instance', async () => {
    const signed = disarm();
    const { relay, events } = fixture(wrapper({ type: 'keysentry-disarm', v: 2, ...signed }));
    expect((await relay.poll(null)).disarms).toEqual([signed]);
    expect((await relay.poll(null)).ignored).toBe(1);
    expect(events.at(-1)?.kind).toBe('approvals:relay-ignored');
  });

  test('disarm rejects a malformed timestamp', async () => {
    const { relay } = fixture(wrapper({ type: 'keysentry-disarm', v: 2, ...disarm('bad-date') }));
    const result = await relay.poll(null);
    expect(result.disarms).toEqual([]);
    expect(result.ignored).toBe(1);
  });

  test.each(['2026-10-27T11:49:59.999Z', '2026-10-27T12:10:00.001Z'])('disarm has no ten minute freshness deadline: %s', async timestamp => {
    expect((await fixture(wrapper({ type: 'keysentry-disarm', v: 2, ...disarm(timestamp) })).relay.poll(null)).disarms).toHaveLength(1);
  });

  test.each(['2026-10-27T11:49:59.999Z', '2026-10-27T12:10:00.001Z'])('approval still rejects a timestamp outside the ten minute window: %s', async timestamp => {
    const result = await fixture(wrapper({ type: 'keysentry-approval', v: 1, approval: approval({ at: timestamp }) })).relay.poll(null);
    expect(result.approvals).toEqual([]);
    expect(result.ignored).toBe(1);
  });

  test('an approval signature cannot be substituted for a disarm signature', async () => {
    const signed = approval();
    const { relay } = fixture(wrapper({ type: 'keysentry-disarm', v: 2, watcherId: 'project', keyId: signed.keyId, at, sig: signed.sig }));
    expect((await relay.poll(null)).ignored).toBe(1);
  });

  test('oversized response and oversized NDJSON lines stop with content-free errors', async () => {
    await expect(fixture('x'.repeat(4 * 1024 * 1024 + 1)).relay.poll(null)).rejects.toThrow('Approval relay response is too large.');
    const { relay, events } = fixture('x'.repeat(16 * 1024 + 1));
    expect((await relay.poll(null)).ignored).toBe(1);
    expect(events).toHaveLength(1);
  });

  test('HTTP errors never expose the relay body or token', async () => {
    const { relay, http } = fixture('', { token: 'token-private' });
    http.on('GET', /^never-matches$/, () => text(500, 'private-server-error'));
    const failingHttp = new FakeHttp().on('GET', /./, () => text(500, 'private-server-error')).on('POST', /./, () => text(400, 'private-server-error'));
    const failed = fixture('', { http: failingHttp }).relay;
    await expect(failed.poll(null)).rejects.toThrow('Unable to poll the approval relay.');
    await expect(failed.publishApproval(approval())).rejects.toThrow('Unable to publish the approval.');
    expect((await relay.poll(null)).ignored).toBe(0);
  });

  test('audit failure rejects poll without forwarding unaudited ignored input or error contents', async () => {
    const { relay } = fixture('bad-json', { audit: { async append() { throw new Error('private-audit-data'); } } });
    await expect(relay.poll(null)).rejects.toThrow('Unable to record the approval relay outcome.');
  });

  test('an audit failure leaves a valid disarm available when the failed poll is retried', async () => {
    let fail = true;
    const audit = { async append() { if (fail) { fail = false; throw new Error('private-audit-data'); } } };
    const signed = disarm();
    const { relay } = fixture(wrapper({ type: 'keysentry-disarm', v: 2, ...signed }) + '\nbad-json', { audit });
    await expect(relay.poll(null)).rejects.toThrow('Unable to record the approval relay outcome.');
    expect((await relay.poll(null)).disarms).toEqual([signed]);
  });

  test.each([
    { server: 'http://ntfy.sh' }, { server: 'https://user:password@ntfy.sh' },
    { server: 'https://ntfy.sh/path' }, { server: 'https://ntfy.sh?token=private' },
    { server: 'https://ntfy.sh#fragment' }, { topic: '../other' }, { topic: 'a?token=private' },
    { token: 'bad\r\nheader' },
  ])('invalid configuration fails without reflecting it: %j', config => {
    expect(() => fixture('', config)).toThrow('Invalid approval relay configuration.');
  });
});
