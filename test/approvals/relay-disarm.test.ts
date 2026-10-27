import { expect, test } from 'vitest';
import * as relayApi from '../../src/approvals/relay.js';
import { canonicalJson, generateDeviceKey, signDetached, verifyDetached } from '../../src/security/index.js';
import type { AuditLog } from '../../src/types.js';
import { FakeHttp, json, text } from '../helpers/fake-http.js';

const key = generateDeviceKey();
const watcherId = 'project-one';
const at = '2026-11-01T12:00:00.000Z';
const topic = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const trustedKeys = [{ keyId: key.keyId, publicKeyDer: key.publicKeyDer }];
const audit: AuditLog = { async append() {}, async checkpoint() {}, async verify() { return { ok: true, entries: 0, checkpoints: 0 }; } };

// This signer is intentionally independent of the production helper to catch protocol mismatches.
function signedDisarm(timestamp = at, watcher = watcherId) {
  const body = { watcherId: watcher, keyId: key.keyId, at: timestamp };
  return { ...body, sig: signDetached(key.privateKeyDer, Buffer.from('keysentry-disarm:v2\n' + canonicalJson(body))).toString('base64') };
}

function fixture(signed = signedDisarm(), opts: Record<string, unknown> = {}) {
  const body = JSON.stringify({ id: 'm1', time: 1793534400, event: 'message', topic,
    message: JSON.stringify({ type: 'keysentry-disarm', v: 2, ...signed }) });
  const http = new FakeHttp().on('GET', /\/json\?/, () => text(200, body)).on('POST', /ntfy\.sh\//, () => json(200, {}));
  const relay = relayApi.createRelay({ http, server: 'https://ntfy.sh', topic, trustedKeyIds: [key.keyId],
    deviceKeys: async () => trustedKeys, audit, now: () => new Date('2026-11-01T12:12:00.000Z'), watcherId, ...opts });
  return { relay, http };
}

test('a watcher-bound v2 disarm is accepted when the watcher reads it twelve minutes later', async () => {
  const signed = signedDisarm();
  expect((await fixture(signed).relay.poll('earlier-cursor')).disarms).toEqual([signed]);
});

test('a first or restarted watcher retrieves retained disarms older than ten minutes', async () => {
  const signed = signedDisarm();
  const body = JSON.stringify({ id: 'retained', time: 1793534400, event: 'message', topic,
    message: JSON.stringify({ type: 'keysentry-disarm', v: 2, ...signed }) });
  const http = new FakeHttp()
    .on('GET', /\/json\?poll=1&since=all$/, () => text(200, body))
    .on('GET', /\/json\?/, () => text(200, ''));
  expect((await fixture(signed, { http }).relay.poll(null)).disarms).toEqual([signed]);
});

test('a verified disarm stays deduplicated after the old freshness window', async () => {
  let now = new Date(at);
  const signed = signedDisarm();
  const { relay } = fixture(signed, { now: () => now });
  expect((await relay.poll(null)).disarms).toEqual([signed]);
  now = new Date('2027-01-01T12:00:00.000Z');
  expect((await relay.poll(null)).disarms).toEqual([]);
});

test('a valid signature for another watcher never disarms this watcher', async () => {
  expect((await fixture(signedDisarm(at, 'project-two')).relay.poll(null)).disarms).toEqual([]);
});

test('a relay without a configured watcher id accepts no disarms', async () => {
  expect((await fixture(signedDisarm(), { watcherId: undefined }).relay.poll(null)).disarms).toEqual([]);
});

test('the shared signer binds the watcher, key id and timestamp with the v2 domain', () => {
  const signed = relayApi.signDisarm(key, { watcherId, at });
  expect(signed).toEqual({ watcherId, keyId: key.keyId, at, sig: expect.any(String) });
  expect(verifyDetached(key.publicKeyDer, Buffer.from('keysentry-disarm:v2\n' + canonicalJson({ watcherId, keyId: key.keyId, at })), Buffer.from(signed.sig, 'base64'))).toBe(true);
  expect(relayApi.verifyDisarm(signed, trustedKeys, watcherId)).toBe(true);
});

test('disarm accepts the project id length supported by sealed watcher configurations', async () => {
  const projectId = 'p'.repeat(4096);
  const signed = signedDisarm(at, projectId);
  expect((await fixture(signed, { watcherId: projectId }).relay.poll(null)).disarms).toEqual([signed]);
});

test('the shared verifier rejects changes to every signed disarm field and unknown keys', () => {
  const signed = signedDisarm();
  expect(relayApi.verifyDisarm(signed, trustedKeys, watcherId)).toBe(true);
  expect(relayApi.verifyDisarm({ ...signed, watcherId: 'project-two' }, trustedKeys, 'project-two')).toBe(false);
  expect(relayApi.verifyDisarm({ ...signed, keyId: '0'.repeat(16) }, trustedKeys, watcherId)).toBe(false);
  expect(relayApi.verifyDisarm({ ...signed, at: '2026-11-01T12:01:00.000Z' }, trustedKeys, watcherId)).toBe(false);
  expect(relayApi.verifyDisarm(signed, [], watcherId)).toBe(false);
  expect(relayApi.verifyDisarm({ ...signed, extra: true }, trustedKeys, watcherId)).toBe(false);
});

test('the shared verifier never throws on malformed disarm input', () => {
  for (const input of [null, undefined, [], {}, { ...signedDisarm(), at: '2026-02-30T12:00:00Z' }, { ...signedDisarm(), sig: 'bad-signature' }]) {
    expect(relayApi.verifyDisarm(input, trustedKeys, watcherId)).toBe(false);
  }
});

test('legacy unbound disarms fail closed even with a trusted signature', async () => {
  const legacy = { keyId: key.keyId, at, sig: signDetached(key.privateKeyDer, Buffer.from('keysentry-disarm:v1\n' + canonicalJson({ at }))).toString('base64') };
  const body = JSON.stringify({ id: 'old', time: 1793534400, event: 'message', topic, message: JSON.stringify({ type: 'keysentry-disarm', v: 1, ...legacy }) });
  const http = new FakeHttp().on('GET', /\/json\?/, () => text(200, body));
  expect((await fixture(signedDisarm(), { http }).relay.poll(null)).disarms).toEqual([]);
  expect(relayApi.verifyDisarm(legacy, trustedKeys, watcherId)).toBe(false);
});

test('publishDisarm uses the v2 envelope and configured watcher binding', async () => {
  const signed = signedDisarm();
  const { relay, http } = fixture(signed);
  await relay.publishDisarm(signed);
  expect(http.calls).toEqual([{ method: 'POST', url: 'https://ntfy.sh/' + topic,
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: 'keysentry-disarm', v: 2, ...signed }) }]);
  await expect(relay.publishDisarm(signedDisarm(at, 'project-two'))).rejects.toThrow('Invalid signed disarm.');
});
