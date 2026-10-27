import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createStateCipher, createStateStore } from '../../src/core/store.js';
import { canonicalJson, generateDeviceKey, signDetached } from '../../src/security/index.js';
import { actionDigest, createApprovalService } from '../../src/approvals/service.js';
import type { ApprovalRequest, AuditEvent, AuditLog, PasskeyCredential } from '../../src/types.js';

const device = generateDeviceKey();
const passkey = generateDeviceKey();
const other = generateDeviceKey();
const origin = 'https://example.org';
const publicRaw = passkey.publicKeyDer.subarray(-32);
const cose = Buffer.concat([Buffer.from('a4010103272006215820', 'hex'), publicRaw]);
const baseCredential: PasskeyCredential = {
  id: Buffer.from('credential-one').toString('base64url'), publicKeyCose: cose.toString('base64url'),
  alg: -8, signCount: 0, backupEligible: false, rpId: 'example.org', origins: [origin],
  label: 'Laptop', createdAt: '2026-10-27T00:00:00.000Z',
};
const action = { id: 'rotate-one', kind: 'rotation', clusterIds: ['cluster-a', 'cluster-b'] };
let dir: string;
let now: Date;
let events: AuditEvent[];
let credentials: PasskeyCredential[];
let opts: Parameters<typeof createApprovalService>[0];
let service: ReturnType<typeof createApprovalService>;

function assertion(request: ApprovalRequest, count = 1, changes: Record<string, unknown> = {}, flags = 5) {
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: request.challenge, origin, ...changes }));
  const authenticatorData = Buffer.alloc(37);
  createHash('sha256').update('example.org').digest().copy(authenticatorData);
  authenticatorData[32] = flags;
  authenticatorData.writeUInt32BE(count, 33);
  const signature = signDetached(passkey.privateKeyDer, Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJSON).digest()]));
  return { credentialId: baseCredential.id, clientDataJSON, authenticatorData, signature };
}

function signed(request: ApprovalRequest, changes: Partial<{ actionId: string; digest: string; at: string }> = {}, key = device) {
  const message = { actionId: request.actionId, digest: request.digest, at: now.toISOString(), ...changes };
  return { ...message, keyId: key.keyId, sig: signDetached(key.privateKeyDer, Buffer.from('keysentry-approval:v1\n' + canonicalJson(message))).toString('base64') };
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'keysentry-approvals-'));
  now = new Date('2026-10-27T10:00:00.000Z');
  events = [];
  credentials = [{ ...baseCredential }];
  const audit: AuditLog = { append: async (event) => { events.push(event); }, checkpoint: async () => {}, verify: async () => ({ ok: true, entries: events.length, checkpoints: 0 }) };
  opts = { store: createStateStore({ cwd: dir, cipher: createStateCipher(Buffer.alloc(32, 7)) }), audit,
    credentials: async () => credentials, deviceKeys: async () => [{ keyId: device.keyId, publicKeyDer: device.publicKeyDer }],
    rpId: 'example.org', origins: [origin], now: () => now };
  service = createApprovalService(opts);
});
afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

describe('action binding and approval lifecycle', () => {
  test('digest covers the canonical complete action', () => {
    const digest = actionDigest({ clusterIds: ['cluster-a', 'cluster-b'], kind: 'rotation', id: 'rotate-one' });
    expect(digest).toBe(createHash('sha256').update('{"clusterIds":["cluster-a","cluster-b"],"id":"rotate-one","kind":"rotation"}').digest('hex'));
    expect(actionDigest({ ...action, planHash: 'changed' })).not.toBe(digest);
  });

  test('a valid passkey assertion approves exactly one pending action', async () => {
    const request = await service.request(action, false);
    expect(Buffer.from(request.challenge, 'base64url')).toHaveLength(32);
    expect(request.expiresAt).toBe('2026-10-27T10:10:00.000Z');
    expect(await service.approveWithPasskey(request.actionId, assertion(request))).toEqual({ actionId: action.id, digest: request.digest, at: now.toISOString(), by: { kind: 'passkey', credentialId: baseCredential.id } });
    expect(await service.status(action.id)).toBe('approved');
    expect(events.some((e) => e.kind === 'approvals:approved')).toBe(true);
  });

  test('replayed approval is rejected including across service instances', async () => {
    const request = await service.request(action, false);
    const approval = signed(request);
    await service.approveWithDevice(action.id, approval);
    await expect(createApprovalService(opts).approveWithDevice(action.id, approval)).rejects.toThrow(/already|used|replay/i);
    expect(events.some((e) => e.kind === 'approvals:replay')).toBe(true);
    expect(await service.status(action.id)).toBe('approved');
  });

  test('approval for another action or a changed digest is rejected', async () => {
    const request = await service.request(action, false);
    const otherRequest = await service.request({ ...action, id: 'rotate-two' }, false);
    await expect(service.approveWithDevice(otherRequest.actionId, signed(request))).rejects.toThrow();
    await expect(service.approveWithDevice(action.id, signed(request, { digest: '0'.repeat(64) }))).rejects.toThrow();
    expect(await service.status(action.id)).toBe('pending');
    expect(await service.status(otherRequest.actionId)).toBe('pending');
  });

  test('passkey assertions are bound to the stored challenge and origin', async () => {
    const request = await service.request(action, false);
    await expect(service.approveWithPasskey(action.id, assertion(request, 1, { challenge: Buffer.alloc(32).toString('base64url') }))).rejects.toThrow();
    await expect(service.approveWithPasskey(action.id, assertion(request, 1, { origin: 'https://another.example' }))).rejects.toThrow();
    await expect(service.approveWithPasskey(action.id, assertion(request, 1, {}, 1))).rejects.toThrow();
    expect(await service.status(action.id)).toBe('pending');
  });

  test('expired requests cannot be approved and expiry is audited once', async () => {
    const request = await service.request(action, false);
    now = new Date(request.expiresAt);
    await expect(service.approveWithPasskey(action.id, assertion(request))).rejects.toThrow(/expired/i);
    await expect(service.approveWithDevice(action.id, signed(request))).rejects.toThrow(/expired/i);
    expect(await service.status(action.id)).toBe('expired');
    expect(events.filter((e) => e.kind === 'approvals:expired')).toHaveLength(1);
  });

  test('widening actions refuse passkey approval and accept a device-key approval', async () => {
    const request = await service.request(action, true);
    await expect(service.approveWithPasskey(action.id, assertion(request))).rejects.toThrow('This change can only be approved on your own computer with `keysentry approve`.');
    expect(events.some((e) => e.kind === 'approvals:widening-refused')).toBe(true);
    expect((await service.approveWithDevice(action.id, signed(request))).by).toEqual({ kind: 'device', keyId: device.keyId });
  });

  test('unknown credentials and five failed attempts reject the request', async () => {
    const request = await service.request(action, false);
    for (let i = 0; i < 5; i++) await expect(service.approveWithPasskey(action.id, { ...assertion(request), credentialId: 'unknown' })).rejects.toThrow();
    expect(await createApprovalService(opts).status(action.id)).toBe('rejected');
    await expect(service.approveWithPasskey(action.id, assertion(request))).rejects.toThrow();
    expect(events.filter((e) => e.kind === 'approvals:rejected')).toHaveLength(6);
  });

  test('clone warnings reject and accepted sign counters persist across instances', async () => {
    const first = await service.request(action, false);
    await service.approveWithPasskey(first.actionId, assertion(first, 5));
    service = createApprovalService(opts);
    const second = await service.request({ ...action, id: 'rotate-two' }, false);
    await expect(service.approveWithPasskey(second.actionId, assertion(second, 5))).rejects.toThrow();
    expect(await service.status(second.actionId)).toBe('pending');
    await service.approveWithPasskey(second.actionId, assertion(second, 6));
    expect(await service.status(second.actionId)).toBe('approved');
    expect(credentials[0]!.signCount).toBe(0);
  });

  test('untrusted device, malformed signature and timestamps outside ten minutes reject', async () => {
    const request = await service.request(action, false);
    await expect(service.approveWithDevice(action.id, signed(request, {}, other))).rejects.toThrow();
    await expect(service.approveWithDevice(action.id, { ...signed(request), sig: 'invalid' })).rejects.toThrow();
    await expect(service.approveWithDevice(action.id, signed(request, { at: '2026-10-27T09:49:59.999Z' }))).rejects.toThrow();
    await expect(service.approveWithDevice(action.id, signed(request, { at: '2026-10-27T10:10:00.001Z' }))).rejects.toThrow();
    expect((await service.approveWithDevice(action.id, signed(request, { at: '2026-10-27T10:10:00.000Z' }))).by.kind).toBe('device');
  });

  test('concurrent approvals across instances consume a challenge only once', async () => {
    const request = await service.request(action, false);
    const results = await Promise.allSettled([service.approveWithPasskey(action.id, assertion(request)), createApprovalService(opts).approveWithDevice(action.id, signed(request))]);
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter((r) => r.status === 'rejected')).toHaveLength(1);
    expect(events.filter((e) => e.kind === 'approvals:approved')).toHaveLength(1);
  });

  test('action IDs cannot be rebound or revived with a fresh challenge', async () => {
    await service.request(action, false);
    await expect(service.request({ ...action, clusterIds: ['other'] }, false)).rejects.toThrow();
    await expect(service.request(action, false)).rejects.toThrow();
    expect(await service.status(action.id)).toBe('pending');
  });

  test('non-string action IDs reject without poisoning saved approval state', async () => {
    for (const id of [123, undefined, null, ['rotate']]) {
      await expect(service.request({ ...action, id } as never, false)).rejects.toThrow();
    }
    await service.request(action, false);
    expect(await service.status(action.id)).toBe('pending');
  });

  test('expired approval attempts are audited as rejected without repeated expiry transitions', async () => {
    const request = await service.request(action, false);
    now = new Date(request.expiresAt);
    await service.status(action.id);
    const before = events.length;
    await expect(service.approveWithDevice(action.id, signed(request))).rejects.toThrow(/expired/i);
    expect(events.slice(before)).toMatchObject([{ kind: 'approvals:rejected', data: { actionId: action.id } }]);
  });

  test('unknown or removed credentials cannot use a retained challenge', async () => {
    const request = await service.request(action, false);
    credentials = [];
    await expect(service.approveWithPasskey(action.id, assertion(request))).rejects.toThrow();
    expect(await service.challenge(action.id)).toMatchObject({ allowCredentials: [] });
    expect(await service.status(action.id)).toBe('pending');
  });

  test('registered credentials for another RP cannot approve', async () => {
    const request = await service.request(action, false);
    credentials[0]!.rpId = 'another.example';
    await expect(service.approveWithPasskey(action.id, assertion(request))).rejects.toThrow();
    expect(await service.status(action.id)).toBe('pending');
  });

  test('an audit failure releases the queue and never returns an unaudited grant', async () => {
    const request = await service.request(action, false);
    const failed = createApprovalService({ ...opts, audit: { ...opts.audit, append: async () => { throw new Error('audit unavailable'); } } });
    await expect(failed.approveWithDevice(action.id, signed(request))).rejects.toThrow('audit unavailable');
    await expect(failed.status(action.id)).rejects.toThrow('audit unavailable');
    expect(await service.status(action.id)).toBe('approved');
    expect(events.filter((event) => event.kind === 'approvals:approved')).toHaveLength(1);
    await expect(service.approveWithDevice(action.id, signed(request))).rejects.toThrow(/used/i);
    await service.request({ ...action, id: 'rotate-two' }, false);
    expect(await service.status('rotate-two')).toBe('pending');
  });

  test('requests never exceed 100 pending under concurrent writers', async () => {
    const results = await Promise.allSettled(Array.from({ length: 101 }, (_, i) => createApprovalService(opts).request({ ...action, id: `rotate-${i}` }, false)));
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(100);
    expect(results.filter((r) => r.status === 'rejected')).toHaveLength(1);
  });

  test('expired records remain for seven days then are pruned', async () => {
    const request = await service.request(action, false);
    now = new Date(request.expiresAt);
    expect(await service.status(action.id)).toBe('expired');
    now = new Date('2026-11-03T10:09:59.999Z');
    expect(await service.describe(action.id)).toMatchObject({ status: 'expired' });
    now = new Date('2026-11-03T10:10:00.000Z');
    expect(await service.describe(action.id)).toBeNull();
  });

  test('approval state is encrypted and safe display metadata omits challenge and cluster IDs', async () => {
    const request = await service.request(action, false);
    expect(await service.describe(action.id)).toEqual({ kind: 'rotation', keyCount: 2, expiresAt: request.expiresAt, status: 'pending' });
    expect(await service.challenge(action.id)).toEqual({ challenge: request.challenge, rpId: 'example.org', allowCredentials: [{ type: 'public-key', id: baseCredential.id }] });
    const raw = await readFile(join(dir, '.keysentry', 'approvals.json'), 'utf8');
    expect(raw.startsWith('keysentry-encrypted:v1\n')).toBe(true);
    expect(raw).not.toContain(request.challenge);
    const auditText = JSON.stringify(events);
    expect(auditText).not.toContain(request.challenge);
    expect(auditText).not.toContain(baseCredential.publicKeyCose);
  });

  test('disarm audit records only the hashed client', async () => {
    await service.recordDisarm('a'.repeat(64));
    expect(events.at(-1)).toMatchObject({ kind: 'approvals:disarm', data: { clientHash: 'a'.repeat(64) } });
  });

  test('disarm audit is retained even while an earlier outcome cannot be audited', async () => {
    const request = await service.request(action, false);
    const failed = createApprovalService({ ...opts, audit: { ...opts.audit, append: async () => { throw new Error('audit unavailable'); } } });
    await expect(failed.approveWithDevice(action.id, signed(request))).rejects.toThrow();
    await expect(failed.recordDisarm('b'.repeat(64))).rejects.toThrow();
    expect(await service.status(action.id)).toBe('approved');
    expect(events.at(-1)).toMatchObject({ kind: 'approvals:disarm', data: { clientHash: 'b'.repeat(64) } });
  });
});
