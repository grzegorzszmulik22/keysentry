import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { APPROVAL_PREFIX, createRelay, signDisarm, type SignedDeviceApproval } from '../../../src/approvals/index.js';
import { createHandshake, generateBoxKeyPair, sealToBox } from '../../../src/box/handshake/index.js';
import { canonicalJson, generateDeviceKey, sealBytes, signDetached } from '../../../src/security/index.js';
import type { HttpClient, HttpRequest } from '../../../src/types.js';
import { createMemoryStorage, type Storage } from '../src/storage.js';
import { createRelayStore, RelayError } from '../src/relay.js';

const time = Date.parse('2026-10-27T12:00:00.000Z');
const secret = 'sk-planted-plaintext-never-store-0123456789';
function hello() {
  const deviceKey = generateDeviceKey();
  const hs = createHandshake('box',{devicePublicKeyDer:deviceKey.publicKeyDer,signingKey:generateDeviceKey(),boxKey:generateBoxKeyPair()});
  const segment = Buffer.from(JSON.stringify({alg:'RS256',typ:'JWT',kid:'test'})).toString('base64url');
  const payload = Buffer.from(JSON.stringify({iss:'https://confidentialcomputing.googleapis.com'})).toString('base64url');
  return hs.next({now:new Date(time),attestationToken:`${segment}.${payload}.${randomBytes(256).toString('base64url')}`}).message!;
}
/** The exact bodies src/approvals/relay.ts publishes, captured from its own HTTP request. */
async function published(send: (relay: ReturnType<typeof createRelay>) => Promise<void>, watcherId = 'project-one'): Promise<unknown> {
  let body = '';
  const http: HttpClient = { async request(req: HttpRequest) { body = req.body ?? ''; return { status: 200, headers: {}, text: '', json: <T>() => ({}) as T }; } };
  const relay = createRelay({ http, server: 'https://relay.example', topic: 'topic', trustedKeyIds: [], watcherId, audit: { append: async () => undefined } as never });
  await send(relay);
  return JSON.parse(body) as unknown;
}
function approval(at: Date): SignedDeviceApproval {
  const key = generateDeviceKey();
  const data = { actionId: 'action-one', digest: 'b'.repeat(64), at: at.toISOString() };
  // The same signing code path as src/cli/autopilot-approvals.ts.
  return { ...data, keyId: key.keyId, sig: signDetached(key.privateKeyDer, Buffer.from(APPROVAL_PREFIX + canonicalJson(data))).toString('base64') };
}
function counting(inner: Storage) {
  const reads: string[] = [];
  return { reads, storage: { ...inner, async get<T>(key: string) { reads.push(key); return inner.get<T>(key); } } as Storage };
}
const blob = (bytes: number, ttlMs?: number) => ({ kind: 'sealed-state' as const, ciphertext: randomBytes(bytes).toString('base64url'), ...(ttlMs ? { ttlMs } : {}) });

describe('ciphertext relay', () => {
  it('isolates box/session queues and refuses duplicate messages', async () => {
    const storage = createMemoryStorage();
    const relay = createRelayStore({storage,now:()=>time});
    const message = hello();
    await relay.publish('box-one',message);
    expect(await relay.poll('box-two')).toEqual([]);
    expect(await relay.poll('box-one','different')).toEqual([]);
    expect(await relay.poll('box-one',message.sessionId)).toEqual([message]);
    await expect(relay.publish('box-one',message)).rejects.toThrow('already queued');
  });
  it('stores only validated signed documents and opaque ciphertext', async () => {
    const storage = createMemoryStorage();
    const relay = createRelayStore({storage,now:()=>time});
    const message = hello();
    await relay.publish('box',message);
    const ciphertext = sealBytes(randomBytes(32),Buffer.from(secret),'backup').toString('base64url');
    const stored = await relay.putBlob('box',{kind:'sealed-state',ciphertext});
    expect((await relay.getBlob('box',stored.id))?.ciphertext).toBe(ciphertext);
    for (const key of await storage.list('')) expect(JSON.stringify(await storage.get(key))).not.toContain(secret);
    await expect(relay.publish('box',{...message,plaintext:secret})).rejects.toThrow('Invalid relay message');
    await expect(relay.publish('box',{...message,attestationToken:secret})).rejects.toThrow('Invalid relay message');
    await expect(relay.putBlob('box',{kind:'sealed-state',ciphertext:secret})).rejects.toThrow('Invalid ciphertext blob');
  });
  it('rejects malformed, oversized, expired and future messages', async () => {
    const storage = createMemoryStorage();
    const message = hello();
    const relay = createRelayStore({storage,now:()=>time,maxMessageBytes:100});
    await expect(relay.publish('box',message)).rejects.toThrow('too large');
    const normal = createRelayStore({storage,now:()=>time});
    for (const changed of [{...message,sig:'invalid'},{...message,seq:8},{...message,sentAt:new Date(time-700000).toISOString(),expiresAt:new Date(time-100000).toISOString()}, {...message,sentAt:new Date(time+70000).toISOString(),expiresAt:new Date(time+670000).toISOString()}]) {
      await expect(normal.publish('box',changed)).rejects.toThrow('Invalid relay message');
    }
    expect(await storage.list('')).toEqual([]);
  });
  it('expires queued messages and blobs and physically sweeps storage, index records included', async () => {
    let now = time;
    const storage = createMemoryStorage();
    const relay = createRelayStore({storage,now:()=>now});
    await relay.publish('box',hello());
    const stored = await relay.putBlob('box',{kind:'sealed-bundle',ciphertext:sealToBox(generateBoxKeyPair().publicKeyRaw,Buffer.from(secret),'test').toString('base64url'),ttlMs:1000});
    expect(await storage.list('relay-index/')).toEqual(['relay-index/box']);
    now += 1000;
    expect(await relay.getBlob('box',stored.id)).toBeNull();
    now += 600000;
    await relay.sweep();
    expect(await relay.poll('box')).toEqual([]);
    expect(await storage.list('')).toEqual([]);
  });
  it('serializes concurrent publishes and bounds queues and blob TTL', async () => {
    const relay = createRelayStore({storage:createMemoryStorage(),now:()=>time,maxQueueMessages:2});
    await Promise.all([relay.publish('box',hello()),relay.publish('box',hello())]);
    expect(await relay.poll('box')).toHaveLength(2);
    await expect(relay.publish('box',hello())).rejects.toThrow('queue is full');
    await expect(relay.putBlob('box',{kind:'sealed-state',ciphertext:randomBytes(40).toString('base64url'),ttlMs:86400001})).rejects.toThrow('Invalid ciphertext blob');
  });
});

describe('M4: approval and disarm wire formats', () => {
  it('relays a disarm exactly as publishDisarm sends it, whatever watcher it names', async () => {
    const relay = createRelayStore({storage:createMemoryStorage(),now:()=>time});
    const key = generateDeviceKey();
    // The CLI signs with the project id as watcherId; the watcher, not the relay, checks it.
    const wire = await published(r => r.publishDisarm(signDisarm(key, { watcherId: 'project-one', at: new Date(time).toISOString() })));
    expect(wire).toMatchObject({ type: 'keysentry-disarm', v: 2, watcherId: 'project-one' });
    await relay.publish('box-one', wire);
    expect(await relay.poll('box-one')).toEqual([wire]);
  });
  it('accepts the seconds-only `at` form that validAt accepts, and an old disarm', async () => {
    const relay = createRelayStore({storage:createMemoryStorage(),now:()=>time});
    const key = generateDeviceKey();
    for (const at of ['2026-10-27T11:59:59Z', '2025-01-01T00:00:00.000Z']) {
      const wire = await published(r => r.publishDisarm(signDisarm(key, { watcherId: 'project-one', at })));
      await expect(relay.publish('box', wire)).resolves.toHaveProperty('id');
    }
  });
  it('refuses the old v1 nested disarm, extra fields, bad signatures and non-canonical times', async () => {
    const relay = createRelayStore({storage:createMemoryStorage(),now:()=>time});
    const wire = await published(r => r.publishDisarm(signDisarm(generateDeviceKey(), { watcherId: 'project-one', at: new Date(time).toISOString() }))) as Record<string, unknown>;
    const { type: _type, v: _v, ...signed } = wire;
    for (const bad of [
      { type: 'keysentry-disarm', v: 1, disarm: signed }, { ...wire, extra: secret }, { ...wire, v: 3 },
      { ...wire, sig: randomBytes(63).toString('base64') }, { ...wire, keyId: 'A'.repeat(16) },
      { ...wire, at: '2026-10-27T12:00:00.0Z' }, { ...wire, at: '2026-02-30T12:00:00Z' }, { ...wire, watcherId: 'line\nbreak' }, { ...wire, watcherId: '' },
    ]) await expect(relay.publish('box', bad)).rejects.toThrow('Invalid relay message');
  });
  it('relays an approval exactly as publishApproval sends it while the verifier window is open', async () => {
    let now = time;
    const relay = createRelayStore({storage:createMemoryStorage(),now:()=>now});
    const wire = await published(r => r.publishApproval(approval(new Date(time))));
    expect(wire).toMatchObject({ type: 'keysentry-approval', v: 1, approval: { actionId: 'action-one' } });
    await relay.publish('box', wire);
    expect(await relay.poll('box')).toEqual([wire]);
    now += 10 * 60_000;
    expect(await relay.poll('box')).toEqual([]);
    for (const at of [new Date(now - 11 * 60_000), new Date(now + 11 * 60_000)]) {
      await expect(relay.publish('box', await published(r => r.publishApproval(approval(at))))).rejects.toThrow('Invalid relay message');
    }
    now = time;
    const seconds = approval(new Date(time)); seconds.at = '2026-10-27T12:00:00Z';
    await expect(relay.publish('box', { type: 'keysentry-approval', v: 1, approval: seconds })).resolves.toHaveProperty('id');
    await expect(relay.publish('box', { ...(wire as object), extra: secret })).rejects.toThrow('Invalid relay message');
  });
});

describe('M2: per-box work, index records and quotas', () => {
  it('counts a box from its index record without reading its blobs', async () => {
    const { reads, storage } = counting(createMemoryStorage());
    const relay = createRelayStore({storage,now:()=>time});
    for (let i = 0; i < 20; i++) await relay.putBlob('box-a', blob(1024));
    reads.length = 0;
    await relay.putBlob('box-a', blob(1024));
    expect(reads).toEqual(['relay-index/box-a']);
  });
  it('serializes per box: a slow box does not delay another box', async () => {
    const inner = createMemoryStorage();
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const storage: Storage = { ...inner, async get<T>(key: string) { if (key === 'relay-index/box-a') await gate; return inner.get<T>(key); } };
    const relay = createRelayStore({storage,now:()=>time});
    await relay.poll('box-b');
    const slow = relay.putBlob('box-a', blob(64));
    await expect(relay.poll('box-b')).resolves.toEqual([]);
    release();
    await slow;
  });
  it('enforces per-box blob count, per-box bytes and the global byte quota, and frees them on expiry', async () => {
    let now = time;
    const storage = createMemoryStorage();
    const count = createRelayStore({storage,now:()=>now,maxBlobsPerBox:2});
    await count.putBlob('box', blob(64, 1000)); await count.putBlob('box', blob(64, 1000));
    await expect(count.putBlob('box', blob(64))).rejects.toThrow('storage is full');
    now += 1000;
    await expect(count.putBlob('box', blob(64))).resolves.toHaveProperty('id');

    const bytes = createRelayStore({storage:createMemoryStorage(),now:()=>now,maxBlobBytesPerBox:4096});
    await bytes.putBlob('box', blob(2000));
    await expect(bytes.putBlob('box', blob(2000))).rejects.toMatchObject({ status: 429 });

    const global = createRelayStore({storage:createMemoryStorage(),now:()=>now,maxTotalBytes:8192});
    await global.putBlob('box-a', blob(3000));
    await global.putBlob('box-b', blob(2000));
    const full = await global.putBlob('box-c', blob(3000)).catch(error => error as RelayError);
    expect(full).toBeInstanceOf(RelayError);
    expect((full as RelayError).status).toBe(507);
    expect(await global.poll('box-c')).toEqual([]);
  });
  it('rebuilds global usage from index records after a restart', async () => {
    const storage = createMemoryStorage();
    await createRelayStore({storage,now:()=>time}).putBlob('box-a', blob(3000));
    const restarted = createRelayStore({storage,now:()=>time,maxTotalBytes:6000});
    await expect(restarted.putBlob('box-b', blob(3000))).rejects.toMatchObject({ status: 507 });
  });
  it('bounds the queue by bytes', async () => {
    const probe = createMemoryStorage();
    await createRelayStore({storage:probe,now:()=>time}).publish('box', hello());
    const one = Buffer.byteLength(JSON.stringify(await probe.get('relay/box')));
    const relay = createRelayStore({storage:createMemoryStorage(),now:()=>time,maxQueueBytes:one+64});
    await relay.publish('box', hello());
    await expect(relay.publish('box', hello())).rejects.toThrow('queue is full');
  });
  it('fails closed on a damaged index record without writing a blob', async () => {
    const storage = createMemoryStorage();
    await storage.put('relay-index/box', { v: 1, queueBytes: 'lots', queueCount: 0, blobs: [] });
    const relay = createRelayStore({storage,now:()=>time});
    await expect(relay.putBlob('box', blob(64))).rejects.toMatchObject({ status: 503 });
    expect(await storage.list('blobs/')).toEqual([]);
  });
  it('sweeps a bounded batch of boxes per call and covers every box over repeated calls', async () => {
    let now = time;
    const storage = createMemoryStorage();
    const relay = createRelayStore({storage,now:()=>now,sweepBatch:2});
    for (const box of ['box-a','box-b','box-c']) await relay.putBlob(box, blob(64, 1000));
    now += 1000;
    await relay.sweep();
    expect((await storage.list('blobs/')).length).toBe(1);
    await relay.sweep();
    expect(await storage.list('')).toEqual([]);
  });
});
