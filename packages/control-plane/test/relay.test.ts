import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { APPROVAL_PREFIX, createRelay, signDisarm, type SignedDeviceApproval } from '../../../src/approvals/index.js';
import { createHandshake, generateBoxKeyPair } from '../../../src/box/handshake/index.js';
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
/** A disarm as publishDisarm sends it; `size` pads the watcher id (at most 4096 characters), so its bytes are known. */
const disarm = (size = 16) => ({ type: 'keysentry-disarm', v: 2, watcherId: `w-${randomBytes(6).toString('hex')}`.padEnd(size, 'x'),
  keyId: '0123456789abcdef', at: new Date(time).toISOString(), sig: randomBytes(64).toString('base64') });
/** Fills a box's queue with `count` disarms of about `size` bytes each. */
async function fill(relay: ReturnType<typeof createRelayStore>, boxId: string, count: number, size = 4000) {
  for (let i = 0; i < count; i++) await relay.publish(boxId, disarm(size));
}

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
  it('stores only validated signed documents, and offers no blob storage (M-a)', async () => {
    const storage = createMemoryStorage();
    const relay = createRelayStore({storage,now:()=>time});
    const message = hello();
    await relay.publish('box',message);
    for (const key of await storage.list('')) expect(JSON.stringify(await storage.get(key))).not.toContain(secret);
    await expect(relay.publish('box',{...message,plaintext:secret})).rejects.toThrow('Invalid relay message');
    await expect(relay.publish('box',{...message,attestationToken:secret})).rejects.toThrow('Invalid relay message');
    const ciphertext = sealBytes(randomBytes(32),Buffer.from(secret),'backup').toString('base64url');
    await expect(relay.publish('box',{kind:'sealed-state',ciphertext})).rejects.toThrow('Invalid relay message');
    expect(Object.keys(relay).sort()).toEqual(['poll','publish','sweep']);
    expect(await storage.list('blobs/')).toEqual([]);
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
  it('expires queued messages and physically sweeps storage, index records included', async () => {
    let now = time;
    const storage = createMemoryStorage();
    const relay = createRelayStore({storage,now:()=>now});
    await relay.publish('box',hello());
    await relay.publish('box-two',disarm());
    expect(await storage.list('relay-index/')).toEqual(['relay-index/box','relay-index/box-two']);
    now += 600000;
    await relay.sweep();
    expect(await storage.list('')).toEqual([]);
    expect(await relay.poll('box')).toEqual([]);
  });
  it('serializes concurrent publishes and bounds queues', async () => {
    const relay = createRelayStore({storage:createMemoryStorage(),now:()=>time,maxQueueMessages:2});
    await Promise.all([relay.publish('box',hello()),relay.publish('box',hello())]);
    expect(await relay.poll('box')).toHaveLength(2);
    await expect(relay.publish('box',hello())).rejects.toThrow('queue is full');
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
  it('a publish reads only its own box\'s records, however much other boxes hold', async () => {
    const { reads, storage } = counting(createMemoryStorage());
    const relay = createRelayStore({storage,now:()=>time});
    for (const box of ['box-b','box-c']) await fill(relay, box, 20);
    await relay.publish('box-a', disarm());
    reads.length = 0;
    await relay.publish('box-a', disarm());
    expect(reads).toEqual(['relay-index/box-a','relay/box-a']);
  });
  it('serializes per box: a slow box does not delay another box', async () => {
    const inner = createMemoryStorage();
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const storage: Storage = { ...inner, async get<T>(key: string) { if (key === 'relay-index/box-a') await gate; return inner.get<T>(key); } };
    const relay = createRelayStore({storage,now:()=>time});
    await relay.poll('box-b');
    const slow = relay.publish('box-a', disarm());
    await expect(relay.poll('box-b')).resolves.toEqual([]);
    await expect(relay.publish('box-b', disarm())).resolves.toHaveProperty('id');
    release();
    await slow;
  });
  it('bounds one box\'s queue by bytes and every queue together by the global quota', async () => {
    const perBox = createRelayStore({storage:createMemoryStorage(),now:()=>time,maxQueueBytes:10_000});
    await fill(perBox, 'box', 2);
    await expect(perBox.publish('box', disarm(4000))).rejects.toMatchObject({ status: 429 });

    const global = createRelayStore({storage:createMemoryStorage(),now:()=>time,maxTotalBytes:20_000,reserveBytes:4_000,shareBytes:5_000,maxQueueBytes:20_000});
    let refused: unknown;
    for (let n = 0; n < 10 && !refused; n++) await global.publish(`box-${n}`, disarm(4000)).catch(error => { refused = error; });
    expect(refused).toBeInstanceOf(RelayError);
    expect((refused as RelayError).status).toBe(507);
    expect(await global.poll('box-9')).toEqual([]);
  });
  it('M-a: boxes over their share are refused before they can refuse another box\'s disarm', async () => {
    const relay = createRelayStore({storage:createMemoryStorage(),now:()=>time,maxTotalBytes:64_000,reserveBytes:16_000,shareBytes:6_000,maxQueueBytes:20_000});
    // One tenant fills its boxes' queues until the shared quota pushes back.
    const statuses: number[] = [];
    for (let n = 0; n < 10 && !statuses.includes(507); n++) {
      for (;;) {
        const status = await relay.publish(`attacker-${n}`, disarm(4000)).then(() => 201, (error: RelayError) => error.status);
        if (status !== 201) { statuses.push(status); break; }
      }
    }
    expect(statuses).toEqual([429, 429, 507]);
    // Boxes within their share move usage into the reserve; there, a box holding more than its share is refused even
    // a tiny message, and every other box still publishes.
    for (let n = 0; n < 2; n++) await relay.publish(`small-${n}`, disarm(4000));
    for (let n = 0; n < 3; n++) await expect(relay.publish(`attacker-${n}`, disarm(16))).rejects.toMatchObject({ status: 507 });
    const wire = await published(r => r.publishDisarm(signDisarm(generateDeviceKey(), { watcherId: 'project-one', at: new Date(time).toISOString() })));
    await expect(relay.publish('victim-box', wire)).resolves.toHaveProperty('id');
    await expect(relay.publish('victim-box', hello())).resolves.toHaveProperty('id');
    expect(await relay.poll('victim-box')).toHaveLength(2);
  });
  it('refuses limits that leave no reserve or a share above the per-box quota', () => {
    expect(() => createRelayStore({storage:createMemoryStorage(),maxTotalBytes:8192,reserveBytes:8192})).toThrow('Invalid relay limits.');
    expect(() => createRelayStore({storage:createMemoryStorage(),maxQueueBytes:4096,shareBytes:8192})).toThrow('Invalid relay limits.');
  });
  it('rebuilds global usage from index records after a restart', async () => {
    const storage = createMemoryStorage();
    await fill(createRelayStore({storage,now:()=>time}), 'box-a', 3);
    const restarted = createRelayStore({storage,now:()=>time,maxTotalBytes:16_000,reserveBytes:1_000,shareBytes:1_000,maxQueueBytes:16_000});
    await expect(restarted.publish('box-b', disarm(4000))).rejects.toMatchObject({ status: 507 });
  });
  it('reads index records written before the blob API was removed', async () => {
    const storage = createMemoryStorage();
    const relay = createRelayStore({storage,now:()=>time});
    await relay.publish('box', disarm());
    const index = await storage.get<Record<string, unknown>>('relay-index/box');
    await storage.put('relay-index/box', { ...index, blobs: [{ id: 'a'.repeat(32), bytes: 64, expiresAt: time + 1000 }] });
    const restarted = createRelayStore({storage,now:()=>time});
    expect(await restarted.poll('box')).toHaveLength(1);
    await expect(restarted.publish('box', disarm())).resolves.toHaveProperty('id');
  });
  it('bounds the queue by bytes', async () => {
    const probe = createMemoryStorage();
    await createRelayStore({storage:probe,now:()=>time}).publish('box', hello());
    const one = Buffer.byteLength(JSON.stringify(await probe.get('relay/box')));
    const relay = createRelayStore({storage:createMemoryStorage(),now:()=>time,maxQueueBytes:one+64});
    await relay.publish('box', hello());
    await expect(relay.publish('box', hello())).rejects.toThrow('queue is full');
  });
  it('fails closed on a damaged index record without writing a message', async () => {
    const storage = createMemoryStorage();
    await storage.put('relay-index/box', { v: 1, queueBytes: 'lots', queueCount: 0 });
    const relay = createRelayStore({storage,now:()=>time});
    await expect(relay.publish('box', disarm())).rejects.toMatchObject({ status: 503 });
    expect(await storage.list('relay/')).toEqual([]);
  });
  it('sweeps a bounded batch of boxes per call and covers every box over repeated calls', async () => {
    let now = time;
    const storage = createMemoryStorage();
    const relay = createRelayStore({storage,now:()=>now,sweepBatch:2});
    for (const box of ['box-a','box-b','box-c']) await relay.publish(box, disarm());
    now += 600_000;
    await relay.sweep();
    expect((await storage.list('relay/')).length).toBe(1);
    await relay.sweep();
    expect(await storage.list('')).toEqual([]);
  });
});
