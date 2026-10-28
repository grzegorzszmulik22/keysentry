import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createHandshake, generateBoxKeyPair, sealToBox } from '../../../src/box/handshake/index.js';
import { generateDeviceKey, sealBytes } from '../../../src/security/index.js';
import { createMemoryStorage } from '../src/storage.js';
import { createRelayStore } from '../src/relay.js';

const time = Date.parse('2026-10-27T12:00:00.000Z');
const secret = 'sk-planted-plaintext-never-store-0123456789';
function hello() {
  const deviceKey = generateDeviceKey();
  const hs = createHandshake('box',{devicePublicKeyDer:deviceKey.publicKeyDer,signingKey:generateDeviceKey(),boxKey:generateBoxKeyPair()});
  const segment = Buffer.from(JSON.stringify({alg:'RS256',typ:'JWT',kid:'test'})).toString('base64url');
  const payload = Buffer.from(JSON.stringify({iss:'https://confidentialcomputing.googleapis.com'})).toString('base64url');
  return hs.next({now:new Date(time),attestationToken:`${segment}.${payload}.${randomBytes(256).toString('base64url')}`}).message!;
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
  it('stores only validated signed documents and opaque ciphertext', async () => {
    const storage = createMemoryStorage();
    const relay = createRelayStore({storage,now:()=>time});
    const message = hello();
    await relay.publish('box',message);
    const ciphertext = sealBytes(randomBytes(32),Buffer.from(secret),'backup').toString('base64url');
    const blob = await relay.putBlob('box',{kind:'sealed-state',ciphertext});
    expect((await relay.getBlob('box',blob.id))?.ciphertext).toBe(ciphertext);
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
  it('expires queued messages and blobs and physically sweeps storage', async () => {
    let now = time;
    const storage = createMemoryStorage();
    const relay = createRelayStore({storage,now:()=>now});
    await relay.publish('box',hello());
    const blob = await relay.putBlob('box',{kind:'sealed-bundle',ciphertext:sealToBox(generateBoxKeyPair().publicKeyRaw,Buffer.from(secret),'test').toString('base64url'),ttlMs:1000});
    now += 1000;
    expect(await relay.getBlob('box',blob.id)).toBeNull();
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
  it('bounds blob size and accepts strict signed approval/disarm wrappers', async () => {
    const storage = createMemoryStorage();
    const relay = createRelayStore({storage,now:()=>time,maxBlobBytes:64});
    await expect(relay.putBlob('box',{kind:'sealed-state',ciphertext:randomBytes(65).toString('base64url')})).rejects.toThrow('too large');
    const approval = {type:'keysentry-approval',v:1,approval:{actionId:'action',keyId:'a'.repeat(16),digest:'b'.repeat(64),at:new Date(time).toISOString(),sig:randomBytes(64).toString('base64')}};
    const disarm = {type:'keysentry-disarm',v:1,disarm:{watcherId:'box',keyId:'a'.repeat(16),at:new Date(time).toISOString(),sig:randomBytes(64).toString('base64')}};
    await relay.publish('box',approval);
    await relay.publish('box',disarm);
    expect(await relay.poll('box')).toEqual([approval,disarm]);
    await expect(relay.publish('box',{...approval,extra:secret})).rejects.toThrow('Invalid relay message');
  });
  it('can deliver an older signed disarm while expiry bounds its relay storage', async () => {
    let clock=time;
    const relay=createRelayStore({storage:createMemoryStorage(),now:()=>clock});
    const disarm={type:'keysentry-disarm',v:1,disarm:{watcherId:'box',keyId:'a'.repeat(16),at:new Date(time-86400000).toISOString(),sig:randomBytes(64).toString('base64')}};
    await relay.publish('box',disarm);
    expect(await relay.poll('box')).toEqual([disarm]);
    clock+=600000;
    expect(await relay.poll('box')).toEqual([]);
  });
});
