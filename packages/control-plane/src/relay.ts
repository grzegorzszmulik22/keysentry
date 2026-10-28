import { createHash } from 'node:crypto';
import { parseHandshakeMessage } from '../../../src/box/handshake/index.js';
import { canonicalJson } from '../../../src/security/index.js';
import { keyedLock } from './lock.js';
import type { Storage } from './storage.js';

interface Queued {id:string; sessionId?:string; expiresAt:number; message:unknown}
/** Per-box index: the size of the box's queue, so the global quota never requires reading queues. */
interface BoxIndex {v:1; queueBytes:number; queueCount:number}
/**
 * Short-lived message queues only. There is no blob storage (M-a): nothing in keysentry used it, and a shared blob
 * quota let a few tenants refuse every other box's disarms.
 */
export interface RelayStore {
  publish(boxId:string,message:unknown):Promise<{id:string}>;
  poll(boxId:string,sessionId?:string):Promise<unknown[]>;
  /** Removes expired records for the next few boxes; repeated calls cover every box. */
  sweep():Promise<void>;
}
export interface RelayOptions {
  storage:Storage;
  now?:()=>number;
  /** One queued message (canonical JSON). Default 1 MiB, at most 2 MiB. */
  maxMessageBytes?:number;
  maxQueueMessages?:number;
  /** Stored bytes of one box's queue. Default 2 MiB, at most 8 MiB. */
  maxQueueBytes?:number;
  /** Stored bytes of every box's queues together. Default 64 MiB. */
  maxTotalBytes?:number;
  /**
   * The last part of the global quota, kept for boxes within their share: once usage reaches it, a message that
   * would take its box's queue above `shareBytes` is refused (507). Default a quarter of `maxTotalBytes`.
   */
  reserveBytes?:number;
  /** A box's share of the reserve. Default 256 KiB (or `maxQueueBytes` when smaller): far above a handshake or a disarm. */
  shareBytes?:number;
  ttlMs?:number;
  /** Boxes visited by one sweep() call. Default 64. */
  sweepBatch?:number;
}
export class RelayError extends Error {
  readonly status: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = 'RelayError';
    this.status = status ?? (message.includes('too large') ? 413 : message.includes('already queued') ? 409 : message.includes('full') ? 429 : 400);
  }
}
const MiB = 1024*1024;
const HANDSHAKE = ['box-hello','cli-challenge','box-attest','token-bundle','box-ack'];
/** The verifier's approval window (src/approvals/relay.ts WINDOW_MS). */
const APPROVAL_WINDOW_MS = 10*60*1000;
function id(value:unknown): asserts value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(value)) throw new RelayError('Invalid relay identifier.');
}
function record(value:unknown): value is Record<string,unknown> { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function fields(value:Record<string,unknown>,keys:string[]) { return Object.keys(value).length === keys.length && keys.every(k=>Object.hasOwn(value,k)); }
function date(value:unknown):number {
  if (typeof value !== 'string') return NaN;
  const ms = Date.parse(value);
  return Number.isFinite(ms) && new Date(ms).toISOString() === value ? ms : NaN;
}
/** Exactly `validAt` in src/approvals/relay.ts: ISO-8601 UTC with or without milliseconds. */
function signedAt(value:unknown):number {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) return NaN;
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) return NaN;
  const canonical = new Date(ms).toISOString();
  return canonical === value || canonical.replace('.000Z','Z') === value ? ms : NaN;
}
/** Exactly `validSigned` in src/approvals/relay.ts: 16-hex key id and a canonical base64 Ed25519 signature. */
function signed(value:Record<string,unknown>):boolean {
  return typeof value.keyId === 'string' && /^[a-f0-9]{16}$/.test(value.keyId) && Number.isFinite(signedAt(value.at))
    && typeof value.sig === 'string' && /^[A-Za-z0-9+/]{86}==$/.test(value.sig)
    && Buffer.from(value.sig,'base64').length === 64 && Buffer.from(value.sig,'base64').toString('base64') === value.sig;
}
function watcherId(value:unknown):boolean {
  return typeof value === 'string' && value.length > 0 && value.length <= 4096 && !/[\u0000-\u001f\u007f]/.test(value);
}
function binary(value:unknown,min:number,max:number,encoding:'base64'|'base64url'='base64url'):boolean {
  if (typeof value !== 'string' || value.length > Math.ceil(max*4/3)+4) return false;
  const buffer = Buffer.from(value,encoding);
  return buffer.length >= min && buffer.length <= max && buffer.toString(encoding) === value;
}
function jwt(value: string):boolean {
  const parts = value.split('.');
  if (parts.length !== 3 || !binary(parts[0],1,8192) || !binary(parts[1],1,48*1024) || !binary(parts[2],256,8192)) return false;
  try {
    const header:unknown = JSON.parse(Buffer.from(parts[0]!,'base64url').toString('utf8'));
    const payload:unknown = JSON.parse(Buffer.from(parts[1]!,'base64url').toString('utf8'));
    return record(header) && header.alg === 'RS256' && header.typ === 'JWT' && record(payload);
  } catch { return false; }
}
function limit(value:number|undefined,fallback:number,max:number):number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result <= 0 || result > max) throw new RelayError('Invalid relay limits.');
  return result;
}
const bytesOf = (value:unknown) => Buffer.byteLength(JSON.stringify(value));
/** Older index records may carry other fields (the removed blob list); only the queue size and count are read. */
function validIndex(value:unknown):value is BoxIndex {
  return record(value) && value.v === 1 && Number.isSafeInteger(value.queueBytes) && (value.queueBytes as number) >= 0
    && Number.isSafeInteger(value.queueCount) && (value.queueCount as number) >= 0;
}

/** Schema/expiry checks only. Endpoints verify signatures, attestations and transcript ordering. */
export function createRelayStore(options:RelayOptions):RelayStore {
  const {storage} = options;
  const now = options.now ?? Date.now;
  const maxMessage = limit(options.maxMessageBytes,MiB,2*MiB);
  const maxQueue = limit(options.maxQueueMessages,128,128);
  const maxQueueBytes = limit(options.maxQueueBytes,2*MiB,8*MiB);
  const maxTotal = limit(options.maxTotalBytes,64*MiB,1024*MiB);
  const reserveBytes = limit(options.reserveBytes,Math.max(1,Math.floor(maxTotal/4)),1024*MiB);
  const shareBytes = limit(options.shareBytes,Math.min(256*1024,maxQueueBytes),8*MiB);
  if (reserveBytes >= maxTotal || shareBytes > maxQueueBytes) throw new RelayError('Invalid relay limits.');
  const ttl = limit(options.ttlMs,600000,86400000);
  const sweepBatch = limit(options.sweepBatch,64,4096);

  // One promise chain per box: a slow box never delays another box's relay traffic.
  const lock = keyedLock();
  function withBox<T>(boxId:string,operation:()=>Promise<T>):Promise<T> {
    try { id(boxId); } catch (error) { return Promise.reject(error); }
    return lock(boxId,operation);
  }

  // Global usage, rebuilt once from the small per-box index records; afterwards kept in memory (single process).
  let used = 0;
  let loaded: Promise<void> | undefined;
  function ready():Promise<void> {
    loaded ??= (async () => {
      let total = 0;
      for (const key of await storage.list('relay-index/')) {
        const index = await storage.get<unknown>(key);
        if (validIndex(index)) total += index.queueBytes;
      }
      used = total;
    })().catch(error=>{ loaded = undefined; throw error; });
    return loaded;
  }
  /** Records what storage already holds (expiry, repairs); never refuses. */
  function track(delta:number):void { used = Math.max(0,used+delta); }
  /**
   * M-a: admits `delta` new bytes for a box whose queue would then hold `boxBytes`. The total is a hard limit; its
   * last `reserveBytes` are only for boxes within their share, so boxes that fill their queues are refused before
   * they can refuse a small message (a disarm, a handshake) for any other box.
   */
  function admit(delta:number,boxBytes:number):void {
    if (delta <= 0) { track(delta); return; }
    if (used + delta > maxTotal) throw new RelayError('Relay storage is full.',507);
    if (used + delta > maxTotal - reserveBytes && boxBytes > shareBytes) throw new RelayError('Relay storage is full.',507);
    used += delta;
  }

  async function readIndex(boxId:string):Promise<BoxIndex> {
    const stored = await storage.get<unknown>(`relay-index/${boxId}`);
    if (stored === null) return {v:1,queueBytes:0,queueCount:0};
    if (!validIndex(stored)) throw new RelayError('Relay storage is unavailable.',503);
    return {v:1,queueBytes:stored.queueBytes,queueCount:stored.queueCount};
  }
  async function writeIndex(boxId:string,index:BoxIndex):Promise<void> {
    if (index.queueCount === 0) await storage.delete(`relay-index/${boxId}`);
    else await storage.put(`relay-index/${boxId}`,index);
  }
  /** Reads the queue, drops expired messages and reconciles the index's queue size with the stored queue. */
  async function queue(boxId:string,index:BoxIndex):Promise<{messages:Queued[];changed:boolean}> {
    const key = `relay/${boxId}`;
    const old = await storage.get<Queued[]>(key) ?? [];
    if (!Array.isArray(old)) throw new RelayError('Relay storage is unavailable.',503);
    const messages = old.filter(item=>record(item) && typeof item.expiresAt === 'number' && item.expiresAt>now());
    if (old.length !== messages.length) {
      if (messages.length) await storage.put(key,messages); else await storage.delete(key);
    }
    const bytes = messages.length ? bytesOf(messages) : 0;
    const changed = bytes !== index.queueBytes || messages.length !== index.queueCount;
    if (changed) { track(bytes-index.queueBytes); index.queueBytes = bytes; index.queueCount = messages.length; }
    return {messages,changed};
  }
  function message(input:unknown):Queued {
    let json:string;
    try { json = canonicalJson(input); } catch { throw new RelayError('Invalid relay message.'); }
    if (Buffer.byteLength(json)>maxMessage) throw new RelayError('Relay message is too large.');
    const snapshot:unknown = JSON.parse(json);
    if (!record(snapshot)) throw new RelayError('Invalid relay message.');
    if (typeof snapshot.type === 'string' && HANDSHAKE.includes(snapshot.type)) {
      try {
        const parsed = parseHandshakeMessage(snapshot);
        const start = date(parsed.sentAt), expiry = date(parsed.expiresAt);
        if (expiry<=now() || start>now()+60000 || expiry-start!==600000) throw new RelayError('Invalid relay message.');
        if ((parsed.type==='box-hello'||parsed.type==='box-attest') && !jwt(parsed.attestationToken)) throw new RelayError('Invalid relay message.');
        if (parsed.type==='token-bundle') {
          const bytes = Buffer.from(parsed.bundle,'base64url');
          if (!bytes.subarray(0,5).equals(Buffer.from([0x4b,0x53,0x42,0x31,1]))) throw new RelayError('Invalid relay message.');
        }
        return {id:parsed.id,sessionId:parsed.sessionId,expiresAt:Math.min(expiry,now()+ttl),message:parsed};
      } catch { throw new RelayError('Invalid relay message.'); }
    }
    const digest = createHash('sha256').update(json).digest('base64url');
    // `publishApproval` wire format: {type:'keysentry-approval', v:1, approval:{actionId,keyId,digest,at,sig}}.
    if (snapshot.type === 'keysentry-approval' && snapshot.v === 1 && fields(snapshot,['type','v','approval'])) {
      const body = snapshot.approval;
      if (!record(body) || !fields(body,['actionId','keyId','digest','at','sig']) || !signed(body)
        || typeof body.actionId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(body.actionId)
        || typeof body.digest !== 'string' || !/^[a-f0-9]{64}$/.test(body.digest)) throw new RelayError('Invalid relay message.');
      // Relayed only while the verifier could still accept it.
      const at = signedAt(body.at);
      if (Math.abs(at-now())>APPROVAL_WINDOW_MS) throw new RelayError('Invalid relay message.');
      return {id:digest,expiresAt:Math.min(now()+ttl,at+APPROVAL_WINDOW_MS),message:snapshot};
    }
    // `publishDisarm` wire format: {type:'keysentry-disarm', v:2, watcherId, keyId, at, sig}. The watcher checks
    // that watcherId is its own; the relay does not bind it to the box id. A disarm only removes authority, so an
    // old one is delivered; its storage TTL starts at receipt.
    if (snapshot.type === 'keysentry-disarm' && snapshot.v === 2 && fields(snapshot,['type','v','watcherId','keyId','at','sig'])) {
      if (!watcherId(snapshot.watcherId) || !signed(snapshot)) throw new RelayError('Invalid relay message.');
      return {id:digest,expiresAt:now()+ttl,message:snapshot};
    }
    throw new RelayError('Invalid relay message.');
  }

  let cursor = '';
  return {
    publish(boxId,input) { return withBox(boxId,async()=>{
      const queued = message(input);
      await ready();
      const index = await readIndex(boxId);
      const {messages,changed} = await queue(boxId,index);
      if (changed) await writeIndex(boxId,index);
      if (messages.some(item=>item.id===queued.id)) throw new RelayError('Relay message is already queued.');
      const next = [...messages,queued];
      const bytes = bytesOf(next);
      if (next.length>maxQueue || bytes>maxQueueBytes) throw new RelayError('Relay queue is full.');
      admit(bytes-index.queueBytes,bytes);
      try { await storage.put(`relay/${boxId}`,next); }
      catch (error) { track(index.queueBytes-bytes); throw error; }
      index.queueBytes = bytes; index.queueCount = next.length;
      await writeIndex(boxId,index);
      return {id:queued.id};
    }); },
    poll(boxId,sessionId) { return withBox(boxId,async()=>{
      if (sessionId!==undefined) id(sessionId);
      await ready();
      const index = await readIndex(boxId);
      const {messages,changed} = await queue(boxId,index);
      if (changed) await writeIndex(boxId,index);
      return messages.filter(item=>sessionId===undefined || item.sessionId===sessionId).map(item=>item.message);
    }); },
    async sweep() {
      await ready();
      const boxes = (await storage.list('relay-index/')).map(key=>key.slice('relay-index/'.length));
      let candidates = boxes.filter(box=>box>cursor);
      if (!candidates.length) candidates = boxes;
      const batch = candidates.slice(0,sweepBatch);
      cursor = candidates.length > sweepBatch ? batch[batch.length-1]! : '';
      for (const boxId of batch) {
        await withBox(boxId,async()=>{
          const index = await readIndex(boxId);
          const {changed} = await queue(boxId,index);
          if (changed) await writeIndex(boxId,index);
        });
      }
    },
  };
}
