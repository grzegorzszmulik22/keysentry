import { createHash, randomBytes } from 'node:crypto';
import { parseHandshakeMessage } from '../../../src/box/handshake/index.js';
import { canonicalJson } from '../../../src/security/index.js';
import { keyedLock } from './lock.js';
import type { Storage } from './storage.js';

export interface CiphertextBlob {kind:'sealed-bundle'|'sealed-state'; ciphertext:string; expiresAt:number}
interface Queued {id:string; sessionId?:string; expiresAt:number; message:unknown}
/** Per-box index: what the box holds, so quotas never require reading its blobs. */
interface BoxIndex {v:1; queueBytes:number; queueCount:number; blobs:{id:string; bytes:number; expiresAt:number}[]}
export interface RelayStore {
  publish(boxId:string,message:unknown):Promise<{id:string}>;
  poll(boxId:string,sessionId?:string):Promise<unknown[]>;
  putBlob(boxId:string,input:{kind:'sealed-bundle'|'sealed-state';ciphertext:string;ttlMs?:number}):Promise<{id:string;expiresAt:number}>;
  getBlob(boxId:string,id:string):Promise<CiphertextBlob|null>;
  /** Removes expired records for the next few boxes; repeated calls cover every box. */
  sweep():Promise<void>;
}
export interface RelayOptions {
  storage:Storage;
  now?:()=>number;
  /** One queued message (canonical JSON). Default 1 MiB, at most 2 MiB. */
  maxMessageBytes?:number;
  /** Decoded bytes of one blob. Default 2 MiB, at most 4 MiB. */
  maxBlobBytes?:number;
  maxQueueMessages?:number;
  /** Stored bytes of one box's queue. Default 4 MiB. */
  maxQueueBytes?:number;
  maxBlobsPerBox?:number;
  /** Stored bytes of one box's blobs. Default 16 MiB. */
  maxBlobBytesPerBox?:number;
  /** Stored bytes of every box's queues and blobs together. Default 64 MiB. */
  maxTotalBytes?:number;
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
function validIndex(value:unknown):value is BoxIndex {
  return record(value) && value.v === 1 && Number.isSafeInteger(value.queueBytes) && (value.queueBytes as number) >= 0
    && Number.isSafeInteger(value.queueCount) && (value.queueCount as number) >= 0 && Array.isArray(value.blobs)
    && value.blobs.every(entry=>record(entry) && typeof entry.id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(entry.id)
      && Number.isSafeInteger(entry.bytes) && (entry.bytes as number) > 0 && Number.isSafeInteger(entry.expiresAt));
}

/** Schema/expiry checks only. Endpoints verify signatures, attestations and transcript ordering. */
export function createRelayStore(options:RelayOptions):RelayStore {
  const {storage} = options;
  const now = options.now ?? Date.now;
  const maxMessage = limit(options.maxMessageBytes,MiB,2*MiB);
  const maxBlob = limit(options.maxBlobBytes,2*MiB,4*MiB);
  const maxQueue = limit(options.maxQueueMessages,128,128);
  const maxQueueBytes = limit(options.maxQueueBytes,4*MiB,8*MiB);
  const maxBlobs = limit(options.maxBlobsPerBox,128,128);
  const maxBoxBlobBytes = limit(options.maxBlobBytesPerBox,16*MiB,64*MiB);
  const maxTotal = limit(options.maxTotalBytes,64*MiB,1024*MiB);
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
        if (validIndex(index)) total += index.queueBytes + index.blobs.reduce((sum,entry)=>sum+entry.bytes,0);
      }
      used = total;
    })().catch(error=>{ loaded = undefined; throw error; });
    return loaded;
  }
  function reserve(delta:number):void {
    if (delta > 0 && used + delta > maxTotal) throw new RelayError('Relay storage is full.',507);
    used = Math.max(0,used+delta);
  }

  async function readIndex(boxId:string):Promise<BoxIndex> {
    const stored = await storage.get<unknown>(`relay-index/${boxId}`);
    if (stored === null) return {v:1,queueBytes:0,queueCount:0,blobs:[]};
    if (!validIndex(stored)) throw new RelayError('Relay storage is unavailable.',503);
    return stored;
  }
  async function writeIndex(boxId:string,index:BoxIndex):Promise<void> {
    if (index.queueCount === 0 && index.blobs.length === 0) await storage.delete(`relay-index/${boxId}`);
    else await storage.put(`relay-index/${boxId}`,index);
  }
  /** Expired blobs are deleted first, then dropped from the index, so a crash never leaves an unindexed blob. */
  async function pruneBlobs(boxId:string,index:BoxIndex):Promise<boolean> {
    const expired = index.blobs.filter(entry=>entry.expiresAt<=now());
    if (!expired.length) return false;
    for (const entry of expired) await storage.delete(`blobs/${boxId}/${entry.id}`);
    index.blobs = index.blobs.filter(entry=>entry.expiresAt>now());
    reserve(-expired.reduce((sum,entry)=>sum+entry.bytes,0));
    return true;
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
    if (changed) { reserve(bytes-index.queueBytes); index.queueBytes = bytes; index.queueCount = messages.length; }
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
      reserve(bytes-index.queueBytes);
      try { await storage.put(`relay/${boxId}`,next); }
      catch (error) { reserve(index.queueBytes-bytes); throw error; }
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
    putBlob(boxId,input) { return withBox(boxId,async()=>{
      if (!record(input) || !Object.keys(input).every(k=>['kind','ciphertext','ttlMs'].includes(k)) || !['sealed-bundle','sealed-state'].includes(input.kind)
        || typeof input.ciphertext !== 'string') throw new RelayError('Invalid ciphertext blob.');
      if (input.ciphertext.length>Math.ceil(maxBlob*4/3)+4 || Buffer.from(input.ciphertext,'base64url').length>maxBlob) throw new RelayError('Ciphertext blob is too large.');
      const duration = input.ttlMs ?? ttl;
      if (!binary(input.ciphertext,32,maxBlob) || !Number.isSafeInteger(duration) || duration<1 || duration>86400000) throw new RelayError('Invalid ciphertext blob.');
      await ready();
      const index = await readIndex(boxId);
      const pruned = await pruneBlobs(boxId,index);
      const blobId = randomBytes(16).toString('base64url'), expiresAt = now()+duration;
      const stored:CiphertextBlob = {kind:input.kind,ciphertext:input.ciphertext,expiresAt};
      const bytes = bytesOf(stored);
      const held = index.blobs.reduce((sum,entry)=>sum+entry.bytes,0);
      if (index.blobs.length>=maxBlobs || held+bytes>maxBoxBlobBytes) {
        if (pruned) await writeIndex(boxId,index);
        throw new RelayError('Ciphertext blob storage is full.');
      }
      reserve(bytes);
      // The index entry is written before the blob: a crash leaves a counted entry for a missing blob, never an
      // uncounted blob.
      index.blobs.push({id:blobId,bytes,expiresAt});
      try {
        await writeIndex(boxId,index);
        await storage.put(`blobs/${boxId}/${blobId}`,stored);
      } catch (error) {
        index.blobs = index.blobs.filter(entry=>entry.id!==blobId);
        reserve(-bytes);
        await writeIndex(boxId,index).catch(()=>undefined);
        throw error;
      }
      return {id:blobId,expiresAt};
    }); },
    getBlob(boxId,blobId) { return withBox(boxId,async()=>{
      id(blobId);
      const blob = await storage.get<CiphertextBlob>(`blobs/${boxId}/${blobId}`);
      if (!blob) return null;
      if (!record(blob) || typeof blob.expiresAt !== 'number' || blob.expiresAt<=now()) {
        await ready();
        const index = await readIndex(boxId);
        if (await pruneBlobs(boxId,index)) await writeIndex(boxId,index);
        else await storage.delete(`blobs/${boxId}/${blobId}`);
        return null;
      }
      return blob;
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
          const pruned = await pruneBlobs(boxId,index);
          const {changed} = await queue(boxId,index);
          if (pruned || changed) await writeIndex(boxId,index);
        });
      }
    },
  };
}
