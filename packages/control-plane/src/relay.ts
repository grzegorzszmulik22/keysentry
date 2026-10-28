import { createHash, randomBytes } from 'node:crypto';
import { parseHandshakeMessage } from '../../../src/box/handshake/index.js';
import { canonicalJson } from '../../../src/security/index.js';
import type { Storage } from './storage.js';

export interface CiphertextBlob {kind:'sealed-bundle'|'sealed-state'; ciphertext:string; expiresAt:number}
interface Queued {id:string; sessionId?:string; expiresAt:number; message:unknown}
export interface RelayStore {
  publish(boxId:string,message:unknown):Promise<{id:string}>;
  poll(boxId:string,sessionId?:string):Promise<unknown[]>;
  putBlob(boxId:string,input:{kind:'sealed-bundle'|'sealed-state';ciphertext:string;ttlMs?:number}):Promise<{id:string;expiresAt:number}>;
  getBlob(boxId:string,id:string):Promise<CiphertextBlob|null>;
  sweep():Promise<void>;
}
export class RelayError extends Error {
  readonly status: number;
  constructor(message: string) {
    super(message);
    this.name = 'RelayError';
    this.status = message.includes('too large') ? 413 : message.includes('already queued') ? 409 : message.includes('full') ? 429 : 400;
  }
}
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

/** Schema/expiry checks only. Endpoints verify signatures, attestations and transcript ordering. */
export function createRelayStore(options:{storage:Storage;now?:()=>number;maxMessageBytes?:number;maxBlobBytes?:number;maxQueueMessages?:number;maxBlobsPerBox?:number;ttlMs?:number}):RelayStore {
  const now = options.now ?? Date.now;
  const maxMessage = options.maxMessageBytes ?? 2*1024*1024;
  const maxBlob = options.maxBlobBytes ?? 2*1024*1024;
  const maxQueue = options.maxQueueMessages ?? 128;
  const maxBlobs = options.maxBlobsPerBox ?? 128;
  const ttl = options.ttlMs ?? 600000;
  if (![maxMessage,maxBlob,maxQueue,maxBlobs,ttl].every(n=>Number.isSafeInteger(n)&&n>0)
    || maxMessage > 2*1024*1024 || maxBlob > 4*1024*1024 || maxQueue>128 || maxBlobs>128 || ttl>86400000) throw new RelayError('Invalid relay limits.');
  let pending:Promise<unknown> = Promise.resolve();
  function serialize<T>(operation:()=>Promise<T>):Promise<T> {
    const next = pending.catch(()=>undefined).then(operation); pending = next; return next;
  }
  async function queue(boxId:string):Promise<Queued[]> {
    const key = `relay/${boxId}`;
    const old = await options.storage.get<Queued[]>(key) ?? [];
    const current = old.filter(item=>item.expiresAt>now());
    if (old.length !== current.length) {
      if (current.length) await options.storage.put(key,current); else await options.storage.delete(key);
    }
    return current;
  }
  async function pruneBlobs(boxId:string):Promise<string[]> {
    const keys = await options.storage.list(`blobs/${boxId}/`);
    const live:string[] = [];
    for (const key of keys) {
      const blob = await options.storage.get<CiphertextBlob>(key);
      if (!blob || blob.expiresAt <= now()) await options.storage.delete(key); else live.push(key);
    }
    return live;
  }
  function message(input:unknown):Queued {
    let json:string;
    try { json = canonicalJson(input); } catch { throw new RelayError('Invalid relay message.'); }
    if (Buffer.byteLength(json)>maxMessage) throw new RelayError('Relay message is too large.');
    const snapshot:unknown = JSON.parse(json);
    if (!record(snapshot)) throw new RelayError('Invalid relay message.');
    if (typeof snapshot.type === 'string' && ['box-hello','cli-challenge','box-attest','token-bundle','box-ack'].includes(snapshot.type)) {
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
    const type = snapshot.type;
    const field = type === 'keysentry-approval' ? 'approval' : type === 'keysentry-disarm' ? 'disarm' : '';
    if (!field || !fields(snapshot,['type','v',field]) || snapshot.v !== 1) throw new RelayError('Invalid relay message.');
    const body = snapshot[field];
    if (!record(body) || !fields(body,field === 'approval' ? ['actionId','keyId','digest','at','sig'] : ['watcherId','keyId','at','sig'])
      || typeof body.keyId !== 'string' || !/^[a-f0-9]{16}$/.test(body.keyId)
      || !binary(body.sig,64,64,'base64') || !Number.isFinite(date(body.at))
      || (field==='approval' && (date(body.at)>now()+60000 || date(body.at)+ttl<=now()))) throw new RelayError('Invalid relay message.');
    if (field === 'approval') {
      if (typeof body.actionId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(body.actionId) || typeof body.digest !== 'string' || !/^[a-f0-9]{64}$/.test(body.digest)) throw new RelayError('Invalid relay message.');
    } else if (typeof body.watcherId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(body.watcherId)) throw new RelayError('Invalid relay message.');
    return {id:createHash('sha256').update(json).digest('base64url'),expiresAt:field==='disarm'?now()+ttl:Math.min(now()+ttl,date(body.at)+ttl),message:snapshot};
  }
  return {
    publish(boxId,input) { return serialize(async()=>{
      id(boxId);
      const queued = message(input);
      if (record(queued.message) && queued.message.type==='keysentry-disarm' && (queued.message.disarm as {watcherId:string}).watcherId !== boxId) throw new RelayError('Invalid relay message.');
      const messages = await queue(boxId);
      if (messages.some(item=>item.id===queued.id)) throw new RelayError('Relay message is already queued.');
      if (messages.length>=maxQueue || Buffer.byteLength(JSON.stringify([...messages,queued]))>7*1024*1024) throw new RelayError('Relay queue is full.');
      await options.storage.put(`relay/${boxId}`,[...messages,queued]);
      return {id:queued.id};
    }); },
    poll(boxId,sessionId) { return serialize(async()=>{
      id(boxId);
      if (sessionId!==undefined) id(sessionId);
      return (await queue(boxId)).filter(item=>sessionId===undefined || item.sessionId===sessionId).map(item=>item.message);
    }); },
    putBlob(boxId,input) { return serialize(async()=>{
      id(boxId);
      if (!record(input) || !Object.keys(input).every(k=>['kind','ciphertext','ttlMs'].includes(k)) || !['sealed-bundle','sealed-state'].includes(input.kind)
        || typeof input.ciphertext !== 'string') throw new RelayError('Invalid ciphertext blob.');
      if (input.ciphertext.length>Math.ceil(maxBlob*4/3)+4 || Buffer.from(input.ciphertext,'base64url').length>maxBlob) throw new RelayError('Ciphertext blob is too large.');
      const duration = input.ttlMs ?? ttl;
      if (!binary(input.ciphertext,32,maxBlob) || !Number.isSafeInteger(duration) || duration<1 || duration>86400000) throw new RelayError('Invalid ciphertext blob.');
      if ((await pruneBlobs(boxId)).length>=maxBlobs) throw new RelayError('Ciphertext blob storage is full.');
      const blobId = randomBytes(16).toString('base64url'), expiresAt = now()+duration;
      await options.storage.put(`blobs/${boxId}/${blobId}`,{kind:input.kind,ciphertext:input.ciphertext,expiresAt});
      return {id:blobId,expiresAt};
    }); },
    getBlob(boxId,blobId) { return serialize(async()=>{
      id(boxId); id(blobId);
      const key = `blobs/${boxId}/${blobId}`;
      const blob = await options.storage.get<CiphertextBlob>(key);
      if (blob && blob.expiresAt<=now()) { await options.storage.delete(key); return null; }
      return blob;
    }); },
    sweep() { return serialize(async()=>{
      for (const key of await options.storage.list('relay/')) await queue(key.slice(6));
      for (const key of await options.storage.list('blobs/')) {
        const blob = await options.storage.get<CiphertextBlob>(key);
        if (!blob || blob.expiresAt<=now()) await options.storage.delete(key);
      }
    }); },
  };
}
