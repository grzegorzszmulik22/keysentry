import { constants } from 'node:fs';
import { lstat, mkdir, open, readdir, rename, unlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import type { HttpClient } from '../../../src/types.js';

/** Values are JSON records; implementations return independent snapshots. */
export interface Storage {
  get<T>(key: string): Promise<T | null>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<void>;
  list(prefix: string): Promise<string[]>;
}

/** 150 characters keeps every file name (lower-case base32, 240 characters plus `.json`) under 255. */
const MAX_KEY = 150;
const KEY = /^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/;
function checkKey(key: string): void {
  if (typeof key !== 'string' || key.length > MAX_KEY || !KEY.test(key)) throw new Error('Invalid storage key.');
}
function checkPrefix(prefix: string): void {
  if (typeof prefix !== 'string') throw new Error('Invalid storage key.');
  if (prefix === '') return;
  checkKey(prefix.endsWith('/') ? prefix.slice(0,-1) : prefix);
}
function encode(value: unknown, maxBytes: number): string {
  let text: string;
  try { text = JSON.stringify(value); if (text === undefined) throw new Error(); }
  catch { throw new Error('Invalid storage record.'); }
  if (Buffer.byteLength(text) > maxBytes) throw new Error('Storage record is too large.');
  return text;
}
function recordLimit(value?: number): number {
  const limit = value ?? 8 * 1024 * 1024;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 64 * 1024 * 1024) throw new Error('Invalid storage limit.');
  return limit;
}

export function createMemoryStorage(options: {maxRecordBytes?:number} = {}): Storage {
  const records = new Map<string,string>();
  const limit = recordLimit(options.maxRecordBytes);
  return {
    async get<T>(key:string) { checkKey(key); const text = records.get(key); return text === undefined ? null : JSON.parse(text) as T; },
    async put(key,value) { checkKey(key); records.set(key,encode(value,limit)); },
    async delete(key) { checkKey(key); records.delete(key); },
    async list(prefix) { checkPrefix(prefix); return [...records.keys()].filter(key=>key.startsWith(prefix)).sort(); },
  };
}

// Lower-case RFC 4648 base32 without padding: one spelling per key, so case-folding file systems (NTFS, default
// APFS) can never map two keys to one file.
const ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
export function base32(bytes: Buffer): string {
  let out = '', bits = 0, value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}
function unbase32(text: string): Buffer | null {
  if (!/^[a-z2-7]+$/.test(text)) return null;
  const bytes: number[] = [];
  let bits = 0, value = 0;
  for (const char of text) {
    value = (value << 5) | ALPHABET.indexOf(char); bits += 5;
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 255); bits -= 8; }
    value &= (1 << bits) - 1;
  }
  const buffer = Buffer.from(bytes);
  return base32(buffer) === text ? buffer : null;
}

/** One private directory, flat base32 names, exclusive temp files and fsync + atomic rename. */
export function createFileStorage(directory: string, options: {maxRecordBytes?:number} = {}): Storage {
  const dir = resolve(directory);
  const limit = recordLimit(options.maxRecordBytes);
  const path = (key:string) => join(dir,base32(Buffer.from(key))+'.json');
  async function ready() {
    await mkdir(dir,{recursive:true,mode:0o700});
    const stat = await lstat(dir);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error();
  }
  async function regular(file:string) {
    try { const stat = await lstat(file); if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(); return stat; }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null; throw error; }
  }
  async function syncDirectory() {
    if (process.platform === 'win32') return;
    const handle = await open(dir,constants.O_RDONLY);
    try { await handle.sync(); } finally { await handle.close(); }
  }
  return {
    async get<T>(key:string) {
      checkKey(key);
      try {
        await ready();
        const stat = await regular(path(key));
        if (!stat) return null;
        if (stat.size > limit) throw new Error();
        const handle = await open(path(key),constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
        try {
          const actual = await handle.stat();
          if (!actual.isFile() || actual.size > limit) throw new Error();
          // Sized to the file, one byte over so growth after the stat is still detected.
          const buffer = Buffer.alloc(actual.size+1);
          let total = 0;
          while (total < buffer.length) {
            const {bytesRead} = await handle.read(buffer,total,buffer.length-total,null);
            if (!bytesRead) break;
            total += bytesRead;
          }
          if (total > actual.size) throw new Error();
          return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(buffer.subarray(0,total))) as T;
        } finally { await handle.close(); }
      } catch { throw new Error('Unable to read storage.'); }
    },
    async put(key,value) {
      checkKey(key);
      const text = encode(value,limit);
      let temporary: string | undefined;
      try {
        await ready();
        await regular(path(key));
        temporary = join(dir,`.tmp-${randomBytes(16).toString('hex')}`);
        const handle = await open(temporary,'wx',0o600);
        try { await handle.writeFile(text,'utf8'); await handle.sync(); } finally { await handle.close(); }
        await rename(temporary,path(key));
        temporary = undefined;
        await syncDirectory();
      } catch { throw new Error('Unable to write storage.'); }
      finally { if (temporary) await unlink(temporary).catch(()=>undefined); }
    },
    async delete(key) {
      checkKey(key);
      try { await ready(); if (await regular(path(key))) { await unlink(path(key)); await syncDirectory(); } }
      catch { throw new Error('Unable to delete storage.'); }
    },
    async list(prefix) {
      checkPrefix(prefix);
      try {
        await ready();
        // Whole base32 characters of the prefix are fixed by it, so most names are skipped without decoding.
        const fixed = base32(Buffer.from(prefix)).slice(0,Math.floor(Buffer.byteLength(prefix)*8/5));
        const keys:string[] = [];
        for (const file of await readdir(dir)) {
          if (!file.endsWith('.json') || !file.startsWith(fixed)) continue;
          const bytes = unbase32(file.slice(0,-5));
          if (!bytes) continue;
          const key = bytes.toString('utf8');
          if (Buffer.from(key).compare(bytes) !== 0 || key.length > MAX_KEY || !KEY.test(key)) continue;
          if (key.startsWith(prefix)) { await regular(join(dir,file)); keys.push(key); }
        }
        return keys.sort();
      } catch { throw new Error('Unable to list storage.'); }
    },
  };
}

export interface GcsStorageOptions {
  /** The runtime's egress-guarded client; it must allow storage.googleapis.com. */
  http: HttpClient;
  bucket: string;
  /** OAuth access token for the bucket (see metadataAccessToken); never logged or put in errors. */
  accessToken: () => Promise<string>;
  /** Optional object-name prefix, e.g. `control/`. */
  objectPrefix?: string;
  maxRecordBytes?: number;
  /** Bounded retries for 429 and 5xx with exponential backoff. */
  retries?: number;
  sleep?: (ms: number) => Promise<void>;
}

const GCS = 'https://storage.googleapis.com';
const BUCKET = /^[a-z0-9][a-z0-9_.-]{1,61}[a-z0-9]$/;

/**
 * Cloud Storage over the JSON API through the injected HttpClient: one object per key, so a restart or
 * scale-to-zero keeps accounts, sessions, ownership and relay records. Single writer (see README): no CAS.
 */
export function createGcsStorage(options: GcsStorageOptions): Storage {
  const limit = recordLimit(options.maxRecordBytes);
  const prefix = options.objectPrefix ?? '';
  const retries = options.retries ?? 3;
  const sleep = options.sleep ?? (ms => new Promise<void>(done => setTimeout(done, ms)));
  if (typeof options.bucket !== 'string' || !BUCKET.test(options.bucket) || options.bucket.includes('..')
    || (prefix !== '' && !/^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*\/$/.test(prefix)) || prefix.length > 64
    || !Number.isSafeInteger(retries) || retries < 0 || retries > 5 || typeof options.accessToken !== 'function') {
    throw new TypeError('Invalid storage configuration.');
  }
  const objects = `${GCS}/storage/v1/b/${options.bucket}/o`;
  const name = (key: string) => encodeURIComponent(prefix + key);
  async function call(method: 'GET' | 'POST' | 'DELETE', url: string, body?: string) {
    for (let attempt = 0; ; attempt++) {
      let token: string;
      try { token = await options.accessToken(); } catch { throw new Error('Storage credentials are unavailable.'); }
      if (typeof token !== 'string' || !token || token.length > 16_384 || /[\r\n\x00]/.test(token)) throw new Error('Storage credentials are unavailable.');
      const headers: Record<string, string> = { authorization: `Bearer ${token}` };
      if (body !== undefined) headers['content-type'] = 'application/json';
      let response: Awaited<ReturnType<HttpClient['request']>> | undefined;
      try { response = await options.http.request({ method, url, headers, ...(body === undefined ? {} : { body }) }); }
      catch { response = undefined; }
      const retryable = response === undefined || response.status === 429 || response.status >= 500;
      if (!retryable || attempt >= retries) return response;
      await sleep(Math.min(2_000, 100 * 2 ** attempt) + Math.floor(Math.random() * 50));
    }
  }
  return {
    async get<T>(key: string) {
      checkKey(key);
      const response = await call('GET', `${objects}/${name(key)}?alt=media`);
      if (response?.status === 404) return null;
      if (!response || response.status !== 200 || Buffer.byteLength(response.text) > limit) throw new Error('Unable to read storage.');
      try { return JSON.parse(response.text) as T; } catch { throw new Error('Unable to read storage.'); }
    },
    async put(key, value) {
      checkKey(key);
      const text = encode(value, limit);
      const response = await call('POST', `${GCS}/upload/storage/v1/b/${options.bucket}/o?uploadType=media&name=${name(key)}`, text);
      if (!response || response.status < 200 || response.status >= 300) throw new Error('Unable to write storage.');
    },
    async delete(key) {
      checkKey(key);
      const response = await call('DELETE', `${objects}/${name(key)}`);
      if (!response || (response.status !== 204 && response.status !== 200 && response.status !== 404)) throw new Error('Unable to delete storage.');
    },
    async list(keyPrefix) {
      checkPrefix(keyPrefix);
      const keys: string[] = [];
      let page: string | undefined;
      for (let pages = 0; pages < 200; pages++) {
        const query = `prefix=${encodeURIComponent(prefix + keyPrefix)}&fields=${encodeURIComponent('items(name),nextPageToken')}&maxResults=1000`
          + (page ? `&pageToken=${encodeURIComponent(page)}` : '');
        const response = await call('GET', `${objects}?${query}`);
        if (!response || response.status !== 200) throw new Error('Unable to list storage.');
        let data: { items?: { name?: unknown }[]; nextPageToken?: unknown };
        try { data = JSON.parse(response.text) as typeof data; } catch { throw new Error('Unable to list storage.'); }
        if (data.items !== undefined && !Array.isArray(data.items)) throw new Error('Unable to list storage.');
        for (const item of data.items ?? []) {
          if (typeof item?.name !== 'string' || !item.name.startsWith(prefix)) continue;
          const key = item.name.slice(prefix.length);
          if (key.length <= MAX_KEY && KEY.test(key) && key.startsWith(keyPrefix)) keys.push(key);
        }
        if (data.nextPageToken === undefined) return keys.sort();
        if (typeof data.nextPageToken !== 'string' || data.nextPageToken.length > 4096) throw new Error('Unable to list storage.');
        page = data.nextPageToken;
      }
      throw new Error('Unable to list storage.');
    },
  };
}

/**
 * Access token for the runtime's service account from the Cloud Run / GCE metadata server, cached until a minute
 * before it expires. The HttpClient must allow `http://metadata.google.internal` (link-local, no TLS).
 */
export function metadataAccessToken(http: HttpClient, now: () => number = Date.now): () => Promise<string> {
  let cached: { token: string; refreshAt: number } | undefined;
  let pending: Promise<string> | undefined;
  async function fetchToken(): Promise<string> {
    const response = await http.request({ method: 'GET', headers: { 'Metadata-Flavor': 'Google' },
      url: 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' });
    const flavor = Object.entries(response.headers).find(([header]) => header.toLowerCase() === 'metadata-flavor')?.[1];
    if (response.status !== 200 || flavor !== 'Google' || response.text.length > 32 * 1024) throw new Error();
    const data = JSON.parse(response.text) as { access_token?: unknown; expires_in?: unknown; token_type?: unknown };
    if (typeof data.access_token !== 'string' || !data.access_token || data.access_token.length > 16_384 || /[\r\n\x00]/.test(data.access_token)
      || typeof data.expires_in !== 'number' || !Number.isFinite(data.expires_in) || data.expires_in <= 0
      || (data.token_type !== undefined && data.token_type !== 'Bearer')) throw new Error();
    cached = { token: data.access_token, refreshAt: now() + Math.max(0, data.expires_in - 60) * 1000 };
    return data.access_token;
  }
  return async () => {
    if (cached && now() < cached.refreshAt) return cached.token;
    pending ??= fetchToken().finally(() => { pending = undefined; });
    try { return await pending; } catch { throw new Error('Storage credentials are unavailable.'); }
  };
}
