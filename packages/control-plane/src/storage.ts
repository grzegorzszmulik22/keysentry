import { constants } from 'node:fs';
import { lstat, mkdir, open, readdir, rename, unlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';

/** Values are JSON records; implementations return independent snapshots. */
export interface Storage {
  get<T>(key: string): Promise<T | null>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<void>;
  list(prefix: string): Promise<string[]>;
}

function checkKey(key: string): void {
  if (typeof key !== 'string' || key.length > 160 || !/^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(key)) {
    throw new Error('Invalid storage key.');
  }
}
function checkPrefix(prefix: string): void {
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

/** One private directory, flat encoded names, exclusive temp files and fsync + atomic rename. */
export function createFileStorage(directory: string, options: {maxRecordBytes?:number} = {}): Storage {
  const dir = resolve(directory);
  const limit = recordLimit(options.maxRecordBytes);
  const path = (key:string) => join(dir,Buffer.from(key).toString('base64url')+'.json');
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
          const buffer = Buffer.alloc(limit+1);
          let total = 0;
          while (total < buffer.length) {
            const {bytesRead} = await handle.read(buffer,total,buffer.length-total,null);
            if (!bytesRead) break;
            total += bytesRead;
          }
          if (total > limit) throw new Error();
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
        const keys:string[] = [];
        for (const file of await readdir(dir)) {
          if (!/^[A-Za-z0-9_-]+\.json$/.test(file)) continue;
          const name = file.slice(0,-5);
          const key = Buffer.from(name,'base64url').toString('utf8');
          if (Buffer.from(key).toString('base64url') !== name) continue;
          checkKey(key);
          if (key.startsWith(prefix)) { await regular(join(dir,file)); keys.push(key); }
        }
        return keys.sort();
      } catch { throw new Error('Unable to list storage.'); }
    },
  };
}
