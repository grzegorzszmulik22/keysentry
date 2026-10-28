import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { lstat, mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { syncFile } from '../../security/index.js';
import type { BoxSealMode } from '../../types.js';
import type { BoxSettings } from './payload.js';

/**
 * Non-secret routing the box needs before it can open its sealed record: which KMS key and audience, in which mode.
 * It is checked against the copy inside the sealed record after opening, so an edited file cannot redirect a box.
 */
export interface BoxRouting { v: 1; boxId: string; mode: BoxSealMode; audience: string; keyName: string }

const MAX_FILE = 64 * 1024;
export const ROUTING_FILE = 'box.json';
export const LOCKED_NOTICE_FILE = 'locked-notice.json';
export const TOKENS_DIR = 'tokens';
export const NOTICE_DIR = 'notice';

export function routingFrom(boxId: string, settings: BoxSettings): BoxRouting {
  return { v: 1, boxId, mode: settings.mode, audience: settings.audience, keyName: settings.keyName };
}
export function sameRouting(a: BoxRouting, b: BoxRouting): boolean {
  return a.boxId === b.boxId && a.mode === b.mode && a.audience === b.audience && a.keyName === b.keyName;
}

async function readSmall(path: string): Promise<Buffer | null> {
  try {
    const info = await lstat(path);
    if (!info.isFile() || info.size > MAX_FILE) throw new Error('The box state directory holds an unexpected file.');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
  return readFile(path);
}

/** Exclusive temporary file, flushed where the sandbox allows, then an atomic rename. */
export async function writeStateFile(dir: string, name: string, value: unknown): Promise<void> {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const temporary = join(dir, `.${name}.${randomBytes(8).toString('hex')}.tmp`);
  try {
    const handle = await open(temporary, 'wx', 0o600);
    try { await handle.writeFile(JSON.stringify(value)); await syncFile(handle); } finally { await handle.close(); }
    await rename(temporary, join(dir, name));
  } finally { await unlink(temporary).catch(() => undefined); }
}

export async function readRouting(dir: string): Promise<BoxRouting | null> {
  const bytes = await readSmall(join(dir, ROUTING_FILE));
  if (!bytes) return null;
  try {
    const value = JSON.parse(bytes.toString('utf8')) as Partial<BoxRouting>;
    if (value.v !== 1 || typeof value.boxId !== 'string' || typeof value.audience !== 'string' || typeof value.keyName !== 'string'
      || !['standard', 'byo-kms', 'unlock-on-restart'].includes(value.mode as string) || Object.keys(value).length !== 5) throw new Error();
    return value as BoxRouting;
  } catch { throw new Error('The box routing record is damaged. Provision a new box.'); }
}

/** A hash of the sealed token record names one locked episode; the notice is sent once per episode, across restarts. */
export async function sealedRecordHash(dir: string): Promise<string | null> {
  const bytes = await readFile(join(dir, TOKENS_DIR, 'sealed-bundle.json')).catch(() => null);
  return bytes ? createHash('sha256').update(bytes).digest('hex') : null;
}
/**
 * The flag carries a MAC under a key derived from the KMS-sealed notice record, which only the box can open, so
 * someone with the disk alone cannot write a flag that silences the notice.
 */
function noticeMac(key: Buffer, record: string): Buffer { return createHmac('sha256', key).update(`keysentry-box-notice:v1\n${record}`).digest(); }
export async function noticeAlreadySent(dir: string, record: string, key: Buffer): Promise<boolean> {
  const bytes = await readSmall(join(dir, LOCKED_NOTICE_FILE)).catch(() => null);
  try {
    const flag = JSON.parse(bytes?.toString('utf8') ?? '') as { record?: unknown; mac?: unknown };
    if (flag.record !== record || typeof flag.mac !== 'string') return false;
    const mac = Buffer.from(flag.mac, 'base64url'), expected = noticeMac(key, record);
    return mac.length === expected.length && timingSafeEqual(mac, expected);
  } catch { return false; }
}
export async function markNoticeSent(dir: string, record: string, key: Buffer): Promise<void> {
  await writeStateFile(dir, LOCKED_NOTICE_FILE, { v: 1, record, mac: noticeMac(key, record).toString('base64url') });
}
/** A sealed record without its routing file means the state was damaged or tampered with; the box must not re-enroll. */
export async function hasSealedRecord(dir: string): Promise<boolean> {
  for (const sub of [TOKENS_DIR, NOTICE_DIR]) {
    try { await lstat(join(dir, sub, 'sealed-bundle.json')); return true; }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') return true; }
  }
  return false;
}
export async function clearNotice(dir: string): Promise<void> {
  await unlink(join(dir, LOCKED_NOTICE_FILE)).catch(() => undefined);
}
