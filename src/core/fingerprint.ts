import { createHmac, randomBytes } from 'node:crypto';
import { link, mkdir, open, readFile, unlink, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { syncFile } from '../security/durable.js';

const PREFIXES = [
  'sk-or-v1-', 'sk-svcacct-', 'sk-proj-', 'sk-ant-', 'sk_live_', 'sk_test_',
  'rk_live_', 'rk_test_', 'github_pat_', 'sb_secret_', 'whsec_',
  'ghp_', 'gho_', 'ghs_', 'ghu_', 'AKIA', 'ASIA', 'xoxb-', 'xoxp-', 'AIza', 're_', 'SG.', 'sk-',
];

function hasCode(error: unknown, code: string): boolean {
  return error instanceof Error && 'code' in error && error.code === code;
}

async function readKey(path: string): Promise<Buffer> {
  const key = await readFile(path);
  if (key.length !== 32) throw new Error('Invalid fingerprint key length.');
  return key;
}

/** Publish a complete private key without ever replacing a concurrent creator's key. */
export async function loadOrCreateFingerprintKey(dir = join(homedir(), '.keysentry')): Promise<Buffer> {
  const path = join(dir, 'fingerprint.key');
  let temp: string | undefined;
  try {
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const ignore = join(dir, '.gitignore');
    let existing = '';
    try {
      existing = await readFile(ignore, 'utf8');
    } catch (error) {
      if (!hasCode(error, 'ENOENT')) throw error;
    }
    if (existing.trimEnd().split(/\r?\n/).at(-1) !== '*') {
      const separator = existing && !existing.endsWith('\n') ? '\n' : '';
      await writeFile(ignore, `${separator}*\n`, { flag: 'a', mode: 0o600 });
    }
    try {
      return await readKey(path);
    } catch (error) {
      if (!hasCode(error, 'ENOENT')) throw error;
    }
    const candidate = join(dir, `.fingerprint-${randomBytes(16).toString('hex')}.tmp`);
    const handle = await open(candidate, 'wx', 0o600);
    temp = candidate;
    try {
      await handle.writeFile(randomBytes(32));
      await syncFile(handle);
    } finally {
      await handle.close();
    }
    try {
      // Hard linking an already complete file provides exclusive, atomic publication.
      await link(temp, path);
    } catch (error) {
      if (!hasCode(error, 'EEXIST')) throw error;
    }
    return await readKey(path);
  } catch {
    throw new Error('Unable to load or create a valid fingerprint key.');
  } finally {
    if (temp) await unlink(temp).catch(() => undefined);
  }
}

export function fingerprint(value: string, key: Buffer): string {
  return createHmac('sha256', key).update(value, 'utf8').digest('hex').slice(0, 32);
}

export function makeHint(value: string): string | null {
  if (value.length < 16) return null;
  // Never derive a suffix from URL text: it may be part of a password, query
  // credential, or malformed authority. Only the parsed database host is safe.
  const text = value.trim();
  if (/^(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?):/i.test(text)) {
    try {
      const url = new URL(text);
      if (!url.hostname) return null;
      return `${url.protocol}//…${url.hostname.slice(-4)}`;
    } catch { return null; }
  }
  if (value.length < 24) return `…${value.slice(-2)}`;
  const prefix = PREFIXES.find((candidate) => value.startsWith(candidate)) ?? '';
  return `${prefix.slice(0, 7)}…${value.slice(-4)}`;
}
