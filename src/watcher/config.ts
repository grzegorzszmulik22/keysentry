import { createHash, createPublicKey } from 'node:crypto';
import { mkdir, readFile, stat } from 'node:fs/promises';
import { isIP } from 'node:net';
import { resolve } from 'node:path';
import { z } from 'zod';
import { verifyArmedPlan } from '../autopilot/armed-plan.js';
import type { ArmedPlan, FeedSource, NotifyChannelKind, PasskeyCredential } from '../types.js';
import { openWatcherConfig } from './seal.js';

export interface WatcherConfig {
  v: 1;
  projectId: string;
  armed: ArmedPlan | null;
  trustedKeyIds: string[];
  devicePublicKeys: { keyId: string; publicKeyDer: string }[];
  passkeys: PasskeyCredential[];
  notify: { channels: { kind: NotifyChannelKind; settings: Record<string, string> }[] };
  sources: { disabled: string[]; extra: FeedSource[] };
  approvals: { publicOrigin: string | null; relay: { server: string; topic: string } | null };
  intervalSeconds: number;
}

export const MAX_WATCHER_CONFIG_BYTES = 2 * 1024 * 1024;
const INVALID_CONFIG = 'The watcher config is invalid. Run keysentry watcher setup again.';
const hostSchema = z.enum(['railway', 'vercel', 'render', 'fly', 'github-actions', 'dotenv']);
const metadata = z.string().min(1).max(4096).refine(value => !/[\u0000-\u001f\u007f]/.test(value));
const keyId = z.string().regex(/^[a-f0-9]{16}$/);
const unique = (values: string[]): boolean => new Set(values).size === values.length;

function httpsUrl(value: string, originOnly = false, allowLocalhost = false): boolean {
  try {
    const url = new URL(value);
    const authority = /^[a-z][a-z0-9+.-]*:\/\/([^/?#\\]*)/i.exec(value)?.[1];
    const local = allowLocalhost && url.hostname === 'localhost' && url.protocol === 'http:';
    return !!authority && !authority.includes('@') && (local || url.protocol === 'https:')
      && !url.username && !url.password && !url.hash && (local || !url.port)
      && !isIP(url.hostname.replace(/^\[|\]$/g, ''))
      && (!originOnly || ((url.pathname === '/' || url.pathname === '') && !url.search));
  } catch { return false; }
}

const urlSchema = z.string().max(8192).refine(value => httpsUrl(value));
const originSchema = z.string().max(8192).refine(value => httpsUrl(value, true, true));
const base64url = z.string().min(1).max(65536).regex(/^[A-Za-z0-9_-]+$/)
  .refine(value => Buffer.from(value, 'base64url').toString('base64url') === value);
const publicKeySchema = z.object({ keyId, publicKeyDer: z.string().max(4096) }).strict().refine(entry => {
  try {
    const der = Buffer.from(entry.publicKeyDer, 'base64');
    return der.toString('base64') === entry.publicKeyDer
      && createPublicKey({ key: der, format: 'der', type: 'spki' }).asymmetricKeyType === 'ed25519'
      && createHash('sha256').update(der).digest('hex').slice(0, 16) === entry.keyId;
  } catch { return false; }
});
const passkeySchema = z.object({
  id: base64url, publicKeyCose: base64url, alg: z.union([z.literal(-7), z.literal(-8), z.literal(-257)]),
  signCount: z.number().int().min(0).max(0xffffffff), backupEligible: z.boolean(),
  rpId: metadata, origins: z.array(originSchema).min(1).max(20), label: metadata,
  createdAt: z.iso.datetime({ offset: true }),
}).strict();
const sourceSchema = z.object({
  id: metadata, kind: z.enum(['official', 'news']), url: urlSchema,
  hosts: z.array(hostSchema).min(1).max(6).refine(unique), outlet: metadata, owner: metadata,
  maxBytes: z.number().int().positive().max(16 * 1024 * 1024).optional(), linkPrefix: urlSchema.optional(),
}).strict();
const schema = z.object({
  v: z.literal(1), projectId: metadata, armed: z.unknown().nullable(),
  trustedKeyIds: z.array(keyId).max(100).refine(unique),
  devicePublicKeys: z.array(publicKeySchema).max(100).refine(values => unique(values.map(value => value.keyId))),
  passkeys: z.array(passkeySchema).max(100).refine(values => unique(values.map(value => value.id))),
  notify: z.object({ channels: z.array(z.object({
    kind: z.enum(['telegram', 'discord', 'slack', 'ntfy', 'webhook', 'resend', 'smtp', 'console']),
    settings: z.record(z.string().min(1).max(256), z.string().max(65536)).refine(value => Object.keys(value).length <= 100),
  }).strict()).max(50) }).strict(),
  sources: z.object({
    disabled: z.array(metadata).max(1000).refine(unique),
    extra: z.array(sourceSchema).max(100).refine(values => unique(values.map(value => value.id))),
  }).strict(),
  approvals: z.object({
    publicOrigin: originSchema.nullable(),
    relay: z.object({ server: z.string().max(8192).refine(value => httpsUrl(value, true)), topic: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/) }).strict().nullable(),
  }).strict(),
  intervalSeconds: z.number().int().positive().max(86400),
}).strict();

/** Configuration validity is separate from present-day authorization to rotate. */
export function parseWatcherConfig(input: unknown): WatcherConfig {
  try {
    const parsed = schema.parse(input);
    let armed: ArmedPlan | null = null;
    if (parsed.armed !== null) {
      const value = parsed.armed as Partial<ArmedPlan> | undefined;
      if (!value || typeof value.createdAt !== 'string') throw new WatcherConfigError();
      // Validate the signed format at creation time. An expired plan must still be
      // loadable so a running watcher can keep reporting in alert-only mode.
      const verified = verifyArmedPlan(value, { now: new Date(value.createdAt), trustedKeyIds: parsed.trustedKeyIds });
      if (!verified.ok || verified.plan.projectId !== parsed.projectId) throw new WatcherConfigError();
      armed = verified.plan;
    }
    return { ...parsed, armed };
  } catch { throw new WatcherConfigError(INVALID_CONFIG); }
}

export interface WatcherConfigLoadOptions {
  cwd?: string;
  platform?: NodeJS.Platform;
  readFile?: (path: string) => Promise<Buffer>;
  stat?: (path: string) => Promise<{ mode: number; size?: number; isDirectory(): boolean }>;
  mkdir?: (path: string, options: { recursive: true; mode: number }) => Promise<unknown>;
}

/** Does not change permissions on an existing directory. The user must fix them. */
export async function ensureWatcherStateDir(stateDir: string, options: WatcherConfigLoadOptions = {}): Promise<void> {
  let info: { mode: number; isDirectory(): boolean };
  try {
    await (options.mkdir ?? mkdir)(stateDir, { recursive: true, mode: 0o700 });
    info = await (options.stat ?? stat)(stateDir);
    if (!info.isDirectory()) throw new WatcherConfigError();
  } catch { throw new WatcherConfigError('KEYSENTRY_STATE_DIR must name a writable state directory.'); }
  if ((options.platform ?? process.platform) !== 'win32' && (info.mode & 0o077) !== 0) {
    throw new WatcherConfigError('KEYSENTRY_STATE_DIR must be private. Run chmod 700 on the state directory, then try again.');
  }
}

/** Fixed, secret-free setup guidance (variable names only), safe to show to the operator as written. */
export class WatcherConfigError extends Error {
  readonly code = 'WATCHER_CONFIG';
  constructor(message = 'The watcher configuration could not be read. Run keysentry watcher setup again.') { super(message); this.name = 'WatcherConfigError'; }
}

/** Read deploy-time secrets in memory only; errors contain variable names, never their contents. */
export async function loadWatcherConfigFromEnv(
  env: Readonly<Record<string, string | undefined>>, options: WatcherConfigLoadOptions = {},
): Promise<{ config: WatcherConfig; deployKey: Buffer; stateDir: string }> {
  const encodedKey = env.KEYSENTRY_WATCHER_KEY;
  if (!encodedKey) throw new WatcherConfigError('Set KEYSENTRY_WATCHER_KEY to the base64 deploy key from keysentry watcher setup.');
  const deployKey = Buffer.from(encodedKey, 'base64');
  if (deployKey.length !== 32 || deployKey.toString('base64') !== encodedKey) {
    deployKey.fill(0);
    throw new WatcherConfigError('KEYSENTRY_WATCHER_KEY must be base64 encoding of exactly 32 bytes.');
  }
  try {
    let sealed = env.KEYSENTRY_WATCHER_CONFIG;
    if (!sealed) {
      const file = env.KEYSENTRY_WATCHER_CONFIG_FILE;
      if (!file) throw new WatcherConfigError('Set KEYSENTRY_WATCHER_CONFIG or KEYSENTRY_WATCHER_CONFIG_FILE to the sealed config from keysentry watcher setup.');
      let bytes: Buffer | undefined;
      try {
        const info = await (options.stat ?? stat)(file);
        if (info.isDirectory() || (info.size !== undefined && info.size > MAX_WATCHER_CONFIG_BYTES * 2)) throw new WatcherConfigError();
        bytes = await (options.readFile ?? readFile)(file);
        if (bytes.length > MAX_WATCHER_CONFIG_BYTES * 2) throw new WatcherConfigError();
        sealed = bytes.toString('utf8').trim();
      } catch { throw new WatcherConfigError('Could not read KEYSENTRY_WATCHER_CONFIG_FILE.'); }
      finally { bytes?.fill(0); }
    }
    const config = openWatcherConfig(sealed, deployKey);
    const cwd = options.cwd ?? process.cwd();
    const stateDir = resolve(cwd, env.KEYSENTRY_STATE_DIR || '.keysentry');
    await ensureWatcherStateDir(stateDir, options);
    return { config, deployKey, stateDir };
  } catch (error) {
    deployKey.fill(0);
    throw error;
  }
}
