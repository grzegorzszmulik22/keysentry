import { lstat, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { createLogger, createRedactor } from '../core/index.js';
import { createFetchHttp } from '../http.js';
import { EGRESS_RULES, createFileReceipt, createGuardedHttp, rulesForUserFeeds, rulesForUserUrls } from '../net/index.js';
import { BUILD_VERSION, checkLocalIntegrity, verifyRelease } from '../release/index.js';
import { createAuditLog, deviceKeyFromPrivate } from '../security/index.js';
import { createMemoryVault, openVault } from '../vault/index.js';
import { loadConfigMetadata } from './config.js';
import { CliError } from './errors.js';
import { confirmVaultFallback, promptPassphrase } from './prompts.js';
import type { RuntimeOptions } from './runtime.js';

function validTimestamp(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](?:0\d|1\d|2[0-3]):[0-5]\d)$/.exec(value);
  if (!match) return false;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1]!
    && hour <= 23 && minute <= 59 && second <= 59 && Number.isFinite(Date.parse(value));
}

/** Inspection commands have no need to load state keys or credential adapters. */
export async function inspectNetwork(options: RuntimeOptions, since?: string) {
  if (since !== undefined && !validTimestamp(since)) {
    throw new CliError('Use an ISO timestamp for --since.');
  }
  const metadata = await loadConfigMetadata(options);
  const rules = [...EGRESS_RULES, ...rulesForUserFeeds(metadata.feedUrls),
    ...rulesForUserUrls(metadata.webhooks, 'notification webhook you configured'), ...metadata.userHostRules];
  const receipt = await createFileReceipt(join(metadata.cwd, '.keysentry', 'network.jsonl')).summarize(since);
  return { rules, receipt };
}

export async function inspectRelease(options: RuntimeOptions, offline = false) {
  const local = await checkLocalIntegrity();
  if (offline || local.status === 'mismatch') return { local };
  const metadata = await loadConfigMetadata(options);
  const redactor = createRedactor();
  const log = options.log ?? createLogger({ redactor });
  const http = createGuardedHttp(options.http ?? createFetchHttp(), {
    rules: [...EGRESS_RULES, ...rulesForUserFeeds(metadata.feedUrls),
      ...rulesForUserUrls(metadata.webhooks, 'notification webhook you configured'), ...metadata.userHostRules],
    receipt: createFileReceipt(join(metadata.cwd, '.keysentry', 'network.jsonl')),
    trustedUrls: metadata.webhooks, log,
  });
  const release = await verifyRelease({ http, version: BUILD_VERSION, bundleSha256: local.actual ?? '' });
  return { local, release };
}

/** Unsigned/empty logs need no vault. A checkpoint needs the saved device key. */
export async function inspectAudit(options: RuntimeOptions) {
  if (options.audit) return { ...await options.audit.verify(), anchorChecked: options.vault?.backend !== 'env' };
  const path = join(resolve(options.cwd ?? process.cwd()), '.keysentry', 'audit.jsonl');
  const userDir = resolve(options.userDir ?? join(homedir(), '.keysentry'));
  const anchor = createHash('sha256').update(resolve(path)).digest('hex').slice(0, 16);
  let hasAnchorMarker = false;
  try { await lstat(join(userDir, 'audit-heads', `${anchor}.json`)); hasAnchorMarker = true; }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new CliError('The audit anchor marker could not be read.'); }
  let hasCheckpoint = false;
  try {
    hasCheckpoint = (await readFile(path, 'utf8')).split('\n').some(line => {
      try { return (JSON.parse(line) as { kind?: unknown }).kind === 'checkpoint'; } catch { return false; }
    });
  } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new CliError('The audit log could not be read.'); }
  const redactor = createRedactor();
  const env = options.env ?? process.env;
  const interactive = (options.stdinIsTTY ?? !!process.stdin.isTTY) && (options.stdoutIsTTY ?? !!process.stdout.isTTY);
  const log = options.log ?? createLogger({ redactor });
  const diagnostic = (text: string) => log.info(redactor.redact(text));
  const store = env.KEYSENTRY_VAULT ?? (process.platform === 'win32' ? 'windows-dpapi' : process.platform === 'darwin' ? 'macos-keychain' : 'linux-secret-service');
  const needsVault = !!options.vault || hasCheckpoint || hasAnchorMarker;
  const vault = options.vault ?? (needsVault ? await openVault({
    env, userDir, log,
    passphrase: options.passphrase ?? (async () => {
      if (interactive) return promptPassphrase(diagnostic, options.promptIO);
      if (!env.KEYSENTRY_VAULT_PASSPHRASE) throw new CliError('The encrypted file needs KEYSENTRY_VAULT_PASSPHRASE when no interactive terminal is available.');
      redactor.register(env.KEYSENTRY_VAULT_PASSPHRASE);
      return Buffer.from(env.KEYSENTRY_VAULT_PASSPHRASE);
    }),
    allowFileFallback: options.allowFileFallback ?? (reason => interactive ? confirmVaultFallback(store, reason, diagnostic, options.promptIO) : Promise.resolve(false)),
  }) : createMemoryVault());
  const verification = await createAuditLog({ path, vault, redactor, deviceKey: async () => {
    const key = await vault.get('key/device-ed25519');
    if (!key) throw new CliError('The device signing key is unavailable; the audit checkpoint cannot be verified here.');
    try { return deviceKeyFromPrivate(key); } finally { key.fill(0); }
  } }).verify();
  return { ...verification, anchorChecked: needsVault && vault.backend !== 'env' };
}
