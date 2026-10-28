import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { createLogger, createRedactor } from '../core/index.js';
import { createFetchHttp } from '../http.js';
import { EGRESS_RULES, createFileReceipt, createGuardedHttp, rulesForUserFeeds, rulesForUserUrls } from '../net/index.js';
import { BUILD_VERSION, checkLocalIntegrity, verifyRelease } from '../release/index.js';
import { createAuditLog, deviceKeyFromPrivate } from '../security/index.js';
import { openVault } from '../vault/index.js';
import { loadConfigMetadata } from './config.js';
import { setupNetwork } from './network-setup.js';
import { kmsEgressRules } from '../kms/index.js';
import { auditExportEgressRules } from '../audit-export/index.js';
import { offlineEgressRules } from '../feeds/index.js';
import { networkStatusLines } from '../net/transport.js';
import { CliError } from './errors.js';
import { effectiveSettings, parseSignedPolicy, readTeamFile, restrictUserEgress } from '../policy/index.js';
import type { TeamPolicy } from '../types.js';
import { confirmVaultFallback, promptPassphrase, promptVaultBackend } from './prompts.js';
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

/**
 * The team policy for commands that open no project state (the roster that verifies its signatures lives there).
 * Every policy rule only narrows, so applying the file's rules here can only make these views stricter; the
 * signatures are checked whenever a command opens the project state (`keysentry policy verify`).
 */
async function policyForInspection(metadata: Awaited<ReturnType<typeof loadConfigMetadata>>): Promise<{ policy: TeamPolicy | null; problem: string | null }> {
  const file = metadata.settings.team.policyFile;
  if (!file) return { policy: null, problem: null };
  try {
    const parsed = parseSignedPolicy(await readTeamFile(resolve(metadata.cwd, file), 'team policy file named in team.policyFile'));
    return parsed.ok ? { policy: parsed.value.policy, problem: null } : { policy: null, problem: parsed.reason };
  } catch (error) {
    return { policy: null, problem: error instanceof CliError ? error.message : 'The team policy file could not be read.' };
  }
}

/** Inspection commands have no need to load state keys or credential adapters. */
export async function inspectNetwork(options: RuntimeOptions, since?: string) {
  if (since !== undefined && !validTimestamp(since)) {
    throw new CliError('Use an ISO timestamp for --since.');
  }
  const configured = await loadConfigMetadata(options);
  const team = await policyForInspection(configured);
  const metadata = team.policy ? await loadConfigMetadata({ ...options, settings: effectiveSettings(configured.settings, team.policy) }) : configured;
  const network = await setupNetwork({ settings: metadata.settings.network, cwd: metadata.cwd, env: options.env ?? process.env,
    policy: team.policy, injected: options.http ?? { request: async () => { throw new CliError('keysentry network does not contact any host.'); } } });
  const all = [...EGRESS_RULES, ...rulesForUserFeeds(network.feedMode.offline ? [] : metadata.feedUrls),
    ...rulesForUserUrls(metadata.webhooks, 'notification webhook you configured'), ...metadata.userHostRules,
    ...(metadata.settings.kms ? kmsEgressRules(metadata.settings.kms) : []), ...auditExportEgressRules(metadata.settings.audit.export)];
  const rules = restrictUserEgress(network.feedMode.offline ? offlineEgressRules(all) : all, team.policy);
  const receipt = await createFileReceipt(join(metadata.cwd, '.keysentry', 'network.jsonl')).summarize(since);
  const teamLines = team.policy ? [`Team policy version ${team.policy.version} narrows these hosts (keysentry policy verify checks its signatures).`]
    : team.problem ? [`The team policy file could not be used, so changes are paused: ${team.problem}`] : [];
  return { rules, receipt, status: [...networkStatusLines(network.summary), ...teamLines] };
}

export async function inspectRelease(options: RuntimeOptions, offline = false) {
  const local = await checkLocalIntegrity();
  if (offline || local.status === 'mismatch') return { local };
  const configured = await loadConfigMetadata(options);
  // A team policy file that cannot be read stops the online check rather than letting it skip a required proxy.
  const team = await policyForInspection(configured);
  if (team.problem) throw new CliError(`The online release check did not run because the team policy file could not be used: ${team.problem}`);
  const metadata = team.policy ? await loadConfigMetadata({ ...options, settings: effectiveSettings(configured.settings, team.policy) }) : configured;
  const redactor = createRedactor();
  const log = options.log ?? createLogger({ redactor });
  // Release checks use the configured proxy and CA like every other request. Proxy credentials come from HTTPS_PROXY
  // here, because this check opens no vault.
  const network = await setupNetwork({ settings: metadata.settings.network, cwd: metadata.cwd, env: options.env ?? process.env,
    redactor, policy: team.policy, ...(options.http ? { injected: options.http } : {}) });
  const http = createGuardedHttp(network.transport, {
    rules: restrictUserEgress([...EGRESS_RULES, ...rulesForUserFeeds(metadata.feedUrls),
      ...rulesForUserUrls(metadata.webhooks, 'notification webhook you configured'), ...metadata.userHostRules], team.policy),
    receipt: createFileReceipt(join(metadata.cwd, '.keysentry', 'network.jsonl')),
    trustedUrls: metadata.webhooks, log,
  });
  const release = await verifyRelease({ http, version: BUILD_VERSION, bundleSha256: local.actual ?? '' });
  return { local, release };
}

/** Always consult the vault: public files cannot decide whether its anchor is checked. */
export async function inspectAudit(options: RuntimeOptions) {
  const path = join(resolve(options.cwd ?? process.cwd()), '.keysentry', 'audit.jsonl');
  const userDir = resolve(options.userDir ?? join(homedir(), '.keysentry'));
  const anchor = createHash('sha256').update(resolve(path)).digest('hex').slice(0, 16);
  const redactor = createRedactor();
  const env = options.env ?? process.env;
  const interactive = (options.stdinIsTTY ?? !!process.stdin.isTTY) && (options.stdoutIsTTY ?? !!process.stdout.isTTY);
  const log = options.log ?? createLogger({ redactor });
  const diagnostic = (text: string) => log.info(redactor.redact(text));
  const store = env.KEYSENTRY_VAULT ?? (process.platform === 'win32' ? 'windows-dpapi' : process.platform === 'darwin' ? 'macos-keychain' : 'linux-secret-service');
  const vault = options.vault ?? await openVault({
    env, userDir, log,
    passphrase: options.passphrase ?? (async () => {
      if (interactive && !env.KEYSENTRY_VAULT_PASSPHRASE) return promptPassphrase(diagnostic, options.promptIO);
      if (!env.KEYSENTRY_VAULT_PASSPHRASE) throw new CliError('The encrypted file needs KEYSENTRY_VAULT_PASSPHRASE when no interactive terminal is available.');
      redactor.register(env.KEYSENTRY_VAULT_PASSPHRASE);
      return Buffer.from(env.KEYSENTRY_VAULT_PASSPHRASE);
    }),
    allowFileFallback: options.allowFileFallback ?? (reason => interactive ? confirmVaultFallback(store, reason, diagnostic, options.promptIO) : Promise.resolve(false)),
    ...(interactive ? { chooseBackend: backend => promptVaultBackend(backend, diagnostic, options.promptIO) } : {}),
  });
  const audit = options.audit ?? createAuditLog({ path, vault, redactor, keyLockPath: join(userDir, 'audit-mac'), deviceKey: async () => {
    const key = await vault.get('key/device-ed25519');
    if (!key) throw new CliError('The device signing key is unavailable; the audit checkpoint cannot be verified here.');
    try { return deviceKeyFromPrivate(key); } finally { key.fill(0); }
  } });
  const verification = await audit.verify();
  const head = await vault.get(`audit/head/${anchor}`);
  const hasHead = head !== null;
  head?.fill(0);
  if (!hasHead && verification.entries > 0) {
    return { ...verification, ok: false, problem: 'This audit log has no anchor in your vault; it may have been replaced.', anchorChecked: vault.backend !== 'env' };
  }
  return { ...verification, anchorChecked: vault.backend !== 'env' };
}
