import { randomBytes } from 'node:crypto';
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import { buildFirstRun, detectDeployTargets, scanHistory, scanWorkingTree, type GitRunner } from '../firstrun/index.js';
import type { FirstRunResult, HostId, Vault, VaultBackendId } from '../types.js';
import { deriveKeyFromPassphrase, openBytes } from '../security/index.js';
import { createEnvVault, createLinuxSecretServiceVault, createMacosKeychainVault, createWindowsDpapiVault, validateVaultName } from '../vault/index.js';
import type { KeysentryRuntime } from './runtime.js';
import { CliError } from './errors.js';
import { providerName } from './provider-names.js';

export interface FirstRunOptions {
  cwd: string;
  noSave?: boolean;
  /** Guard defaults to the working tree; the ordinary first run includes history. */
  includeHistory?: boolean;
  /** Existing projects supply their already-open runtime; a first run never opens a vault. */
  runtime?: Pick<KeysentryRuntime, 'fingerprintKey' | 'store'>;
  confirmSave?: (result: FirstRunResult) => Promise<boolean>;
  /** Resolve encrypted project storage after consent, without opening it for an unsaved scan. */
  saveResult?: (result: FirstRunResult) => Promise<void>;
  git?: GitRunner;
  fingerprintKey?: Buffer;
  vault?: Vault;
  userDir?: string;
  env?: NodeJS.ProcessEnv;
  passphrase?: () => Promise<Buffer>;
}

const BACKENDS: readonly VaultBackendId[] = ['macos-keychain', 'windows-dpapi', 'linux-secret-service', 'encrypted-file', 'env', 'memory'];
const KEY_UNAVAILABLE = 'The saved project fingerprint key could not be read. Unlock the existing vault or provide its key before scanning this project.';

/** Bounded reads do not initialize a backend or follow a saved-state file link. */
async function readExisting(path: string, maxBytes: number): Promise<string | null> {
  try {
    const info = await lstat(path);
    if (!info.isFile() || info.isSymbolicLink() || info.size > maxBytes) throw new CliError(KEY_UNAVAILABLE);
    const bytes = await readFile(path);
    if (bytes.length > maxBytes) throw new CliError(KEY_UNAVAILABLE);
    return bytes.toString('utf8');
  } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null; throw error; }
}

function base64(value: unknown, maxBytes: number): Buffer {
  if (typeof value !== 'string' || value.length > Math.ceil(maxBytes / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new CliError(KEY_UNAVAILABLE);
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length > maxBytes || bytes.toString('base64') !== value) throw new CliError(KEY_UNAVAILABLE);
  return bytes;
}

/** The regular encrypted-file adapter locks even on get(). Read one existing snapshot with shared primitives. */
async function encryptedFingerprint(path: string, name: string, opts: FirstRunOptions): Promise<Buffer> {
  const raw = await readExisting(path, 4 * 1024 * 1024);
  if (!raw) throw new CliError(KEY_UNAVAILABLE);
  const file: unknown = JSON.parse(raw);
  if (!file || typeof file !== 'object' || Array.isArray(file)) throw new CliError(KEY_UNAVAILABLE);
  const data = file as Record<string, unknown>;
  const params = data.params as { N?: unknown; r?: unknown; p?: unknown } | undefined;
  if (data.v !== 1 || !params || ![params.N, params.r, params.p].every(n => typeof n === 'number' && Number.isSafeInteger(n) && n > 0)
    || typeof params.N !== 'number' || typeof params.r !== 'number' || typeof params.p !== 'number'
    || params.N > 1_048_576 || (params.N & (params.N - 1)) !== 0 || params.r > 32 || params.p > 16 || 128 * params.N * params.r > 256 * 1024 * 1024
    || !data.entries || typeof data.entries !== 'object' || Array.isArray(data.entries)) throw new CliError(KEY_UNAVAILABLE);
  const salt = base64(data.salt, 16);
  if (salt.length !== 16) throw new CliError(KEY_UNAVAILABLE);
  const entries = data.entries as Record<string, unknown>;
  if (Object.keys(entries).length > 10_000) throw new CliError(KEY_UNAVAILABLE);
  for (const [entry, sealed] of Object.entries(entries)) {
    validateVaultName(entry);
    if (typeof sealed !== 'string') throw new CliError(KEY_UNAVAILABLE);
  }
  if (!Object.hasOwn(entries, name)) throw new CliError(KEY_UNAVAILABLE);
  const check = base64(data.check, 256);
  const value = base64(entries[name], 256);
  const passphrase = opts.passphrase ? await opts.passphrase() : opts.env?.KEYSENTRY_VAULT_PASSPHRASE
    ? Buffer.from(opts.env.KEYSENTRY_VAULT_PASSPHRASE) : null;
  if (!passphrase) throw new CliError('The saved project fingerprint key needs the existing encrypted-vault passphrase.');
  let key: Buffer | undefined;
  try {
    key = await deriveKeyFromPassphrase(passphrase, salt, { N: params.N, r: params.r, p: params.p });
    const checked = openBytes(key, check, 'vault:__check__');
    try { if (!checked.equals(Buffer.from('keysentry-vault-check'))) throw new CliError(KEY_UNAVAILABLE); }
    finally { checked.fill(0); }
    return openBytes(key, value, `vault:${name}`);
  } finally { passphrase.fill(0); key?.fill(0); }
}

async function existingFingerprint(cwd: string, opts: FirstRunOptions): Promise<Buffer | null> {
  try {
    const directory = join(cwd, '.keysentry');
    try {
      const info = await lstat(directory);
      if (!info.isDirectory() || info.isSymbolicLink() || relative(await realpath(cwd), await realpath(directory)) !== '.keysentry') throw new CliError(KEY_UNAVAILABLE);
    } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null; throw error; }
    const raw = await readExisting(join(directory, 'project.json'), 4096);
    if (raw === null) return null;
    const project: unknown = JSON.parse(raw);
    const id = project && typeof project === 'object' && 'id' in project ? project.id : undefined;
    if (typeof id !== 'string' || !/^[0-9a-f]{16}$/.test(id)) throw new CliError(KEY_UNAVAILABLE);
    const name = `project/${id}/key/fingerprint`;
    if (opts.vault) {
      const value = await opts.vault.get(name);
      if (!value) throw new CliError(KEY_UNAVAILABLE);
      return value;
    }
    const env = opts.env ?? process.env;
    const userDir = resolve(opts.userDir ?? join(homedir(), '.keysentry'));
    let selected = env.KEYSENTRY_VAULT;
    if (selected === undefined) {
      const choice = await readExisting(join(userDir, 'vault-backend.json'), 4096);
      if (choice !== null) {
        const parsed: unknown = JSON.parse(choice);
        if (!parsed || typeof parsed !== 'object' || !('backend' in parsed) || typeof parsed.backend !== 'string') throw new CliError(KEY_UNAVAILABLE);
        selected = parsed.backend;
      }
    }
    if (selected === undefined) {
      const file = await readExisting(join(userDir, 'vault.enc'), 4 * 1024 * 1024);
      selected = file !== null ? 'encrypted-file' : process.platform === 'win32' ? 'windows-dpapi' : process.platform === 'darwin' ? 'macos-keychain' : 'linux-secret-service';
    }
    if (!BACKENDS.includes(selected as VaultBackendId) || selected === 'memory') throw new CliError(KEY_UNAVAILABLE);
    if (selected === 'encrypted-file') return await encryptedFingerprint(join(userDir, 'vault.enc'), name, { ...opts, env });
    const vault = selected === 'env' ? createEnvVault(env) : selected === 'windows-dpapi'
      ? createWindowsDpapiVault({ dir: join(userDir, 'vault-dpapi') }) : selected === 'macos-keychain'
        ? createMacosKeychainVault() : createLinuxSecretServiceVault();
    const value = await vault.get(name);
    if (!value) throw new CliError(KEY_UNAVAILABLE);
    return value;
  } catch { throw new CliError(KEY_UNAVAILABLE); }
}

/** Local-only scanning. The returned summary contains hints and keyed identifiers, never raw hits. */
export async function runFirstRun(opts: FirstRunOptions): Promise<{ result: FirstRunResult; saved: boolean }> {
  const cwd = resolve(opts.cwd);
  const start = performance.now();
  const supplied = opts.runtime?.fingerprintKey ?? opts.fingerprintKey;
  const key = supplied ? Buffer.from(supplied) : await existingFingerprint(cwd, opts) ?? randomBytes(32);
  if (key.length !== 32) { key.fill(0); throw new CliError('The project fingerprint key must contain 32 bytes.'); }
  let result: FirstRunResult;
  try {
    const [files, history, deployTargets] = await Promise.all([
      scanWorkingTree(cwd), opts.includeHistory === false ? Promise.resolve({ commits: 0, complete: true, hits: [] }) : scanHistory(cwd, { git: opts.git }), detectDeployTargets(cwd),
    ]);
    result = buildFirstRun({ root: cwd, files, history, deployTargets, fingerprintKey: key, elapsedMs: Math.round(performance.now() - start) });
  } finally { key.fill(0); }
  if (opts.noSave || !opts.confirmSave || !await opts.confirmSave(result)) return { result, saved: false };
  if (opts.saveResult) {
    await opts.saveResult(result);
    return { result, saved: true };
  }
  const directory = join(cwd, '.keysentry');
  const path = join(directory, 'first-run.json');
  if (opts.runtime) {
    await opts.runtime.store.writeJson('report', path, result);
  } else {
    // This initial summary is value-free metadata. Full project state is encrypted once a vault is connected.
    // Exclusive writes avoid following a pre-existing file link or replacing another process's saved result.
    try { await mkdir(directory, { mode: 0o700 }); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw new CliError('The first-run summary could not be saved.'); }
    const info = await lstat(directory);
    if (!info.isDirectory() || info.isSymbolicLink()) throw new CliError('The state directory must be a local directory. Nothing was saved.');
    const ignore = join(directory, '.gitignore');
    try { await writeFile(ignore, '*\n', { flag: 'wx', mode: 0o600 }); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw new CliError('The state ignore file could not be saved.');
      const existing = await lstat(ignore);
      if (!existing.isFile() || existing.isSymbolicLink() || await readFile(ignore, 'utf8') !== '*\n') {
        throw new CliError('The state ignore file differs from the expected file. Nothing was saved.');
      }
    }
    try { await writeFile(path, `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx', mode: 0o600 }); }
    catch { throw new CliError('The first-run summary could not be saved. Existing files were kept.'); }
  }
  return { result, saved: true };
}

const HOST_NAMES: Record<HostId, string> = { railway: 'Railway', vercel: 'Vercel', render: 'Render', fly: 'Fly.io', 'github-actions': 'GitHub Actions', dotenv: 'Local files',
  netlify: 'Netlify', 'cloudflare-workers': 'Cloudflare Workers', 'supabase-functions': 'Supabase Edge Functions',
  heroku: 'Heroku', digitalocean: 'DigitalOcean App Platform', coolify: 'Coolify', zeabur: 'Zeabur',
  kubernetes: 'Kubernetes', 'aws-secrets-manager': 'AWS Secrets Manager', 'vault-kv': 'HashiCorp Vault', doppler: 'Doppler', infisical: 'Infisical', };
const count = (value: number, noun: string) => `${value} ${noun}${value === 1 ? '' : 's'}`;

export function formatFirstRun(result: FirstRunResult, includeHistory = true): string {
  const committed = result.findings.filter(finding => finding.inGitHistory).length;
  const hosts = [...new Set(result.deployTargets.map(target => HOST_NAMES[target.host]))];
  const lines = [
    includeHistory ? `Found ${count(result.findings.length, 'key')} in local files and git history.` : `Found ${count(result.findings.length, 'key')} in the working tree.`,
    includeHistory ? `Scanned ${count(result.scannedFiles, 'file')} and ${count(result.scannedCommits, 'commit')}${result.historyComplete ? '.' : '; history scan is incomplete.'}` : `Scanned ${count(result.scannedFiles, 'file')}.`,
    ...(includeHistory ? [committed ? `${count(committed, 'key')} appeared in git history. Removing a file does not remove its history; rotate these keys.` : 'No keys found in the scanned git history.'] : []),
    ...(hosts.length ? [`Possible deployment platforms: ${hosts.join(', ')} (from project configuration).`] : []),
    ...result.findings.map(finding => `${providerName(finding.provider)}: ${finding.hint ?? '(hidden)'} — ${finding.locations.map(location => `${location.path}${location.line === undefined ? '' : `:${location.line}`}${location.kind === 'history' ? ' (git history)' : ''}`).join(', ')}`),
    ...(result.nextSteps.length ? ['', 'Next steps:', ...result.nextSteps.map(step => `- ${step}`)] : []),
    '', includeHistory ? 'First run reads local files and git history. No network calls, token or account are needed.' : 'This check reads local files only. Use --history to include git history.',
  ];
  return lines.join('\n');
}
