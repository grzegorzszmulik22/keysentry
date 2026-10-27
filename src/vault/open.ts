import { randomBytes } from 'node:crypto';
import { access, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Logger, Vault, VaultBackendId } from '../types.js';
import { runHelper } from './exec.js';
import { VaultUnavailableError } from './errors.js';
import { createMemoryVault } from './backends/memory.js';
import { createEnvVault } from './backends/env.js';
import { createEncryptedFileVault } from './backends/encrypted-file.js';
import { createMacosKeychainVault } from './backends/macos-keychain.js';
import { createWindowsDpapiVault } from './backends/windows-dpapi.js';
import { createLinuxSecretServiceVault } from './backends/linux-secret-service.js';

const BACKENDS: readonly VaultBackendId[] = ['macos-keychain', 'windows-dpapi', 'linux-secret-service', 'encrypted-file', 'env', 'memory'];
const FIX = {
  'macos-keychain': 'unlock the login keychain (Keychain Access) or check that /usr/bin/security works',
  'linux-secret-service': 'install libsecret-tools (Debian/Ubuntu) or libsecret (Fedora/Arch) and run inside a desktop session, or choose the encrypted file',
  'windows-dpapi': 'check that Windows PowerShell (powershell.exe) can run',
};
type OSBackend = keyof typeof FIX;

export async function openVault(opts: {
  platform?: NodeJS.Platform;
  env: NodeJS.ProcessEnv;
  userDir: string;
  log: Logger;
  exec?: typeof runHelper;
  passphrase?: () => Promise<Buffer>;
  allowFileFallback: (reason: string) => Promise<boolean>;
  /** Supplied only by interactive callers when both existing stores are available. */
  chooseBackend?: (operatingSystemBackend: VaultBackendId) => Promise<VaultBackendId>;
}): Promise<Vault> {
  const explicit = opts.env.KEYSENTRY_VAULT;
  if (explicit !== undefined && !BACKENDS.includes(explicit as VaultBackendId)) {
    throw new TypeError(`KEYSENTRY_VAULT must be one of: ${BACKENDS.join(', ')}.`);
  }
  const choicePath = join(opts.userDir, 'vault-backend.json');
  let remembered: VaultBackendId | undefined;
  if (explicit === undefined) {
    try {
      const choice: unknown = JSON.parse(await readFile(choicePath, 'utf8'));
      if (!choice || typeof choice !== 'object' || !('backend' in choice) || !BACKENDS.includes(choice.backend as VaultBackendId)) {
        throw new TypeError();
      }
      remembered = choice.backend as VaultBackendId;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw new VaultUnavailableError('The saved vault backend choice cannot be read. Set KEYSENTRY_VAULT to the backend you used before to choose it again.');
      }
    }
  }
  const selected = explicit as VaultBackendId | undefined ?? remembered;
  async function remember(vault: Vault): Promise<Vault> {
    if (remembered === vault.backend) return vault;
    await mkdir(opts.userDir, { recursive: true, mode: 0o700 });
    const temporary = `${choicePath}.${randomBytes(8).toString('hex')}.tmp`;
    try {
      await writeFile(temporary, `${JSON.stringify({ backend: vault.backend })}\n`, { mode: 0o600, flag: 'wx' });
      await rename(temporary, choicePath);
    } finally { await rm(temporary, { force: true }); }
    return vault;
  }
  function fileVault(): Vault {
    if (!opts.passphrase) throw new VaultUnavailableError('The encrypted file needs a passphrase. Run keysentry in an interactive terminal to enter one.');
    return createEncryptedFileVault({ path: join(opts.userDir, 'vault.enc'), passphrase: opts.passphrase });
  }
  if (selected === 'env') return remember(createEnvVault(opts.env));
  if (selected === 'memory') {
    opts.log.warn('The memory vault is temporary; nothing will be kept after exit.');
    return remember(createMemoryVault());
  }
  if (selected === 'encrypted-file') return remember(fileVault());
  let hasFile = false;
  if (!selected) {
    try { await access(join(opts.userDir, 'vault.enc')); hasFile = true; }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  }
  const platform = opts.platform ?? process.platform;
  const backend: OSBackend | undefined = selected as OSBackend | undefined
    ?? (platform === 'darwin' ? 'macos-keychain' : platform === 'win32' ? 'windows-dpapi' : platform === 'linux' ? 'linux-secret-service' : undefined);
  if (backend) {
    let vault: Vault;
    if (backend === 'macos-keychain') vault = createMacosKeychainVault({ exec: opts.exec });
    else if (backend === 'windows-dpapi') vault = createWindowsDpapiVault({ dir: join(opts.userDir, 'vault-dpapi'), exec: opts.exec });
    else vault = createLinuxSecretServiceVault({ exec: opts.exec });
    const probe = randomBytes(32);
    try {
      if (backend === 'linux-secret-service' && !opts.env.DBUS_SESSION_BUS_ADDRESS) throw new VaultUnavailableError();
      await vault.set('__probe__', probe);
      const result = await vault.get('__probe__');
      try { if (!result?.equals(probe)) throw new VaultUnavailableError(); }
      finally { result?.fill(0); }
      if (!await vault.delete('__probe__')) throw new VaultUnavailableError();
    } catch {
      // Probe items are disposable; cleanup must not mask the platform fix.
      if (!(backend === 'linux-secret-service' && !opts.env.DBUS_SESSION_BUS_ADDRESS)) {
        try { await vault.delete('__probe__'); } catch { /* Unavailable backend. */ }
      }
      const reason = `The ${backend} vault is unavailable. To use it, ${FIX[backend]}.`;
      if (!selected && hasFile) {
        opts.log.warn('The operating system vault is unavailable. Using your existing encrypted file vault.');
        return remember(fileVault());
      }
      if (selected || !await opts.allowFileFallback(reason)) throw new VaultUnavailableError(reason);
      return remember(fileVault());
    } finally { probe.fill(0); }
    // Keep the choice outside the probe catch: persistence or prompt failures must not trigger fallback.
    if (hasFile) {
      if (opts.chooseBackend) {
        const choice = await opts.chooseBackend(backend);
        if (choice !== backend && choice !== 'encrypted-file') throw new TypeError('Choose the encrypted file or the available operating system vault.');
        if (choice === 'encrypted-file') return remember(fileVault());
      } else {
        opts.log.warn('Both the encrypted file and the operating system vault are available. Using the encrypted file because no vault choice has been saved.');
        return remember(fileVault());
      }
    }
    return remember(vault);
  }
  const reason = 'No operating system credential store is available on this platform. Choose the encrypted file to continue.';
  if (hasFile) {
    opts.log.warn('No operating system vault is available. Using your existing encrypted file vault.');
    return remember(fileVault());
  }
  if (!await opts.allowFileFallback(reason)) throw new VaultUnavailableError(reason);
  return remember(fileVault());
}
