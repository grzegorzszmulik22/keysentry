import { randomBytes } from 'node:crypto';
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
}): Promise<Vault> {
  const selected = opts.env.KEYSENTRY_VAULT;
  if (selected !== undefined && !BACKENDS.includes(selected as VaultBackendId)) {
    throw new TypeError(`KEYSENTRY_VAULT must be one of: ${BACKENDS.join(', ')}.`);
  }
  function fileVault(): Vault {
    if (!opts.passphrase) throw new VaultUnavailableError('The encrypted file needs a passphrase. Run keysentry in an interactive terminal to enter one.');
    return createEncryptedFileVault({ path: join(opts.userDir, 'vault.enc'), passphrase: opts.passphrase });
  }
  if (selected === 'env') return createEnvVault(opts.env);
  if (selected === 'memory') {
    opts.log.warn('The memory vault is temporary; nothing will be kept after exit.');
    return createMemoryVault();
  }
  if (selected === 'encrypted-file') return fileVault();
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
      return vault;
    } catch {
      // Probe items are disposable; cleanup must not mask the platform fix.
      if (!(backend === 'linux-secret-service' && !opts.env.DBUS_SESSION_BUS_ADDRESS)) {
        try { await vault.delete('__probe__'); } catch { /* Unavailable backend. */ }
      }
      const reason = `The ${backend} vault is unavailable. To use it, ${FIX[backend]}.`;
      if (selected || !await opts.allowFileFallback(reason)) throw new VaultUnavailableError(reason);
      return fileVault();
    } finally { probe.fill(0); }
  }
  const reason = 'No operating system credential store is available on this platform. Choose the encrypted file to continue.';
  if (!await opts.allowFileFallback(reason)) throw new VaultUnavailableError(reason);
  return fileVault();
}
