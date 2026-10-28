import type { Vault } from '../types.js';

/**
 * Watcher keys this computer trusts for signed approval requests and notices: the self-hosted watcher from
 * `watcher setup`, and the watcher inside each cloud box, recorded after that box confirmed its deployment.
 */
export async function trustedWatcherKeys(vault: Vault): Promise<Buffer[]> {
  const keys: Buffer[] = [];
  const own = await vault.get('watcher/signing/public');
  if (own) keys.push(own);
  for (const name of await vault.list('box/')) {
    if (!/^box\/[a-z][a-z0-9-]*\/watcher-public$/.test(name)) continue;
    const key = await vault.get(name);
    if (key) keys.push(key);
  }
  return keys;
}
