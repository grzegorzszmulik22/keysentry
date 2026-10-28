import type { Vault } from '../types.js';

/**
 * Watcher keys this computer trusts for signed approval requests and notices: the self-hosted watcher from
 * `watcher setup`, and the watcher inside each cloud box, recorded after that box confirmed its deployment.
 */
export async function trustedWatcherKeys(vault: Vault): Promise<Buffer[]> {
  return (await knownWatcherKeys(vault)).map(entry => entry.publicKeyDer);
}

/**
 * The same keys, each with who holds it. A deployed watcher signs its audit export webhook batches with its own key,
 * so `audit export status` lists these next to this computer's key (review M3).
 */
export async function knownWatcherKeys(vault: Vault): Promise<{ signer: string; publicKeyDer: Buffer }[]> {
  const keys: { signer: string; publicKeyDer: Buffer }[] = [];
  const own = await vault.get('watcher/signing/public');
  if (own) keys.push({ signer: 'deployed watcher', publicKeyDer: own });
  for (const name of await vault.list('box/')) {
    const match = /^box\/([a-z][a-z0-9-]*)\/watcher-public$/.exec(name);
    if (!match) continue;
    const key = await vault.get(name);
    if (key) keys.push({ signer: `cloud box ${match[1]}`, publicKeyDer: key });
  }
  return keys;
}
