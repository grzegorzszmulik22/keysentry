import type { Vault } from '../../types.js';
import { VaultUnavailableError } from '../errors.js';
import { runHelper } from '../exec.js';
import { validateVaultName } from '../names.js';

const FIX = 'unlock the login keychain (Keychain Access) or check that /usr/bin/security works';
const INTERNAL = new Set(['__index__', '__probe__']);

/** Keychain values are base64 so every Vault buffer can use security's text interface. */
export function createMacosKeychainVault(opts: { exec?: typeof runHelper } = {}): Vault {
  const exec = opts.exec ?? runHelper;
  let tail: Promise<unknown> = Promise.resolve();
  function serialized<T>(operation: () => Promise<T>): Promise<T> {
    const next = tail.then(operation);
    tail = next.catch(() => {});
    return next;
  }
  function unavailable(): VaultUnavailableError {
    return new VaultUnavailableError(`The macOS keychain is unavailable; ${FIX}.`);
  }
  async function helper(args: string[], stdin?: Buffer) {
    try { return await exec('/usr/bin/security', args, { stdin }); }
    catch { throw unavailable(); }
  }
  function decode(value: Buffer): Buffer {
    const encoded = value.toString('utf8').trim();
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) throw unavailable();
    return Buffer.from(encoded, 'base64');
  }
  async function read(name: string): Promise<Buffer | null> {
    const result = await helper(['find-generic-password', '-s', 'keysentry', '-a', name, '-w']);
    if (result.code === 44) return null;
    if (result.code !== 0 || result.stderr.trim()) throw unavailable();
    return decode(result.stdout);
  }
  async function write(name: string, value: Buffer): Promise<void> {
    const encoded = value.length === 0 ? '""' : value.toString('base64');
    const command = Buffer.from(`add-generic-password -U -s keysentry -a ${name} -w ${encoded}\n`);
    const result = await helper(['-i'], command);
    if (result.code !== 0 || result.stderr.trim()) throw unavailable();
  }
  async function names(): Promise<string[]> {
    const value = await read('__index__');
    if (value === null) return [];
    try {
      const parsed: unknown = JSON.parse(value.toString('utf8'));
      if (!Array.isArray(parsed) || !parsed.every((name): name is string => typeof name === 'string')) throw unavailable();
      for (const name of parsed) validateVaultName(name);
      return [...new Set(parsed)].filter((name) => !INTERNAL.has(name)).sort();
    } catch { throw unavailable(); }
  }
  async function index(values: string[]) {
    await write('__index__', Buffer.from(JSON.stringify([...new Set(values)].filter((name) => !INTERNAL.has(name)).sort())));
  }
  return {
    backend: 'macos-keychain',
    async get(name) {
      validateVaultName(name);
      return serialized(() => read(name));
    },
    async set(name, value) {
      validateVaultName(name);
      return serialized(async () => {
        const previous = INTERNAL.has(name) ? [] : await names();
        await write(name, value);
        if (!INTERNAL.has(name)) await index([...previous, name]);
      });
    },
    async delete(name) {
      validateVaultName(name);
      return serialized(async () => {
        const previous = INTERNAL.has(name) ? [] : await names();
        const result = await helper(['delete-generic-password', '-s', 'keysentry', '-a', name]);
        if (result.code === 44) return false;
        if (result.code !== 0 || result.stderr.trim()) throw unavailable();
        if (!INTERNAL.has(name)) await index(previous.filter((item) => item !== name));
        return true;
      });
    },
    async list(prefix = '') {
      if (prefix) validateVaultName(prefix);
      return serialized(async () => (await names()).filter((name) => name.startsWith(prefix)));
    },
  };
}
