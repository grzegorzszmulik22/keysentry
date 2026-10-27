import type { Vault } from '../../types.js';
import { VaultUnavailableError } from '../errors.js';
import { runHelper } from '../exec.js';
import { validateVaultName } from '../names.js';

const FIX = 'install libsecret-tools (Debian/Ubuntu) or libsecret (Fedora/Arch) and run inside a desktop session, or choose the encrypted file';
const INTERNAL = new Set(['__index__', '__probe__']);

/** Only lookup is used for reads: secret-tool search can print unrelated secret values. */
export function createLinuxSecretServiceVault(opts: { exec?: typeof runHelper } = {}): Vault {
  const exec = opts.exec ?? runHelper;
  let tail: Promise<unknown> = Promise.resolve();
  function serialized<T>(operation: () => Promise<T>): Promise<T> {
    const next = tail.then(operation);
    tail = next.catch(() => {});
    return next;
  }
  function unavailable(): VaultUnavailableError {
    return new VaultUnavailableError(`The Linux secret service is unavailable; ${FIX}.`);
  }
  async function helper(args: string[], stdin?: Buffer) {
    try { return await exec('secret-tool', args, { stdin }); }
    catch { throw unavailable(); }
  }
  function decode(value: Buffer): Buffer {
    const encoded = value.toString('utf8').trim();
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) throw unavailable();
    return Buffer.from(encoded, 'base64');
  }
  async function read(name: string): Promise<Buffer | null> {
    const result = await helper(['lookup', 'service', 'keysentry', 'account', name]);
    try {
      if (result.code === 1 && result.stdout.length === 0 && !result.stderr.trim()) return null;
      if (result.code !== 0 || result.stderr.trim()) throw unavailable();
      return decode(result.stdout);
    } finally { result.stdout.fill(0); }
  }
  async function write(name: string, value: Buffer): Promise<void> {
    const result = await helper(['store', '--label', `keysentry ${name}`, 'service', 'keysentry', 'account', name], Buffer.from(`${value.toString('base64')}\n`));
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
    backend: 'linux-secret-service',
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
        const existing = await read(name);
        if (existing === null) return false;
        existing.fill(0);
        const previous = INTERNAL.has(name) ? [] : await names();
        const result = await helper(['clear', 'service', 'keysentry', 'account', name]);
        if (result.code === 1 && result.stdout.length === 0 && !result.stderr.trim()) return false;
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
