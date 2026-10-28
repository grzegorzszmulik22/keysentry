import { createHash, randomBytes } from 'node:crypto';
import { mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import type { Vault } from '../../types.js';
import { VaultUnavailableError } from '../errors.js';
import { runHelper } from '../exec.js';
import { validateVaultName } from '../names.js';
import { syncFile } from '../../security/durable.js';

const FIX = 'check that Windows PowerShell (powershell.exe) can run';
const INTERNAL = new Set(['__index__', '__probe__']);
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

// Both scripts are fixed. Names and payloads only enter the helper on stdin.
function script(operation: 'Protect' | 'Unprotect'): string {
  return `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
  Add-Type -AssemblyName System.Security
  $name = [Console]::In.ReadLine()
  $payload = [Console]::In.ReadLine()
  $bytes = [Convert]::FromBase64String($payload)
  $entropy = [System.Text.Encoding]::UTF8.GetBytes('keysentry-v1:' + $name)
  $result = [System.Security.Cryptography.ProtectedData]::${operation}($bytes, $entropy, 'CurrentUser')
  [Console]::Out.Write([Convert]::ToBase64String($result))
} catch {
  [Console]::Error.WriteLine('DPAPI operation failed.')
  exit 1
} finally {
  if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
  if ($null -ne $result) { [Array]::Clear($result, 0, $result.Length) }
}`;
}

const PROTECT_COMMAND = Buffer.from(script('Protect'), 'utf16le').toString('base64');
const UNPROTECT_COMMAND = Buffer.from(script('Unprotect'), 'utf16le').toString('base64');

/** DPAPI protects the bytes; all filesystem operations remain in Node. */
export function createWindowsDpapiVault(opts: { dir: string; exec?: typeof runHelper }): Vault {
  const exec = opts.exec ?? runHelper;
  let tail: Promise<unknown> = Promise.resolve();
  function serialized<T>(operation: () => Promise<T>): Promise<T> {
    const next = tail.then(async () => {
      try { return await operation(); }
      catch (error) {
        if (error instanceof VaultUnavailableError) throw error;
        throw unavailable();
      }
    });
    tail = next.catch(() => {});
    return next;
  }
  function unavailable(): VaultUnavailableError {
    return new VaultUnavailableError(`The Windows credential store is unavailable; ${FIX}.`);
  }
  function path(name: string): string {
    return join(opts.dir, `${createHash('sha256').update(name, 'utf8').digest('hex')}.dpapi`);
  }
  function isMissing(error: unknown): boolean {
    return error !== null && typeof error === 'object' && 'code' in error && error.code === 'ENOENT';
  }
  async function atomicWrite(file: string, value: string) {
    await mkdir(opts.dir, { recursive: true, mode: 0o700 });
    const temporary = join(opts.dir, `.tmp-${randomBytes(16).toString('hex')}`);
    try {
      const handle = await open(temporary, 'wx', 0o600);
      try { await handle.writeFile(value, 'utf8'); await syncFile(handle); }
      finally { await handle.close(); }
      await rename(temporary, file);
    } finally {
      await unlink(temporary).catch((error: unknown) => { if (!isMissing(error)) throw error; });
    }
  }
  async function transform(name: string, payload: string, protect: boolean): Promise<string> {
    let result: Awaited<ReturnType<typeof runHelper>>;
    try {
      result = await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', protect ? PROTECT_COMMAND : UNPROTECT_COMMAND], { stdin: Buffer.from(`${name}\n${payload}\n`) });
    } catch { throw unavailable(); }
    // The exit code decides: Windows PowerShell may write CLIXML progress records to stderr even on success.
    if (result.code !== 0) throw unavailable();
    const encoded = result.stdout.toString('utf8').trim();
    if (!BASE64.test(encoded) || (protect && !encoded)) throw unavailable();
    return encoded;
  }
  async function names(): Promise<string[]> {
    let value: string;
    try { value = await readFile(join(opts.dir, 'index.json'), 'utf8'); }
    catch (error) { if (isMissing(error)) return []; throw error; }
    try {
      const parsed: unknown = JSON.parse(value);
      if (!Array.isArray(parsed) || !parsed.every((name): name is string => typeof name === 'string')) throw unavailable();
      for (const name of parsed) validateVaultName(name);
      return [...new Set(parsed)].filter((name) => !INTERNAL.has(name)).sort();
    } catch { throw unavailable(); }
  }
  async function index(values: string[]) {
    await atomicWrite(join(opts.dir, 'index.json'), JSON.stringify([...new Set(values)].filter((name) => !INTERNAL.has(name)).sort()));
  }
  return {
    backend: 'windows-dpapi',
    async get(name) {
      validateVaultName(name);
      return serialized(async () => {
        let encoded: string;
        try { encoded = (await readFile(path(name), 'utf8')).trim(); }
        catch (error) { if (isMissing(error)) return null; throw error; }
        if (!encoded || !BASE64.test(encoded)) throw unavailable();
        return Buffer.from(await transform(name, encoded, false), 'base64');
      });
    },
    async set(name, value) {
      validateVaultName(name);
      return serialized(async () => {
        const previous = INTERNAL.has(name) ? [] : await names();
        const protectedValue = await transform(name, value.toString('base64'), true);
        await atomicWrite(path(name), protectedValue);
        if (!INTERNAL.has(name)) await index([...previous, name]);
      });
    },
    async delete(name) {
      validateVaultName(name);
      return serialized(async () => {
        const previous = INTERNAL.has(name) ? [] : await names();
        try { await unlink(path(name)); }
        catch (error) { if (isMissing(error)) return false; throw error; }
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
