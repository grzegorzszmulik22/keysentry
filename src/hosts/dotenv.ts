import { randomUUID } from 'node:crypto';
import { chmod, lstat, open, readdir, readFile, rename, rm, stat } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import type { HostAdapter, Logger, RawVariable, ServiceRef } from '../types.js';
import { syncFile } from '../security/durable.js';

export interface DotenvHostOptions {
  roots: string[];
  log: Logger;
  includeTemplates?: boolean;
}

const excluded = new Set(['node_modules', '.git', 'dist', 'build', '.keysentry']);
const templates = new Set(['.env.example', '.env.sample', '.env.template', '.env.dist']);
const validName = /^[A-Za-z_][A-Za-z0-9_.-]*$/;
const temporaryName = /\.keysentry-.+\.tmp$/;
const activeTemporaryFiles = new Set<string>();
type Quote = "'" | '"' | '`' | '';
interface Entry { name: string; start: number; end: number; quote: Quote; value: string }

function parse(source: string): Entry[] {
  // dotenv normalizes CRLF and bare CR before parsing. Keep an offset map so
  // writes can still preserve untouched source bytes, including CRLF and BOM.
  let normalized = '';
  const offsets: number[] = [];
  for (let cursor = 0; cursor < source.length; cursor++) {
    offsets.push(cursor);
    if (source[cursor] === '\r') {
      normalized += '\n';
      if (source[cursor + 1] === '\n') cursor++;
    } else normalized += source[cursor];
  }
  offsets.push(source.length);
  const entries: Entry[] = [];
  // dotenv's LINE grammar, with a prefix capture and indices for lossless edits.
  // In particular, escaped delimiters are retained, not decoded; unquoted #
  // begins a comment even without a preceding space. Invalid lines are ignored.
  const assignment = /(?:^|^)(\s*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?))(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#.*)?(?:$|$)/dgm;
  let match: RegExpExecArray | null;
  while ((match = assignment.exec(normalized)) !== null) {
    const raw = match[3] ?? '';
    const trimmed = raw.trim();
    const first = trimmed[0];
    const quote: Quote = (first === "'" || first === '"' || first === '`') && trimmed.endsWith(first) && trimmed.length >= 2 ? first : '';
    let value = trimmed.replace(/^(['"`])([\s\S]*)\1$/mg, '$2');
    if (first === '"') value = value.replace(/\\n/g, '\n').replace(/\\r/g, '\r');
    const rawStart = match.indices![3]?.[0] ?? match.indices![1]![1];
    const start = rawStart + raw.length - raw.trimStart().length;
    const end = start + trimmed.length;
    entries.push({ name: match[2]!, start: offsets[start]!, end: offsets[end]!, quote, value });
  }
  return entries;
}

function sameValues(actual: Entry[], expected: { name: string; value: string }[]): boolean {
  return actual.length === expected.length && actual.every((entry, index) =>
    entry.name === expected[index]!.name && entry.value === expected[index]!.value);
}

function unrepresentable(): never {
  throw new Error('dotenv value cannot round-trip with dotenv quoting; use a representable value or another secret source');
}

function encode(value: string, quote: Quote, inContext: (encoded: string) => boolean): string {
  function candidate(style: Quote): string | undefined {
    if (style === '"') {
      // dotenv has no escape for a literal backslash-n/backslash-r. Doubling
      // backslashes or escaping quotes would silently change the app's value.
      if (/\\[nr]/.test(value)) return undefined;
      return '"' + value.replace(/\n/g, '\\n').replace(/\r/g, '\\r') + '"';
    }
    return style + value + style;
  }
  function roundTrips(encoded: string | undefined): encoded is string {
    if (encoded === undefined) return false;
    // Include an inline comment and following assignment: a delimiter at the
    // end of the value must not swallow either when inserted into a real file.
    const entries = parse(`KEY=${encoded} # keysentry\nAFTER=sentinel\n`);
    return entries.length === 2 && entries[0]?.name === 'KEY' && entries[0].value === value
      && entries[1]?.name === 'AFTER' && entries[1].value === 'sentinel' && inContext(encoded);
  }
  const preferred = candidate(quote);
  if (roundTrips(preferred)) return preferred;
  // Single quotes preserve literal escapes even across real LF newlines.
  // The round-trip check still rejects CR/CRLF normalization or delimiter collisions.
  if (!value.includes("'")) {
    const single = candidate("'");
    if (roundTrips(single)) return single;
  }
  if (!/[\r\n]/.test(value)) {
    if (!value.includes('`')) {
      const backtick = candidate('`');
      if (roundTrips(backtick)) return backtick;
    }
  }
  const double = candidate('"');
  if (roundTrips(double)) return double;
  return unrepresentable();
}

export function createDotenvHost(options: DotenvHostOptions): HostAdapter {
  const roots = [...new Set(options.roots.map((root) => resolve(root)))];

  async function readSource(path: string): Promise<string> {
    let bytes: Buffer;
    try { bytes = await readFile(path); }
    catch { throw new Error('dotenv file read failed'); }
    const source = bytes.toString('utf8');
    if (!Buffer.from(source, 'utf8').equals(bytes)) throw new Error('dotenv file is not valid UTF-8');
    return source;
  }

  function skipped(path: string): void {
    options.log.warn('dotenv file skipped: unreadable or cannot be parsed as UTF-8 dotenv', { file: path });
  }

  async function discover(validate: boolean): Promise<ServiceRef[]> {
    const services: ServiceRef[] = [];
    const seen = new Set<string>();
    async function visit(dir: string, root: string, prefix: string): Promise<void> {
      const items = await readdir(dir, { withFileTypes: true });
      items.sort((a, b) => a.name.localeCompare(b.name));
      const envFile = (name: string) => !temporaryName.test(name) && (name === '.env' || name.startsWith('.env.'));
      if (items.some((item) => item.isFile() && envFile(item.name))) {
        for (const item of items) {
          const path = join(dir, item.name);
          if (!item.isFile() || !temporaryName.test(item.name) || activeTemporaryFiles.has(path)) continue;
          try { await rm(path, { force: true }); }
          catch { options.log.warn('dotenv stale temporary file could not be removed', { file: path }); }
        }
      }
      for (const item of items) {
        if (item.isSymbolicLink()) continue;
        const path = join(dir, item.name);
        const name = prefix ? join(prefix, item.name) : item.name;
        if (item.isDirectory()) {
          if (!excluded.has(item.name)) await visit(path, root, name);
        } else if (item.isFile() && envFile(item.name)) {
          if ((!options.includeTemplates && templates.has(item.name)) || seen.has(path)) continue;
          seen.add(path);
          if (validate) {
            try { parse(await readSource(path)); }
            catch { skipped(path); continue; }
          }
          services.push({ host: 'dotenv', projectId: root, projectName: basename(root), serviceId: path, serviceName: name, environmentId: '', environmentName: '' });
        }
      }
    }
    try {
      for (const root of roots) {
        const info = await lstat(root);
        if (info.isDirectory() && !info.isSymbolicLink()) await visit(root, root, '');
      }
    } catch {
      throw new Error('dotenv file discovery failed');
    }
    return services;
  }

  async function listServices(): Promise<ServiceRef[]> { return discover(true); }

  async function sourceFor(service: ServiceRef): Promise<string> {
    // Reject caller-supplied paths which discovery would skip, including symlinks/templates.
    const allowed = (await discover(false)).some((ref) => ref.projectId === service.projectId && ref.serviceId === service.serviceId);
    if (service.host !== 'dotenv' || !allowed) throw new Error('dotenv file is outside the configured scan');
    return readSource(service.serviceId);
  }

  return {
    id: 'dotenv',
    capabilities: { readValues: true, batchWrite: true, redeploy: false },
    listServices,
    async readVariables(service) {
      const vars = new Map<string, RawVariable>();
      let entries: Entry[];
      try { entries = parse(await sourceFor(service)); }
      catch { skipped(service.serviceId); return []; }
      for (const entry of entries) vars.set(entry.name, { name: entry.name, value: entry.value, sealed: false });
      return [...vars.values()];
    },
    async writeVariables(service, vars) {
      const changes = Object.entries(vars);
      if (changes.some(([name, value]) => !validName.test(name) || typeof value !== 'string')) throw new Error('dotenv variable name or value is invalid');
      if (!changes.length) return;
      const source = await sourceFor(service);
      const entries = parse(source);
      const expected = entries.map(({ name, value }) => ({ name, value }));
      const targets = new Map(changes);
      const found = new Set<string>();
      let updated = '';
      let cursor = 0;
      for (const [index, entry] of entries.entries()) {
        if (!targets.has(entry.name)) continue;
        const value = targets.get(entry.name)!;
        expected[index]!.value = value;
        const prefix = updated + source.slice(cursor, entry.start);
        // A delimiter may pair with a later quote in a preserved comment or
        // assignment. Validate candidates against this actual file context.
        updated = prefix + encode(value, entry.quote, (encoded) =>
          sameValues(parse(prefix + encoded + source.slice(entry.end)), expected));
        cursor = entry.end;
        found.add(entry.name);
      }
      updated += source.slice(cursor);
      const newline = /\r\n|[\r\n]/.exec(source)?.[0] ?? '\n';
      for (const [name, value] of changes) {
        if (found.has(name)) continue;
        if (updated.length && !/[\r\n]$/.test(updated)) updated += newline;
        const prefix = updated + `${name}=`;
        expected.push({ name, value });
        updated = prefix + encode(value, '', (encoded) => sameValues(parse(prefix + encoded + newline), expected)) + newline;
      }
      if (!sameValues(parse(updated), expected)) unrepresentable();
      if (updated === source) return;
      const temporary = join(dirname(service.serviceId), `${basename(service.serviceId)}.keysentry-${randomUUID()}.tmp`);
      let file;
      activeTemporaryFiles.add(temporary);
      try {
        // The atomic replacement is the requested dotenv destination; never create backup copies.
        const mode = (await stat(service.serviceId)).mode & 0o777;
        file = await open(temporary, 'wx', 0o600);
        await file.writeFile(updated, 'utf8');
        await syncFile(file);
        await rename(temporary, service.serviceId);
        // Keep the temp private until it becomes the requested destination. Path-based chmod: the Node permission
        // model disables FileHandle.chmod (fchmod) entirely but allows chmod on granted paths.
        await chmod(service.serviceId, mode);
      } catch {
        throw new Error('dotenv atomic write failed');
      } finally {
        if (file) await file.close().catch(() => {});
        await rm(temporary, { force: true }).catch(() => {});
        activeTemporaryFiles.delete(temporary);
      }
    },
    async redeploy() { return null; },
    async deploymentStatus() { throw new Error('dotenv does not create deployments'); },
  };
}
