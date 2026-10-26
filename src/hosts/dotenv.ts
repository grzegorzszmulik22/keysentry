import { randomUUID } from 'node:crypto';
import { lstat, open, readdir, readFile, rename, rm, stat } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import type { HostAdapter, Logger, RawVariable, ServiceRef } from '../types.js';

export interface DotenvHostOptions {
  roots: string[];
  log: Logger;
  includeTemplates?: boolean;
}

const excluded = new Set(['node_modules', '.git', 'dist', 'build', '.keysentry']);
const templates = new Set(['.env.example', '.env.sample', '.env.template', '.env.dist']);
const validName = /^[A-Za-z_][A-Za-z0-9_.-]*$/;
type Quote = "'" | '"' | '`' | '';
interface Entry { name: string; start: number; end: number; quote: Quote; value: string }

function lineEnd(source: string, offset: number): number {
  const newline = /[\r\n\u2028\u2029]/g;
  newline.lastIndex = offset;
  return newline.exec(source)?.index ?? source.length;
}

function parse(source: string): Entry[] {
  const entries: Entry[] = [];
  const assignment = /^[\t \uFEFF]*(?:export[\t ]+)?([A-Za-z_][A-Za-z0-9_.-]*)[\t ]*=[\t ]*/gm;
  let match: RegExpExecArray | null;
  while ((match = assignment.exec(source)) !== null) {
    const start = assignment.lastIndex;
    const first = source[start];
    const quote: Quote = first === "'" || first === '"' || first === '`' ? first : '';
    let end: number;
    let value: string;
    if (quote) {
      let cursor = start + 1;
      for (; cursor < source.length; cursor++) {
        if (quote === '"' && source[cursor] === '\\') { cursor++; continue; }
        if (source[cursor] === quote) break;
      }
      if (cursor >= source.length) throw new Error('dotenv contains an unterminated quoted value');
      end = cursor + 1;
      value = source.slice(start + 1, cursor);
      if (quote === '"') {
        value = value.replace(/\\([\\"nr])/g, (_, char: string) => char === 'n' ? '\n' : char === 'r' ? '\r' : char);
      }
    } else {
      const boundary = lineEnd(source, start);
      const comment = source.indexOf('#', start);
      end = comment !== -1 && comment < boundary ? comment : boundary;
      while (end > start && /[\t \r]/.test(source[end - 1]!)) end--;
      value = source.slice(start, end);
    }
    entries.push({ name: match[1]!, start, end, quote, value });
    const nextLine = lineEnd(source, end);
    assignment.lastIndex = nextLine === source.length ? source.length : nextLine + (source.startsWith('\r\n', nextLine) ? 2 : 1);
  }
  return entries;
}

function encode(value: string, quote: Quote = ''): string {
  if ((quote === "'" || quote === '`') && !value.includes(quote)) return `${quote}${value}${quote}`;
  if (quote === '"' || quote !== '' || /[\s#'"`\\]/.test(value)) {
    return '"' + value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r') + '"';
  }
  return value;
}

export function createDotenvHost(options: DotenvHostOptions): HostAdapter {
  const roots = [...new Set(options.roots.map((root) => resolve(root)))];

  async function listServices(): Promise<ServiceRef[]> {
    const services: ServiceRef[] = [];
    const seen = new Set<string>();
    async function visit(dir: string, root: string, prefix: string): Promise<void> {
      const items = await readdir(dir, { withFileTypes: true });
      items.sort((a, b) => a.name.localeCompare(b.name));
      for (const item of items) {
        if (item.isSymbolicLink()) continue;
        const path = join(dir, item.name);
        const name = prefix ? join(prefix, item.name) : item.name;
        if (item.isDirectory()) {
          if (!excluded.has(item.name)) await visit(path, root, name);
        } else if (item.isFile() && (item.name === '.env' || item.name.startsWith('.env.'))) {
          if ((!options.includeTemplates && templates.has(item.name)) || seen.has(path)) continue;
          seen.add(path);
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

  async function sourceFor(service: ServiceRef): Promise<string> {
    // Reject caller-supplied paths which discovery would skip, including symlinks/templates.
    const allowed = (await listServices()).some((ref) => ref.projectId === service.projectId && ref.serviceId === service.serviceId);
    if (service.host !== 'dotenv' || !allowed) throw new Error('dotenv file is outside the configured scan');
    let bytes: Buffer;
    try { bytes = await readFile(service.serviceId); }
    catch { throw new Error('dotenv file read failed'); }
    const source = bytes.toString('utf8');
    if (!Buffer.from(source, 'utf8').equals(bytes)) throw new Error('dotenv file is not valid UTF-8');
    return source;
  }

  return {
    id: 'dotenv',
    capabilities: { readValues: true, batchWrite: true, redeploy: false },
    listServices,
    async readVariables(service) {
      const vars = new Map<string, RawVariable>();
      for (const entry of parse(await sourceFor(service))) vars.set(entry.name, { name: entry.name, value: entry.value, sealed: false });
      return [...vars.values()];
    },
    async writeVariables(service, vars) {
      const changes = Object.entries(vars);
      if (changes.some(([name, value]) => !validName.test(name) || typeof value !== 'string')) throw new Error('dotenv variable name or value is invalid');
      if (!changes.length) return;
      const source = await sourceFor(service);
      const entries = parse(source);
      const targets = new Map(changes);
      const found = new Set<string>();
      let updated = '';
      let cursor = 0;
      for (const entry of entries) {
        if (!targets.has(entry.name)) continue;
        updated += source.slice(cursor, entry.start) + encode(targets.get(entry.name)!, entry.quote);
        cursor = entry.end;
        found.add(entry.name);
      }
      updated += source.slice(cursor);
      const newline = /\r\n|[\r\n\u2028\u2029]/.exec(source)?.[0] ?? '\n';
      for (const [name, value] of changes) {
        if (found.has(name)) continue;
        if (updated.length && !/[\r\n\u2028\u2029]$/.test(updated)) updated += newline;
        updated += `${name}=${encode(value)}${newline}`;
      }
      if (updated === source) return;
      const temporary = join(dirname(service.serviceId), `.keysentry-${randomUUID()}.tmp`);
      let file;
      try {
        // The atomic replacement is the requested dotenv destination; never create backup copies.
        const mode = (await stat(service.serviceId)).mode & 0o777;
        file = await open(temporary, 'wx', 0o600);
        await file.writeFile(updated, 'utf8');
        await file.sync();
        await file.chmod(mode);
        await file.close();
        file = undefined;
        await rename(temporary, service.serviceId);
      } catch {
        throw new Error('dotenv atomic write failed');
      } finally {
        if (file) await file.close().catch(() => {});
        await rm(temporary, { force: true }).catch(() => {});
      }
    },
    async redeploy() { return null; },
    async deploymentStatus() { throw new Error('dotenv does not create deployments'); },
  };
}
