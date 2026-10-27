import { constants } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { classify } from '../core/classify.js';
import type { Classification } from '../types.js';

/** Transient scanner input. buildFirstRun consumes and clears value; never serialize these hits. */
export interface RawHit extends Classification {
  kind: 'file' | 'history';
  path: string;
  name: string;
  value?: string;
  line?: number;
  commit?: string;
  committedAt?: string;
  template?: boolean;
}

const IGNORED = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.venv', 'vendor', '.keysentry']);
const MAX_BYTES = 1024 * 1024;
interface Candidate { name: string; value: string; line: number }

export function isTemplate(path: string): boolean {
  return /\.(?:example|sample|template)(?:\.|$)/i.test(path);
}

export function isDotenvPath(path: string): boolean {
  const parts = path.split('/');
  const name = parts.at(-1)!;
  return name === '.dev.vars' || name === '.env' || name.startsWith('.env.')
    || (parts.at(-2) === '.vercel' && name.startsWith('.env'));
}

function placeholder(value: string): boolean {
  const body = value.replace(/^(?:sk-(?:ant-(?:api03|admin01)-|or-v1-|proj-|svcacct-)?|[sr]k_(?:live|test)_|whsec_|github_pat_|gh[pous]_|sb_secret_|xox[bp]-|re_|SG\.)/, '');
  return /^(?:\$\{[^}]*\}|<[^>]+>)$/.test(value)
    || /^(?:your[-_ ]|replace[-_ ]|placeholder|change[-_ ]?me|example(?:[-_ ]|$)|sample(?:[-_ ]|$)|template(?:[-_ ]|$)|dummy(?:[-_ ]|$))/i.test(body)
    || /^(?:x{6,}|\*{6,}|\.{3,})$/i.test(body);
}

/** Read-only copy of hosts/dotenv's private LINE parser; see notes/firstrun.md. */
function dotenvCandidates(source: string): Candidate[] {
  const normalized = source.replace(/\r\n?/g, '\n');
  const assignment = /(?:^|^)(\s*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?))(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#.*)?(?:$|$)/dgm;
  const result: Candidate[] = [];
  let cursor = 0;
  let line = 1;
  for (const match of normalized.matchAll(assignment)) {
    // Prefix whitespace can include blank lines; locate the actual variable name.
    const start = match.index + match[1]!.lastIndexOf(match[2]!);
    for (; cursor < start; cursor++) if (normalized[cursor] === '\n') line++;
    const raw = (match[3] ?? '').trim();
    let value = raw.replace(/^(['"`])([\s\S]*)\1$/mg, '$2');
    if (raw.startsWith('"')) value = value.replace(/\\n/g, '\n').replace(/\\r/g, '\r');
    result.push({ name: match[2]!, value, line });
  }
  return result;
}

/** Simple assignment extraction, shared with added history lines; never evaluates project code. */
export function extractCandidates(source: string, dotenv = false): Candidate[] {
  if (dotenv) return dotenvCandidates(source);
  const result: Candidate[] = [];
  for (const [index, text] of source.split(/\r\n?|\n/).entries()) {
    const json = [...text.matchAll(/"((?:\\.|[^"\\])+)"\s*:\s*"((?:\\.|[^"\\])*)"/g)];
    if (json.length) {
      for (const match of json) {
        try {
          result.push({ name: JSON.parse(`"${match[1]}"`) as string, value: JSON.parse(`"${match[2]}"`) as string, line: index + 1 });
        } catch { /* Malformed config is skipped without reflecting its contents. */ }
      }
      continue;
    }
    const match = /^\s*(?:-\s*)?(?:export\s+)?(["']?)([A-Za-z_][\w.-]*|\/\/[^=\s]+)\1\s*(?:=|:\s*)\s*(.*?)\s*$/.exec(text);
    if (!match) continue;
    const raw = match[3]!;
    const quoted = /^(['"`])((?:\\.|(?!\1)[^\\])*)\1\s*(?:[,#].*)?$/.exec(raw);
    let value = quoted ? quoted[2]! : raw.replace(/\s+#.*$/, '').replace(/,\s*$/, '').trim();
    if (quoted?.[1] === '"') value = value.replace(/\\n/g, '\n').replace(/\\r/g, '\r');
    result.push({ name: match[2]!, value, line: index + 1 });
  }
  return result;
}

export function classifyCandidate(name: string, value: string): Classification | null {
  const classification = classify(name, value);
  return classification.isSecret && !placeholder(value) ? classification : null;
}

function selected(path: string): boolean {
  const parts = path.split('/');
  const name = parts.at(-1)!;
  return name === '.env' || name.startsWith('.env.') || name === '.dev.vars' || name === '.npmrc' || name === '.pypirc'
    || /^docker-compose.*\.ya?ml$/.test(name) || name.endsWith('.tfvars') || name === 'wrangler.toml'
    || (parts.at(-2) === '.vercel' && name.startsWith('.env'))
    || (parts.at(-2) === 'config' && /\.(?:json|yaml|yml|toml)$/.test(name));
}

export async function scanWorkingTree(root: string, opts: { maxFiles?: number; maxBytes?: number } = {}): Promise<{ files: number; hits: RawHit[] }> {
  const result: { files: number; hits: RawHit[] } = { files: 0, hits: [] };
  const maxFiles = Number.isFinite(opts.maxFiles) ? Math.max(0, Math.floor(opts.maxFiles!)) : 10_000;
  const maxBytes = Number.isFinite(opts.maxBytes) ? Math.max(0, Math.min(MAX_BYTES, Math.floor(opts.maxBytes!))) : MAX_BYTES;
  const base = resolve(root);
  let canonical: string;
  try {
    const info = await lstat(base);
    if (!info.isDirectory() || info.isSymbolicLink()) return result;
    canonical = await realpath(base);
  } catch { return result; }

  async function visit(directory: string, prefix: string, depth: number): Promise<void> {
    let entries;
    try { entries = await readdir(directory, { withFileTypes: true }); }
    catch { return; }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (result.files >= maxFiles) return;
      if (entry.isSymbolicLink()) continue;
      const path = prefix ? `${prefix}/${entry.name}` : entry.name;
      const absolute = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (depth < 3 && !IGNORED.has(entry.name)) await visit(absolute, path, depth + 1);
        continue;
      }
      if (!entry.isFile() || !selected(path)) continue;
      let handle;
      try {
        const resolved = await realpath(absolute);
        const inside = relative(canonical, resolved);
        if (inside === '..' || inside.startsWith(`..${sep}`) || isAbsolute(inside)) continue;
        handle = await open(absolute, constants.O_RDONLY | constants.O_NOFOLLOW);
        const info = await handle.stat();
        if (!info.isFile() || info.size > maxBytes) continue;
        // A growing file cannot make readFile allocate without a bound.
        const bytes = Buffer.alloc(Math.min(info.size + 1, maxBytes + 1));
        let count = 0;
        while (count < bytes.length) {
          const read = await handle.read(bytes, count, bytes.length - count, null);
          if (!read.bytesRead) break;
          count += read.bytesRead;
        }
        if (count > maxBytes || count > info.size) continue;
        const content = bytes.subarray(0, count);
        const source = content.toString('utf8');
        if (source.includes('\0') || !Buffer.from(source, 'utf8').equals(content)) continue;
        result.files++;
        for (const candidate of extractCandidates(source, isDotenvPath(path))) {
          const classification = classifyCandidate(candidate.name, candidate.value);
          if (classification) result.hits.push({ ...classification, kind: 'file', path, ...candidate, template: isTemplate(path) });
        }
      } catch { /* Unreadable files are skipped; OS errors can contain untrusted filenames. */ }
      finally { await handle?.close().catch(() => undefined); }
    }
  }
  await visit(base, '', 0);
  return result;
}
