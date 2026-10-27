import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { classify, createRedactor, makeHint } from '../core/index.js';
import type { ProviderId } from '../types.js';

export type GitRunner = (args: string[], opts: {
  cwd: string; onLine: (line: string) => void; signal: AbortSignal;
}) => Promise<{ code: number }>;

export interface GuardResult {
  blocked: { path: string; line: number; provider: ProviderId; hint: string | null }[];
}

const MAX_LINE = 1024 * 1024;
const MAX_ALLOW_BYTES = 1024 * 1024;
const GIT_ERROR = 'Unable to check staged changes. The commit was not checked.';

/** Small streaming runner, independent of the parallel first-run module. */
export const defaultGitRunner: GitRunner = async (args, opts) => {
  const env: NodeJS.ProcessEnv = {};
  for (const name of ['PATH', 'SystemRoot', 'HOME', 'USERPROFILE']) {
    const key = Object.keys(process.env).find((key) => key.toLowerCase() === name.toLowerCase());
    if (key !== undefined) env[name] = process.env[key];
  }
  Object.assign(env, {
    GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0', GIT_PAGER: 'cat',
    GIT_OPTIONAL_LOCKS: '0', LC_ALL: 'C',
  });
  return new Promise<{ code: number }>((fulfil, reject) => {
    if (opts.signal.aborted) { reject(new Error(GIT_ERROR)); return; }
    const child = spawn('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'diff.external=',
      '-c', 'core.fsmonitor=false', ...args], {
      cwd: opts.cwd, shell: false, windowsHide: true, env, stdio: ['ignore', 'pipe', 'ignore'],
    });
    let done = false;
    let pending = '';
    const decoder = new StringDecoder('utf8');
    function fail(): void {
      if (done) return;
      done = true;
      pending = '';
      opts.signal.removeEventListener('abort', fail);
      child.kill();
      reject(new Error(GIT_ERROR));
    }
    function consume(text: string): void {
      pending += text;
      let end: number;
      while ((end = pending.indexOf('\n')) !== -1) {
        if (end > MAX_LINE) throw new Error(GIT_ERROR);
        const line = pending.slice(0, end).replace(/\r$/, '');
        pending = pending.slice(end + 1);
        opts.onLine(line);
      }
      if (pending.length > MAX_LINE) throw new Error(GIT_ERROR);
    }
    opts.signal.addEventListener('abort', fail, { once: true });
    child.stdout.on('data', (data: Buffer) => {
      if (done) return;
      try { consume(decoder.write(data)); } catch { fail(); }
    });
    child.stdout.on('error', fail);
    child.on('error', fail);
    child.on('close', (code) => {
      if (done) return;
      try {
        consume(decoder.end());
        if (pending) opts.onLine(pending.replace(/\r$/, ''));
      } catch { fail(); return; }
      done = true;
      pending = '';
      opts.signal.removeEventListener('abort', fail);
      fulfil({ code: code ?? 1 });
    });
  }).catch(() => { throw new Error(GIT_ERROR); });
};

interface AllowRules { hashes: Set<string>; paths: string[] }

async function readAllowRules(root: string): Promise<AllowRules> {
  const rules: AllowRules = { hashes: new Set(), paths: [] };
  const path = join(root, '.keysentry-allow');
  try {
    let info;
    try { info = await lstat(path); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return rules;
      throw error;
    }
    if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_ALLOW_BYTES) throw new Error();
    const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    let bytes: Buffer;
    try {
      if (!(await handle.stat()).isFile()) throw new Error();
      bytes = Buffer.alloc(MAX_ALLOW_BYTES + 1);
      let length = 0;
      while (length < bytes.length) {
        const read = await handle.read(bytes, length, bytes.length - length, null);
        if (read.bytesRead === 0) break;
        length += read.bytesRead;
      }
      if (length > MAX_ALLOW_BYTES) throw new Error();
      bytes = bytes.subarray(0, length);
    } finally { await handle.close(); }
    const source = bytes.toString('utf8');
    if (!Buffer.from(source).equals(bytes)) throw new Error();
    for (const line of source.split(/\r?\n/)) {
      const rule = line.trim();
      if (!rule || rule.startsWith('#')) continue;
      const hash = /^sha256:([0-9a-fA-F]{32})$/.exec(rule);
      if (hash) { rules.hashes.add(hash[1]!.toLowerCase()); continue; }
      if (rule.startsWith('path:')) {
        const glob = rule.slice(5);
        if (glob && glob.length <= 1024 && !/^[A-Za-z]:|^\//.test(glob)
          && !/[\\\x00-\x1f\x7f]/.test(glob) && !glob.split('/').some((part) => part === '..' || part === '.')) {
          rules.paths.push(glob);
          continue;
        }
      }
      throw new Error();
    }
    return rules;
  } catch { throw new Error('Unable to read valid .keysentry-allow rules.'); }
}

// A small NFA keeps untrusted glob matching bounded rather than backtracking.
function matchesGlob(path: string, glob: string): boolean {
  type Token = { kind: 'literal'; char: string } | { kind: 'one' | 'star' | 'all' | 'dirs' };
  const tokens: Token[] = [];
  for (let i = 0; i < glob.length; i++) {
    const char = glob[i]!;
    if (char === '*' && glob[i + 1] === '*') {
      while (glob[i + 1] === '*') i++;
      if (glob[i + 1] === '/') { tokens.push({ kind: 'dirs' }); i++; }
      else tokens.push({ kind: 'all' });
    } else if (char === '*') tokens.push({ kind: 'star' });
    else if (char === '?') tokens.push({ kind: 'one' });
    else tokens.push({ kind: 'literal', char });
  }
  // State records token offset and whether **/ is in the middle of a segment.
  let states = new Set<number>([0]);
  function close(input: Set<number>): Set<number> {
    const result = new Set(input);
    for (const state of result) {
      const index = Math.floor(state / 2);
      const kind = tokens[index]?.kind;
      if (kind === 'star' || kind === 'all' || (kind === 'dirs' && state % 2 === 0)) result.add((index + 1) * 2);
    }
    return result;
  }
  states = close(states);
  for (const char of path) {
    const next = new Set<number>();
    for (const state of states) {
      const index = Math.floor(state / 2);
      const token = tokens[index];
      if (!token) continue;
      if (token.kind === 'literal' && token.char === char || token.kind === 'one' && char !== '/') next.add((index + 1) * 2);
      else if (token.kind === 'star' && char !== '/' || token.kind === 'all') next.add(index * 2);
      else if (token.kind === 'dirs') next.add(index * 2 + (char === '/' ? 0 : 1));
    }
    states = close(next);
    if (states.size === 0) return false;
  }
  return states.has(tokens.length * 2);
}

function gitPath(text: string): string | null {
  let decoded = text;
  if (text.startsWith('"')) {
    if (!text.endsWith('"')) throw new Error(GIT_ERROR);
    const bytes: number[] = [];
    const escapes: Record<string, number> = { a: 7, b: 8, t: 9, n: 10, v: 11, f: 12, r: 13, '"': 34, '\\': 92 };
    for (let i = 1; i < text.length - 1; i++) {
      const char = text[i]!;
      if (char !== '\\') { bytes.push(...Buffer.from(char)); continue; }
      const next = text[++i]!;
      if (/[0-7]/.test(next)) {
        let octal = next;
        while (octal.length < 3 && /[0-7]/.test(text[i + 1] ?? '')) octal += text[++i];
        bytes.push(Number.parseInt(octal, 8));
      } else if (next in escapes) bytes.push(escapes[next]!);
      else throw new Error(GIT_ERROR);
    }
    decoded = Buffer.from(bytes).toString('utf8');
  }
  if (decoded === '/dev/null') return null;
  if (!decoded.startsWith('b/')) throw new Error(GIT_ERROR);
  const path = decoded.slice(2);
  if (!path || path.startsWith('/') || path.split('/').some((part) => part === '..') || path.includes('\0')) throw new Error(GIT_ERROR);
  return path;
}

function candidates(line: string): { name: string; value: string }[] {
  const result: { name: string; value: string }[] = [];
  function add(name: string, value: string): void {
    if (value) result.push({ name, value });
  }
  function unquote(text: string): string {
    if (text.startsWith('"')) {
      try { const value: unknown = JSON.parse(text); if (typeof value === 'string') return value; } catch { /* dotenv quotes */ }
    }
    return text.slice(1, -1);
  }
  const values = /(?:^|[^A-Za-z0-9_.-])["'`]?([A-Za-z_][A-Za-z0-9_.-]*)["'`]?\s*(?:=|:)\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`[^`]*`|[^\s,;}#]+)/g;
  for (const match of line.matchAll(values)) {
    const raw = match[2]!;
    add(match[1]!, /^["'`]/.test(raw) ? unquote(raw) : raw);
  }
  for (const match of line.matchAll(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`[^`]*`/g)) add('', unquote(match[0]));
  // Also recognize bare tokens and credential URLs in code or comments.
  for (const match of line.matchAll(/[^\s"'`<>()[\]{},;=]+/g)) add('', match[0]);
  return result;
}

function printable(text: string): string {
  return text.replace(/[\x00-\x1f\x7f-\x9f]/g, (char) => {
    if (char === '\t') return '\\t';
    if (char === '\n') return '\\n';
    if (char === '\r') return '\\r';
    return '\\x' + char.charCodeAt(0).toString(16).padStart(2, '0');
  });
}

export async function guardStaged(root: string, git: GitRunner = defaultGitRunner): Promise<GuardResult> {
  const rules = await readAllowRules(root);
  const blocked: GuardResult['blocked'] = [];
  const redactor = createRedactor();
  let path: string | null = null;
  let line = 0;
  let oldLeft = 0;
  let newLeft = 0;
  let pathAllowed = false;
  let pem: { line: number; type: string; value: string } | null = null;
  function scanAdded(text: string, addedLine: number): void {
    const seen = new Set<string>();
    function check(name: string, value: string, location = addedLine): void {
      const detected = classify(name, value);
      // Dedupe after classification so a name-dependent key is still detected
      // when the same value first appeared in an ordinary field on this line.
      if (!detected.isSecret || seen.has(value)) return;
      seen.add(value);
      redactor.register(value);
      if (pathAllowed) return;
      const hash = createHash('sha256').update('keysentry-allow:v1:').update(value).digest('hex').slice(0, 32);
      if (rules.hashes.has(hash)) return;
      blocked.push({ path: path!, line: location, provider: detected.provider, hint: makeHint(value) });
    }
    if (pem) pem.value += '\n' + text;
    else {
      const begin = /-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY)-----/.exec(text);
      if (begin && !text.includes(`-----END ${begin[1]}-----`)) {
        pem = { line: addedLine, type: begin[1]!, value: text.slice(begin.index) };
      }
    }
    if (pem) {
      if (pem.value.length > MAX_LINE) throw new Error(GIT_ERROR);
      const footer = `-----END ${pem.type}-----`;
      const end = pem.value.indexOf(footer);
      if (end !== -1) {
        check('', pem.value.slice(0, end + footer.length), pem.line);
        pem = null;
      }
    }
    for (const candidate of candidates(text)) check(candidate.name, candidate.value);
  }
  function onLine(text: string): void {
    if (text.length > MAX_LINE) throw new Error(GIT_ERROR);
    if (oldLeft > 0 || newLeft > 0) {
      if (text.startsWith('+') && newLeft > 0) {
        const addedLine = line++;
        newLeft--;
        if (path !== null) scanAdded(text.slice(1), addedLine);
      } else if (text.startsWith('-') && oldLeft > 0) oldLeft--;
      else if (text.startsWith(' ') && oldLeft > 0 && newLeft > 0) { oldLeft--; newLeft--; line++; }
      else if (!text.startsWith('\\ No newline')) throw new Error(GIT_ERROR);
      return;
    }
    if (text.startsWith('diff --git ')) { path = null; pathAllowed = false; pem = null; return; }
    if (text.startsWith('+++ ')) {
      path = gitPath(text.slice(4));
      pathAllowed = path !== null && rules.paths.some((glob) => matchesGlob(path!, glob));
      return;
    }
    const hunk = /^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(text);
    if (hunk) {
      pem = null;
      oldLeft = Number(hunk[1] ?? 1);
      line = Number(hunk[2]);
      newLeft = Number(hunk[3] ?? 1);
      if (![oldLeft, line, newLeft].every(Number.isSafeInteger)) throw new Error(GIT_ERROR);
    }
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20_000);
  timer.unref();
  try {
    const result = await git(['diff', '--cached', '-U0', '--no-color', '--no-ext-diff', '--no-textconv',
      '--src-prefix=a/', '--dst-prefix=b/', '--'], { cwd: resolve(root), onLine, signal: controller.signal });
    if (result.code !== 0 || controller.signal.aborted || oldLeft > 0 || newLeft > 0) throw new Error(GIT_ERROR);
  } catch { throw new Error(GIT_ERROR); }
  finally { clearTimeout(timer); }
  return { blocked: blocked.map((hit) => ({ ...hit,
    path: printable(redactor.redact(hit.path)), hint: hit.hint === null ? null : printable(hit.hint),
  })) };
}

export function formatGuardStaged(result: GuardResult): { output: string; exitCode: 0 | 1 } {
  if (result.blocked.length === 0) return { output: '', exitCode: 0 };
  const lines = result.blocked.map((hit) => `${printable(hit.path)}:${hit.line}  ${hit.provider}  ${hit.hint === null ? '(hidden)' : printable(hit.hint)}`);
  lines.push(`Commit stopped: ${result.blocked.length} ${result.blocked.length === 1 ? 'secret' : 'secrets'} would be committed. Remove them, or add a test value to .keysentry-allow.`);
  return { output: lines.join('\n') + '\n', exitCode: 1 };
}
