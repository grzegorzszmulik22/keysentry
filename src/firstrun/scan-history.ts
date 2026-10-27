import { spawn, type ChildProcessByStdio } from 'node:child_process';
import type { Readable } from 'node:stream';
import { classifyCandidate, extractCandidates, isDotenvPath, isTemplate, type RawHit } from './scan-files.js';

export type GitRunner = (args: string[], opts: { cwd: string; onLine: (line: string) => void; signal: AbortSignal }) => Promise<{ code: number }>;
export interface HistoryScan { commits: number; complete: boolean; hits: RawHit[]; note?: string }
const MAX_LINE_BYTES = 4096;

/** Git output stays in a bounded line buffer; stderr is drained without retaining or printing it. */
export const defaultGitRunner: GitRunner = (args, opts) => new Promise((resolve) => {
  if (opts.signal.aborted) { resolve({ code: 1 }); return; }
  const env: NodeJS.ProcessEnv = {};
  for (const name of ['PATH', 'SystemRoot', 'HOME', 'USERPROFILE']) {
    const value = process.env[name];
    if (value !== undefined) env[name] = value;
  }
  Object.assign(env, { GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0', GIT_PAGER: 'cat', GIT_OPTIONAL_LOCKS: '0', LC_ALL: 'C' });
  let child: ChildProcessByStdio<null, Readable, Readable>;
  try {
    child = spawn('git', ['--no-lazy-fetch', '-c', 'core.hooksPath=/dev/null', '-c', 'diff.external=', '-c', 'core.fsmonitor=false', ...args], {
      cwd: opts.cwd, env, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch { resolve({ code: 1 }); return; }
  let settled = false;
  let pending = Buffer.alloc(0);
  let prefix = Buffer.alloc(0);
  let oversized = false;
  let killTimer: ReturnType<typeof setTimeout> | undefined;
  function finish(code: number): void {
    if (settled) return;
    settled = true;
    pending = Buffer.alloc(0);
    opts.signal.removeEventListener('abort', abort);
    resolve({ code });
  }
  function abort(): void {
    child.kill();
    killTimer = setTimeout(() => { child.kill('SIGKILL'); }, 100);
    killTimer.unref();
    finish(1);
  }
  function deliver(): void {
    if (!settled && !opts.signal.aborted) {
      // Retain structure only for skipped lines, so subsequent hunk line numbers remain accurate.
      const start = prefix.toString('utf8');
      const skipped = start.startsWith('+++') ? '+++ ' : start.startsWith('+') ? '+\0' : start.startsWith(' ') ? ' '
        : start.startsWith('\0') ? '\0' : /^(?:diff --git |@@)/.test(start) ? 'diff --git ' : null;
      const line = oversized ? skipped : pending.toString('utf8').replace(/\r$/, '');
      try { if (line !== null) opts.onLine(line); }
      catch { abort(); }
    }
    pending = Buffer.alloc(0);
    prefix = Buffer.alloc(0);
    oversized = false;
  }
  child.stdout.on('data', (chunk: Buffer) => {
    if (settled) return;
    let cursor = 0;
    while (cursor < chunk.length && !settled) {
      const newline = chunk.indexOf(10, cursor);
      const end = newline < 0 ? chunk.length : newline;
      if (prefix.length < 16) prefix = Buffer.concat([prefix, chunk.subarray(cursor, Math.min(end, cursor + 16 - prefix.length))]);
      if (!oversized) {
        if (pending.length + end - cursor > MAX_LINE_BYTES) { oversized = true; pending = Buffer.alloc(0); }
        else pending = Buffer.concat([pending, chunk.subarray(cursor, end)]);
      }
      if (newline < 0) break;
      deliver();
      cursor = newline + 1;
    }
  });
  child.stdout.on('end', () => { if (pending.length || oversized) deliver(); });
  child.stdout.on('error', () => abort());
  child.stderr.on('error', () => undefined);
  child.stderr.resume();
  child.on('error', () => finish(1));
  child.once('close', (code) => { clearTimeout(killTimer); finish(code ?? 1); });
  opts.signal.addEventListener('abort', abort, { once: true });
  if (opts.signal.aborted) abort();
});

function gitPath(text: string): string | null {
  let path = text;
  if (path.startsWith('"') && path.endsWith('"')) {
    // Git's C quoting includes octal UTF-8 bytes, which JSON.parse does not accept.
    const bytes: number[] = [];
    const inner = path.slice(1, -1);
    for (let index = 0; index < inner.length; index++) {
      const char = inner[index]!;
      if (char !== '\\') { bytes.push(...Buffer.from(char)); continue; }
      const rest = inner.slice(index + 1);
      const octal = /^[0-7]{1,3}/.exec(rest)?.[0];
      if (octal) { bytes.push(parseInt(octal, 8)); index += octal.length; continue; }
      const escaped = inner[++index];
      const escapes: Record<string, string> = { t: '\t', n: '\n', r: '\r', b: '\b', f: '\f', v: '\v', '\\': '\\', '"': '"' };
      if (!escaped || escapes[escaped] === undefined) return null;
      bytes.push(...Buffer.from(escapes[escaped]!));
    }
    path = Buffer.from(bytes).toString('utf8');
  }
  if (!path.startsWith('b/')) return null;
  path = path.slice(2);
  if (!path || /[\x00-\x1f\x7f\\]/.test(path) || /^[A-Za-z]:/.test(path)
    || path.startsWith('/') || path.split('/').some((part) => part === '..' || part === '.' || part === '')) return null;
  return path;
}

export async function scanHistory(root: string, opts: { budgetMs?: number; maxCommits?: number; git?: GitRunner } = {}): Promise<HistoryScan> {
  const result: HistoryScan = { commits: 0, complete: false, hits: [] };
  const budget = Number.isFinite(opts.budgetMs) ? Math.max(0, opts.budgetMs!) : 20_000;
  const maxCommits = Number.isFinite(opts.maxCommits) ? Math.max(0, Math.floor(opts.maxCommits!)) : 20_000;
  if (budget === 0 || maxCommits === 0) return { ...result, note: 'Git history scan stopped; scanned the last 0 commits.' };
  const controller = new AbortController();
  const deadline = performance.now() + budget;
  const timer = setTimeout(() => controller.abort(), budget);
  let commit: string | undefined;
  let committedAt: string | undefined;
  let path: string | null = null;
  let line = 0;
  let binary = false;
  let accepting = true;
  let multiline: { source: string; line: number } | null = null;
  function unclosedQuote(source: string): boolean {
    const assignment = /^\s*(?:export\s+)?[\w.-]+(?:\s*=\s*?|:\s+?)\s*(['"`])/.exec(source);
    if (!assignment) return false;
    const quote = assignment[1];
    for (let index = assignment[0].length; index < source.length; index++) {
      if (source[index] === '\\' && source[index + 1] === quote) { index++; continue; }
      if (source[index] === quote) return false;
    }
    return true;
  }
  function collect(source: string, startLine: number): void {
    if (!path) return;
    for (const candidate of extractCandidates(source, isDotenvPath(path))) {
      const classification = classifyCandidate(candidate.name, candidate.value);
      if (classification) result.hits.push({ ...classification, ...candidate, kind: 'history', path, line: startLine + candidate.line - 1,
        commit, committedAt, template: isTemplate(path) });
    }
  }
  function onLine(text: string): void {
    if (!accepting || controller.signal.aborted) return;
    if (performance.now() >= deadline) { controller.abort(); return; }
    if (!text.startsWith('+') || text.startsWith('+++')) multiline = null;
    if (text.startsWith('\0')) {
      commit = undefined; committedAt = undefined; path = null; binary = false;
      const header = /^\0([a-fA-F0-9]{40}|[a-fA-F0-9]{64})\0(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2}))$/.exec(text);
      if (!header) return;
      if (result.commits >= maxCommits) { controller.abort(); return; }
      result.commits++;
      commit = header[1]!; committedAt = header[2]!;
      return;
    }
    if (!commit) return;
    if (text.startsWith('diff --git ')) { path = null; binary = false; line = 0; return; }
    if (text.startsWith('+++ ')) { path = gitPath(text.slice(4)); line = 0; return; }
    if (/^(?:Binary files |GIT binary patch)/.test(text)) { binary = true; return; }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(text);
    if (hunk) { line = Number(hunk[1]); return; }
    if (text.startsWith('+') && !text.startsWith('+++')) {
      const currentLine = line++;
      if (!path || binary || text.includes('\0') || Buffer.byteLength(text, 'utf8') > MAX_LINE_BYTES) { multiline = null; return; }
      const added = text.slice(1);
      if (multiline) {
        // Only one incomplete dotenv value is retained, with a 64 KiB ceiling.
        if (Buffer.byteLength(multiline.source, 'utf8') + Buffer.byteLength(added, 'utf8') + 1 > 64 * 1024) { multiline = null; return; }
        multiline.source += `\n${added}`;
        if (!unclosedQuote(multiline.source)) { collect(multiline.source, multiline.line); multiline = null; }
      } else if (isDotenvPath(path) && unclosedQuote(added)) {
        multiline = { source: added, line: currentLine };
      } else {
        collect(added, currentLine);
      }
    } else if (text.startsWith(' ')) line++;
  }
  let removeAbort: () => void = () => undefined;
  try {
    const aborted = new Promise<{ code: number }>((resolve) => {
      const stop = () => resolve({ code: 1 });
      controller.signal.addEventListener('abort', stop, { once: true });
      removeAbort = () => controller.signal.removeEventListener('abort', stop);
    });
    const git = opts.git ?? defaultGitRunner;
    const execution = git(['log', '--all', '-p', '--no-color', '--no-ext-diff', '--no-textconv', '--no-show-signature', '--src-prefix=a/', '--dst-prefix=b/', '-U0', '--diff-filter=AM', '--format=%x00%H%x00%cI'], {
      cwd: root, onLine, signal: controller.signal,
    });
    const { code } = await Promise.race([execution, aborted]);
    result.complete = code === 0 && !controller.signal.aborted;
    if (!result.complete) result.note = controller.signal.aborted
      ? `Git history scan stopped; scanned the last ${result.commits} commits.`
      : `Git history is unavailable or incomplete; scanned ${result.commits} commits.`;
  } catch { result.note = `Git history is unavailable or incomplete; scanned ${result.commits} commits.`; }
  finally { accepting = false; multiline = null; clearTimeout(timer); removeAbort(); }
  return result;
}
