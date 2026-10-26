import { CliError } from './errors.js';
import { createInterface } from 'node:readline';
import { createPrivateKey, X509Certificate } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { StringDecoder } from 'node:string_decoder';
import { RotationAbortedError, type GuidedPrompt, type ProviderId } from '../types.js';
import { getProvider } from '../providers/index.js';

/** Separate the terminal from diagnostics so an explicit reveal never reaches a log sink. */
export interface PromptIO {
  input?: NodeJS.ReadStream;
  output?: { isTTY?: boolean; write(value: string): unknown };
}

const pasteStart = '\x1b[200~';
const pasteEnd = '\x1b[201~';

function terminal(io: PromptIO) {
  const input = io.input ?? process.stdin;
  const output = io.output ?? process.stderr;
  return input.isTTY && typeof input.setRawMode === 'function' && output.isTTY ? { input, output } : null;
}

export function hasInteractiveTerminal(io: PromptIO = {}): boolean {
  return terminal(io) !== null;
}

/** Read raw data rather than keypresses: newlines inside bracketed paste are part of the value. */
async function readHidden(io: NonNullable<ReturnType<typeof terminal>>): Promise<{ value: string | null; pasted: boolean }> {
  const { input, output } = io;
  const previousRaw = input.isRaw === true;
  const wasFlowing = input.readableFlowing === true;
  try {
    input.setRawMode(true);
    output.write('\x1b[?2004h');
    return await new Promise((resolve, reject) => {
      let value = '';
      let pending = '';
      let pasting = false;
      let pasted = false;
      let done = false;
      let escapeTimer: ReturnType<typeof setTimeout> | undefined;
      const decoder = new StringDecoder('utf8');
      const finish = (error?: Error) => {
        if (done) return;
        done = true;
        clearTimeout(escapeTimer);
        input.removeListener('data', onData);
        input.removeListener('end', onEnd);
        input.removeListener('error', onError);
        if (error) reject(error);
        else {
          // Normalize after collection so a CRLF split across chunks remains one newline.
          const submitted = pasted ? value.replace(/\r\n?/g, '\n') : value;
          resolve({ value: submitted.length ? submitted : null, pasted });
        }
      };
      const onEnd = () => finish(pending.endsWith('\x1b')
        ? new RotationAbortedError()
        : new CliError('Hidden input ended before a value was submitted.'));
      const onError = () => finish(new CliError('Hidden input could not be read.'));
      const onData = (chunk: Buffer | string) => {
        clearTimeout(escapeTimer);
        pending += typeof chunk === 'string' ? chunk : decoder.write(chunk);
        // Cancellation must not be swallowed as part of an incomplete escape sequence.
        if (pending.includes('\x03')) { finish(new RotationAbortedError()); return; }
        while (pending.length && !done) {
          if (pasting) {
            const escape = pending.indexOf('\x1b');
            if (escape < 0) {
              value += pending;
              pending = '';
              return;
            }
            value += pending.slice(0, escape);
            pending = pending.slice(escape);
            if (!pending.startsWith(pasteEnd)) {
              // A split paste-end marker may continue in the next chunk; any other Escape cancels.
              if (pasteEnd.startsWith(pending)) escapeTimer = setTimeout(() => finish(new RotationAbortedError()), 100);
              else finish(new RotationAbortedError());
              return;
            }
            pending = pending.slice(pasteEnd.length);
            pasting = false;
            continue;
          }
          if (pending[0] === '\x1b') {
            // Escape also prefixes paste and cursor keys; allow their next chunk to arrive.
            if (pending === '\x1b') {
              escapeTimer = setTimeout(() => finish(new RotationAbortedError()), 100);
              return;
            }
            if (pending[1] === '\r' || pending[1] === '\n') { finish(new RotationAbortedError()); return; }
            if (pending.length < pasteStart.length && pasteStart.startsWith(pending)) return;
            if (pending.startsWith(pasteStart)) {
              pasted = pasting = true;
              pending = pending.slice(pasteStart.length);
              continue;
            }
            // Ignore cursor/function/meta keys without inserting their escape sequences.
            const escape = /^\x1b\[[0-?]*[ -/]*[@-~]/.exec(pending);
            if (escape) { pending = pending.slice(escape[0].length); continue; }
            if (pending === '\x1b' || /^\x1b\[[0-?]*[ -/]*$/.test(pending)) return;
            pending = pending.slice(2);
            continue;
          }
          const character = String.fromCodePoint(pending.codePointAt(0)!);
          pending = pending.slice(character.length);
          if (character === '\x04' || character === '\r' || character === '\n') { finish(); return; }
          if (character === '\x7f' || character === '\b') { value = Array.from(value).slice(0, -1).join(''); continue; }
          if (character === '\x15') { value = ''; continue; }
          value += character;
        }
      };
      input.on('data', onData);
      input.once('end', onEnd);
      input.once('error', onError);
      input.resume();
    });
  } finally {
    try { output.write('\x1b[?2004l'); }
    finally { input.setRawMode(previousRaw); if (!wasFlowing) input.pause(); }
  }
}

export async function confirmRotation(count: number, write: (text: string) => void): Promise<boolean> {
  if (!process.stdin.isTTY) { write('Interactive confirmation requires a terminal. Pass --yes after reviewing the dry run.'); return false; }
  const input = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = await new Promise<string>(resolve => input.question(`Type ${count} to rotate ${count} secret cluster(s): `, resolve));
    return answer.trim() === String(count);
  } finally { input.close(); }
}

/** Pending actions need their exact id typed locally before they can change credentials. */
export async function confirmAction(id: string, write: (text: string) => void, io: PromptIO = {}): Promise<boolean> {
  const tty = terminal(io);
  if (!tty) { write('Interactive action confirmation requires a terminal.'); return false; }
  write(`Type ${id} and press Enter to approve this action: `);
  const answer = await readHidden(tty);
  return answer.value === id && !answer.pasted && hasInteractiveTerminal(io);
}

function validateValue(value: string | null): string | null {
  if (value === null || value.length === 0) return null;
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/.test(value) || /\r(?!\n)/.test(value)) {
    throw new CliError('Replacement value contains unsupported control characters.');
  }
  const start = value.trimStart();
  try {
    if (/^-----BEGIN [^-\r\n]*PRIVATE KEY-----/.test(start)) createPrivateKey(value);
    else if (/^-----BEGIN (?:TRUSTED )?CERTIFICATE-----/.test(start)) new X509Certificate(value);
    else if (/^[{\[]/.test(start)) JSON.parse(value);
    else if (value.includes('\n')) throw new Error('Unsupported multi-line value.');
  } catch { throw new CliError('Replacement value is not a valid private key, certificate, or JSON document.'); }
  return value;
}

/** Hidden input stays in memory; @file contents are read without printing the value or path. */
export async function promptSecret(prompt: GuidedPrompt, write: (text: string) => void, io: PromptIO = {}): Promise<string | null> {
  write(`${prompt.provider}: ${prompt.guidance.url}\n${prompt.guidance.steps.map((step, index) => `${index + 1}. ${step}`).join('\n')}`);
  const tty = terminal(io);
  if (!tty) { write('Guided step skipped: hidden input requires an interactive terminal.'); return null; }
  write('Enter the new value (hidden), paste a multi-line value with bracketed paste, or type @<path> to read a file. Press Enter with an empty value to skip.');
  const { value, pasted } = await readHidden(tty);
  if (value === null || pasted || !value.startsWith('@')) return validateValue(value);
  let contents: string;
  try {
    contents = await readFile(value.slice(1), 'utf8');
  } catch { throw new CliError('Could not read the replacement value file.'); }
  const replacement = validateValue(contents.replace(/(?:\r\n|\n)$/, ''));
  write('Replacement value loaded. Delete the input file after the rotation to remove the extra secret copy.');
  return replacement;
}

export interface RevealInfo { clusterId: string; provider: ProviderId; hint: string | null; reason: string }

/** The sole intentional plaintext output path: a local human must explicitly opt in on a TTY. */
export async function revealSecret(info: RevealInfo, value: string, write: (text: string) => void, io: PromptIO = {}): Promise<boolean> {
  const fallback = () => {
    write(`Find or replace the key in the provider dashboard: ${getProvider(info.provider).guidance().url}`);
    return false;
  };
  const tty = terminal(io);
  if (!tty) return fallback();
  write(`WARNING: displaying the replacement secret exposes it in terminal scrollback. ${info.reason}\nType SHOW and press Enter to display it once; any other answer keeps it hidden. Ctrl-C declines this reveal and stops new rotations; remaining replacements will still be offered and staged services deployed.`);
  try {
    const answer = await readHidden(tty);
    if (answer.value !== 'SHOW' || answer.pasted || !tty.input.isTTY || !tty.output.isTTY) return fallback();
    tty.output.write(`\n${value}\n`);
    return true;
  } catch (error) {
    if (error instanceof RotationAbortedError) throw error;
    return fallback();
  }
}
