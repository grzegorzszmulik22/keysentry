import { CliError } from './errors.js';
import { createInterface } from 'node:readline';
import { readFile } from 'node:fs/promises';
import { StringDecoder } from 'node:string_decoder';
import type { GuidedPrompt, ProviderId } from '../types.js';
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
      const decoder = new StringDecoder('utf8');
      const finish = (error?: CliError) => {
        if (done) return;
        done = true;
        input.removeListener('data', onData);
        input.removeListener('end', onEnd);
        input.removeListener('error', onError);
        if (error) reject(error); else resolve({ value: value.length ? value : null, pasted });
      };
      const onEnd = () => finish(new CliError('Hidden input ended before a value was submitted.'));
      const onError = () => finish(new CliError('Hidden input could not be read.'));
      const onData = (chunk: Buffer | string) => {
        pending += typeof chunk === 'string' ? chunk : decoder.write(chunk);
        while (pending.length && !done) {
          if (pasting) {
            const end = pending.indexOf(pasteEnd);
            const cancel = pending.indexOf('\x03');
            if (cancel >= 0 && (end < 0 || cancel < end)) { finish(new CliError('Rotation input cancelled.')); return; }
            if (end < 0) {
              // Keep enough tail to recognize an end marker split across stream chunks.
              const complete = Math.max(0, pending.length - pasteEnd.length + 1);
              value += pending.slice(0, complete);
              pending = pending.slice(complete);
              return;
            }
            value += pending.slice(0, end);
            pending = pending.slice(end + pasteEnd.length);
            pasting = false;
            continue;
          }
          if (pending[0] === '\x1b') {
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
          if (character === '\x03') { finish(new CliError('Rotation input cancelled.')); return; }
          if (character === '\x04' || character === '\r' || character === '\n') { finish(); return; }
          if (character === '\x7f' || character === '\b') { value = Array.from(value).slice(0, -1).join(''); continue; }
          if (character === '\x15') { value = ''; continue; }
          if (character.codePointAt(0)! >= 0x20) value += character;
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

/** Hidden input stays in memory; @file contents are read without printing the value or path. */
export async function promptSecret(prompt: GuidedPrompt, write: (text: string) => void, io: PromptIO = {}): Promise<string | null> {
  write(`${prompt.provider}: ${prompt.guidance.url}\n${prompt.guidance.steps.map((step, index) => `${index + 1}. ${step}`).join('\n')}`);
  const tty = terminal(io);
  if (!tty) { write('Guided step skipped: hidden input requires an interactive terminal.'); return null; }
  write('Enter the new value (hidden), paste a multi-line value with bracketed paste, or type @<path> to read a file. Press Enter with an empty value to skip.');
  const { value, pasted } = await readHidden(tty);
  if (value === null || pasted || !value.startsWith('@')) return value;
  try {
    const contents = await readFile(value.slice(1), 'utf8');
    write('Replacement value loaded. Delete the input file after the rotation to remove the extra secret copy.');
    return contents.length ? contents : null;
  } catch { throw new CliError('Could not read the replacement value file.'); }
}

export interface RevealInfo { clusterId: string; provider: ProviderId; hint: string | null; reason: string }

/** The sole intentional plaintext output path: a local human must explicitly opt in on a TTY. */
export async function revealSecret(info: RevealInfo, value: string, write: (text: string) => void, io: PromptIO = {}): Promise<void> {
  const fallback = () => write(`Find or replace the key in the provider dashboard: ${getProvider(info.provider).guidance().url}`);
  const tty = terminal(io);
  if (!tty) { fallback(); return; }
  write(`WARNING: displaying the replacement secret exposes it in terminal scrollback. ${info.reason}\nType SHOW and press Enter to display it once; any other answer keeps it hidden.`);
  try {
    const answer = await readHidden(tty);
    if (answer.value !== 'SHOW' || answer.pasted || !tty.input.isTTY || !tty.output.isTTY) { fallback(); return; }
    tty.output.write(`\n${value}\n`);
  } catch { fallback(); }
}
