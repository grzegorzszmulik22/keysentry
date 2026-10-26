import { CliError } from './errors.js';
import { emitKeypressEvents, createInterface } from 'node:readline';
import type { GuidedPrompt } from '../types.js';

export async function confirmRotation(count: number, write: (text: string) => void): Promise<boolean> {
  if (!process.stdin.isTTY) { write('Interactive confirmation requires a terminal. Pass --yes after reviewing the dry run.'); return false; }
  const input = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = await new Promise<string>(resolve => input.question(`Type ${count} to rotate ${count} secret cluster(s): `, resolve));
    return answer.trim() === String(count);
  } finally { input.close(); }
}

/** Raw terminal input: no readline echo, history, argv, environment, or temporary file. */
export async function promptSecret(prompt: GuidedPrompt, write: (text: string) => void): Promise<string | null> {
  write(`${prompt.provider}: ${prompt.guidance.url}\n${prompt.guidance.steps.map((step, index) => `${index + 1}. ${step}`).join('\n')}`);
  if (!process.stdin.isTTY || !process.stdin.setRawMode) { write('Guided step skipped: hidden input requires an interactive terminal.'); return null; }
  write('Enter the new value (hidden); press Enter with an empty value to skip.');
  const stdin = process.stdin;
  const previousRaw = stdin.isRaw;
  const wasPaused = stdin.isPaused();
  emitKeypressEvents(stdin);
  stdin.setRawMode(true);
  stdin.resume();
  try {
    return await new Promise<string | null>((resolve, reject) => {
      let value = '';
      const finish = (error?: Error) => {
        stdin.removeListener('keypress', onKey);
        stdin.removeListener('end', onEnd);
        if (error) reject(error); else resolve(value.length ? value : null);
      };
      const onEnd = () => finish(new CliError('Hidden input ended before a value was submitted.'));
      const onKey = (text: string | undefined, key: { name?: string; ctrl?: boolean; meta?: boolean }) => {
        if (key.ctrl && key.name === 'c') { finish(new CliError('Rotation input cancelled.')); return; }
        if (key.ctrl && key.name === 'd') { finish(); return; }
        if (key.name === 'return' || key.name === 'enter') { finish(); return; }
        if (key.name === 'backspace' || key.name === 'delete') { value = Array.from(value).slice(0, -1).join(''); return; }
        if (key.ctrl && key.name === 'u') { value = ''; return; }
        if (!key.ctrl && !key.meta && text && !/[\x00-\x1f\x7f]/.test(text)) value += text;
      };
      stdin.on('keypress', onKey);
      stdin.once('end', onEnd);
    });
  } finally { stdin.setRawMode(previousRaw); if (wasPaused) stdin.pause(); }
}
