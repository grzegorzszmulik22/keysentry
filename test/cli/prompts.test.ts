import { afterEach, describe, expect, it } from 'vitest';
import { PassThrough } from 'node:stream';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promptSecret, revealSecret } from '../../src/cli/prompts.js';
import type { GuidedPrompt } from '../../src/types.js';

const prompt: GuidedPrompt = {
  clusterId: 'cluster-one', provider: 'google', hint: null, consumers: [],
  guidance: { url: 'https://console.cloud.google.com/apis/credentials', steps: ['Create a replacement key.'] },
};
const info = { clusterId: 'cluster-one', provider: 'google' as const, hint: null, reason: 'The rolled key could not be written.' };
const dirs: string[] = [];
afterEach(async () => {
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

function terminal(inputTty = true, outputTty = true, initiallyPaused = true) {
  const stream = new PassThrough();
  if (initiallyPaused) stream.pause();
  const raw: boolean[] = [];
  const input = Object.assign(stream, {
    isTTY: inputTty, isRaw: false,
    setRawMode(mode: boolean) { this.isRaw = mode; raw.push(mode); return this; },
  }) as unknown as NodeJS.ReadStream;
  const output: string[] = [];
  const diagnostics: string[] = [];
  const io = { input, output: { isTTY: outputTty, write: (value: string) => { output.push(value); return true; } } };
  return { stream, input, io, raw, output, diagnostics, write: (value: string) => diagnostics.push(value) };
}

describe('hidden guided input', () => {
  it('pauses initially unconsumed stdin after a hidden prompt so the process can exit', async () => {
    const t = terminal(true, true, false);
    expect(t.input.readableFlowing).toBeNull();
    expect(t.input.isPaused()).toBe(false);
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('opaque-value\r');
    expect((await result) === 'opaque-value').toBe(true);
    expect(t.input.readableFlowing).toBe(false);
    expect(t.input.listenerCount('data')).toBe(0);
    expect(t.raw).toEqual([true, false]);
  });

  it('preserves multiline bracketed paste across chunk boundaries without echoing', async () => {
    const t = terminal();
    const value = '-----BEGIN PRIVATE KEY-----\r\nopaque key body\n-----END PRIVATE KEY-----\n';
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('\x1b[20');
    t.stream.write('0~' + value.slice(0, 35));
    t.stream.write(value.slice(35) + '\x1b[201');
    t.stream.write('~\r');
    expect((await result) === value).toBe(true);
    expect(t.output.join('').includes(value)).toBe(false);
    expect(t.diagnostics.join('').includes(value)).toBe(false);
    expect(t.output.join('')).toBe('\x1b[?2004h\x1b[?2004l');
    expect(t.raw).toEqual([true, false]);
    expect(t.input.listenerCount('data')).toBe(0);
    expect(t.input.isPaused()).toBe(true);
  });

  it('loads all bytes of an @file and suggests deleting the file without echoing its contents', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'keysentry-prompt-')); dirs.push(dir);
    const path = join(dir, 'replacement.json');
    const value = '{\n  "private_key": "opaque-file-value"\n}\n';
    await writeFile(path, value, 'utf8');
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('@' + path + '\r');
    expect((await result) === value).toBe(true);
    expect(t.diagnostics.join(' ')).toMatch(/delet.*file/i);
    expect(t.output.join('').includes(value)).toBe(false);
    expect(t.diagnostics.join('').includes(value)).toBe(false);
  });

  it('does not mistake a bracketed secret beginning with @ for a file path', async () => {
    const t = terminal();
    const value = '@this-is-a-secret-value';
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('\x1b[200~' + value + '\x1b[201~\r');
    expect((await result) === value).toBe(true);
  });

  it('rejects an unreadable file without including the hidden path', async () => {
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('@missing-private-value-file\r');
    await expect(result).rejects.toThrow('Could not read the replacement value file.');
    expect(t.diagnostics.join(' ').includes('missing-private-value-file')).toBe(false);
    expect(t.raw).toEqual([true, false]);
  });

  it('restores raw mode and disables paste on cancellation', async () => {
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('\x03');
    await expect(result).rejects.toThrow('Rotation input cancelled.');
    expect(t.raw).toEqual([true, false]);
    expect(t.output.join('')).toBe('\x1b[?2004h\x1b[?2004l');
    expect(t.input.listenerCount('data')).toBe(0);
  });

  it('rejects an unfinished paste instead of accepting a truncated value', async () => {
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.end('\x1b[200~first line\nsecond line');
    await expect(result).rejects.toThrow('Hidden input ended before a value was submitted.');
    expect(t.raw).toEqual([true, false]);
  });

  it('allows cancellation before an unfinished paste closes', async () => {
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.end('\x1b[200~first line\nsecond line\x03');
    await expect(result).rejects.toThrow('Rotation input cancelled.');
    expect(t.raw).toEqual([true, false]);
  });

  it('handles split UTF-8, editing keys, and an initially raw flowing input', async () => {
    const t = terminal();
    t.input.isRaw = true;
    t.input.resume();
    const result = promptSecret(prompt, t.write, t.io);
    const value = Buffer.from('opaque-\u{1f511}');
    t.stream.write(value.subarray(0, value.length - 2));
    t.stream.write(value.subarray(value.length - 2));
    t.stream.write('\x1b[D\x7fvalue\r');
    expect((await result) === 'opaque-value').toBe(true);
    expect(t.raw).toEqual([true, true]);
    expect(t.input.isPaused()).toBe(false);
  });

  it('skips hidden input when either surface is not a terminal', async () => {
    for (const tty of [[false, true], [true, false]]) {
      const t = terminal(tty[0], tty[1]);
      expect(await promptSecret(prompt, t.write, t.io)).toBeNull();
      expect(t.raw).toEqual([]);
    }
  });
});

describe('explicit emergency reveal', () => {
  it('pauses initially unconsumed stdin after revealing so the process can exit', async () => {
    const t = terminal(true, true, false);
    expect(t.input.readableFlowing).toBeNull();
    const result = revealSecret(info, 'new-emergency-value', t.write, t.io);
    t.stream.write('SHOW\r');
    await result;
    expect(t.input.readableFlowing).toBe(false);
    expect(t.input.listenerCount('data')).toBe(0);
    expect(t.raw).toEqual([true, false]);
  });

  it('writes the value once to the terminal only after exact SHOW and keeps it out of diagnostics', async () => {
    const t = terminal();
    const value = 'new-emergency-value';
    const result = revealSecret(info, value, t.write, t.io);
    expect(t.output.join('').includes(value)).toBe(false);
    expect(t.diagnostics.join(' ')).toMatch(/warning/i);
    t.stream.write('SHOW\r');
    await result;
    expect(t.output.join('').split(value).length - 1).toBe(1);
    expect(t.diagnostics.join('').includes(value)).toBe(false);
    expect(t.raw).toEqual([true, false]);
  });

  it('refuses case variants and explains the dashboard fallback', async () => {
    const t = terminal();
    const result = revealSecret(info, 'unrevealed-value', t.write, t.io);
    t.stream.write('show\r');
    await result;
    expect(t.output.join('').includes('unrevealed-value')).toBe(false);
    expect(t.diagnostics.join(' ')).toContain('https://console.cloud.google.com');
  });

  it('requires typed confirmation rather than pasted SHOW', async () => {
    const t = terminal();
    const result = revealSecret(info, 'unrevealed-value', t.write, t.io);
    t.stream.write('\x1b[200~SHOW\x1b[201~\r');
    await result;
    expect(t.output.join('').includes('unrevealed-value')).toBe(false);
    expect(t.diagnostics.join(' ')).toMatch(/dashboard/i);
  });

  it('never reveals to redirected output or from noninteractive input', async () => {
    for (const tty of [[false, true], [true, false]]) {
      const t = terminal(tty[0], tty[1]);
      await revealSecret(info, 'unrevealed-value', t.write, t.io);
      expect(t.output.join('').includes('unrevealed-value')).toBe(false);
      expect(t.diagnostics.join(' ')).toMatch(/dashboard/i);
      expect(t.raw).toEqual([]);
    }
  });
});
