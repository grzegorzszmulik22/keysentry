import { afterEach, describe, expect, it, vi } from 'vitest';
import { PassThrough } from 'node:stream';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rootCertificates } from 'node:tls';
import * as prompts from '../../src/cli/prompts.js';
import { RotationAbortedError, type GuidedPrompt } from '../../src/types.js';

const { promptSecret, revealSecret } = prompts;

const prompt: GuidedPrompt = {
  clusterId: 'cluster-one', provider: 'google', hint: null, consumers: [],
  guidance: { url: 'https://console.cloud.google.com/apis/credentials', steps: ['Create a replacement key.'] },
};
const info = { clusterId: 'cluster-one', provider: 'google' as const, hint: null, reason: 'The rolled key could not be written.' };
const dirs: string[] = [];
afterEach(async () => {
  vi.useRealTimers();
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe('vault prompts', () => {
  it.each(['y', 'yes'])('asks before replacing an unreadable inventory and accepts %j', async answer => {
    const t = terminal();
    const result = prompts.confirmInventoryReplacement(t.write, t.io);
    t.stream.write(answer + '\r');
    expect(await result).toBe(true);
    expect(t.diagnostics).toContain("keysentry can't read the saved inventory on this computer. Replace it with a fresh scan? [y/N]");
  });

  it.each(['', 'n', 'yes please', '\x1b[200~yes\x1b[201~'])('declines inventory replacement without a typed yes (%j)', async answer => {
    const t = terminal();
    const result = prompts.confirmInventoryReplacement(t.write, t.io);
    t.stream.write(answer + '\r');
    expect(await result).toBe(false);
  });

  it('requires the full typed word yes when a release manifest is missing', async () => {
    const t = terminal();
    const result = prompts.confirmMissingManifest(t.write, t.io);
    t.stream.write('yes\r');
    expect(await result).toBe(true);
    expect(t.diagnostics.join(' ')).toMatch(/release manifest.*missing/i);
    expect(t.diagnostics.join(' ')).toContain('Type yes');
  });

  it.each(['', 'y', 'YES', ' yes', 'yes ', '\x1b[200~yes\x1b[201~'])('refuses abbreviated or pasted missing-manifest confirmation (%j)', async answer => {
    const t = terminal();
    const result = prompts.confirmMissingManifest(t.write, t.io);
    t.stream.write(answer + '\r');
    expect(await result).toBe(false);
  });

  it.each([['', 'encrypted-file'], ['file', 'encrypted-file'], ['os', 'linux-secret-service']] as const)(
    'chooses %s when both vault stores exist', async (answer, backend) => {
      const t = terminal();
      const result = prompts.promptVaultBackend('linux-secret-service', t.write, t.io);
      t.stream.write(answer + '\r');
      expect(await result).toBe(backend);
      expect(t.diagnostics.join(' ')).toMatch(/encrypted file/i);
      expect(t.diagnostics.join(' ')).toContain('linux-secret-service');
    },
  );

  it.each(['other', '\x1b[200~os\x1b[201~'])('refuses an invalid or pasted vault choice (%j)', async answer => {
    const t = terminal();
    const result = prompts.promptVaultBackend('linux-secret-service', t.write, t.io);
    t.stream.write(answer + '\r');
    await expect(result).rejects.toThrow('Choose file or os.');
  });

  it('does not accept the new confirmations without a terminal', async () => {
    for (const flags of [[false, true], [true, false]]) {
      const t = terminal(...flags);
      expect(await prompts.confirmInventoryReplacement(t.write, t.io)).toBe(false);
      expect(await prompts.confirmMissingManifest(t.write, t.io)).toBe(false);
      expect(await prompts.promptVaultBackend('linux-secret-service', t.write, t.io)).toBe('encrypted-file');
      expect(t.raw).toEqual([]);
    }
  });

  it('reads a credential hidden and never interprets @ as a file', async () => {
    const t = terminal();
    const result = prompts.promptVaultValue('RAILWAY_TOKEN', t.write, t.io);
    t.stream.write('@opaque-vault-value\r');
    expect(await result).toBe('@opaque-vault-value');
    expect(t.output.join('')).not.toContain('@opaque-vault-value');
    expect(t.diagnostics.join('')).not.toContain('@opaque-vault-value');
    expect(t.diagnostics.join('')).toContain('RAILWAY_TOKEN');
    expect(t.raw).toEqual([true, false]);
  });

  it('allows an empty credential prompt to cancel', async () => {
    const t = terminal();
    const result = prompts.promptVaultValue('RAILWAY_TOKEN', t.write, t.io);
    t.stream.write('\r');
    expect(await result).toBeNull();
  });

  it('reads a passphrase into a Buffer without echoing it', async () => {
    const t = terminal();
    const result = prompts.promptPassphrase(t.write, t.io);
    t.stream.write('a long opaque passphrase\r');
    const passphrase = await result;
    expect(Buffer.isBuffer(passphrase)).toBe(true);
    expect(passphrase.toString()).toBe('a long opaque passphrase');
    expect(t.output.join('') + t.diagnostics.join('')).not.toContain('a long opaque passphrase');
    passphrase.fill(0);
  });

  it('refuses an empty passphrase', async () => {
    const t = terminal();
    const result = prompts.promptPassphrase(t.write, t.io);
    t.stream.write('\r');
    await expect(result).rejects.toThrow(/passphrase.*empty/i);
  });

  it('asks the exact fallback question and accepts an explicit y', async () => {
    const t = terminal();
    const result = prompts.confirmVaultFallback('linux-secret-service', 'store unavailable', t.write, t.io);
    t.stream.write('y\r');
    expect(await result).toBe(true);
    expect(t.diagnostics).toContain("keysentry can't use linux-secret-service here (store unavailable). Keep keys in an encrypted file protected by a passphrase instead? [y/N]");
  });

  it.each(['', 'n', 'yes please'])('declines fallback without an explicit yes (%j)', async answer => {
    const t = terminal();
    const result = prompts.confirmVaultFallback('windows-dpapi', 'store unavailable', t.write, t.io);
    t.stream.write(answer + '\r');
    expect(await result).toBe(false);
  });

  it('requires typed RESET before deleting state', async () => {
    const t = terminal();
    const result = prompts.confirmStateReset(t.write, t.io);
    t.stream.write('RESET\r');
    expect(await result).toBe(true);
    expect(t.diagnostics.join('')).toContain('RESET');
  });

  it.each(['reset', ' RESET', 'RESET ', '\x1b[200~RESET\x1b[201~'])('refuses another or pasted reset confirmation (%j)', async answer => {
    const t = terminal();
    const result = prompts.confirmStateReset(t.write, t.io);
    t.stream.write(answer + '\r');
    expect(await result).toBe(false);
  });

  it('does not read hidden values or accept confirmations from a nonterminal', async () => {
    for (const flags of [[false, true], [true, false]]) {
      const t = terminal(...flags);
      await expect(prompts.promptPassphrase(t.write, t.io)).rejects.toThrow(/terminal/i);
      await expect(prompts.promptVaultValue('RAILWAY_TOKEN', t.write, t.io)).rejects.toThrow(/terminal/i);
      expect(await prompts.confirmVaultFallback('windows-dpapi', 'unavailable', t.write, t.io)).toBe(false);
      expect(await prompts.confirmStateReset(t.write, t.io)).toBe(false);
      expect(t.raw).toEqual([]);
    }
  });
});

describe('rotation grace prompt', () => {
  const grace = () => ({ planId: 'plan-one', deadline: new Date(Date.now() + 120_000).toISOString(), clusters: [] });

  it.each([['', 'revoke'], ['u', 'undo'], ['l', 'defer']] as const)('accepts %j as %s', async (answer, decision) => {
    const t = terminal();
    const result = prompts.promptGrace(grace(), t.write, t.io);
    t.stream.write(answer + '\r');
    expect(await result).toBe(decision);
    expect(t.diagnostics.join('\n')).toContain('New keys are live. Old keys stay valid for 2 minutes so you can undo.');
    expect(t.diagnostics.join('\n')).toContain('Enter: revoke now · u: undo · l: later (run "keysentry finish")');
    expect(t.input.listenerCount('data')).toBe(0);
    expect(t.raw).toEqual([true, false]);
  });

  it('shows a countdown and revokes at the deadline without input', async () => {
    vi.useFakeTimers();
    const t = terminal();
    const result = prompts.promptGrace({ ...grace(), deadline: new Date(Date.now() + 2500).toISOString() }, t.write, t.io);
    await vi.advanceTimersByTimeAsync(1000);
    expect(t.diagnostics.join('\n')).toMatch(/0:02/);
    await vi.advanceTimersByTimeAsync(1500);
    expect(await result).toBe('revoke');
    expect(t.input.listenerCount('data')).toBe(0);
    expect(t.raw).toEqual([true, false]);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('revokes directly when the deadline has already passed', async () => {
    const t = terminal();
    expect(await prompts.promptGrace({ ...grace(), deadline: new Date(Date.now() - 1).toISOString() }, t.write, t.io)).toBe('revoke');
    expect(t.raw).toEqual([]);
  });

  it('clears countdown timers and restores the terminal on cancellation', async () => {
    vi.useFakeTimers();
    const t = terminal();
    const result = prompts.promptGrace(grace(), t.write, t.io);
    t.stream.write('\x03');
    await expect(result).rejects.toBeInstanceOf(RotationAbortedError);
    expect(vi.getTimerCount()).toBe(0);
    expect(t.raw).toEqual([true, false]);
  });

  it('does not shorten a grace period that exceeds the Node timer limit', async () => {
    vi.useFakeTimers();
    const t = terminal();
    let settled = false;
    const result = prompts.promptGrace({ ...grace(), deadline: new Date(Date.now() + 40 * 86_400_000).toISOString() }, t.write, t.io);
    void result.then(() => { settled = true; });
    await vi.advanceTimersByTimeAsync(2);
    expect(settled).toBe(false);
    t.stream.write('l\r');
    expect(await result).toBe('defer');
    expect(vi.getTimerCount()).toBe(0);
  });

  it('uses an injected terminal for rotation confirmation', async () => {
    const t = terminal();
    const result = prompts.confirmRotation(2, t.write, t.io);
    t.stream.write('2\r');
    expect(await result).toBe(true);
  });
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

  it('normalizes pasted CRLF across chunk boundaries without echoing', async () => {
    const t = terminal();
    const value = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const pasted = value.replaceAll('\n', '\r\n');
    const firstEol = pasted.indexOf('\r') + 1;
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('\x1b[20');
    t.stream.write('0~' + pasted.slice(0, firstEol));
    t.stream.write(pasted.slice(firstEol) + '\x1b[201');
    t.stream.write('~\r');
    expect((await result) === value).toBe(true);
    expect(t.output.join('').includes(value)).toBe(false);
    expect(t.diagnostics.join('').includes(value)).toBe(false);
    expect(t.output.join('')).toBe('\x1b[?2004h\x1b[?2004l');
    expect(t.raw).toEqual([true, false]);
    expect(t.input.listenerCount('data')).toBe(0);
    expect(t.input.isPaused()).toBe(true);
  });

  it('removes one trailing file newline and suggests deleting the file without echoing its contents', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'keysentry-prompt-')); dirs.push(dir);
    const path = join(dir, 'replacement.json');
    const value = '{\n  "private_key": "opaque-file-value"\n}\n';
    await writeFile(path, value, 'utf8');
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('@' + path + '\r');
    expect((await result) === value.slice(0, -1)).toBe(true);
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
    await expect(result).rejects.toBeInstanceOf(RotationAbortedError);
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
    await expect(result).rejects.toBeInstanceOf(RotationAbortedError);
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

  it('normalizes lone carriage returns in a pasted private key', async () => {
    const t = terminal();
    const value = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('\x1b[200~' + value.replaceAll('\n', '\r') + '\x1b[201~\r');
    expect((await result) === value).toBe(true);
  });

  it('accepts a valid pasted certificate', async () => {
    const t = terminal();
    const value = rootCertificates[0]!;
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('\x1b[200~' + value + '\x1b[201~\r');
    expect((await result) === value).toBe(true);
  });

  it.each([
    '-----BEGIN PRIVATE KEY-----\nopaque-malformed-secret\n-----END PRIVATE KEY-----',
    '-----BEGIN CERTIFICATE-----\nopaque-malformed-secret\n-----END CERTIFICATE-----',
    '{\n"private_key":"opaque-malformed-secret",\n}',
  ])('rejects malformed structured paste without disclosing its value', async value => {
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('\x1b[200~' + value + '\x1b[201~\r');
    const error = await result.catch(error => error as Error);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message.includes('opaque-malformed-secret')).toBe(false);
    expect(t.diagnostics.join('').includes('opaque-malformed-secret')).toBe(false);
    expect(t.output.join('').includes('opaque-malformed-secret')).toBe(false);
  });

  it('rejects multiline input that is not a private key, certificate, or JSON document', async () => {
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('\x1b[200~opaque\nreplacement\x1b[201~\r');
    await expect(result).rejects.toThrow();
    expect(t.diagnostics.join('').includes('opaque')).toBe(false);
  });

  it.each(['\n', '\r\n', ''])('removes exactly one trailing file EOL (%j)', async eol => {
    const dir = await mkdtemp(join(tmpdir(), 'keysentry-prompt-')); dirs.push(dir);
    const path = join(dir, 'replacement.txt');
    const value = 'opaque-file-value';
    await writeFile(path, value + eol, 'utf8');
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('@' + path + '\r');
    expect((await result) === value).toBe(true);
  });

  it('preserves an earlier file newline when removing the final EOL', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'keysentry-prompt-')); dirs.push(dir);
    const path = join(dir, 'replacement.json');
    const value = '{"private_key":"opaque-file-value"}\n';
    await writeFile(path, value + '\r\n', 'utf8');
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('@' + path + '\r');
    expect((await result) === value).toBe(true);
  });

  it('validates structured file contents before accepting them', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'keysentry-prompt-')); dirs.push(dir);
    const path = join(dir, 'replacement.json');
    await writeFile(path, '{\n"private_key":"opaque-malformed-secret",\n}\n', 'utf8');
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('@' + path + '\r');
    await expect(result).rejects.toThrow();
    expect(t.diagnostics.join('').includes('opaque-malformed-secret')).toBe(false);
  });

  it.each(['\x00', '\x01', '\x0b', '\x1f', '\x7f', '\x85', '\x9f'])('rejects a pasted control character (%j)', async control => {
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('\x1b[200~opaque' + control + 'value\x1b[201~\r');
    await expect(result).rejects.toThrow();
    expect(t.diagnostics.join('').includes('opaque')).toBe(false);
  });

  it('rejects controls typed directly rather than silently altering the secret', async () => {
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('opaque\x00value\r');
    await expect(result).rejects.toThrow();
  });

  it('preserves a tab in a single-line value', async () => {
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('opaque\tvalue\r');
    expect((await result) === 'opaque\tvalue').toBe(true);
  });

  it('aborts on standalone Escape and restores the terminal', async () => {
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('\x1b');
    await expect(result).rejects.toBeInstanceOf(RotationAbortedError);
    expect(t.raw).toEqual([true, false]);
    expect(t.input.listenerCount('data')).toBe(0);
  });

  it('does not cancel a paste marker split immediately after Escape', async () => {
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.write('\x1b');
    t.stream.write('[200~opaque-value\x1b[201~\r');
    expect((await result) === 'opaque-value').toBe(true);
  });

  it('does not swallow Ctrl-C following an unfinished escape sequence', async () => {
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.end('\x1b\x03');
    await expect(result).rejects.toBeInstanceOf(RotationAbortedError);
    expect(t.raw).toEqual([true, false]);
  });

  it('does not swallow Escape cancellation followed immediately by Enter', async () => {
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.end('\x1b\r');
    await expect(result).rejects.toBeInstanceOf(RotationAbortedError);
    expect(t.raw).toEqual([true, false]);
  });

  it('allows Escape to cancel an unfinished bracketed paste', async () => {
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    t.stream.end('\x1b[200~opaque-value\x1b');
    await expect(result).rejects.toBeInstanceOf(RotationAbortedError);
    expect(t.raw).toEqual([true, false]);
  });

  it.each(['\x1b\r', '\x1b\n', '\x1b\r\x1b[201~\r', '\x1b\x1b[201~\r'])(
    'aborts Escape inside bracketed paste instead of treating it as invalid secret data (%j)', async cancellation => {
      const t = terminal();
      const result = promptSecret(prompt, t.write, t.io);
      t.stream.end('\x1b[200~opaque-value' + cancellation);
      await expect(result).rejects.toBeInstanceOf(RotationAbortedError);
      expect(t.raw).toEqual([true, false]);
      expect(t.input.listenerCount('data')).toBe(0);
      expect(t.output.join('').includes('opaque-value')).toBe(false);
    },
  );

  it.each([1, 2, 3, 4, 5])('recognizes a paste end marker split after byte %i', async split => {
    const t = terminal();
    const result = promptSecret(prompt, t.write, t.io);
    const end = '\x1b[201~';
    t.stream.write('\x1b[200~opaque-value' + end.slice(0, split));
    t.stream.write(end.slice(split) + '\r');
    expect((await result) === 'opaque-value').toBe(true);
    expect(t.raw).toEqual([true, false]);
  });
});

describe('explicit emergency reveal', () => {
  it('pauses initially unconsumed stdin after revealing so the process can exit', async () => {
    const t = terminal(true, true, false);
    expect(t.input.readableFlowing).toBeNull();
    const result = revealSecret(info, 'new-emergency-value', t.write, t.io);
    t.stream.write('SHOW\r');
    expect(await result).toBe(true);
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
    expect(await result).toBe(true);
    expect(t.output.join('').split(value).length - 1).toBe(1);
    expect(t.diagnostics.join('').includes(value)).toBe(false);
    expect(t.raw).toEqual([true, false]);
  });

  it('refuses case variants and explains the dashboard fallback', async () => {
    const t = terminal();
    const result = revealSecret(info, 'unrevealed-value', t.write, t.io);
    t.stream.write('show\r');
    expect(await result).toBe(false);
    expect(t.output.join('').includes('unrevealed-value')).toBe(false);
    expect(t.diagnostics.join(' ')).toContain('https://console.cloud.google.com');
  });

  it('requires typed confirmation rather than pasted SHOW', async () => {
    const t = terminal();
    const result = revealSecret(info, 'unrevealed-value', t.write, t.io);
    t.stream.write('\x1b[200~SHOW\x1b[201~\r');
    expect(await result).toBe(false);
    expect(t.output.join('').includes('unrevealed-value')).toBe(false);
    expect(t.diagnostics.join(' ')).toMatch(/dashboard/i);
  });

  it('never reveals to redirected output or from noninteractive input', async () => {
    for (const tty of [[false, true], [true, false]]) {
      const t = terminal(tty[0], tty[1]);
      expect(await revealSecret(info, 'unrevealed-value', t.write, t.io)).toBe(false);
      expect(t.output.join('').includes('unrevealed-value')).toBe(false);
      expect(t.diagnostics.join(' ')).toMatch(/dashboard/i);
      expect(t.raw).toEqual([]);
    }
  });

  it('preserves cancellation so the rotation can abort', async () => {
    const t = terminal();
    const result = revealSecret(info, 'unrevealed-value', t.write, t.io);
    t.stream.write('\x03');
    await expect(result).rejects.toBeInstanceOf(RotationAbortedError);
    expect(t.output.join('').includes('unrevealed-value')).toBe(false);
  });

  it('reports a failed terminal write without exposing the value in diagnostics', async () => {
    const t = terminal();
    const output = t.io.output.write;
    t.io.output.write = value => {
      if (value.includes('unrevealed-value')) throw new Error('unrevealed-value');
      return output(value);
    };
    const result = revealSecret(info, 'unrevealed-value', t.write, t.io);
    t.stream.write('SHOW\r');
    expect(await result).toBe(false);
    expect(t.diagnostics.join('').includes('unrevealed-value')).toBe(false);
  });
});

describe('action confirmation', () => {
  it.each([[true, true, true], [false, true, false], [true, false, false]])('requires interactive input and output (%j, %j)', (input, output, expected) => {
    expect(prompts.hasInteractiveTerminal(terminal(input, output).io)).toBe(expected);
  });

  it('requires the exact action id typed by the operator', async () => {
    const t = terminal();
    const result = prompts.confirmAction('action-one', t.write, t.io);
    t.stream.write('action-one\r');
    expect(await result).toBe(true);
    expect(t.diagnostics.join(' ')).toContain('action-one');
  });

  it.each(['other-action', ' action-one', 'action-one '])('refuses a different action id (%j)', async answer => {
    const t = terminal();
    const result = prompts.confirmAction('action-one', t.write, t.io);
    t.stream.write(answer + '\r');
    expect(await result).toBe(false);
  });

  it('refuses a pasted action id', async () => {
    const t = terminal();
    const result = prompts.confirmAction('action-one', t.write, t.io);
    t.stream.write('\x1b[200~action-one\x1b[201~\r');
    expect(await result).toBe(false);
  });

  it('refuses confirmation without a terminal', async () => {
    const t = terminal(false);
    expect(await prompts.confirmAction('action-one', t.write, t.io)).toBe(false);
    expect(t.raw).toEqual([]);
  });

  it('aborts on cancellation before approving an action', async () => {
    const t = terminal();
    const result = prompts.confirmAction('action-one', t.write, t.io);
    t.stream.write('\x03');
    await expect(result).rejects.toBeInstanceOf(RotationAbortedError);
    expect(t.raw).toEqual([true, false]);
  });
});
