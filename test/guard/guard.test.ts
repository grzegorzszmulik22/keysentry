import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { formatGuardStaged, guardStaged, type GitRunner } from '../../src/guard/guard.js';

// Synthetic values only. Each test catches a missed detection, an overbroad
// exception, an incorrect location, or exposure through the public result.
const openai = 'sk-proj-aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY';
const github = 'ghp_zY1xW0vU8tS6rQ4pN2mL9kJ7hG5fE3dB';
const aws = 'aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY2zA4cD6e';
function diff(path: string, added: string[], start = 1): string {
  return ['diff --git a/' + path + ' b/' + path, '--- a/' + path,
    '+++ b/' + path, `@@ -0,0 +${start},${added.length} @@`,
    ...added.map((line) => '+' + line)].join('\n');
}
function gitDiff(source: string, inspect?: (args: string[]) => void): GitRunner {
  return async (args, opts) => {
    inspect?.(args);
    for (const line of source.split('\n')) opts.onLine(line);
    return { code: 0 };
  };
}

describe('staged guard', () => {
  let root: string;
  beforeEach(async () => { root = await mkdtemp(join(tmpdir(), 'keysentry-guard-')); });
  afterEach(async () => { vi.restoreAllMocks(); await rm(root, { recursive: true, force: true }); });

  it('blocks a staged key and passes a clean diff without a network call', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network must not be used.'));
    const result = await guardStaged(root, gitDiff(diff('.env', ['PORT=3000', `OPENAI_API_KEY=${openai}`])));
    expect(result).toEqual({ blocked: [{ path: '.env', line: 2, provider: 'openai', hint: 'sk-proj…W1xY' }] });
    expect(await guardStaged(root, gitDiff(diff('config.json', ['{"PORT": 3000}', 'NODE_ENV=production']))))
      .toEqual({ blocked: [] });
    expect(fetch).not.toHaveBeenCalled();
    expect(JSON.stringify(result)).not.toContain(openai);
  });

  it('uses the index diff and disables external diff and text conversion', async () => {
    let invoked: string[] = [];
    await guardStaged(root, gitDiff('', (args) => { invoked = args; }));
    expect(invoked).toEqual(expect.arrayContaining(['diff', '--cached', '-U0', '--no-color', '--no-ext-diff', '--no-textconv']));
    expect(invoked).not.toContain(openai);
  });

  it('counts new-side lines across deletions and several hunks and ignores removed values', async () => {
    const source = ['diff --git a/.env b/.env', '--- a/.env', '+++ b/.env', '@@ -2,2 +2,1 @@',
      `-OPENAI_API_KEY=${openai}`, '-OLD=1', '+PORT=3000', '@@ -20,0 +20,2 @@',
      '+# comment', `+GITHUB_TOKEN=${github}`].join('\n');
    expect(await guardStaged(root, gitDiff(source))).toEqual({ blocked: [
      { path: '.env', line: 21, provider: 'github', hint: 'ghp_…E3dB' },
    ] });
  });

  it('extracts JSON, YAML, dotenv, source strings and name-dependent credentials', async () => {
    const source = diff('config/settings.json', [
      `{"OPENAI_API_KEY": "${openai}", "GITHUB_TOKEN": "${github}"}`, // two locations on one line
      `  AWS_SECRET_ACCESS_KEY: '${aws}'`,
      `export KEY="${openai}" # ignored comment`,
      `return '${github}';`,
      'STRIPE_SECRET_KEY=pk_test_aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY',
    ]);
    const result = await guardStaged(root, gitDiff(source));
    expect(result.blocked.map(({ line, provider }) => ({ line, provider }))).toEqual([
      { line: 1, provider: 'openai' }, { line: 1, provider: 'github' },
      { line: 2, provider: 'aws' }, { line: 3, provider: 'openai' }, { line: 4, provider: 'github' },
    ]);
    for (const value of [openai, github, aws]) expect(JSON.stringify(result)).not.toContain(value);
  });

  it('allows only the exact value matching the domain-separated allow hash', async () => {
    const hash = createHash('sha256').update('keysentry-allow:v1:' + openai).digest('hex').slice(0, 32);
    await writeFile(join(root, '.keysentry-allow'), `# Fake test key only\nsha256:${hash}\n`);
    const result = await guardStaged(root, gitDiff(diff('.env', [`A=${openai}`, `B=${github}`])));
    expect(result.blocked).toEqual([{ path: '.env', line: 2, provider: 'github', hint: 'ghp_…E3dB' }]);
    expect(await readFile(join(root, '.keysentry-allow'), 'utf8')).not.toContain(openai);
  });

  it('does not accept an ordinary SHA-256 hash or a prefix hash as an exception', async () => {
    const hash = createHash('sha256').update(openai).digest('hex').slice(0, 32);
    await writeFile(join(root, '.keysentry-allow'), `sha256:${hash}\n`);
    expect((await guardStaged(root, gitDiff(diff('.env', [`A=${openai}`])))).blocked).toHaveLength(1);
  });

  it('anchors fixture path globs and gives star, double-star and question their path meanings', async () => {
    await writeFile(join(root, '.keysentry-allow'), 'path:test/fixtures/**/key?.env\npath:test/*.env\n');
    const paths = ['test/fixtures/key1.env', 'test/fixtures/deep/more/key2.env', 'test/a.env',
      'test/deep/a.env', 'src/test/a.env', 'test/fixtures/key12.env', 'production.env'];
    const result = await guardStaged(root, gitDiff(paths.map((path) => diff(path, [`KEY=${openai}`])).join('\n')));
    expect(result.blocked.map(({ path }) => path)).toEqual([
      'test/deep/a.env', 'src/test/a.env', 'test/fixtures/key12.env', 'production.env',
    ]);
  });

  it('rejects malformed allow rules without echoing their contents', async () => {
    await writeFile(join(root, '.keysentry-allow'), `sha256:${openai}\n`);
    await expect(guardStaged(root, gitDiff(diff('.env', [`KEY=${openai}`]))))
      .rejects.toThrow('Unable to read valid .keysentry-allow rules.');
  });

  it('does not follow an allow-file symlink', async (ctx) => {
    const outside = join(root, 'allow-target');
    await writeFile(outside, 'path:**\n');
    try { await symlink(outside, join(root, '.keysentry-allow')); }
    catch (error) {
      if (process.platform === 'win32' && (error as NodeJS.ErrnoException).code === 'EPERM') { ctx.skip(); return; }
      throw error;
    }
    await expect(guardStaged(root, gitDiff(diff('.env', [`KEY=${openai}`]))))
      .rejects.toThrow('Unable to read valid .keysentry-allow rules.');
  });

  it('decodes quoted git paths and cannot confuse added content with a file header', async () => {
    const source = ['diff --git a/one b/one', '--- a/one', '+++ "b/test\\t\\303\\251.env"',
      '@@ -0,0 +5,3 @@', '+++ b/forged.env', '+--- a/forged.env', `+KEY=${openai}`].join('\n');
    expect((await guardStaged(root, gitDiff(source))).blocked[0]).toEqual({
      path: 'test\\té.env', line: 7, provider: 'openai', hint: 'sk-proj…W1xY',
    });
  });

  it('ignores binary changes and does not retain a prior file location', async () => {
    const source = [diff('.env', ['PORT=3000']), 'diff --git a/blob b/blob',
      'Binary files a/blob and b/blob differ', `+KEY=${openai}`].join('\n');
    expect(await guardStaged(root, gitDiff(source))).toEqual({ blocked: [] });
  });

  it('redacts detected values even if a value occurs inside a file path', async () => {
    const result = await guardStaged(root, gitDiff(diff(`config/${openai}.env`, [`KEY=${openai}`])));
    expect(result.blocked).toHaveLength(1);
    expect(JSON.stringify(result)).not.toContain(openai);
  });

  it('blocks complete added PEM private keys and allows an exact fake multiline value', async () => {
    const pem = '-----BEGIN RSA PRIVATE KEY-----\nZmFrZS1wcml2YXRlLW1hdGVyaWFs\n-----END RSA PRIVATE KEY-----';
    const result = await guardStaged(root, gitDiff(diff('certs/key.pem', pem.split('\n'), 4)));
    expect(result.blocked).toEqual([{ path: 'certs/key.pem', line: 4, provider: 'private-key', hint: '…----' }]);
    expect(JSON.stringify(result)).not.toContain('ZmFrZS1wcml2YXRlLW1hdGVyaWFs');
    const hash = createHash('sha256').update('keysentry-allow:v1:' + pem).digest('hex').slice(0, 32);
    await writeFile(join(root, '.keysentry-allow'), `sha256:${hash}\n`);
    expect(await guardStaged(root, gitDiff(diff('certs/key.pem', pem.split('\n'))))).toEqual({ blocked: [] });
  });

  it('refuses a truncated hunk and an oversized line instead of passing an unchecked diff', async () => {
    await expect(guardStaged(root, gitDiff('--- a/.env\n+++ b/.env\n@@ -0,0 +1,2 @@\n+PORT=3')))
      .rejects.toThrow('Unable to check staged changes. The commit was not checked.');
    await expect(guardStaged(root, gitDiff(diff('.env', ['#'.repeat(1024 * 1024 + 1)]))))
      .rejects.toThrow('Unable to check staged changes. The commit was not checked.');
  });

  it('does not hide a name-dependent secret reused under an ordinary name on the same line', async () => {
    const value = 'aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY';
    const result = await guardStaged(root, gitDiff(diff('config.json', [
      `{"LABEL": "${value}", "OPENAI_API_KEY": "${value}"}`,
    ])));
    expect(result.blocked.map(({ provider }) => provider)).toEqual(['openai']);
  });

  it.each([1, 128])('refuses an incomplete diff after git exits with code %s', async (code) => {
    const git: GitRunner = async (_args, opts) => {
      opts.onLine(`+KEY=${openai}`);
      return { code };
    };
    await expect(guardStaged(root, git)).rejects.toThrow('Unable to check staged changes. The commit was not checked.');
  });

  it('replaces git failures containing a secret with a safe error', async () => {
    const git: GitRunner = async () => { throw new Error(openai); };
    const error = await guardStaged(root, git).catch((error: unknown) => error);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe('Unable to check staged changes. The commit was not checked.');
  });

  it('formats the required blocked output and exit status and stays quiet for a clean diff', async () => {
    const result = await guardStaged(root, gitDiff(diff('.env', [`KEY=${openai}`], 9)));
    expect(formatGuardStaged(result)).toEqual({
      output: '.env:9  openai  sk-proj…W1xY\nCommit stopped: 1 secret would be committed. Remove them, or add a test value to .keysentry-allow.\n',
      exitCode: 1,
    });
    expect(formatGuardStaged({ blocked: [] })).toEqual({ output: '', exitCode: 0 });
  });
});
