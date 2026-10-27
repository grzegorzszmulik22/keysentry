import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, test } from 'vitest';
import { signRelease, verifyReleaseArtifacts } from '../../scripts/sign-release.mjs';

const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map(dir => rm(dir, { recursive: true, force: true }))); });

async function fixture(): Promise<{ dir: string; sums: string }> {
  const dir = await mkdtemp(join(tmpdir(), 'keysentry-release-artifacts-'));
  dirs.push(dir);
  const entries = [];
  for (const name of ['keysentry.mjs', 'release-manifest.json', 'keysentry-1.0.0.tgz']) {
    const value = `fixture ${name}\n`;
    await writeFile(join(dir, name), value);
    entries.push(`${createHash('sha256').update(value).digest('hex')}  ${name}\n`);
  }
  const sums = join(dir, 'SHA256SUMS');
  await writeFile(sums, entries.join(''));
  return { dir, sums };
}

test('release artifact verification rehashes every signed artifact without executing it', async () => {
  const { sums } = await fixture();
  await expect(verifyReleaseArtifacts(sums)).resolves.toBe(3);
});

test('a changed build artifact is refused before a signature is written', async () => {
  const { dir, sums } = await fixture();
  await writeFile(join(dir, 'keysentry.mjs'), 'changed artifact');
  const { privateKey } = generateKeyPairSync('ed25519');
  await expect(signRelease(sums, {
    KEYSENTRY_RELEASE_SIGNING_KEY: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
  })).rejects.toThrow(/checksum/);
  await expect(readFile(`${sums}.sig`)).rejects.toMatchObject({ code: 'ENOENT' });
});

test.each(['../outside', '/absolute', 'sub/file', 'sub\\file', 'keysentry.mjs'])('release checksums reject unsafe or duplicate paths (%s)', async name => {
  const { sums } = await fixture();
  await writeFile(sums, `${await readFile(sums, 'utf8')}${'a'.repeat(64)}  ${name}\n`);
  await expect(verifyReleaseArtifacts(sums)).rejects.toThrow(/checksums/);
});

test('release checksums require the bundle, manifest and one tarball', async () => {
  const { sums } = await fixture();
  const content = await readFile(sums, 'utf8');
  await writeFile(sums, content.split('\n').filter(line => !line.endsWith('release-manifest.json')).join('\n'));
  await expect(verifyReleaseArtifacts(sums)).rejects.toThrow(/checksums/);
});

test('release artifact verification refuses symlinks', async () => {
  const { dir, sums } = await fixture();
  const target = join(dir, 'actual-bundle');
  await writeFile(target, 'fixture keysentry.mjs\n');
  await rm(join(dir, 'keysentry.mjs'));
  await symlink(target, join(dir, 'keysentry.mjs'), 'file');
  await expect(verifyReleaseArtifacts(sums)).rejects.toThrow(/regular file/);
});
