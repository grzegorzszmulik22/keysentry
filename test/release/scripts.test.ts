import { createHash, createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, expect, test } from 'vitest';
import { signRelease } from '../../scripts/sign-release.mjs';
import { assertReproducible } from '../../scripts/check-reproducible.mjs';
import { releasePackageManifest, resolveReleaseOutput } from '../../scripts/release-build.mjs';
import { buildChildEnvironment, normalizeBundleShebang, withBuildEnvironment } from '../../scripts/build-bundle.mjs';

const temporaryDirectories: string[] = [];

async function temporaryDirectory(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'keysentry-release-script-'));
  temporaryDirectories.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map(dir => rm(dir, { recursive: true, force: true })));
});

test('bundle keeps one executable shebang when esbuild preserves the entry shebang before the banner', () => {
  const banner = '#!/usr/bin/env node\n';
  expect(normalizeBundleShebang(`${banner}${banner}import "node:crypto";\n`)).toBe(`${banner}import "node:crypto";\n`);
  expect(normalizeBundleShebang(`${banner}import "node:crypto";\n`)).toBe(`${banner}import "node:crypto";\n`);
});

test('build child environments keep OS paths, build metadata and locales without forwarding credentials', () => {
  const child = buildChildEnvironment({
    PATH: '/node/bin', SystemRoot: 'C:\\Windows', HOME: '/home/build', USERPROFILE: 'C:\\Users\\build',
    TEMP: '/tmp/build', npm_execpath: '/node/npm-cli.js', TZ: 'Pacific/Kiritimati', LANG: 'de_DE.UTF-8', LC_ALL: 'de_DE.UTF-8',
    KEYSENTRY_BUILD_COMMIT: 'abc123', KEYSENTRY_RELEASE_REPO: 'example/keysentry', SOURCE_DATE_EPOCH: 'now',
    OPENAI_ADMIN_KEY: 'provider-secret', RAILWAY_TOKEN: 'host-secret', NPM_TOKEN: 'registry-secret',
    NODE_AUTH_TOKEN: 'auth-secret', npm_config_token: 'npm-config-secret', KEYSENTRY_RELEASE_SIGNING_KEY: 'signing-secret',
    UNRELATED: 'unrelated-value', NODE_OPTIONS: '--require /tmp/unreviewed-hook.js',
  });
  expect(child).toEqual({
    PATH: '/node/bin', SystemRoot: 'C:\\Windows', HOME: '/home/build', USERPROFILE: 'C:\\Users\\build',
    TEMP: '/tmp/build', npm_execpath: '/node/npm-cli.js', TZ: 'Pacific/Kiritimati', LANG: 'de_DE.UTF-8', LC_ALL: 'de_DE.UTF-8',
    KEYSENTRY_BUILD_COMMIT: 'abc123', KEYSENTRY_RELEASE_REPO: 'example/keysentry', SOURCE_DATE_EPOCH: '499162500',
  });
});

test('esbuild environment wrapper filters credentials and restores the original environment after success', async () => {
  const original = process.env;
  const result = await withBuildEnvironment({
    PATH: original.PATH, KEYSENTRY_BUILD_COMMIT: 'abc123', OPENAI_ADMIN_KEY: 'provider-secret',
    NPM_TOKEN: 'registry-secret', KEYSENTRY_RELEASE_SIGNING_KEY: 'signing-secret',
  }, async () => {
    expect(process.env.KEYSENTRY_BUILD_COMMIT).toBe('abc123');
    expect(process.env.OPENAI_ADMIN_KEY).toBeUndefined();
    expect(process.env.NPM_TOKEN).toBeUndefined();
    expect(process.env.KEYSENTRY_RELEASE_SIGNING_KEY).toBeUndefined();
    expect(process.env.SOURCE_DATE_EPOCH).toBe('499162500');
    return 'built';
  });
  expect(result).toBe('built');
  expect(process.env).toBe(original);
});

test('esbuild environment wrapper restores the original environment when the build fails', async () => {
  const original = process.env;
  const failure = new Error('build failed');
  await expect(withBuildEnvironment({ PATH: original.PATH, RAILWAY_TOKEN: 'host-secret' }, async () => {
    expect(process.env.RAILWAY_TOKEN).toBeUndefined();
    throw failure;
  })).rejects.toBe(failure);
  expect(process.env).toBe(original);
});

test('sign-release signs exact checksum bytes with the release domain and public-key-derived key id', async () => {
  const dir = await temporaryDirectory();
  const sumsPath = join(dir, 'SHA256SUMS');
  const sums = Buffer.from(`${'a'.repeat(64)}  keysentry.mjs\r\n`, 'utf8');
  await writeFile(sumsPath, sums);
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicDer = publicKey.export({ format: 'der', type: 'spki' });
  const privateDer = privateKey.export({ format: 'der', type: 'pkcs8' });

  await signRelease(sumsPath, { KEYSENTRY_RELEASE_SIGNING_KEY: privateDer.toString('base64') });

  const line = await readFile(`${sumsPath}.sig`, 'utf8');
  const expectedKeyId = createHash('sha256').update(publicDer).digest('hex').slice(0, 16);
  expect(line).toMatch(new RegExp(`^${expectedKeyId} [A-Za-z0-9+/]{86}==\\n$`));
  const signature = Buffer.from(line.trim().split(' ')[1]!, 'base64');
  expect(verify(null, Buffer.concat([Buffer.from('keysentry-release:v1\n'), sums]), publicKey, signature)).toBe(true);
  expect(verify(null, sums, publicKey, signature)).toBe(false);
  expect(verify(null, Buffer.from(`keysentry-release:v1\n${'b'.repeat(64)}  keysentry.mjs\r\n`), publicKey, signature)).toBe(false);
  expect(createPublicKey(privateKey).export({ format: 'der', type: 'spki' })).toEqual(publicDer);
});

test('sign-release requires the signing environment variable and leaves no signature behind', async () => {
  const dir = await temporaryDirectory();
  const path = join(dir, 'SHA256SUMS');
  await writeFile(path, `${'a'.repeat(64)}  keysentry.mjs\n`);
  await expect(signRelease(path, {})).rejects.toThrow(/KEYSENTRY_RELEASE_SIGNING_KEY/);
  await expect(readFile(`${path}.sig`)).rejects.toMatchObject({ code: 'ENOENT' });
});

test.each(['private-material-is-not-base64', Buffer.from('private-material').toString('base64')])(
  'sign-release rejects malformed private material without echoing it (%#)',
  async material => {
    const dir = await temporaryDirectory();
    const path = join(dir, 'SHA256SUMS');
    await writeFile(path, 'checksums\n');
    const error = await signRelease(path, { KEYSENTRY_RELEASE_SIGNING_KEY: material }).catch((error: Error) => error);
    expect(error).toBeInstanceOf(Error);
    expect(error.message).not.toContain(material);
    expect(error.message).not.toContain('private-material');
    await expect(readFile(`${path}.sig`)).rejects.toMatchObject({ code: 'ENOENT' });
  },
);

test('sign-release rejects a non-Ed25519 private key', async () => {
  const dir = await temporaryDirectory();
  const path = join(dir, 'SHA256SUMS');
  await writeFile(path, 'checksums\n');
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const material = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
  await expect(signRelease(path, { KEYSENTRY_RELEASE_SIGNING_KEY: material })).rejects.toThrow(/Ed25519/);
});

test('release output stays in a named directory below dist-release', () => {
  expect(resolveReleaseOutput()).toBe(resolve('dist-release/out'));
  expect(resolveReleaseOutput('nested/out')).toBe(resolve('dist-release/nested/out'));
});

test.each(['', '.', '..', '../outside', resolve('elsewhere')])('release output rejects unsafe clean targets (%s)', name => {
  expect(() => resolveReleaseOutput(name)).toThrow(/dist-release/);
});

test('release package drops source dependencies, hooks and private flag while including provenance repository metadata', () => {
  const result = releasePackageManifest({
    name: 'keysentry', version: '1.0.0', description: 'Rotate keys', private: true,
    dependencies: { unnecessary: '1.0.0' }, devDependencies: { typescript: '5.0.0' },
    scripts: { preinstall: 'do-not-run', postinstall: 'do-not-run' },
    engines: { node: '>=20' },
  }, { KEYSENTRY_RELEASE_REPO: 'example/keysentry' });
  expect(result).toMatchObject({
    name: 'keysentry', version: '1.0.0', license: 'Apache-2.0', type: 'module',
    bin: { keysentry: 'keysentry.mjs' }, engines: { node: '>=22.13' },
    repository: { type: 'git', url: 'git+https://github.com/example/keysentry.git' },
  });
  for (const field of ['dependencies', 'devDependencies', 'scripts', 'private']) expect(result).not.toHaveProperty(field);
  expect(result.files).toEqual(['keysentry.mjs', 'release-manifest.json', 'README.md', 'LICENSE', 'NOTICE']);
});

async function releasePair(): Promise<{ first: string; second: string; root: string }> {
  const root = await temporaryDirectory();
  const first = join(root, 'first');
  const second = join(root, 'second');
  for (const directory of [first, second]) {
    await mkdir(join(directory, 'pkg'), { recursive: true });
    await writeFile(join(directory, 'keysentry.mjs'), '#!/usr/bin/env node\nconsole.log("keysentry");\n');
    await writeFile(join(directory, 'pkg', 'package.json'), '{"name":"keysentry"}\n');
  }
  return { first, second, root };
}

test('reproducibility accepts identical output including nested package files', async () => {
  const { first, second, root } = await releasePair();
  await expect(assertReproducible(first, second, root)).resolves.toBe(2);
});

test('reproducibility rejects any changed nested package bytes', async () => {
  const { first, second, root } = await releasePair();
  await writeFile(join(second, 'pkg', 'package.json'), '{"name":"changed"}\n');
  await expect(assertReproducible(first, second, root)).rejects.toThrow(/pkg\/package.json/);
});

test('reproducibility rejects a missing or extra artifact', async () => {
  const { first, second, root } = await releasePair();
  await writeFile(join(first, 'keysentry-0.1.0.tgz'), 'packed');
  await expect(assertReproducible(first, second, root)).rejects.toThrow(/keysentry-0.1.0.tgz/);
});

test.each(['native', 'slash', 'escaped'])('reproducibility rejects repository path leakage (%s)', async style => {
  const { first, second, root } = await releasePair();
  const absolute = style === 'native' ? root : style === 'slash' ? root.replaceAll('\\', '/') : JSON.stringify(root);
  for (const directory of [first, second]) await writeFile(join(directory, 'keysentry.mjs'), `// source ${absolute}\n`);
  await expect(assertReproducible(first, second, root)).rejects.toThrow(/absolute|repository/i);
});
