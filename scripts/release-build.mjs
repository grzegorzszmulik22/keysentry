#!/usr/bin/env node
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { access, copyFile, lstat, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { buildBundle, buildChildEnvironment, REPOSITORY_ROOT } from './build-bundle.mjs';

const execFileAsync = promisify(execFile);
const RELEASE_ROOT = resolve(REPOSITORY_ROOT, 'dist-release');

export function resolveReleaseOutput(outDir = 'out') {
  const output = resolve(RELEASE_ROOT, outDir);
  const rel = relative(RELEASE_ROOT, output);
  if (!outDir || isAbsolute(outDir) || !rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
    throw new Error('Release output must be a named directory inside dist-release.');
  }
  return output;
}

async function checkCleanTarget(output) {
  // A junction/symlink must not turn an otherwise safe lexical path into a
  // recursive removal outside dist-release. Check each existing component.
  const components = relative(REPOSITORY_ROOT, output).split(sep);
  let current = REPOSITORY_ROOT;
  for (const component of components) {
    current = join(current, component);
    try {
      if ((await lstat(current)).isSymbolicLink()) throw new Error('Release output may not contain a symlink or junction.');
    } catch (error) {
      if (error.code === 'ENOENT') return;
      throw error;
    }
  }
}

async function sha256(path) {
  return createHash('sha256').update(await readFile(path)).digest('hex');
}

async function npmCliPath(env) {
  const candidates = [
    env.npm_execpath,
    join(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js'),
    resolve(dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js'),
    resolve(dirname(process.execPath), '../share/nodejs/npm/bin/npm-cli.js'),
  ];
  try {
    const require = createRequire(import.meta.url);
    candidates.push(require.resolve('npm/bin/npm-cli.js'));
  } catch {
    // npm run supplies npm_execpath; the remaining paths cover direct node use.
  }
  for (const candidate of candidates) {
    if (!candidate || !/npm-cli\.js$/.test(candidate)) continue;
    try {
      await access(candidate);
      return candidate;
    } catch {
      // Try the next installed npm location.
    }
  }
  throw new Error('Could not locate npm. Run this build with npm run release:build.');
}

export function releasePackageManifest(pkg, env = process.env) {
  const repository = env.KEYSENTRY_RELEASE_REPO || 'grzenio22/keysentry';
  return {
    name: pkg.name,
    version: pkg.version,
    description: pkg.description,
    license: 'Apache-2.0',
    type: 'module',
    bin: { keysentry: 'keysentry.mjs' },
    engines: { node: '>=22.13' },
    files: ['keysentry.mjs', 'release-manifest.json', 'README.md', 'LICENSE', 'NOTICE'],
    repository: { type: 'git', url: `git+https://github.com/${repository}.git` },
  };
}

export async function releaseBuild(outDir = 'out', env = process.env) {
  const output = resolveReleaseOutput(outDir);
  await checkCleanTarget(output);
  const pkg = JSON.parse(await readFile(resolve(REPOSITORY_ROOT, 'package.json'), 'utf8'));
  await rm(output, { recursive: true, force: true });
  await mkdir(output, { recursive: true });
  const bundlePath = join(output, 'keysentry.mjs');
  await buildBundle({ outFile: bundlePath, env });
  const manifest = {
    name: pkg.name,
    version: pkg.version,
    commit: env.KEYSENTRY_BUILD_COMMIT || 'dev',
    node: process.version,
    files: { 'keysentry.mjs': await sha256(bundlePath) },
  };
  await writeFile(join(output, 'release-manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);

  const packageDirectory = join(output, 'pkg');
  await mkdir(packageDirectory);
  const packageManifest = releasePackageManifest(pkg, env);
  await writeFile(join(packageDirectory, 'package.json'), `${JSON.stringify(packageManifest, null, 2)}\n`);
  for (const filename of ['README.md', 'LICENSE', 'NOTICE']) {
    await copyFile(join(REPOSITORY_ROOT, filename), join(packageDirectory, filename));
  }
  for (const filename of ['keysentry.mjs', 'release-manifest.json']) {
    await copyFile(join(output, filename), join(packageDirectory, filename));
  }

  const childEnv = buildChildEnvironment(env);
  const npmCli = await npmCliPath(childEnv);
  const packed = await execFileAsync(process.execPath, [npmCli, 'pack', '--ignore-scripts', '--offline', '--json', '--pack-destination', output], {
    cwd: packageDirectory,
    env: childEnv,
    maxBuffer: 16 * 1024 * 1024,
  });
  const records = JSON.parse(packed.stdout);
  const tarball = records[0]?.filename;
  if (!tarball || typeof tarball !== 'string' || /[/\\]/.test(tarball)) throw new Error('npm pack did not report a release tarball.');
  const artifacts = ['keysentry.mjs', 'release-manifest.json', tarball].sort();
  const sums = await Promise.all(artifacts.map(async filename => `${await sha256(join(output, filename))}  ${filename}\n`));
  await writeFile(join(output, 'SHA256SUMS'), sums.join(''));
  return output;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    const args = process.argv.slice(2);
    if (args.length > 1) throw new Error('Usage: node scripts/release-build.mjs [output directory name]');
    const output = await releaseBuild(args[0]);
    console.log(`Release artifacts written to ${relative(REPOSITORY_ROOT, output)}.`);
  } catch (error) {
    // Subprocess errors may carry captured output or environment data. Keep the
    // CLI failure bounded to the operation; detailed diagnostics stay local.
    console.error(error.code ? 'keysentry release build failed.' : error.message);
    process.exitCode = 1;
  }
}
