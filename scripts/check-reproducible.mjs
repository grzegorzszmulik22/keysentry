#!/usr/bin/env node
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { buildChildEnvironment, REPOSITORY_ROOT } from './build-bundle.mjs';
import { resolveReleaseOutput } from './release-build.mjs';

const execFileAsync = promisify(execFile);

async function directoryHashes(root, subdirectory = '') {
  const hashes = new Map();
  const directory = join(root, subdirectory);
  const entries = (await readdir(directory, { withFileTypes: true })).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  for (const entry of entries) {
    const name = subdirectory ? `${subdirectory}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      for (const [path, hash] of await directoryHashes(root, name)) hashes.set(path, hash);
    } else if (entry.isFile()) {
      hashes.set(name, createHash('sha256').update(await readFile(join(root, name))).digest('hex'));
    } else {
      throw new Error(`Release output contains a non-regular artifact: ${name}`);
    }
  }
  return hashes;
}

async function assertNoRepositoryPath(directory, repositoryRoot) {
  const bundle = await readFile(join(directory, 'keysentry.mjs'), 'utf8');
  // Cover native Windows paths, JSON-escaped backslashes and POSIX paths.
  const normalizedBundle = bundle.replaceAll('\\\\', '\\').replaceAll('\\', '/').toLowerCase();
  const normalizedRoot = resolve(repositoryRoot).replaceAll('\\', '/').replace(/\/$/, '').toLowerCase();
  if (normalizedBundle.includes(normalizedRoot)) throw new Error('Release bundle contains the absolute repository path.');
}

export async function assertReproducible(firstDirectory, secondDirectory, repositoryRoot = REPOSITORY_ROOT) {
  await Promise.all([assertNoRepositoryPath(firstDirectory, repositoryRoot), assertNoRepositoryPath(secondDirectory, repositoryRoot)]);
  const [first, second] = await Promise.all([directoryHashes(firstDirectory), directoryHashes(secondDirectory)]);
  const allPaths = [...new Set([...first.keys(), ...second.keys()])].sort();
  const changed = allPaths.filter(path => first.get(path) !== second.get(path));
  if (changed.length) throw new Error(`Release files differ between builds: ${changed.join(', ')}`);
  return allPaths.length;
}

async function checkReproducible() {
  const builds = [
    { directory: 'repro-a', TZ: 'UTC', LANG: 'C' },
    { directory: 'repro-b', TZ: 'Pacific/Kiritimati', LANG: 'de_DE.UTF-8' },
  ];
  for (const build of builds) {
    const env = buildChildEnvironment({ ...process.env, TZ: build.TZ, LANG: build.LANG });
    await execFileAsync(process.execPath, [join(REPOSITORY_ROOT, 'scripts/release-build.mjs'), build.directory], {
      cwd: REPOSITORY_ROOT,
      env,
      maxBuffer: 16 * 1024 * 1024,
    });
  }
  const first = resolveReleaseOutput(builds[0].directory);
  const second = resolveReleaseOutput(builds[1].directory);
  const count = await assertReproducible(first, second);
  console.log(`Reproducible: ${count} files match in ${relative(REPOSITORY_ROOT, first)} and ${relative(REPOSITORY_ROOT, second)}.`);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    await checkReproducible();
  } catch (error) {
    console.error(error.code ? 'keysentry reproducibility check failed.' : error.message);
    process.exitCode = 1;
  }
}
