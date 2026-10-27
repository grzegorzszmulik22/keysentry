#!/usr/bin/env node
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const REPOSITORY_ROOT = fileURLToPath(new URL('..', import.meta.url));

const BUILD_ENVIRONMENT_NAMES = new Set([
  'path', 'pathext', 'systemroot', 'windir', 'home', 'userprofile', 'homedrive', 'homepath',
  'appdata', 'localappdata', 'temp', 'tmp', 'tmpdir', 'npm_execpath',
  'keysentry_build_commit', 'keysentry_release_repo', 'tz', 'lang', 'lc_all',
]);

export function buildChildEnvironment(env = process.env) {
  const child = {};
  for (const [name, value] of Object.entries(env)) {
    if (value !== undefined && BUILD_ENVIRONMENT_NAMES.has(name.toLowerCase())) child[name] = value;
  }
  child.SOURCE_DATE_EPOCH = '499162500';
  return child;
}

export async function withBuildEnvironment(env, operation) {
  const originalEnvironment = process.env;
  process.env = buildChildEnvironment(env);
  try {
    return await operation();
  } finally {
    process.env = originalEnvironment;
  }
}

// esbuild preserves an entry module's hashbang before its banner. Keep the
// required banner while making the resulting bundle a valid executable module.
export function normalizeBundleShebang(source) {
  return source.replace(/^(#!\/usr\/bin\/env node\r?\n)(?:#!\/usr\/bin\/env node\r?\n)+/, '$1');
}

export async function buildBundle({ outFile = resolve(REPOSITORY_ROOT, 'dist/keysentry.mjs'), env = process.env } = {}) {
  const pkg = JSON.parse(await readFile(resolve(REPOSITORY_ROOT, 'package.json'), 'utf8'));
  await mkdir(dirname(outFile), { recursive: true });
  const define = {
    __KEYSENTRY_VERSION__: JSON.stringify(pkg.version),
    __KEYSENTRY_COMMIT__: JSON.stringify(env.KEYSENTRY_BUILD_COMMIT || 'dev'),
    __KEYSENTRY_RELEASE_REPO__: JSON.stringify(env.KEYSENTRY_RELEASE_REPO || 'grzenio22/keysentry'),
  };
  // esbuild's JavaScript API starts a service process using process.env. This
  // dedicated build script filters that environment while the service exists.
  await withBuildEnvironment(env, async () => {
    const { build, stop } = await import('esbuild');
    try {
      await build({
        absWorkingDir: REPOSITORY_ROOT,
        entryPoints: ['src/cli/index.ts'],
        outfile: outFile,
        platform: 'node',
        format: 'esm',
        target: 'node22',
        bundle: true,
        minify: false,
        legalComments: 'inline',
        metafile: false,
        banner: {
          js: "#!/usr/bin/env node\nimport { createRequire as __ksCreateRequire } from 'node:module'; const require = __ksCreateRequire(import.meta.url);",
        },
        define,
      });
    } finally {
      await stop();
    }
  });
  const source = await readFile(outFile, 'utf8');
  const normalized = normalizeBundleShebang(source);
  if (source !== normalized) await writeFile(outFile, normalized);
  return outFile;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    await buildBundle();
  } catch {
    console.error('keysentry bundle build failed.');
    process.exitCode = 1;
  }
}
