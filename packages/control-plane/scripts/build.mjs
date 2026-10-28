#!/usr/bin/env node
// Builds the hosted control plane into one ES module for Dockerfile.control-plane: packages/control-plane/src/main.ts
// and the shared modules it imports, checked against scripts/bundle-policy.mjs. Refuses out-of-date page assets.
// usage: node packages/control-plane/scripts/build.mjs [--out <file>]   (default dist-control-plane/control-plane.mjs)
import { mkdir, readFile, rm } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { bundleViolations } from './bundle-policy.mjs';
import { buildControlPlaneUi, UI_OUT } from './build-ui.mjs';

export const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
export const ENTRY = 'packages/control-plane/src/main.ts';

export async function buildControlPlane({ outFile = resolve(REPOSITORY_ROOT, 'dist-control-plane', 'control-plane.mjs') } = {}) {
  const assets = (await readFile(UI_OUT, 'utf8').catch(() => '')).replace(/\r\n/g, '\n');
  if (assets !== await buildControlPlaneUi()) {
    throw new Error('packages/control-plane/src/ui-assets.ts is out of date. Run: node packages/control-plane/scripts/build-ui.mjs');
  }
  await mkdir(dirname(outFile), { recursive: true });
  const { build, stop } = await import('esbuild');
  try {
    const result = await build({
      absWorkingDir: REPOSITORY_ROOT,
      entryPoints: [ENTRY],
      outfile: outFile,
      platform: 'node',
      format: 'esm',
      target: 'node22',
      bundle: true,
      minify: false,
      legalComments: 'inline',
      metafile: true,
      logLevel: 'error',
      banner: { js: "import { createRequire as __ksCreateRequire } from 'node:module'; const require = __ksCreateRequire(import.meta.url);" },
    });
    const violations = bundleViolations(Object.keys(result.metafile.inputs));
    if (violations.length) {
      await rm(outFile, { force: true });
      throw new Error(`The control-plane bundle would include modules outside its policy: ${violations.join(', ')}`);
    }
    return { outFile, inputs: Object.keys(result.metafile.inputs).sort() };
  } finally {
    await stop();
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const index = process.argv.indexOf('--out');
  try {
    const { outFile } = await buildControlPlane(index > 0 && process.argv[index + 1] ? { outFile: resolve(process.argv[index + 1]) } : {});
    console.log(`Built ${outFile}`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'The control-plane build failed.');
    process.exitCode = 1;
  }
}
