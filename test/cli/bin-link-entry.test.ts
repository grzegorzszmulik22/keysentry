import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, test } from 'vitest';
import { isExecutableEntry } from '../../src/cli/index.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });

// npm's POSIX bin link and the Windows junction reproduction from the review probe.
// The full bundled subprocess scenario is also exercised by the POSIX package CI job.
test('the CLI entry guard recognizes an npm-style link to its actual module', async () => {
  const root = await mkdtemp(join(tmpdir(), 'keysentry-bin-link-')); dirs.push(root);
  const real = join(root, 'lib', 'keysentry'); await mkdir(real, { recursive: true });
  const bundle = join(real, 'keysentry.mjs'); await writeFile(bundle, '// CLI module');
  let linked: string;
  if (process.platform === 'win32') {
    await symlink(real, join(root, 'linked'), 'junction'); linked = join(root, 'linked', 'keysentry.mjs');
  } else {
    await mkdir(join(root, 'bin')); linked = join(root, 'bin', 'keysentry'); await symlink(bundle, linked);
  }
  expect(isExecutableEntry(linked, bundle)).toBe(true);
  expect(isExecutableEntry(join(root, 'unrelated.mjs'), bundle)).toBe(false);
});

test('entry resolution failures run only recognized keysentry basenames', () => {
  expect(isExecutableEntry('/missing/keysentry', '/module/keysentry.mjs')).toBe(true);
  expect(isExecutableEntry('/missing/keysentry.mjs', '/module/keysentry.mjs')).toBe(true);
  expect(isExecutableEntry('/missing/test.mjs', '/module/keysentry.mjs')).toBe(false);
});
