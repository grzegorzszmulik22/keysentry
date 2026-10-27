import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, test } from 'vitest';
// @ts-expect-error -- plain .mjs build script without type declarations
import { buildUiAssets } from '../../scripts/build-ui.mjs';

const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map(dir => rm(dir, { recursive: true, force: true }))); });

async function client(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ks-ui-')); dirs.push(dir);
  await mkdir(join(dir, 'screens'));
  await writeFile(join(dir, 'main.ts'), "import { show } from './screens/home.js';\nconst n: number = 1;\nshow(n);\n");
  await writeFile(join(dir, 'screens', 'home.ts'), 'export function show(n: number): void { document.title = String(n); }\r\n');
  await writeFile(join(dir, 'styles.css'), ':root { --ink: #1B2533; }\r\n');
  await writeFile(join(dir, 'index.html'), '<!doctype html><script type="module" src="/app/main.js"></script>\n');
  await writeFile(join(dir, 'notes.txt'), 'ignored');
  return dir;
}

test('build-ui transpiles TypeScript, keeps CSS and HTML, and is deterministic', async () => {
  const dir = await client();
  const first = await buildUiAssets(dir);
  const second = await buildUiAssets(dir);
  expect(first).toBe(second);
  expect(first).toContain('"/app/main.js"');
  expect(first).toContain('"/app/screens/home.js"');
  expect(first).toContain('"/app/styles.css"');
  expect(first).toContain('"/":');
  expect(first).not.toContain('notes.txt');
  expect(first).not.toContain(': number');
  expect(first).not.toContain('\r\n');
});
