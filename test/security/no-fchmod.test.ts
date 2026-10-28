import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { expect, test } from 'vitest';

async function sources(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...await sources(path));
    else if (entry.name.endsWith('.ts')) out.push(path);
  }
  return out;
}

// The Node permission model (used by the release bundle on Node 22.23.4 / 24.22.1 / 26.12.1+) disables fchmod,
// fchown, futimes, fsync and fdatasync on file handles, so such calls make writes fail only in the sandboxed bundle.
// Found by sandboxed container smoke tests (guard install-hook, dotenv rotation, the audit lock, every state write).
// Flushing goes through syncFile() in src/security/durable.ts, which tolerates the sandbox.
test('no source file uses file-handle calls that the Node permission model disables', async () => {
  const offenders: string[] = [];
  for (const path of await sources('src')) {
    const text = await readFile(path, 'utf8');
    if (/\b(?:handle|file|fh|fd|lock|repair|directory)\.(?:chmod|chown|utimes)\(/.test(text)) offenders.push(`${path}: file-handle chmod/chown/utimes`);
    if (/\bf(?:chmod|chown|utimes|sync|datasync)(?:Sync)?\(/.test(text)) offenders.push(`${path}: fd-based call`);
    if (!path.endsWith('durable.ts') && /\.(?:sync|datasync)\(\)/.test(text)) offenders.push(`${path}: flush outside syncFile()`);
  }
  expect(offenders).toEqual([]);
});
