import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export async function computeSha256File(path: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest('hex');
}

export interface LocalIntegrityResult {
  status: 'ok' | 'mismatch' | 'dev' | 'missing-manifest';
  expected?: string;
  actual?: string;
}

/** Local consistency only: an adjacent manifest is not a publisher signature. */
export async function checkLocalIntegrity(opts: { bundlePath?: string | null } = {}): Promise<LocalIntegrityResult> {
  let bundlePath = opts.bundlePath;
  if (bundlePath === undefined) {
    const entry = fileURLToPath(import.meta.url);
    bundlePath = basename(entry) === 'keysentry.mjs' ? entry : null;
  }
  if (bundlePath === null) return { status: 'dev' };

  let manifest: unknown;
  try {
    manifest = JSON.parse(await readFile(join(dirname(resolve(bundlePath)), 'release-manifest.json'), 'utf8'));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { status: 'missing-manifest' };
    return { status: 'mismatch' };
  }
  const files = manifest && typeof manifest === 'object' && 'files' in manifest ? manifest.files : undefined;
  const expected = files && typeof files === 'object' && 'keysentry.mjs' in files ? files['keysentry.mjs'] : undefined;
  if (typeof expected !== 'string' || !/^[a-f0-9]{64}$/.test(expected)) return { status: 'mismatch' };
  let actual: string;
  try {
    actual = await computeSha256File(resolve(bundlePath));
  } catch {
    return { status: 'mismatch', expected };
  }
  return { status: actual === expected ? 'ok' : 'mismatch', expected, actual };
}
