import { constants } from 'node:fs';
import fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import type { HostId } from '../types.js';

type DeployTarget = { host: HostId; evidence: string };

const CONFIGS: readonly DeployTarget[] = [
  { host: 'railway', evidence: 'railway.json' },
  { host: 'railway', evidence: 'railway.toml' },
  { host: 'railway', evidence: '.railway/railway.ts' },
  { host: 'vercel', evidence: 'vercel.json' },
  { host: 'vercel', evidence: '.vercel/project.json' },
  { host: 'fly', evidence: 'fly.toml' },
  { host: 'render', evidence: 'render.yaml' },
];
const MAX_WORKFLOW_BYTES = 1024 * 1024;

/** Each component must be a regular directory or file; symbolic links are skipped. */
async function inspectPath(root: string, relative: string, directory = false): Promise<string | null> {
  let path = root;
  const parts = relative.split('/');
  try {
    for (let index = 0; index < parts.length; index++) {
      path = join(path, parts[index]!);
      const info = await fs.lstat(path);
      const wantsDirectory = index < parts.length - 1 || directory;
      if (info.isSymbolicLink() || !(wantsDirectory ? info.isDirectory() : info.isFile())) return null;
    }
    return path;
  } catch {
    return null;
  }
}

async function referencesSecrets(path: string): Promise<boolean> {
  let file: fs.FileHandle | undefined;
  let bytes: Buffer | undefined;
  try {
    file = await fs.open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const info = await file.stat();
    if (!info.isFile() || info.size > MAX_WORKFLOW_BYTES) return false;
    // A bounded read remains bounded even when the file grows after stat().
    bytes = Buffer.alloc(info.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await file.read(bytes, offset, bytes.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    return /\bsecrets\./u.test(bytes.subarray(0, offset).toString('utf8'));
  } catch {
    return false;
  } finally {
    bytes?.fill(0);
    await file?.close().catch(() => {});
  }
}

/** Infer possible deployment hosts from local filenames, without returning file contents. */
export async function detectDeployTargets(root: string): Promise<DeployTarget[]> {
  const absoluteRoot = resolve(root);
  try {
    const info = await fs.lstat(absoluteRoot);
    if (info.isSymbolicLink() || !info.isDirectory()) return [];
  } catch {
    return [];
  }

  const targets: DeployTarget[] = [];
  for (const config of CONFIGS) {
    if (await inspectPath(absoluteRoot, config.evidence)) targets.push({ ...config });
  }

  const workflows = await inspectPath(absoluteRoot, '.github/workflows', true);
  if (!workflows) return targets;
  let names: string[];
  try {
    names = await fs.readdir(workflows);
  } catch {
    return targets;
  }
  for (const name of names.sort()) {
    // Preserve a single, printable filename component in every returned evidence path.
    if (name === '.' || name === '..' || /[/\\\u0000-\u001f\u007f-\u009f]/u.test(name)) continue;
    const evidence = `.github/workflows/${name}`;
    const path = await inspectPath(absoluteRoot, evidence);
    if (path && await referencesSecrets(path)) targets.push({ host: 'github-actions', evidence });
  }
  return targets;
}
