import fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { detectDeployTargets } from '../../src/firstrun/deploy-targets.js';

const roots: string[] = [];

async function fixture(): Promise<string> {
  const root = await fs.mkdtemp(join(tmpdir(), 'keysentry-deploy-targets-'));
  roots.push(root);
  return root;
}

async function write(root: string, path: string, contents = '{}'): Promise<void> {
  const file = join(root, path);
  await fs.mkdir(dirname(file), { recursive: true });
  await fs.writeFile(file, contents);
}

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  for (const root of roots.splice(0)) await fs.rm(root, { recursive: true, force: true });
});

describe('deployment target detection', () => {
  it.each([
    ['railway.json', 'railway'],
    ['railway.toml', 'railway'],
    ['.railway/railway.ts', 'railway'],
    ['vercel.json', 'vercel'],
    ['.vercel/project.json', 'vercel'],
    ['fly.toml', 'fly'],
    ['render.yaml', 'render'],
  ])('infers %s from a regular config file', async (evidence, host) => {
    const root = await fixture();
    await write(root, evidence, 'config contents are not needed for inference');

    expect(await detectDeployTargets(root)).toEqual([{ host, evidence }]);
  });

  it('finds GitHub Actions workflows with secrets references in filename order', async () => {
    const root = await fixture();
    await write(root, '.github/workflows/z-deploy.yaml', 'env:\n  TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n');
    await write(root, '.github/workflows/a-test.yml', 'env:\n  TOKEN: ${{ secrets.TEST_TOKEN }}\n');
    await write(root, '.github/workflows/public.yml', 'env:\n  MODE: production\n');
    await write(root, '.github/workflows/not-a-reference.yml', 'env:\n  TEXT: mysecrets.TOKEN\n');
    await write(root, '.github/workflows/nested/ignored.yml', 'env: ${{ secrets.NESTED }}\n');

    expect(await detectDeployTargets(root)).toEqual([
      { host: 'github-actions', evidence: '.github/workflows/a-test.yml' },
      { host: 'github-actions', evidence: '.github/workflows/z-deploy.yaml' },
    ]);
  });

  it('returns only relative filenames without values and makes no network call or writes', async () => {
    const root = await fixture();
    const value = 'private-planted-value-for-deploy-inference';
    await write(root, 'railway.json', JSON.stringify({ token: value }));
    await write(root, 'vercel.json', JSON.stringify({ env: { TOKEN: value } }));
    await write(root, '.github/workflows/deploy.yml', 'env:\n  TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n  OTHER: ' + value + '\n');
    const before = await fs.readdir(root, { recursive: true });
    vi.stubGlobal('fetch', () => { throw new Error('Network is unavailable during first run.'); });

    const result = await detectDeployTargets(root);

    expect(result).toEqual([
      { host: 'railway', evidence: 'railway.json' },
      { host: 'vercel', evidence: 'vercel.json' },
      { host: 'github-actions', evidence: '.github/workflows/deploy.yml' },
    ]);
    expect(JSON.stringify(result)).not.toContain(value);
    for (const target of result) {
      expect(isAbsolute(target.evidence)).toBe(false);
      expect(target.evidence).not.toContain('..');
      expect(target.evidence).not.toContain('\\');
    }
    expect(await fs.readdir(root, { recursive: true })).toEqual(before);
    expect(await fs.readFile(join(root, 'railway.json'), 'utf8')).toBe(JSON.stringify({ token: value }));
  });

  it('does not infer a host from directories or configs outside the project root', async () => {
    const root = await fixture();
    await fs.mkdir(join(root, 'vercel.json'));
    await write(root, 'nested/fly.toml');
    await write(root, 'node_modules/example/render.yaml');

    expect(await detectDeployTargets(root)).toEqual([]);
  });

  it('skips workflows over 1 MiB while accepting the size limit', async () => {
    const root = await fixture();
    const prefix = 'env: ${{ secrets.TOKEN }}\n';
    const atLimit = Buffer.alloc(1024 * 1024, 0x20);
    atLimit.write(prefix);
    await write(root, '.github/workflows/at-limit.yml', atLimit.toString());
    await write(root, '.github/workflows/too-large.yml', prefix + ' '.repeat(1024 * 1024));

    expect(await detectDeployTargets(root)).toEqual([
      { host: 'github-actions', evidence: '.github/workflows/at-limit.yml' },
    ]);
  });

  it('skips symlinked config directories and workflow directories outside the root', async () => {
    const root = await fixture();
    const outside = await fixture();
    await write(outside, 'railway.ts');
    await write(outside, 'project.json');
    await write(outside, 'workflows/deploy.yml', 'env: ${{ secrets.TOKEN }}\n');
    const directoryLink = process.platform === 'win32' ? 'junction' : 'dir';
    await fs.symlink(outside, join(root, '.railway'), directoryLink);
    await fs.symlink(outside, join(root, '.vercel'), directoryLink);
    await fs.mkdir(join(root, '.github'));
    await fs.symlink(join(outside, 'workflows'), join(root, '.github/workflows'), directoryLink);

    expect(await detectDeployTargets(root)).toEqual([]);
  });

  it('skips a symlinked root and symlinked .github ancestor', async () => {
    const root = await fixture();
    const outside = await fixture();
    await write(outside, 'fly.toml');
    await write(outside, 'workflows/deploy.yml', 'env: ${{ secrets.TOKEN }}\n');
    const directoryLink = process.platform === 'win32' ? 'junction' : 'dir';
    await fs.symlink(outside, join(root, 'linked-root'), directoryLink);
    await fs.symlink(outside, join(root, '.github'), directoryLink);

    expect(await detectDeployTargets(join(root, 'linked-root'))).toEqual([]);
    expect(await detectDeployTargets(root)).toEqual([]);
  });

  it('skips symlinked config and workflow files', async (context) => {
    const root = await fixture();
    const outside = await fixture();
    await write(outside, 'config');
    await write(outside, 'workflow', 'env: ${{ secrets.TOKEN }}\n');
    await fs.mkdir(join(root, '.github/workflows'), { recursive: true });
    try {
      await fs.symlink(join(outside, 'config'), join(root, 'fly.toml'), 'file');
      await fs.symlink(join(outside, 'workflow'), join(root, '.github/workflows/deploy.yml'), 'file');
    } catch (error) {
      if (process.platform === 'win32' && (error as NodeJS.ErrnoException).code === 'EPERM') {
        context.skip();
        return;
      }
      throw error;
    }

    expect(await detectDeployTargets(root)).toEqual([]);
  });

  it('returns no targets for a missing root or a root that is a file', async () => {
    const root = await fixture();
    await write(root, 'file');

    expect(await detectDeployTargets(join(root, 'missing'))).toEqual([]);
    expect(await detectDeployTargets(join(root, 'file'))).toEqual([]);
  });

  it('returns no targets when the root cannot be inspected', async () => {
    const root = await fixture();
    await write(root, 'fly.toml');
    vi.spyOn(fs, 'lstat').mockRejectedValue(Object.assign(new Error('Unshown filesystem details'), { code: 'EACCES' }));

    expect(await detectDeployTargets(root)).toEqual([]);
  });

  it('continues with other hosts when a workflow cannot be opened', async () => {
    const root = await fixture();
    await write(root, 'fly.toml');
    await write(root, '.github/workflows/deploy.yml', 'env: ${{ secrets.TOKEN }}\n');
    vi.spyOn(fs, 'open').mockRejectedValue(Object.assign(new Error('Unshown filesystem details'), { code: 'EACCES' }));

    expect(await detectDeployTargets(root)).toEqual([{ host: 'fly', evidence: 'fly.toml' }]);
  });
});
