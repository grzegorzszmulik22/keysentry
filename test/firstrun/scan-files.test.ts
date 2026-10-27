import { mkdtemp, mkdir, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { scanWorkingTree } from '../../src/firstrun/scan-files.js';

const roots: string[] = [];
const secret = 'sk-proj-FirstRunKey0123456789abcdef';
async function fixture(): Promise<string> {
  const dir = await mkdtemp(join(resolve('test/firstrun'), '.files-'));
  roots.push(dir);
  return dir;
}
async function put(root: string, path: string, source: string | Buffer): Promise<void> {
  await mkdir(dirname(join(root, path)), { recursive: true });
  await writeFile(join(root, path), source);
}
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('first-run working tree', () => {
  it('finds keys in dotenv and common configs and ignores dependencies and build output', async () => {
    const root = await fixture();
    const included: Record<string, string> = {
      '.env': `# comment\nexport OPENAI_API_KEY="${secret}" # inline\nPORT=3000\nNEXT_PUBLIC_URL=https://example.com`,
      '.env.local': `OTHER=${secret}`,
      '.dev.vars': `OPENAI_API_KEY='${secret}'`,
      '.npmrc': `//registry.npmjs.org/:_authToken=${secret}`,
      '.pypirc': `password = ${secret}`,
      'docker-compose.prod.yaml': `environment:\n  OPENAI_API_KEY: ${secret}`,
      'production.tfvars': `openai_api_key = "${secret}"`,
      'wrangler.toml': `OPENAI_API_KEY = "${secret}"`,
      '.vercel/.env.production': `OPENAI_API_KEY=${secret}`,
      'config/api.json': `{"OPENAI_API_KEY": "${secret}", "port": 3000}`,
      'nested/config/api.yml': `OPENAI_API_KEY: '${secret}'`,
      'a/b/c/.env': `OPENAI_API_KEY=${secret}`,
    };
    for (const [path, source] of Object.entries(included)) await put(root, path, source);
    for (const ignored of ['node_modules', '.git', 'dist', 'build', '.next', '.venv', 'vendor', '.keysentry']) {
      await put(root, `${ignored}/.env`, `KEY=${secret}`);
    }
    await put(root, 'a/b/c/d/.env', `KEY=${secret}`);
    await put(root, 'source.ts', `const KEY="${secret}"`);
    const result = await scanWorkingTree(root);
    expect(result.files).toBe(12);
    expect(result.hits.map((hit) => hit.path).sort()).toEqual(Object.keys(included).sort());
    expect(result.hits.every((hit) => hit.provider === 'openai' && hit.kind === 'file')).toBe(true);
    expect(result.hits.find((hit) => hit.path === '.env')?.line).toBe(2);
  });

  it('labels templates and ignores placeholder values even if the shape resembles a key', async () => {
    const root = await fixture();
    await put(root, '.env.example', `OPENAI_API_KEY=sk-proj-your-key-goes-here\nACTUAL_KEY=${secret}`);
    await put(root, '.env.sample', 'API_TOKEN=replace_me_with_a_secret_token');
    await put(root, '.env.template', 'API_TOKEN=${API_TOKEN}');
    const result = await scanWorkingTree(root);
    expect(result.files).toBe(3);
    expect(result.hits).toHaveLength(1);
    expect(result.hits[0]).toMatchObject({ path: '.env.example', template: true, value: secret, line: 2 });
  });

  it.each(['sk_test_your_stripe_secret_key', 'sk-ant-api03-your-api-key-goes-here', 'sk-or-v1-your-api-key-goes-here',
    'github_pat_your_personal_access_token_here', 'sk-proj-xxxxxxxxxxxxxxxxxxxxxxxx'])('ignores provider-prefixed template placeholders: %s', async (value) => {
    const root = await fixture();
    await put(root, '.env.example', `OPENAI_API_KEY=${value}`);
    expect((await scanWorkingTree(root)).hits).toEqual([]);
  });

  it('uses dotenv quoting, comments, escaped newlines and multiline private keys', async () => {
    const root = await fixture();
    const pem = '-----BEGIN PRIVATE KEY-----\nabc123DEF456\n-----END PRIVATE KEY-----';
    await put(root, '.env', `export OPENAI_API_KEY = '${secret}'#comment\r\nPRIVATE_KEY="${pem.replaceAll('\n', '\\n')}"\r\nSECOND_KEY="${pem}"\n`);
    const result = await scanWorkingTree(root);
    expect(result.hits.map(({ provider, line }) => ({ provider, line }))).toEqual([
      { provider: 'openai', line: 1 }, { provider: 'private-key', line: 2 }, { provider: 'private-key', line: 3 },
    ]);
    expect(result.hits[1]?.value).toBe(pem);
  });

  it('keeps literal credentials mixed with placeholders and real keys containing example words', async () => {
    const root = await fixture();
    const url = 'postgres://user:P4ssw0rdQ9x7@${DB_HOST}/app';
    const actual = 'sk-proj-live_example_0123456789abcdef';
    await put(root, '.env.example', `DATABASE_URL=${url}\nOPENAI_API_KEY=${actual}`);
    const result = await scanWorkingTree(root);
    expect(result.hits.map(({ value }) => value)).toEqual([url, actual]);
  });

  it('ends quoted config values before quoted inline comments', async () => {
    const root = await fixture();
    await put(root, 'wrangler.toml', `OPENAI_API_KEY = "${secret}" # "example"`);
    await put(root, 'config/api.yml', `OPENAI_API_KEY: '${secret}' # 'example'`);
    const result = await scanWorkingTree(root);
    expect(result.hits).toHaveLength(2);
    expect(result.hits.every(({ value }) => value === secret)).toBe(true);
  });

  it('caps files and bytes and skips binary files', async () => {
    const root = await fixture();
    await put(root, '.env.a', `KEY=${secret}`);
    await put(root, '.env.b', `KEY=${secret}`);
    await put(root, '.env.huge', `KEY=${secret}\n${'x'.repeat(1024 * 1024)}`);
    await put(root, '.env.binary', Buffer.from(`KEY=${secret}\0`));
    expect((await scanWorkingTree(root, { maxFiles: 1 })).files).toBe(1);
    expect((await scanWorkingTree(root, { maxBytes: 10 })).files).toBe(0);
    const result = await scanWorkingTree(root);
    expect(result.files).toBe(2);
    expect(result.hits).toHaveLength(2);
  });

  it('does not follow directory or file symlinks, make network calls or write state', async () => {
    const root = await fixture();
    const outside = await fixture();
    await put(outside, '.env', `KEY=${secret}`);
    await symlink(outside, join(root, 'linked'), 'junction');
    const fetch = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network forbidden'));
    expect(await scanWorkingTree(root)).toEqual({ files: 0, hits: [] });
    expect(fetch).not.toHaveBeenCalled();
    expect(await readdir(root)).toEqual(['linked']);
  });

  it('returns empty output for a missing directory without exposing the path in errors', async () => {
    expect(await scanWorkingTree(join(await fixture(), secret))).toEqual({ files: 0, hits: [] });
  });
});
