import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
// @ts-expect-error Plain JavaScript shared with the build script, without declarations.
import { BUNDLE_ALLOWED, bundleViolations } from '../scripts/bundle-policy.mjs';

const root = new URL('../../../', import.meta.url);
const read = (path: string) => readFile(new URL(path, root), 'utf8').then(text => text.replace(/\r\n/g, '\n'));
const froms = (text: string) => [...text.matchAll(/^FROM\s+(?:--platform=(\S+)\s+)?(\S+)/gm)].map(match => ({ platform: match[1], image: match[2] }));
const instructions = (text: string) => text.split('\n').filter(line => !line.trim().startsWith('#')).join('\n');

/** Relative runtime imports of one TypeScript source file (type-only imports are erased and never bundled). */
function imports(source: string): string[] {
  const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  const found: string[] = [];
  for (const match of code.matchAll(/\b(import|export)\s+(type\s+)?(?:[^'";]*?\sfrom\s*)?['"](\.{1,2}\/[^'"]+)['"]/g)) if (!match[2]) found.push(match[3]!);
  for (const match of code.matchAll(/\bimport\(\s*['"](\.{1,2}\/[^'"]+)['"]\s*\)/g)) found.push(match[1]!);
  return found;
}
async function graph(entry: string): Promise<string[]> {
  const seen = new Set<string>();
  const queue = [entry];
  while (queue.length) {
    const file = queue.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    for (const specifier of imports(await read(file))) {
      const target = new URL(specifier.replace(/\.js$/, '.ts'), new URL(file, root)).href.slice(root.href.length);
      queue.push(target);
    }
  }
  return [...seen].sort();
}

describe('Dockerfile.control-plane', () => {
  it('pins amd64 and the Dockerfile digests, and runs the bundle as non-root on distroless without a shell', async () => {
    const image = await read('Dockerfile.control-plane'), main = await read('Dockerfile');
    expect(froms(image).map(from => from.platform)).toEqual(['linux/amd64', 'linux/amd64']);
    expect(froms(image).map(from => from.image)).toEqual(froms(main).map(from => from.image));
    expect(froms(image).every(from => /@sha256:[a-f0-9]{64}$/.test(from.image!))).toBe(true);
    const runtime = instructions(image.slice(image.lastIndexOf('\nFROM ')));
    expect(runtime).toContain('gcr.io/distroless/nodejs24');
    expect(runtime).not.toMatch(/^(?:RUN|SHELL|VOLUME|ADD)\b/m);
    expect(runtime).toMatch(/^USER 65532$/m);
    expect(runtime).toMatch(/^ENTRYPOINT \["\/nodejs\/bin\/node", "\/app\/control-plane\.mjs"\]$/m);
    expect(runtime).not.toMatch(/^CMD\b/m);
    // Only the bundle and the licence files reach the runtime image.
    expect([...runtime.matchAll(/^COPY\s+(.*)$/gm)].map(match => match[1])).toEqual([
      '--from=build /build/out/control-plane.mjs /app/',
      '--from=build /build/LICENSE /build/NOTICE /app/',
    ]);
    expect(runtime).toMatch(/^ENV NODE_ENV=production$/m);
    expect(runtime).not.toMatch(/^ENV\b.*\b\w*(?:_KEY|TOKEN|SECRET|PASSPHRASE|_REF)\w*=/m);
    expect(runtime).not.toMatch(/tee\.launch_policy/);
  });
  it('builds only the control plane: never the release bundle, the watcher or the box image', async () => {
    const image = instructions(await read('Dockerfile.control-plane'));
    const build = image.slice(0, image.lastIndexOf('\nFROM '));
    expect(build).not.toMatch(/release:build|keysentry\.mjs|box", "agent|\bwatch\b|Dockerfile\.box/);
    expect([...build.matchAll(/^RUN\s+(.*)$/gm)].map(match => match[1])).toEqual([
      'npm ci --ignore-scripts',
      'node packages/control-plane/scripts/build.mjs --out /build/out/control-plane.mjs',
    ]);
    // The package's tests and the repository's other packages and tools are not copied.
    const copied = [...build.matchAll(/^COPY\s+(?!--from)(.*)$/gm)].map(match => match[1]!);
    expect(copied).toEqual([
      'package.json package-lock.json ./', 'tsconfig.json LICENSE NOTICE ./', 'src/ src/',
      'packages/control-plane/package.json packages/control-plane/tsconfig.json packages/control-plane/',
      'packages/control-plane/src/ packages/control-plane/src/', 'packages/control-plane/scripts/ packages/control-plane/scripts/',
      'packages/control-plane/ui/ packages/control-plane/ui/',
    ]);
  });
  it('the entry imports no watcher, CLI, box agent, dashboard or emulator module', async () => {
    const reachable = await graph('packages/control-plane/src/main.ts');
    expect(reachable).toContain('packages/control-plane/src/server.ts');
    expect(reachable).toContain('src/net/guarded-http.ts');
    expect(bundleViolations(reachable)).toEqual([]);
    expect(reachable.some(file => /^src\/(?:watcher|cli|box\/agent|dashboard)\/|emulator|local-box/.test(file))).toBe(false);
  });
  it('the policy refuses what must never ship', () => {
    expect(bundleViolations([
      'src/watcher/index.ts', 'src/cli/box.ts', 'src/box/agent/main.ts', 'src/box/seal/kms.ts', 'src/dashboard/server/server.ts',
      'packages/control-plane/src/emulator/index.ts', 'packages/control-plane/src/local-box.ts', 'node_modules/typescript/lib/typescript.js',
      'src/approvals/server.ts', 'src/unknown/module.ts',
    ])).toHaveLength(10);
    expect(bundleViolations(['packages/control-plane/src/main.ts', 'src/box/handshake/messages.ts', 'node_modules/zod/index.js'])).toEqual([]);
    expect(BUNDLE_ALLOWED.length).toBeGreaterThan(0);
  });
  it('esbuild bundles the entry within the policy (skipped where child processes are blocked)', async ctx => {
    let result: { metafile?: { inputs: Record<string, unknown> } };
    try {
      const { build } = await import('esbuild');
      result = await build({ absWorkingDir: decodeURIComponent(root.pathname).replace(/^\/([A-Za-z]:)/, '$1'), entryPoints: ['packages/control-plane/src/main.ts'],
        bundle: true, platform: 'node', format: 'esm', target: 'node22', write: false, metafile: true, outfile: 'control-plane.mjs', logLevel: 'silent' });
    } catch (error) {
      if (/EPERM|spawn|service/i.test(String((error as Error)?.message))) { ctx.skip(); return; }
      throw error;
    }
    const inputs = Object.keys(result.metafile!.inputs);
    expect(inputs).toContain('packages/control-plane/src/main.ts');
    expect(bundleViolations(inputs)).toEqual([]);
  }, 60_000);
});
