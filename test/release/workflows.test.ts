import { readFile } from 'node:fs/promises';
import { expect, test } from 'vitest';
import { parse } from 'yaml';

interface Step { name?: string; run?: string; uses?: string; with?: Record<string, unknown>; env?: Record<string, string> }
interface Job { needs?: string | string[]; environment?: string; if?: string; steps: Step[]; strategy?: { matrix: { os: string[] } } }

async function workflow(name: string): Promise<{ jobs: Record<string, Job> }> {
  return parse(await readFile(new URL(`../../.github/workflows/${name}.yml`, import.meta.url), 'utf8'));
}

test('release signing is isolated from dependency installation, builds and caches', async () => {
  const { jobs } = await workflow('release');
  expect(JSON.stringify(jobs.build)).not.toContain('secrets.');
  expect(JSON.stringify(jobs)).not.toContain('"cache":"npm"');
  expect(jobs.sign).toBeDefined();
  const signer = jobs.sign!;
  expect(signer.needs).toBe('build');
  expect(signer.environment).toBe('release');
  expect(signer.steps.find(step => step.uses?.startsWith('actions/checkout@'))?.with?.ref).toBe('${{ github.sha }}');
  expect(signer.steps.some(step => step.uses?.startsWith('actions/download-artifact@'))).toBe(true);
  const commands = signer.steps.map(step => step.run ?? '').join('\n');
  expect(commands).not.toMatch(/\b(?:npm|npx|vitest|esbuild)\b/);
  const verification = signer.steps.findIndex(step => step.run?.includes('sign-release.mjs --verify'));
  const signing = signer.steps.findIndex(step => step.env?.KEYSENTRY_RELEASE_SIGNING_KEY !== undefined);
  expect(verification).toBeGreaterThan(-1);
  expect(signing).toBeGreaterThan(verification);
  expect(signer.steps[signing]!.run).toBe('node scripts/sign-release.mjs dist-release/out/SHA256SUMS');
  expect(signer.steps.filter(step => JSON.stringify(step).includes('secrets.KEYSENTRY_RELEASE_SIGNING_KEY'))).toHaveLength(1);
  const buildCommands = jobs.build!.steps.map(step => step.run ?? '');
  expect(buildCommands).toContain('node tools/vitest-sandbox.mjs test/');
  expect(buildCommands.filter(command => command.startsWith('npm run release:build'))).toHaveLength(2);
  const comparison = buildCommands.findIndex(command => command.includes('await assertReproducible'));
  expect(comparison).toBeGreaterThan(buildCommands.lastIndexOf('npm run release:build -- repro-b'));
  expect(buildCommands[comparison]).toContain("'dist-release/out', 'dist-release/repro-b'");
  expect(buildCommands.slice(comparison + 1).some(command => command.includes('release:build'))).toBe(false);
});

test('public release and provenance jobs wait for signing and stay disabled on private repositories', async () => {
  const { jobs } = await workflow('release');
  for (const name of ['attest', 'publish']) {
    expect(jobs[name]).toBeDefined();
    const job = jobs[name]!;
    expect([job.needs].flat()).toContain('sign');
    expect(job.if).toBe('${{ !github.event.repository.private }}');
  }
  expect(jobs.publish!.steps.some(step => step.with?.name === 'release-signature')).toBe(true);
});

test('POSIX packed-bin CI exercises global and npx links on Linux and macOS', async () => {
  const { jobs } = await workflow('ci');
  const job = jobs['packed-bin']!;
  expect(job).toBeDefined();
  expect(job.strategy?.matrix.os).toEqual(['ubuntu-latest', 'macos-latest']);
  const commands = job.steps.map(step => step.run ?? '').join('\n');
  expect(commands).toContain('npm run release:build');
  expect(commands).toContain('npm install --global --prefix');
  expect(commands).toContain('keysentry --version');
  expect(commands).toContain('keysentry --help');
  expect(commands).toContain('npx --no-install keysentry --version');
  expect(commands).toContain('test "$(keysentry --version)" = "$version"');
  expect(commands).toContain("grep -q 'Usage: keysentry'");
  expect(commands).toContain('test "$(npx --no-install keysentry --version)" = "$version"');
  expect(commands).toContain('mktemp -d');
});

test('CI runs the regular suite separately from reviewer probes', async () => {
  const { jobs } = await workflow('ci');
  expect(jobs.test!.steps.some(step => step.run === 'node tools/vitest-sandbox.mjs test/')).toBe(true);
});
