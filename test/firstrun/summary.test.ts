import { mkdtemp, mkdir, readdir, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fingerprint, makeHint } from '../../src/core/fingerprint.js';
import { buildFirstRun, detectDeployTargets, scanHistory, scanWorkingTree } from '../../src/firstrun/index.js';
import type { RawHit } from '../../src/firstrun/scan-files.js';

const key = Buffer.alloc(32, 7);
const present = 'sk-proj-PresentKey0123456789abcdef';
const removed = 'sk-proj-RemovedKey0123456789abcdef';
const roots: string[] = [];
function hit(value: string, path = '.env', kind: 'file' | 'history' = 'file'): RawHit {
  return { kind, path, name: 'OPENAI_API_KEY', value, provider: 'openai', tier: 'ai', isSecret: true, confidence: 'high', line: 1,
    ...(kind === 'history' ? { commit: 'a'.repeat(40), committedAt: '2026-10-27T12:00:00Z' } : {}) };
}
afterEach(async () => {
  vi.restoreAllMocks();
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});

describe('first-run summary', () => {
  it('a key removed from the working tree is still reported from history', () => {
    const result = buildFirstRun({ root: '/project', files: { files: 1, hits: [hit(present)] },
      history: { commits: 2, complete: true, hits: [hit(present, '.env', 'history'), hit(removed, 'old.env', 'history')] },
      deployTargets: [{ host: 'railway', evidence: 'railway.json' }], fingerprintKey: key, elapsedMs: 123 });
    expect(result).toMatchObject({ scannedFiles: 1, scannedCommits: 2, historyComplete: true, elapsedMs: 123 });
    const current = result.findings.find((item) => item.id === fingerprint(present, key))!;
    const old = result.findings.find((item) => item.id === fingerprint(removed, key))!;
    expect(current).toMatchObject({ hint: makeHint(present), provider: 'openai', tier: 'ai', inGitHistory: true, likelyDeployedOn: ['railway'] });
    expect(current.locations).toEqual([
      { kind: 'file', path: '.env', line: 1, stillPresent: true },
      { kind: 'history', path: '.env', line: 1, commit: 'a'.repeat(40), committedAt: '2026-10-27T12:00:00Z', stillPresent: true },
    ]);
    expect(old).toMatchObject({ inGitHistory: true, likelyDeployedOn: [], locations: [{ kind: 'history', path: 'old.env', line: 1, stillPresent: false }] });
    expect(result.nextSteps[0]).toBe('Rotate the 2 keys that were committed to git; removing them from the code is not enough.');
    expect(JSON.stringify(result)).not.toContain(present);
    expect(JSON.stringify(result)).not.toContain(removed);
  });

  it('clusters copies by the supplied keyed fingerprint and consumes raw values', () => {
    const raw = [hit(present), hit(present, 'nested/.env'), hit(present)];
    const input = { root: '/project', files: { files: 2, hits: raw }, history: { commits: 0, complete: true, hits: [] }, deployTargets: [], fingerprintKey: key, elapsedMs: 1 };
    const result = buildFirstRun(input);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.locations).toHaveLength(2);
    expect(result.findings[0]?.id).toBe(fingerprint(present, key));
    expect(raw.every((entry) => entry.value === undefined)).toBe(true);
    const second = buildFirstRun({ ...input, files: { files: 1, hits: [hit(present)] }, fingerprintKey: Buffer.alloc(32, 8) });
    expect(second.findings[0]?.id).not.toBe(result.findings[0]?.id);
  });

  it('orders useful next steps and recommends the narrowest known platform token', () => {
    const result = buildFirstRun({ root: '/project', files: { files: 1, hits: [hit(present)] },
      history: { commits: 1, complete: true, hits: [hit(present, '.env', 'history')] },
      deployTargets: [{ host: 'railway', evidence: 'railway.json' }, { host: 'fly', evidence: 'fly.toml' },
        { host: 'github-actions', evidence: '.github/workflows/build.yml' }, { host: 'railway', evidence: 'railway.toml' }], fingerprintKey: key, elapsedMs: 1 });
    expect(result.nextSteps[0]).toMatch(/^Rotate the 1 key that/);
    expect(result.nextSteps[1]).toMatch(/Connect Railway.*Project token/);
    expect(result.nextSteps[2]).toMatch(/Connect Fly.io.*Read-only token/);
    expect(result.nextSteps[3]).toMatch(/Connect GitHub Actions.*Secrets: read/);
    expect(result.nextSteps.slice(4)).toEqual(['See the key map.', 'Practise a breach with keysentry drill.', 'Arm autopilot after a successful drill.']);
  });

  it('redacts planted values from paths, evidence and all serialized result fields', () => {
    const files = { files: 1, hits: [hit(present, `/project/${removed}/.env`), hit(removed)] };
    const result = buildFirstRun({ root: '/project', files, history: { commits: 0, complete: false, hits: [] },
      deployTargets: [{ host: 'github-actions', evidence: `.github/workflows/${present}.yml` }], fingerprintKey: key, elapsedMs: 0 });
    const json = JSON.stringify(result);
    for (const value of [present, removed]) expect(json).not.toContain(value);
    expect(json).not.toContain('/project');
  });

  it('does not suggest drills or arming when no keys were detected and reports partial history', () => {
    const result = buildFirstRun({ root: '/project', files: { files: 3, hits: [] }, history: { commits: 12, complete: false, hits: [] },
      deployTargets: [], fingerprintKey: key, elapsedMs: 2 });
    expect(result.findings).toEqual([]);
    expect(result.nextSteps).toEqual(['Git history scan is incomplete; scanned the last 12 commits.']);
  });

  it('runs the local pipeline without fetch calls or state writes and removes every planted value', async () => {
    const root = await mkdtemp(join(resolve('test/firstrun'), '.summary-'));
    roots.push(root);
    await writeFile(join(root, '.env'), `OPENAI_API_KEY=${present}`);
    await writeFile(join(root, 'railway.json'), '{}');
    await mkdir(join(root, 'config'));
    await writeFile(join(root, 'config', 'api.json'), JSON.stringify({ OPENAI_API_KEY: removed }));
    const before = await readdir(root, { recursive: true });
    const fetch = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network is unavailable.'));
    const [files, history, deployTargets] = await Promise.all([scanWorkingTree(root), scanHistory(root, { git: async (_args, { onLine }) => {
      for (const line of [`\0${'a'.repeat(40)}\x002026-10-27T12:00:00Z`, '+++ b/.env', '@@ -0,0 +1 @@', `+OPENAI_API_KEY=${removed}`]) onLine(line);
      return { code: 0 };
    } }), detectDeployTargets(root)]);
    const result = buildFirstRun({ root, files, history, deployTargets, fingerprintKey: key, elapsedMs: 1 });
    expect(result.findings).toHaveLength(2);
    for (const value of [present, removed]) expect(JSON.stringify(result)).not.toContain(value);
    expect(fetch).not.toHaveBeenCalled();
    expect(await readdir(root, { recursive: true })).toEqual(before);
  });
});
