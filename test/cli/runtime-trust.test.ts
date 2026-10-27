import { mkdir, mkdtemp, readFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, test } from 'vitest';
import { createRuntime } from '../../src/cli/runtime.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
async function fixture() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-runtime-trust-')); dirs.push(cwd);
  const vault = createFakeVault();
  const runtime = await createRuntime({ cwd, userDir: join(cwd, 'user'), vault, inflight: createFakeInFlight(),
    env: {}, http: new FakeHttp(), hosts: [], log: silentLogger, stdinIsTTY: true, stdoutIsTTY: true });
  return { cwd, vault, runtime };
}

test('runtime encrypts state and mirrors even direct store journal appends to audit', async () => {
  const { runtime } = await fixture();
  await runtime.scan();
  expect(await readFile(runtime.paths.inventory, 'utf8')).toMatch(/^keysentry-encrypted:v1\n/);
  await runtime.store.journal().append({ at: new Date().toISOString(), planId: 'plan-20261027120000-abcd', event: 'resume', data: { value: 'metadata-excluded' } });
  await runtime.checkpoint();
  const records = (await readFile(runtime.paths.audit, 'utf8')).trim().split('\n').map(line => JSON.parse(line));
  expect(records.some(record => record.kind === 'journal:resume' && record.data.planId === 'plan-20261027120000-abcd')).toBe(true);
  expect(JSON.stringify(records)).not.toContain('metadata-excluded');
  expect((await runtime.audit.verify()).ok).toBe(true);
});

test('runtime vault changes contain names and roles only in the audit log', async () => {
  const { runtime, vault } = await fixture();
  await runtime.vaultSet('GITHUB_TOKEN', 'opaque-token-value', 'read');
  expect((await vault.get('cred/GITHUB_TOKEN@read'))?.toString()).toBe('opaque-token-value');
  const status = await runtime.vaultStatus();
  expect(JSON.stringify(status)).toContain('GITHUB_TOKEN');
  expect(JSON.stringify(status)).not.toContain('opaque-token-value');
  expect(await readFile(runtime.paths.audit, 'utf8')).not.toContain('opaque-token-value');
});

test('runtime records that the audit vault has an anchor even if the log is later removed', async () => {
  const { runtime, cwd } = await fixture();
  await runtime.scan();
  const { createHash } = await import('node:crypto');
  const marker = join(cwd, 'user', 'audit-heads', `${createHash('sha256').update(runtime.paths.audit).digest('hex').slice(0, 16)}.json`);
  expect(JSON.parse(await readFile(marker, 'utf8'))).toEqual({ v: 1 });
});

test('automatic audit checkpoints also preserve anchor presence before a command ends', async () => {
  const { runtime, cwd } = await fixture();
  for (let index = 0; index < 50; index++) await runtime.audit.append({ kind: 'test', summary: 'Metadata event.' });
  const { createHash } = await import('node:crypto');
  const marker = join(cwd, 'user', 'audit-heads', `${createHash('sha256').update(runtime.paths.audit).digest('hex').slice(0, 16)}.json`);
  expect(JSON.parse(await readFile(marker, 'utf8'))).toEqual({ v: 1 });
});

test('refused reset validates directory links before shredding recovery values', async () => {
  const { runtime, cwd } = await fixture();
  const planId = 'plan-20261027120000-abcd';
  await runtime.inflight.put(planId, 'new:cluster', 'retained-recovery-value');
  await runtime.store.journal().append({ at: new Date().toISOString(), planId, event: 'plan-end', data: { status: 'partial' } });
  const target = join(cwd, 'outside-state'); await mkdir(target);
  await symlink(target, runtime.paths.plans, process.platform === 'win32' ? 'junction' : 'dir');
  await expect(runtime.resetState(true)).rejects.toThrow(/link/);
  expect(await runtime.inflight.get(planId, 'new:cluster')).toBe('retained-recovery-value');
});
