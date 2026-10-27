import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, test } from 'vitest';
import { runCli } from '../../src/cli/index.js';
import { inspectAudit } from '../../src/cli/inspection.js';
import { createRuntime } from '../../src/cli/runtime.js';
import { canonicalJson } from '../../src/security/canonical.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
// KEYSENTRY_VAULT=memory guarantees no real keychain/DPAPI is opened even if the code decides to.
const SAFE_ENV = { KEYSENTRY_VAULT: 'memory' };

function chain(events: { kind: string; summary: string; data?: Record<string, unknown> }[], start = { seq: 0, hash: '0'.repeat(64) }) {
  const lines: string[] = [];
  let prev = start.hash;
  let seq = start.seq;
  for (const event of events) {
    seq += 1;
    const content = { seq, at: '2026-10-27T12:00:00.000Z', kind: event.kind, summary: event.summary, data: event.data, prev };
    const hash = createHash('sha256').update(canonicalJson(content)).digest('hex');
    lines.push(canonicalJson({ ...content, hash }));
    prev = hash;
  }
  return lines;
}

async function project() {
  const cwd = await mkdtemp(join(tmpdir(), 'ks-probe-audit-')); dirs.push(cwd);
  const userDir = join(cwd, 'user');
  const vault = createFakeVault();
  const runtime = await createRuntime({ cwd, userDir, vault, inflight: createFakeInFlight(), fingerprintKey: Buffer.alloc(32, 3),
    env: SAFE_ENV, http: new FakeHttp(), hosts: [], log: silentLogger, stdinIsTTY: true, stdoutIsTTY: true });
  await runtime.scan();
  await runtime.vaultSet('GITHUB_TOKEN', 'opaque-token-value-123', 'write');
  const marker = join(userDir, 'audit-heads', `${createHash('sha256').update(runtime.paths.audit).digest('hex').slice(0, 16)}.json`);
  expect((await runtime.audit.verify()).ok).toBe(true);
  return { cwd, userDir, vault, runtime, marker };
}

test('deleting the marker and re-chaining the log without checkpoints is detected by audit verify', async () => {
  const { cwd, userDir, runtime, marker } = await project();
  // Rewrite history: only an innocuous scan ever happened; the vault-set and checkpoints are gone.
  await writeFile(runtime.paths.audit, chain([{ kind: 'scan', summary: 'Scan saved.', data: { hosts: 0, services: 0, clusters: 0, errors: 0 } }]).join('\n') + '\n');
  await unlink(marker);

  const result = await inspectAudit({ cwd, userDir, env: SAFE_ENV, log: silentLogger, stdinIsTTY: false, stdoutIsTTY: false });
  const lines: string[] = [];
  const code = await runCli(['audit', 'verify'], { cwd, userDir, env: SAFE_ENV, log: silentLogger, output: line => lines.push(line), error: line => lines.push(line), stdinIsTTY: false, stdoutIsTTY: false });
  expect({ ok: result.ok, exit: code }).toEqual({ ok: false, exit: 1 });
});

test('entries fabricated after the last signed checkpoint are not reported as verified', async () => {
  const { runtime, vault } = await project();
  const text = await readFile(runtime.paths.audit, 'utf8');
  const last = JSON.parse(text.trim().split('\n').at(-1)!) as { seq: number; hash: string; kind: string };
  expect(last.kind).toBe('checkpoint');
  // Append a fabricated record claiming a state reset that never happened.
  const forged = chain([{ kind: 'state-reset', summary: 'Encrypted saved state reset.', data: { files: 3, force: false } }], last);
  await writeFile(runtime.paths.audit, text + forged.join('\n') + '\n');
  const result = await runtime.audit.verify();
  expect(vault.dump().size).toBeGreaterThan(0);
  expect(result.ok).toBe(false);
  expect(result).toMatchObject({ firstBadSeq: last.seq + 1, problem: `entry ${last.seq + 1} was not written by keysentry on this computer` });
});

test('audit verification reads the saved head after both log and marker are deleted', async () => {
  const { cwd, userDir, vault, runtime, marker } = await project();
  await unlink(marker);
  await unlink(runtime.paths.audit);
  const result = await inspectAudit({ cwd, userDir, vault, env: SAFE_ENV, log: silentLogger });
  expect(result).toMatchObject({ ok: false, entries: 0, truncatedSinceLastKnownHead: true, anchorChecked: true });
});

test('a valid nonempty audit chain without its vault head is refused by the CLI', async () => {
  const { cwd, userDir, vault, runtime } = await project();
  const anchor = createHash('sha256').update(runtime.paths.audit).digest('hex').slice(0, 16);
  await vault.delete(`audit/head/${anchor}`);
  const result = await inspectAudit({ cwd, userDir, vault, env: SAFE_ENV, log: silentLogger });
  expect(result).toMatchObject({ ok: false, problem: 'This audit log has no anchor in your vault; it may have been replaced.' });
  expect(await runCli(['audit', 'verify'], { cwd, userDir, vault, env: SAFE_ENV, log: silentLogger, output: () => {} })).toBe(1);
});

