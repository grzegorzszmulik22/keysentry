import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { runCli } from '../../src/cli/index.js';
import * as cliModule from '../../src/cli/index.js';
import * as vaultModule from '../../src/vault/index.js';
import { createFileReceipt } from '../../src/net/index.js';
import * as releaseModule from '../../src/release/index.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createAuditLog } from '../../src/security/index.js';

const dirs: string[] = [];
afterEach(async () => { vi.restoreAllMocks(); await Promise.all(dirs.splice(0).map(path => rm(path, { recursive: true, force: true }))); });
async function fixture() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-inspection-')); dirs.push(cwd);
  const output: string[] = []; const errors: string[] = [];
  const opened = vi.spyOn(vaultModule, 'openVault').mockRejectedValue(new Error('must not open vault'));
  return { cwd, output, errors, opened, options: { cwd, userDir: join(cwd, '.user'), env: {}, output: (line: string) => output.push(line), error: (line: string) => errors.push(line) } };
}

it.each([['--help'], ['--version']])('%j prints without opening the vault', async (...args) => {
  const f = await fixture(); expect(await runCli(args as string[], f.options)).toBe(0); expect(f.opened).not.toHaveBeenCalled();
});

it('network groups the allow-list and shows host-only receipts without opening the vault', async () => {
  const f = await fixture();
  await writeFile(join(f.cwd, 'keysentry.yaml'), 'network:\n  allowHosts: [custom.example.com]\nmonitor:\n  webhooks: [https://notify.example.com/private-path?token=opaque]\n');
  await createFileReceipt(join(f.cwd, '.keysentry', 'network.jsonl')).record({ at: '2026-10-27T10:00:00.000Z', host: 'api.openai.com', method: 'GET', purpose: 'OpenAI key verification', allowed: true, status: 200 });
  expect(await runCli(['network'], f.options)).toBe(0);
  expect(f.output.join('\n')).toContain('api.openai.com'); expect(f.output.join('\n')).toContain('added by you');
  expect(f.output.join('\n')).not.toContain('private-path'); expect(f.output.join('\n')).not.toContain('opaque'); expect(f.opened).not.toHaveBeenCalled();
});

it('verify --offline checks the local copy without opening the vault', async () => {
  const f = await fixture(); expect(await runCli(['verify', '--offline'], f.options)).toBe(0);
  expect(f.output.join('\n')).toMatch(/local|development/i); expect(f.opened).not.toHaveBeenCalled();
});

it('audit verify consults the vault even for an empty local log', async () => {
  // Skipping the vault for an empty or unsigned log allowed a deleted marker to bypass its head.
  const f = await fixture(); f.opened.mockResolvedValue(createFakeVault());
  expect(await runCli(['audit', 'verify'], f.options)).toBe(0);
  expect(f.output.join('\n')).toMatch(/0|empty/); expect(f.opened).toHaveBeenCalledOnce();
});

it('network rejects a malformed since timestamp', async () => {
  const f = await fixture(); expect(await runCli(['network', '--since', 'yesterday'], f.options)).toBe(1);
});

it.each(['2026-02-30T00:00:00Z', '2026-10-27T10:00:00', '2026-10-27T24:00:00Z'])('network rejects invalid or ambiguous ISO timestamp %s', async since => {
  const f = await fixture(); expect(await runCli(['network', '--since', since], f.options)).toBe(1);
});

it('network accepts an ISO timestamp with an explicit offset', async () => {
  const f = await fixture(); expect(await runCli(['network', '--since', '2026-10-27T10:00:00+02:00'], f.options)).toBe(0);
});

it('unknown mcp command exits 1 without opening the vault', async () => {
  const f = await fixture(); expect(await runCli(['mcp'], f.options)).toBe(1); expect(f.opened).not.toHaveBeenCalled();
});

it('agent mutation refusal happens before opening the vault', async () => {
  const f = await fixture(); expect(await runCli(['rotate', '--execute', '--yes'], { ...f.options, env: { AI_AGENT: 'test' }, stdinIsTTY: true, stdoutIsTTY: true })).toBe(1);
  expect(f.errors.join('\n')).toContain('AI coding agent'); expect(f.opened).not.toHaveBeenCalled();
});

it('an integrity mismatch refuses execution before opening the vault', async () => {
  const f = await fixture(); vi.spyOn(releaseModule, 'checkLocalIntegrity').mockResolvedValue({ status: 'mismatch' });
  expect(await runCli(['rotate', '--execute', '--yes'], { ...f.options, stdinIsTTY: true, stdoutIsTTY: true })).toBe(1);
  expect(f.errors.join('\n')).toContain('does not match its local manifest'); expect(f.opened).not.toHaveBeenCalled();
});

it('development execution prints one local-integrity warning', async () => {
  const f = await fixture(); vi.spyOn(releaseModule, 'checkLocalIntegrity').mockResolvedValue({ status: 'dev' });
  expect(await runCli(['rotate', '--execute', '--yes'], { ...f.options, stdinIsTTY: true, stdoutIsTTY: true })).toBe(1);
  expect(f.errors.filter(line => line.includes('Development copy:'))).toHaveLength(1);
});

it('audit verify consults a previous-anchor marker even after every audit line is deleted', async () => {
  const f = await fixture();
  const anchor = createHash('sha256').update(resolve(f.cwd, '.keysentry', 'audit.jsonl')).digest('hex').slice(0, 16);
  await mkdir(join(f.options.userDir, 'audit-heads'), { recursive: true });
  await writeFile(join(f.options.userDir, 'audit-heads', `${anchor}.json`), '{"v":1}\n');
  const vault = createFakeVault({ [`audit/head/${anchor}`]: Buffer.from(JSON.stringify({ seq: 3, hash: 'a'.repeat(64) })) });
  f.opened.mockResolvedValue(vault);
  expect(await runCli(['audit', 'verify'], f.options)).toBe(1);
  expect(f.opened).toHaveBeenCalledOnce(); expect(f.output.join('\n')).toMatch(/shorter|failed/i);
});

it('audit verify checks for an anchor even when no marker exists', async () => {
  // Public marker files no longer decide whether audit verification opens the vault.
  const f = await fixture(); f.opened.mockResolvedValue(createFakeVault());
  expect(await runCli(['audit', 'verify'], f.options)).toBe(0);
  expect(f.opened).toHaveBeenCalledOnce();
  expect(f.output.join('\n')).not.toContain('independent vault anchor was not checked');
});

it('audit verification supplies the noninteractive encrypted-file passphrase without opening runtime state', async () => {
  const f = await fixture(); const vault = createFakeVault();
  const audit = createAuditLog({ path: join(f.cwd, '.keysentry', 'audit.jsonl'), vault, deviceKey: () => vaultModule.deviceKey(vault) });
  await audit.append({ kind: 'test', summary: 'Recorded metadata.' }); await audit.checkpoint();
  f.opened.mockImplementation(async opts => {
    expect(opts.passphrase).toBeTypeOf('function');
    const passphrase = await opts.passphrase!();
    try { expect(passphrase.equals(Buffer.from('test-passphrase'))).toBe(true); } finally { passphrase.fill(0); }
    return vault;
  });
  expect(await runCli(['audit', 'verify'], { ...f.options, env: { KEYSENTRY_VAULT: 'encrypted-file', KEYSENTRY_VAULT_PASSPHRASE: 'test-passphrase' }, stdinIsTTY: false, stdoutIsTTY: false })).toBe(0);
  expect(f.opened).toHaveBeenCalledOnce();
});

it('a passphrase set in the environment is used in a terminal too, without a prompt', async () => {
  const f = await fixture(); const vault = createFakeVault();
  const audit = createAuditLog({ path: join(f.cwd, '.keysentry', 'audit.jsonl'), vault, deviceKey: () => vaultModule.deviceKey(vault) });
  await audit.append({ kind: 'test', summary: 'Recorded metadata.' }); await audit.checkpoint();
  f.opened.mockImplementation(async opts => {
    const passphrase = await opts.passphrase!();
    try { expect(passphrase.equals(Buffer.from('test-passphrase'))).toBe(true); } finally { passphrase.fill(0); }
    return vault;
  });
  expect(await runCli(['audit', 'verify'], { ...f.options, env: { KEYSENTRY_VAULT: 'encrypted-file', KEYSENTRY_VAULT_PASSPHRASE: 'test-passphrase' }, stdinIsTTY: true, stdoutIsTTY: true })).toBe(0);
  expect(f.output.join(' ')).not.toContain('Enter the encrypted-file passphrase');
});

it('bin permissions include the adjacent release manifest without granting the installation directory', async () => {
  const f = await fixture(); const bundle = join(f.cwd, 'installation', 'keysentry.mjs');
  // H3: permission grants use the real module path, with an explicit seam for a synthetic installed bundle.
  const permissions = await cliModule.permissionOptionsForBin(['node', bundle, '--cwd', f.cwd], { KEYSENTRY_VAULT: 'memory' }, bundle);
  expect(permissions.readPaths).toContain(join(f.cwd, 'installation', 'release-manifest.json'));
  // A bare invocation now runs Git for the first-run history scan.
  expect(permissions.readPaths).toContain(bundle); expect(permissions.allowChildProcess).toBe(true);
  expect(permissions.writePaths).not.toContain(join(f.cwd, 'installation'));
});

it('signed audit inspection refuses a nonempty log without an anchor in the selected vault', async () => {
  // A checkpoint signature alone cannot establish that this is the complete saved history.
  const f = await fixture(); const vault = createFakeVault();
  const audit = createAuditLog({ path: join(f.cwd, '.keysentry', 'audit.jsonl'), vault, deviceKey: () => vaultModule.deviceKey(vault) });
  await audit.append({ kind: 'test', summary: 'Recorded metadata.' }); await audit.checkpoint();
  const key = await vault.get('key/device-ed25519');
  const envVault = vaultModule.createEnvVault({ KEYSENTRY_DEVICE_KEY: key!.toString('base64') }); key!.fill(0);
  expect(await runCli(['audit', 'verify'], { ...f.options, vault: envVault })).toBe(1);
  expect(f.output.join('\n')).toContain('This audit log has no anchor in your vault; it may have been replaced.');
  expect(f.opened).not.toHaveBeenCalled();
});

it('network applies the team policy file narrowing without opening the vault; verify refuses an unreadable policy file', async () => {
  const f = await fixture();
  await writeFile(join(f.cwd, 'keysentry.yaml'), 'team:\n  enabled: true\n  policyFile: policy.json\nmonitor:\n  webhooks: [https://notify.example.com/hook]\n');
  const policy = { v: 1, teamId: 'team-test-0001', version: 1, prev: null, updatedAt: '2026-10-28T00:00:00.000Z', autopilot: {}, approvals: { required: 1, wideningAdmins: 1 },
    network: { offline: true, allowHosts: ['other.example.com'] }, notify: {}, rotation: {}, audit: {} };
  await writeFile(join(f.cwd, 'policy.json'), JSON.stringify({ policy, signatures: [] }));
  expect(await runCli(['network', '--json'], f.options)).toBe(0);
  const shown = JSON.parse(f.output.join('\n'));
  expect(shown.rules.some((rule: { host: string }) => rule.host === 'notify.example.com')).toBe(false);
  expect(shown.status).toContain('Team policy version 1 narrows these hosts (keysentry policy verify checks its signatures).');
  expect(shown.status.join('\n')).toMatch(/offline/i);
  await writeFile(join(f.cwd, 'policy.json'), '{ not json');
  f.output.length = 0;
  expect(await runCli(['network'], f.options)).toBe(0);
  expect(f.output.join('\n')).toContain('The team policy file could not be used, so changes are paused: The team policy file named in team.policyFile is not valid JSON.');
  expect(await runCli(['verify'], f.options)).toBe(1);
  expect(f.errors.join('\n')).toContain('The online release check did not run because the team policy file could not be used');
  expect(f.opened).not.toHaveBeenCalled();
});
