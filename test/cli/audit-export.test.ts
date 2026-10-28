import { randomBytes, createHmac } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import type { Server, Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { createServer as createTlsServer } from 'node:tls';
import { Command } from 'commander';
import { afterEach, describe, expect, it } from 'vitest';
import { auditExportSourceId, registerAuditExportCommands, runAuditExportForRuntime } from '../../src/cli/audit-export.js';
import { CliError } from '../../src/cli/errors.js';
import { createRuntime } from '../../src/cli/runtime.js';
import { assertHumanForMutation, AgentRefusalError } from '../../src/safety/index.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { FakeHttp, silentLogger, text } from '../helpers/fake-http.js';
import { unexpected } from '../audit-export/helpers.js';

const cert = await readFile(new URL('../fixtures/tls/cert.pem', import.meta.url), 'utf8');
const key = await readFile(new URL('../fixtures/tls/key.pem', import.meta.url), 'utf8');
const dirs: string[] = [];
const servers: { server: Server; sockets: Set<Socket> }[] = [];
afterEach(async () => {
  for (const { server, sockets } of servers.splice(0)) {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

const secretBytes = randomBytes(32);
const WHSEC = `whsec_${secretBytes.toString('base64')}`;

async function syslogServer() {
  const received: Buffer[] = [];
  const sockets = new Set<Socket>();
  const server = createTlsServer({ key, cert }, socket => {
    sockets.add(socket);
    const chunks: Buffer[] = [];
    socket.on('data', chunk => chunks.push(chunk));
    socket.on('error', () => {});
    socket.on('end', () => { received.push(Buffer.concat(chunks)); socket.end(); });
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  servers.push({ server, sockets });
  return { port: (server.address() as { port: number }).port, received };
}

async function fixture(options: { exportYaml?: string; webhookStatus?: number } = {}) {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-audit-export-cli-'));
  dirs.push(cwd);
  const syslog = await syslogServer();
  await writeFile(join(cwd, 'ca.pem'), cert);
  await writeFile(join(cwd, 'keysentry.yaml'), options.exportYaml ?? [
    'network:', '  caFile: ca.pem',
    'audit:', '  export:',
    '    - kind: webhook', '      id: hook', '      url: https://hooks.example.com/audit', '      signing: hmac-sha256',
    '    - kind: syslog', '      id: siem', '      host: localhost', `      port: ${syslog.port}`,
  ].join('\n'));
  const http = new FakeHttp().on('POST', /^https:\/\/hooks\.example\.com\/audit$/, () => text(options.webhookStatus ?? 200, ''));
  const vault = createFakeVault();
  const rt = await createRuntime({ cwd, userDir: join(cwd, 'user'), vault, hosts: [], env: {}, http, log: silentLogger, stdinIsTTY: true, stdoutIsTTY: true });
  await rt.audit.append({ kind: 'scan', summary: 'Scanned 0 services.' });
  await rt.audit.append({ kind: 'vault-set', summary: 'Credential stored.', data: { name: 'OPENAI_API_KEY', role: 'write' } });
  const output: string[] = [];
  const diagnostics: string[] = [];
  let exitCode = 0;
  async function run(args: string[], extra: { env?: NodeJS.ProcessEnv; stdin?: string; tty?: boolean } = {}) {
    output.length = 0; diagnostics.length = 0; exitCode = 0;
    const program = new Command().exitOverride().option('--json');
    program.configureOutput({ writeOut: line => output.push(line), writeErr: () => {} });
    program.command('audit').command('verify');
    const env = extra.env ?? {};
    const tty = extra.tty ?? true;
    const promptIO = extra.stdin === undefined ? undefined
      : { input: Object.assign(Readable.from([Buffer.from(extra.stdin)]), { isTTY: false }) as unknown as NodeJS.ReadStream };
    registerAuditExportCommands(program, {
      getRuntime: async () => rt,
      emit: (value, human) => output.push(program.opts().json ? JSON.stringify(value) : human ?? JSON.stringify(value)),
      diagnostic: line => diagnostics.push(line),
      human: (action, allowPipedStdin) => assertHumanForMutation({ env, action, allowPipedStdin, stdinIsTTY: tty && extra.stdin === undefined, stdoutIsTTY: tty }),
      setExit: code => { exitCode = code; },
      env, ...(promptIO ? { promptIO } : {}), sleep: async () => {},
    });
    await program.parseAsync(args, { from: 'user' });
    return exitCode;
  }
  return { cwd, rt, http, vault, syslog, output, diagnostics, run };
}

describe('keysentry audit export', () => {
  it('stores the webhook secret through --stdin, then sends to every target and reports per target', async () => {
    const f = await fixture();
    expect(await f.run(['audit', 'export', 'secret', 'hook', 'hmac-secret', '--stdin'], { stdin: `${WHSEC}\n` })).toBe(0);
    expect(f.output).toEqual(['Stored the hmac-secret for hook.']);
    expect((await f.vault.get('audit-export/hook/hmac-secret'))!.toString()).toBe(WHSEC);

    expect(await f.run(['audit', 'export'])).toBe(0);
    const report = f.output.join('\n');
    expect(report).toMatch(/^Audit log verified: \d+ entries\./);
    expect(report).toMatch(/hook \(webhook\): sent \d+ records \(seq 1-\d+\) in 1 batch; up to date\./);
    expect(report).toMatch(/siem \(syslog\): sent \d+ records \(seq 1-\d+\) in 1 batch; up to date\./);

    const call = f.http.calls.find(request => request.url === 'https://hooks.example.com/audit')!;
    const signature = createHmac('sha256', secretBytes).update(`${call.headers!['webhook-id']}.${call.headers!['webhook-timestamp']}.${call.body}`).digest('base64');
    expect(call.headers!['webhook-signature']).toBe(`v1,${signature}`);
    expect(call.headers!['webhook-id']).toMatch(new RegExp(`^${auditExportSourceId(f.rt.projectId)}_[0-9a-f]{16}_1-\\d+$`));
    const records = (JSON.parse(call.body!) as { data: { records: { seq: number; kind: string }[] } }).data.records;
    expect(records.map(record => record.kind)).toEqual(expect.arrayContaining(['scan', 'vault-set', 'audit-export:credential-set', 'checkpoint']));
    expect(f.syslog.received).toHaveLength(1);
    expect(f.syslog.received[0]!.toString('utf8')).toMatch(/\[keysentry@32473 seq="1" kind="scan" log="[0-9a-f]{16}"\]/);
    // The secret never reaches a record, a request or the output.
    expect(JSON.stringify([f.http.calls, f.output, f.syslog.received.map(bytes => bytes.toString())])).not.toContain(WHSEC);
    const receipt = await readFile(join(f.rt.paths.dir, 'network.jsonl'), 'utf8');
    expect(receipt).toContain(`syslog:localhost:${f.syslog.port}`);
    expect(receipt).toContain('hooks.example.com');

    expect(await f.run(['audit', 'export'])).toBe(0);
    expect(f.output.join('\n')).toMatch(/hook \(webhook\): (up to date|sent 1 record)/);
  });

  it('shows a dry run without sending, and status afterwards', async () => {
    const f = await fixture();
    expect(await f.run(['audit', 'export', '--dry-run'])).toBe(0);
    const plan = f.output.join('\n');
    expect(plan).toContain('Dry run: nothing was sent and no progress was saved.');
    expect(plan).toContain('hook: signed webhook (hmac-sha256) to hooks.example.com');
    expect(plan).not.toContain('/audit');
    expect(plan).toContain('Credentials: missing.');
    expect(plan).toMatch(/batch seq 1-\d+: \d+ records, \d+ bytes -> localhost:\d+/);
    expect(plan).toContain('#2 ');
    expect(f.http.calls).toEqual([]);
    expect(f.syslog.received).toEqual([]);

    expect(await f.run(['audit', 'export', 'status'])).toBe(0);
    expect(f.output.join('\n')).toMatch(/siem: syslog over TLS to localhost:\d+\n {2}At seq 0; \d+ waiting\. Last success: never\./);
  });

  it('fails a target without blocking the others, and exits 1', async () => {
    const f = await fixture({ webhookStatus: 503 });
    await f.run(['audit', 'export', 'secret', 'hook', 'hmac-secret', '--stdin'], { stdin: WHSEC });
    expect(await f.run(['audit', 'export'])).toBe(1);
    const report = f.output.join('\n');
    expect(report).toContain('hook (webhook): failed. The webhook receiver answered HTTP 503.');
    expect(report).toMatch(/entries wait and will be sent in order next time; nothing is skipped\./);
    expect(report).toMatch(/siem \(syslog\): sent \d+ records/);
    expect(await f.run(['audit', 'export', 'status'])).toBe(0);
    expect(f.output.join('\n')).toContain('Last problem (1 failed attempt): The webhook receiver answered HTTP 503.');
  });

  it('refuses to export from a log that does not verify', async () => {
    const f = await fixture();
    const log = await readFile(f.rt.paths.audit, 'utf8');
    await writeFile(f.rt.paths.audit, log.replace('Scanned 0 services.', 'Scanned 9 services.'));
    const error = await f.run(['audit', 'export']).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(CliError);
    expect((error as Error).message).toMatch(/^The audit log did not verify, so nothing was exported/);
    expect(f.http.calls).toEqual([]);
    expect(f.syslog.received).toEqual([]);
  });

  it('prints secret-free JSON with --json', async () => {
    const f = await fixture();
    await f.run(['audit', 'export', 'secret', 'hook', 'hmac-secret', '--stdin'], { stdin: WHSEC });
    await f.run(['--json', 'audit', 'export']);
    const result = JSON.parse(f.output[0]!) as { targets: { id: string; status: string }[] };
    expect(result.targets.map(target => [target.id, target.status])).toEqual([['hook', 'sent'], ['siem', 'sent']]);
    expect(f.output[0]).not.toContain(WHSEC);
  });

  it('says so when no targets are configured', async () => {
    const f = await fixture({ exportYaml: 'audit:\n  export: []\n' });
    expect(await f.run(['audit', 'export'])).toBe(0);
    expect(f.output).toEqual(['No audit export targets are configured. Add them under audit.export in keysentry.yaml.']);
    expect(await runAuditExportForRuntime(f.rt)).toBeNull();
  });

  it('keeps credential changes away from AI agents and non-terminals, and checks names and formats', async () => {
    const f = await fixture();
    await expect(f.run(['audit', 'export', 'secret', 'hook', 'hmac-secret', '--stdin'], { stdin: WHSEC, env: { CLAUDE_CODE_CHILD_SESSION: '1' } }))
      .rejects.toBeInstanceOf(AgentRefusalError);
    await expect(f.run(['audit', 'export', 'secret', 'hook', 'hmac-secret'], { tty: false })).rejects.toBeInstanceOf(AgentRefusalError);
    await expect(f.run(['audit', 'export', 'secret', 'nope', 'bearer', '--stdin'], { stdin: 'x' })).rejects.toThrow('No audit export target has that id');
    await expect(f.run(['audit', 'export', 'secret', 'siem', 'bearer', '--stdin'], { stdin: 'x' })).rejects.toThrow('needs no stored credential');
    await expect(f.run(['audit', 'export', 'secret', 'hook', 'bearer', '--stdin'], { stdin: 'x' })).rejects.toThrow('takes these credentials: hmac-secret');
    const weak = await f.run(['audit', 'export', 'secret', 'hook', 'hmac-secret', '--stdin'], { stdin: 'whsec_c2hvcnQtc2VjcmV0' }).then(unexpected, (caught: unknown) => caught as Error);
    expect(weak.message).toContain('whsec_ followed by base64 of 24 to 64 random bytes');
    expect(weak.message).not.toContain('c2hvcnQtc2VjcmV0');
    expect(await f.vault.get('audit-export/hook/hmac-secret')).toBeNull();
    await f.run(['audit', 'export', 'secret', 'hook', 'hmac-secret', '--stdin'], { stdin: WHSEC });
    expect(await f.run(['audit', 'export', 'secret', 'hook', 'hmac-secret', '--remove'])).toBe(0);
    expect(f.output).toEqual(['Removed the hmac-secret for hook.']);
    expect(await f.vault.get('audit-export/hook/hmac-secret')).toBeNull();
    // Sending itself changes nothing an agent could abuse: it is not gated.
    expect(await f.run(['audit', 'export', '--dry-run'], { env: { CLAUDE_CODE_CHILD_SESSION: '1' }, tty: false })).toBe(0);
  });

  it('refuses a syslog target that a configured proxy would cover, until it is listed in noProxy', async () => {
    const f = await fixture();
    const env = { HTTPS_PROXY: 'http://proxy.internal:3128' };
    await f.run(['audit', 'export', 'secret', 'hook', 'hmac-secret', '--stdin'], { stdin: WHSEC });
    expect(await f.run(['audit', 'export', '--target', 'siem'], { env })).toBe(1);
    expect(f.output.join('\n')).toContain('Add localhost to network.noProxy');
    expect(f.syslog.received).toEqual([]);
    expect(await f.run(['audit', 'export', '--target', 'siem'], { env: { ...env, NO_PROXY: 'localhost' } })).toBe(0);
    expect(f.syslog.received).toHaveLength(1);
  });

  it('exports after a watcher cycle through the runtime hook, signing the tail first', async () => {
    const f = await fixture();
    await f.vault.set('audit-export/hook/hmac-secret', Buffer.from(WHSEC));
    const result = await runAuditExportForRuntime(f.rt);
    expect(result!.targets.map(target => target.status)).toEqual(['sent', 'sent']);
    const lines = (await readFile(f.rt.paths.audit, 'utf8')).trimEnd().split('\n');
    expect(JSON.parse(lines.at(-1)!).kind).toBe('checkpoint');
    expect(result!.targets[0]!.cursor).toBe(lines.length);
  });
});
