import { afterEach, expect, test } from 'vitest';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRuntime, runCli } from '../../src/cli/index.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { FakeHttp, silentLogger, text } from '../helpers/fake-http.js';
import { configureApprovalRelay } from '../../src/cli/phase2.js';
import { loadConfigMetadata } from '../../src/cli/config.js';
import { verifyWatcherResume } from '../../src/watcher/index.js';
import { createApprovalService } from '../../src/approvals/index.js';
import { createFakeAuthenticator } from '../dashboard/helpers/fake-authenticator.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
async function context(interactive = true) {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-phase2-commands-')); dirs.push(cwd);
  const http = new FakeHttp();
  const runtime = await createRuntime({ cwd, userDir: join(cwd, 'user'), vault: createFakeVault(), hosts: [], env: {}, http, log: silentLogger, stdinIsTTY: interactive, stdoutIsTTY: interactive });
  const output: string[] = []; const errors: string[] = [];
  return { runtime, http, output, errors, options: { runtime, env: {}, stdinIsTTY: true, stdoutIsTTY: true, output: (line: string) => output.push(line), error: (line: string) => errors.push(line) } };
}

function registrationRequest(url: URL, headers: Record<string, string> = {}, body?: unknown) {
  return new Promise<{ status: number; headers: import('node:http').IncomingHttpHeaders; body: string }>((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port: url.port, path: url.pathname + url.search,
      method: body === undefined ? 'GET' : 'POST', headers: { Host: url.host, ...headers } }, response => {
      let text = ''; response.setEncoding('utf8'); response.on('data', chunk => { text += chunk; });
      response.on('end', () => resolve({ status: response.statusCode!, headers: response.headers, body: text }));
    });
    req.on('error', reject); req.end(body === undefined ? undefined : JSON.stringify(body));
  });
}

test('passkey registration opens a private launcher file and never prints its bearer URL', async () => {
  const c = await context(); const human = createFakeAuthenticator(); let path = '', bearer = '';
  const code = await runCli(['passkey', 'register', '--json'], { ...c.options, openBrowser: async value => {
    path = value;
    const html = await readFile(path, 'utf8');
    expect(html).toContain('http-equiv="refresh"');
    bearer = /href="([^"]+)"/.exec(html)![1]!.replaceAll('&amp;', '&');
    if (process.platform !== 'win32') expect((await stat(path)).mode & 0o777).toBe(0o600);
    const ready = new URL(bearer);
    const page = await registrationRequest(ready);
    const cookie = page.headers['set-cookie']![0]!.split(';')[0]!;
    const csrf = /name="csrf" content="([A-Za-z0-9_-]+)"/.exec(page.body)![1]!;
    const headers = { Cookie: cookie, Origin: ready.origin, 'Content-Type': 'application/json', 'X-Keysentry-CSRF': csrf };
    const options = await registrationRequest(new URL('/options', ready), headers, {});
    const response = human.registration(JSON.parse(options.body).challenge, ready.origin).response;
    expect((await registrationRequest(new URL('/register', ready), headers, response)).status).toBe(200);
  } });
  expect(code).toBe(0);
  expect(path).toMatch(/\.html$/);
  expect(path).toContain(c.runtime.userDir);
  expect(c.errors.join('\n')).toContain(path);
  const output = [...c.output, ...c.errors].join('\n');
  expect(output).not.toContain(bearer); expect(output).not.toContain('?token=');
  await expect(readFile(path)).rejects.toMatchObject({ code: 'ENOENT' });
});

test('passkey registration removes its launcher on cancellation', async () => {
  const c = await context(); let path = '';
  expect(await runCli(['passkey', 'register', '--json'], { ...c.options, openBrowser: async value => {
    path = value; expect(await readFile(path, 'utf8')).toContain('http-equiv="refresh"'); process.emit('SIGINT');
  } })).toBe(0);
  expect(JSON.parse(c.output.join('\n')).status).toBe('cancelled');
  await expect(readFile(path)).rejects.toMatchObject({ code: 'ENOENT' });
});

test('passkey registration removes its launcher when an injected opener fails', async () => {
  const c = await context(); let path = '';
  expect(await runCli(['passkey', 'register', '--json'], { ...c.options, openBrowser: async value => {
    path = value; await readFile(path); throw new Error('Opener unavailable');
  } })).toBe(1);
  expect(path).toMatch(/\.html$/);
  await expect(readFile(path)).rejects.toMatchObject({ code: 'ENOENT' });
  expect([...c.output, ...c.errors].join('\n')).not.toContain('?token=');
});

test('new command groups are exposed in top-level help', async () => {
  const c = await context();
  expect(await runCli(['--help'], c.options)).toBe(0);
  for (const name of ['arm', 'disarm', 'autopilot', 'watch', 'watcher', 'notify', 'passkey']) expect(c.output.join('\n')).toContain(name);
});

test('arm reaches the recent drill gate and refuses remote policy widening', async () => {
  const c = await context();
  expect(await runCli(['arm'], c.options)).toBe(1);
  expect(c.errors.join('\n')).toMatch(/drill.*24 hours/);
  c.errors.length = 0;
  expect(await runCli(['arm', '--relay'], c.options)).toBe(1);
  expect(c.errors.join('\n')).toMatch(/local/);
});

test('disarm and status use the same encrypted local state', async () => {
  const c = await context();
  expect(await runCli(['disarm'], c.options)).toBe(0);
  expect(c.output.join('\n')).toMatch(/disarmed/i);
  c.output.length = 0;
  expect(await runCli(['autopilot', 'status', '--json'], c.options)).toBe(0);
  expect(JSON.parse(c.output.join('\n')).disarmed).toBe(true);
});

test('shared CLI autopilot manager reports saved notification freshness to dashboard consumers', async () => {
  const c = await context(), at = '2026-10-27T12:00:00Z';
  await c.runtime.store.writeJson('plan', join(c.runtime.paths.dir, 'notification-messages.json'), { lastSuccessAt: at });
  const { createCliAutopilotManager } = await import('../../src/cli/phase2.js');
  expect(createCliAutopilotManager).toBeTypeOf('function');
  expect((await createCliAutopilotManager(c.runtime).status()).lastNotificationSuccess).toBe(at);
});

test('remote disarm publishes the watcher-bound v2 envelope', async () => {
  const c = await context();
  c.runtime.config.settings.notify.relay = { server: 'https://ntfy.sh' };
  await c.runtime.vault.set('notify/relay/topic', Buffer.from('saved-topic'));
  c.http.on('POST', /ntfy\.sh/, () => text(200, '{}'));
  expect(await runCli(['disarm', '--relay'], c.options)).toBe(0);
  expect(JSON.parse(c.http.calls.find(call => call.method === 'POST')!.body!)).toMatchObject({
    type: 'keysentry-disarm', v: 2, watcherId: c.runtime.projectId,
  });
  expect(c.output.join('\n')).toMatch(/next check/);
});

test('autopilot resume publishes a watcher-bound recovery message and reports next-check delivery', async () => {
  const c = await context();
  c.runtime.config.settings.notify.relay = { server: 'https://ntfy.sh' };
  await c.runtime.vault.set('notify/relay/topic', Buffer.from('saved-topic'));
  c.http.on('POST', /ntfy\.sh/, () => text(200, '{}'));
  expect(await runCli(['autopilot', 'resume', '--relay'], c.options)).toBe(0);
  const message = JSON.parse(c.http.calls.find(call => call.method === 'POST')!.body!);
  const key = await c.runtime.signingKey();
  expect(verifyWatcherResume(message, { watcherId: c.runtime.projectId, trustedKeyIds: [key.keyId],
    deviceKeys: [{ keyId: key.keyId, publicKeyDer: key.publicKeyDer }], now: c.runtime.now() }).ok).toBe(true);
  expect(c.output.join('\n')).toMatch(/published.*next check/i);
});

test('autopilot resume refuses missing relay and publication failure without success output', async () => {
  const c = await context();
  expect(await runCli(['autopilot', 'resume', '--relay'], c.options)).toBe(1);
  expect(c.output).toEqual([]);
  c.runtime.config.settings.notify.relay = { server: 'https://ntfy.sh' };
  await c.runtime.vault.set('notify/relay/topic', Buffer.from('saved-topic'));
  c.http.on('POST', /ntfy\.sh/, () => text(503, 'unavailable'));
  expect(await runCli(['autopilot', 'resume', '--relay'], c.options)).toBe(1);
  expect(c.output).toEqual([]);
});

test('approve --relay displays the bound keys and still asks confirmation with --yes before publishing', async () => {
  const c = await context();
  c.runtime.config.settings.notify.relay = { server: 'https://ntfy.sh' };
  await c.runtime.vault.set('notify/relay/topic', Buffer.from('saved-topic'));
  const action = { id: 'relay-action', kind: 'autopilot', clusterIds: ['bound-cluster'],
    clusters: [{ clusterId: 'bound-cluster', hint: 'sk-...last' }], planHash: 'a'.repeat(64) };
  const key = await c.runtime.signingKey();
  const service = createApprovalService({ store: c.runtime.store, audit: c.runtime.audit, credentials: async () => [],
    deviceKeys: async () => [{ keyId: key.keyId, publicKeyDer: key.publicKeyDer }], rpId: 'localhost', origins: ['http://localhost'] });
  const request = await service.request(action, false);
  await c.runtime.store.writeJson('pending', join(c.runtime.paths.dir, 'watcher-approvals.json'), { actions: [{ action, request }] });
  expect(await runCli(['approve', action.id, '--relay', '--yes'], { ...c.options, confirmAction: async id => {
    expect(id).toBe(action.id); expect(c.errors.join('\n')).toContain('bound-cluster (sk-...last)'); return false;
  } })).toBe(0);
  expect(c.output.join('\n')).toContain('Approval cancelled.');
  expect(c.http.calls).toEqual([]);
  expect(await service.status(action.id)).toBe('pending');
});

test('new local-only mutations refuse coding-agent environments before work', async () => {
  const c = await context();
  for (const args of [['arm'], ['disarm'], ['notify', 'add', 'console'], ['notify', 'remove', 'one'], ['passkey', 'register'], ['passkey', 'remove', 'one'], ['watcher', 'setup']]) {
    c.errors.length = 0;
    expect(await runCli(args, { ...c.options, env: { CODEX_THREAD_ID: 'present' } })).toBe(1);
    expect(c.errors.join('\n')).toMatch(/agent|human|terminal/i);
  }
});

test('watch --once accepts a noninteractive service without an agent marker', async () => {
  const c = await context(false);
  expect(await runCli(['watch', '--once'], { ...c.options, stdinIsTTY: false, stdoutIsTTY: false })).toBe(2);
  // With no armed plan or notification history the actual watcher reports alert-only.
  expect(c.errors.join('\n')).not.toMatch(/interactive terminal|coding agent/);
  expect(await c.runtime.store.readJson('plan', join(c.runtime.paths.dir, 'watcher-tick.json'))).not.toBeNull();
});

test.each([['watch'], ['watch', '--once']])('watch refuses an agent marker before watcher work: %s', async (...args) => {
  const c = await context();
  expect(await runCli(args as string[], { ...c.options, stdinIsTTY: false, stdoutIsTTY: false, env: { CODEX_THREAD_ID: 'present' } })).toBe(1);
  expect(c.errors.join('\n')).toMatch(/coding agent/);
  expect(await c.runtime.store.readJson('plan', join(c.runtime.paths.dir, 'watcher-tick.json'))).toBeNull();
});

test('local watcher setup creates its relay topic privately and saves only the server in YAML', async () => {
  const c = await context();
  await configureApprovalRelay(c.runtime, 'https://relay.example.test');
  const topic = await c.runtime.vault.get('notify/relay/topic');
  expect(topic?.toString()).toMatch(/^[A-Z2-7]{32}$/);
  expect((await loadConfigMetadata({ cwd: c.runtime.config.cwd, env: {} })).settings.notify.relay).toEqual({ server: 'https://relay.example.test' });
  const before = topic?.toString();
  await configureApprovalRelay(c.runtime, 'https://relay.example.test');
  expect((await c.runtime.vault.get('notify/relay/topic'))?.toString()).toBe(before);
});

test('watcher setup JSON refusal cannot export deploy secrets or change relay settings', async () => {
  const c = await context();
  expect(await runCli(['watcher', 'setup', '--relay-server', 'https://relay.example.test', '--json'], c.options)).toBe(1);
  expect(c.output).toEqual([]);
  expect(await c.runtime.vault.get('notify/relay/topic')).toBeNull();
});

test('public-origin passkey registration explains the dashboard limit and notify list has metadata only', async () => {
  const c = await context();
  expect(await runCli(['passkey', 'register', '--origin', 'https://watcher.example.test', '--json'], c.options)).toBe(0);
  // Dashboard enrollment is removed; registration requires a human terminal.
  expect(c.output.join('\n')).toContain('human terminal');
  c.output.length = 0;
  expect(await runCli(['notify', 'list', '--json'], c.options)).toBe(0);
  expect(JSON.parse(c.output.join('\n'))).toEqual([]);
});
