import { afterEach, expect, test, vi } from 'vitest';
import { request } from 'node:http';
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect } from 'node:net';
import { runInNewContext } from 'node:vm';
import { createApprovalServer } from '../../src/approvals/server.js';
import { ApprovalError, createApprovalService } from '../../src/approvals/service.js';
import { createStateCipher, createStateStore } from '../../src/core/store.js';
import { generateDeviceKey, signDetached } from '../../src/security/index.js';
import type { AuditLog, PasskeyCredential } from '../../src/types.js';

const origin = 'https://approvals.example.org';
const digest = '0'.repeat(64);
const servers: ReturnType<typeof createApprovalServer>[] = [];
const tempDirs: string[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  vi.restoreAllMocks();
});

function service() {
  return {
    describe: vi.fn(async () => ({ digest, kind: 'rotate', keyCount: 3, expiresAt: '2026-10-27T12:10:00.000Z', status: 'pending' as const })),
    challenge: vi.fn(async () => ({ challenge: 'YWJj', rpId: 'approvals.example.org', allowCredentials: [{ type: 'public-key' as const, id: 'Y3JlZA' }] })),
    approveWithPasskey: vi.fn(async () => ({ actionId: 'action-1', digest: '0'.repeat(64), at: '2026-10-27T12:00:00.000Z', by: { kind: 'passkey' as const, credentialId: 'Y3JlZA' } })),
    recordDisarm: vi.fn(async () => undefined),
  };
}

async function start(options: Partial<Parameters<typeof createApprovalServer>[0]> = {}) {
  const svc = service();
  const disarm = vi.fn(async () => undefined);
  const server = createApprovalServer({ service: svc, port: 0, host: '127.0.0.1', publicOrigin: origin, disarm, ...options });
  servers.push(server);
  const { port } = await server.listen();
  return { server, port, svc, disarm };
}

function call(port: number, path: string, options: { method?: string; headers?: Record<string, string>; body?: string } = {}) {
  return new Promise<{ status: number; headers: import('node:http').IncomingHttpHeaders; body: string }>((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method: options.method ?? 'GET', agent: false, headers: { Host: 'approvals.example.org', ...options.headers } }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.end(options.body);
  });
}

const post = { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' }, body: JSON.stringify({ digest }) };
const assertion = JSON.stringify({ digest, credentialId: 'Y3JlZA', clientDataJSON: 'Y2xpZW50', authenticatorData: 'YXV0aA', signature: 'c2ln' });

function raw(port: number, input: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect(port, '127.0.0.1', () => socket.end(input));
    const chunks: Buffer[] = [];
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    socket.on('error', reject);
  });
}

test('server serves only its routes with the security headers and rejects cross-origin POSTs', async () => {
  const { port } = await start();
  const health = await call(port, '/healthz');
  expect(health.status).toBe(200);
  expect(JSON.parse(health.body)).toEqual({ ok: true, version: '0.0.0-dev' });
  for (const response of [health, await call(port, '/missing'), await call(port, '/healthz', { method: 'POST' })]) {
    expect(response.headers['content-security-policy']).toBe("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['referrer-policy']).toBe('no-referrer');
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers['strict-transport-security']).toBe('max-age=31536000');
    expect(response.headers['permissions-policy']).toBe('publickey-credentials-get=(self)');
  }
  expect((await call(port, '/missing')).status).toBe(404);
  expect((await call(port, '/healthz', { method: 'POST' })).status).toBe(405);
  expect((await call(port, '/a/action-1/challenge', { ...post, headers: { ...post.headers, Origin: 'https://elsewhere.example.org' } })).status).toBe(403);
  expect((await call(port, '/a/action-1/challenge', { ...post, headers: { 'Content-Type': 'application/json' } })).status).toBe(403);
});

test('Host must match the public origin even when forwarded headers claim otherwise', async () => {
  const { port } = await start();
  expect((await call(port, '/healthz', { headers: { Host: 'evil.example.org', 'X-Forwarded-Host': 'approvals.example.org' } })).status).toBe(403);
  expect((await call(port, '/healthz', { headers: { Host: 'approvals.example.org:443' } })).status).toBe(403);
});

test('approval page escapes metadata and the script is served separately', async () => {
  const svc = service();
  svc.describe.mockResolvedValue({ digest, kind: '<script>alert("value")</script>', keyCount: 3, expiresAt: '2026-10-27T12:10:00.000Z', status: 'pending' });
  const { port } = await start({ service: svc });
  const page = await call(port, '/a/action-1');
  expect(page.status).toBe(200);
  expect(page.body).toContain('&lt;script&gt;');
  expect(page.body).not.toContain('<script>alert');
  expect(page.body).toContain('3 keys');
  expect(page.body).toContain('2026-10-27T12:10:00.000Z');
  expect(page.body).toContain('<script src="/static/approve.js" defer></script>');
  expect(page.body).toContain(`data-digest="${digest}"`);
  expect((await call(port, '/static/approve.js')).headers['content-type']).toContain('javascript');
});

test('unknown actions and path variants do not serve an approval page', async () => {
  const svc = service();
  svc.describe.mockResolvedValue(null as never);
  const { port } = await start({ service: svc });
  for (const path of ['/a/missing', '/a/action-1/', '/a/action-1?x=1', '/a/%61ction-1', '/a/../disarm']) {
    expect((await call(port, path)).status).toBe(404);
  }
});

test('challenge and assertion routes decode only the bounded canonical base64url body', async () => {
  const { port, svc } = await start();
  const challenge = await call(port, '/a/action-1/challenge', post);
  expect(challenge.status).toBe(200);
  expect(JSON.parse(challenge.body)).toEqual({ challenge: 'YWJj', rpId: 'approvals.example.org', allowCredentials: [{ type: 'public-key', id: 'Y3JlZA' }] });
  expect(svc.challenge).toHaveBeenCalledWith('action-1', digest);
  const result = await call(port, '/a/action-1/assert', { ...post, body: assertion });
  expect(result.status).toBe(200);
  expect(JSON.parse(result.body)).toMatchObject({ ok: true });
  expect(svc.approveWithPasskey).toHaveBeenCalledWith('action-1', { credentialId: 'Y3JlZA', clientDataJSON: Buffer.from('client'), authenticatorData: Buffer.from('auth'), signature: Buffer.from('sig') }, digest);
  for (const body of ['null', '[]', '{', '{"credentialId":"x"}', assertion.replace('Y2xpZW50', 'Y2xpZW50='), assertion.replace('YXV0aA', 'YXV0aB')]) {
    const response = await call(port, '/a/action-1/assert', { ...post, body });
    expect(response.status).toBe(400);
  }
});

test('service rejections show safe outcome text and unexpected errors reveal no diagnostics', async () => {
  const svc = service();
  svc.approveWithPasskey.mockRejectedValueOnce(new ApprovalError('This change can only be approved on your own computer with `keysentry approve`.'));
  svc.approveWithPasskey.mockRejectedValueOnce(new Error('private-value-in-diagnostics'));
  const { port } = await start({ service: svc });
  const refused = await call(port, '/a/action-1/assert', { ...post, body: assertion });
  expect(refused.status).toBe(403);
  expect(JSON.parse(refused.body).text).toContain('keysentry approve');
  const failed = await call(port, '/a/action-1/assert', { ...post, body: assertion });
  expect(failed.status).toBe(500);
  expect(failed.body).not.toContain('private-value');
});

test('challenge and assertion endpoints require the displayed canonical digest', async () => {
  const { port, svc } = await start({ rateLimitPerMinute: 100 });
  for (const invalid of [undefined, null, 0, '', 'a'.repeat(63), 'A'.repeat(64), 'g'.repeat(64)]) {
    const fields = invalid === undefined ? {} : { digest: invalid };
    expect((await call(port, '/a/action-1/challenge', { ...post, body: JSON.stringify(fields) })).status).toBe(400);
    expect((await call(port, '/a/action-1/assert', { ...post, body: JSON.stringify({ ...JSON.parse(assertion), ...fields, ...(invalid === undefined ? { digest: undefined } : {}) }) })).status).toBe(400);
  }
  expect(svc.challenge).not.toHaveBeenCalled();
  expect(svc.approveWithPasskey).not.toHaveBeenCalled();
});

test('a stale page cannot get a challenge or approve a replacement version of the same action', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-approval-stale-page-'));
  tempDirs.push(cwd);
  const key = generateDeviceKey();
  const credential: PasskeyCredential = {
    id: Buffer.from('version-credential').toString('base64url'),
    publicKeyCose: Buffer.concat([Buffer.from('a4010103272006215820', 'hex'), key.publicKeyDer.subarray(-32)]).toString('base64url'),
    alg: -8, signCount: 0, backupEligible: false, rpId: 'approvals.example.org', origins: [origin], label: 'Test key', createdAt: '2026-10-27T12:00:00.000Z',
  };
  const audit: AuditLog = { append: async () => undefined, checkpoint: async () => undefined, verify: async () => ({ ok: true, entries: 0, checkpoints: 0 }) };
  const svc = createApprovalService({
    store: createStateStore({ cwd, cipher: createStateCipher(Buffer.alloc(32, 20)) }), audit, credentials: async () => [credential], deviceKeys: async () => [], rpId: credential.rpId, origins: [origin], now: () => new Date('2026-10-27T12:00:00.000Z'),
  });
  const action = { id: 'versioned-action', kind: 'rotate', clusterIds: ['cluster-1'] };
  const first = await svc.request(action, false);
  const { port } = await start({ service: svc });
  const page = await call(port, '/a/versioned-action');
  const displayedDigest = /data-digest="([a-f0-9]{64})"/.exec(page.body)?.[1];
  expect(displayedDigest).toBe(first.digest);
  const changedAction = { ...action, clusterIds: ['cluster-1', 'cluster-2'] };
  const replacement = await svc.request(changedAction, false);
  expect((await call(port, '/a/versioned-action/challenge', { ...post, body: JSON.stringify({ digest: displayedDigest }) })).status).toBe(403);
  expect(await svc.request(changedAction, false)).toEqual(replacement);
  expect(await svc.status(action.id)).toBe('pending');
  const options = JSON.parse((await call(port, '/a/versioned-action/challenge', { ...post, body: JSON.stringify({ digest: replacement.digest }) })).body);
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin }));
  const authenticatorData = Buffer.concat([createHash('sha256').update(credential.rpId).digest(), Buffer.from([0x05, 0, 0, 0, 1])]);
  const signature = signDetached(key.privateKeyDer, Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJSON).digest()]));
  const signed = { credentialId: credential.id, clientDataJSON: clientDataJSON.toString('base64url'), authenticatorData: authenticatorData.toString('base64url'), signature: signature.toString('base64url') };
  expect((await call(port, '/a/versioned-action/assert', { ...post, body: JSON.stringify({ ...signed, digest: displayedDigest }) })).status).toBe(403);
  expect(await svc.status(action.id)).toBe('pending');
  expect(await svc.approved()).toEqual([]);
  expect((await call(port, '/a/versioned-action/assert', { ...post, body: JSON.stringify({ ...signed, digest: replacement.digest }) })).status).toBe(200);
});

test('HTTP expectation failures carry the same security headers', async () => {
  const { port } = await start();
  for (const expectation of ['100-continue', 'unrecognized-expectation']) {
    const response = await call(port, '/a/action-1/challenge', { ...post, headers: { ...post.headers, Expect: expectation } });
    expect(response.status).toBe(417);
    expect(response.headers['content-security-policy']).toBeDefined();
    expect(response.headers['cache-control']).toBe('no-store');
  }
});

test('CONNECT and malformed HTTP receive fixed responses with security headers', async () => {
  const { port } = await start();
  const connected = await raw(port, 'CONNECT /healthz HTTP/1.1\r\nHost: approvals.example.org\r\n\r\n');
  expect(connected).toContain('405 Method Not Allowed');
  expect(connected).toContain('Method not allowed.\n');
  const malformed = await raw(port, 'GET / HTTP/1.1\r\nHost: approvals.example.org\r\ninvalid header\r\n\r\n');
  expect(malformed).toContain('400 Bad Request');
  expect(malformed).toContain('Content-Security-Policy:');
  expect(malformed).not.toContain('invalid header');
});

test('chunked bodies enforce the byte cap and ambiguous HTTP framing is rejected', async () => {
  const { port, svc } = await start();
  const oversized = await raw(port, 'POST /a/action-1/assert HTTP/1.1\r\nHost: approvals.example.org\r\nOrigin: https://approvals.example.org\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4000\r\n' + ' '.repeat(16384) + '\r\n1\r\n \r\n0\r\n\r\n');
  expect(oversized).toContain('413 Payload Too Large');
  expect(svc.approveWithPasskey).not.toHaveBeenCalled();
  const ambiguous = await raw(port, 'POST /a/action-1/assert HTTP/1.1\r\nHost: approvals.example.org\r\nOrigin: https://approvals.example.org\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n');
  expect(ambiguous).toContain('400 Bad Request');
  expect(ambiguous).toContain('Content-Security-Policy:');
  const duplicate = await raw(port, 'GET /healthz HTTP/1.1\r\nHost: approvals.example.org\r\nHost: evil.example.org\r\nConnection: close\r\n\r\n');
  expect(duplicate).toContain('403 Forbidden');
});

test('real service approves one signed passkey response over HTTP and rejects its replay', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-approval-server-'));
  tempDirs.push(cwd);
  const key = generateDeviceKey();
  const credential: PasskeyCredential = {
    id: Buffer.from('real-credential').toString('base64url'),
    publicKeyCose: Buffer.concat([Buffer.from('a4010103272006215820', 'hex'), key.publicKeyDer.subarray(-32)]).toString('base64url'),
    alg: -8, signCount: 0, backupEligible: false, rpId: 'approvals.example.org', origins: [origin], label: 'Test key', createdAt: '2026-10-27T12:00:00.000Z',
  };
  const audit: AuditLog = { append: async () => undefined, checkpoint: async () => undefined, verify: async () => ({ ok: true, entries: 0, checkpoints: 0 }) };
  let now = new Date('2026-10-27T12:00:00.000Z');
  const svc = createApprovalService({
    store: createStateStore({ cwd, cipher: createStateCipher(Buffer.alloc(32, 19)) }), audit, credentials: async () => [credential], deviceKeys: async () => [], rpId: credential.rpId, origins: [origin], now: () => now,
  });
  const requested = await svc.request({ id: 'real-action', kind: 'rotate', clusterIds: ['cluster-1'] }, false);
  const { port } = await start({ service: svc });
  const options = JSON.parse((await call(port, '/a/real-action/challenge', { ...post, body: JSON.stringify({ digest: requested.digest }) })).body);
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin }));
  const auth = Buffer.concat([createHash('sha256').update(credential.rpId).digest(), Buffer.from([0x05, 0, 0, 0, 1])]);
  const signature = signDetached(key.privateKeyDer, Buffer.concat([auth, createHash('sha256').update(clientDataJSON).digest()]));
  const body = JSON.stringify({ digest: requested.digest, credentialId: credential.id, clientDataJSON: clientDataJSON.toString('base64url'), authenticatorData: auth.toString('base64url'), signature: signature.toString('base64url') });
  expect((await call(port, '/a/real-action/assert', { ...post, body })).status).toBe(200);
  expect(await svc.status('real-action')).toBe('approved');
  expect((await call(port, '/a/real-action/assert', { ...post, body })).status).toBe(403);
  const terminal = await call(port, '/a/real-action');
  expect(terminal.body).toContain('disabled');
  const expired = await svc.request({ id: 'expired-action', kind: 'rotate', clusterIds: ['cluster-1'] }, false);
  now = new Date('2026-10-27T12:10:00.000Z');
  expect((await call(port, '/a/expired-action/challenge', { ...post, body: JSON.stringify({ digest: expired.digest }) })).status).toBe(403);
  expect(await svc.status('expired-action')).toBe('expired');
});

test('JSON routes reject unsupported media, compressed input and oversized bodies', async () => {
  const { port, svc } = await start();
  expect((await call(port, '/a/action-1/challenge', { ...post, headers: { Origin: origin, 'Content-Type': 'text/plain' } })).status).toBe(415);
  expect((await call(port, '/a/action-1/challenge', { ...post, headers: { ...post.headers, 'Content-Encoding': 'gzip' } })).status).toBe(415);
  expect((await call(port, '/a/action-1/assert', { ...post, body: ' '.repeat(16 * 1024 + 1) })).status).toBe(413);
  expect(svc.approveWithPasskey).not.toHaveBeenCalled();
});

test('disarm needs no passkey but needs the confirmation field and audits a hash of the client', async () => {
  const { port, svc, disarm } = await start();
  expect((await call(port, '/disarm')).body).toContain('name="confirm"');
  const form = { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'confirm=wrong' };
  expect((await call(port, '/disarm', form)).status).toBe(400);
  expect(disarm).not.toHaveBeenCalled();
  const response = await call(port, '/disarm', { ...form, body: 'confirm=DISARM' });
  expect(response.status).toBe(200);
  expect(response.body).toContain('Autopilot is off. Nothing will rotate automatically until you re-arm it on your computer.');
  expect(disarm).toHaveBeenCalledTimes(1);
  expect(svc.recordDisarm).toHaveBeenCalledWith(createHash('sha256').update('127.0.0.1').digest('hex'));
  expect(svc.approveWithPasskey).not.toHaveBeenCalled();
});

test('disarm rejects duplicate confirmations and forms larger than one KiB', async () => {
  const { port, disarm } = await start();
  const form = { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' } };
  expect((await call(port, '/disarm', { ...form, body: 'confirm=DISARM&confirm=DISARM' })).status).toBe(400);
  expect((await call(port, '/disarm', { ...form, body: 'confirm=DISARM&padding=' + 'x'.repeat(1024) })).status).toBe(413);
  expect(disarm).not.toHaveBeenCalled();
});

test('rate limit returns 429 after the budget and refills over time', async () => {
  const now = vi.spyOn(Date, 'now').mockReturnValue(1_000_000);
  const { port } = await start({ rateLimitPerMinute: 2 });
  expect((await call(port, '/healthz')).status).toBe(200);
  expect((await call(port, '/healthz')).status).toBe(200);
  expect((await call(port, '/healthz')).status).toBe(429);
  now.mockReturnValue(1_030_000);
  expect((await call(port, '/healthz')).status).toBe(200);
});

test('approval traffic cannot consume either disarm route budget', async () => {
  vi.spyOn(Date, 'now').mockReturnValue(1_000_000);
  const { port, disarm } = await start({ rateLimitPerMinute: 2 });
  expect((await call(port, '/healthz')).status).toBe(200);
  expect((await call(port, '/healthz')).status).toBe(200);
  expect((await call(port, '/healthz')).status).toBe(429);
  expect((await call(port, '/disarm')).status).toBe(200);
  const response = await call(port, '/disarm', {
    method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'confirm=DISARM',
  });
  expect(response.status).toBe(200);
  expect(disarm).toHaveBeenCalledTimes(1);
});

test('GET and POST disarm share ten tokens per minute without consuming approval tokens', async () => {
  const now = vi.spyOn(Date, 'now').mockReturnValue(1_000_000);
  const { port, disarm } = await start({ rateLimitPerMinute: 1 });
  for (let i = 0; i < 9; i++) expect((await call(port, '/disarm')).status).toBe(200);
  expect((await call(port, '/disarm', {
    method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'confirm=DISARM',
  })).status).toBe(200);
  const limited = await call(port, '/disarm');
  expect(limited.status).toBe(429);
  expect(limited.headers['retry-after']).toBe('6');
  expect((await call(port, '/healthz')).status).toBe(200);
  now.mockReturnValue(1_006_000);
  expect((await call(port, '/disarm')).status).toBe(200);
  expect(disarm).toHaveBeenCalledTimes(1);
});

test('disarm budgets are configurable and separate for clients behind the trusted proxy', async () => {
  vi.spyOn(Date, 'now').mockReturnValue(1_000_000);
  const { port } = await start({ rateLimitPerMinute: 1, disarmRateLimitPerMinute: 1, trustProxyHops: 1 });
  const one = { 'X-Forwarded-For': '198.51.100.1' };
  const two = { 'X-Forwarded-For': '198.51.100.2' };
  expect((await call(port, '/disarm', { headers: one })).status).toBe(200);
  expect((await call(port, '/disarm', { headers: one })).status).toBe(429);
  expect((await call(port, '/disarm', { headers: two })).status).toBe(200);
  expect((await call(port, '/healthz', { headers: one })).status).toBe(200);
});

test('approval outcomes and the approved page explain the configured watcher check delay', async () => {
  const svc = service();
  const { port } = await start({ service: svc, watcherCheckMinutes: 3 });
  const outcome = 'Approved. The watcher will carry this out on its next check (within about 3 minutes).';
  const approved = await call(port, '/a/action-1/assert', { ...post, body: assertion });
  expect(JSON.parse(approved.body).text).toBe(outcome);
  svc.describe.mockResolvedValue({ digest, kind: 'rotate', keyCount: 3, expiresAt: '2026-10-27T12:10:00.000Z', status: 'approved' } as never);
  const page = await call(port, '/a/action-1');
  expect(page.body).toContain(outcome);
  expect(page.body).toContain('disabled');
});

test('executed and superseded pages distinguish their terminal outcomes', async () => {
  const svc = service();
  const { port } = await start({ service: svc });
  for (const [status, text] of [
    ['executed', 'Executed. The watcher has carried out this action.'],
    ['superseded', 'This request was replaced by a newer version.'],
  ]) {
    svc.describe.mockResolvedValue({ digest, kind: 'rotate', keyCount: 3, expiresAt: '2026-10-27T12:10:00.000Z', status } as never);
    const page = await call(port, '/a/action-1');
    expect(page.body).toContain(text);
    expect(page.body).toContain('disabled');
  }
});

test('forwarded addresses cannot bypass the bucket unless exactly one proxy hop is trusted', async () => {
  const local = await start({ rateLimitPerMinute: 1 });
  expect((await call(local.port, '/healthz', { headers: { 'X-Forwarded-For': '198.51.100.1' } })).status).toBe(200);
  expect((await call(local.port, '/healthz', { headers: { 'X-Forwarded-For': '198.51.100.2' } })).status).toBe(429);
  const proxied = await start({ rateLimitPerMinute: 1, trustProxyHops: 1 });
  expect((await call(proxied.port, '/healthz', { headers: { 'X-Forwarded-For': '198.51.100.1, 198.51.100.20' } })).status).toBe(200);
  expect((await call(proxied.port, '/healthz', { headers: { 'X-Forwarded-For': '198.51.100.2, 198.51.100.20' } })).status).toBe(429);
  expect((await call(proxied.port, '/healthz', { headers: { 'X-Forwarded-For': '198.51.100.21' } })).status).toBe(200);
});

test('invalid or oversized forwarding headers fall back to the socket client budget', async () => {
  vi.spyOn(Date, 'now').mockReturnValue(1_000_000);
  const { port } = await start({ rateLimitPerMinute: 1, trustProxyHops: 1 });
  expect((await call(port, '/healthz')).status).toBe(200);
  for (const forwarded of ['198.51.100.1, invalid', 'not-an-address', '198.51.100.1,' + ' '.repeat(4096) + '198.51.100.2']) {
    expect((await call(port, '/healthz', { headers: { 'X-Forwarded-For': forwarded } })).status).toBe(429);
  }
});

test('expectation handling charges the selected route budget', async () => {
  vi.spyOn(Date, 'now').mockReturnValue(1_000_000);
  const { port } = await start({ rateLimitPerMinute: 1, disarmRateLimitPerMinute: 1 });
  expect((await call(port, '/healthz')).status).toBe(200);
  const response = await call(port, '/disarm', {
    method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded', Expect: '100-continue' }, body: 'confirm=DISARM',
  });
  expect(response.status).toBe(417);
  expect((await call(port, '/disarm')).status).toBe(429);
});

test('HTTP localhost omits HSTS and invalid public origins are refused', async () => {
  const { port } = await start({ publicOrigin: 'http://localhost:8000' });
  expect((await call(port, '/healthz', { headers: { Host: 'localhost:8000' } })).headers['strict-transport-security']).toBeUndefined();
  for (const publicOrigin of ['https://example.org/path', 'https://user:pass@example.org', 'http://example.org', 'https://example.org?x=1']) {
    expect(() => createApprovalServer({ service: service(), port: 0, publicOrigin, disarm: async () => undefined })).toThrow();
  }
});

test('static approval script performs the passkey ceremony and shows the result without inline code', async () => {
  const { port } = await start();
  const script = (await call(port, '/static/approve.js')).body;
  let click: (() => Promise<void>) | undefined;
  const button = { disabled: false, dataset: { digest }, addEventListener: (_event: string, fn: () => Promise<void>) => { click = fn; } };
  const result = { textContent: '' };
  const fetches: { path: string; options: { body: string } }[] = [];
  let requested: unknown;
  runInNewContext(script, {
    document: { getElementById: (id: string) => id === 'approve' ? button : result },
    location: { pathname: '/a/action-1' },
    atob: (value: string) => Buffer.from(value, 'base64').toString('binary'),
    btoa: (value: string) => Buffer.from(value, 'binary').toString('base64'),
    Uint8Array,
    navigator: { credentials: { get: async (options: unknown) => {
      requested = options;
      return { rawId: Uint8Array.from(Buffer.from('cred')).buffer, response: { clientDataJSON: Uint8Array.from(Buffer.from('client')).buffer, authenticatorData: Uint8Array.from(Buffer.from('auth')).buffer, signature: Uint8Array.from(Buffer.from('sig')).buffer } };
    } } },
    fetch: async (path: string, options: { body: string }) => {
      fetches.push({ path, options });
      return { ok: true, json: async () => path.endsWith('/challenge') ? { challenge: 'YWJj', rpId: 'approvals.example.org', allowCredentials: [{ type: 'public-key', id: 'Y3JlZA' }] } : { ok: true, text: 'Approved.' } };
    },
  });
  expect(click).toBeTypeOf('function');
  await click!();
  expect(requested).toMatchObject({ publicKey: { rpId: 'approvals.example.org', userVerification: 'required' } });
  expect(fetches.map((item) => item.path)).toEqual(['/a/action-1/challenge', '/a/action-1/assert']);
  expect(JSON.parse(fetches[0]!.options.body)).toEqual({ digest });
  expect(JSON.parse(fetches[1]!.options.body)).toEqual({ digest, credentialId: 'Y3JlZA', clientDataJSON: 'Y2xpZW50', authenticatorData: 'YXV0aA', signature: 'c2ln' });
  expect(result.textContent).toBe('Approved.');
});

test('healthz answers 503 with a fixed problem code while the watcher cannot work, and reports offline mode (review H1, L9)', async () => {
  let health: import('../../src/approvals/server.js').ServerHealth = { problem: { code: 'network', reason: 'Fixed reason.' } };
  const { port } = await start({ health: () => health });
  const sick = await call(port, '/healthz');
  expect(sick.status).toBe(503);
  expect(JSON.parse(sick.body)).toEqual({ ok: false, version: '0.0.0-dev', problem: 'network', reason: 'Fixed reason.' });
  expect(sick.headers['cache-control']).toBe('no-store');
  health = { feedsOffline: true };
  expect(JSON.parse((await call(port, '/healthz')).body)).toEqual({ ok: true, version: '0.0.0-dev', feeds: 'offline' });
  health = {};
  expect(JSON.parse((await call(port, '/healthz')).body)).toEqual({ ok: true, version: '0.0.0-dev' });
});
