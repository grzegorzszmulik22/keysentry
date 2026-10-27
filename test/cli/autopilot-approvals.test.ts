import { afterEach, describe, expect, test } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createStateCipher, createStateStore } from '../../src/core/index.js';
import { canonicalJson, generateDeviceKey, signDetached } from '../../src/security/index.js';
import { createApprovalService, createRelay } from '../../src/approvals/index.js';
import { createGuardedHttp } from '../../src/net/index.js';
import type { ApprovalAction } from '../../src/approvals/index.js';
import type { AuditEvent, AuditLog } from '../../src/types.js';
import { FakeHttp, json, text } from '../helpers/fake-http.js';
import { APPROVAL_REQUEST_PREFIX } from '../../src/cli/watcher.js';
import { approveAutopilot, type AutopilotApprovalDependencies } from '../../src/cli/autopilot-approvals.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
const action: ApprovalAction = { id: 'autopilot-action', kind: 'autopilot', clusterIds: ['openai-key', 'openrouter-key'],
  clusters: [{ clusterId: 'openai-key', hint: 'sk-...abcd' }, { clusterId: 'openrouter-key', hint: null }], planHash: 'a'.repeat(64) };
async function fixture() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-cli-approval-')); dirs.push(cwd);
  let current = new Date('2026-10-27T12:00:00.000Z'); const key = generateDeviceKey(); const watcher = generateDeviceKey();
  const store = createStateStore({ cwd, cipher: createStateCipher(Buffer.alloc(32, 6)) });
  const events: AuditEvent[] = [];
  const audit: AuditLog = { append: async event => { events.push(event); }, checkpoint: async () => {}, verify: async () => ({ ok: true, entries: events.length, checkpoints: 0 }) };
  const deviceKeys = async () => [{ keyId: key.keyId, publicKeyDer: key.publicKeyDer }]; const now = () => current;
  const service = createApprovalService({ store, audit, deviceKeys, credentials: async () => [], now, rpId: 'localhost', origins: ['http://localhost'] });
  const fake = new FakeHttp().on('POST', /^https:\/\/ntfy.sh\//, () => json(200, {}));
  const receipt: unknown[] = [];
  const http = createGuardedHttp(fake, { rules: [{ host: 'ntfy.sh', owner: 'user', purpose: 'approval relay you configured' }],
    trustedUrls: ['https://ntfy.sh/private-topic', 'https://ntfy.sh/private-topic/json?poll=1'],
    receipt: { record: async entry => { receipt.push(entry); }, summarize: async () => [] } });
  const gates: string[] = []; const reviews: unknown[] = [];
  const deps: AutopilotApprovalDependencies = { store, audit, http, deviceKey: async () => key, watcherPublicKeys: async () => [watcher.publicKeyDer],
    deviceKeys, passkeys: async () => [], now, relay: { server: 'https://ntfy.sh', topic: 'private-topic', token: 'private-token' },
    assertHuman: action => { gates.push(action); }, review: request => { reviews.push(request); }, confirm: async () => true };
  const request = await service.request(action, false);
  const saveLocal = async (changes = {}) => { await store.writeJson('pending', join(store.paths.dir, 'watcher-approvals.json'), { actions: [{ action, request: { ...request, ...changes } }] }); };
  const requestMessage = (changes: Record<string, unknown> = {}, signedChanges: Record<string, unknown> = {}, signing = watcher) => {
    const metadata = { actionId: request.actionId, digest: request.digest, expiresAt: request.expiresAt, kind: 'autopilot', keyCount: 2,
      clusters: action.clusters, watcherCheckMinutes: 10, ...changes };
    const signed = { request: metadata, keyId: signing.keyId };
    return { type: 'keysentry-approval-request', v: 1, ...signed,
      sig: signDetached(signing.privateKeyDer, Buffer.from(APPROVAL_REQUEST_PREFIX + canonicalJson(signed))).toString('base64'), ...signedChanges };
  };
  const wrapper = (message: unknown) => JSON.stringify({ id: 'relay-id', event: 'message', topic: 'private-topic', time: Math.floor(current.getTime() / 1000), message: JSON.stringify(message) });
  const remote = (message: unknown) => { fake.on('GET', /\/json\?poll=1$/, () => text(200, wrapper(message))); };
  return { store, key, watcher, events, service, fake, receipt, deps, request, saveLocal, requestMessage, wrapper, remote, gates, reviews,
    setNow: (at: string) => { current = new Date(at); } };
}

describe('autopilot device-key approvals', () => {
  test('locally signs the exact pending action and reuses its trusted grant on retry', async () => {
    const f = await fixture(); await f.saveLocal();
    expect(await approveAutopilot(action.id, {}, f.deps)).toEqual({ actionId: action.id, digest: f.request.digest, status: 'approved' });
    expect(await f.service.status(action.id)).toBe('approved');
    expect((await approveAutopilot(action.id, {}, f.deps))?.status).toBe('approved');
    expect(await f.service.approved()).toHaveLength(1);
    expect(f.gates).toEqual(['approve an autopilot action', 'approve an autopilot action']); expect(f.fake.calls).toEqual([]);
  });
  test('unknown local autopilot action falls back to monitor approval without network', async () => {
    const f = await fixture(); expect(await approveAutopilot('monitor-action', {}, f.deps)).toBeNull(); expect(f.fake.calls).toEqual([]);
  });
  test.each([{ widening: true }, { digest: '0'.repeat(64) }, { actionId: 'other-action' }])('refuses a widened or altered local pending request %j', async changes => {
    const f = await fixture(); await f.saveLocal(changes);
    await expect(approveAutopilot(action.id, {}, f.deps)).rejects.toThrow(/approval|request/i);
    expect(await f.service.status(action.id)).toBe('pending');
  });
  test('expired local request cannot be approved', async () => {
    const f = await fixture(); await f.saveLocal(); f.setNow(f.request.expiresAt);
    await expect(approveAutopilot(action.id, {}, f.deps)).rejects.toThrow(/expired/i);
    expect(await f.service.status(action.id)).toBe('expired');
  });
  test('human gate runs before any local or remote approval processing', async () => {
    const f = await fixture(); f.deps.assertHuman = () => { throw new Error('human refused'); };
    await expect(approveAutopilot(action.id, { relay: true }, f.deps)).rejects.toThrow('human refused'); expect(f.fake.calls).toEqual([]);
  });
  test('approve --relay verifies the watcher request and publishes a signed approval that the watcher accepts', async () => {
    const f = await fixture(); f.remote(f.requestMessage());
    const result = await approveAutopilot(action.id, { relay: true }, f.deps);
    expect(result).toEqual({ actionId: action.id, digest: f.request.digest, status: 'published', watcherCheckMinutes: 10 });
    const post = f.fake.calls.find(call => call.method === 'POST')!;
    expect(post.headers?.Authorization).toBe('Bearer private-token'); expect(post.body).not.toContain('private-token');
    const watcherHttp = new FakeHttp().on('GET', /\/json\?/, () => text(200, f.wrapper(JSON.parse(post.body!))));
    const relay = createRelay({ http: watcherHttp, ...f.deps.relay!, trustedKeyIds: [f.key.keyId], deviceKeys: f.deps.deviceKeys, audit: f.deps.audit, now: f.deps.now });
    const polled = await relay.poll(null); expect(polled.approvals).toHaveLength(1);
    expect((await f.service.approveWithDevice(action.id, polled.approvals[0]!)).by).toEqual({ kind: 'device', keyId: f.key.keyId });
    expect(JSON.stringify(f.receipt)).not.toMatch(/private-topic|private-token/);
    expect(f.receipt).toEqual([expect.objectContaining({ host: 'ntfy.sh', allowed: true }), expect.objectContaining({ host: 'ntfy.sh', allowed: true })]);
  });
  test('relay displays the watcher-signed keys and hints before confirmation and publishes nothing when declined', async () => {
    const f = await fixture(); f.remote(f.requestMessage());
    f.deps.confirm = async () => {
      expect(f.reviews).toEqual([expect.objectContaining({ actionId: action.id, clusters: action.clusters })]);
      expect(f.fake.calls.filter(call => call.method === 'POST')).toEqual([]);
      return false;
    };
    expect((await approveAutopilot(action.id, { relay: true }, f.deps))?.status).toBe('cancelled');
    expect(f.fake.calls.filter(call => call.method === 'POST')).toEqual([]);
    expect(await f.service.status(action.id)).toBe('pending');
  });
  test('relay does not sign when no confirmation adapter is provided', async () => {
    const f = await fixture(); f.remote(f.requestMessage());
    await expect(approveAutopilot(action.id, { relay: true }, { ...f.deps, confirm: undefined })).rejects.toThrow(/confirm/i);
    expect(f.fake.calls.filter(call => call.method === 'POST')).toEqual([]);
  });
  test('a request that expires during confirmation is not signed or published', async () => {
    const f = await fixture(); f.remote(f.requestMessage());
    f.deps.confirm = async () => { f.setNow(f.request.expiresAt); return true; };
    await expect(approveAutopilot(action.id, { relay: true }, f.deps)).rejects.toThrow(/expired/i);
    expect(f.fake.calls.filter(call => call.method === 'POST')).toEqual([]);
  });
  test('local approval executes through the supplied action executor after recording the trusted grant', async () => {
    const f = await fixture(); await f.saveLocal();
    f.deps.executeApprovedAction = async id => {
      expect((await f.service.approved()).map(entry => entry.action.id)).toEqual([id]);
      await f.service.markExecuted(id, f.request.digest);
      return { executed: true };
    };
    expect((await approveAutopilot(action.id, {}, f.deps))?.status).toBe('executed');
    expect(await f.service.status(action.id)).toBe('executed');
  });
  test('local approval preserves a trusted grant when the executor reports a temporary hold', async () => {
    const f = await fixture(); await f.saveLocal();
    f.deps.executeApprovedAction = async () => ({ executed: false, reason: 'Automatic work is paused.' });
    expect(await approveAutopilot(action.id, {}, f.deps)).toMatchObject({ status: 'approved', reason: 'Automatic work is paused.' });
    expect(await f.service.status(action.id)).toBe('approved');
  });
  test('a held local grant can execute on retry after the request expiry without a second signature', async () => {
    const f = await fixture(); await f.saveLocal();
    f.deps.executeApprovedAction = async () => ({ executed: false, reason: 'Automatic work is paused.' });
    await approveAutopilot(action.id, {}, f.deps);
    f.setNow('2026-10-27T13:00:00.000Z');
    f.deps.executeApprovedAction = async id => { await f.service.markExecuted(id, f.request.digest); return { executed: true }; };
    f.deps.deviceKey = async () => { throw new Error('An existing trusted grant needs no new signature.'); };
    expect((await approveAutopilot(action.id, {}, f.deps))?.status).toBe('executed');
  });
  test('an executor failure preserves the grant and records an execution hold instead of an approval rejection', async () => {
    const f = await fixture(); await f.saveLocal();
    f.deps.executeApprovedAction = async () => { throw new Error('private transport detail'); };
    await expect(approveAutopilot(action.id, {}, f.deps)).rejects.toThrow(/approved.*execution|execution.*complete/i);
    expect(await f.service.status(action.id)).toBe('approved');
    expect(f.events.some(event => event.kind === 'autopilot-approval-execution-held')).toBe(true);
    expect(f.events.some(event => event.kind === 'autopilot-approval-rejected')).toBe(false);
    expect(JSON.stringify(f.events)).not.toContain('private transport detail');
  });
  test('Actions approval requests remain reviewable after ten minutes', async () => {
    const f = await fixture();
    f.remote(f.requestMessage({ expiresAt: '2026-10-27T12:50:00.000Z', watcherCheckMinutes: 20 }));
    f.setNow('2026-10-27T12:20:00.000Z');
    expect(await approveAutopilot(action.id, { relay: true }, f.deps)).toMatchObject({ status: 'published', watcherCheckMinutes: 20 });
  });
  test.each(['2026-10-27T11:59:00.000Z', '2026-10-27T12:05:00.000Z'])('relay history selects the latest signed request over an older version expiring %s', async expiresAt => {
    const f = await fixture();
    const old = f.requestMessage({ digest: 'b'.repeat(64), expiresAt });
    f.fake.on('GET', /\/json\?poll=1$/, () => text(200, [f.wrapper(old), f.wrapper(f.requestMessage())].join('\n')));
    expect(await approveAutopilot(action.id, { relay: true }, f.deps)).toMatchObject({ status: 'published', digest: f.request.digest });
    expect(JSON.parse(f.fake.calls.find(call => call.method === 'POST')!.body!).approval.digest).toBe(f.request.digest);
  });
  test('relay refuses differently bound versions with the same signed expiry', async () => {
    const f = await fixture();
    const old = f.requestMessage({ digest: 'b'.repeat(64) });
    f.fake.on('GET', /\/json\?poll=1$/, () => text(200, [f.wrapper(old), f.wrapper(f.requestMessage())].join('\n')));
    await expect(approveAutopilot(action.id, { relay: true }, f.deps)).rejects.toThrow(/current|ambiguous/i);
    expect(f.fake.calls.filter(call => call.method === 'POST')).toEqual([]);
  });
  test('relay can use the exact locally saved pending action without fetching a remote digest', async () => {
    const f = await fixture(); await f.saveLocal();
    expect((await approveAutopilot(action.id, { relay: true }, f.deps))?.status).toBe('published');
    expect(f.fake.calls.map(call => call.method)).toEqual(['POST']); expect(await f.service.status(action.id)).toBe('pending');
  });
  test.each([
    ['edited digest', (f: Awaited<ReturnType<typeof fixture>>) => { const message = f.requestMessage(); return { ...message, request: { ...message.request, digest: '0'.repeat(64) } }; }],
    ['forged signature', (f: Awaited<ReturnType<typeof fixture>>) => f.requestMessage({}, { sig: Buffer.alloc(64).toString('base64') })],
    ['untrusted signer', (f: Awaited<ReturnType<typeof fixture>>) => f.requestMessage({}, {}, generateDeviceKey())],
    ['expired request', (f: Awaited<ReturnType<typeof fixture>>) => f.requestMessage({ expiresAt: '2026-10-27T11:59:59.000Z' })],
    ['widening kind', (f: Awaited<ReturnType<typeof fixture>>) => f.requestMessage({ kind: 'arm' })],
    ['widening extra field', (f: Awaited<ReturnType<typeof fixture>>) => f.requestMessage({ widening: true })],
    ['wrong action', (f: Awaited<ReturnType<typeof fixture>>) => f.requestMessage({ actionId: 'another-action' })],
    ['missing cluster metadata', (f: Awaited<ReturnType<typeof fixture>>) => f.requestMessage({ clusters: undefined })],
    ['mismatched key count', (f: Awaited<ReturnType<typeof fixture>>) => f.requestMessage({ keyCount: 1 })],
    ['duplicate clusters', (f: Awaited<ReturnType<typeof fixture>>) => f.requestMessage({ clusters: [action.clusters![0], action.clusters![0]] })],
    ['control characters in hint', (f: Awaited<ReturnType<typeof fixture>>) => f.requestMessage({ clusters: [{ clusterId: 'key', hint: 'bad\u001btext' }], keyCount: 1 })],
  ])('relay refuses %s and publishes nothing', async (_name, make) => {
    const f = await fixture(); f.remote(make(f)); await expect(approveAutopilot(action.id, { relay: true }, f.deps)).rejects.toThrow(/approval|request/i);
    expect(f.fake.calls.filter(call => call.method === 'POST')).toEqual([]);
  });
  test('relay requires configured connection details and a trusted watcher key', async () => {
    const f = await fixture(); f.remote(f.requestMessage());
    await expect(approveAutopilot(action.id, { relay: true }, { ...f.deps, relay: undefined })).rejects.toThrow(/relay/i);
    await expect(approveAutopilot(action.id, { relay: true }, { ...f.deps, watcherPublicKeys: async () => [] })).rejects.toThrow(/watcher|request|approval/i);
    expect(f.fake.calls.filter(call => call.method === 'POST')).toEqual([]);
  });
  test.each([4 * 1024 * 1024 + 1, 16 * 1024 + 1])('relay rejects oversized responses or lines (%i bytes)', async bytes => {
    const f = await fixture(); f.fake.on('GET', /./, () => text(200, 'x'.repeat(bytes)));
    await expect(approveAutopilot(action.id, { relay: true }, f.deps)).rejects.toThrow(/too large/i);
    expect(f.fake.calls.filter(call => call.method === 'POST')).toEqual([]);
  });
});
