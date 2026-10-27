import { request } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createRuntime } from '../../src/cli/runtime.js';
import { createDashboardApi, createDashboardPasskeyStore } from '../../src/cli/dashboard-api.js';
import { startDashboard } from '../../src/dashboard/server/index.js';
import { bodyDigest } from '../../src/dashboard/server/api.js';
import { getProvider } from '../../src/providers/index.js';
import { createFakeAuthenticator } from '../dashboard/helpers/fake-authenticator.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';

const dirs: string[] = [];
const dashboards: Awaited<ReturnType<typeof startDashboard>>[] = [];
afterEach(async () => {
  await Promise.all(dashboards.splice(0).map(dashboard => dashboard.close()));
  await Promise.all(dirs.splice(0).map(path => rm(path, { recursive: true, force: true })));
});
interface Reply { status: number; body: any; headers: import('node:http').IncomingHttpHeaders; text: string }
function http(port: number, path: string, auth?: { cookie: string; csrf: string }, body?: unknown, proof?: string): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port, path, method: body === undefined ? 'GET' : 'POST', headers: {
      Host: `localhost:${port}`, ...(auth ? { Cookie: auth.cookie } : {}),
      ...(body === undefined ? {} : { Origin: `http://localhost:${port}`, 'X-CSRF-Token': auth?.csrf ?? '', 'Content-Type': 'application/json' }),
      ...(proof ? { 'X-Passkey-Assertion': proof } : {}),
    } }, res => {
      let text = ''; res.setEncoding('utf8'); res.on('data', chunk => { text += chunk; });
      res.on('end', () => { let body: unknown; try { body = JSON.parse(text); } catch { body = text; } resolve({ status: res.statusCode!, body, headers: res.headers, text }); });
    });
    req.on('error', reject); req.end(body === undefined ? undefined : JSON.stringify(body));
  });
}

describe('dashboard end-to-end flow', () => {
  it('connects, scans, previews, drills, rotates into grace and finishes through passkey-bound HTTP against fakes', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'keysentry-dashboard-e2e-')); dirs.push(cwd);
    const host = new FakeHost('railway'); host.pendingPolls = 0;
    const provider = new FakeProvider('openrouter', 'auto', 'sk-or-v1-0123456789abcdef');
    const old = provider.issue(); host.addService('api', { OPENROUTER_API_KEY: old.value });
    const vault = createFakeVault(); const outbound = new FakeHttp();
    const runtime = await createRuntime({ cwd, userDir: join(cwd, '.user'), env: {}, vault, inflight: createFakeInFlight(),
      hosts: [host], providers: id => id === provider.id ? provider : getProvider(id), http: outbound, log: silentLogger,
      stdinIsTTY: false, stdoutIsTTY: false, sleep: async () => {}, firstRunGit: async () => ({ code: 0 }) });
    const d = await startDashboard({ api: createDashboardApi(runtime), passkeys: createDashboardPasskeyStore(vault), readOnly: false }); dashboards.push(d);
    const exchanged = await http(d.port, `/${new URL(d.url).search}`);
    expect(exchanged.status).toBe(303);
    const cookie = exchanged.headers['set-cookie']![0]!.split(';')[0]!;
    const auth = { cookie, csrf: '' };
    const session = await http(d.port, '/api/session', auth); auth.csrf = session.body.csrf;
    const authenticator = createFakeAuthenticator();
    const registration = await http(d.port, '/api/passkey/register/options', auth, {});
    expect(registration.status).toBe(200);
    expect((await http(d.port, '/api/passkey/register/finish', auth, authenticator.registration(registration.body.challenge, `http://localhost:${d.port}`))).body).toEqual({ registered: true });
    const responses: string[] = [];
    async function change(route: string, body: unknown) {
      const challenge = await http(d.port, '/api/passkey/challenge', auth, { route, bodyDigest: bodyDigest(body) });
      expect(challenge.status).toBe(200);
      const proof = authenticator.assertionHeader(challenge.body.challenge, `http://localhost:${d.port}`);
      const response = await http(d.port, `/api/${route}`, auth, body, proof);
      responses.push(response.text); expect(response.status).toBe(200); return response.body;
    }
    const connect = { name: 'RAILWAY_TOKEN', role: 'read', value: 'private-platform-token-e2e' };
    expect((await http(d.port, '/api/vault/store', auth, connect)).status).toBe(403);
    expect(await change('vault/store', connect)).toEqual({ stored: true });
    const keys = await http(d.port, '/api/keys', auth); responses.push(keys.text);
    expect(keys.status).toBe(200); expect(keys.body.keys).toHaveLength(1);
    const ids = keys.body.keys.map((key: { id: string }) => key.id);
    const preview = await http(d.port, '/api/rotate/preview', auth, { clusterIds: ids }); responses.push(preview.text);
    expect(preview.status).toBe(200); expect(preview.body.steps).toHaveLength(1);
    expect(provider.keys.size).toBe(1); expect(host.writes).toHaveLength(0);
    const drill = await http(d.port, '/api/drill', auth, {}); responses.push(drill.text);
    expect(drill.status).toBe(200); expect(drill.body.score).toBeGreaterThanOrEqual(0);
    expect(provider.keys.size).toBe(1); expect(host.writes).toHaveLength(0);
    const report = await change('rotate/execute', { planId: preview.body.planId, planHash: preview.body.planHash });
    expect(report.report.status).toBe('grace-pending'); expect(provider.keys.size).toBe(2);
    expect(host.writes).toHaveLength(1); expect(host.redeploys).toEqual(['api']); expect(provider.keys.get(old.ref)?.active).toBe(true);
    const active = await http(d.port, '/api/rotations', auth); responses.push(active.text);
    expect(active.body.active).toEqual(expect.arrayContaining([expect.objectContaining({ planId: preview.body.planId, status: 'grace-pending' })]));
    const finished = await change('rotation/finish', { planId: preview.body.planId, early: true });
    expect(finished.report.status).toBe('complete'); expect(provider.keys.get(old.ref)?.active).toBe(false);
    const timeline = await http(d.port, '/api/timeline', auth, { id: preview.body.planId }); responses.push(timeline.text);
    expect(timeline.status).toBe(200); expect(timeline.body.events.some((event: { kind: string }) => event.kind === 'revoked')).toBe(true);
    const replacement = [...provider.keys.values()].find(key => key.ref !== old.ref)!;
    for (const value of [old.value, replacement.value, connect.value]) {
      expect(responses.join('\n')).not.toContain(value);
      expect(await readFile(runtime.paths.audit, 'utf8')).not.toContain(value);
    }
    expect(await vault.list('passkey/')).toEqual([`passkey/${authenticator.id}`]);
    expect((await createDashboardPasskeyStore(vault).list())[0]!.signCount).toBe(3);
    expect(await runtime.audit.verify()).toMatchObject({ ok: true });
  });
});
