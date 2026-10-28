import { randomBytes } from 'node:crypto';
import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { startLocalBox, type LocalBox } from '../../../packages/control-plane/src/index.js';
import {
  createHttpBoxRelay, encodeBoxPayload, startBoxAgent, type BoxAgent, type BoxAgentDependencies, type BoxEnrollPayload, type BoxRelay,
} from '../../../src/box/index.js';
import { openVerifiedBoxSession } from '../../../src/cli/box-flow.js';
import { createFetchHttp } from '../../../src/http.js';
import { generateDeviceKey, type DeviceKey } from '../../../src/security/index.js';
import type { BoxSealMode } from '../../../src/types.js';

const planted = 'sk-or-v1-agent-unit-planted-0123456789abcdef';
const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => { for (const cleanup of cleanups.splice(0).reverse()) await cleanup(); });

async function box(overrides: Partial<BoxAgentDependencies> = {}) {
  const device = generateDeviceKey();
  const stateDir = await mkdtemp(join(tmpdir(), 'keysentry-box-agent-'));
  const logs: string[] = [], started: Record<string, string>[] = [];
  let mints = 0, current: BoxAgent | undefined;
  const local: LocalBox = await startLocalBox({ boxId: 'unit-box', bootBox: async rt => {
    current = await startBoxAgent({ boxId: rt.boxId, relay: rt.relay as BoxRelay, http: rt.http, stateDir, pollIntervalMs: 20, retryMs: 60,
      tee: { token: input => { mints++; return rt.tee.token(input); }, defaultToken: () => rt.tee.defaultToken() },
      enrollmentDeviceKeys: [device.publicKeyDer],
      log: { info: message => logs.push(message), warn: message => logs.push(message) },
      startWatcher: async (env, signal) => { started.push(env); await new Promise(resolve => signal.addEventListener('abort', resolve)); },
      sendNotice: async () => {},
      ...overrides });
    return current;
  } });
  cleanups.push(async () => { await local.close(); await rm(stateDir, { recursive: true, force: true }); });
  const relay = createHttpBoxRelay({ http: createFetchHttp(), origin: local.origin, boxId: 'unit-box', credential: async () => local.cliToken });
  const policy = local.emulator.policy;
  const trust = { jwks: async () => local.emulator.jwks, projectIds: [policy.projectId], serviceAccounts: [policy.serviceAccount], allowedDigests: policy.allowedDigests, emulator: true };
  const session = (key: DeviceKey = device, timeoutMs = 8_000) => openVerifiedBoxSession({ relay, boxId: 'unit-box', deviceKey: key, trust, pollMs: 20, timeoutMs });
  const payload = (mode: BoxSealMode = 'standard', extra: Partial<BoxEnrollPayload> = {}): BoxEnrollPayload => ({ v: 1, kind: 'enroll', boxId: 'unit-box',
    settings: { mode, audience: local.emulator.audience, keyName: local.emulator.keyName, deviceKeys: [device.publicKeyDer.toString('base64')] },
    deployment: { KEYSENTRY_WATCHER_KEY: 'k', KEYSENTRY_WATCHER_CONFIG: `config-${randomBytes(4).toString('hex')}`, KEYSENTRY_STATE_KEY: 's',
      KEYSENTRY_VAULT_PASSPHRASE: 'p', KEYSENTRY_WATCHER_VAULT: planted },
    notice: { channels: [], secrets: [] }, ...(mode === 'unlock-on-restart' ? { shareB: randomBytes(32).toString('base64') } : {}), ...extra });
  const send = async (value: Parameters<typeof encodeBoxPayload>[0], key?: DeviceKey) => {
    const opened = await session(key);
    expect(opened.verification.ok).toBe(true);
    await opened.send!(encodeBoxPayload(value));
  };
  return { local, device, stateDir, logs, started, agent: () => current!, mints: () => mints, session, payload, send };
}
async function eventually(check: () => unknown, ms = 5_000): Promise<void> {
  const end = Date.now() + ms;
  while (true) {
    try { await check(); return; } catch (error) { if (Date.now() > end) throw error; }
    await new Promise(resolve => setTimeout(resolve, 20));
  }
}

describe('box agent', () => {
  it('refuses a bundle addressed to another box and seals nothing', async () => {
    const b = await box();
    await expect(b.send(b.payload('standard', { boxId: 'other-box' }))).rejects.toThrow(/did not confirm/);
    expect(b.agent().status().state).toBe('enrolling');
    expect(await readdir(b.stateDir)).toEqual([]);
    expect(b.logs).toContain('A token bundle for another box was refused.');
  });

  it('keeps its seal settings once enrolled and replaces tokens from an enrolled device', async () => {
    const b = await box();
    await b.send(b.payload());
    await eventually(() => expect(b.agent().status()).toMatchObject({ state: 'running', watcher: true }));
    await expect(b.send(b.payload('byo-kms'))).rejects.toThrow(/did not confirm/);
    expect(b.logs).toContain('This box already seals tokens with other settings. Provision a new box to change them.');
    const replacement = b.payload();
    await b.send(replacement);
    await eventually(() => expect(b.started.at(-1)?.KEYSENTRY_WATCHER_CONFIG).toBe(replacement.deployment.KEYSENTRY_WATCHER_CONFIG));
    // Each deployment gets its own watcher state directory.
    expect(b.started.at(-1)!.KEYSENTRY_STATE_DIR).not.toBe(b.started[0]!.KEYSENTRY_STATE_DIR);
  });

  it('mints an attestation token for a challenge only when an allowed device signed it', async () => {
    const b = await box();
    await eventually(() => expect(b.mints()).toBe(1));
    await expect(b.session(generateDeviceKey(), 600)).rejects.toThrow(/did not answer/);
    expect(b.mints()).toBe(1);
  });

  it('starts the watcher again after it stops by itself', async () => {
    let runs = 0;
    const b = await box({ startWatcher: async () => { runs++; } });
    await b.send(b.payload());
    await eventually(() => expect(runs).toBeGreaterThanOrEqual(2));
    expect(b.logs).toContain('The watcher stopped. The box will start it again.');
  });

  it('retries the restart notice until a channel delivers it, then sends no more', async () => {
    let attempts = 0;
    const delivered: string[] = [];
    const b = await box({ sendNotice: async (_kit, message) => { attempts++; if (attempts < 3) throw new Error('offline'); delivered.push(message.title); } });
    await b.send(b.payload('unlock-on-restart'));
    await b.local.restart();
    await eventually(() => expect(b.agent().status().noticeSent).toBe(true));
    expect(attempts).toBe(3);
    await b.local.restart();
    await eventually(() => expect(b.agent().status()).toMatchObject({ state: 'locked', noticeSent: true }));
    expect(delivered).toHaveLength(1);
  });

  it('refuses a state directory that belongs to another box', async () => {
    const stateDir = await mkdtemp(join(tmpdir(), 'keysentry-box-other-'));
    cleanups.push(() => rm(stateDir, { recursive: true, force: true }));
    await writeFile(join(stateDir, 'box.json'), JSON.stringify({ v: 1, boxId: 'other-box', mode: 'standard',
      audience: '//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q', keyName: 'projects/p/locations/global/keyRings/r/cryptoKeys/k' }));
    await expect(startBoxAgent({ boxId: 'unit-box', stateDir, relay: {} as never, tee: {} as never, http: {} as never, enrollmentDeviceKeys: [],
      startWatcher: async () => {}, sendNotice: async () => {} })).rejects.toThrow(/another box/);
  });

  it('logs fixed text only', async () => {
    const b = await box();
    await b.send(b.payload());
    await b.local.restart();
    await eventually(() => expect(b.agent().status().state).toBe('running'));
    expect(b.logs.join('\n')).not.toContain(planted);
    expect(b.logs).toEqual(expect.arrayContaining(['Box sealed new tokens.', 'Box resumed from its sealed record.']));
  });
});
