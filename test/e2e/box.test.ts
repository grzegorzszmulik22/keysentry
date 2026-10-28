import { randomBytes } from 'node:crypto';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { startLocalBox, type LocalBox, type LocalBoxRuntime } from '../../packages/control-plane/src/index.js';
import {
  boxKeyBindingNonce, createHandshake, createHttpBoxRelay, generateBoxKeyPair, startBoxAgent,
  type BoxAgent, type BoxEnrollPayload, type BoxRelay, encodeBoxPayload,
} from '../../src/box/index.js';
import { openVerifiedBoxSession, type BoxTrust } from '../../src/cli/box-flow.js';
import { createFetchHttp } from '../../src/http.js';
import { generateDeviceKey, type DeviceKey } from '../../src/security/index.js';
import type { BoxSealMode, SignedNotifyMessage } from '../../src/types.js';

const PLANTED = {
  KEYSENTRY_WATCHER_KEY: Buffer.alloc(32, 7).toString('base64'),
  KEYSENTRY_WATCHER_CONFIG: 'keysentry-watcher-config:v1:planted-sealed-config-0123456789',
  KEYSENTRY_STATE_KEY: Buffer.alloc(32, 9).toString('base64'),
  KEYSENTRY_VAULT_PASSPHRASE: 'planted-passphrase-zq8x0v7c6b5n4m3',
  KEYSENTRY_WATCHER_VAULT: 'planted-vault-blob-sk-or-v1-0123456789abcdef0123456789abcdef',
};
const NOTICE_SECRET = 'planted-ntfy-topic-6f1d0c9b';

interface Harness {
  local: LocalBox; relay: BoxRelay; device: DeviceKey; trust: BoxTrust; stateDir: string;
  agent(): BoxAgent; watchers: Record<string, string>[]; notices: SignedNotifyMessage[]; runtime(): LocalBoxRuntime;
}
const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => { for (const cleanup of cleanups.splice(0).reverse()) await cleanup(); });

async function harness(): Promise<Harness> {
  const device = generateDeviceKey();
  const stateDir = await mkdtemp(join(tmpdir(), 'keysentry-box-e2e-'));
  const watchers: Record<string, string>[] = [], notices: SignedNotifyMessage[] = [];
  let current: BoxAgent | undefined, runtime: LocalBoxRuntime | undefined;
  const local = await startLocalBox({ boxId: 'test-box', bootBox: async rt => {
    runtime = rt;
    current = await startBoxAgent({ boxId: rt.boxId, relay: rt.relay as BoxRelay, tee: rt.tee, http: rt.http, stateDir,
      enrollmentDeviceKeys: [device.publicKeyDer], pollIntervalMs: 20, retryMs: 50,
      startWatcher: async (env, signal) => { watchers.push(env); await new Promise(resolve => signal.addEventListener('abort', resolve)); },
      sendNotice: async (_kit, message) => { notices.push(message); } });
    return current;
  } });
  cleanups.push(async () => { await local.close(); await rm(stateDir, { recursive: true, force: true }); });
  const transport = createFetchHttp();
  const relay = createHttpBoxRelay({ http: transport, origin: local.origin, boxId: 'test-box', credential: async () => local.cliToken });
  const policy = local.emulator.policy;
  const trust: BoxTrust = { jwks: async () => local.emulator.jwks, projectIds: [policy.projectId], serviceAccounts: [policy.serviceAccount],
    allowedDigests: policy.allowedDigests, emulator: true };
  return { local, relay, device, trust, stateDir, agent: () => current!, watchers, notices, runtime: () => runtime! };
}

function enroll(h: Harness, mode: BoxSealMode, shareB?: Buffer): BoxEnrollPayload {
  return { v: 1, kind: 'enroll', boxId: 'test-box',
    settings: { mode, audience: h.local.emulator.audience, keyName: h.local.emulator.keyName, deviceKeys: [h.device.publicKeyDer.toString('base64')] },
    deployment: { ...PLANTED }, notice: { channels: [{ id: 'phone', kind: 'ntfy', server: 'https://ntfy.sh' }], secrets: [{ name: 'notify/phone/topic', value: NOTICE_SECRET }] },
    ...(shareB ? { shareB: shareB.toString('base64') } : {}) };
}

const session = (h: Harness, device = h.device, timeoutMs = 10_000) =>
  openVerifiedBoxSession({ relay: h.relay, boxId: 'test-box', deviceKey: device, trust: h.trust, pollMs: 20, timeoutMs });

async function send(h: Harness, payload: Parameters<typeof encodeBoxPayload>[0]): Promise<void> {
  const opened = await session(h);
  expect(opened.verification.failed).toEqual([]);
  const bytes = encodeBoxPayload(payload);
  try { await opened.send!(bytes); } finally { bytes.fill(0); }
}
async function eventually(check: () => unknown, ms = 5_000): Promise<void> {
  const end = Date.now() + ms;
  while (true) {
    try { await check(); return; } catch (error) { if (Date.now() > end) throw error; }
    await new Promise(resolve => setTimeout(resolve, 20));
  }
}
async function files(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...await files(path)); else out.push(path);
  }
  return out;
}
async function expectNoPlaintext(h: Harness): Promise<void> {
  const planted = [...Object.values(PLANTED), NOTICE_SECRET];
  const relayText = JSON.stringify(await h.relay.poll());
  for (const value of planted) expect(relayText).not.toContain(value);
  for (const path of await files(h.stateDir)) {
    const text = await readFile(path, 'utf8');
    for (const value of planted) expect(text).not.toContain(value);
  }
}
async function bundlesSent(h: Harness): Promise<number> {
  return (await h.relay.poll()).filter(message => (message as { type?: string }).type === 'token-bundle').length;
}

describe('cloud box end to end against the local emulator', () => {
  for (const mode of ['standard', 'byo-kms'] as const) {
    it(`${mode}: verifies, seals, runs the watcher, and resumes by itself after a restart`, async () => {
      const h = await harness();
      const opened = await session(h);
      expect(opened.verification.ok).toBe(true);
      expect(opened.verification.checks.map(check => check.name)).toEqual(expect.arrayContaining(['box-signature', 'box-key-unchanged',
        'signature', 'nonce-box-key', 'nonce-challenge', 'debug', 'support-stable', 'image-digest', 'project', 'service-account']));
      const bytes = encodeBoxPayload(enroll(h, mode));
      await opened.send!(bytes); bytes.fill(0);
      await eventually(() => expect(h.agent().status()).toMatchObject({ state: 'running', watcher: true }));
      expect(h.watchers.at(-1)).toMatchObject(PLANTED);
      await h.local.restart();
      await eventually(() => expect(h.agent().status()).toMatchObject({ state: 'running', watcher: true }));
      expect(h.watchers).toHaveLength(2);
      expect(h.watchers[1]).toMatchObject(PLANTED);
      expect(h.notices).toEqual([]);
      await expectNoPlaintext(h);
    });
  }

  it('unlock-on-restart: pauses after a restart, notifies once across restarts, and resumes only with the share', async () => {
    const h = await harness();
    const share = randomBytes(32);
    await send(h, enroll(h, 'unlock-on-restart', share));
    await eventually(() => expect(h.agent().status()).toMatchObject({ state: 'running', watcher: true }));
    await h.local.restart();
    await eventually(() => expect(h.agent().status()).toMatchObject({ state: 'locked', watcher: false, noticeSent: true }));
    expect(h.notices).toHaveLength(1);
    expect(h.notices[0]!.lines.join(' ')).toContain('keysentry box unlock test-box');
    await h.local.restart();
    await eventually(() => expect(h.agent().status()).toMatchObject({ state: 'locked', noticeSent: true }));
    expect(h.notices).toHaveLength(1);
    expect(h.watchers).toHaveLength(1);

    // A wrong share is refused and the box stays paused.
    const wrong = await session(h);
    await expect(wrong.send!(encodeBoxPayload({ v: 1, kind: 'unlock', boxId: 'test-box', shareB: randomBytes(32).toString('base64') })))
      .rejects.toThrow(/did not confirm/);
    expect(h.agent().status().state).toBe('locked');

    await send(h, { v: 1, kind: 'unlock', boxId: 'test-box', shareB: share.toString('base64') });
    await eventually(() => expect(h.agent().status()).toMatchObject({ state: 'running', watcher: true }));
    expect(h.watchers.at(-1)).toMatchObject(PLANTED);
    await expectNoPlaintext(h);
  }, 30_000);

  it('a device that was not enrolled cannot unlock the box', async () => {
    const h = await harness();
    const share = randomBytes(32);
    await send(h, enroll(h, 'unlock-on-restart', share));
    await h.local.restart();
    await eventually(() => expect(h.agent().status().state).toBe('locked'));
    await expect(session(h, generateDeviceKey(), 1_500)).rejects.toThrow(/did not answer/);
    expect(h.agent().status().state).toBe('locked');
  });

  const rejections: [string, Parameters<LocalBox['emulator']['setSwitches']>[0], string][] = [
    ['wrong digest', { wrongDigest: true }, 'image-digest'],
    ['debug image', { debugImage: true }, 'debug'],
    ['another project', { otherProject: true }, 'project'],
    ['another service account', { otherServiceAccount: true }, 'service-account'],
    ['missing STABLE', { missingStable: true }, 'support-stable'],
    ['stale token', { staleIat: true }, 'time'],
    ['token replayed from an earlier request', { replay: true }, 'nonce-challenge'],
  ];
  for (const [label, switches, check] of rejections) {
    it(`refuses a box with a ${label} and names the ${check} check`, async () => {
      const h = await harness();
      h.local.emulator.setSwitches(switches);
      const opened = await session(h);
      expect(opened.verification.ok).toBe(false);
      expect(opened.verification.failed).toContain(check);
      expect(opened.send).toBeUndefined();
      expect(await bundlesSent(h)).toBe(0);
    });
  }

  it('a tampering relay that swaps in its own box key gets no tokens: the nonce does not bind that key', async () => {
    const h = await harness();
    // A genuine token exists for the real box's key; the relay presents it with keys it controls.
    await eventually(async () => expect((await h.relay.poll()).length).toBeGreaterThan(0));
    const real = (await h.relay.poll()).find(message => (message as { type?: string }).type === 'box-hello') as { boxPublicKey: string; boxSigningPublicKey: string };
    const realBinding = boxKeyBindingNonce(Buffer.from(real.boxPublicKey, 'base64url'), Buffer.from(real.boxSigningPublicKey, 'base64url'));
    const attacker = { boxKey: generateBoxKeyPair(), signingKey: generateDeviceKey() };
    let fake = createHandshake('box', { devicePublicKeyDer: h.device.publicKeyDer, ...attacker });
    await new Promise(resolve => setTimeout(resolve, 5));
    const hello = fake.next({ now: new Date(), attestationToken: h.local.emulator.mintToken({ audience: 'keysentry-box:test-box', nonces: [realBinding] }) });
    fake = hello.handshake;
    await h.relay.publish(hello.message!);
    const pending = session(h);
    await eventually(async () => {
      const challenge = (await h.relay.poll(fake.sessionId!)).find(message => (message as { type?: string }).type === 'cli-challenge') as { challenge: string } | undefined;
      expect(challenge).toBeDefined();
      const token = h.local.emulator.mintToken({ audience: 'keysentry-box:test-box', nonces: [realBinding, challenge!.challenge] });
      const attest = fake.next({ now: new Date(), message: challenge, attestationToken: token });
      await h.relay.publish(attest.message!);
    });
    const opened = await pending;
    expect(opened.verification.ok).toBe(false);
    expect(opened.verification.failed).toContain('nonce-box-key');
    expect(opened.send).toBeUndefined();
    expect(await bundlesSent(h)).toBe(0);
  });

  it('a relay that replays an old attestation from an earlier session is refused', async () => {
    const h = await harness();
    const first = await session(h);
    expect(first.verification.ok).toBe(true);
    const old = (await h.relay.poll()).find(message => (message as { type?: string }).type === 'box-attest') as { attestationToken: string };
    const attacker = { boxKey: generateBoxKeyPair(), signingKey: generateDeviceKey() };
    let fake = createHandshake('box', { devicePublicKeyDer: h.device.publicKeyDer, ...attacker });
    await new Promise(resolve => setTimeout(resolve, 5));
    const hello = fake.next({ now: new Date(), attestationToken: old.attestationToken });
    fake = hello.handshake;
    await h.relay.publish(hello.message!);
    const pending = session(h);
    await eventually(async () => {
      const challenge = (await h.relay.poll(fake.sessionId!)).find(message => (message as { type?: string }).type === 'cli-challenge');
      expect(challenge).toBeDefined();
      await h.relay.publish(fake.next({ now: new Date(), message: challenge, attestationToken: old.attestationToken }).message!);
    });
    const opened = await pending;
    expect(opened.verification.failed).toEqual(expect.arrayContaining(['nonce-box-key', 'nonce-challenge']));
    expect(await bundlesSent(h)).toBe(0);
  });
});
