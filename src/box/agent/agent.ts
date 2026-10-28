import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import {
  HANDSHAKE_TTL_MS, boxKeyBindingNonce, createHandshake, generateBoxKeyPair, parseHandshakeMessage,
  serializeHandshakeMessage, verifyHandshakeMessage, type Handshake, type HandshakeMessage,
} from '../handshake/index.js';
import { createBoxSealer, type BoxSealer } from '../seal/index.js';
import { generateDeviceKey, type DeviceKey } from '../../security/index.js';
import { signMessage } from '../../notify/index.js';
import type { HttpClient, Logger, NotifyMessage, SignedNotifyMessage } from '../../types.js';
import { BoxPayloadError, decodeBoxPayload, encodeBoxPayload, isBoxId, type BoxEnrollPayload, type BoxNoticeKit } from './payload.js';
import type { BoxRelay } from './relay.js';
import {
  NOTICE_DIR, ROUTING_FILE, TOKENS_DIR, clearNotice, markNoticeSent, noticeAlreadySent, readRouting, routingFrom,
  sameRouting, sealedRecordHash, writeStateFile, type BoxRouting,
} from './state.js';
import type { TeeTokenSource } from './tee.js';

/** The audience of handshake attestation tokens; the CLI expects exactly this for the box it talks to. */
export function boxAttestationAudience(boxId: string): string { return `keysentry-box:${boxId}`; }

export type BoxAgentState = 'enrolling' | 'running' | 'locked' | 'unavailable' | 'stopped';

export class BoxAgentError extends Error {
  constructor(message: string) { super(message); this.name = 'BoxAgentError'; }
}

export interface BoxAgentDependencies {
  boxId: string;
  relay: BoxRelay;
  tee: TeeTokenSource;
  /** Egress-guarded client for STS and KMS only. */
  http: HttpClient;
  stateDir: string;
  /**
   * Devices allowed to send the first tokens to a box that holds no sealed record. This is routing from outside the
   * box and is not trusted: whoever enrolls a box can only give it their own tokens, and every later session uses the
   * device keys sealed inside the record. See notes/box-agent.md.
   */
  enrollmentDeviceKeys: readonly Buffer[];
  /** Runs the deployed watcher with these variables, in memory, until the signal aborts. */
  startWatcher(env: Record<string, string>, signal: AbortSignal): Promise<unknown>;
  /** Delivers the restart notice of a locked box. Must reject unless a channel delivered it. */
  sendNotice(kit: BoxNoticeKit, message: SignedNotifyMessage): Promise<void>;
  now?: () => Date;
  log?: Pick<Logger, 'info' | 'warn'>;
  pollIntervalMs?: number;
  /** Wait before restarting a watcher that stopped on its own, retrying a notice, or reopening a record. */
  retryMs?: number;
  maxSessions?: number;
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
}

export interface BoxAgentStatus {
  state: BoxAgentState;
  sessions: number;
  watcher: boolean;
  noticeSent: boolean;
  deviceKeys: number;
}
export interface BoxAgent {
  status(): BoxAgentStatus;
  /** Runs one relay cycle now (tests and the emulator). */
  cycle(): Promise<void>;
  stop(): Promise<void>;
  readonly done: Promise<void>;
}

interface Candidate { handshake: Handshake; deviceKey: Buffer }
interface Session { id: string; deadline: number; candidates: Candidate[]; rejected: Set<string>; done: boolean }

const SEQ: Partial<Record<Handshake['state'], number>> = { 'awaiting-challenge': 1, 'awaiting-bundle': 3 };
const silent: Pick<Logger, 'info' | 'warn'> = { info() {}, warn() {} };

/**
 * Inside the box: fresh keys each boot, attestation-bound sessions through the relay, sealing at rest, then the same
 * watcher a self-hosted deployment runs. Plaintext exists only in this process's memory.
 */
export async function startBoxAgent(deps: BoxAgentDependencies): Promise<BoxAgent> {
  if (!isBoxId(deps.boxId)) throw new BoxAgentError('The box id is invalid.');
  const now = deps.now ?? (() => new Date());
  const log = deps.log ?? silent;
  const stateDir = resolve(deps.stateDir);
  const pollMs = deps.pollIntervalMs ?? 5_000;
  const retryMs = deps.retryMs ?? 60_000;
  const maxSessions = deps.maxSessions ?? 4;
  const sleep = deps.sleep ?? ((ms: number, signal: AbortSignal) => delay(ms, undefined, { signal }));
  const audience = boxAttestationAudience(deps.boxId);
  const boxKey = generateBoxKeyPair();
  const signingKey: DeviceKey = generateDeviceKey();
  const binding = boxKeyBindingNonce(boxKey.publicKeyRaw, signingKey.publicKeyDer.subarray(-32));
  const controller = new AbortController();

  let state: BoxAgentState = 'unavailable';
  let routing = await readRouting(stateDir);
  if (routing && routing.boxId !== deps.boxId) throw new BoxAgentError('This state directory belongs to another box.');
  let deviceKeys: Buffer[] = routing ? [] : deps.enrollmentDeviceKeys.map(key => Buffer.from(key));
  if (!routing) state = 'enrolling';
  let tokens: BoxSealer | undefined;
  let env: Record<string, string> | undefined;
  let noticeKit: BoxNoticeKit | undefined;
  let noticeSent = false;
  let retryAt = 0;
  let sessions: Session[] = [];
  let watcher: { controller: AbortController; done: Promise<void> } | undefined;
  let busy: Promise<void> = Promise.resolve();

  const sealer = (route: BoxRouting, notice = false) => createBoxSealer({ http: deps.http,
    stateDir: join(stateDir, notice ? NOTICE_DIR : TOKENS_DIR),
    // The notice record uses its own box id, so its KMS and envelope contexts differ from the token record's.
    config: { boxId: notice ? `${route.boxId}.notice` : route.boxId, mode: notice ? 'standard' : route.mode, audience: route.audience, keyName: route.keyName },
    readAttestationToken: () => deps.tee.defaultToken() });

  function storedEnroll(bytes: Buffer, route: BoxRouting): BoxEnrollPayload {
    const payload = decodeBoxPayload(bytes);
    if (payload.kind !== 'enroll' || payload.boxId !== route.boxId || payload.shareB !== undefined
      || !sameRouting(routingFrom(payload.boxId, payload.settings), route)) throw new BoxAgentError('The sealed record does not match this box.');
    return payload;
  }

  function run(payload: BoxEnrollPayload): void {
    deviceKeys = payload.settings.deviceKeys.map(key => Buffer.from(key, 'base64'));
    // A directory per deployment: new tokens from setup come with a new state key and project binding.
    const deployment = createHash('sha256').update(payload.deployment.KEYSENTRY_WATCHER_CONFIG).digest('hex').slice(0, 16);
    env = { ...payload.deployment, KEYSENTRY_STATE_DIR: join(stateDir, `watcher-${deployment}`) };
    noticeKit = undefined;
    state = 'running';
    retryAt = 0;
  }

  async function restore(): Promise<void> {
    const route = routing!;
    tokens = sealer(route);
    if (route.mode !== 'unlock-on-restart') {
      const opened = await tokens.openSealed();
      if (opened.status !== 'open') throw new BoxAgentError('The sealed record could not be opened.');
      try { run(storedEnroll(opened.bundle, route)); } finally { opened.bundle.fill(0); }
      log.info('Box resumed from its sealed record.');
      return;
    }
    const notice = await sealer(route, true).openSealed();
    if (notice.status !== 'open') throw new BoxAgentError('The sealed notice record could not be opened.');
    try {
      const record = decodeBoxPayload(notice.bundle);
      if (record.kind !== 'notice' || record.boxId !== route.boxId || !sameRouting(routingFrom(record.boxId, record.settings), route)) {
        throw new BoxAgentError('The sealed notice record does not match this box.');
      }
      deviceKeys = record.settings.deviceKeys.map(key => Buffer.from(key, 'base64'));
      noticeKit = record.notice;
    } finally { notice.bundle.fill(0); }
    if ((await tokens.openSealed()).status !== 'locked') throw new BoxAgentError('The sealed record could not be checked.');
    const record = await sealedRecordHash(stateDir);
    noticeSent = record !== null && await noticeAlreadySent(stateDir, record);
    state = 'locked';
    log.info('Box restarted locked. Autopilot is paused until the device share arrives.');
  }

  async function deliverNotice(): Promise<void> {
    if (noticeSent || !noticeKit || now().getTime() < retryAt) return;
    const record = await sealedRecordHash(stateDir);
    if (!record) return;
    const message: NotifyMessage = { id: randomUUID(), at: now().toISOString(), kind: 'box-locked', severity: 'warning',
      title: 'Your cloud box restarted and is waiting for you',
      lines: [`Box ${deps.boxId} restarted. Autopilot is paused and no key will change until you unlock it.`,
        `On your computer, run: keysentry box unlock ${deps.boxId}`] };
    try {
      await deps.sendNotice(noticeKit, signMessage(message, signingKey));
      await markNoticeSent(stateDir, record);
      noticeSent = true;
    } catch {
      retryAt = now().getTime() + retryMs;
      log.warn('The box could not deliver its restart notice. It will try again.');
    }
  }

  function startWatcher(): void {
    if (state !== 'running' || watcher || !env || now().getTime() < retryAt) return;
    const own = new AbortController();
    const done = Promise.resolve()
      .then(() => deps.startWatcher({ ...env! }, own.signal))
      .then(() => undefined, () => undefined)
      .then(() => {
        if (watcher?.controller !== own) return;
        watcher = undefined;
        if (!own.signal.aborted) { retryAt = now().getTime() + retryMs; log.warn('The watcher stopped. The box will start it again.'); }
      });
    watcher = { controller: own, done };
  }
  async function stopWatcher(): Promise<void> {
    const current = watcher; watcher = undefined;
    if (current) { current.controller.abort(); await current.done; }
  }

  async function openSession(): Promise<void> {
    const at = now();
    sessions = sessions.filter(session => !session.done && session.deadline > at.getTime());
    if (sessions.some(session => session.candidates[0]?.handshake.state === 'awaiting-challenge') || deviceKeys.length === 0) return;
    while (sessions.length >= maxSessions) sessions.shift();
    const id = randomBytes(16).toString('base64url'), messageId = randomBytes(16).toString('base64url');
    const token = await deps.tee.token({ audience, nonces: [binding] });
    // One handshake per allowed device. Ed25519 signatures are deterministic, so with the same inputs every candidate
    // emits the same hello; the device whose signature verifies on the challenge keeps the session.
    const transitions = deviceKeys.map(deviceKey => ({ deviceKey,
      step: createHandshake('box', { devicePublicKeyDer: deviceKey, signingKey, boxKey, sessionId: id }).next({ now: at, attestationToken: token, id: messageId }) }));
    const hello = transitions[0]!.step.message!;
    if (transitions.some(item => serializeHandshakeMessage(item.step.message!) !== serializeHandshakeMessage(hello))) throw new BoxAgentError('Handshake candidates disagree.');
    await deps.relay.publish(hello);
    sessions.push({ id, deadline: at.getTime() + HANDSHAKE_TTL_MS, rejected: new Set(), done: false,
      candidates: transitions.map(item => ({ handshake: item.step.handshake, deviceKey: item.deviceKey })) });
  }

  async function onChallenge(session: Session, raw: unknown, message: HandshakeMessage): Promise<boolean> {
    if (message.type !== 'cli-challenge') return false;
    const accepting = session.candidates.filter(candidate => verifyHandshakeMessage(message, candidate.deviceKey));
    if (accepting.length === 0) return false;
    // Minted only for a challenge signed by an allowed device: one token per handshake, never per poll.
    const token = await deps.tee.token({ audience, nonces: [binding, message.challenge] });
    for (const candidate of accepting) {
      try {
        const step = candidate.handshake.next({ now: now(), message: raw, attestationToken: token });
        await deps.relay.publish(step.message!);
        session.candidates = [{ handshake: step.handshake, deviceKey: candidate.deviceKey }];
        return true;
      } catch { /* try the next allowed device */ }
    }
    return false;
  }

  async function onBundle(session: Session, raw: unknown): Promise<boolean> {
    const candidate = session.candidates[0]!;
    let step;
    try { step = candidate.handshake.next({ now: now(), message: raw }); } catch { return false; }
    const plaintext = step.plaintext!;
    try { await apply(plaintext); }
    catch (error) {
      session.done = true;
      log.warn(error instanceof BoxAgentError || error instanceof BoxPayloadError ? error.message : 'The box could not apply a token bundle.');
      return true;
    } finally { plaintext.fill(0); }
    session.done = true;
    // The ack goes out only after the record is sealed at rest, so the CLI's success means the box kept the tokens.
    await deps.relay.publish(step.message!);
    // Sessions opened under the previous device list keep only devices still on the new one. Their announcements
    // stay on the relay, so dropping a still-valid session would leave a CLI waiting on it.
    sessions = sessions.filter(other => {
      if (other === session) return true;
      other.candidates = other.candidates.filter(candidate => deviceKeys.some(key => key.equals(candidate.deviceKey)));
      return other.candidates.length > 0;
    });
    return true;
  }

  async function apply(plaintext: Buffer): Promise<void> {
    const payload = decodeBoxPayload(plaintext);
    if (payload.boxId !== deps.boxId) throw new BoxAgentError('A token bundle for another box was refused.');
    if (payload.kind === 'notice') throw new BoxPayloadError();
    if (payload.kind === 'unlock') {
      if (state !== 'locked') return;
      const share = Buffer.from(payload.shareB, 'base64');
      try {
        const opened = await tokens!.openSealed(share);
        if (opened.status !== 'open') throw new BoxAgentError('The device share did not unlock the box.');
        try { run(storedEnroll(opened.bundle, routing!)); } finally { opened.bundle.fill(0); }
      } catch (error) { throw error instanceof BoxAgentError ? error : new BoxAgentError('The device share did not unlock the box.'); }
      finally { share.fill(0); }
      await clearNotice(stateDir); noticeSent = false;
      log.info('Box unlocked by a verified device.');
      return;
    }
    const next = routingFrom(deps.boxId, payload.settings);
    if (routing && !sameRouting(routing, next)) throw new BoxAgentError('This box already seals tokens with other settings. Provision a new box to change them.');
    if (state === 'locked') throw new BoxAgentError('Unlock the box before sending new tokens.');
    if (next.mode === 'unlock-on-restart' && payload.shareB === undefined) throw new BoxAgentError('Unlock-on-restart needs the device share with the tokens.');
    const { shareB, ...kept } = payload;
    const stored = encodeBoxPayload(kept);
    const share = shareB === undefined ? undefined : Buffer.from(shareB, 'base64');
    const target = sealer(next);
    try {
      await target.sealBundle(stored, share);
      if (next.mode === 'unlock-on-restart') {
        const notice = encodeBoxPayload({ v: 1, kind: 'notice', boxId: deps.boxId, settings: payload.settings, notice: payload.notice });
        try { await sealer(next, true).sealBundle(notice); } finally { notice.fill(0); }
      }
      if (!routing) { await writeStateFile(stateDir, ROUTING_FILE, next); routing = next; }
      await clearNotice(stateDir); noticeSent = false;
    } finally { stored.fill(0); share?.fill(0); }
    tokens = target;
    await stopWatcher();
    run(kept);
    log.info('Box sealed new tokens.');
  }

  async function poll(): Promise<void> {
    if (sessions.length === 0) return;
    const queued = await deps.relay.poll();
    for (const session of sessions) {
      let progressed = true;
      while (progressed && !session.done) {
        progressed = false;
        const expected = SEQ[session.candidates[0]!.handshake.state];
        if (expected === undefined) break;
        for (const raw of queued) {
          let message: HandshakeMessage;
          try { message = parseHandshakeMessage(raw); } catch { continue; }
          if (message.sessionId !== session.id || message.seq !== expected || session.rejected.has(message.id)) continue;
          const accepted = expected === 1 ? await onChallenge(session, raw, message) : await onBundle(session, raw);
          if (accepted) { progressed = true; break; }
          if (session.rejected.size < 256) session.rejected.add(message.id);
        }
      }
    }
  }

  async function cycle(): Promise<void> {
    if (state === 'stopped') return;
    if (state === 'unavailable' && now().getTime() >= retryAt) {
      try { await restore(); }
      catch {
        retryAt = now().getTime() + retryMs;
        log.warn('The box could not open its sealed record. It will try again.');
        return;
      }
    }
    if (state === 'unavailable') return;
    if (state === 'locked') await deliverNotice();
    startWatcher();
    await openSession();
    await poll();
    startWatcher();
  }
  function serialized(): Promise<void> {
    const next = busy.catch(() => undefined).then(cycle);
    busy = next.catch(() => undefined);
    return next;
  }

  const done = (async () => {
    while (!controller.signal.aborted) {
      try { await serialized(); } catch { log.warn('A box cycle failed. It will run again.'); }
      try { await sleep(pollMs, controller.signal); } catch { /* stopped */ }
    }
  })();

  return {
    status: () => ({ state, sessions: sessions.length, watcher: watcher !== undefined, noticeSent, deviceKeys: deviceKeys.length }),
    cycle: serialized,
    async stop() {
      controller.abort();
      await done;
      await busy;
      state = 'stopped';
      await stopWatcher();
      await tokens?.lock();
      env = undefined;
      sessions = [];
    },
    done,
  };
}
